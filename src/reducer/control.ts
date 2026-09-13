// Control machine (§2.4): signed control actions against the bootstrap
// control quorum. Admissible while halted (it is the resume/revoke path).

import { edVerify } from "../crypto.ts";
import { err } from "../errors.ts";
import type { Json } from "../json/strict.ts";
import { u64 } from "../scalars.ts";
import type * as T from "../types.ts";
import { controlRevision, emitEvent, insertAuditDelivery } from "./core.ts";
import { memberMap, type CallCtx, type MutationOutcome } from "./methods.ts";

export function controlApply(ctx: CallCtx, certificateObjectId: string): MutationOutcome {
  const store = ctx.store;
  const obj = store.getObject(certificateObjectId);
  if (!obj || obj.kind !== "control") throw err("NOT_FOUND", "control certificate not found");
  const cert = obj.body as T.ControlCertificate;
  const b = cert.body;

  if (b.tenant !== ctx.policy.tenant || b.environment !== ctx.policy.environment) {
    throw err("CONTROL_STALE", "certificate scope mismatch");
  }
  const revision = controlRevision(store);
  if (u64(b.base_revision) !== revision) throw err("CONTROL_STALE", "base_revision does not match the control stream");
  if (store.hasControlNonce(b.nonce)) throw err("CONTROL_STALE", "control nonce was already admitted");
  if (ctx.now >= u64(b.expires_ms)) throw err("CONTROL_STALE", "control certificate expired");

  // authority: bootstrap control quorum over kind "control"
  const members = memberMap(ctx.policy);
  for (const s of cert.signatures) {
    const m = members.get(s.key_id);
    if (!m || !ctx.policy.control.keys.includes(s.key_id) || store.isKeyRevoked(s.key_id) ||
        !edVerify("control", b as unknown as Json, m.public_key, s.sig)) {
      throw err("SIGNATURE_INVALID", "control signature invalid");
    }
  }
  const principals = new Set<string>();
  for (const s of cert.signatures) principals.add(members.get(s.key_id)!.principal);
  const q = ctx.policy.control;
  const mandatoryOk = q.mandatory_principals.every((mp) => principals.has(mp));
  if (principals.size < q.threshold || !mandatoryOk) throw err("QUORUM_MISSING", "control quorum not satisfied");

  const newRevision = revision + 1n;
  const events: string[] = [];

  switch (b.action.kind) {
    case "halt":
      store.setControlState("HALTED", null);
      break;
    case "resume": {
      // incident evidence must exist; storage/clock/custody checks run at the transport layer
      const blob = store.getObject(b.action.incident.object);
      if (!blob) throw err("NOT_FOUND", "resume incident evidence object not found");
      if (!ctx.clockSafe) throw err("CLOCK_UNSAFE", "clock is still unsafe; resume requires validated time");
      store.setControlState("RUNNING", null);
      break;
    }
    case "revoke_key": {
      const blob = store.getObject(b.action.incident.object);
      if (!blob) throw err("NOT_FOUND", "revoke_key incident evidence object not found");
      store.revokeKey(b.action.key_id, newRevision);
      break;
    }
    case "activate_policy": {
      const pol = store.getObject(b.action.policy);
      if (!pol || pol.kind !== "policy") throw err("NOT_FOUND", "policy object not found");
      if (pol.digest !== b.action.policy_hash) throw err("POLICY_INVALID", "policy hash does not match the named object");
      if (store.getPolicyByObject(b.action.policy) === null) {
        store.putPolicy(b.action.policy, b.action.policy_hash, newRevision);
      }
      store.setMeta({ active_policy: b.action.policy });
      break;
    }
  }

  store.putControlNonce(b.nonce);
  store.setMeta({ control_revision: newRevision });
  const ev = emitEvent(ctx, "control", null, null, ctx.commandId, ctx.now,
    { kind: "ControlApplied", certificate: certificateObjectId as T.Id, control_revision: String(newRevision) as T.U64 },
    [certificateObjectId]);
  events.push("ControlApplied");
  insertAuditDelivery(ctx, "control", BigInt(ev.body.seq), ev.hash);

  return {
    result: {
      status: store.getControlState().status,
      revision: String(newRevision),
      revoked_keys: store.revokedKeys(),
      active_policy: store.getMeta()!.active_policy,
    },
    events,
  };
}
