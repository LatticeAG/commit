// Object registry digests (§1.3) and admission checks beyond schema shape
// (§1.2 semantic refinements: deadline ordering, roster rules, cap relations).

import { D, H } from "./crypto.ts";
import { err } from "./errors.ts";
import { jcsBytes } from "./json/jcs.ts";
import { decodeBase64urlCanonical, sortedUnique, u64 } from "./scalars.ts";
import { SIGNED_WRAPPER_KINDS, type CustodyManifest, type Envelope, type ObjectBody, type ObjectEntry, type ObjectKind, type Policy, type Quorum } from "./types.ts";

/**
 * Registry digest of a stored object:
 *  - blob: H(decoded bytes)
 *  - signed wrapper kinds (approval, award, control, custody): D("manifest",{kind,body:wrapper})
 *  - any other typed object: D(kind, body)
 */
export function registryDigest(kind: ObjectKind, body: ObjectBody): string {
  if (kind === "blob") {
    return H(decodeBase64urlCanonical((body as { encoding: string; data: string }).data));
  }
  if (SIGNED_WRAPPER_KINDS.has(kind)) {
    return D("manifest", { kind, body } as unknown as import("./json/strict.ts").Json);
  }
  return D(kind, body as unknown as import("./json/strict.ts").Json);
}

/** Canonical byte length of the complete stored object (wrapper included). */
export function objectBytes(kind: ObjectKind, body: ObjectBody): number {
  if (kind === "blob") {
    return decodeBase64urlCanonical((body as { encoding: string; data: string }).data).length;
  }
  return jcsBytes(body as unknown as import("./json/strict.ts").Json).length;
}

export function objectEntry(id: string, kind: ObjectKind, body: ObjectBody): ObjectEntry {
  return { id, kind, digest: registryDigest(kind, body), bytes: String(objectBytes(kind, body)) };
}

/** Sort ObjectEntry rows by (kind, digest, id). */
export function entryOrder(a: ObjectEntry, b: ObjectEntry): number {
  if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
  if (a.digest !== b.digest) return a.digest < b.digest ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

// ---------- Policy admission (§1.2) ----------

export function validatePolicySemantics(p: Policy, custodyManifest?: CustodyManifest, writerKey?: string): void {
  // Members sorted by key_id; key ids, principals, public keys unique.
  const keyIds = p.members.map((m) => m.key_id);
  if (!sortedUnique(keyIds)) throw err("POLICY_INVALID", "members must be sorted by key_id");
  if (new Set(p.members.map((m) => m.principal)).size !== p.members.length) {
    throw err("POLICY_INVALID", "member principals must be unique");
  }
  if (new Set(p.members.map((m) => m.public_key)).size !== p.members.length) {
    throw err("POLICY_INVALID", "member public keys must be unique");
  }
  const memberByKey = new Map(p.members.map((m) => [m.key_id, m]));
  const principalHasKey = (principal: string, keys: string[]) =>
    keys.some((k) => memberByKey.get(k)?.principal === principal);

  for (const [name, q] of Object.entries({ approve: p.approve, attest: p.attest, arbitrate: p.arbitrate, control: p.control })) {
    checkQuorum(name, q, memberByKey);
    for (const mp of q.mandatory_principals) {
      if (!principalHasKey(mp, q.keys)) {
        throw err("POLICY_INVALID", `mandatory principal ${mp} has no key in ${name} roster`);
      }
    }
  }

  // Cap relations.
  const maxAmt = u64(p.max_amount_minor);
  const maxExp = u64(p.max_exposure_minor);
  const daily = u64(p.daily_commit_minor);
  const maxDur = u64(p.max_duration_ms);
  if (maxAmt <= 0n || maxAmt > maxExp) throw err("POLICY_INVALID", "max_amount/max_exposure relation");
  if (maxAmt > daily) throw err("POLICY_INVALID", "max_amount/daily_commit relation");
  if (maxDur > 2592000000n) throw err("POLICY_INVALID", "max_duration_ms bound");
  if (u64(p.min_challenge_ms) < 1000n) throw err("POLICY_INVALID", "min_challenge_ms below 1000");

  // Payer must be a mandatory approve principal; at least one human member overall for approval.
  const approveMembers = p.approve.keys.map((k) => memberByKey.get(k)!);
  if (!approveMembers.some((m) => m.kind === "human")) {
    throw err("POLICY_INVALID", "approve roster requires at least one human");
  }

  // Arbitrators distinct from any possible payer/payee is per-envelope; here we
  // require arbitrate principals to not overlap approve mandatory principals is
  // NOT required — the per-envelope check compares to that envelope's parties.

  // Receipt/writer keys are never quorum-eligible.
  if (custodyManifest) {
    for (const m of p.members) {
      if (m.public_key === custodyManifest.receipt_key) {
        throw err("POLICY_INVALID", "custody receipt key is not quorum-eligible");
      }
    }
    if (p.custody !== custodyManifest.custody) {
      throw err("POLICY_INVALID", "policy custody does not match custody manifest");
    }
    if (p.asset.code !== custodyManifest.asset.code || p.asset.scale !== custodyManifest.asset.scale || p.asset.custody !== custodyManifest.asset.custody) {
      throw err("POLICY_INVALID", "policy asset does not match custody manifest");
    }
  }
  if (writerKey) {
    for (const m of p.members) {
      if (m.public_key === writerKey) throw err("POLICY_INVALID", "writer key is not quorum-eligible");
    }
  }
}

function checkQuorum(name: string, q: Quorum, memberByKey: Map<string, { principal: string }>): void {
  if (q.threshold < 1 || q.threshold > q.keys.length || q.keys.length > 16) {
    throw err("POLICY_INVALID", `${name} threshold/keys relation invalid`);
  }
  for (const k of q.keys) {
    if (!memberByKey.has(k)) throw err("POLICY_INVALID", `${name} key ${k} resolves outside policy members`);
  }
}

// ---------- Envelope admission (§1.2) ----------

export function validateEnvelopeSemantics(e: Envelope, p: Policy, admissionMs: bigint): void {
  if (e.payer === e.payee) throw err("SCHEMA_INVALID", "payer must differ from payee");
  if (e.tenant !== p.tenant || e.environment !== p.environment) throw err("SCHEMA_INVALID", "envelope tenant/environment mismatch with policy");
  if (e.custody !== p.custody) throw err("ASSET_MISMATCH", "envelope custody differs from policy");
  if (e.asset.code !== p.asset.code || e.asset.scale !== p.asset.scale || e.asset.custody !== p.asset.custody) {
    throw err("ASSET_MISMATCH", "envelope asset differs from policy");
  }
  if (e.policy_hash !== D("policy", p as unknown as import("./json/strict.ts").Json)) {
    throw err("POLICY_INACTIVE", "envelope pins a non-active policy");
  }
  const amount = u64(e.amount_minor);
  if (amount <= 0n || amount > u64(p.max_amount_minor)) throw err("AMOUNT_OVERFLOW", "amount outside policy bounds");
  const fallback = u64(e.dispute_fallback_pay_minor);
  if (fallback < 0n || fallback > amount) throw err("SCHEMA_INVALID", "dispute_fallback_pay_minor out of range");

  const created = u64(e.created_ms);
  const commitBy = u64(e.commit_by_ms);
  const fundBy = u64(e.fund_by_ms);
  const condBy = u64(e.condition_by_ms);
  if (!(created <= admissionMs && admissionMs < commitBy && commitBy <= fundBy && fundBy < condBy)) {
    throw err("DEADLINE_CLOSED", "envelope deadline ordering violated at admission");
  }
  if (u64(e.challenge_ms) < u64(p.min_challenge_ms) || u64(p.min_challenge_ms) < 1000n) {
    throw err("SCHEMA_INVALID", "challenge_ms below policy minimum");
  }
  if (u64(e.dispute_ms) < 1000n) throw err("SCHEMA_INVALID", "dispute_ms below 1000");
  const horizon = condBy + u64(e.challenge_ms) + u64(e.dispute_ms) - created;
  if (horizon > u64(p.max_duration_ms) || u64(p.max_duration_ms) > 2592000000n) {
    throw err("SCHEMA_INVALID", "total horizon exceeds max_duration_ms");
  }

  // Clauses: nonempty (schema), sorted by ASCII id.
  const clauseIds = e.condition.clauses.map((c) => c.id);
  if (!sortedUnique(clauseIds)) throw err("SCHEMA_INVALID", "clauses must be sorted by id and unique");

  // Parents sorted by (system,profile,ref,digest).
  const parentKeys = e.parents.map((x) => `${x.system}${x.profile}${x.ref}${x.digest}`);
  if (!sortedUnique(parentKeys)) throw err("SCHEMA_INVALID", "parents must be sorted by (system,profile,ref,digest)");

  // Arbitrators must be distinct from payer and payee.
  const memberByKey = new Map(p.members.map((m) => [m.key_id, m]));
  const arbPrincipals = new Set(p.arbitrate.keys.map((k) => memberByKey.get(k)!.principal));
  if (arbPrincipals.has(e.payer) || arbPrincipals.has(e.payee)) {
    throw err("POLICY_INVALID", "arbitrators must be distinct from payer and payee");
  }
  // Payer must be a mandatory approve principal.
  const mandatory = new Set(p.approve.mandatory_principals);
  if (!mandatory.has(e.payer)) {
    throw err("POLICY_INVALID", "payer must be a mandatory approval principal");
  }
}
