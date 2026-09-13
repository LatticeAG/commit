// Coordinator: the single sequencer behind the §3.1 RPC surface. Owns
// authentication (peer principal + capability), param schemas, idempotency
// keys, clock admission, transaction boundaries, and method dispatch.

import crypto from "node:crypto";
import { err } from "./errors.ts";
import { jcsBytes, jcs } from "./json/jcs.ts";
import { parseStrictJson, checkArtifactBounds, type Json } from "./json/strict.ts";
import { H } from "./crypto.ts";
import {
  decodeBase64urlCanonical, isAscii, isId, moneyU64, strictU64, u64, utf8Len,
} from "./scalars.ts";
import { validBlobRef, validRequest, validState, validAsset, validObjectBody } from "./schema.ts";
import type { Store, ObjectRow, PromiseRow } from "./store.ts";
import { OBJECT_KINDS } from "./types.ts";
import type * as T from "./types.ts";
import type { Ctx } from "./reducer/core.ts";
import {
  approvalSubmit, conditionSubmit, disputeOpen, disputeResolve, objectPut,
  promiseAdvance, promiseCancel, promiseCommit, promisePropose,
  envelopeOf, memberMap, type CallCtx, type MutationOutcome,
} from "./reducer/methods.ts";
import { custodyReconcile, custodyRetry, operationView } from "./reducer/custody.ts";
import { controlApply } from "./reducer/control.ts";
import { exportProof, verifyProofRpc } from "./proof.ts";

export const MUTATION_METHODS: ReadonlySet<T.Method> = new Set([
  "object.put", "promise.propose", "approval.submit", "promise.commit", "promise.cancel",
  "condition.submit", "dispute.open", "dispute.resolve", "promise.advance",
  "custody.reconcile", "custody.retry", "control.apply", "proof.export",
]);

const READ_METHODS: ReadonlySet<T.Method> = new Set([
  "object.get", "promise.get", "promise.list", "event.list", "account.get",
  "proof.verify", "control.status", "health.get",
]);

export interface CoordinatorDeps extends Ctx {
  clock: { observe(wall: bigint): { now: bigint; wallNow: bigint; safe: boolean } };
  storageOk(): boolean;
}

function isObj(v: unknown): v is { [k: string]: Json } {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function reqFields(params: unknown, fields: string[]): { [k: string]: Json } {
  if (!isObj(params)) throw err("SCHEMA_INVALID", "params is not an object");
  const want = new Set(fields);
  for (const k of Object.keys(params)) {
    if (!want.has(k)) throw err("SCHEMA_INVALID", `unknown params member "${k}"`);
  }
  for (const k of fields) {
    if (!Object.hasOwn(params, k)) throw err("SCHEMA_INVALID", `missing params member "${k}"`);
  }
  return params;
}

function paramId(params: { [k: string]: Json }, f: string): string {
  const v = params[f];
  if (typeof v !== "string" || !isId(v)) throw err("SCHEMA_INVALID", `${f} is not a valid Id`);
  return v;
}

function paramU64(params: { [k: string]: Json }, f: string): string {
  const v = params[f];
  strictU64(v, f);
  return v as string;
}

export class Coordinator {
  readonly deps: CoordinatorDeps;
  constructor(deps: CoordinatorDeps) { this.deps = deps; }

  /** Authenticated call. `capability` is the peer-mapped record; `request` is the parsed frame body. */
  async call(actor: string, capability: T.Capability, request: unknown, nowMs?: bigint): Promise<{ ok: true; result: unknown } | { ok: false; error: T.ErrorBody }> {
    try {
      const req = validRequest(request);
      const result = await this.dispatch(actor, capability, req, nowMs);
      return { ok: true, result };
    } catch (e) {
      const ce = e as { code?: string; retryable?: boolean; message?: string; currentRevision?: string | null };
      return { ok: false, error: { code: ce.code ?? "INTERNAL", retryable: ce.retryable ?? false, message: ce.message ?? "internal error", current_revision: ce.currentRevision ?? null } };
    }
  }

  private async dispatch(actor: string, cap: T.Capability, req: T.Request, nowMs?: bigint): Promise<unknown> {
    const store = this.deps.store;
    const method = req.method;
    const params = req.params;
    const requestId = req.request_id;

    // clock admission: one validated reading per command; the harness injects wall time
    const reading = this.deps.clock.observe(nowMs ?? BigInt(Date.now()));

    // stage 2: presented capability must be the peer-bound record and unexpired
    if (req.capability !== cap.capability) throw err("FORBIDDEN", "capability is not bound to this peer");
    if (u64(cap.expires_ms) <= reading.now) throw err("UNAUTHENTICATED", "capability expired");

    // stage 3 (partial): method must be in the capability's method list
    if (!cap.methods.includes(method)) throw err("FORBIDDEN", `capability does not allow ${method}`);

    // stage 4: params schema (closed record per method)
    const p = this.validateParams(method, params);

    const ctx: CallCtx = {
      ...this.deps, now: reading.now, wallNow: reading.wallNow, clockSafe: reading.safe,
      actor, capability: cap, commandId: requestId,
    };

    // stage 6: request-id idempotency for mutations (replay precedes revision/safety/deadline)
    const isMutation = MUTATION_METHODS.has(method);
    let requestHash = "";
    if (isMutation) {
      requestHash = H(jcsBytes(params as Json));
      const prior = store.getIdempotent(actor, cap.capability, method, requestId);
      if (prior) {
        if (prior.request_hash === requestHash) return JSON.parse(prior.canonical_response);
        throw err("IDEMPOTENCY_CONFLICT", "request_id was used with different parameters");
      }
    }

    const run = async (): Promise<unknown> => {
      switch (method) {
        case "object.put":
          return store.tx(() => objectPut(ctx, p.object, p.kind as T.ObjectKind, p.body).result);
        case "object.get":
          return this.objectGet(ctx, p.object);
        case "promise.propose":
          return store.tx(() => promisePropose(ctx, p.envelope).result);
        case "promise.get":
          return this.promiseGet(ctx, p.commit_id);
        case "promise.list":
          return this.promiseList(ctx, p.state, p.cursor, p.limit);
        case "approval.submit":
          return store.tx(() => approvalSubmit(ctx, p.commit_id, BigInt(p.expected_revision), p.approval).result);
        case "promise.commit":
          return store.tx(() => promiseCommit(ctx, p.commit_id, BigInt(p.expected_revision)).result);
        case "promise.cancel":
          return store.tx(() => promiseCancel(ctx, p.commit_id, BigInt(p.expected_revision)).result);
        case "condition.submit":
          return store.tx(() => conditionSubmit(ctx, p.commit_id, BigInt(p.expected_revision), p.evidence).result);
        case "dispute.open":
          return store.tx(() => disputeOpen(ctx, p.commit_id, BigInt(p.expected_revision), p.case_id, p.reason, p.evidence).result);
        case "dispute.resolve":
          return store.tx(() => disputeResolve(ctx, p.commit_id, BigInt(p.expected_revision), p.award).result);
        case "promise.advance":
          return store.tx(() => promiseAdvance(ctx, p.commit_id, BigInt(p.expected_revision)).result);
        case "custody.reconcile":
          return custodyReconcile(ctx, p.operation_id, p.receipt);
        case "custody.retry":
          return custodyRetry(ctx, p.operation_id, p.no_effect_receipt);
        case "account.get":
          return this.accountGet(ctx, p.principal, p.asset);
        case "event.list":
          return this.eventList(ctx, p.commit_id, BigInt(p.after_seq), p.limit);
        case "proof.export":
          return store.tx(() => exportProof(ctx, p.commit_id, p.disclosure, p.cursor));
        case "proof.verify":
          return verifyProofRpc(ctx, p.manifest, p.trust);
        case "control.apply":
          return store.tx(() => controlApply(ctx, p.certificate).result);
        case "control.status":
          return this.controlStatus(ctx);
        case "health.get":
          return this.healthGet(ctx);
      }
      throw err("SCHEMA_INVALID", "unknown method");
    };

    const result = await run();
    if (isMutation) {
      store.putIdempotent(actor, cap.capability, method, requestId, requestHash, JSON.stringify(result), ctx.now);
    }
    return result;
  }

  // ---------- param validation (exact closed shapes per §3.2) ----------

  private validateParams(method: T.Method, params: unknown): Record<string, any> {
    switch (method) {
      case "object.put": {
        const q = reqFields(params, ["object", "kind", "body"]);
        const kind = q.kind;
        if (typeof kind !== "string" || !OBJECT_KINDS.includes(kind as T.ObjectKind)) throw err("SCHEMA_INVALID", "kind invalid");
        return { object: paramId(q, "object"), kind, body: q.body };
      }
      case "object.get": {
        const q = reqFields(params, ["object"]);
        return { object: paramId(q, "object") };
      }
      case "promise.propose": {
        const q = reqFields(params, ["envelope"]);
        return { envelope: paramId(q, "envelope") };
      }
      case "promise.get": {
        const q = reqFields(params, ["commit_id"]);
        return { commit_id: paramId(q, "commit_id") };
      }
      case "promise.list": {
        const q = reqFields(params, ["state", "cursor", "limit"]);
        const state = q.state === null ? null : validState(q.state);
        const cursor = q.cursor === null ? null : this.cursorString(q.cursor);
        const limit = this.listLimit(q.limit, 100);
        return { state, cursor, limit };
      }
      case "approval.submit": {
        const q = reqFields(params, ["commit_id", "expected_revision", "approval"]);
        return { commit_id: paramId(q, "commit_id"), expected_revision: paramU64(q, "expected_revision"), approval: paramId(q, "approval") };
      }
      case "promise.commit":
      case "promise.cancel":
      case "promise.advance": {
        const q = reqFields(params, ["commit_id", "expected_revision"]);
        return { commit_id: paramId(q, "commit_id"), expected_revision: paramU64(q, "expected_revision") };
      }
      case "condition.submit": {
        const q = reqFields(params, ["commit_id", "expected_revision", "evidence"]);
        return { commit_id: paramId(q, "commit_id"), expected_revision: paramU64(q, "expected_revision"), evidence: paramId(q, "evidence") };
      }
      case "dispute.open": {
        const q = reqFields(params, ["commit_id", "expected_revision", "case_id", "reason", "evidence"]);
        const reason = q.reason;
        if (reason !== "delivery" && reason !== "fraud" && reason !== "integrity") throw err("SCHEMA_INVALID", "reason invalid");
        return { commit_id: paramId(q, "commit_id"), expected_revision: paramU64(q, "expected_revision"), case_id: paramId(q, "case_id"), reason, evidence: validBlobRef(q.evidence, "evidence") };
      }
      case "dispute.resolve": {
        const q = reqFields(params, ["commit_id", "expected_revision", "award"]);
        return { commit_id: paramId(q, "commit_id"), expected_revision: paramU64(q, "expected_revision"), award: paramId(q, "award") };
      }
      case "custody.reconcile": {
        const q = reqFields(params, ["operation_id", "receipt"]);
        return { operation_id: paramId(q, "operation_id"), receipt: q.receipt === null ? null : paramId(q, "receipt") };
      }
      case "custody.retry": {
        const q = reqFields(params, ["operation_id", "no_effect_receipt"]);
        return { operation_id: paramId(q, "operation_id"), no_effect_receipt: paramId(q, "no_effect_receipt") };
      }
      case "account.get": {
        const q = reqFields(params, ["principal", "asset"]);
        return { principal: paramId(q, "principal"), asset: validAsset(q.asset) };
      }
      case "event.list": {
        const q = reqFields(params, ["commit_id", "after_seq", "limit"]);
        return { commit_id: paramId(q, "commit_id"), after_seq: paramU64(q, "after_seq"), limit: this.listLimit(q.limit, 256) };
      }
      case "proof.export": {
        const q = reqFields(params, ["commit_id", "disclosure", "cursor"]);
        if (q.disclosure !== "full" && q.disclosure !== "redacted") throw err("SCHEMA_INVALID", "disclosure invalid");
        return { commit_id: paramId(q, "commit_id"), disclosure: q.disclosure, cursor: q.cursor === null ? null : this.cursorString(q.cursor) };
      }
      case "proof.verify": {
        const q = reqFields(params, ["manifest", "trust"]);
        return { manifest: paramId(q, "manifest"), trust: paramId(q, "trust") };
      }
      case "control.apply": {
        const q = reqFields(params, ["certificate"]);
        return { certificate: paramId(q, "certificate") };
      }
      case "control.status":
      case "health.get": {
        reqFields(params, []);
        return {};
      }
    }
    throw err("SCHEMA_INVALID", "unknown method");
  }

  private cursorString(v: unknown): string {
    if (typeof v !== "string" || v.length === 0 || utf8Len(v) > 4096 || !isAscii(v)) {
      throw err("SCHEMA_INVALID", "cursor invalid");
    }
    return v;
  }

  private listLimit(v: unknown, max: number): number {
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) throw err("SCHEMA_INVALID", "limit must be a positive integer");
    if (v > max) throw err("LIMIT_EXCEEDED", `limit exceeds ${max}`);
    return v;
  }

  // ---------- reads ----------

  private partyOrScoped(ctx: CallCtx, commitId: string): PromiseRow {
    const p = this.deps.store.getPromise(commitId);
    if (!p) throw err("NOT_FOUND", "promise not found");
    const allowed = ctx.actor === p.payer || ctx.actor === p.payee || ctx.capability.commit_ids.includes(commitId);
    if (!allowed) throw err("NOT_FOUND", "promise not found");
    return p;
  }

  private promiseView(ctx: CallCtx, p: PromiseRow): T.PromiseView {
    const store = this.deps.store;
    const op = store.latestOperation(p.commit_id);
    return {
      commit_id: p.commit_id, envelope: p.envelope_object, envelope_hash: p.envelope_hash,
      revision: String(p.revision), state: p.state,
      approval_count: store.listApprovals(p.envelope_hash).length,
      escrow_id: p.escrow_id, release_at_ms: p.release_at === null ? null : String(p.release_at),
      case_id: p.case_id, decision_by_ms: p.decision_by === null ? null : String(p.decision_by),
      disposition: p.disposition, allocation: p.allocation,
      operation: op ? op.operation_id : null,
      halted: store.getControlState().status === "HALTED",
    };
  }

  private promiseGet(ctx: CallCtx, commitId: string): T.PromiseView {
    return this.promiseView(ctx, this.partyOrScoped(ctx, commitId));
  }

  private promiseList(ctx: CallCtx, state: T.State | null, cursor: string | null, limit: number): { items: T.PromiseView[]; next_cursor: string | null } {
    const store = this.deps.store;
    let afterOrdinal = 0n;
    let snapshotMax = store.maxPromiseOrdinal();
    if (cursor !== null) {
      const c = this.decodeCursor(cursor, ctx);
      if (c.kind !== "list") throw err("CURSOR_INVALID", "cursor is not a list cursor");
      if (c.state !== state) throw err("CURSOR_INVALID", "cursor filter mismatch");
      afterOrdinal = BigInt(c.last_ordinal ?? "0");
      snapshotMax = BigInt(c.snapshot_max ?? "0");
    }
    const rows = store.listPromises(state, ctx.actor, afterOrdinal, limit + 1);
    const visible = rows.filter((r) => ctx.actor === r.payer || ctx.actor === r.payee || ctx.capability.commit_ids.includes(r.commit_id));
    const bounded = visible.filter((r) => store.promiseOrdinal(r.commit_id) <= snapshotMax);
    const items = bounded.slice(0, limit).map((r) => this.promiseView(ctx, r));
    let next: string | null = null;
    if (bounded.length > limit) {
      const lastOrd = store.promiseOrdinal(items[items.length - 1]!.commit_id);
      next = this.encodeCursor({ kind: "list", principal: ctx.actor, capability: ctx.capability.capability, state, snapshot_max: String(snapshotMax), last_ordinal: String(lastOrd), exp: String(ctx.now + 300000n) });
    }
    return { items, next_cursor: next };
  }

  private eventList(ctx: CallCtx, commitId: string, afterSeq: bigint, limit: number): { events: T.SignedEvent[]; next_seq: string } {
    this.partyOrScoped(ctx, commitId);
    const rows = this.deps.store.listEvents(commitId, afterSeq, limit);
    const events = rows.map((r) => this.signedEventOf(r));
    const next = events.length ? events[events.length - 1]!.body.seq : String(afterSeq);
    return { events, next_seq: next };
  }

  private signedEventOf(r: { canonical_body: Buffer; event_hash: string; key_id: string; signature: string }): T.SignedEvent {
    const raw = r.canonical_body as unknown as string | Uint8Array;
    const body = parseStrictJson(typeof raw === "string" ? raw : Buffer.from(raw).toString("utf8")) as unknown as T.EventBody;
    return { body, hash: r.event_hash, key_id: r.key_id, signature: r.signature };
  }

  private objectGet(ctx: CallCtx, objectId: string): { object: string; kind: T.ObjectKind; body: T.ObjectBody } {
    const store = this.deps.store;
    const row = store.getObject(objectId);
    if (!row) throw err("NOT_FOUND", "object not found");
    if (!this.objectVisible(ctx, row)) throw err("NOT_FOUND", "object not found");
    return { object: row.object_id, kind: row.kind, body: row.body };
  }

  private objectVisible(ctx: CallCtx, row: ObjectRow): boolean {
    const store = this.deps.store;
    const partyTo = (commitId: string | null): boolean => {
      if (!commitId) return false;
      const p = store.getPromise(commitId);
      if (!p) return false;
      return ctx.actor === p.payer || ctx.actor === p.payee || ctx.capability.commit_ids.includes(commitId);
    };
    if (row.scope_commit && partyTo(row.scope_commit)) return true;
    if (row.owner !== null) return row.owner === ctx.actor;
    if (row.kind === "custody") {
      const op = store.db.prepare("SELECT commit_id FROM operations WHERE operation_id = ?").get((row.body as T.CustodyReceipt).body.operation_id) as { commit_id: string } | undefined;
      return partyTo(op?.commit_id ?? null) || ctx.capability.methods.includes("custody.reconcile");
    }
    // unscoped system objects (chunks, manifests, policies): any object.get capability
    return true;
  }

  private accountGet(ctx: CallCtx, principal: string, asset: T.Asset): T.AccountResult {
    const store = this.deps.store;
    const auditor = ctx.capability.methods.includes("proof.export");
    if (ctx.actor !== principal && !auditor) throw err("NOT_FOUND", "account not found");
    const acc = store.getAccount(ctx.custody.custody, asset.code, principal);
    if (!acc) throw err("NOT_FOUND", "account not found");
    // exposed: payer-side outstanding exposure; held: escrow-held attributable to nonterminal promises
    let exposed = 0n; let held = 0n;
    const rows = store.db.prepare(
      "SELECT e.amount, e.status, p.payer, p.payee FROM exposure e JOIN promises p ON p.commit_id = e.commit_id",
    ).all() as { amount: bigint | number; status: string; payer: string; payee: string }[];
    for (const r of rows) {
      const amt = BigInt(r.amount);
      if (r.payer === principal) exposed += amt;
      if ((r.payer === principal || r.payee === principal) && r.status === "held") held += amt;
    }
    return {
      principal, asset,
      available_minor: String(acc.available_minor), exposed_minor: String(exposed), held_minor: String(held),
    };
  }

  private controlStatus(_ctx: CallCtx): T.ControlStatus {
    const store = this.deps.store;
    const meta = store.getMeta()!;
    return {
      status: store.getControlState().status, revision: String(meta.control_revision),
      revoked_keys: store.revokedKeys(), active_policy: meta.active_policy,
    };
  }

  private healthGet(ctx: CallCtx): T.HealthResult {
    const store = this.deps.store;
    const storage = this.deps.storageOk() ? "ok" : "failed";
    const clock = ctx.clockSafe ? "ok" : "unsafe";
    const custody = ctx.adapter === null || ctx.localCustody ? "ok" : "ok";
    const halted = store.getControlState().status === "HALTED";
    return { ready: storage === "ok" && clock === "ok" && custody === "ok" && !halted, storage, clock, custody, protocol: "commit/1" };
  }

  // ---------- cursors (encrypted, authorization-bound) ----------

  private encodeCursor(payload: Record<string, string | null>): string {
    const nonce = crypto.randomBytes(12);
    const key = crypto.createHash("sha256").update(this.deps.cursorSecret).digest();
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    const pt = Buffer.from(jcs(payload as Json), "utf8");
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, ct]).toString("base64url");
  }

  private decodeCursor(cursor: string, ctx: CallCtx): Record<string, string | null> {
    try {
      const raw = decodeBase64urlCanonical(cursor);
      if (raw.length < 29) throw new Error("short");
      const key = crypto.createHash("sha256").update(this.deps.cursorSecret).digest();
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
      decipher.setAuthTag(raw.subarray(12, 28));
      const pt = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
      const payload = parseStrictJson(pt) as Record<string, string | null>;
      if (payload.principal !== ctx.actor || payload.capability !== ctx.capability.capability) {
        throw err("CURSOR_INVALID", "cursor bound to a different authorization");
      }
      if (BigInt(payload.exp ?? "0") < ctx.now) throw err("CURSOR_INVALID", "cursor expired");
      return payload;
    } catch (e) {
      if ((e as { code?: string }).code === "CURSOR_INVALID") throw e;
      throw err("CURSOR_INVALID", "cursor does not decode");
    }
  }
}

export function currentRevisionOf(store: Store, commitId: string): string {
  const p = store.getPromise(commitId);
  return p ? String(p.revision) : "0";
}
