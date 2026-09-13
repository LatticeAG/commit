// Custody operation automaton (§2.3): receipt ingestion, reconcile, retry,
// dispatch, and restart recovery.

import { D, edVerify, H } from "../crypto.ts";
import { err } from "../errors.ts";
import { jcsBytes } from "../json/jcs.ts";
import type { Json } from "../json/strict.ts";
import { parseStrictJson } from "../json/strict.ts";
import { u64 } from "../scalars.ts";
import type { OperationRow } from "../store.ts";
import type * as T from "../types.ts";
import { admitSystemObject, emitEvent, insertAuditDelivery, lastEventSeq, recordIncident, requireClockSafe, safetyHalt } from "./core.ts";
import { decideSettlement, applyReserveLedger, applySettleLedger, envelopeOf, promiseAdvance, type CallCtx } from "./methods.ts";

export function operationView(op: OperationRow): T.OperationView {
  return {
    operation_id: op.operation_id as T.Id, state: op.state, request_hash: op.request_hash as T.Digest,
    attempts: op.attempts, last_receipt: op.last_receipt as T.Id | null,
  };
}

function receiptRequest(op: OperationRow): T.CustodyRequest {
  const raw = op.canonical_request as unknown as string | Uint8Array;
  const text = typeof raw === "string" ? raw : Buffer.from(raw).toString("utf8");
  return parseStrictJson(text) as unknown as T.CustodyRequest;
}

function conflict(ctx: CallCtx, op: OperationRow, receiptObjId: string, receipt: T.CustodyReceipt, what: string): never {
  // The halt itself is applied by ingestReceiptGuarded in a separate committed
  // transaction; this throw only aborts the mutating command.
  throw new CustodyConflict(what, H(jcsBytes(receipt as unknown as Json)));
}

/** Thrown inside the mutating tx; the halt is committed by the guard below. */
export class CustodyConflict extends Error {
  readonly code = "CUSTODY_CONFLICT";
  readonly retryable = false;
  readonly currentRevision = null;
  readonly evidenceDigest: string;
  constructor(message: string, evidenceDigest: string) { super(message); this.name = "CustodyConflict"; this.evidenceDigest = evidenceDigest; }
}

/**
 * Run receipt ingestion in its own transaction. On CUSTODY_CONFLICT, commit a
 * separate halt transaction (incident + SafetyHalted) so the safety halt
 * survives the rejected command — the only permitted economic side effect.
 */
export function ingestReceiptGuarded(ctx: CallCtx, op: OperationRow, objectId: string, receipt: T.CustodyReceipt): { events: string[]; view: T.OperationView } {
  try {
    return ctx.store.tx(() => ingestReceipt(ctx, op, objectId, receipt));
  } catch (e) {
    if (e instanceof CustodyConflict) {
      ctx.store.tx(() => {
        const incId = recordIncident(ctx, "CUSTODY_CONFLICT", e.evidenceDigest, ctx.now);
        safetyHalt(ctx, "custody", incId, ctx.now);
      });
    }
    throw e;
  }
}

/**
 * Validate a receipt's signature + bindings against a known operation.
 * Returns the stored object id when the receipt is a verbatim replay.
 */
function validateReceiptBinding(ctx: CallCtx, op: OperationRow, objectId: string | null, receipt: T.CustodyReceipt): void {
  const b = receipt.body;
  const request = receiptRequest(op);
  if (b.custody !== ctx.custody.custody || b.operation_id !== op.operation_id || b.escrow_id !== request.escrow_id) {
    throw err("RECEIPT_INVALID", "receipt does not bind this custody domain/operation");
  }
  if (b.request_hash !== op.request_hash || b.request_hash !== D("custody", request as unknown as Json)) {
    throw err("RECEIPT_INVALID", "receipt request_hash mismatch");
  }
  if (u64(b.amount_minor) !== u64(request.amount_minor)) throw err("RECEIPT_INVALID", "receipt amount mismatch");
  if (request.kind === "reserve") {
    if (b.allocation !== null) throw err("RECEIPT_INVALID", "reserve receipt must carry null allocation");
  } else {
    const want = request.allocation!;
    const got = b.allocation;
    if (!got || u64(got.pay_minor) !== u64(want.pay_minor) || u64(got.return_minor) !== u64(want.return_minor)) {
      throw err("RECEIPT_INVALID", "allocation receipt must equal the selected allocation exactly");
    }
  }
  if (!edVerify("custody", b as unknown as Json, ctx.custody.receipt_key, receipt.signature)) {
    throw err("RECEIPT_INVALID", "receipt signature does not verify under the pinned custody key");
  }
  if (b.attempt < 1 || b.attempt > 3) throw err("RECEIPT_INVALID", "attempt out of range");
  if (objectId) void objectId;
}

/**
 * Core receipt admission (§2.3). Caller holds the transaction.
 * Returns emitted event kinds; throws protocol errors.
 */
export function ingestReceipt(ctx: CallCtx, op: OperationRow, objectId: string, receipt: T.CustodyReceipt): { events: string[]; view: T.OperationView } {
  const store = ctx.store;
  const b = receipt.body;
  const p = store.getPromise(op.commit_id)!;
  const bodyHash = H(jcsBytes(b as unknown as Json));
  const events: string[] = [];

  // same-revision handling
  const existing = store.getReceipt(op.operation_id, b.provider_revision);
  if (existing) {
    if (existing.body_hash === bodyHash) {
      return { events: [], view: operationView(store.getOperation(op.operation_id)!) }; // idempotent observation
    }
    conflict(ctx, op, objectId, receipt, "conflicting bytes at one provider revision");
  }

  // terminal-operation handling: any different final outcome after APPLIED/NO_EFFECT/BLOCKED is a conflict
  const priorFinal = store.hasFinalReceipt(op.operation_id);
  if (priorFinal && (op.state === "APPLIED" || op.state === "NO_EFFECT" || op.state === "BLOCKED")) {
    const priorStatus = priorFinal.status;
    const newIsFinalOther = b.final && b.status !== priorStatus;
    if (newIsFinalOther) conflict(ctx, op, objectId, receipt, "conflicting terminal outcomes for one operation");
    if (!b.final && BigInt(b.provider_revision) < BigInt(priorFinal.provider_revision)) {
      return { events: [], view: operationView(store.getOperation(op.operation_id)!) }; // unseen regressing observation: quarantine, no state change
    }
  }

  // monotone provider revision
  const latest = store.latestReceipt(op.operation_id);
  if (latest && BigInt(b.provider_revision) < BigInt(latest.provider_revision)) {
    return { events: [], view: operationView(store.getOperation(op.operation_id)!) }; // quarantined regression
  }

  validateReceiptBinding(ctx, op, objectId, receipt);
  store.putReceipt({ operation_id: op.operation_id, provider_revision: b.provider_revision, attempt: b.attempt, body_hash: bodyHash, object_id: objectId, final: b.final ? 1 : 0, status: b.status });
  store.updateOperation(op.operation_id, { last_provider_revision: b.provider_revision, last_receipt: objectId });

  const isReserve = op.kind === "reserve";
  const uncertainEvent = isReserve ? "FundingUncertain" : "SettlementUncertain";
  const unknownPromiseState: T.State = isReserve ? "FUNDING_UNKNOWN" : "SETTLEMENT_UNKNOWN";

  if (b.status === "applied" && b.final) {
    if (isReserve) {
      requireClockSafe(ctx.clockSafe); // reserve receipts are time-dependent
      const e = envelopeOf(ctx, p);
      const escrowId = receiptRequest(op).escrow_id;
      store.updateOperation(op.operation_id, { state: "APPLIED" });
      store.deleteOutbox(op.operation_id);
      const ev = emitEvent(ctx, p.commit_id, p.state, "ACTIVE", ctx.commandId, ctx.now,
        { kind: "EscrowHeld", receipt: objectId as T.Id, escrow_id: escrowId }, [objectId]);
      applyReserveLedger(ctx, store, p, BigInt(ev.body.seq));
      store.updateExposure(p.commit_id, { status: "held" });
      const late = ctx.now >= u64(e.fund_by_ms);
      if (!late) {
        store.updatePromise(p.commit_id, { state: "ACTIVE", revision: BigInt(ev.body.seq), escrow_id: escrowId, next_due_ms: u64(e.condition_by_ms) });
        events.push("EscrowHeld");
      } else {
        // late funding: emit EscrowHeld into ACTIVE, then funding_late disposition
        store.updatePromise(p.commit_id, { state: "ACTIVE", revision: BigInt(ev.body.seq), escrow_id: escrowId });
        events.push("EscrowHeld");
        if (store.getControlState().status === "HALTED") {
          // halt prohibits disposition selection; the first safe advance picks funding_late
          store.updatePromise(p.commit_id, { late_pending: 1 });
        } else {
          const out = decideSettlement(ctx, store.getPromise(p.commit_id)!, "funding_late", null, { pay_minor: "0", return_minor: e.amount_minor });
          events.push(...out.events);
        }
      }
      insertAuditDelivery(ctx, p.commit_id, store.lastEvent(p.commit_id)!.seq, store.lastEvent(p.commit_id)!.event_hash);
      return { events, view: operationView(store.getOperation(op.operation_id)!) };
    }
    // allocate applied: deadline-independent confirmation
    store.updateOperation(op.operation_id, { state: "APPLIED" });
    store.deleteOutbox(op.operation_id);
    const allocation = receiptRequest(op).allocation!;
    const ev = emitEvent(ctx, p.commit_id, p.state, "SETTLED", ctx.commandId, ctx.now,
      { kind: "Settled", receipt: objectId as T.Id, allocation }, [objectId]);
    applySettleLedger(ctx, store, p, allocation, BigInt(ev.body.seq));
    store.deleteExposure(p.commit_id);
    store.updatePromise(p.commit_id, { state: "SETTLED", revision: BigInt(ev.body.seq), next_due_ms: null });
    events.push("Settled");
    insertAuditDelivery(ctx, p.commit_id, BigInt(ev.body.seq), ev.hash);
    return { events, view: operationView(store.getOperation(op.operation_id)!) };
  }

  if (b.status === "no_effect" && b.final) {
    if (isReserve) {
      store.updateOperation(op.operation_id, { state: "NO_EFFECT" });
      store.deleteOutbox(op.operation_id);
      const ev = emitEvent(ctx, p.commit_id, p.state, "UNFUNDED", ctx.commandId, ctx.now,
        { kind: "FundingFailed", receipt: objectId as T.Id, reason: "no_effect" }, [objectId]);
      store.deleteExposure(p.commit_id);
      store.updatePromise(p.commit_id, { state: "UNFUNDED", revision: BigInt(ev.body.seq), next_due_ms: null });
      events.push("FundingFailed");
      insertAuditDelivery(ctx, p.commit_id, BigInt(ev.body.seq), ev.hash);
      return { events, view: operationView(store.getOperation(op.operation_id)!) };
    }
    store.updateOperation(op.operation_id, { state: "BLOCKED" });
    store.deleteOutbox(op.operation_id);
    const ev = emitEvent(ctx, p.commit_id, p.state, "SETTLEMENT_BLOCKED", ctx.commandId, ctx.now,
      { kind: "SettlementBlocked", receipt: objectId as T.Id, reason: "no_effect" }, [objectId]);
    store.updatePromise(p.commit_id, { state: "SETTLEMENT_BLOCKED", revision: BigInt(ev.body.seq), next_due_ms: null });
    events.push("SettlementBlocked");
    insertAuditDelivery(ctx, p.commit_id, BigInt(ev.body.seq), ev.hash);
    return { events, view: operationView(store.getOperation(op.operation_id)!) };
  }

  // nonfinal observations
  if (b.status === "pending") {
    const ev = emitEvent(ctx, p.commit_id, p.state, p.state, ctx.commandId, ctx.now,
      { kind: "CustodyObservation", receipt: objectId as T.Id }, [objectId]);
    store.updatePromise(p.commit_id, { revision: BigInt(ev.body.seq) });
    events.push("CustodyObservation");
    insertAuditDelivery(ctx, p.commit_id, BigInt(ev.body.seq), ev.hash);
    return { events, view: operationView(store.getOperation(op.operation_id)!) };
  }

  // status === "unknown" (nonfinal)
  if (op.state === "DISPATCHED" || op.state === "READY") {
    store.updateOperation(op.operation_id, { state: "UNKNOWN" });
    const ev = emitEvent(ctx, p.commit_id, p.state, unknownPromiseState, ctx.commandId, ctx.now,
      { kind: uncertainEvent === "FundingUncertain" ? "FundingUncertain" : "SettlementUncertain", operation_id: op.operation_id as T.Id, reason: "transport" } as T.EventData, [objectId]);
    store.updatePromise(p.commit_id, { state: unknownPromiseState, revision: BigInt(ev.body.seq), next_due_ms: null });
    events.push(uncertainEvent);
  } else {
    const ev = emitEvent(ctx, p.commit_id, p.state, p.state, ctx.commandId, ctx.now,
      { kind: "CustodyObservation", receipt: objectId as T.Id }, [objectId]);
    store.updatePromise(p.commit_id, { revision: BigInt(ev.body.seq) });
    events.push("CustodyObservation");
  }
  insertAuditDelivery(ctx, p.commit_id, store.lastEvent(p.commit_id)!.seq, store.lastEvent(p.commit_id)!.event_hash);
  return { events, view: operationView(store.getOperation(op.operation_id)!) };
}

// ---------- custody.reconcile ----------

export async function custodyReconcile(ctx: CallCtx, operationId: string, receiptObjectId: string | null): Promise<T.OperationView> {
  const store = ctx.store;
  const op = store.getOperation(operationId);
  if (!op) throw err("NOT_FOUND", "operation not found");

  if (receiptObjectId === null) {
    // authoritative lookup of the original operation
    if (!ctx.adapter) throw err("PROVIDER_UNKNOWN", "no external custody adapter configured");
    const outcome = await ctx.adapter.lookup(op.operation_id, op.request_hash, op.attempts);
    if (outcome.status === "error") {
      if (outcome.error.code === "PROVIDER_UNKNOWN") throw err("PROVIDER_UNKNOWN", "provider lookup unavailable", { retryable: true });
      throw err(outcome.error.code, outcome.error.message);
    }
    if (outcome.status === "inconclusive") throw err("PROVIDER_UNKNOWN", "provider lookup inconclusive", { retryable: true });
    if (outcome.status === "none") return operationView(op);
    const rc = outcome.receipt;
    const objId = `rc_${op.operation_id}_${rc.body.provider_revision}_${rc.body.status}`;
    store.tx(() => admitSystemObject(ctx, objId, "custody", rc, ctx.now));
    return ingestReceiptGuarded(ctx, op, objId, rc).view;
  }

  const obj = store.getObject(receiptObjectId);
  if (!obj || obj.kind !== "custody") throw err("NOT_FOUND", "receipt object not found");
  const receipt = obj.body as T.CustodyReceipt;
  return ingestReceiptGuarded(ctx, op, receiptObjectId, receipt).view;
}

// ---------- custody.retry ----------

export async function custodyRetry(ctx: CallCtx, operationId: string, noEffectReceiptId: string): Promise<T.OperationView> {
  const store = ctx.store;
  const op = store.getOperation(operationId);
  if (!op) throw err("NOT_FOUND", "operation not found");

  // §2.3 preconditions are evaluated before transition existence.
  const pre = () => {
    if (ctx.custody.retry_mode !== "sequenced-no-effect/1") return "manifest does not declare sequenced-no-effect/1";
    const obj = store.getObject(noEffectReceiptId);
    if (!obj || obj.kind !== "custody") return "presented object is not a custody receipt";
    const rc = obj.body as T.CustodyReceipt;
    const b = rc.body;
    if (b.operation_id !== op.operation_id || b.status !== "no_effect" || !b.final || b.attempt !== op.attempts) {
      return "receipt is not the signed final no_effect for the latest attempt";
    }
    if (b.request_hash !== op.request_hash || !edVerify("custody", b as unknown as Json, ctx.custody.receipt_key, rc.signature)) {
      return "receipt does not verify against this operation";
    }
    return null;
  };
  const preErr = pre();
  if (preErr) throw err("RETRY_UNSAFE", preErr);
  // provider dedup horizon retained + conclusive authoritative lookup
  if (!ctx.adapter) throw err("RETRY_UNSAFE", "no custody adapter to prove retained dedup identity");
  const lookup = await ctx.adapter.lookup(op.operation_id, op.request_hash, op.attempts);
  if (lookup.status !== "receipt") throw err("RETRY_UNSAFE", "provider dedup horizon or lookup is not conclusive");
  if (op.attempts >= 3) throw err("RETRY_UNSAFE", "attempt budget exhausted");

  // transition existence: only a precondition-valid retry against a non-BLOCKED op is STATE_CONFLICT
  if (op.state !== "BLOCKED") throw err("STATE_CONFLICT", "retry requires a BLOCKED operation");
  if (store.getControlState().status === "HALTED") throw err("HALTED", "custody.retry is a mutation outside the halt permit list");

  return store.tx(() => {
    const p = store.getPromise(op.commit_id)!;
    store.updateOperation(op.operation_id, { state: "READY" });
    store.putOutbox(op.operation_id, op.request_hash, "READY", u64(ctx.writerEpoch), null);
    const ev = emitEvent(ctx, p.commit_id, "SETTLEMENT_BLOCKED", "SETTLING", ctx.commandId, ctx.now,
      { kind: "SettlementRetried", operation_id: op.operation_id as T.Id, receipt: noEffectReceiptId as T.Id }, [noEffectReceiptId]);
    store.updatePromise(p.commit_id, { state: "SETTLING", revision: BigInt(ev.body.seq), next_due_ms: null });
    insertAuditDelivery(ctx, p.commit_id, BigInt(ev.body.seq), ev.hash);
    return operationView(store.getOperation(op.operation_id)!);
  });
}

// ---------- dispatch worker (§2.3 READY → DISPATCHED → outcomes) ----------

export interface DispatchReport { dispatched: string[]; uncertain: string[]; expired: string[]; errors: string[] }

export async function dispatchTick(ctx: CallCtx): Promise<DispatchReport> {
  const store = ctx.store;
  const report: DispatchReport = { dispatched: [], uncertain: [], expired: [], errors: [] };
  if (store.getControlState().status === "HALTED") return report;
  if (!ctx.clockSafe) return report;
  if (!ctx.adapter) return report;

  for (const row of store.readyOutbox(ctx.now)) {
    const op = store.getOperation(row.operation_id)!;
    const request = receiptRequest(op);
    // reserve expiry before any dispatch → locally provable no-effect
    if (request.kind === "reserve" && request.not_after_ms !== null && u64(request.not_after_ms) <= ctx.now) {
      store.tx(() => {
        const p = store.getPromise(op.commit_id)!;
        store.updateOperation(op.operation_id, { state: "NO_EFFECT" });
        store.deleteOutbox(op.operation_id);
        const ev = emitEvent(ctx, op.commit_id, p.state, "UNFUNDED", `sys_${op.commit_id}_${lastEventSeq(store, op.commit_id) + 1n}`, ctx.now,
          { kind: "FundingFailed", receipt: null, reason: "unsent_expiry" }, []);
        store.deleteExposure(op.commit_id);
        store.updatePromise(op.commit_id, { state: "UNFUNDED", revision: BigInt(ev.body.seq), next_due_ms: null });
      });
      report.expired.push(op.operation_id);
      continue;
    }
    // persist dispatch marker + attempt before the send, and take the row out
    // of the READY set so a later tick can never re-send a dispatched operation
    const attempt = store.tx(() => {
      const cur = store.getOperation(op.operation_id)!;
      const n = cur.attempts + 1;
      if (n > 3) throw err("RETRY_UNSAFE", "attempt budget exhausted");
      store.updateOperation(op.operation_id, { state: "DISPATCHED", attempts: n, first_dispatch_ms: cur.first_dispatch_ms ?? ctx.now });
      store.updateOutbox(op.operation_id, "DISPATCHED", null);
      return n;
    });
    let outcome;
    try {
      outcome = await ctx.adapter.invoke(request, attempt, null, ctx.writerEpoch);
    } catch (e) {
      outcome = { status: "timeout" as const };
    }
    if (outcome.status === "inflight") {
      report.dispatched.push(op.operation_id);
      continue;
    }
    if (outcome.status === "timeout" || (outcome.status === "error" && outcome.error.code === "PROVIDER_UNKNOWN")) {
      store.tx(() => {
        const p = store.getPromise(op.commit_id)!;
        const toState: T.State = op.kind === "reserve" ? "FUNDING_UNKNOWN" : "SETTLEMENT_UNKNOWN";
        const kind = op.kind === "reserve" ? "FundingUncertain" : "SettlementUncertain";
        store.updateOperation(op.operation_id, { state: "UNKNOWN" });
        const ev = emitEvent(ctx, op.commit_id, p.state, toState, `sys_${op.commit_id}_${lastEventSeq(store, op.commit_id) + 1n}`, ctx.now,
          { kind, operation_id: op.operation_id as T.Id, reason: "transport" } as T.EventData, []);
        store.updatePromise(op.commit_id, { state: toState, revision: BigInt(ev.body.seq), next_due_ms: null });
      });
      report.uncertain.push(op.operation_id);
      continue;
    }
    if (outcome.status === "error") {
      report.errors.push(`${op.operation_id}:${outcome.error.code}`);
      continue;
    }
    // receipt outcome
    const rc = outcome.receipt;
    const objId = `rc_${op.operation_id}_${rc.body.provider_revision}_${rc.body.status}`;
    store.tx(() => admitSystemObject(ctx, objId, "custody", rc, ctx.now));
    ingestReceiptGuarded(ctx, op, objId, rc);
    report.dispatched.push(op.operation_id);
  }
  return report;
}

// ---------- lookup worker (DISPATCHED/UNKNOWN → authoritative lookup) ----------

export interface LookupReport { resolved: string[]; uncertain: string[]; inconclusive: string[]; errors: string[] }

/** Poll the adapter for dispatched/unknown operations; ingest or mark uncertain. */
export async function lookupTick(ctx: CallCtx): Promise<LookupReport> {
  const store = ctx.store;
  const report: LookupReport = { resolved: [], uncertain: [], inconclusive: [], errors: [] };
  if (store.getControlState().status === "HALTED") return report;
  if (!ctx.adapter) return report;
  const rows = store.db.prepare("SELECT operation_id FROM operations WHERE state IN ('DISPATCHED','UNKNOWN')").all() as { operation_id: string }[];
  for (const { operation_id } of rows) {
    const op = store.getOperation(operation_id)!;
    let outcome;
    try {
      outcome = await ctx.adapter.lookup(op.operation_id, op.request_hash, op.attempts);
    } catch {
      outcome = { status: "error" as const, error: { code: "PROVIDER_UNKNOWN", retryable: true, message: "lookup failed", current_revision: null } };
    }
    if (outcome.status === "error" || outcome.status === "inconclusive") {
      // transition DISPATCHED → UNKNOWN once; already-UNKNOWN stays without re-emitting
      if (op.state === "DISPATCHED") {
        store.tx(() => {
          const p = store.getPromise(op.commit_id)!;
          const toState: T.State = op.kind === "reserve" ? "FUNDING_UNKNOWN" : "SETTLEMENT_UNKNOWN";
          const kind = op.kind === "reserve" ? "FundingUncertain" : "SettlementUncertain";
          store.updateOperation(op.operation_id, { state: "UNKNOWN" });
          const ev = emitEvent(ctx, op.commit_id, p.state, toState, `sys_${op.commit_id}_${lastEventSeq(store, op.commit_id) + 1n}`, ctx.now,
            { kind, operation_id: op.operation_id as T.Id, reason: "transport" } as T.EventData, []);
          store.updatePromise(op.commit_id, { state: toState, revision: BigInt(ev.body.seq), next_due_ms: null });
        });
        report.uncertain.push(operation_id);
      } else {
        report.inconclusive.push(operation_id);
      }
      continue;
    }
    if (outcome.status === "none") continue;
    const rc = outcome.receipt;
    const objId = `rc_${op.operation_id}_${rc.body.provider_revision}_${rc.body.status}`;
    store.tx(() => admitSystemObject(ctx, objId, "custody", rc, ctx.now));
    ingestReceiptGuarded(ctx, op, objId, rc);
    report.resolved.push(operation_id);
  }
  return report;
}

// ---------- timer worker ----------

export function timerTick(ctx: CallCtx): { advanced: string[]; errors: { commit_id: string; code: string }[] } {
  const store = ctx.store;
  const out = { advanced: [] as string[], errors: [] as { commit_id: string; code: string }[] };
  if (!ctx.clockSafe) return out;
  if (store.getControlState().status === "HALTED") return out;
  for (const p of store.duePromises(ctx.now)) {
    try {
      const seq = lastEventSeq(store, p.commit_id) + 1n;
      const sub: CallCtx = { ...ctx, actor: p.payer as T.Id, commandId: `sys_${p.commit_id}_${seq}` };
      store.tx(() => promiseAdvance(sub, p.commit_id, p.revision));
      out.advanced.push(p.commit_id);
    } catch (e) {
      out.errors.push({ commit_id: p.commit_id, code: (e as { code?: string }).code ?? "INTERNAL" });
    }
  }
  return out;
}

// ---------- restart recovery ----------

/**
 * Re-scan durable operation markers after restart. Emits exactly one
 * FundingUncertain/SettlementUncertain per operation whose promise is not
 * already in the matching UNKNOWN state. Performs no sends.
 */
export function recoverAfterRestart(ctx: CallCtx): { uncertain: string[] } {
  const store = ctx.store;
  const out = { uncertain: [] as string[] };
  const rows = store.db.prepare("SELECT operation_id FROM operations WHERE state IN ('DISPATCHED','UNKNOWN')").all() as { operation_id: string }[];
  for (const { operation_id } of rows) {
    const op = store.getOperation(operation_id)!;
    const p = store.getPromise(op.commit_id)!;
    const wantState: T.State = op.kind === "reserve" ? "FUNDING_UNKNOWN" : "SETTLEMENT_UNKNOWN";
    if (p.state === wantState) continue; // already unknown for this operation
    if (op.state === "APPLIED" || op.state === "NO_EFFECT" || op.state === "BLOCKED") continue;
    if (p.state === "SETTLED" || p.state === "UNFUNDED") continue;
    store.tx(() => {
      const cur = store.getPromise(op.commit_id)!;
      const curOp = store.getOperation(operation_id)!;
      if (cur.state === wantState || curOp.state === "APPLIED" || curOp.state === "NO_EFFECT") return;
      if (curOp.state === "DISPATCHED") store.updateOperation(operation_id, { state: "UNKNOWN" });
      const kind = op.kind === "reserve" ? "FundingUncertain" : "SettlementUncertain";
      const ev = emitEvent(ctx, op.commit_id, cur.state, wantState, `sys_${op.commit_id}_${lastEventSeq(store, op.commit_id) + 1n}`, ctx.now,
        { kind, operation_id: operation_id as T.Id, reason: "restart" } as T.EventData, []);
      store.updatePromise(op.commit_id, { state: wantState, revision: BigInt(ev.body.seq), next_due_ms: null });
    });
    out.uncertain.push(operation_id);
  }
  return out;
}
