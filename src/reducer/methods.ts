// Promise/custody reducers — the §2 state machines applied inside
// BEGIN IMMEDIATE transactions, honoring the §3.1 error ordering:
//   existence → idempotency/business → revision → transition → safety →
//   deadline → authority → condition/award validity → economic.

import { D, edSign, edVerify, H } from "../crypto.ts";
import { err } from "../errors.ts";
import { jcsBytes } from "../json/jcs.ts";
import type { Json } from "../json/strict.ts";
import { u64 } from "../scalars.ts";
import type { Store, PromiseRow } from "../store.ts";
import type * as T from "../types.ts";
import { decodeBase64urlCanonical } from "../scalars.ts";
import { validateEnvelopeSemantics } from "../objects.ts";
import {
  admitObject, admitSystemObject, emitEvent, insertAuditDelivery,
  recordIncident, requireClockSafe, requireRunning, safetyHalt,
  type Ctx,
} from "./core.ts";

export interface CallCtx extends Ctx {
  now: bigint;          // validated admission timestamp for this command
  wallNow: bigint;
  clockSafe: boolean;
  actor: T.Id;          // authenticated principal ("" for system workers)
  capability: T.Capability;
  commandId: string;    // request_id or sys_<stream>_<seq>
}

export interface MutationOutcome {
  result: unknown;
  events: string[];
}

// ---------- helpers ----------

export function envelopeOf(ctx: Ctx, p: PromiseRow): T.Envelope {
  const row = ctx.store.getObject(p.envelope_object);
  if (!row) throw err("OBJECT_MISSING", "envelope object missing");
  return row.body as T.Envelope;
}

export function memberMap(policy: T.Policy): Map<string, T.Member> {
  return new Map(policy.members.map((m) => [m.key_id, m]));
}

export function escrowIdFor(envelopeHash: string): string {
  return `e_${envelopeHash.slice(0, 32)}`;
}

export function operationIdsFor(envelopeHash: string): { reserve: string; allocate: string } {
  return { reserve: `r_${envelopeHash.slice(0, 32)}`, allocate: `s_${envelopeHash.slice(0, 32)}` };
}

function utcDay(ms: bigint): bigint {
  return ms / 86400000n;
}

/** Revision gate (§3.1 stage 7). */
function checkRevision(p: PromiseRow, expected: bigint): void {
  if (p.revision !== expected) {
    throw err("STALE_REVISION", `expected revision ${expected}, current ${p.revision}`, { currentRevision: String(p.revision) });
  }
}

/** Distinct non-revoked principals signed under a role roster + mandatory + threshold. */
export function quorumCheck(
  ctx: Ctx,
  quorum: T.Quorum,
  signerKeyIds: string[],
): { ok: boolean; distinctPrincipals: Set<string>; excludedRevoked: string[] } {
  const members = memberMap(ctx.policy);
  const roster = new Set(quorum.keys);
  const principals = new Set<string>();
  const excluded: string[] = [];
  for (const keyId of signerKeyIds) {
    if (!roster.has(keyId)) continue;
    const m = members.get(keyId);
    if (!m) continue;
    if (ctx.store.isKeyRevoked(keyId)) {
      excluded.push(keyId);
      continue;
    }
    principals.add(m.principal);
  }
  const mandatoryOk = quorum.mandatory_principals.every((mp) => principals.has(mp));
  return { ok: principals.size >= quorum.threshold && mandatoryOk, distinctPrincipals: principals, excludedRevoked: excluded };
}

function flushAudit(ctx: CallCtx, store: Store, commitId: string): void {
  const last = store.lastEvent(commitId);
  if (last) insertAuditDelivery(ctx, commitId, last.seq, last.event_hash);
}

// ---------- object.put ----------

export function objectPut(ctx: CallCtx, objectId: string, kind: T.ObjectKind, rawBody: unknown): MutationOutcome {
  if (kind === "trust" || kind === "migration") {
    throw err("FORBIDDEN", `kind ${kind} is never accepted via object.put`);
  }
  if (!ctx.capability.object_kinds.includes(kind)) throw err("FORBIDDEN", `capability cannot put kind ${kind}`);
  const r = admitObject(ctx, objectId, kind, rawBody, ctx.actor, ctx.now);
  return { result: { object: r.object, digest: r.digest, bytes: r.bytes }, events: [] };
}

// ---------- promise.propose ----------

export function promisePropose(ctx: CallCtx, envelopeObjectId: string): MutationOutcome {
  const store = ctx.store;
  const obj = store.getObject(envelopeObjectId);
  if (!obj || obj.kind !== "envelope") throw err("NOT_FOUND", "envelope object not found");
  const e = obj.body as T.Envelope;

  // capability scope (needs the envelope): caller is the payer, commit in scope, amount bounded
  if (ctx.actor !== e.payer) throw err("FORBIDDEN", "proposer must be the envelope payer");
  if (!ctx.capability.commit_ids.includes(e.commit_id)) throw err("FORBIDDEN", "commit_id outside capability scope");
  if (u64(e.amount_minor) > u64(ctx.capability.max_amount_minor)) throw err("FORBIDDEN", "amount exceeds capability bound");

  // business-key uniqueness (includes commit_id collision)
  if (store.getPromise(e.commit_id) !== null || store.getPromiseByBusiness(e.tenant, e.environment, e.business_id) !== null) {
    throw err("BUSINESS_CONFLICT", "business key or commit_id already bound");
  }

  requireRunning(store);
  requireClockSafe(ctx.clockSafe);

  // admission validity: §1.2 semantic refinements incl. deadline ordering and
  // the active-policy pin (POLICY_INACTIVE on a non-active hash)
  validateEnvelopeSemantics(e, ctx.policy, ctx.now);

  const emitted = emitEvent(ctx, e.commit_id, null, "PROPOSED", ctx.commandId, ctx.now,
    { kind: "Proposed", envelope: envelopeObjectId as T.Id, envelope_hash: D("envelope", e as unknown as Json) as T.Digest, business_id: e.business_id },
    [envelopeObjectId]);

  store.putPromise({
    commit_id: e.commit_id, tenant: e.tenant, environment: e.environment, business_id: e.business_id,
    envelope_object: envelopeObjectId, envelope_hash: D("envelope", e as unknown as Json), state: "PROPOSED",
    revision: 1n, payer: e.payer, payee: e.payee, amount: u64(e.amount_minor),
    release_at: null, decision_by: null, allocation: null, disposition: null,
    next_due_ms: u64(e.commit_by_ms), escrow_id: null, case_id: null, late_pending: 0, consumed: 0,
  });
  store.markObjectReferenced(envelopeObjectId, e.commit_id);
  flushAudit(ctx, store, e.commit_id);
  return { result: { commit_id: e.commit_id, state: "PROPOSED", revision: "1", events: ["Proposed"] }, events: ["Proposed"] };
}

// ---------- approval.submit ----------

export function approvalSubmit(ctx: CallCtx, commitId: string, expected: bigint, approvalObjectId: string): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  const obj = store.getObject(approvalObjectId);
  if (!obj || obj.kind !== "approval") throw err("NOT_FOUND", "approval object not found");
  const approval = obj.body as T.Approval;
  const b = approval.body;

  // capability scope: caller is the member's principal, or an explicit signer-relay for that key
  const members = memberMap(ctx.policy);
  const member = members.get(b.key_id);
  const relayOk = ctx.capability.commit_ids.includes(commitId) && ctx.capability.methods.includes("approval.submit");
  if (ctx.actor !== member?.principal && !relayOk) throw err("FORBIDDEN", "caller cannot submit this approval");

  if (b.commit_id !== commitId) throw err("NOT_FOUND", "approval names a different promise");
  const envHash = D("envelope", envelopeOf(ctx, p) as unknown as Json);
  if (b.envelope_hash !== envHash || b.policy_hash !== D("policy", ctx.policy as unknown as Json)) {
    throw err("APPROVAL_CONFLICT", "approval does not bind this envelope/policy");
  }

  // approval slot idempotency: identical replay returns the stored result; different body conflicts
  const slot = store.getApproval(envHash, b.key_id);
  if (slot && store.getObject(slot.approval_object)?.digest === obj.digest) {
    return { result: JSON.parse(slot.response), events: [] };
  }
  if (slot) throw err("APPROVAL_CONFLICT", "a different approval body already occupies this slot");

  checkRevision(p, expected);
  if (p.state !== "PROPOSED") throw err("STATE_CONFLICT", "promise is not PROPOSED", { currentRevision: String(p.revision) });
  requireRunning(store);
  requireClockSafe(ctx.clockSafe);
  if (ctx.now >= u64(envelopeOf(ctx, p).commit_by_ms)) throw err("DEADLINE_CLOSED", "commit_by has passed", { currentRevision: String(p.revision) });

  if (!member || !ctx.policy.approve.keys.includes(b.key_id)) throw err("SIGNATURE_INVALID", "key is not in the approve roster");
  if (store.isKeyRevoked(b.key_id)) throw err("KEY_REVOKED", "key was revoked before this authority cut");
  if (b.tenant !== p.tenant || b.environment !== p.environment) throw err("SIGNATURE_INVALID", "approval scope mismatch");
  if (!edVerify("approval", b as unknown as Json, member.public_key, approval.signature)) {
    throw err("SIGNATURE_INVALID", "approval signature does not verify");
  }

  const ev = emitEvent(ctx, commitId, "PROPOSED", "PROPOSED", ctx.commandId, ctx.now,
    { kind: "ApprovalAccepted", approval: approvalObjectId as T.Id, key_id: b.key_id }, [approvalObjectId]);
  store.updatePromise(commitId, { revision: BigInt(ev.body.seq), state: "PROPOSED" });
  const response = JSON.stringify({ commit_id: commitId, state: "PROPOSED", revision: ev.body.seq, events: ["ApprovalAccepted"] });
  store.putApproval({ envelope_hash: envHash, key_id: b.key_id, approval_object: approvalObjectId, principal: member.principal, accepted_seq: BigInt(ev.body.seq), response });
  flushAudit(ctx, store, commitId);
  return { result: JSON.parse(response), events: ["ApprovalAccepted"] };
}

// ---------- promise.cancel ----------

export function promiseCancel(ctx: CallCtx, commitId: string, expected: bigint): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  if (ctx.actor !== p.payer) throw err("FORBIDDEN", "only the payer may cancel");
  checkRevision(p, expected);
  if (p.state !== "PROPOSED") throw err("STATE_CONFLICT", "cancel requires PROPOSED", { currentRevision: String(p.revision) });
  requireRunning(store);
  requireClockSafe(ctx.clockSafe);
  const e = envelopeOf(ctx, p);
  if (ctx.now >= u64(e.commit_by_ms)) throw err("DEADLINE_CLOSED", "commit_by has passed", { currentRevision: String(p.revision) });

  const ev = emitEvent(ctx, commitId, "PROPOSED", "CANCELLED", ctx.commandId, ctx.now, { kind: "Cancelled", actor: ctx.actor }, []);
  store.updatePromise(commitId, { state: "CANCELLED", revision: BigInt(ev.body.seq), next_due_ms: null });
  flushAudit(ctx, store, commitId);
  return { result: { commit_id: commitId, state: "CANCELLED", revision: ev.body.seq, events: ["Cancelled"] }, events: ["Cancelled"] };
}

// ---------- custody request construction ----------

export function buildReserveRequest(ctx: Ctx, e: T.Envelope): T.CustodyRequest {
  const envHash = D("envelope", e as unknown as Json);
  return {
    v: 1, tenant: e.tenant, environment: e.environment, custody: e.custody,
    operation_id: operationIdsFor(envHash).reserve as T.Id, kind: "reserve", envelope_hash: envHash as T.Digest,
    escrow_id: escrowIdFor(envHash) as T.Id, payer: e.payer, payee: e.payee, asset: e.asset,
    amount_minor: e.amount_minor, allocation: null, not_after_ms: e.fund_by_ms, fence: ctx.writerEpoch as T.U64,
  };
}

export function buildAllocateRequest(ctx: Ctx, e: T.Envelope, allocation: T.Allocation): T.CustodyRequest {
  const envHash = D("envelope", e as unknown as Json);
  return {
    v: 1, tenant: e.tenant, environment: e.environment, custody: e.custody,
    operation_id: operationIdsFor(envHash).allocate as T.Id, kind: "allocate", envelope_hash: envHash as T.Digest,
    escrow_id: escrowIdFor(envHash) as T.Id, payer: e.payer, payee: e.payee, asset: e.asset,
    amount_minor: e.amount_minor, allocation, not_after_ms: null, fence: ctx.writerEpoch as T.U64,
  };
}

export function receiptObjectId(opId: string, providerRev: string): string {
  return `rc_${opId}_${providerRev}`;
}

/** Synthesize a signed sim-ledger receipt for an applied local operation. */
export function simReceipt(ctx: CallCtx, request: T.CustodyRequest, status: "applied" | "no_effect"): T.CustodyReceipt {
  const rev = String(ctx.store.bumpCounter(`prov_${request.operation_id}`));
  const body: T.CustodyReceiptBody = {
    v: 1, custody: request.custody, operation_id: request.operation_id,
    request_hash: D("custody", request as unknown as Json) as T.Digest, escrow_id: request.escrow_id,
    status, final: true, attempt: 1, allocation: request.kind === "reserve" ? null : request.allocation,
    amount_minor: request.amount_minor, provider_revision: rev as T.U64, observed_ms: String(ctx.now) as T.U64,
    evidence: null,
  };
  const signature = edSign("custody", body as unknown as Json, ctx.receiptSeed!);
  return { body, signature };
}

// ---------- ledger application (§6.3) ----------

export function escrowAccount(commitId: string): string {
  return `escrow_${commitId}`;
}

export function applyReserveLedger(ctx: Ctx, store: Store, p: PromiseRow, causeSeq: bigint): void {
  const e = envelopeOf(ctx, p);
  const escrow = escrowAccount(p.commit_id);
  store.insertLedgerTransaction(p.commit_id, causeSeq, [
    { account: p.payer, asset_code: e.asset.code, side: "DEBIT", amount_minor: p.amount, commit_id: p.commit_id },
    { account: escrow, asset_code: e.asset.code, side: "CREDIT", amount_minor: p.amount, commit_id: p.commit_id },
  ]);
  const payerAcc = store.getAccount(e.custody, e.asset.code, p.payer) ?? { available_minor: 0n, held_minor: 0n, beneficial: 1 };
  store.upsertAccount(e.custody, e.asset.code, p.payer, payerAcc.available_minor - p.amount, payerAcc.held_minor, payerAcc.beneficial);
  const escAcc = store.getAccount(e.custody, e.asset.code, escrow) ?? { available_minor: 0n, held_minor: 0n, beneficial: 1 };
  store.upsertAccount(e.custody, e.asset.code, escrow, escAcc.available_minor, escAcc.held_minor + p.amount, 1);
}

export function applySettleLedger(ctx: Ctx, store: Store, p: PromiseRow, allocation: T.Allocation, causeSeq: bigint): void {
  const e = envelopeOf(ctx, p);
  const escrow = escrowAccount(p.commit_id);
  const pay = u64(allocation.pay_minor);
  const ret = u64(allocation.return_minor);
  const lines: { account: string; asset_code: string; side: "DEBIT" | "CREDIT"; amount_minor: bigint; commit_id: string | null }[] = [
    { account: escrow, asset_code: e.asset.code, side: "DEBIT", amount_minor: pay + ret, commit_id: p.commit_id },
  ];
  if (pay > 0n) lines.push({ account: p.payee, asset_code: e.asset.code, side: "CREDIT", amount_minor: pay, commit_id: p.commit_id });
  if (ret > 0n) lines.push({ account: p.payer, asset_code: e.asset.code, side: "CREDIT", amount_minor: ret, commit_id: p.commit_id });
  store.insertLedgerTransaction(p.commit_id, causeSeq, lines);
  const escAcc = store.getAccount(e.custody, e.asset.code, escrow)!;
  store.upsertAccount(e.custody, e.asset.code, escrow, escAcc.available_minor, escAcc.held_minor - (pay + ret), 1);
  if (pay > 0n) {
    const payee = store.getAccount(e.custody, e.asset.code, p.payee) ?? { available_minor: 0n, held_minor: 0n, beneficial: 1 };
    store.upsertAccount(e.custody, e.asset.code, p.payee, payee.available_minor + pay, payee.held_minor, payee.beneficial);
  }
  if (ret > 0n) {
    const payer = store.getAccount(e.custody, e.asset.code, p.payer) ?? { available_minor: 0n, held_minor: 0n, beneficial: 1 };
    store.upsertAccount(e.custody, e.asset.code, p.payer, payer.available_minor + ret, payer.held_minor, payer.beneficial);
  }
}

// ---------- promise.commit ----------

export function promiseCommit(ctx: CallCtx, commitId: string, expected: bigint): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  if (ctx.actor !== p.payer) throw err("FORBIDDEN", "commit requires the payer or an execute capability for the payer");
  checkRevision(p, expected);
  if (p.state !== "PROPOSED") throw err("STATE_CONFLICT", "commit requires PROPOSED", { currentRevision: String(p.revision) });
  requireRunning(store);
  requireClockSafe(ctx.clockSafe);
  const e = envelopeOf(ctx, p);
  if (ctx.now >= u64(e.commit_by_ms)) throw err("DEADLINE_CLOSED", "commit_by has passed", { currentRevision: String(p.revision) });

  // authority: collected non-revoked approvals vs the approve quorum
  const envHash = D("envelope", e as unknown as Json);
  const collected = store.listApprovals(envHash);
  const allKeyIds = collected.map((a) => a.key_id);
  const live = allKeyIds.filter((k) => !store.isKeyRevoked(k));
  const excludedForRevocation = allKeyIds.length !== live.length;
  const q = quorumCheck(ctx, ctx.policy.approve, live);
  const members = memberMap(ctx.policy);
  const humanOk = live.some((k) => members.get(k)?.kind === "human" && !store.isKeyRevoked(k));
  if (!(q.ok && humanOk)) {
    if (excludedForRevocation) throw err("KEY_REVOKED", "revoked-key exclusion defeats the quorum", { currentRevision: String(p.revision) });
    throw err("QUORUM_MISSING", "approval quorum is not satisfied", { currentRevision: String(p.revision) });
  }

  // economic guards
  const day = utcDay(ctx.now);
  if (store.dailyBudgetCharged(e.tenant, e.environment, day) + p.amount > u64(ctx.policy.daily_commit_minor)) {
    throw err("BUDGET_EXCEEDED", "daily admission budget exceeded", { currentRevision: String(p.revision) });
  }
  if (store.totalExposure(e.tenant, e.environment) + p.amount > u64(ctx.policy.max_exposure_minor)) {
    throw err("BUDGET_EXCEEDED", "outstanding exposure bound exceeded", { currentRevision: String(p.revision) });
  }
  if (ctx.localCustody) {
    const acc = store.getAccount(e.custody, e.asset.code, e.payer);
    if (!acc || acc.available_minor < p.amount) {
      throw err("INSUFFICIENT_FUNDS", "payer balance is insufficient", { currentRevision: String(p.revision) });
    }
  }

  // consume: charge budget, reserve exposure, create reserve operation
  const reserve = buildReserveRequest(ctx, e);
  const requestHash = D("custody", reserve as unknown as Json);
  store.chargeDailyBudget(e.tenant, e.environment, day, envHash, p.amount);
  store.putExposure(p.commit_id, p.amount, reserve.operation_id, "reserved");
  store.updatePromise(commitId, { consumed: 1 });
  const approvalIds = collected.map((a) => a.approval_object).sort();
  const ev1 = emitEvent(ctx, commitId, "PROPOSED", "FUNDING", ctx.commandId, ctx.now,
    { kind: "CommitAuthorized", reserve, approvals: approvalIds as T.Id[], budget_day: String(day) as T.U64 }, approvalIds);
  store.putOperation({
    operation_id: reserve.operation_id, kind: "reserve", commit_id: commitId,
    canonical_request: jcsBytes(reserve as unknown as Json), request_hash: requestHash, state: "READY", attempts: 0,
  });
  store.putOutbox(reserve.operation_id, requestHash, "READY", u64(ctx.writerEpoch), null);
  store.updatePromise(commitId, { state: "FUNDING", revision: BigInt(ev1.body.seq), next_due_ms: u64(e.fund_by_ms) });

  const events = ["CommitAuthorized"];
  if (ctx.localCustody) {
    // sim-ledger/1: reserve applies inside this transaction; EscrowHeld immediately.
    const receipt = simReceipt(ctx, reserve, "applied");
    const rcId = receiptObjectId(reserve.operation_id, receipt.body.provider_revision);
    admitSystemObject(ctx, rcId, "custody", receipt, ctx.now);
    store.putReceipt({ operation_id: reserve.operation_id, provider_revision: receipt.body.provider_revision, attempt: 1, body_hash: H(jcsBytes(receipt.body as unknown as Json)), object_id: rcId, final: 1, status: "applied" });
    store.updateOperation(reserve.operation_id, { state: "APPLIED", attempts: 1, last_provider_revision: receipt.body.provider_revision, last_receipt: rcId, first_dispatch_ms: ctx.now });
    store.deleteOutbox(reserve.operation_id);
    applyReserveLedger(ctx, store, p, BigInt(ev1.body.seq) + 1n);
    const ev2 = emitEvent(ctx, commitId, "FUNDING", "ACTIVE", ctx.commandId, ctx.now,
      { kind: "EscrowHeld", receipt: rcId as T.Id, escrow_id: reserve.escrow_id }, [rcId]);
    store.updatePromise(commitId, {
      state: "ACTIVE", revision: BigInt(ev2.body.seq), escrow_id: reserve.escrow_id,
      next_due_ms: u64(e.condition_by_ms),
    });
    store.updateExposure(commitId, { status: "held" });
    events.push("EscrowHeld");
  }
  flushAudit(ctx, store, commitId);
  const last = store.lastEvent(commitId)!;
  return { result: { commit_id: commitId, state: store.getPromise(commitId)!.state, revision: String(last.seq), events }, events };
}

// ---------- condition.submit ----------

export function conditionSubmit(ctx: CallCtx, commitId: string, expected: bigint, evidenceObjectId: string): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  if (ctx.actor !== p.payer && ctx.actor !== p.payee) throw err("FORBIDDEN", "condition.submit requires payer or payee");
  const obj = store.getObject(evidenceObjectId);
  if (!obj || obj.kind !== "evidence") throw err("NOT_FOUND", "evidence object not found");
  const evidence = obj.body as T.EvidenceSet;
  checkRevision(p, expected);
  if (p.state !== "ACTIVE") throw err("STATE_CONFLICT", "condition evidence requires ACTIVE", { currentRevision: String(p.revision) });
  if (p.late_pending) throw err("STATE_CONFLICT", "late-funded ACTIVE must resolve funding_late before evidence", { currentRevision: String(p.revision) });
  requireRunning(store);
  requireClockSafe(ctx.clockSafe);
  const e = envelopeOf(ctx, p);
  if (ctx.now >= u64(e.condition_by_ms)) throw err("DEADLINE_CLOSED", "condition_by has passed", { currentRevision: String(p.revision) });

  if (evidence.commit_id !== commitId || evidence.envelope_hash !== p.envelope_hash) {
    throw err("EVIDENCE_MISMATCH", "evidence does not bind this promise", { currentRevision: String(p.revision) });
  }
  const clauses = e.condition.clauses;
  if (evidence.items.length !== clauses.length) {
    throw err("EVIDENCE_MISMATCH", "evidence must satisfy every clause exactly once", { currentRevision: String(p.revision) });
  }
  for (let i = 0; i < clauses.length; i++) {
    const clause = clauses[i]!;
    const item = evidence.items[i]!;
    if (item.clause_id !== clause.id || item.kind !== clause.kind) {
      throw err("EVIDENCE_MISMATCH", `evidence item ${i} does not satisfy clause ${clause.id} in order`, { currentRevision: String(p.revision) });
    }
    if (clause.kind === "attested" && item.kind === "attested") {
      checkAttestation(ctx, item.certificate, clause, e, p);
    } else if (clause.kind === "hashlock" && item.kind === "hashlock") {
      checkHashlock(clause, item.preimage_base64url, p);
    }
  }

  const releaseAt = ctx.now + u64(e.challenge_ms);
  const ev = emitEvent(ctx, commitId, "ACTIVE", "RELEASE_PENDING", ctx.commandId, ctx.now,
    { kind: "ConditionSatisfied", evidence: evidenceObjectId as T.Id, release_at_ms: String(releaseAt) as T.U64 }, [evidenceObjectId]);
  store.updatePromise(commitId, { state: "RELEASE_PENDING", revision: BigInt(ev.body.seq), release_at: releaseAt, next_due_ms: releaseAt });
  flushAudit(ctx, store, commitId);
  return { result: { commit_id: commitId, state: "RELEASE_PENDING", revision: ev.body.seq, events: ["ConditionSatisfied"] }, events: ["ConditionSatisfied"] };
}

function checkAttestation(ctx: CallCtx, cert: T.Attestation, clause: T.Clause & { kind: "attested" }, e: T.Envelope, p: PromiseRow): void {
  const b = cert.body;
  if (b.tenant !== e.tenant || b.environment !== e.environment || b.commit_id !== e.commit_id ||
      b.envelope_hash !== p.envelope_hash || b.clause_id !== clause.id || b.predicate !== clause.predicate) {
    throw err("EVIDENCE_MISMATCH", "attestation does not bind the clause and envelope", { currentRevision: String(p.revision) });
  }
  const members = memberMap(ctx.policy);
  for (const s of cert.signatures) {
    const m = members.get(s.key_id);
    if (!m || !ctx.policy.attest.keys.includes(s.key_id) || ctx.store.isKeyRevoked(s.key_id) ||
        !edVerify("attestation", b as unknown as Json, m.public_key, s.sig)) {
      throw err("SIGNATURE_INVALID", "attestation signature invalid", { currentRevision: String(p.revision) });
    }
  }
  const q = quorumCheck(ctx, ctx.policy.attest, cert.signatures.map((s) => s.key_id));
  if (!q.ok) throw err("QUORUM_MISSING", "attest quorum not satisfied", { currentRevision: String(p.revision) });
  if (!(u64(b.issued_ms) <= ctx.now && ctx.now < u64(b.valid_until_ms))) {
    throw err("EVIDENCE_EXPIRED", "attestation is not inside its validity window", { currentRevision: String(p.revision) });
  }
}

function checkHashlock(clause: T.Clause & { kind: "hashlock" }, preimageB64: string, p: PromiseRow): void {
  const pre = decodeBase64urlCanonical(preimageB64);
  if (pre.length === 0 || pre.length > clause.max_preimage_bytes) {
    throw err("CONDITION_UNSATISFIED", "preimage outside declared bounds", { currentRevision: String(p.revision) });
  }
  if (H(pre) !== clause.sha256) {
    throw err("CONDITION_UNSATISFIED", "preimage does not match the hashlock", { currentRevision: String(p.revision) });
  }
}

// ---------- dispute.open ----------

export function disputeOpen(ctx: CallCtx, commitId: string, expected: bigint, caseId: string, reason: "delivery" | "fraud" | "integrity", evidenceRef: T.BlobRef): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  if (ctx.actor !== p.payer && ctx.actor !== p.payee) throw err("FORBIDDEN", "dispute.open requires the payer or payee", { currentRevision: String(p.revision) });
  const blob = store.getObject(evidenceRef.object);
  if (!blob || blob.kind !== "blob") throw err("NOT_FOUND", "dispute evidence blob not found");
  checkRevision(p, expected);
  if (p.state === "DISPUTED") throw err("DISPUTE_EXISTS", "a dispute is already open", { currentRevision: String(p.revision) });
  if (p.state !== "RELEASE_PENDING") throw err("STATE_CONFLICT", "dispute requires RELEASE_PENDING", { currentRevision: String(p.revision) });
  // disputes remain admissible while halted, but only before the original deadline
  requireClockSafe(ctx.clockSafe);
  const releaseAt = p.release_at!;
  if (ctx.now >= releaseAt) throw err("DEADLINE_CLOSED", "release_at has passed", { currentRevision: String(p.revision) });
  if (blob.digest !== evidenceRef.sha256 || BigInt(blob.bytes) !== u64(evidenceRef.bytes)) {
    throw err("EVIDENCE_MISMATCH", "dispute evidence blob ref does not match stored object", { currentRevision: String(p.revision) });
  }

  const e = envelopeOf(ctx, p);
  const decisionBy = releaseAt + u64(e.dispute_ms);
  const ev = emitEvent(ctx, commitId, "RELEASE_PENDING", "DISPUTED", ctx.commandId, ctx.now,
    { kind: "DisputeOpened", case_id: caseId as T.Id, actor: ctx.actor, reason, evidence: evidenceRef, decision_by_ms: String(decisionBy) as T.U64 }, [evidenceRef.object]);
  store.updatePromise(commitId, { state: "DISPUTED", revision: BigInt(ev.body.seq), case_id: caseId, decision_by: decisionBy, next_due_ms: decisionBy });
  flushAudit(ctx, store, commitId);
  return { result: { commit_id: commitId, state: "DISPUTED", revision: ev.body.seq, events: ["DisputeOpened"] }, events: ["DisputeOpened"] };
}

// ---------- dispute.resolve ----------

const POST_DECISION: ReadonlySet<T.State> = new Set(["SETTLING", "SETTLEMENT_UNKNOWN", "SETTLEMENT_BLOCKED", "SETTLED"]);

export function disputeResolve(ctx: CallCtx, commitId: string, expected: bigint, awardObjectId: string): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  const obj = store.getObject(awardObjectId);
  if (!obj || obj.kind !== "award") throw err("NOT_FOUND", "award object not found");
  const award = obj.body as T.Award;
  const arbPrincipals = new Set(ctx.policy.arbitrate.keys.map((k) => memberMap(ctx.policy).get(k)!.principal));
  if (!arbPrincipals.has(ctx.actor) && ctx.actor !== p.payer && ctx.actor !== p.payee) {
    throw err("FORBIDDEN", "resolve requires an arbitrator or a party", { currentRevision: String(p.revision) });
  }
  checkRevision(p, expected);
  if (POST_DECISION.has(p.state)) throw err("DECISION_FINAL", "a disposition is already selected", { currentRevision: String(p.revision) });
  if (p.state !== "DISPUTED") throw err("STATE_CONFLICT", "resolve requires DISPUTED", { currentRevision: String(p.revision) });
  requireRunning(store);
  requireClockSafe(ctx.clockSafe);
  if (ctx.now >= p.decision_by!) throw err("DEADLINE_CLOSED", "decision_by has passed", { currentRevision: String(p.revision) });

  const b = award.body;
  const members = memberMap(ctx.policy);
  for (const s of award.signatures) {
    const m = members.get(s.key_id);
    if (!m || !ctx.policy.arbitrate.keys.includes(s.key_id) || store.isKeyRevoked(s.key_id) ||
        !edVerify("award", b as unknown as Json, m.public_key, s.sig)) {
      throw err("SIGNATURE_INVALID", "award signature invalid", { currentRevision: String(p.revision) });
    }
  }
  const q = quorumCheck(ctx, ctx.policy.arbitrate, award.signatures.map((s) => s.key_id));
  if (!q.ok) throw err("QUORUM_MISSING", "arbitrate quorum not satisfied", { currentRevision: String(p.revision) });

  if (b.tenant !== p.tenant || b.environment !== p.environment || b.commit_id !== commitId ||
      b.envelope_hash !== p.envelope_hash || b.case_id !== p.case_id || b.rules_digest !== ctx.policy.rules_digest) {
    throw err("AWARD_INVALID", "award does not bind this dispute and policy", { currentRevision: String(p.revision) });
  }
  if (u64(b.pay_minor) + u64(b.return_minor) !== p.amount) {
    throw err("AWARD_INVALID", "award allocation does not conserve the locked amount", { currentRevision: String(p.revision) });
  }
  for (const ref of b.evidence) {
    const rb = store.getObject(ref.object);
    if (!rb || rb.kind !== "blob" || rb.digest !== ref.sha256 || BigInt(rb.bytes) !== u64(ref.bytes)) {
      throw err("AWARD_INVALID", `award evidence ${ref.object} is not a known blob`, { currentRevision: String(p.revision) });
    }
  }

  const allocation: T.Allocation = { pay_minor: b.pay_minor, return_minor: b.return_minor };
  return decideSettlement(ctx, p, "award", awardObjectId, allocation);
}

// ---------- promise.advance ----------

export function promiseAdvance(ctx: CallCtx, commitId: string, expected: bigint): MutationOutcome {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  const e = envelopeOf(ctx, p);
  const st = p.state;
  const isParty = ctx.actor === p.payer || ctx.actor === p.payee;
  const isScheduler = ctx.capability.methods.includes("promise.advance") && ctx.capability.commit_ids.includes(commitId);
  if (!isParty && !isScheduler) throw err("FORBIDDEN", "advance requires a party or scheduler capability", { currentRevision: String(p.revision) });
  checkRevision(p, expected);

  const listed =
    st === "PROPOSED" || st === "FUNDING" || st === "ACTIVE" || st === "RELEASE_PENDING" || st === "DISPUTED";
  if (!listed) throw err("STATE_CONFLICT", `no advance transition from ${st}`, { currentRevision: String(p.revision) });

  requireRunning(store);
  requireClockSafe(ctx.clockSafe);

  switch (st) {
    case "PROPOSED": {
      if (ctx.now < u64(e.commit_by_ms)) throw err("NOT_DUE", "commit_by has not elapsed", { currentRevision: String(p.revision) });
      const ev = emitEvent(ctx, commitId, "PROPOSED", "EXPIRED", ctx.commandId, ctx.now, { kind: "Expired", deadline_ms: e.commit_by_ms }, []);
      store.updatePromise(commitId, { state: "EXPIRED", revision: BigInt(ev.body.seq), next_due_ms: null });
      flushAudit(ctx, store, commitId);
      return { result: { commit_id: commitId, state: "EXPIRED", revision: ev.body.seq, events: ["Expired"] }, events: ["Expired"] };
    }
    case "FUNDING": {
      if (ctx.now < u64(e.fund_by_ms)) throw err("NOT_DUE", "fund_by has not elapsed", { currentRevision: String(p.revision) });
      const op = store.getOperationFor(commitId, "reserve");
      if (op && op.state === "READY") {
        // provably unsent: cancel outbox, release exposure
        store.updateOperation(op.operation_id, { state: "NO_EFFECT" });
        store.deleteOutbox(op.operation_id);
        const ev = emitEvent(ctx, commitId, "FUNDING", "UNFUNDED", ctx.commandId, ctx.now,
          { kind: "FundingFailed", receipt: null, reason: "unsent_expiry" }, []);
        store.updatePromise(commitId, { state: "UNFUNDED", revision: BigInt(ev.body.seq), next_due_ms: null });
        store.deleteExposure(commitId);
        flushAudit(ctx, store, commitId);
        return { result: { commit_id: commitId, state: "UNFUNDED", revision: ev.body.seq, events: ["FundingFailed"] }, events: ["FundingFailed"] };
      }
      const ev = emitEvent(ctx, commitId, "FUNDING", "FUNDING_UNKNOWN", ctx.commandId, ctx.now,
        { kind: "FundingUncertain", operation_id: op!.operation_id as T.Id, reason: "deadline" }, []);
      store.updatePromise(commitId, { state: "FUNDING_UNKNOWN", revision: BigInt(ev.body.seq), next_due_ms: null });
      if (op && op.state === "DISPATCHED") store.updateOperation(op.operation_id, { state: "UNKNOWN" });
      flushAudit(ctx, store, commitId);
      return { result: { commit_id: commitId, state: "FUNDING_UNKNOWN", revision: ev.body.seq, events: ["FundingUncertain"] }, events: ["FundingUncertain"] };
    }
    case "ACTIVE": {
      if (p.late_pending) {
        return decideSettlement(ctx, p, "funding_late", null, { pay_minor: "0", return_minor: e.amount_minor });
      }
      if (ctx.now < u64(e.condition_by_ms)) throw err("NOT_DUE", "condition_by has not elapsed", { currentRevision: String(p.revision) });
      return decideSettlement(ctx, p, "condition_timeout", null, { pay_minor: "0", return_minor: e.amount_minor });
    }
    case "RELEASE_PENDING": {
      if (ctx.now < p.release_at!) throw err("NOT_DUE", "release_at has not elapsed", { currentRevision: String(p.revision) });
      return decideSettlement(ctx, p, "release", null, { pay_minor: e.amount_minor, return_minor: "0" });
    }
    case "DISPUTED": {
      if (ctx.now < p.decision_by!) throw err("NOT_DUE", "decision_by has not elapsed", { currentRevision: String(p.revision) });
      const fallback = u64(e.dispute_fallback_pay_minor);
      return decideSettlement(ctx, p, "dispute_timeout", null, {
        pay_minor: String(fallback), return_minor: String(p.amount - fallback),
      });
    }
  }
  throw err("STATE_CONFLICT", `no advance transition from ${st}`);
}

/** Emit SettlementDecided, create the allocate operation, and apply locally when sim-ledger. */
export function decideSettlement(ctx: CallCtx, p: PromiseRow, reason: T.Disposition, awardObjectId: string | null, allocation: T.Allocation): MutationOutcome {
  const store = ctx.store;
  const e = envelopeOf(ctx, p);
  const from = p.state;
  const request = buildAllocateRequest(ctx, e, allocation);
  const requestHash = D("custody", request as unknown as Json);
  const refs = awardObjectId ? [awardObjectId] : [];
  const ev = emitEvent(ctx, p.commit_id, from, "SETTLING", ctx.commandId, ctx.now,
    { kind: "SettlementDecided", reason, award: awardObjectId as T.Id | null, allocation, request }, refs);
  store.putOperation({
    operation_id: request.operation_id, kind: "allocate", commit_id: p.commit_id,
    canonical_request: jcsBytes(request as unknown as Json), request_hash: requestHash, state: "READY", attempts: 0,
  });
  store.putOutbox(request.operation_id, requestHash, "READY", u64(ctx.writerEpoch), null);
  store.updatePromise(p.commit_id, {
    state: "SETTLING", revision: BigInt(ev.body.seq), allocation, disposition: reason, next_due_ms: null, late_pending: 0,
  });
  const events = ["SettlementDecided"];

  if (ctx.localCustody) {
    const receipt = simReceipt(ctx, request, "applied");
    const rcId = receiptObjectId(request.operation_id, receipt.body.provider_revision);
    admitSystemObject(ctx, rcId, "custody", receipt, ctx.now);
    store.putReceipt({ operation_id: request.operation_id, provider_revision: receipt.body.provider_revision, attempt: 1, body_hash: H(jcsBytes(receipt.body as unknown as Json)), object_id: rcId, final: 1, status: "applied" });
    store.updateOperation(request.operation_id, { state: "APPLIED", attempts: 1, last_provider_revision: receipt.body.provider_revision, last_receipt: rcId, first_dispatch_ms: ctx.now });
    store.deleteOutbox(request.operation_id);
    const ev2 = emitEvent(ctx, p.commit_id, "SETTLING", "SETTLED", ctx.commandId, ctx.now,
      { kind: "Settled", receipt: rcId as T.Id, allocation }, [rcId]);
    applySettleLedger(ctx, store, p, allocation, BigInt(ev2.body.seq));
    store.updatePromise(p.commit_id, { state: "SETTLED", revision: BigInt(ev2.body.seq) });
    store.deleteExposure(p.commit_id);
    events.push("Settled");
  }
  flushAudit(ctx, store, p.commit_id);
  const last = store.lastEvent(p.commit_id)!;
  return { result: { commit_id: p.commit_id, state: store.getPromise(p.commit_id)!.state, revision: String(last.seq), events }, events };
}
