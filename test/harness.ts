// Deterministic conformance harness (§11.1): builds seeded states via real
// coordinator calls, injects clock/adapter, and exposes the harness-only ops
// (parse, crypto, policy, recover, ledger, schedule).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import crypto from "node:crypto";
import { Store } from "../src/store.ts";
import { Coordinator, type CoordinatorDeps } from "../src/coordinator.ts";
import { CoordinatorClock } from "../src/clock.ts";
import { isCommitError } from "../src/errors.ts";
import { D } from "../src/crypto.ts";
import { jcs } from "../src/json/jcs.ts";
import { parseStrictJson, type Json } from "../src/json/strict.ts";
import { validObjectBody } from "../src/schema.ts";
import { admitObject } from "../src/reducer/core.ts";
import { dispatchTick, lookupTick, timerTick, recoverAfterRestart } from "../src/reducer/custody.ts";
import type { CustodyAdapter, InvokeOutcome, LookupOutcome } from "../src/custody/adapter.ts";
import type * as T from "../src/types.ts";
import * as F from "./fixtures.ts";

export interface Outcome { ok: boolean; code?: string; result?: unknown }

/** Scripted custody adapter for external-conformance fixtures. */
export class TestAdapter implements CustodyAdapter {
  readonly profile = "sim-ledger/1";
  invokeQueue: InvokeOutcome[] = [];
  lookupQueue: LookupOutcome[] = [];
  invocations = 0;
  lookups = 0;
  readonly custodyId: string;
  constructor(custodyId: string) { this.custodyId = custodyId; }
  async invoke(): Promise<InvokeOutcome> {
    this.invocations++;
    const next = this.invokeQueue.shift();
    if (!next) return { status: "inflight" };
    return next;
  }
  async lookup(): Promise<LookupOutcome> {
    this.lookups++;
    const next = this.lookupQueue.shift();
    if (!next) return { status: "inconclusive" };
    return next;
  }
  async fence(): Promise<{ ok: true; epoch: string }> {
    return { ok: true, epoch: "1" };
  }
}

export const CAP_PARTY: T.Capability = {
  uid: 1001, principal: "alice", capability: "cap_party",
  methods: ["object.put", "object.get", "promise.propose", "promise.get", "promise.list", "approval.submit", "promise.commit", "promise.cancel", "condition.submit", "dispute.open", "dispute.resolve", "promise.advance", "account.get", "event.list", "proof.export"],
  object_kinds: ["envelope", "approval", "evidence", "award", "blob"],
  commit_ids: ["c1", "c2"], max_amount_minor: "50000", expires_ms: "4102444800000",
};
export const CAP_SIGNER: T.Capability = {
  uid: 1002, principal: "bob", capability: "cap_signer",
  methods: ["object.put", "object.get", "approval.submit", "promise.get", "event.list"],
  object_kinds: ["approval", "blob"], commit_ids: ["c1"], max_amount_minor: "0", expires_ms: "4102444800000",
};
export const CAP_OPS: T.Capability = {
  uid: 1003, principal: "ops", capability: "cap_ops",
  methods: ["object.put", "object.get", "custody.reconcile", "custody.retry", "control.apply", "control.status", "health.get", "promise.get", "event.list", "account.get", "promise.list"],
  object_kinds: ["control", "custody", "blob"], commit_ids: [], max_amount_minor: "0", expires_ms: "4102444800000",
};
export const CAP_AUDIT: T.Capability = {
  uid: 1004, principal: "auditor", capability: "cap_audit",
  methods: ["object.get", "promise.get", "promise.list", "event.list", "account.get", "proof.export", "proof.verify", "control.status"],
  object_kinds: [], commit_ids: ["c1"], max_amount_minor: "0", expires_ms: "4102444800000",
};
export const CAP_CAROL: T.Capability = {
  uid: 1005, principal: "carol", capability: "cap_carol",
  methods: ["object.put", "object.get", "dispute.open", "approval.submit", "promise.get"], object_kinds: ["blob", "approval"],
  commit_ids: ["c1"], max_amount_minor: "0", expires_ms: "4102444800000",
};

export interface HarnessOpts {
  external?: boolean;          // adapter-driven custody path
  retryManifest?: boolean;     // custody manifest with sequenced-no-effect/1
  aliceBalance?: bigint;
}

export class Harness {
  dir: string;
  store: Store;
  clock: CoordinatorClock;
  coord: Coordinator;
  adapter: TestAdapter | null;
  dispatches = 0;

  constructor(opts: HarnessOpts = {}) {
    this.dir = mkdtempSync(join(tmpdir(), "commit-test-"));
    this.store = new Store(join(this.dir, "store.db"), this.dir);
    this.adapter = opts.external ? new TestAdapter("sim1") : null;
    const custody = (opts.retryManifest ? F.custody_manifest_retry : F.custody_manifest) as unknown as T.CustodyManifest;
    // the harness injects simulated wall times; only backwards movement is unsafe
    this.clock = new CoordinatorClock(0n, 10n ** 15n);
    const deps: CoordinatorDeps = {
      store: this.store, custody, policy: F.P0 as T.Policy, policyObjectId: "pol1",
      writerSeed: F.seed(12), writerKeyId: "writer1",
      receiptSeed: F.seed(11), receiptKeyId: "receipt1",
      writerEpoch: "1", adapter: this.adapter, localCustody: !opts.external,
      maxObjectsPerPrincipal: 10000, maxUnboundObjectBytes: 104857600n,
      objectDir: null, cursorSecret: crypto.randomBytes(32), auditEvery: false,
      clock: this.clock,
      storageOk: () => true,
    };
    this.coord = new Coordinator(deps);
    this.store.tx(() => {
      this.store.initMeta({ tenant: "lab1", environment: "simulation", writer_epoch: 1n, active_policy: "pol1", last_clock_ms: 0n });
      this.store.putPolicy("pol1", D("policy", F.P0 as Json), 0n);
    });
    // genesis backing: alice 100000, merchant 0
    this.store.tx(() => {
      this.store.upsertAccount("sim1", "SIMUSD", "alice", opts.aliceBalance ?? 100000n, 0n, 1);
      this.store.upsertAccount("sim1", "SIMUSD", "merchant", 0n, 0n, 1);
      this.store.insertLedgerTransaction("genesis", 0n, [
        { account: "backing", asset_code: "SIMUSD", side: "DEBIT", amount_minor: opts.aliceBalance ?? 100000n, commit_id: null },
        { account: "alice", asset_code: "SIMUSD", side: "CREDIT", amount_minor: opts.aliceBalance ?? 100000n, commit_id: null },
      ]);
    });
  }

  ctxAt(nowMs: bigint, actor = "ops"): import("../src/reducer/methods.ts").CallCtx {
    const r = this.clock.observe(nowMs);
    const d = this.coord.deps;
    return { ...d, now: r.now, wallNow: r.wallNow, clockSafe: r.safe, actor: actor as T.Id, capability: CAP_OPS, commandId: `sys_h_${nowMs}` };
  }

  close(): void {
    this.store.close();
    rmSync(this.dir, { recursive: true, force: true });
  }

  /** Seed an object directly into the registry (operator-loaded, no owner). Does not move the clock. */
  seedObject(id: string, kind: T.ObjectKind, body: unknown): void {
    const d = this.coord.deps;
    const now = this.clock.lastValidatedMs;
    const ctx = { ...d, now, wallNow: now, clockSafe: true, actor: "ops" as T.Id, capability: CAP_OPS, commandId: `sys_seed_${id}` };
    this.store.tx(() => admitObject(ctx, id, kind, body, null, now));
  }

  /** RPC call with explicit actor/capability/time. `presented` overrides request.capability. */
  async call(actor: string, cap: T.Capability, method: T.Method, params: unknown, requestId: string, nowMs: bigint, presented?: string): Promise<Outcome> {
    const res = await this.coord.call(actor, cap, { v: 1, request_id: requestId, capability: (presented ?? cap.capability) as T.Id, method, params }, nowMs);
    return res.ok ? { ok: true, result: res.result } : { ok: false, code: res.error.code, result: res.error };
  }

  /** dispatch worker only (READY outbox → adapter invoke). */
  async dispatch(nowMs: bigint) {
    return dispatchTick(this.ctxAt(nowMs));
  }

  /** lookup worker only (DISPATCHED/UNKNOWN → adapter lookup → ingest). */
  async lookup(nowMs: bigint) {
    return lookupTick(this.ctxAt(nowMs));
  }

  /** timer worker only (due promises → promise.advance). */
  timers(nowMs: bigint) {
    return timerTick(this.ctxAt(nowMs));
  }

  /** schedule: run dispatch + lookup + timer workers at the given wall time. */
  async schedule(nowMs: bigint): Promise<{ dispatched: number; advanced: string[] }> {
    const ctx = this.ctxAt(nowMs);
    const d = await dispatchTick(ctx);
    this.dispatches += d.dispatched.length;
    const l = await lookupTick(ctx);
    const t = timerTick(ctx);
    return { dispatched: d.dispatched.length + l.resolved.length, advanced: t.advanced };
  }

  /** recover: simulate restart marker replay. */
  async recover(nowMs: bigint): Promise<{ uncertain: string[] }> {
    return recoverAfterRestart(this.ctxAt(nowMs));
  }

  /** ledger: journal sums for a cause. */
  ledger(commitId: string, causeSeq: bigint): { debits: string; credits: string } {
    const s = this.store.journalSums(commitId, causeSeq);
    return { debits: String(s.debits), credits: String(s.credits) };
  }

  balance(principal: string): { available: bigint; held: bigint } {
    const a = this.store.getAccount("sim1", "SIMUSD", principal);
    return { available: a?.available_minor ?? 0n, held: a?.held_minor ?? 0n };
  }

  escrowHeld(commitId: string): bigint {
    const a = this.store.getAccount("sim1", "SIMUSD", `escrow_${commitId}`);
    return a?.held_minor ?? 0n;
  }

  eventCount(commitId: string): number {
    return this.store.allEvents(commitId).length;
  }

  getPromise(commitId: string) {
    return this.store.getPromise(commitId);
  }
}

// ---------- seeded states (§11.2) ----------

const OBJ_SEED: [string, T.ObjectKind][] = [
  ["pol1", "policy"], ["env1", "envelope"], ["va1", "approval"], ["vb1", "approval"], ["vc1", "approval"],
  ["ev1", "evidence"], ["rc_reserve1", "custody"], ["rc_settle1", "custody"],
];

export async function seedZ(opts: HarnessOpts = {}): Promise<Harness> {
  const h = new Harness(opts);
  for (const [id, kind] of OBJ_SEED) h.seedObject(id, kind, F.fixtures[id]);
  return h;
}

export async function seedP0(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedZ(opts);
  h.seedObject("blob1", "blob", F.blob1);
  const r = await h.call("alice", CAP_PARTY, "promise.propose", { envelope: "env1" }, "q_propose", 1000n);
  if (!r.ok) throw new Error(`P0 seed failed: ${r.code}`);
  return h;
}

export async function seedP1(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedP0(opts);
  const r = await h.call("alice", CAP_PARTY, "approval.submit", { commit_id: "c1", expected_revision: "1", approval: "va1" }, "q_va", 1100n);
  if (!r.ok) throw new Error(`P1 seed failed: ${r.code}`);
  return h;
}

export async function seedP(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedP1(opts);
  const r = await h.call("bob", CAP_SIGNER, "approval.submit", { commit_id: "c1", expected_revision: "2", approval: "vb1" }, "q_vb", 1200n);
  if (!r.ok) throw new Error(`P seed failed: ${r.code}`);
  return h;
}

export async function seedA(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedP(opts);
  const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_commit", 2000n);
  if (!r.ok) throw new Error(`A seed failed: ${r.code}`);
  if (opts.external) {
    h.adapter!.invokeQueue.push({ status: "inflight" });
    await h.dispatch(2000n);
  }
  return h;
}

export async function seedR(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedA(opts);
  if (opts.external) {
    // reserve receipt arrives via adapter lookup → EscrowHeld → ACTIVE
    h.adapter!.lookupQueue.push({ status: "receipt", receipt: F.rc_reserve1 as unknown as T.CustodyReceipt });
    await h.lookup(2500n);
    const p = h.getPromise("c1")!;
    if (p.state !== "ACTIVE") throw new Error(`R(external) reserve not applied: ${p.state}`);
  }
  const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev1" }, "q_condition", 4000n);
  if (!r.ok) throw new Error(`R seed failed: ${r.code}`);
  return h;
}

export async function seedD(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedR(opts);
  const r = await h.call("alice", CAP_PARTY, "dispute.open", { commit_id: "c1", expected_revision: "6", case_id: "case1", reason: "delivery", evidence: F.BR }, "q_dispute", 4500n);
  if (!r.ok) throw new Error(`D seed failed: ${r.code}`);
  return h;
}

export async function seedF(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedR(opts);
  const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "6" }, "q_advance", 6000n);
  if (!r.ok) throw new Error(`F seed failed: ${r.code}`);
  return h;
}

/** XF: P + external adapter commit at 2000 → FUNDING rev4, reserve DISPATCHED/1. */
export async function seedXF(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedP({ ...opts, external: true });
  const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_commit", 2000n);
  if (!r.ok) throw new Error(`XF seed failed: ${r.code}`);
  h.adapter!.invokeQueue.push({ status: "inflight" });
  await h.dispatch(2000n);
  return h;
}

/** XU: R-external; allocate dispatched at 7000 returning the ambiguous receipt. */
export async function seedXU(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedR({ ...opts, external: true });
  const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "6" }, "q_advance", 6000n);
  if (!r.ok) throw new Error(`XU seed advance failed: ${r.code}`);
  h.adapter!.invokeQueue.push({ status: "receipt", receipt: F.fixtures.rc_unknown1 as T.CustodyReceipt });
  await h.dispatch(7000n);
  return h;
}

/** XB: XU + final no-effect receipt at 7100; manifest declares sequenced-no-effect/1. */
export async function seedXB(opts: HarnessOpts = {}): Promise<Harness> {
  const h = await seedXU({ ...opts, retryManifest: true });
  h.seedObject("rc_noeffect1", "custody", F.fixtures.rc_noeffect1);
  const r = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: (F.allocate.operation_id), receipt: "rc_noeffect1" }, "q_reconcile_ne", 7100n);
  if (!r.ok) throw new Error(`XB seed failed: ${r.code}`);
  return h;
}

// ---------- harness-only ops ----------

export function opParse(raw: string, kind?: string): Outcome {
  try {
    const v = parseStrictJson(raw);
    if (kind !== undefined) validObjectBody(kind as T.ObjectKind, v);
    return { ok: true, result: { canonical: jcs(v) } };
  } catch (e) {
    return { ok: false, code: isCommitError(e) ? e.code : "INVALID_JSON" };
  }
}
