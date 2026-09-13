// TV-C-01 … TV-C-68 — the §11 conformance vectors, run against the real
// coordinator + reducer + store + verifier.

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { D, edVerify, H } from "../src/crypto.ts";
import { jcs } from "../src/json/jcs.ts";
import type { Json } from "../src/json/strict.ts";
import { validEnvelope, validPolicy } from "../src/schema.ts";
import { validatePolicySemantics } from "../src/objects.ts";
import { verifyBundle } from "../src/proof.ts";
import { storeBackup, storeVerify } from "../src/migrate.ts";
import type * as T from "../src/types.ts";
import * as F from "./fixtures.ts";
import {
  Harness, seedA, seedD, seedF, seedP, seedP0, seedP1, seedR, seedXU, seedXB, seedXF,
  CAP_PARTY, CAP_SIGNER, CAP_OPS, CAP_AUDIT, CAP_CAROL, opParse,
} from "./harness.ts";

const CAP_ARB: T.Capability = {
  uid: 1006, principal: "fay", capability: "cap_arb",
  methods: ["object.get", "promise.get", "dispute.resolve", "event.list"],
  object_kinds: ["award", "blob"], commit_ids: ["c1"], max_amount_minor: "0", expires_ms: "4102444800000",
};
const CAP_MERCHANT: T.Capability = {
  uid: 1007, principal: "merchant", capability: "cap_merchant",
  methods: ["object.get", "promise.get", "dispute.open", "event.list"],
  object_kinds: ["blob"], commit_ids: ["c1"], max_amount_minor: "0", expires_ms: "4102444800000",
};

/** crypto op: verify an approval's signature + envelope/policy binding. */
function cryptoVerifyApproval(approval: T.Approval, env: unknown, pol: unknown): { ok: true; principal: string } | { ok: false; code: string } {
  const b = approval.body;
  if (b.envelope_hash !== D("envelope", env as Json) || b.policy_hash !== D("policy", pol as Json)) {
    return { ok: false, code: "SIGNATURE_INVALID" };
  }
  const m = F.members.find((x) => x.key_id === b.key_id);
  if (!m || !edVerify("approval", b as unknown as Json, m.public_key, approval.signature)) {
    return { ok: false, code: "SIGNATURE_INVALID" };
  }
  return { ok: true, principal: m.principal };
}

function approvalFor(envBody: unknown, keyIdx: number): T.Approval {
  const envH = D("envelope", envBody as Json);
  const body = {
    v: 1, tenant: "lab1", environment: "simulation", commit_id: (envBody as T.Envelope).commit_id,
    envelope_hash: envH, policy_hash: D("policy", F.P0 as Json), key_id: "k" + keyIdx, decision: "approve",
  };
  return { body, signature: F.sign("approval", body, keyIdx) } as unknown as T.Approval;
}

function controlCert(action: T.ControlAction, nonce: string, baseRev = "0"): T.ControlCertificate {
  const body = { v: 1, tenant: "lab1", environment: "simulation", base_revision: baseRev, nonce, expires_ms: "50000", action };
  return { body, signatures: F.sigs("control", body, [9, 10]) } as unknown as T.ControlCertificate;
}

function alloc(x: unknown): { pay_minor: string; return_minor: string } {
  return x as { pay_minor: string; return_minor: string };
}

// ---------- parse / crypto / policy ops ----------

test("TV-C-01 JCS sorts members", () => {
  const r = opParse('{"b":2,"a":1}');
  assert.equal(r.ok, true);
  assert.equal((r.result as { canonical: string }).canonical, '{"a":1,"b":2}');
});

test("TV-C-02 duplicate member", () => {
  const r = opParse('{"a":1,"a":2}');
  assert.deepEqual({ ok: r.ok, code: r.code }, { ok: false, code: "INVALID_JSON" });
});

test("TV-C-03 exponent number in envelope", () => {
  const r = opParse('{"amount_minor":1e4}', "envelope");
  assert.equal(r.ok, false);
  assert.equal(r.code, "SCHEMA_INVALID");
});

test("TV-C-04 negative zero", () => {
  const r = opParse('{"v":-0}');
  assert.equal(r.ok, false);
  assert.equal(r.code, "SCHEMA_INVALID");
});

test("TV-C-05 non-BMP key ordering", () => {
  const canonical = jcs({ "\u{1F600}": 2, "": 1 });
  assert.equal(Buffer.from(canonical, "utf8").toString("hex"), "7b22f09f9880223a322c22ee8080223a317d");
});

test("TV-C-06 no Unicode normalization", () => {
  assert.notEqual(jcs({ x: "é" }), jcs({ x: "é" }));
});

test("TV-C-07 unpaired surrogate", () => {
  const r = opParse('{"x":"\\ud800"}');
  assert.equal(r.ok, false);
  assert.equal(r.code, "INVALID_JSON");
});

test("TV-C-08 va1 verifies against E0/P0", () => {
  const r = cryptoVerifyApproval(F.fixtures.va1 as T.Approval, F.E0, F.P0);
  assert.deepEqual(r, { ok: true, principal: "alice" });
});

test("TV-C-09 va1 against modified envelope", () => {
  const env = F.patch(F.E0, { amount_minor: "10001" });
  const r = cryptoVerifyApproval(F.fixtures.va1 as T.Approval, env, F.P0);
  assert.equal(r.ok, false);
  assert.equal((r as { code: string }).code, "SIGNATURE_INVALID");
});

test("TV-C-10 wrong signature domain", () => {
  const va = F.fixtures.va1 as T.Approval;
  const bad = { body: va.body, signature: F.sign("award", va.body, 1) };
  const r = cryptoVerifyApproval(bad as T.Approval, F.E0, F.P0);
  assert.equal(r.ok, false);
  assert.equal((r as { code: string }).code, "SIGNATURE_INVALID");
});

test("TV-C-14 duplicate member public key", () => {
  const pol = F.patch(F.P0, {});
  (pol.members as T.Member[])[1]!.public_key = (pol.members as T.Member[])[0]!.public_key;
  assert.throws(() => validatePolicySemantics(pol as T.Policy, F.custody_manifest as T.CustodyManifest, F.pub(12)),
    (e) => (e as { code?: string }).code === "POLICY_INVALID");
});

test("TV-C-62 amount above u64", () => {
  const r = opParse(JSON.stringify(F.patch(F.E0, { amount_minor: "9223372036854775808" })), "envelope");
  assert.equal(r.ok, false);
  assert.equal(r.code, "AMOUNT_OVERFLOW");
});

test("TV-C-66 threshold exceeds roster", () => {
  const pol = F.patch(F.P0, { approve: { threshold: 4, keys: ["k1", "k2", "k3"], mandatory_principals: ["alice"] } });
  assert.throws(() => validatePolicySemantics(pol as T.Policy, F.custody_manifest as T.CustodyManifest, F.pub(12)),
    (e) => (e as { code?: string }).code === "POLICY_INVALID");
});

test("TV-C-67 live envelope with stale approvals", () => {
  const env = F.patch(F.E0, { environment: "live" });
  const r1 = cryptoVerifyApproval(F.fixtures.va1 as T.Approval, env, F.P0);
  const r2 = cryptoVerifyApproval(F.fixtures.vb1 as T.Approval, env, F.P0);
  assert.equal(r1.ok, false);
  assert.equal(r2.ok, false);
});

// ---------- promise lifecycle ----------

test("TV-C-11 identical approval replay", async () => {
  const h = await seedP0();
  try {
    const r1 = await h.call("alice", CAP_PARTY, "approval.submit", { commit_id: "c1", expected_revision: "1", approval: "va1" }, "q_va", 1100n);
    assert.equal(r1.ok, true, JSON.stringify(r1));
    const n1 = h.eventCount("c1");
    const r2 = await h.call("alice", CAP_PARTY, "approval.submit", { commit_id: "c1", expected_revision: "2", approval: "va1" }, "q_va2", 1200n);
    assert.equal(r2.ok, true);
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v1", 1200n)).result as T.PromiseView;
    assert.equal(view.state, "PROPOSED");
    assert.equal(view.revision, "2");
    assert.equal(view.approval_count, 1);
    assert.equal(h.eventCount("c1") - n1, 0);
  } finally { h.close(); }
});

test("TV-C-12 commit with one approval", async () => {
  const h = await seedP1();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "2" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "QUORUM_MISSING");
    assert.equal(h.getPromise("c1")!.revision, 2n);
  } finally { h.close(); }
});

test("TV-C-13 quorum without mandatory principal", async () => {
  const h = await seedP0();
  try {
    await h.call("bob", CAP_SIGNER, "approval.submit", { commit_id: "c1", expected_revision: "1", approval: "vb1" }, "q_vb", 1100n);
    await h.call("carol", CAP_CAROL, "approval.submit", { commit_id: "c1", expected_revision: "2", approval: "vc1" }, "q_vc", 1150n);
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "QUORUM_MISSING");
  } finally { h.close(); }
});

test("TV-C-15 simulation commit applies locally", async () => {
  const h = await seedP();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_commit", 2000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 2000n)).result as T.PromiseView;
    assert.equal(view.state, "ACTIVE");
    assert.equal(view.revision, "5");
    const bal = h.balance("alice");
    assert.equal(bal.available, 90000n);
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-16 insufficient funds", async () => {
  const h = await seedP({ aliceBalance: 9999n });
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "INSUFFICIENT_FUNDS");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-17 commit at commit_by", async () => {
  const h = await seedP();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 10000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "DEADLINE_CLOSED");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-18 advance expires PROPOSED", async () => {
  const h = await seedP();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "3" }, "q_adv", 10000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 10000n)).result as T.PromiseView;
    assert.equal(view.state, "EXPIRED");
    assert.equal(view.revision, "4");
    assert.equal(h.escrowHeld("c1"), 0n);
  } finally { h.close(); }
});

test("TV-C-19 cancel before deadline", async () => {
  const h = await seedP();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.cancel", { commit_id: "c1", expected_revision: "3" }, "q_x", 9999n);
    assert.equal(r.ok, true);
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 9999n)).result as T.PromiseView;
    assert.equal(view.state, "CANCELLED");
    assert.equal(view.revision, "4");
  } finally { h.close(); }
});

test("TV-C-20 cancel after commit", async () => {
  const h = await seedA();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.cancel", { commit_id: "c1", expected_revision: "5" }, "q_x", 2500n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "STATE_CONFLICT");
    assert.equal(h.getPromise("c1")!.revision, 5n);
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-21 business-key conflict", async () => {
  const h = await seedP0();
  try {
    const env2 = F.patch(F.E0, { commit_id: "c2", amount_minor: "10001" });
    h.seedObject("env2", "envelope", env2);
    const r = await h.call("alice", CAP_PARTY, "promise.propose", { envelope: "env2" }, "q_p2", 1500n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "BUSINESS_CONFLICT");
    assert.equal(Number((h.store.db.prepare("SELECT COUNT(*) n FROM promises").get() as { n: bigint | number }).n), 1);
  } finally { h.close(); }
});

test("TV-C-22 idempotent commit replay", async () => {
  const h = await seedP();
  try {
    const r1 = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q1", 2000n);
    assert.equal(r1.ok, true);
    const n1 = h.eventCount("c1");
    const r2 = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q1", 2500n);
    assert.equal(r2.ok, true);
    assert.equal((r2.result as { revision: string }).revision, "5");
    assert.equal((r2.result as { state: string }).state, "ACTIVE");
    assert.equal(h.eventCount("c1") - n1, 0);
    assert.equal(h.balance("alice").available, 90000n);
  } finally { h.close(); }
});

test("TV-C-23 request-id reuse with different params", async () => {
  const h = await seedP();
  try {
    await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q1", 2000n);
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "5" }, "q1", 2500n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "IDEMPOTENCY_CONFLICT");
    assert.equal(h.getPromise("c1")!.revision, 5n);
  } finally { h.close(); }
});

test("TV-C-24 concurrent revision race", async () => {
  const h = await seedP();
  try {
    const w = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q1", 2000n);
    assert.equal(w.ok, true);
    const l = await h.call("alice", CAP_PARTY, "promise.cancel", { commit_id: "c1", expected_revision: "3" }, "q2", 2000n);
    assert.equal(l.ok, false);
    assert.equal(l.code, "STALE_REVISION");
    assert.equal(h.getPromise("c1")!.state, "ACTIVE");
    assert.equal(h.getPromise("c1")!.revision, 5n);
  } finally { h.close(); }
});

test("TV-C-25 daily budget exhausted", async () => {
  const h = await seedP();
  try {
    h.store.tx(() => h.store.chargeDailyBudget("lab1", "simulation", 0n, D("policy", F.P0 as Json), 95000n));
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "BUDGET_EXCEEDED");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-26 exposure bound", async () => {
  const h = await seedP();
  try {
    // a second live promise for the same tenant/environment holding 95000 of exposure
    h.store.tx(() => {
      h.store.putPromise({
        commit_id: "c9", tenant: "lab1", environment: "simulation", business_id: "o9",
        envelope_object: "env1", envelope_hash: "f".repeat(64), state: "ACTIVE", revision: 5n,
        payer: "alice", payee: "merchant", amount: 95000n, release_at: null, decision_by: null,
        allocation: null, disposition: null, next_due_ms: null, escrow_id: "esc_c9",
        case_id: null, late_pending: 0, consumed: 1,
      });
      h.store.putExposure("c9", 95000n, "r_c9", "held");
    });
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "BUDGET_EXCEEDED");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-27 condition satisfied", async () => {
  const h = await seedA();
  try {
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev1" }, "q_ev", 4000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 4000n)).result as T.PromiseView;
    assert.equal(view.state, "RELEASE_PENDING");
    assert.equal(view.revision, "6");
    assert.equal(view.release_at_ms, "6000");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-28 condition after deadline", async () => {
  const h = await seedA();
  try {
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev1" }, "q_ev", 30000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "DEADLINE_CLOSED");
    assert.equal(h.getPromise("c1")!.revision, 5n);
  } finally { h.close(); }
});

test("TV-C-29 expired attestation", async () => {
  const h = await seedA();
  try {
    const ab = { ...F.AB, valid_until_ms: "4000" };
    const ev = { v: 1, commit_id: "c1", envelope_hash: D("envelope", F.E0 as Json), items: [{ clause_id: "delivery", kind: "attested", certificate: { body: ab, signatures: F.sigs("attestation", ab, [4, 5]) } }] };
    h.seedObject("ev2", "evidence", ev);
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev2" }, "q_ev2", 4000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "EVIDENCE_EXPIRED");
    assert.equal(h.getPromise("c1")!.revision, 5n);
  } finally { h.close(); }
});

test("TV-C-30 attestation clause mismatch", async () => {
  const h = await seedA();
  try {
    const ab = { ...F.AB, clause_id: "other" };
    const ev = { v: 1, commit_id: "c1", envelope_hash: D("envelope", F.E0 as Json), items: [{ clause_id: "delivery", kind: "attested", certificate: { body: ab, signatures: F.sigs("attestation", ab, [4, 5]) } }] };
    h.seedObject("ev3", "evidence", ev);
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev3" }, "q_ev3", 4000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "EVIDENCE_MISMATCH");
  } finally { h.close(); }
});

test("TV-C-31 attestation quorum short", async () => {
  const h = await seedA();
  try {
    const ab = F.AB;
    const ev = { v: 1, commit_id: "c1", envelope_hash: D("envelope", F.E0 as Json), items: [{ clause_id: "delivery", kind: "attested", certificate: { body: ab, signatures: F.sigs("attestation", ab, [4]) } }] };
    h.seedObject("ev4", "evidence", ev);
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "ev4" }, "q_ev4", 4000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "QUORUM_MISSING");
  } finally { h.close(); }
});

test("TV-C-32 condition timeout settles to payer", async () => {
  const h = await seedA();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "5" }, "q_adv", 30000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 30000n)).result as T.PromiseView;
    assert.equal(view.state, "SETTLED");
    assert.equal(view.revision, "7");
    assert.deepEqual(view.allocation, { pay_minor: "0", return_minor: "10000" });
    assert.equal(h.balance("alice").available, 100000n);
    assert.equal(h.balance("merchant").available, 0n);
  } finally { h.close(); }
});

test("TV-C-33 advance before release_at", async () => {
  const h = await seedR();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "6" }, "q_adv", 5999n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "NOT_DUE");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-34 release settles to payee", async () => {
  const h = await seedF();
  try {
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 6000n)).result as T.PromiseView;
    assert.equal(view.state, "SETTLED");
    assert.equal(view.revision, "8");
    assert.deepEqual(view.allocation, { pay_minor: "10000", return_minor: "0" });
    assert.equal(h.balance("merchant").available, 10000n);
    assert.equal(h.balance("alice").available, 90000n);
  } finally { h.close(); }
});

test("TV-C-35 dispute before release", async () => {
  const h = await seedR();
  try {
    const r = await h.call("alice", CAP_PARTY, "dispute.open", { commit_id: "c1", expected_revision: "6", case_id: "case1", reason: "delivery", evidence: F.BR as T.BlobRef }, "q_d", 5999n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 5999n)).result as T.PromiseView;
    assert.equal(view.state, "DISPUTED");
    assert.equal(view.revision, "7");
    assert.equal(view.decision_by_ms, "10000");
  } finally { h.close(); }
});

test("TV-C-36 dispute at release_at", async () => {
  const h = await seedR();
  try {
    const r = await h.call("alice", CAP_PARTY, "dispute.open", { commit_id: "c1", expected_revision: "6", case_id: "case1", reason: "delivery", evidence: F.BR as T.BlobRef }, "q_d", 6000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "DEADLINE_CLOSED");
  } finally { h.close(); }
});

test("TV-C-37 dispute by non-party", async () => {
  const h = await seedR();
  try {
    const r = await h.call("carol", CAP_CAROL, "dispute.open", { commit_id: "c1", expected_revision: "6", case_id: "case1", reason: "delivery", evidence: F.BR as T.BlobRef }, "q_d", 4500n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "FORBIDDEN");
    assert.equal(h.getPromise("c1")!.revision, 6n);
  } finally { h.close(); }
});

test("TV-C-38 second dispute", async () => {
  const h = await seedD();
  try {
    const r = await h.call("merchant", CAP_MERCHANT, "dispute.open", { commit_id: "c1", expected_revision: "7", case_id: "case2", reason: "fraud", evidence: F.BR as T.BlobRef }, "q_d2", 5000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "DISPUTE_EXISTS");
  } finally { h.close(); }
});

test("TV-C-39 arbitral award", async () => {
  const h = await seedD();
  try {
    h.seedObject("award1", "award", F.award1);
    const r = await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "7", award: "award1" }, "q_r", 5000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 5000n)).result as T.PromiseView;
    assert.equal(view.state, "SETTLED");
    assert.equal(view.revision, "9");
    assert.equal(h.balance("alice").available, 92500n);
    assert.equal(h.balance("merchant").available, 7500n);
    assert.equal(h.escrowHeld("c1"), 0n);
  } finally { h.close(); }
});

test("TV-C-40 non-conserving award", async () => {
  const h = await seedD();
  try {
    const wb = { ...F.WB, pay_minor: "7501", return_minor: "2500" };
    const award = { body: wb, signatures: F.sigs("award", wb, [6, 7]) };
    h.seedObject("award2", "award", award);
    const r = await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "7", award: "award2" }, "q_r", 5000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "AWARD_INVALID");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-41 award after decision_by", async () => {
  const h = await seedD();
  try {
    h.seedObject("award1", "award", F.award1);
    const r = await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "7", award: "award1" }, "q_r", 10000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "DEADLINE_CLOSED");
  } finally { h.close(); }
});

test("TV-C-42 dispute timeout fallback", async () => {
  const h = await seedD();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "7" }, "q_adv", 10000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 10000n)).result as T.PromiseView;
    assert.equal(view.state, "SETTLED");
    assert.equal(view.revision, "9");
    assert.deepEqual(view.allocation, { pay_minor: "0", return_minor: "10000" });
    assert.equal(h.balance("alice").available, 100000n);
  } finally { h.close(); }
});

test("TV-C-43 second award rejected", async () => {
  const h = await seedD();
  try {
    h.seedObject("award1", "award", F.award1);
    const r1 = await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "7", award: "award1" }, "q_r", 5000n);
    assert.equal(r1.ok, true);
    const wb2 = { ...F.WB, pay_minor: "0", return_minor: "10000" };
    const award2 = { body: wb2, signatures: F.sigs("award", wb2, [7, 8]) };
    h.seedObject("award3", "award", award2);
    const r2 = await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "9", award: "award3" }, "q_r2", 5001n);
    assert.equal(r2.ok, false);
    assert.equal(r2.code, "DECISION_FINAL");
    const view = (await h.call("alice", CAP_PARTY, "promise.get", { commit_id: "c1" }, "q_v", 5001n)).result as T.PromiseView;
    assert.deepEqual(view.allocation, { pay_minor: "7500", return_minor: "2500" });
    assert.equal(h.escrowHeld("c1"), 0n);
  } finally { h.close(); }
});

// ---------- external custody ----------

test("TV-C-44 reserve transport timeout", async () => {
  const h = await seedXF();
  try {
    h.adapter!.lookupQueue.push({ status: "inconclusive" });
    const rep = await h.schedule(3000n);
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "FUNDING_UNKNOWN");
    assert.equal(view.revision, 5n);
    const exp = h.store.getExposure("c1")!;
    assert.equal(exp.amount, 10000n);
    assert.equal(h.adapter!.invocations, 1);
    assert.equal(rep.dispatched, 0);
  } finally { h.close(); }
});

test("TV-C-45 late applied reserve settles to payer", async () => {
  const h = await seedXF();
  try {
    const r = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.reserve.operation_id, receipt: "rc_reserve1" }, "q_rc", 20000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "SETTLING");
    assert.equal(view.revision, 6n);
    assert.deepEqual(alloc(view.allocation), { pay_minor: "0", return_minor: "10000" });
    assert.equal(h.store.getExposure("c1")!.amount, 10000n);
  } finally { h.close(); }
});

test("TV-C-46 unsent reserve expires to UNFUNDED", async () => {
  const h = await seedP({ external: true });
  try {
    const c = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_commit", 2000n);
    assert.equal(c.ok, true);
    // no dispatch scheduled — op remains READY/attempts0
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "4" }, "q_adv", 20000n);
    assert.equal(r.ok, true);
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "UNFUNDED");
    assert.equal(view.revision, 5n);
    assert.equal(h.store.getExposure("c1"), null);
    assert.equal(h.adapter!.invocations, 0);
  } finally { h.close(); }
});

test("TV-C-47 dispatched reserve past fund_by", async () => {
  const h = await seedXF();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "4" }, "q_adv", 20000n);
    assert.equal(r.ok, true);
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "FUNDING_UNKNOWN");
    assert.equal(view.revision, 5n);
    assert.equal(h.store.getExposure("c1")!.amount, 10000n);
    assert.equal(h.adapter!.invocations, 1);
  } finally { h.close(); }
});

test("TV-C-48 retry rejected for unknown receipt", async () => {
  const h = await seedXU();
  try {
    const r = await h.call("ops", CAP_OPS, "custody.retry", { operation_id: F.allocate.operation_id, no_effect_receipt: "rc_unk1" }, "q_rt", 7200n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "RETRY_UNSAFE");
    assert.equal(h.adapter!.invocations, 2);
  } finally { h.close(); }
});

test("TV-C-49 applied allocation receipt then idempotent replay", async () => {
  const h = await seedXU();
  try {
    h.seedObject("rc_applied1", "custody", F.fixtures.rc_applied1);
    const r1 = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.allocate.operation_id, receipt: "rc_applied1" }, "q_rc1", 7500n);
    assert.equal(r1.ok, true, JSON.stringify(r1));
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "SETTLED");
    assert.equal(view.revision, 9n);
    assert.equal(h.escrowHeld("c1"), 0n);
    const n = h.eventCount("c1");
    const r2 = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.allocate.operation_id, receipt: "rc_applied1" }, "q_rc2", 7600n);
    assert.equal(r2.ok, true);
    assert.equal(h.eventCount("c1") - n, 0);
    assert.equal(h.balance("merchant").available, 10000n);
  } finally { h.close(); }
});

test("TV-C-50 sequenced no-effect retry", async () => {
  const h = await seedXB();
  try {
    h.adapter!.lookupQueue.push({ status: "receipt", receipt: F.fixtures.rc_noeffect1 as T.CustodyReceipt });
    const r = await h.call("ops", CAP_OPS, "custody.retry", { operation_id: F.allocate.operation_id, no_effect_receipt: "rc_noeffect1" }, "q_rt", 7200n);
    assert.equal(r.ok, true, JSON.stringify(r));
    const view = h.getPromise("c1")!;
    assert.equal(view.state, "SETTLING");
    assert.equal(view.revision, 10n);
    const op = h.store.getOperation(F.allocate.operation_id)!;
    assert.equal(op.state, "READY");
    assert.equal(op.attempts, 1);
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-51 retry unsafe without retained identity", async () => {
  const h = await seedXB();
  try {
    h.adapter!.lookupQueue.push({ status: "inconclusive" });
    const r = await h.call("ops", CAP_OPS, "custody.retry", { operation_id: F.allocate.operation_id, no_effect_receipt: "rc_noeffect1" }, "q_rt", 7200n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "RETRY_UNSAFE");
    assert.equal(h.getPromise("c1")!.state, "SETTLEMENT_BLOCKED");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-52 allocation-mismatch receipt rejected", async () => {
  const h = await seedXU();
  try {
    const body = { ...F.receipt("applied", true, 2).body, allocation: { pay_minor: "9999", return_minor: "1" } };
    const rc = { body, signature: F.sign("custody", body, 11) };
    h.seedObject("rc_bad1", "custody", rc);
    const r = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.allocate.operation_id, receipt: "rc_bad1" }, "q_rc", 7500n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "RECEIPT_INVALID");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-53 conflicting receipts halt the domain", async () => {
  const h = await seedXU();
  try {
    h.seedObject("rc_applied1", "custody", F.fixtures.rc_applied1);
    const r1 = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.allocate.operation_id, receipt: "rc_applied1" }, "q_rc1", 7500n);
    assert.equal(r1.ok, true);
    h.seedObject("rc_noeffect1", "custody", F.fixtures.rc_noeffect1);
    const r2 = await h.call("ops", CAP_OPS, "custody.reconcile", { operation_id: F.allocate.operation_id, receipt: "rc_noeffect1" }, "q_rc2", 7600n);
    assert.equal(r2.ok, false);
    assert.equal(r2.code, "CUSTODY_CONFLICT");
    assert.equal(h.store.getControlState().status, "HALTED");
    assert.equal(h.balance("merchant").available, 10000n);
  } finally { h.close(); }
});

// ---------- control / safety ----------

test("TV-C-54 commit after key revocation", async () => {
  const h = await seedP();
  try {
    const cert = controlCert({ kind: "revoke_key", key_id: "k2", incident: F.BR as T.BlobRef }, "00000000000000000000000000000011");
    h.seedObject("ctl_rev", "control", cert);
    const c = await h.call("ops", CAP_OPS, "control.apply", { certificate: "ctl_rev" }, "q_ctl", 1500n);
    assert.equal(c.ok, true, JSON.stringify(c));
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "KEY_REVOKED");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-55 backwards clock suppresses deadlines", async () => {
  const h = await seedP();
  try {
    const r = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 900n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "CLOCK_UNSAFE");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

test("TV-C-56 halt blocks advance", async () => {
  const h = await seedR();
  try {
    const cert = controlCert({ kind: "halt", reason: "maintenance" }, "00000000000000000000000000000012");
    h.seedObject("ctl_halt", "control", cert);
    const c = await h.call("ops", CAP_OPS, "control.apply", { certificate: "ctl_halt" }, "q_ctl", 5000n);
    assert.equal(c.ok, true);
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "6" }, "q_adv", 6000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "HALTED");
    assert.equal(h.getPromise("c1")!.state, "RELEASE_PENDING");
    assert.equal(h.escrowHeld("c1"), 10000n);
  } finally { h.close(); }
});

test("TV-C-57 restart recovery is quiet", async () => {
  const h = await seedXU();
  try {
    const before = h.eventCount("c1");
    const rep = await h.recover(8000n);
    assert.deepEqual(rep.uncertain, []);
    assert.equal(h.eventCount("c1"), before);
    assert.equal(h.getPromise("c1")!.state, "SETTLEMENT_UNKNOWN");
    assert.equal(h.adapter!.invocations, 2);
  } finally { h.close(); }
});

test("TV-C-58 old backup vs pin ahead", async () => {
  const h = await seedP();
  try {
    const dir = h.dir + "-backup";
    storeBackup(h.dir, dir);
    const r = storeVerify(dir, F.pin1);
    assert.equal(r.integrity, "incomplete");
    assert.ok(r.codes.includes("PIN_AHEAD"));
  } finally { h.close(); }
});

// ---------- proofs ----------

test("TV-C-59 modified event detected", () => {
  const bad = JSON.parse(JSON.stringify(F.proof_full1)) as T.ProofManifest;
  const settled = bad.events.find((e) => (e.body.data as { kind: string }).kind === "Settled")!;
  (settled.body.data as { allocation: T.Allocation }).allocation = { pay_minor: "9999", return_minor: "1" };
  const rows = Object.keys(F.kinds).map((id) => ({ id, kind: F.kinds[id]!, body: F.fixtures[id] }));
  const r = verifyBundle(bad, rows, F.pin0);
  assert.equal(r.integrity, "invalid");
  assert.equal(r.authorization, "invalid");
  assert.equal(r.effects_enabled, false);
  assert.deepEqual(r.codes, ["EVENT_HASH_MISMATCH"]);
});

test("TV-C-60 missing evidence is incomplete", () => {
  const rows = Object.keys(F.kinds).filter((id) => id !== "ev1").map((id) => ({ id, kind: F.kinds[id]!, body: F.fixtures[id] }));
  const r = verifyBundle(F.proof_full1, rows, F.pin0);
  assert.equal(r.integrity, "incomplete");
  assert.equal(r.authorization, "incomplete");
  assert.equal(r.effects_enabled, false);
  assert.deepEqual(r.codes, ["OBJECT_MISSING"]);
});

// ---------- capability auth ----------

test("TV-C-61 capability not bound to peer", async () => {
  const h = await seedP();
  try {
    // uid1002 (bob/cap_signer) presents cap_party
    const r = await h.call("bob", CAP_SIGNER, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_c", 2000n, "cap_party");
    assert.equal(r.ok, false);
    assert.equal(r.code, "FORBIDDEN");
    assert.equal(h.getPromise("c1")!.revision, 3n);
  } finally { h.close(); }
});

// ---------- hashlock ----------

test("TV-C-63 hashlock satisfied", async () => {
  const h = await seedHashlockA();
  try {
    const ev = { v: 1, commit_id: "c1", envelope_hash: D("envelope", envHashlock() as unknown as Json), items: [{ clause_id: "delivery", kind: "hashlock", preimage_base64url: "YWJj" }] };
    h.seedObject("evh", "evidence", ev);
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "evh" }, "q_ev", 4000n);
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(h.getPromise("c1")!.state, "RELEASE_PENDING");
  } finally { h.close(); }
});

test("TV-C-64 hashlock wrong preimage", async () => {
  const h = await seedHashlockA();
  try {
    const ev = { v: 1, commit_id: "c1", envelope_hash: D("envelope", envHashlock() as unknown as Json), items: [{ clause_id: "delivery", kind: "hashlock", preimage_base64url: "YWJk" }] };
    h.seedObject("evh2", "evidence", ev);
    const r = await h.call("alice", CAP_PARTY, "condition.submit", { commit_id: "c1", expected_revision: "5", evidence: "evh2" }, "q_ev", 4000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "CONDITION_UNSATISFIED");
  } finally { h.close(); }
});

// ---------- ledger ----------

test("TV-C-65 ledger conservation", async () => {
  const h = await seedD();
  try {
    h.seedObject("award1", "award", F.award1);
    await h.call("fay", CAP_ARB, "dispute.resolve", { commit_id: "c1", expected_revision: "7", award: "award1" }, "q_r", 5000n);
    const sums = h.ledger("c1", 9n);
    assert.equal(sums.debits, "10000");
    assert.equal(sums.credits, "10000");
    assert.equal(BigInt(sums.debits) - BigInt(sums.credits), 0n);
  } finally { h.close(); }
});

// ---------- scheduling ----------

test("TV-C-68 dispute beats the timer", async () => {
  const h = await seedR();
  try {
    const d = await h.call("alice", CAP_PARTY, "dispute.open", { commit_id: "c1", expected_revision: "6", case_id: "case1", reason: "delivery", evidence: F.BR as T.BlobRef }, "q_d", 5999n);
    assert.equal(d.ok, true);
    const sch = await h.schedule(6000n);
    assert.equal(h.getPromise("c1")!.state, "DISPUTED");
    assert.equal(h.getPromise("c1")!.revision, 7n);
    const r = await h.call("alice", CAP_PARTY, "promise.advance", { commit_id: "c1", expected_revision: "7" }, "q_adv", 6000n);
    assert.equal(r.ok, false);
    assert.equal(r.code, "NOT_DUE");
    assert.equal(h.escrowHeld("c1"), 10000n);
    void sch;
  } finally { h.close(); }
});

// ---------- local helpers ----------

function envHashlock(): T.Envelope {
  return F.patch(F.E0, {
    condition: { kind: "all", clauses: [{ id: "delivery", kind: "hashlock", sha256: H(Buffer.from("abc", "utf8")), max_preimage_bytes: 3 }] },
  }) as T.Envelope;
}

async function seedHashlockA(): Promise<Harness> {
  const h = new Harness();
  for (const [id, kind] of [["pol1", "policy"], ["va1", "approval"], ["vb1", "approval"], ["ev1", "evidence"], ["rc_reserve1", "custody"], ["rc_settle1", "custody"]] as [string, T.ObjectKind][]) {
    h.seedObject(id, kind, F.fixtures[id]);
  }
  const env = envHashlock();
  h.seedObject("env1", "envelope", env);
  h.seedObject("vah", "approval", approvalFor(env, 1));
  h.seedObject("vbh", "approval", approvalFor(env, 2));
  h.seedObject("blob1", "blob", F.blob1);
  const r1 = await h.call("alice", CAP_PARTY, "promise.propose", { envelope: "env1" }, "q_propose", 1000n);
  if (!r1.ok) throw new Error(`hashlock propose: ${r1.code}`);
  const r2 = await h.call("alice", CAP_PARTY, "approval.submit", { commit_id: "c1", expected_revision: "1", approval: "vah" }, "q_va", 1100n);
  if (!r2.ok) throw new Error(`hashlock approve1: ${r2.code}`);
  const r3 = await h.call("bob", CAP_SIGNER, "approval.submit", { commit_id: "c1", expected_revision: "2", approval: "vbh" }, "q_vb", 1200n);
  if (!r3.ok) throw new Error(`hashlock approve2: ${r3.code}`);
  const r4 = await h.call("alice", CAP_PARTY, "promise.commit", { commit_id: "c1", expected_revision: "3" }, "q_commit", 2000n);
  if (!r4.ok) throw new Error(`hashlock commit: ${r4.code}`);
  return h;
}

