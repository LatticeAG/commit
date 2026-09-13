// §11.1 fixture generator — verbatim port of the published deterministic
// generator. Public test material only; never usable for deployment.

import crypto from "node:crypto";

export const J = (x: unknown): string => {
  if (x === null || typeof x !== "object") return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map(J).join(",") + "]";
  return "{" + Object.keys(x as Record<string, unknown>).sort().map((k) => JSON.stringify(k) + ":" + J((x as Record<string, unknown>)[k])).join(",") + "}";
};
export const H = (b: Buffer | string) => crypto.createHash("sha256").update(b).digest("hex");
export const D = (k: string, x: unknown) => H(Buffer.concat([Buffer.from("LAGI-COMMIT/" + k + "/1\0"), Buffer.from(J(x))]));
export const key = (i: number) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, i)]), format: "der", type: "pkcs8" });
export const pub = (i: number) => crypto.createPublicKey(key(i)).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
export const sign = (k: string, b: unknown, i: number) => crypto.sign(null, Buffer.concat([Buffer.from("LAGI-COMMIT-SIGN/" + k + "/1\0"), Buffer.from(D(k, b), "hex")]), key(i)).toString("hex");
export const sigs = (kind: string, body: unknown, indices: number[]) => indices.map((i) => ({ key_id: "k" + i, sig: sign(kind, body, i) })).sort((a, b) => (a.key_id < b.key_id ? -1 : 1));
export const seed = (i: number) => Buffer.alloc(32, i);

const names = ["alice", "bob", "carol", "dana", "eli", "fay", "gus", "hal", "ivy", "jay"];
export const members = names.map((principal, i) => ({ key_id: "k" + (i + 1), principal, kind: [2, 4].includes(i) ? "service" : "human", public_key: pub(i + 1) })).sort((a, b) => (a.key_id < b.key_id ? -1 : 1));
export const asset = { code: "SIMUSD", scale: 2, custody: "sim1" };
export const quorum = (keys: string[], mandatory_principals: string[] = []) => ({ threshold: 2, keys: [...keys].sort(), mandatory_principals });

export const P0 = {
  v: 1, policy_id: "pol1", tenant: "lab1", environment: "simulation", custody: "sim1", asset, members,
  approve: quorum(["k1", "k2", "k3"], ["alice"]), attest: quorum(["k4", "k5"]), arbitrate: quorum(["k6", "k7", "k8"]), control: quorum(["k9", "k10"]),
  max_amount_minor: "50000", max_exposure_minor: "100000", daily_commit_minor: "100000", max_duration_ms: "2592000000", min_challenge_ms: "1000",
  rules_digest: H(Buffer.from("rules-v1")),
};

export const E0 = {
  v: 1, tenant: "lab1", environment: "simulation", commit_id: "c1", business_id: "invoice7",
  payer: "alice", payee: "merchant", custody: "sim1", asset,
  amount_minor: "10000", policy_hash: D("policy", P0), nonce: "00000000000000000000000000000001",
  created_ms: "1000", commit_by_ms: "10000", fund_by_ms: "20000",
  condition_by_ms: "30000", challenge_ms: "2000", dispute_ms: "4000", dispute_fallback_pay_minor: "0",
  condition: { kind: "all", clauses: [{ id: "delivery", kind: "attested", predicate: "delivery.accepted", authority: "attest" }] },
  purpose: "Invoice 7 delivery", parents: [],
};

export const approval = (i: number) => {
  const body = { v: 1, tenant: "lab1", environment: "simulation", commit_id: "c1", envelope_hash: D("envelope", E0), policy_hash: D("policy", P0), key_id: "k" + i, decision: "approve" };
  return { body, signature: sign("approval", body, i) };
};
export const blob1 = { encoding: "base64url", data: "e30" };
export const BR = { object: "blob1", sha256: H(Buffer.from("{}")), bytes: "2", media: "application/json" };
export const AB = { v: 1, tenant: "lab1", environment: "simulation", commit_id: "c1", envelope_hash: D("envelope", E0), clause_id: "delivery", predicate: "delivery.accepted", outcome: "satisfied", evidence: BR, issued_ms: "3000", valid_until_ms: "30000" };
export const ev1 = { v: 1, commit_id: "c1", envelope_hash: D("envelope", E0), items: [{ clause_id: "delivery", kind: "attested", certificate: { body: AB, signatures: sigs("attestation", AB, [4, 5]) } }] };
export const WB = { v: 1, tenant: "lab1", environment: "simulation", commit_id: "c1", envelope_hash: D("envelope", E0), case_id: "case1", rules_digest: P0.rules_digest, evidence: [BR], pay_minor: "7500", return_minor: "2500", reason: "performance" };
export const award1 = { body: WB, signatures: sigs("award", WB, [6, 7]) };
export const CB = { v: 1, tenant: "lab1", environment: "simulation", base_revision: "0", nonce: "00000000000000000000000000000002", expires_ms: "50000", action: { kind: "halt", reason: "maintenance" } };
export const halt1 = { body: CB, signatures: sigs("control", CB, [9, 10]) };

export const suffix = D("envelope", E0).slice(0, 32);
export const reserve = { v: 1, tenant: "lab1", environment: "simulation", custody: "sim1", operation_id: "r_" + suffix, kind: "reserve", envelope_hash: D("envelope", E0), escrow_id: "e_" + suffix, payer: "alice", payee: "merchant", asset, amount_minor: "10000", allocation: null, not_after_ms: "20000", fence: "1" };
export const allocate = { ...reserve, operation_id: "s_" + suffix, kind: "allocate", allocation: { pay_minor: "10000", return_minor: "0" }, not_after_ms: null };
export const receipt = (status: string, final: boolean, revision: number) => {
  const body = { v: 1, custody: "sim1", operation_id: allocate.operation_id, request_hash: D("custody", allocate), escrow_id: allocate.escrow_id, status, final, attempt: 1, allocation: allocate.allocation, amount_minor: "10000", provider_revision: String(revision), observed_ms: "7000", evidence: null };
  return { body, signature: sign("custody", body, 11) };
};
export const rcReserveBody = { v: 1, custody: "sim1", operation_id: reserve.operation_id, request_hash: D("custody", reserve), escrow_id: reserve.escrow_id, status: "applied", final: true, attempt: 1, allocation: null, amount_minor: "10000", provider_revision: "1", observed_ms: "2000", evidence: null };
export const rc_reserve1 = { body: rcReserveBody, signature: sign("custody", rcReserveBody, 11) };
export const rcSettleBody = { ...receipt("applied", true, 1).body, observed_ms: "6000" };
export const rc_settle1 = { body: rcSettleBody, signature: sign("custody", rcSettleBody, 11) };

export const fixtures: Record<string, unknown> = {
  pol1: P0, env1: E0, va1: approval(1), vb1: approval(2), vc1: approval(3), blob1, ev1, award1, halt1, reserve, allocate, rc_reserve1, rc_settle1,
  rc_unknown1: receipt("unknown", false, 1), rc_noeffect1: receipt("no_effect", true, 2), rc_applied1: receipt("applied", true, 2),
};

export const kinds: Record<string, string> = { pol1: "policy", env1: "envelope", va1: "approval", vb1: "approval", blob1: "blob", ev1: "evidence", rc_reserve1: "custody", rc_settle1: "custody" };
export const entry = (id: string) => {
  const kind = kinds[id]!, body = fixtures[id]!, wrapped = ["approval", "custody"].includes(kind);
  return { id, kind, digest: kind === "blob" ? H(Buffer.from((body as { data: string }).data, "base64url")) : wrapped ? D("manifest", { kind, body }) : D(kind, body), bytes: String(kind === "blob" ? Buffer.from((body as { data: string }).data, "base64url").length : Buffer.byteLength(J(body))) };
};
export const order = (a: { kind: string; digest: string; id: string }, b: { kind: string; digest: string; id: string }) => {
  const x = [a.kind, a.digest, a.id].join("/"), y = [b.kind, b.digest, b.id].join("/");
  return x < y ? -1 : x > y ? 1 : 0;
};

export const events: { body: Record<string, unknown>; hash: string; key_id: string; signature: string }[] = [];
export const event = (from: string | null, to: string | null, time_ms: string, command_id: string, data: unknown, ids: string[]) => {
  const body = {
    v: 1, tenant: "lab1", environment: "simulation", stream: "c1", seq: String(events.length + 1),
    prev: events.length ? events.at(-1)!.hash : "0".repeat(64), command_id, time_ms, writer_epoch: "1", authority_seq: "0",
    policy_hash: D("policy", P0), from, to, objects: ids.map(entry).sort(order), data,
  };
  events.push({ body, hash: D("event", body), key_id: "writer1", signature: sign("event", body, 12) });
};

event(null, "PROPOSED", "1000", "q_propose", { kind: "Proposed", envelope: "env1", envelope_hash: D("envelope", E0), business_id: "invoice7" }, ["env1"]);
event("PROPOSED", "PROPOSED", "1100", "q_va", { kind: "ApprovalAccepted", approval: "va1", key_id: "k1" }, ["va1"]);
event("PROPOSED", "PROPOSED", "1200", "q_vb", { kind: "ApprovalAccepted", approval: "vb1", key_id: "k2" }, ["vb1"]);
event("PROPOSED", "FUNDING", "2000", "q_commit", { kind: "CommitAuthorized", reserve, approvals: ["va1", "vb1"], budget_day: "0" }, ["va1", "vb1"]);
event("FUNDING", "ACTIVE", "2000", "q_commit", { kind: "EscrowHeld", receipt: "rc_reserve1", escrow_id: reserve.escrow_id }, ["rc_reserve1"]);
event("ACTIVE", "RELEASE_PENDING", "4000", "q_condition", { kind: "ConditionSatisfied", evidence: "ev1", release_at_ms: "6000" }, ["ev1"]);
event("RELEASE_PENDING", "SETTLING", "6000", "q_advance", { kind: "SettlementDecided", reason: "release", award: null, allocation: allocate.allocation, request: allocate }, []);
event("SETTLING", "SETTLED", "6000", "q_advance", { kind: "Settled", receipt: "rc_settle1", allocation: allocate.allocation }, ["rc_settle1"]);

export const balances = [
  { account: "alice", available_minor: "90000", held_minor: "0" },
  { account: "escrow_c1", available_minor: "0", held_minor: "0" },
  { account: "merchant", available_minor: "10000", held_minor: "0" },
];
export const checkpointBody = { v: 1, tenant: "lab1", environment: "simulation", stream: "c1", seq: "8", head: events.at(-1)!.hash, authority_head: "0".repeat(64), ledger_root: H(Buffer.from(J(balances))), writer_epoch: "1", created_ms: "6000" };
export const checkpoint = { body: checkpointBody, key_id: "writer1", signature: sign("checkpoint", checkpointBody, 12) };
export const custody_manifest = { v: 1, custody: "sim1", profile: "sim-ledger/1", asset, implementation_digest: H(Buffer.from("sim-ledger/1")), receipt_key: pub(11), idempotency_min_ms: "2592000000", authoritative_lookup: true, atomic_allocation: true, fencing: true, retry_mode: "never" };
export const custody_manifest_retry = { ...custody_manifest, retry_mode: "sequenced-no-effect/1" };
export const proof_full1 = { v: 1, format: "commit-proof/1", commit_id: "c1", disclosure: "full", previous: null, events, authority_events: [], objects: Object.keys(kinds).map(entry).sort(order), checkpoint, custody_manifest };
export const proof1 = { ...proof_full1, disclosure: "redacted" };
export const pin1 = { v: 1, tenant: "lab1", environment: "simulation", genesis_policy_hash: D("policy", P0), writer_key: pub(12), writer_epoch: "1", custody_key: pub(11), custody_manifest_hash: D("custody_manifest", custody_manifest), reducer_digest: H(Buffer.from("commit-reducer/1")), minimum_checkpoint: checkpoint };
const rows = [{ id: "proof1", kind: "manifest", body: proof1 }, ...proof1.objects.filter((e) => !["blob1", "ev1"].includes(e.id)).map((e) => ({ id: e.id, kind: e.kind, body: fixtures[e.id] }))];
export const chunk = Buffer.from(rows.map(J).join("\n") + "\n");
export const exportResult = { manifest: "proof1", chunk: { object: "chunk1", sha256: H(chunk), bytes: String(chunk.length), media: "application/octet-stream" }, next_cursor: null, complete: true };
export const pin0 = { ...pin1, minimum_checkpoint: null };
Object.assign(fixtures, { proof_full1, proof1, pin0, pin1, custody_manifest, chunk1: { encoding: "base64url", data: chunk.toString("base64url") } });

export const digests = { policy: D("policy", P0), envelope: D("envelope", E0), allocate: D("custody", allocate), blob: BR.sha256, proof: D("manifest", proof1), canonical_envelope_bytes: Buffer.byteLength(J(E0)) };

/** RFC 7396 merge patch over a deep copy. */
export function patch<T>(x: T, p: Record<string, unknown>): T {
  const out = JSON.parse(JSON.stringify(x)) as Record<string, unknown>;
  const apply = (tgt: Record<string, unknown>, src: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(src)) {
      if (v === null) delete tgt[k];
      else if (v !== null && typeof v === "object" && !Array.isArray(v) && typeof tgt[k] === "object" && tgt[k] !== null && !Array.isArray(tgt[k])) apply(tgt[k] as Record<string, unknown>, v as Record<string, unknown>);
      else tgt[k] = v;
    }
  };
  apply(out, p);
  return out as T;
}
