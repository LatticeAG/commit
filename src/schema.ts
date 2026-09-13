// Closed-schema runtime validators for every §1.2–§3.1 type (§1.1 rules are
// normative runtime contracts). Every field required, nullable = null, no
// unknown members. Structural violations → SCHEMA_INVALID; monetary U64 range
// violations → AMOUNT_OVERFLOW.

import { err } from "./errors.ts";
import type { Json } from "./json/strict.ts";
import {
  ASSET_CODE_RE, ID_RE, MAX_AWARD_EVIDENCE, MAX_CLAUSES, MAX_DURATION_MS,
  MAX_EVIDENCE_ITEMS, MAX_PARENTS, MAX_POLICY_MEMBERS, MAX_PREIMAGE_BYTES,
  MAX_QUORUM_KEYS, MAX_SIGNATURES, MAX_BLOB_BYTES, NONCE_RE, PREDICATE_RE,
  PUBKEY_RE, SIG_RE, DIGEST_RE, STRING_BOUND_DEFAULT, STRING_BOUND_EXTREF,
  STRING_BOUND_PURPOSE, decodeBase64urlCanonical, isAscii, moneyU64, safeInt,
  sortedUnique, strictU64, utf8Len,
} from "./scalars.ts";
import { METHODS, OBJECT_KINDS } from "./types.ts";
import type * as T from "./types.ts";

type J = Json;

function isObj(v: unknown): v is { [k: string]: J } {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function keys(v: { [k: string]: J }, required: string[]): void {
  const want = new Set(required);
  for (const k of Object.keys(v)) {
    if (!want.has(k)) throw err("SCHEMA_INVALID", `unknown member "${k}"`);
  }
  for (const k of required) {
    if (!Object.hasOwn(v, k)) throw err("SCHEMA_INVALID", `missing member "${k}"`);
  }
}

function id(v: unknown, f: string, reserved = false): string {
  if (typeof v !== "string" || !ID_RE.test(v) || (!reserved && v === "control")) {
    throw err("SCHEMA_INVALID", `${f} is not a valid Id`);
  }
  return v;
}

function digest(v: unknown, f: string): string {
  if (typeof v !== "string" || !DIGEST_RE.test(v)) throw err("SCHEMA_INVALID", `${f} is not a Digest`);
  return v;
}

function nonce(v: unknown, f: string): string {
  if (typeof v !== "string" || !NONCE_RE.test(v)) throw err("SCHEMA_INVALID", `${f} is not a Nonce`);
  return v;
}

function pub(v: unknown, f: string): string {
  if (typeof v !== "string" || !PUBKEY_RE.test(v)) throw err("SCHEMA_INVALID", `${f} is not a PublicKey`);
  return v;
}

function sig(v: unknown, f: string): string {
  if (typeof v !== "string" || !SIG_RE.test(v)) throw err("SCHEMA_INVALID", `${f} is not a Sig`);
  return v;
}

function u64s(v: unknown, f: string): string {
  strictU64(v, f);
  return v as string;
}

function money(v: unknown, f: string): string {
  moneyU64(v, f);
  return v as string;
}

function str(v: unknown, f: string, max = STRING_BOUND_DEFAULT): string {
  if (typeof v !== "string") throw err("SCHEMA_INVALID", `${f} is not a string`);
  if (utf8Len(v) > max) throw err("SCHEMA_INVALID", `${f} exceeds ${max} bytes`);
  return v;
}

function bool(v: unknown, f: string): boolean {
  if (typeof v !== "boolean") throw err("SCHEMA_INVALID", `${f} is not a boolean`);
  return v;
}

function intnum(v: unknown, f: string, lo: number, hi: number): number {
  const n = safeInt(v, f);
  if (n < lo || n > hi) throw err("SCHEMA_INVALID", `${f} out of range [${lo},${hi}]`);
  return n;
}

function env(v: unknown): T.Environment {
  if (v !== "simulation" && v !== "live") throw err("SCHEMA_INVALID", "environment invalid");
  return v;
}

export function validAsset(v: unknown): T.Asset {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "asset is not an object");
  keys(v, ["code", "scale", "custody"]);
  const code = str(v.code, "asset.code");
  if (!ASSET_CODE_RE.test(code)) throw err("SCHEMA_INVALID", "asset.code invalid");
  return { code, scale: intnum(v.scale, "asset.scale", 0, 9), custody: id(v.custody, "asset.custody") };
}

function validMember(v: unknown): T.Member {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "member is not an object");
  keys(v, ["key_id", "principal", "kind", "public_key"]);
  const kind = v.kind;
  if (kind !== "human" && kind !== "service") throw err("SCHEMA_INVALID", "member.kind invalid");
  return { key_id: id(v.key_id, "member.key_id"), principal: id(v.principal, "member.principal"), kind, public_key: pub(v.public_key, "member.public_key") };
}

function validQuorum(v: unknown, f: string): T.Quorum {
  if (!isObj(v)) throw err("SCHEMA_INVALID", `${f} is not an object`);
  keys(v, ["threshold", "keys", "mandatory_principals"]);
  if (!Array.isArray(v.keys)) throw err("SCHEMA_INVALID", `${f}.keys not an array`);
  if (!Array.isArray(v.mandatory_principals)) throw err("SCHEMA_INVALID", `${f}.mandatory_principals not an array`);
  const k = v.keys.map((x, i) => id(x, `${f}.keys[${i}]`));
  const m = v.mandatory_principals.map((x, i) => id(x, `${f}.mandatory_principals[${i}]`));
  if (k.length > MAX_QUORUM_KEYS || m.length > MAX_QUORUM_KEYS) throw err("LIMIT_EXCEEDED", `${f} roster too large`);
  if (!sortedUnique(k) || !sortedUnique(m)) throw err("SCHEMA_INVALID", `${f} arrays must be sorted and unique`);
  return { threshold: intnum(v.threshold, `${f}.threshold`, 0, MAX_QUORUM_KEYS), keys: k, mandatory_principals: m };
}

export function validPolicy(v: unknown): T.Policy {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "policy is not an object");
  keys(v, ["v", "policy_id", "tenant", "environment", "custody", "asset", "members", "approve", "attest", "arbitrate", "control", "max_amount_minor", "max_exposure_minor", "daily_commit_minor", "max_duration_ms", "min_challenge_ms", "rules_digest"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "policy.v must be 1");
  if (!Array.isArray(v.members)) throw err("SCHEMA_INVALID", "members not an array");
  if (v.members.length === 0 || v.members.length > MAX_POLICY_MEMBERS) throw err("LIMIT_EXCEEDED", "policy members bound");
  const members = v.members.map(validMember);
  const policy: T.Policy = {
    v: 1, policy_id: id(v.policy_id, "policy_id"), tenant: id(v.tenant, "tenant"),
    environment: env(v.environment), custody: id(v.custody, "custody"),
    asset: validAsset(v.asset), members,
    approve: validQuorum(v.approve, "approve"), attest: validQuorum(v.attest, "attest"),
    arbitrate: validQuorum(v.arbitrate, "arbitrate"), control: validQuorum(v.control, "control"),
    max_amount_minor: money(v.max_amount_minor, "max_amount_minor"),
    max_exposure_minor: money(v.max_exposure_minor, "max_exposure_minor"),
    daily_commit_minor: money(v.daily_commit_minor, "daily_commit_minor"),
    max_duration_ms: u64s(v.max_duration_ms, "max_duration_ms"),
    min_challenge_ms: u64s(v.min_challenge_ms, "min_challenge_ms"),
    rules_digest: digest(v.rules_digest, "rules_digest"),
  };
  return policy;
}

export function validBlobRef(v: unknown, f = "blobref"): T.BlobRef {
  if (!isObj(v)) throw err("SCHEMA_INVALID", `${f} is not an object`);
  keys(v, ["object", "sha256", "bytes", "media"]);
  const media = v.media;
  if (media !== "application/json" && media !== "application/octet-stream") throw err("SCHEMA_INVALID", `${f}.media invalid`);
  return { object: id(v.object, `${f}.object`), sha256: digest(v.sha256, `${f}.sha256`), bytes: u64s(v.bytes, `${f}.bytes`), media };
}

function validForeignRef(v: unknown): T.ForeignRef {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "foreign ref is not an object");
  keys(v, ["system", "profile", "ref", "digest"]);
  const system = v.system;
  if (!["covenant", "charter", "world", "proof", "mint", "treaty"].includes(system as string)) {
    throw err("SCHEMA_INVALID", "foreign ref system invalid");
  }
  const profile = str(v.profile, "profile", STRING_BOUND_DEFAULT);
  const ref = str(v.ref, "ref", STRING_BOUND_EXTREF);
  if (!isAscii(profile) || !isAscii(ref)) throw err("SCHEMA_INVALID", "foreign ref must be ASCII");
  return { system: system as T.ForeignRef["system"], profile, ref, digest: str(v.digest, "digest", STRING_BOUND_DEFAULT) };
}

export function validClause(v: unknown): T.Clause {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "clause is not an object");
  const cid = id(v.id, "clause.id");
  if (v.kind === "attested") {
    keys(v, ["id", "kind", "predicate", "authority"]);
    if (v.authority !== "attest") throw err("SCHEMA_INVALID", "clause.authority must be attest");
    const predicate = str(v.predicate, "clause.predicate", 128);
    if (!PREDICATE_RE.test(predicate) || !isAscii(predicate)) throw err("SCHEMA_INVALID", "clause.predicate invalid");
    return { id: cid, kind: "attested", predicate, authority: "attest" };
  }
  if (v.kind === "hashlock") {
    keys(v, ["id", "kind", "sha256", "max_preimage_bytes"]);
    const mpb = intnum(v.max_preimage_bytes, "clause.max_preimage_bytes", 1, MAX_PREIMAGE_BYTES);
    return { id: cid, kind: "hashlock", sha256: digest(v.sha256, "clause.sha256"), max_preimage_bytes: mpb };
  }
  throw err("SCHEMA_INVALID", "clause.kind invalid");
}

export function validEnvelope(v: unknown): T.Envelope {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "envelope is not an object");
  keys(v, ["v", "tenant", "environment", "commit_id", "business_id", "payer", "payee", "custody", "asset", "amount_minor", "policy_hash", "nonce", "created_ms", "commit_by_ms", "fund_by_ms", "condition_by_ms", "challenge_ms", "dispute_ms", "dispute_fallback_pay_minor", "condition", "purpose", "parents"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "envelope.v must be 1");
  if (!isObj(v.condition)) throw err("SCHEMA_INVALID", "condition is not an object");
  keys(v.condition, ["kind", "clauses"]);
  if (v.condition.kind !== "all") throw err("SCHEMA_INVALID", "condition.kind must be all");
  if (!Array.isArray(v.condition.clauses)) throw err("SCHEMA_INVALID", "clauses not an array");
  if (v.condition.clauses.length === 0 || v.condition.clauses.length > MAX_CLAUSES) {
    throw err("LIMIT_EXCEEDED", "clause count bound");
  }
  const clauses = v.condition.clauses.map(validClause);
  if (!Array.isArray(v.parents)) throw err("SCHEMA_INVALID", "parents not an array");
  if (v.parents.length > MAX_PARENTS) throw err("LIMIT_EXCEEDED", "parents bound");
  const parents = v.parents.map(validForeignRef);
  const envelope: T.Envelope = {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    commit_id: id(v.commit_id, "commit_id"), business_id: id(v.business_id, "business_id"),
    payer: id(v.payer, "payer"), payee: id(v.payee, "payee"), custody: id(v.custody, "custody"),
    asset: validAsset(v.asset), amount_minor: money(v.amount_minor, "amount_minor"),
    policy_hash: digest(v.policy_hash, "policy_hash"), nonce: nonce(v.nonce, "nonce"),
    created_ms: u64s(v.created_ms, "created_ms"), commit_by_ms: u64s(v.commit_by_ms, "commit_by_ms"),
    fund_by_ms: u64s(v.fund_by_ms, "fund_by_ms"), condition_by_ms: u64s(v.condition_by_ms, "condition_by_ms"),
    challenge_ms: u64s(v.challenge_ms, "challenge_ms"), dispute_ms: u64s(v.dispute_ms, "dispute_ms"),
    dispute_fallback_pay_minor: money(v.dispute_fallback_pay_minor, "dispute_fallback_pay_minor"),
    condition: { kind: "all", clauses }, purpose: str(v.purpose, "purpose", STRING_BOUND_PURPOSE),
    parents,
  };
  return envelope;
}

export function validSignature(v: unknown): T.Signature {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "signature is not an object");
  keys(v, ["key_id", "sig"]);
  return { key_id: id(v.key_id, "key_id"), sig: sig(v.sig, "sig") };
}

export function validSignatureSet(v: unknown, f = "signatures"): T.Signature[] {
  if (!Array.isArray(v)) throw err("SCHEMA_INVALID", `${f} not an array`);
  if (v.length === 0 || v.length > MAX_SIGNATURES) throw err("LIMIT_EXCEEDED", `${f} bound`);
  const sigs = v.map(validSignature);
  if (!sortedUnique(sigs.map((s) => s.key_id))) throw err("SCHEMA_INVALID", `${f} must be sorted by key_id and unique`);
  return sigs;
}

export function validApprovalBody(v: unknown): T.ApprovalBody {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "approval.body is not an object");
  keys(v, ["v", "tenant", "environment", "commit_id", "envelope_hash", "policy_hash", "key_id", "decision"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "approval.v must be 1");
  if (v.decision !== "approve") throw err("SCHEMA_INVALID", "approval.decision must be approve");
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    commit_id: id(v.commit_id, "commit_id"), envelope_hash: digest(v.envelope_hash, "envelope_hash"),
    policy_hash: digest(v.policy_hash, "policy_hash"), key_id: id(v.key_id, "key_id"), decision: "approve",
  };
}

export function validApproval(v: unknown): T.Approval {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "approval is not an object");
  keys(v, ["body", "signature"]);
  return { body: validApprovalBody(v.body), signature: sig(v.signature, "signature") };
}

export function validAttestationBody(v: unknown): T.AttestationBody {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "attestation.body is not an object");
  keys(v, ["v", "tenant", "environment", "commit_id", "envelope_hash", "clause_id", "predicate", "outcome", "evidence", "issued_ms", "valid_until_ms"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "attestation.v must be 1");
  if (v.outcome !== "satisfied") throw err("SCHEMA_INVALID", "attestation.outcome must be satisfied");
  const predicate = str(v.predicate, "predicate", 128);
  if (!PREDICATE_RE.test(predicate) || !isAscii(predicate)) throw err("SCHEMA_INVALID", "predicate invalid");
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    commit_id: id(v.commit_id, "commit_id"), envelope_hash: digest(v.envelope_hash, "envelope_hash"),
    clause_id: id(v.clause_id, "clause_id"), predicate, outcome: "satisfied",
    evidence: validBlobRef(v.evidence, "evidence"), issued_ms: u64s(v.issued_ms, "issued_ms"),
    valid_until_ms: u64s(v.valid_until_ms, "valid_until_ms"),
  };
}

export function validAttestation(v: unknown): T.Attestation {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "attestation is not an object");
  keys(v, ["body", "signatures"]);
  return { body: validAttestationBody(v.body), signatures: validSignatureSet(v.signatures) };
}

export function validEvidenceSet(v: unknown): T.EvidenceSet {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "evidence set is not an object");
  keys(v, ["v", "commit_id", "envelope_hash", "items"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "evidence.v must be 1");
  if (!Array.isArray(v.items)) throw err("SCHEMA_INVALID", "items not an array");
  if (v.items.length === 0 || v.items.length > MAX_EVIDENCE_ITEMS) throw err("LIMIT_EXCEEDED", "evidence items bound");
  const items = v.items.map((it, i): T.EvidenceItem => {
    if (!isObj(it)) throw err("SCHEMA_INVALID", `items[${i}] is not an object`);
    const cid = id(it.clause_id, `items[${i}].clause_id`);
    if (it.kind === "attested") {
      keys(it, ["clause_id", "kind", "certificate"]);
      return { clause_id: cid, kind: "attested", certificate: validAttestation(it.certificate) };
    }
    if (it.kind === "hashlock") {
      keys(it, ["clause_id", "kind", "preimage_base64url"]);
      const p = str(it.preimage_base64url, `items[${i}].preimage_base64url`, MAX_PREIMAGE_BYTES * 2);
      decodeBase64urlCanonical(p); // canonical check
      return { clause_id: cid, kind: "hashlock", preimage_base64url: p };
    }
    throw err("SCHEMA_INVALID", `items[${i}].kind invalid`);
  });
  return { v: 1, commit_id: id(v.commit_id, "commit_id"), envelope_hash: digest(v.envelope_hash, "envelope_hash"), items };
}

export function validAllocation(v: unknown, f = "allocation"): T.Allocation {
  if (!isObj(v)) throw err("SCHEMA_INVALID", `${f} is not an object`);
  keys(v, ["pay_minor", "return_minor"]);
  return { pay_minor: money(v.pay_minor, `${f}.pay_minor`), return_minor: money(v.return_minor, `${f}.return_minor`) };
}

export function validAwardBody(v: unknown): T.AwardBody {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "award.body is not an object");
  keys(v, ["v", "tenant", "environment", "commit_id", "envelope_hash", "case_id", "rules_digest", "evidence", "pay_minor", "return_minor", "reason"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "award.v must be 1");
  if (!Array.isArray(v.evidence)) throw err("SCHEMA_INVALID", "award.evidence not an array");
  if (v.evidence.length > MAX_AWARD_EVIDENCE) throw err("LIMIT_EXCEEDED", "award evidence bound");
  const reason = v.reason;
  if (reason !== "performance" && reason !== "nonperformance" && reason !== "compromise") {
    throw err("SCHEMA_INVALID", "award.reason invalid");
  }
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    commit_id: id(v.commit_id, "commit_id"), envelope_hash: digest(v.envelope_hash, "envelope_hash"),
    case_id: id(v.case_id, "case_id"), rules_digest: digest(v.rules_digest, "rules_digest"),
    evidence: v.evidence.map((x, i) => validBlobRef(x, `evidence[${i}]`)),
    pay_minor: money(v.pay_minor, "pay_minor"), return_minor: money(v.return_minor, "return_minor"),
    reason,
  };
}

export function validAward(v: unknown): T.Award {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "award is not an object");
  keys(v, ["body", "signatures"]);
  return { body: validAwardBody(v.body), signatures: validSignatureSet(v.signatures) };
}

export function validBlobObject(v: unknown): T.BlobObject {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "blob is not an object");
  keys(v, ["encoding", "data"]);
  if (v.encoding !== "base64url") throw err("SCHEMA_INVALID", "blob.encoding must be base64url");
  const data = str(v.data, "data", MAX_BLOB_BYTES * 2);
  const decoded = decodeBase64urlCanonical(data);
  if (decoded.length > MAX_BLOB_BYTES) throw err("LIMIT_EXCEEDED", "blob exceeds 512 KiB decoded");
  return { encoding: "base64url", data };
}

export function validCustodyManifest(v: unknown): T.CustodyManifest {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "custody manifest is not an object");
  keys(v, ["v", "custody", "profile", "asset", "implementation_digest", "receipt_key", "idempotency_min_ms", "authoritative_lookup", "atomic_allocation", "fencing", "retry_mode"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "custody manifest.v must be 1");
  if (v.profile !== "sim-ledger/1" && v.profile !== "certified-escrow/1") throw err("SCHEMA_INVALID", "profile invalid");
  if (v.authoritative_lookup !== true || v.atomic_allocation !== true || v.fencing !== true) {
    throw err("SCHEMA_INVALID", "custody manifest capability flags must be true");
  }
  if (v.retry_mode !== "never" && v.retry_mode !== "sequenced-no-effect/1") throw err("SCHEMA_INVALID", "retry_mode invalid");
  return {
    v: 1, custody: id(v.custody, "custody"), profile: v.profile, asset: validAsset(v.asset),
    implementation_digest: digest(v.implementation_digest, "implementation_digest"),
    receipt_key: pub(v.receipt_key, "receipt_key"),
    idempotency_min_ms: u64s(v.idempotency_min_ms, "idempotency_min_ms"),
    authoritative_lookup: true, atomic_allocation: true, fencing: true, retry_mode: v.retry_mode,
  };
}

export function validCustodyRequest(v: unknown): T.CustodyRequest {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "custody request is not an object");
  keys(v, ["v", "tenant", "environment", "custody", "operation_id", "kind", "envelope_hash", "escrow_id", "payer", "payee", "asset", "amount_minor", "allocation", "not_after_ms", "fence"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "custody request.v must be 1");
  const kind = v.kind;
  if (kind !== "reserve" && kind !== "allocate") throw err("SCHEMA_INVALID", "custody request kind invalid");
  const allocation = v.allocation === null ? null : validAllocation(v.allocation);
  const notAfter = v.not_after_ms === null ? null : u64s(v.not_after_ms, "not_after_ms");
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    custody: id(v.custody, "custody"), operation_id: id(v.operation_id, "operation_id"), kind,
    envelope_hash: digest(v.envelope_hash, "envelope_hash"), escrow_id: id(v.escrow_id, "escrow_id"),
    payer: id(v.payer, "payer"), payee: id(v.payee, "payee"), asset: validAsset(v.asset),
    amount_minor: money(v.amount_minor, "amount_minor"), allocation, not_after_ms: notAfter,
    fence: u64s(v.fence, "fence"),
  };
}

export function validCustodyReceipt(v: unknown): T.CustodyReceipt {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "custody receipt is not an object");
  keys(v, ["body", "signature"]);
  const b = v.body;
  if (!isObj(b)) throw err("SCHEMA_INVALID", "receipt.body is not an object");
  keys(b, ["v", "custody", "operation_id", "request_hash", "escrow_id", "status", "final", "attempt", "allocation", "amount_minor", "provider_revision", "observed_ms", "evidence"]);
  if (b.v !== 1) throw err("UNSUPPORTED_VERSION", "receipt.v must be 1");
  const status = b.status;
  if (status !== "applied" && status !== "no_effect" && status !== "pending" && status !== "unknown") {
    throw err("SCHEMA_INVALID", "receipt.status invalid");
  }
  const fin = bool(b.final, "final");
  if ((status === "applied" || status === "no_effect") && !fin) throw err("SCHEMA_INVALID", "final outcome must set final=true");
  if ((status === "pending" || status === "unknown") && fin) throw err("SCHEMA_INVALID", "pending/unknown must set final=false");
  const allocation = b.allocation === null ? null : validAllocation(b.allocation);
  const evidence = b.evidence === null ? null : validBlobRef(b.evidence, "evidence");
  return {
    body: {
      v: 1, custody: id(b.custody, "custody"), operation_id: id(b.operation_id, "operation_id"),
      request_hash: digest(b.request_hash, "request_hash"), escrow_id: id(b.escrow_id, "escrow_id"),
      status, final: fin, attempt: intnum(b.attempt, "attempt", 1, 3), allocation,
      amount_minor: money(b.amount_minor, "amount_minor"),
      provider_revision: u64s(b.provider_revision, "provider_revision"),
      observed_ms: u64s(b.observed_ms, "observed_ms"), evidence,
    },
    signature: sig(v.signature, "signature"),
  };
}

export function validControlBody(v: unknown): T.ControlBody {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "control.body is not an object");
  keys(v, ["v", "tenant", "environment", "base_revision", "nonce", "expires_ms", "action"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "control.v must be 1");
  if (!isObj(v.action)) throw err("SCHEMA_INVALID", "action is not an object");
  const kind = v.action.kind;
  let action: T.ControlAction;
  if (kind === "halt") {
    keys(v.action, ["kind", "reason"]);
    const r = v.action.reason;
    if (r !== "security" && r !== "clock" && r !== "custody" && r !== "maintenance") throw err("SCHEMA_INVALID", "halt reason invalid");
    action = { kind: "halt", reason: r };
  } else if (kind === "resume") {
    keys(v.action, ["kind", "incident"]);
    action = { kind: "resume", incident: validBlobRef(v.action.incident, "incident") };
  } else if (kind === "revoke_key") {
    keys(v.action, ["kind", "key_id", "incident"]);
    action = { kind: "revoke_key", key_id: id(v.action.key_id, "key_id"), incident: validBlobRef(v.action.incident, "incident") };
  } else if (kind === "activate_policy") {
    keys(v.action, ["kind", "policy", "policy_hash"]);
    action = { kind: "activate_policy", policy: id(v.action.policy, "policy"), policy_hash: digest(v.action.policy_hash, "policy_hash") };
  } else {
    throw err("SCHEMA_INVALID", "control action kind invalid");
  }
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    base_revision: u64s(v.base_revision, "base_revision"), nonce: nonce(v.nonce, "nonce"),
    expires_ms: u64s(v.expires_ms, "expires_ms"), action,
  };
}

export function validControlCertificate(v: unknown): T.ControlCertificate {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "control certificate is not an object");
  keys(v, ["body", "signatures"]);
  return { body: validControlBody(v.body), signatures: validSignatureSet(v.signatures) };
}

export function validObjectEntry(v: unknown): T.ObjectEntry {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "object entry is not an object");
  keys(v, ["id", "kind", "digest", "bytes"]);
  const kind = v.kind;
  if (typeof kind !== "string" || !OBJECT_KINDS.includes(kind as T.ObjectKind)) throw err("SCHEMA_INVALID", "object entry kind invalid");
  return { id: id(v.id, "id"), kind: kind as T.ObjectKind, digest: digest(v.digest, "digest"), bytes: u64s(v.bytes, "bytes") };
}

export function validEventBody(v: unknown): T.EventBody {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "event body is not an object");
  keys(v, ["v", "tenant", "environment", "stream", "seq", "prev", "command_id", "time_ms", "writer_epoch", "authority_seq", "policy_hash", "from", "to", "objects", "data"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "event.v must be 1");
  if (!Array.isArray(v.objects)) throw err("SCHEMA_INVALID", "event.objects not an array");
  if (v.objects.length > 64) throw err("LIMIT_EXCEEDED", "event objects bound");
  const from = v.from === null ? null : validState(v.from);
  const to = v.to === null ? null : validState(v.to);
  const data = validEventData(v.data);
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    stream: id(v.stream, "stream", true), seq: u64s(v.seq, "seq"), prev: digest(v.prev, "prev"),
    command_id: id(v.command_id, "command_id"), time_ms: u64s(v.time_ms, "time_ms"),
    writer_epoch: u64s(v.writer_epoch, "writer_epoch"), authority_seq: u64s(v.authority_seq, "authority_seq"),
    policy_hash: digest(v.policy_hash, "policy_hash"), from, to,
    objects: v.objects.map(validObjectEntry), data,
  };
}

export function validState(v: unknown): T.State {
  const states = ["PROPOSED", "CANCELLED", "EXPIRED", "FUNDING", "FUNDING_UNKNOWN", "UNFUNDED", "ACTIVE", "RELEASE_PENDING", "DISPUTED", "SETTLING", "SETTLEMENT_UNKNOWN", "SETTLEMENT_BLOCKED", "SETTLED"];
  if (typeof v !== "string" || !states.includes(v)) throw err("SCHEMA_INVALID", "state invalid");
  return v as T.State;
}

export function validEventData(v: unknown): T.EventData {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "event data is not an object");
  const kind = v.kind;
  if (typeof kind !== "string") throw err("SCHEMA_INVALID", "event data kind invalid");
  const k = (required: string[]) => keys(v, required);
  switch (kind) {
    case "Proposed":
      k(["kind", "envelope", "envelope_hash", "business_id"]);
      return { kind, envelope: id(v.envelope, "envelope"), envelope_hash: digest(v.envelope_hash, "envelope_hash"), business_id: id(v.business_id, "business_id") };
    case "ApprovalAccepted":
      k(["kind", "approval", "key_id"]);
      return { kind, approval: id(v.approval, "approval"), key_id: id(v.key_id, "key_id") };
    case "Cancelled":
      k(["kind", "actor"]);
      return { kind, actor: id(v.actor, "actor") };
    case "Expired":
      k(["kind", "deadline_ms"]);
      return { kind, deadline_ms: u64s(v.deadline_ms, "deadline_ms") };
    case "CommitAuthorized":
      k(["kind", "reserve", "approvals", "budget_day"]);
      if (!Array.isArray(v.approvals)) throw err("SCHEMA_INVALID", "approvals not an array");
      return { kind, reserve: validCustodyRequest(v.reserve), approvals: v.approvals.map((x, i) => id(x, `approvals[${i}]`)), budget_day: u64s(v.budget_day, "budget_day") };
    case "EscrowHeld":
      k(["kind", "receipt", "escrow_id"]);
      return { kind, receipt: id(v.receipt, "receipt"), escrow_id: id(v.escrow_id, "escrow_id") };
    case "FundingUncertain": {
      k(["kind", "operation_id", "reason"]);
      if (v.reason !== "transport" && v.reason !== "deadline" && v.reason !== "restart") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, operation_id: id(v.operation_id, "operation_id"), reason: v.reason };
    }
    case "FundingFailed": {
      k(["kind", "receipt", "reason"]);
      if (v.reason !== "no_effect" && v.reason !== "unsent_expiry") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, receipt: v.receipt === null ? null : id(v.receipt, "receipt"), reason: v.reason };
    }
    case "ConditionSatisfied":
      k(["kind", "evidence", "release_at_ms"]);
      return { kind, evidence: id(v.evidence, "evidence"), release_at_ms: u64s(v.release_at_ms, "release_at_ms") };
    case "DisputeOpened": {
      k(["kind", "case_id", "actor", "reason", "evidence", "decision_by_ms"]);
      if (v.reason !== "delivery" && v.reason !== "fraud" && v.reason !== "integrity") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, case_id: id(v.case_id, "case_id"), actor: id(v.actor, "actor"), reason: v.reason, evidence: validBlobRef(v.evidence, "evidence"), decision_by_ms: u64s(v.decision_by_ms, "decision_by_ms") };
    }
    case "SettlementDecided": {
      k(["kind", "reason", "award", "allocation", "request"]);
      const r = v.reason;
      if (r !== "release" && r !== "condition_timeout" && r !== "funding_late" && r !== "award" && r !== "dispute_timeout") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, reason: r, award: v.award === null ? null : id(v.award, "award"), allocation: validAllocation(v.allocation), request: validCustodyRequest(v.request) };
    }
    case "SettlementUncertain": {
      k(["kind", "operation_id", "reason"]);
      if (v.reason !== "transport" && v.reason !== "restart") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, operation_id: id(v.operation_id, "operation_id"), reason: v.reason };
    }
    case "SettlementBlocked": {
      k(["kind", "receipt", "reason"]);
      if (v.reason !== "no_effect") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, receipt: id(v.receipt, "receipt"), reason: "no_effect" };
    }
    case "SettlementRetried":
      k(["kind", "operation_id", "receipt"]);
      return { kind, operation_id: id(v.operation_id, "operation_id"), receipt: id(v.receipt, "receipt") };
    case "Settled":
      k(["kind", "receipt", "allocation"]);
      return { kind, receipt: id(v.receipt, "receipt"), allocation: validAllocation(v.allocation) };
    case "CustodyObservation":
      k(["kind", "receipt"]);
      return { kind, receipt: id(v.receipt, "receipt") };
    case "ControlApplied":
      k(["kind", "certificate", "control_revision"]);
      return { kind, certificate: id(v.certificate, "certificate"), control_revision: u64s(v.control_revision, "control_revision") };
    case "SafetyHalted": {
      k(["kind", "reason", "incident"]);
      if (v.reason !== "clock" && v.reason !== "storage" && v.reason !== "custody" && v.reason !== "fence") throw err("SCHEMA_INVALID", "reason invalid");
      return { kind, reason: v.reason, incident: id(v.incident, "incident") };
    }
    default:
      throw err("SCHEMA_INVALID", `unknown event data kind ${kind}`);
  }
}

export function validSignedEvent(v: unknown): T.SignedEvent {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "signed event is not an object");
  keys(v, ["body", "hash", "key_id", "signature"]);
  return { body: validEventBody(v.body), hash: digest(v.hash, "hash"), key_id: id(v.key_id, "key_id"), signature: sig(v.signature, "signature") };
}

export function validCheckpoint(v: unknown): T.Checkpoint {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "checkpoint is not an object");
  keys(v, ["body", "key_id", "signature"]);
  const b = v.body;
  if (!isObj(b)) throw err("SCHEMA_INVALID", "checkpoint.body is not an object");
  keys(b, ["v", "tenant", "environment", "stream", "seq", "head", "authority_head", "ledger_root", "writer_epoch", "created_ms"]);
  if (b.v !== 1) throw err("UNSUPPORTED_VERSION", "checkpoint.v must be 1");
  return {
    body: {
      v: 1, tenant: id(b.tenant, "tenant"), environment: env(b.environment),
      stream: id(b.stream, "stream", true), seq: u64s(b.seq, "seq"), head: digest(b.head, "head"),
      authority_head: digest(b.authority_head, "authority_head"), ledger_root: digest(b.ledger_root, "ledger_root"),
      writer_epoch: u64s(b.writer_epoch, "writer_epoch"), created_ms: u64s(b.created_ms, "created_ms"),
    },
    key_id: id(v.key_id, "key_id"), signature: sig(v.signature, "signature"),
  };
}

export function validProofManifest(v: unknown): T.ProofManifest {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "proof manifest is not an object");
  keys(v, ["v", "format", "commit_id", "disclosure", "previous", "events", "authority_events", "objects", "checkpoint", "custody_manifest"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "manifest.v must be 1");
  if (v.format !== "commit-proof/1") throw err("SCHEMA_INVALID", "manifest format must be commit-proof/1");
  if (v.disclosure !== "full" && v.disclosure !== "redacted") throw err("SCHEMA_INVALID", "disclosure invalid");
  if (!Array.isArray(v.events) || !Array.isArray(v.authority_events) || !Array.isArray(v.objects)) {
    throw err("SCHEMA_INVALID", "manifest arrays invalid");
  }
  if (v.events.length > 256 || v.authority_events.length > 256 || v.objects.length > 64 * 256) {
    throw err("LIMIT_EXCEEDED", "manifest size bound");
  }
  return {
    v: 1, format: "commit-proof/1", commit_id: id(v.commit_id, "commit_id"), disclosure: v.disclosure,
    previous: v.previous === null ? null : validBlobRef(v.previous, "previous"),
    events: v.events.map(validSignedEvent), authority_events: v.authority_events.map(validSignedEvent),
    objects: v.objects.map(validObjectEntry), checkpoint: validCheckpoint(v.checkpoint),
    custody_manifest: validCustodyManifest(v.custody_manifest),
  };
}

export function validTrustPin(v: unknown): T.TrustPin {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "trust pin is not an object");
  keys(v, ["v", "tenant", "environment", "genesis_policy_hash", "writer_key", "writer_epoch", "custody_key", "custody_manifest_hash", "reducer_digest", "minimum_checkpoint"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "trust.v must be 1");
  return {
    v: 1, tenant: id(v.tenant, "tenant"), environment: env(v.environment),
    genesis_policy_hash: digest(v.genesis_policy_hash, "genesis_policy_hash"),
    writer_key: pub(v.writer_key, "writer_key"), writer_epoch: u64s(v.writer_epoch, "writer_epoch"),
    custody_key: pub(v.custody_key, "custody_key"),
    custody_manifest_hash: digest(v.custody_manifest_hash, "custody_manifest_hash"),
    reducer_digest: digest(v.reducer_digest, "reducer_digest"),
    minimum_checkpoint: v.minimum_checkpoint === null ? null : validCheckpoint(v.minimum_checkpoint),
  };
}

export function validMigration(v: unknown): T.Migration {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "migration is not an object");
  keys(v, ["v", "from_storage", "to_storage", "source_head", "binary_digest", "transform_digest", "expected_projection_root", "backup_digest", "writer_epoch"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "migration.v must be 1");
  return {
    v: 1, from_storage: intnum(v.from_storage, "from_storage", 0, 1e9), to_storage: intnum(v.to_storage, "to_storage", 0, 1e9),
    source_head: digest(v.source_head, "source_head"), binary_digest: digest(v.binary_digest, "binary_digest"),
    transform_digest: digest(v.transform_digest, "transform_digest"),
    expected_projection_root: digest(v.expected_projection_root, "expected_projection_root"),
    backup_digest: digest(v.backup_digest, "backup_digest"), writer_epoch: u64s(v.writer_epoch, "writer_epoch"),
  };
}

export function validRequest(v: unknown): T.Request {
  if (!isObj(v)) throw err("SCHEMA_INVALID", "request is not an object");
  keys(v, ["v", "request_id", "capability", "method", "params"]);
  if (v.v !== 1) throw err("UNSUPPORTED_VERSION", "request.v must be 1");
  if (typeof v.method !== "string" || !METHODS.includes(v.method as T.Method)) {
    throw err("SCHEMA_INVALID", "method unknown");
  }
  return { v: 1, request_id: id(v.request_id, "request_id"), capability: id(v.capability, "capability"), method: v.method as T.Method, params: v.params };
}

export function validObjectBody(kind: T.ObjectKind, v: unknown): T.ObjectBody {
  switch (kind) {
    case "policy": return validPolicy(v);
    case "envelope": return validEnvelope(v);
    case "approval": return validApproval(v);
    case "evidence": return validEvidenceSet(v);
    case "award": return validAward(v);
    case "control": return validControlCertificate(v);
    case "custody": return validCustodyReceipt(v);
    case "blob": return validBlobObject(v);
    case "manifest": return validProofManifest(v);
    case "trust": return validTrustPin(v);
    case "migration": return validMigration(v);
  }
}
