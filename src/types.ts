// Protocol schemas (§1.2–§1.5, §3.1). Closed records; all fields required.

export type Id = string;
export type U64 = string;
export type Digest = string;
export type Nonce = string;
export type PublicKey = string;
export type Sig = string;
export type Environment = "simulation" | "live";

export type Asset = { code: string; scale: number; custody: Id };
export type Member = { key_id: Id; principal: Id; kind: "human" | "service"; public_key: PublicKey };
export type Quorum = { threshold: number; keys: Id[]; mandatory_principals: Id[] };

export type Policy = {
  v: 1; policy_id: Id; tenant: Id; environment: Environment; custody: Id; asset: Asset;
  members: Member[]; approve: Quorum; attest: Quorum; arbitrate: Quorum; control: Quorum;
  max_amount_minor: U64; max_exposure_minor: U64; daily_commit_minor: U64;
  max_duration_ms: U64; min_challenge_ms: U64; rules_digest: Digest;
};

export type BlobRef = { object: Id; sha256: Digest; bytes: U64; media: "application/json" | "application/octet-stream" };
export type ForeignRef = { system: "covenant" | "charter" | "world" | "proof" | "mint" | "treaty"; profile: string; ref: string; digest: string };

export type Clause =
  | { id: Id; kind: "attested"; predicate: string; authority: "attest" }
  | { id: Id; kind: "hashlock"; sha256: Digest; max_preimage_bytes: number };

export type Envelope = {
  v: 1; tenant: Id; environment: Environment; commit_id: Id; business_id: Id;
  payer: Id; payee: Id; custody: Id; asset: Asset; amount_minor: U64;
  policy_hash: Digest; nonce: Nonce; created_ms: U64; commit_by_ms: U64;
  fund_by_ms: U64; condition_by_ms: U64; challenge_ms: U64; dispute_ms: U64;
  dispute_fallback_pay_minor: U64; condition: { kind: "all"; clauses: Clause[] };
  purpose: string; parents: ForeignRef[];
};

export type Signature = { key_id: Id; sig: Sig };
export type ApprovalBody = {
  v: 1; tenant: Id; environment: Environment; commit_id: Id;
  envelope_hash: Digest; policy_hash: Digest; key_id: Id; decision: "approve";
};
export type Approval = { body: ApprovalBody; signature: Sig };

export type AttestationBody = {
  v: 1; tenant: Id; environment: Environment; commit_id: Id; envelope_hash: Digest;
  clause_id: Id; predicate: string; outcome: "satisfied"; evidence: BlobRef;
  issued_ms: U64; valid_until_ms: U64;
};
export type Attestation = { body: AttestationBody; signatures: Signature[] };

export type EvidenceItem =
  | { clause_id: Id; kind: "attested"; certificate: Attestation }
  | { clause_id: Id; kind: "hashlock"; preimage_base64url: string };
export type EvidenceSet = { v: 1; commit_id: Id; envelope_hash: Digest; items: EvidenceItem[] };

export type AwardBody = {
  v: 1; tenant: Id; environment: Environment; commit_id: Id; envelope_hash: Digest;
  case_id: Id; rules_digest: Digest; evidence: BlobRef[];
  pay_minor: U64; return_minor: U64; reason: "performance" | "nonperformance" | "compromise";
};
export type Award = { body: AwardBody; signatures: Signature[] };

export type Allocation = { pay_minor: U64; return_minor: U64 };

export type State =
  | "PROPOSED" | "CANCELLED" | "EXPIRED" | "FUNDING" | "FUNDING_UNKNOWN"
  | "UNFUNDED" | "ACTIVE" | "RELEASE_PENDING" | "DISPUTED" | "SETTLING"
  | "SETTLEMENT_UNKNOWN" | "SETTLEMENT_BLOCKED" | "SETTLED";

export type Disposition = "release" | "condition_timeout" | "funding_late" | "award" | "dispute_timeout";

export type PromiseView = {
  commit_id: Id; envelope: Id; envelope_hash: Digest; revision: U64; state: State;
  approval_count: number; escrow_id: Id | null; release_at_ms: U64 | null;
  case_id: Id | null; decision_by_ms: U64 | null; disposition: Disposition | null;
  allocation: Allocation | null; operation: Id | null; halted: boolean;
};

export type BlobObject = { encoding: "base64url"; data: string };

export type CustodyManifest = {
  v: 1; custody: Id; profile: "sim-ledger/1" | "certified-escrow/1"; asset: Asset;
  implementation_digest: Digest; receipt_key: PublicKey; idempotency_min_ms: U64;
  authoritative_lookup: true; atomic_allocation: true; fencing: true;
  retry_mode: "never" | "sequenced-no-effect/1";
};

export type CustodyRequest = {
  v: 1; tenant: Id; environment: Environment; custody: Id; operation_id: Id;
  kind: "reserve" | "allocate"; envelope_hash: Digest; escrow_id: Id;
  payer: Id; payee: Id; asset: Asset; amount_minor: U64;
  allocation: Allocation | null; not_after_ms: U64 | null; fence: U64;
};

export type CustodyReceiptBody = {
  v: 1; custody: Id; operation_id: Id; request_hash: Digest; escrow_id: Id;
  status: "applied" | "no_effect" | "pending" | "unknown";
  final: boolean; attempt: number; allocation: Allocation | null; amount_minor: U64;
  provider_revision: U64; observed_ms: U64; evidence: BlobRef | null;
};
export type CustodyReceipt = { body: CustodyReceiptBody; signature: Sig };

export type OperationState = "READY" | "DISPATCHED" | "UNKNOWN" | "APPLIED" | "NO_EFFECT" | "BLOCKED";
export type OperationView = { operation_id: Id; state: OperationState; request_hash: Digest; attempts: number; last_receipt: Id | null };

export type ControlAction =
  | { kind: "halt"; reason: "security" | "clock" | "custody" | "maintenance" }
  | { kind: "resume"; incident: BlobRef }
  | { kind: "revoke_key"; key_id: Id; incident: BlobRef }
  | { kind: "activate_policy"; policy: Id; policy_hash: Digest };
export type ControlBody = {
  v: 1; tenant: Id; environment: Environment; base_revision: U64;
  nonce: Nonce; expires_ms: U64; action: ControlAction;
};
export type ControlCertificate = { body: ControlBody; signatures: Signature[] };

export type EventData =
  | { kind: "Proposed"; envelope: Id; envelope_hash: Digest; business_id: Id }
  | { kind: "ApprovalAccepted"; approval: Id; key_id: Id }
  | { kind: "Cancelled"; actor: Id }
  | { kind: "Expired"; deadline_ms: U64 }
  | { kind: "CommitAuthorized"; reserve: CustodyRequest; approvals: Id[]; budget_day: U64 }
  | { kind: "EscrowHeld"; receipt: Id; escrow_id: Id }
  | { kind: "FundingUncertain"; operation_id: Id; reason: "transport" | "deadline" | "restart" }
  | { kind: "FundingFailed"; receipt: Id | null; reason: "no_effect" | "unsent_expiry" }
  | { kind: "ConditionSatisfied"; evidence: Id; release_at_ms: U64 }
  | { kind: "DisputeOpened"; case_id: Id; actor: Id; reason: "delivery" | "fraud" | "integrity"; evidence: BlobRef; decision_by_ms: U64 }
  | { kind: "SettlementDecided"; reason: Disposition; award: Id | null; allocation: Allocation; request: CustodyRequest }
  | { kind: "SettlementUncertain"; operation_id: Id; reason: "transport" | "restart" }
  | { kind: "SettlementBlocked"; receipt: Id; reason: "no_effect" }
  | { kind: "SettlementRetried"; operation_id: Id; receipt: Id }
  | { kind: "Settled"; receipt: Id; allocation: Allocation }
  | { kind: "CustodyObservation"; receipt: Id }
  | { kind: "ControlApplied"; certificate: Id; control_revision: U64 }
  | { kind: "SafetyHalted"; reason: "clock" | "storage" | "custody" | "fence"; incident: Id };

export type ObjectEntry = { id: Id; kind: ObjectKind; digest: Digest; bytes: U64 };

export type EventBody = {
  v: 1; tenant: Id; environment: Environment; stream: Id; seq: U64; prev: Digest;
  command_id: Id; time_ms: U64; writer_epoch: U64; authority_seq: U64;
  policy_hash: Digest; from: State | null; to: State | null; objects: ObjectEntry[]; data: EventData;
};
export type SignedEvent = { body: EventBody; hash: Digest; key_id: Id; signature: Sig };

export type CheckpointBody = {
  v: 1; tenant: Id; environment: Environment; stream: Id; seq: U64; head: Digest;
  authority_head: Digest; ledger_root: Digest; writer_epoch: U64; created_ms: U64;
};
export type Checkpoint = { body: CheckpointBody; key_id: Id; signature: Sig };

export type ProofManifest = {
  v: 1; format: "commit-proof/1"; commit_id: Id; disclosure: "full" | "redacted";
  previous: BlobRef | null; events: SignedEvent[]; authority_events: SignedEvent[]; objects: ObjectEntry[];
  checkpoint: Checkpoint; custody_manifest: CustodyManifest;
};

export type TrustPin = {
  v: 1; tenant: Id; environment: Environment; genesis_policy_hash: Digest;
  writer_key: PublicKey; writer_epoch: U64; custody_key: PublicKey;
  custody_manifest_hash: Digest; reducer_digest: Digest;
  minimum_checkpoint: Checkpoint | null;
};

export type VerifyResult = {
  integrity: "verified" | "invalid" | "incomplete";
  authorization: "verified" | "invalid" | "incomplete";
  execution: "local-simulation-verified" | "custodian-attested" | "unknown";
  conservation: "verified" | "not-checked";
  freshness: "as-of-pin" | "unanchored";
  through_seq: U64; effects_enabled: false;
  codes: string[];
};

export type Migration = {
  v: 1; from_storage: number; to_storage: number; source_head: Digest;
  binary_digest: Digest; transform_digest: Digest; expected_projection_root: Digest;
  backup_digest: Digest; writer_epoch: U64;
};

export type ObjectKind = "policy" | "envelope" | "approval" | "evidence" | "award"
  | "control" | "custody" | "blob" | "manifest" | "trust" | "migration";

export type ObjectBody = Policy | Envelope | Approval | EvidenceSet | Award | ControlCertificate
  | CustodyReceipt | BlobObject | ProofManifest | TrustPin | Migration;

export const OBJECT_KINDS: readonly ObjectKind[] = [
  "policy", "envelope", "approval", "evidence", "award",
  "control", "custody", "blob", "manifest", "trust", "migration",
];

/** Object kinds whose stored body is a signed wrapper {body,signature(s)}. */
export const SIGNED_WRAPPER_KINDS: ReadonlySet<ObjectKind> = new Set(["approval", "award", "control", "custody"]);

// ---- RPC surface (§3.1) ----

export type Method =
  | "object.put" | "object.get" | "promise.propose" | "promise.get" | "promise.list"
  | "approval.submit" | "promise.commit" | "promise.cancel" | "condition.submit" | "dispute.open"
  | "dispute.resolve" | "promise.advance" | "custody.reconcile" | "custody.retry" | "account.get"
  | "event.list" | "proof.export" | "proof.verify" | "control.apply" | "control.status" | "health.get";

export const METHODS: readonly Method[] = [
  "object.put", "object.get", "promise.propose", "promise.get", "promise.list",
  "approval.submit", "promise.commit", "promise.cancel", "condition.submit", "dispute.open",
  "dispute.resolve", "promise.advance", "custody.reconcile", "custody.retry", "account.get",
  "event.list", "proof.export", "proof.verify", "control.apply", "control.status", "health.get",
];

export type Request = { v: 1; request_id: Id; capability: Id; method: Method; params: unknown };
export type ErrorBody = { code: string; retryable: boolean; message: string; current_revision: U64 | null };
export type Response =
  | { v: 1; request_id: Id; ok: true; result: unknown }
  | { v: 1; request_id: Id; ok: false; error: ErrorBody };

export type MutationResult = { commit_id: Id; state: State; revision: U64; events: string[] };
export type AccountResult = { principal: Id; asset: Asset; available_minor: U64; exposed_minor: U64; held_minor: U64 };
export type ExportResult = { manifest: Id; chunk: BlobRef; next_cursor: string | null; complete: boolean };
export type ControlStatus = { status: "RUNNING" | "HALTED"; revision: U64; revoked_keys: Id[]; active_policy: Id };
export type HealthResult = { ready: boolean; storage: "ok" | "failed"; clock: "ok" | "unsafe"; custody: "ok" | "degraded"; protocol: "commit/1" };

// ---- Custody adapter contract (§3.4) ----

export type AdapterRequest =
  | { method: "invoke"; params: { request: CustodyRequest; attempt: number; prior_no_effect: CustodyReceipt | null; writer_epoch: U64 } }
  | { method: "lookup"; params: { operation_id: Id; request_hash: Digest; attempt: number } }
  | { method: "fence"; params: { custody: Id; previous_epoch: U64; new_epoch: U64 } };

export type AdapterResponse =
  | { ok: true; receipt: CustodyReceipt }
  | { ok: true; epoch: U64 }
  | { ok: false; error: ErrorBody };

// ---- Audit delivery (§9.2) ----

export type AuditDelivery = { v: 1; delivery_id: Id; manifest: Id; digest: Digest; through_seq: U64 };
export type AuditAck =
  | { v: 1; delivery_id: Id; accepted_digest: Digest; status: "stored" }
  | { v: 1; delivery_id: Id; status: "rejected"; code: "DIGEST_CONFLICT" | "FORBIDDEN" | "STORAGE_UNAVAILABLE" };

// ---- Capability (§5 [[principals]]) ----

export type Capability = {
  uid: number; principal: Id; capability: Id; methods: Method[];
  object_kinds: ObjectKind[]; commit_ids: Id[]; max_amount_minor: U64; expires_ms: U64;
};
