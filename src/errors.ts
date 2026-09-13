// Protocol error type and the §3.5 error contract.

export type ErrorCode = string;

export class CommitError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly currentRevision: string | null;

  constructor(code: ErrorCode, message: string, opts: { retryable?: boolean; currentRevision?: string | null } = {}) {
    super(message);
    this.name = "CommitError";
    this.code = code;
    this.retryable = opts.retryable ?? RETRYABLE.has(code) ?? false;
    this.currentRevision = opts.currentRevision ?? null;
  }

  toErrorBody(): { code: string; retryable: boolean; message: string; current_revision: string | null } {
    return { code: this.code, retryable: this.retryable, message: this.message, current_revision: this.currentRevision };
  }
}

const RETRYABLE = new Map<string, boolean>([
  ["BUSY", true],
  ["NOT_DUE", true],
  ["PROVIDER_UNKNOWN", true],
  ["STORAGE_UNAVAILABLE", true],
  ["HALTED", true],
]);

export function err(code: ErrorCode, message: string, opts: { retryable?: boolean; currentRevision?: string | null } = {}): CommitError {
  return new CommitError(code, message, opts);
}

export function isCommitError(e: unknown): e is CommitError {
  return e instanceof CommitError;
}

/** CLI exit-code families per §4. */
export function exitCodeFor(code: string): number {
  switch (code) {
    case "INVALID_JSON":
    case "SCHEMA_INVALID":
    case "LIMIT_EXCEEDED":
    case "UNSUPPORTED_VERSION":
      return 2;
    case "UNAUTHENTICATED":
    case "FORBIDDEN":
    case "NOT_FOUND":
    case "TRUST_UNANCHORED":
      return 3;
    case "SIGNATURE_INVALID":
    case "POLICY_INACTIVE":
    case "POLICY_INVALID":
    case "KEY_REVOKED":
    case "QUORUM_MISSING":
    case "APPROVAL_CONFLICT":
    case "CONDITION_UNSATISFIED":
    case "EVIDENCE_EXPIRED":
    case "EVIDENCE_MISMATCH":
    case "AWARD_INVALID":
    case "RECEIPT_INVALID":
      return 4;
    case "STATE_CONFLICT":
    case "DEADLINE_CLOSED":
    case "NOT_DUE":
    case "DISPUTE_EXISTS":
    case "DECISION_FINAL":
    case "STALE_REVISION":
    case "IDEMPOTENCY_CONFLICT":
    case "OBJECT_CONFLICT":
    case "BUSINESS_CONFLICT":
    case "CONTROL_STALE":
      return 5;
    case "INSUFFICIENT_FUNDS":
    case "BUDGET_EXCEEDED":
    case "AMOUNT_OVERFLOW":
    case "ASSET_MISMATCH":
      return 6;
    case "PROVIDER_UNKNOWN":
    case "EXPORT_INCOMPLETE":
    case "SETTLEMENT_BLOCKED":
    case "PIN_AHEAD":
      return 7;
    case "STORAGE_UNAVAILABLE":
    case "CLOCK_UNSAFE":
    case "FENCE_STALE":
    case "HALTED":
    case "CUSTODY_CONFLICT":
    case "BUSY":
    case "OBJECT_MISSING":
    default:
      return 8;
  }
}

/** Documented stub for hosted/paid/zone-gated surfaces (§12 P6+). */
export class NotImplementedSurface extends Error {
  readonly surface: string;
  readonly reason: string;
  constructor(surface: string, reason: string) {
    super(`${surface}: not implemented in the OSS core — ${reason}`);
    this.name = "NotImplementedSurface";
    this.surface = surface;
    this.reason = reason;
  }
}
