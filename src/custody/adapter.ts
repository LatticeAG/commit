// Custody adapter contract (§1.4, §3.4). Exactly three calls: invoke, lookup,
// fence. Never exposed to party capabilities or public ingress.

import type { CustodyReceipt, CustodyRequest, ErrorBody, Id, U64 } from "../types.ts";

export type InvokeOutcome =
  | { status: "receipt"; receipt: CustodyReceipt }
  | { status: "inflight" }                    // dispatched, response pending
  | { status: "timeout" }                     // transport deadline hit
  | { status: "error"; error: ErrorBody };

export type LookupOutcome =
  | { status: "receipt"; receipt: CustodyReceipt }
  | { status: "none" }                        // conclusive: provider holds nothing yet
  | { status: "inconclusive" }                // provider cannot answer now
  | { status: "error"; error: ErrorBody };

export interface CustodyAdapter {
  readonly custodyId: Id;
  readonly profile: string;
  invoke(request: CustodyRequest, attempt: number, priorNoEffect: CustodyReceipt | null, writerEpoch: U64): Promise<InvokeOutcome>;
  lookup(operationId: Id, requestHash: string, attempt: number): Promise<LookupOutcome>;
  fence(custody: Id, previousEpoch: U64, newEpoch: U64): Promise<{ ok: true; epoch: U64 } | { ok: false; error: ErrorBody }>;
}

/** Adapter error codes (§3.4). */
export const ADAPTER_ERRORS = new Set(["PROVIDER_UNKNOWN", "RECEIPT_INVALID", "RETRY_UNSAFE", "FENCE_STALE", "STORAGE_UNAVAILABLE"]);
