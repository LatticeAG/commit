// certified-escrow/1 adapter — zone-gated custody surface (§1.4, §12 P6).
//
// A real certified-escrow adapter requires a separately reviewed provider
// contract: exclusive reserve ownership, unique operation identities,
// authoritative lookup, atomic two-beneficiary allocation, fencing, and the
// sequenced-no-effect/1 retry mode where offered. The OSS core ships the
// documented stub only: every call throws NotImplementedSurface with the gate
// reason rather than pretending to move real funds.

import { NotImplementedSurface } from "../errors.ts";
import type { CustodyAdapter, InvokeOutcome, LookupOutcome } from "./adapter.ts";
import type { CustodyReceipt, CustodyRequest, ErrorBody, Id, U64 } from "../types.ts";

const GATE = "certified-escrow/1 requires a separately reviewed custody provider (P6 gate); no network connector ships in the OSS core";

export class CertifiedEscrowStub implements CustodyAdapter {
  readonly profile = "certified-escrow/1";
  readonly custodyId: Id;
  constructor(custodyId: Id) { this.custodyId = custodyId; }

  invoke(_request: CustodyRequest, _attempt: number, _priorNoEffect: CustodyReceipt | null, _writerEpoch: U64): Promise<InvokeOutcome> {
    throw new NotImplementedSurface("certified-escrow/1 invoke", GATE);
  }

  lookup(_operationId: Id, _requestHash: string, _attempt: number): Promise<LookupOutcome> {
    throw new NotImplementedSurface("certified-escrow/1 lookup", GATE);
  }

  fence(_custody: Id, _previousEpoch: U64, _newEpoch: U64): Promise<{ ok: true; epoch: U64 } | { ok: false; error: ErrorBody }> {
    throw new NotImplementedSurface("certified-escrow/1 fence", GATE);
  }
}
