// Minimal typed client SDK over the unix-socket RPC surface (§5).

import { rpcCall, type CallOptions } from "./server.ts";
import { randomId } from "./crypto.ts";
import type * as T from "./types.ts";
import type { Json } from "./json/strict.ts";

export class CommitClient {
  readonly socketPath: string;
  readonly capability: T.Id;
  readonly opts: CallOptions;
  constructor(socketPath: string, capability: T.Id, opts: CallOptions = {}) {
    this.socketPath = socketPath;
    this.capability = capability;
    this.opts = opts;
  }

  async call(method: T.Method, params: Json, requestId?: T.Id): Promise<unknown> {
    const req: T.Request = {
      v: 1,
      request_id: requestId ?? (randomId("req") as T.Id),
      capability: this.capability,
      method,
      params,
    };
    const res = await rpcCall(this.socketPath, req, this.opts);
    if (!res.ok) {
      const e = res.error;
      const err = new Error(`${e.code}: ${e.message}`) as Error & { code: string; retryable: boolean; currentRevision: string | null };
      err.code = e.code; err.retryable = e.retryable; err.currentRevision = e.current_revision;
      throw err;
    }
    return res.result;
  }

  objectPut(object: T.Id, kind: T.ObjectKind, body: Json, requestId: T.Id) {
    return this.call("object.put", { object, kind, body }, requestId);
  }
  objectGet(object: T.Id) { return this.call("object.get", { object } as Json); }
  propose(envelope: T.Id, requestId: T.Id) { return this.call("promise.propose", { envelope } as Json, requestId); }
  promiseGet(commitId: T.Id) { return this.call("promise.get", { commit_id: commitId } as Json); }
  promiseList(state: T.State | null, cursor: string | null, limit: number) {
    return this.call("promise.list", { state, cursor, limit } as unknown as Json);
  }
  approve(commitId: T.Id, expectedRevision: T.U64, approval: T.Id, requestId: T.Id) {
    return this.call("approval.submit", { commit_id: commitId, expected_revision: expectedRevision, approval } as Json, requestId);
  }
  commit(commitId: T.Id, expectedRevision: T.U64, requestId: T.Id) {
    return this.call("promise.commit", { commit_id: commitId, expected_revision: expectedRevision } as Json, requestId);
  }
  cancel(commitId: T.Id, expectedRevision: T.U64, requestId: T.Id) {
    return this.call("promise.cancel", { commit_id: commitId, expected_revision: expectedRevision } as Json, requestId);
  }
  satisfy(commitId: T.Id, expectedRevision: T.U64, evidence: T.Id, requestId: T.Id) {
    return this.call("condition.submit", { commit_id: commitId, expected_revision: expectedRevision, evidence } as Json, requestId);
  }
  disputeOpen(commitId: T.Id, expectedRevision: T.U64, caseId: T.Id, reason: string, evidence: Json, requestId: T.Id) {
    return this.call("dispute.open", { commit_id: commitId, expected_revision: expectedRevision, case_id: caseId, reason, evidence }, requestId);
  }
  disputeResolve(commitId: T.Id, expectedRevision: T.U64, award: T.Id, requestId: T.Id) {
    return this.call("dispute.resolve", { commit_id: commitId, expected_revision: expectedRevision, award } as Json, requestId);
  }
  advance(commitId: T.Id, expectedRevision: T.U64, requestId: T.Id) {
    return this.call("promise.advance", { commit_id: commitId, expected_revision: expectedRevision } as Json, requestId);
  }
  custodyReconcile(operationId: T.Id, receipt: T.Id | null, requestId: T.Id) {
    return this.call("custody.reconcile", { operation_id: operationId, receipt } as Json, requestId);
  }
  custodyRetry(operationId: T.Id, noEffectReceipt: T.Id, requestId: T.Id) {
    return this.call("custody.retry", { operation_id: operationId, no_effect_receipt: noEffectReceipt } as Json, requestId);
  }
  accountGet(principal: T.Id, asset: Json) { return this.call("account.get", { principal, asset } as Json); }
  eventList(commitId: T.Id, afterSeq: T.U64, limit: number) {
    return this.call("event.list", { commit_id: commitId, after_seq: afterSeq, limit } as unknown as Json);
  }
  proofExport(commitId: T.Id, disclosure: "full" | "redacted", cursor: string | null, requestId: T.Id) {
    return this.call("proof.export", { commit_id: commitId, disclosure, cursor } as unknown as Json, requestId);
  }
  proofVerify(manifest: T.Id, trust: T.Id) { return this.call("proof.verify", { manifest, trust } as Json); }
  controlApply(certificate: T.Id, requestId: T.Id) { return this.call("control.apply", { certificate } as Json, requestId); }
  controlStatus() { return this.call("control.status", {} as Json); }
  health() { return this.call("health.get", {} as Json); }
}
