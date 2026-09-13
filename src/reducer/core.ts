// Reducer core: event emission, object admission, shared guards.

import { D, edSign, H } from "../crypto.ts";
import { err } from "../errors.ts";
import { jcsBytes } from "../json/jcs.ts";
import type { Json } from "../json/strict.ts";
import { objectEntry, entryOrder, registryDigest } from "../objects.ts";
import { u64 } from "../scalars.ts";
import { validObjectBody } from "../schema.ts";
import type { Store, ObjectRow } from "../store.ts";
import type { CustodyAdapter } from "../custody/adapter.ts";
import type * as T from "../types.ts";

export interface Ctx {
  store: Store;
  custody: T.CustodyManifest;
  policy: T.Policy;
  policyObjectId: string;
  writerSeed: Buffer;            // signs events + checkpoints ("writer1" role)
  writerKeyId: string;
  receiptSeed: Buffer | null;    // sim-ledger receipt signing key
  receiptKeyId: string;          // receipt key id label (receipts bind custody, not a member key)
  writerEpoch: string;
  adapter: CustodyAdapter | null; // external profile adapter (null for pure local handling w/o dispatch)
  localCustody: boolean;         // sim-ledger/1 in-transaction application (false = outbox dispatch path)
  maxObjectsPerPrincipal: number;
  maxUnboundObjectBytes: bigint;
  objectDir: string | null;      // filesystem object dir; null keeps canonical bytes in-row only
  cursorSecret: Buffer;          // HMAC/encryption key for list & export cursors
  auditEvery: boolean;           // insert audit_outbox deliveries per committed event tx
}

export interface EmittedEvent {
  signed: T.SignedEvent;
  kind: string;
}

export function lastEventSeq(store: Store, stream: string): bigint {
  return store.lastEvent(stream)?.seq ?? 0n;
}

export function lastEventHash(store: Store, stream: string): string {
  return store.lastEvent(stream)?.event_hash ?? "0".repeat(64);
}

function entryForObject(store: Store, id: string): T.ObjectEntry {
  const row = store.getObject(id);
  if (!row) throw err("OBJECT_MISSING", `event references unknown object ${id}`);
  return { id: row.object_id, kind: row.kind, digest: row.digest, bytes: String(row.bytes) };
}

/**
 * Append one signed event to a stream inside the current transaction.
 * `refs` are object ids whose registry entries get bound into the event.
 */
export function emitEvent(
  ctx: Ctx,
  stream: string,
  from: T.State | null,
  to: T.State | null,
  commandId: string,
  timeMs: bigint,
  data: T.EventData,
  refs: string[],
): T.SignedEvent {
  const store = ctx.store;
  const meta = store.getMeta()!;
  const seq = lastEventSeq(store, stream) + 1n;
  const prev = lastEventHash(store, stream);
  const objects = refs.map((id) => entryForObject(store, id)).sort(entryOrder);
  if (objects.length > 64) throw err("LIMIT_EXCEEDED", "event objects bound");
  const isControl = stream === "control";
  const body: T.EventBody = {
    v: 1,
    tenant: meta.tenant as T.Id,
    environment: meta.environment as T.Environment,
    stream: stream as T.Id,
    seq: String(seq),
    prev,
    command_id: commandId as T.Id,
    time_ms: String(timeMs),
    writer_epoch: String(meta.writer_epoch),
    authority_seq: isControl ? String(seq) : String(meta.control_revision),
    policy_hash: ctx.policy ? (D("policy", ctx.policy as unknown as Json) as T.Digest) : ("0".repeat(64) as T.Digest),
    from,
    to,
    objects,
    data,
  };
  const hash = D("event", body as unknown as Json);
  const signature = edSign("event", body as unknown as Json, ctx.writerSeed);
  store.insertEvent({
    stream,
    seq,
    prev,
    event_hash: hash,
    canonical_body: jcsBytes(body as unknown as Json),
    signature,
    key_id: ctx.writerKeyId,
    transaction_id: store.bumpCounter("event_tx"),
  });
  for (const id of refs) store.markObjectReferenced(id, isControl ? null : stream);
  return { body, hash, key_id: ctx.writerKeyId, signature };
}

/**
 * Admit an object into the registry inside the current transaction.
 * Idempotent re-upload of identical kind+body; OBJECT_CONFLICT otherwise.
 */
export function admitObject(
  ctx: Ctx,
  objectId: string,
  kind: T.ObjectKind,
  rawBody: unknown,
  owner: string | null,
  nowMs: bigint,
): { object: string; digest: string; bytes: string; row: ObjectRow | null } {
  const body = validObjectBody(kind, rawBody) as T.ObjectBody;
  const digest = registryDigest(kind, body);
  const bytes = objectBytesLocal(kind, body);
  const existing = ctx.store.getObject(objectId);
  if (existing) {
    if (existing.kind === kind && existing.digest === digest) {
      return { object: objectId, digest, bytes: String(existing.bytes), row: existing };
    }
    throw err("OBJECT_CONFLICT", `object ${objectId} already exists with different bytes or kind`);
  }
  if (owner !== null) {
    if (ctx.store.countObjectsByOwner(owner) >= ctx.maxObjectsPerPrincipal) {
      throw err("LIMIT_EXCEEDED", "per-principal object quota reached");
    }
    if (ctx.store.unboundBytesByOwner(owner) + BigInt(bytes) > ctx.maxUnboundObjectBytes) {
      throw err("LIMIT_EXCEEDED", "per-principal unbound object byte quota reached");
    }
  }
  ctx.store.putObject({
    object_id: objectId, kind, digest, bytes, path: null, owner,
    scope_commit: scopeOfBody(kind, body), created_ms: nowMs, referenced: 0, body,
  });
  return { object: objectId, digest, bytes: String(bytes), row: ctx.store.getObject(objectId) };
}

function objectBytesLocal(kind: T.ObjectKind, body: T.ObjectBody): number {
  if (kind === "blob") {
    return Buffer.from((body as T.BlobObject).data, "base64url").length;
  }
  return jcsBytes(body as unknown as Json).length;
}

function scopeOfBody(kind: T.ObjectKind, body: T.ObjectBody): string | null {
  const b = body as Record<string, unknown>;
  if (kind === "envelope") return (b.commit_id as string) ?? null;
  if (kind === "evidence" || kind === "manifest") return (b.commit_id as string) ?? null;
  if ((kind === "approval" || kind === "award" || kind === "control") && typeof b.body === "object" && b.body !== null) {
    return ((b.body as Record<string, unknown>).commit_id as string) ?? null;
  }
  return null;
}

/** System object admission (receipts, manifests, chunks, incidents) — never charged to a caller quota. */
export function admitSystemObject(ctx: Ctx, objectId: string, kind: T.ObjectKind, body: unknown, nowMs: bigint): { digest: string; bytes: string } {
  const r = admitObject(ctx, objectId, kind, body, null, nowMs);
  ctx.store.markObjectReferenced(objectId, null);
  return { digest: r.digest, bytes: r.bytes };
}

// ---------- shared guards ----------

export function requireClockSafe(safe: boolean): void {
  if (!safe) throw err("CLOCK_UNSAFE", "clock is unsafe; deadline evaluation suspended");
}

export function requireRunning(store: Store): void {
  if (store.getControlState().status === "HALTED") throw err("HALTED", "coordinator is halted");
}

export function controlRevision(store: Store): bigint {
  return store.getMeta()!.control_revision;
}

export function insertAuditDelivery(ctx: Ctx, stream: string, throughSeq: bigint, digest: string): void {
  if (!ctx.auditEvery) return;
  const meta = ctx.store.getMeta()!;
  const n = meta.delivery_seq + 1n;
  ctx.store.setMeta({ delivery_seq: n });
  ctx.store.putAuditDelivery(`d${n.toString(16)}`, stream, throughSeq, digest);
}

export function recordIncident(ctx: Ctx, code: string, evidenceDigest: string, observedMs: bigint): string {
  const meta = ctx.store.getMeta()!;
  const n = meta.delivery_seq + 900000n; // incident ids live in their own range to stay unique
  ctx.store.setMeta({ delivery_seq: n });
  const id = `inc${n.toString(16)}`;
  ctx.store.putIncident(id, code, evidenceDigest, observedMs);
  return id;
}

/** Halt the domain and emit SafetyHalted on the control stream (durable-logging path). */
export function safetyHalt(ctx: Ctx, reason: "clock" | "storage" | "custody" | "fence", incidentId: string, nowMs: bigint): void {
  if (ctx.store.getControlState().status === "HALTED") return; // one halt per incident stream position
  ctx.store.setControlState("HALTED", incidentId);
  emitEvent(ctx, "control", null, null, `sys_control_${controlRevision(ctx.store) + 1n}` as T.Id, nowMs, { kind: "SafetyHalted", reason, incident: incidentId } as T.EventData, []);
  ctx.store.setMeta({ control_revision: controlRevision(ctx.store) + 1n });
}
