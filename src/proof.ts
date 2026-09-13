// Proof export (commit-proof/1 bundles) and the offline verifier (§9.3).
// The verifier performs no provider calls, clock reads, or side effects.

import crypto from "node:crypto";
import { D, edSign, edVerify, H } from "./crypto.ts";
import { err } from "./errors.ts";
import { jcs, jcsBytes } from "./json/jcs.ts";
import { parseStrictJson, type Json } from "./json/strict.ts";
import { entryOrder, registryDigest, validatePolicySemantics } from "./objects.ts";
import { decodeBase64urlCanonical, u64 } from "./scalars.ts";
import { validObjectBody, validProofManifest, validTrustPin } from "./schema.ts";
import type { Store, EventRow, PromiseRow } from "./store.ts";
import type * as T from "./types.ts";
import { admitSystemObject } from "./reducer/core.ts";
import type { CallCtx } from "./reducer/methods.ts";

/** This implementation's reducer identity digest; pinned in TrustPin.reducer_digest. */
export const REDUCER_DIGEST = H(Buffer.from("commit-reducer/1"));

const ZERO64 = "0".repeat(64);

// ---------- checkpoint ----------

export function ledgerRoot(store: Store, custody: string, assetCode: string): string {
  const rows = store.allAccounts(custody, assetCode)
    .filter((a) => a.beneficial === 1)
    .map((a) => ({ account: a.principal, available_minor: String(a.available_minor), held_minor: String(a.held_minor) }));
  rows.sort((a, b) => (a.account < b.account ? -1 : a.account > b.account ? 1 : 0));
  return H(jcsBytes(rows as unknown as Json));
}

export function makeCheckpoint(ctx: CallCtx, stream: string, seq: bigint, head: string): T.Checkpoint {
  const store = ctx.store;
  const controlHead = store.lastEvent("control")?.event_hash ?? ZERO64;
  const body: T.CheckpointBody = {
    v: 1, tenant: ctx.policy.tenant, environment: ctx.policy.environment, stream,
    seq: String(seq), head, authority_head: controlHead,
    ledger_root: ledgerRoot(store, ctx.custody.custody, ctx.custody.asset.code),
    writer_epoch: ctx.writerEpoch as T.U64, created_ms: String(ctx.now) as T.U64,
  };
  return { body, key_id: ctx.writerKeyId, signature: edSign("checkpoint", body as unknown as Json, ctx.writerSeed) };
}

// ---------- export ----------

const CHUNK_LIMIT = 1048576;
const SEGMENT_EVENTS = 256;

export function exportProof(ctx: CallCtx, commitId: string, disclosure: "full" | "redacted", cursor: string | null): T.ExportResult {
  const store = ctx.store;
  const p = store.getPromise(commitId);
  if (!p) throw err("NOT_FOUND", "promise not found");
  const isParty = ctx.actor === p.payer || ctx.actor === p.payee;
  const isAuditor = ctx.capability.commit_ids.includes(commitId);
  if (!isParty && !isAuditor) throw err("NOT_FOUND", "promise not found");

  if (cursor !== null) return continueExport(ctx, commitId, disclosure, decodeExportCursor(ctx, cursor));

  const events = store.allEvents(commitId);
  if (events.length === 0) throw err("EXPORT_INCOMPLETE", "no events to export");
  const authEvents = store.allEvents("control");

  // segment long histories: ≤256 promise events per manifest, predecessor-linked
  const segments: EventRow[][] = [];
  for (let i = 0; i < events.length; i += SEGMENT_EVENTS) segments.push(events.slice(i, i + SEGMENT_EVENTS));
  let previous: T.BlobRef | null = null;
  let lastManifestId = "";
  let lastResult: T.ExportResult | null = null;
  for (const seg of segments) {
    const lastSeq = seg[seg.length - 1]!.seq;
    const head = seg[seg.length - 1]!.event_hash;
    const checkpoint = makeCheckpoint(ctx, commitId, lastSeq, head);
    if (store.getCheckpoint(commitId, lastSeq) === null) {
      store.putCheckpoint(commitId, lastSeq, head, checkpoint.body.authority_head, checkpoint.body.ledger_root, null);
    }
    const manifest = buildManifest(ctx, p, seg, authEvents, checkpoint, disclosure, previous);
    const r = finishSegment(ctx, manifest, 0);
    lastManifestId = r.manifest;
    previous = { object: r.manifest, sha256: store.getObject(r.manifest)!.digest, bytes: String(store.getObject(r.manifest)!.bytes), media: "application/json" };
    lastResult = r;
  }
  void lastManifestId;
  return lastResult!;
}

interface ExportCursorPayload { kind: "export"; commit_id: string; disclosure: string; manifest_id: string; row_index: string }

function encodeExportCursor(ctx: CallCtx, payload: ExportCursorPayload): string {
  const nonce = crypto.randomBytes(12);
  const k = crypto.createHash("sha256").update(ctx.cursorSecret).digest();
  const c = crypto.createCipheriv("aes-256-gcm", k, nonce);
  const ct = Buffer.concat([c.update(Buffer.from(jcs(payload as unknown as Json), "utf8")), c.final()]);
  return Buffer.concat([nonce, c.getAuthTag(), ct]).toString("base64url");
}

function decodeExportCursor(ctx: CallCtx, cursor: string): ExportCursorPayload {
  try {
    const raw = decodeBase64urlCanonical(cursor);
    if (raw.length < 29) throw new Error("short");
    const k = crypto.createHash("sha256").update(ctx.cursorSecret).digest();
    const d = crypto.createDecipheriv("aes-256-gcm", k, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    const payload = parseStrictJson(Buffer.concat([d.update(raw.subarray(28)), d.final()])) as unknown as ExportCursorPayload;
    if (payload.kind !== "export") throw new Error("wrong kind");
    return payload;
  } catch {
    throw err("CURSOR_INVALID", "export cursor does not decode");
  }
}

function continueExport(ctx: CallCtx, commitId: string, disclosure: "full" | "redacted", payload: ExportCursorPayload): T.ExportResult {
  const store = ctx.store;
  if (payload.commit_id !== commitId || payload.disclosure !== disclosure) {
    throw err("CURSOR_INVALID", "cursor pins a different export");
  }
  const manifestRow = store.getObject(payload.manifest_id);
  if (!manifestRow || manifestRow.kind !== "manifest") throw err("CURSOR_INVALID", "cursor manifest missing");
  return finishSegment(ctx, manifestRow.body as T.ProofManifest, Number(BigInt(payload.row_index)));
}

function neededObjectIds(events: T.SignedEvent[]): Set<string> {
  const ids = new Set<string>();
  for (const ev of events) for (const o of ev.body.objects) ids.add(o.id);
  return ids;
}

/** Recursively collect BlobRef.object ids nested inside an object body. */
function nestedBlobRefs(v: unknown, out: Set<string>): void {
  if (v === null || typeof v !== "object") return;
  if (Array.isArray(v)) { for (const x of v) nestedBlobRefs(x, out); return; }
  const o = v as Record<string, unknown>;
  const ks = Object.keys(o);
  if (ks.length === 4 && typeof o.object === "string" && typeof o.sha256 === "string" &&
      typeof o.bytes === "string" && typeof o.media === "string") {
    out.add(o.object);
    return;
  }
  for (const k of ks) nestedBlobRefs(o[k], out);
}

function buildManifest(ctx: CallCtx, p: PromiseRow, events: EventRow[], authEvents: EventRow[], checkpoint: T.Checkpoint, disclosure: "full" | "redacted", previous: T.BlobRef | null): T.ProofManifest {
  const store = ctx.store;
  const signedEvents = events.map(toSigned);
  const signedAuth = authEvents.map(toSigned);
  const ids = neededObjectIds([...signedEvents, ...signedAuth]);
  ids.add(p.envelope_object);
  ids.add(ctx.policyObjectId);
  // expand nested blob references (attestation evidence, award exhibits, …)
  for (const id of [...ids]) {
    const row = store.getObject(id);
    if (row) nestedBlobRefs(row.body, ids);
  }
  const entries: T.ObjectEntry[] = [];
  for (const id of ids) {
    const row = store.getObject(id);
    if (row) entries.push({ id: row.object_id, kind: row.kind, digest: row.digest, bytes: String(row.bytes) });
  }
  entries.sort(entryOrder);
  return {
    v: 1, format: "commit-proof/1", commit_id: p.commit_id, disclosure,
    previous, events: signedEvents, authority_events: signedAuth, objects: entries,
    checkpoint, custody_manifest: ctx.custody,
  };
}

function toSigned(r: EventRow): T.SignedEvent {
  const raw = r.canonical_body as unknown as string | Uint8Array;
  const body = parseStrictJson(typeof raw === "string" ? raw : Buffer.from(raw).toString("utf8")) as unknown as T.EventBody;
  return { body, hash: r.event_hash, key_id: r.key_id, signature: r.signature };
}

/** Store manifest + emit chunk rows; paginate when rows exceed 1 MiB. */
function finishSegment(ctx: CallCtx, manifest: T.ProofManifest, startRow: number): T.ExportResult {
  const store = ctx.store;
  const n = store.bumpCounter("export_seq");
  const manifestId = `proof${n}`;
  admitSystemObject(ctx, manifestId, "manifest", manifest, ctx.now);

  const rows: { id: string; kind: T.ObjectKind; body: T.ObjectBody; digest: string }[] = [];
  for (const e of manifest.objects) {
    if (manifest.disclosure === "redacted" && (e.kind === "blob" || e.kind === "evidence")) continue;
    const row = store.getObject(e.id);
    if (row) rows.push({ id: row.object_id, kind: row.kind, body: row.body, digest: row.digest });
  }
  rows.sort((a, b) => entryOrder({ id: a.id, kind: a.kind, digest: a.digest, bytes: "0" }, { id: b.id, kind: b.kind, digest: b.digest, bytes: "0" }));

  const manifestLine = jcs({ id: manifestId, kind: "manifest", body: manifest } as unknown as Json);
  if (manifestLine.length + 1 > CHUNK_LIMIT) throw err("EXPORT_INCOMPLETE", "manifest row exceeds chunk bound");
  const selected: string[] = [];
  let size = manifestLine.length + 1;
  let idx = startRow;
  for (; idx < rows.length; idx++) {
    const line = jcs({ id: rows[idx]!.id, kind: rows[idx]!.kind, body: rows[idx]!.body } as unknown as Json);
    if (line.length + 1 > CHUNK_LIMIT) throw err("EXPORT_INCOMPLETE", "single object row exceeds chunk bound");
    if (size + line.length + 1 > CHUNK_LIMIT) break;
    selected.push(line);
    size += line.length + 1;
  }
  const chunk = Buffer.from([manifestLine, ...selected].join("\n") + "\n", "utf8");
  const cn = store.bumpCounter("chunk_seq");
  const chunkId = `chunk${cn}`;
  admitSystemObject(ctx, chunkId, "blob", { encoding: "base64url", data: chunk.toString("base64url") }, ctx.now);
  const ref: T.BlobRef = { object: chunkId, sha256: H(chunk), bytes: String(chunk.length), media: "application/octet-stream" };
  const complete = idx >= rows.length;
  const next = complete ? null : encodeExportCursor(ctx, {
    kind: "export", commit_id: manifest.commit_id, disclosure: manifest.disclosure,
    manifest_id: manifestId, row_index: String(idx),
  });
  return { manifest: manifestId, chunk: ref, next_cursor: next, complete };
}

// ---------- offline verifier (§9.3) ----------

const INTEGRITY_INVALID = new Set(["SCHEMA_INVALID", "UNSUPPORTED_VERSION", "OBJECT_HASH_MISMATCH", "EVENT_HASH_MISMATCH", "CHAIN_GAP", "CHAIN_FORK", "PIN_MISMATCH", "TRUST_UNANCHORED"]);
const INCOMPLETE = new Set(["OBJECT_MISSING", "PIN_AHEAD"]);
const AUTH_INVALID = new Set(["SIGNATURE_INVALID", "POLICY_INVALID", "KEY_REVOKED", "QUORUM_MISSING", "TRANSITION_INVALID", "DEADLINE_INVALID", "ALLOCATION_INVALID", "RECEIPT_INVALID", "CUSTODY_CONFLICT", "EVENT_HASH_MISMATCH", "PIN_MISMATCH", "TRUST_UNANCHORED"]);
const AUTH_INCOMPLETE = new Set(["OBJECT_MISSING", "PIN_AHEAD"]);

class VErr extends Error { readonly code: string; constructor(code: string) { super(code); this.name = "VErr"; this.code = code; } }

export function verifyBundle(
  manifestRaw: unknown,
  objectRows: { id: string; kind: string; body: unknown }[],
  trustRaw: unknown,
  opts: { reducerDigest?: string } = {},
): T.VerifyResult {
  const codes = new Set<string>();
  const add = (c: string) => { codes.add(c); };
  const fail = (c: string): never => { throw new VErr(c); };
  const run = (fn: () => void): boolean => {
    try { fn(); return codes.size === 0; } catch (e) {
      if (e instanceof VErr) { add(e.code); return false; }
      throw e;
    }
  };
  const weakest = (): T.VerifyResult => dimsFromCodes(codes, manifestForDims(manifestRaw));

  // stage 1: bounds, canonical schemas, inventory digests
  let manifest: T.ProofManifest;
  let trust: T.TrustPin;
  const objects = new Map<string, { kind: T.ObjectKind; body: T.ObjectBody }>();
  try {
    manifest = validProofManifest(manifestRaw);
    trust = validTrustPin(trustRaw);
    for (const r of objectRows) {
      if (typeof r?.id !== "string" || typeof r?.kind !== "string") fail("SCHEMA_INVALID");
      objects.set(r.id, { kind: r.kind as T.ObjectKind, body: validObjectBody(r.kind as T.ObjectKind, r.body) });
    }
    for (const [id, o] of objects) {
      const entry = manifest.objects.find((x) => x.id === id);
      if (entry && (entry.kind !== o.kind || registryDigest(o.kind, o.body) !== entry.digest)) add("OBJECT_HASH_MISMATCH");
    }
    if (codes.size) fail(codes.values().next().value!);
  } catch (e) {
    if (e instanceof VErr) add(e.code);
    else if ((e as { code?: string }).code) add((e as { code: string }).code === "LIMIT_EXCEEDED" ? "SCHEMA_INVALID" : (e as { code: string }).code);
    else add("SCHEMA_INVALID");
    return { integrity: "invalid", authorization: "invalid", execution: "unknown", conservation: "not-checked", freshness: "unanchored", through_seq: "0", effects_enabled: false, codes: [...codes].sort() };
  }

  // stage 2: trust anchoring
  {
    const before = codes.size;
    if (trust.tenant !== manifest.checkpoint.body.tenant || trust.environment !== manifest.checkpoint.body.environment) add("TRUST_UNANCHORED");
    if (trust.reducer_digest !== (opts.reducerDigest ?? REDUCER_DIGEST)) add("TRUST_UNANCHORED");
    if (D("custody_manifest", manifest.custody_manifest as unknown as Json) !== trust.custody_manifest_hash) add("TRUST_UNANCHORED");
    if (codes.size > before) return weakest();
  }

  // stage 3: pinned policy object + authority history
  let policy: T.Policy | null = null;
  for (const [, o] of objects) {
    if (o.kind === "policy" && registryDigest("policy", o.body as T.Policy) === trust.genesis_policy_hash) policy = o.body as T.Policy;
  }
  {
    const before = codes.size;
    if (!policy) add("OBJECT_MISSING");
    else {
      try { validatePolicySemantics(policy, manifest.custody_manifest, trust.writer_key); } catch { add("POLICY_INVALID"); }
    }
    if (codes.size > before) return weakest();
  }

  const evs = manifest.events;

  // stage 4: chain structure — seq contiguity, prev links, declared hashes, checkpoint inclusion
  {
    const before = codes.size;
    let prev = ZERO64;
    for (let i = 0; i < evs.length; i++) {
      const ev = evs[i]!;
      if (BigInt(ev.body.seq) !== BigInt(i + 1)) add("CHAIN_GAP");
      if (ev.body.prev !== prev) add("CHAIN_FORK");
      if (D("event", ev.body as unknown as Json) !== ev.hash) add("EVENT_HASH_MISMATCH");
      prev = ev.hash;
    }
    const cp = manifest.checkpoint;
    if (evs.length && (cp.body.stream !== manifest.commit_id || cp.body.head !== evs[evs.length - 1]!.hash || BigInt(cp.body.seq) !== BigInt(evs.length))) {
      add("CHAIN_GAP");
    }
    if (codes.size > before) return weakest();
  }

  // stage 4b: writer signatures/epochs evaluated only after structure passes
  {
    const before = codes.size;
    let lastEpoch = 0n;
    for (const ev of [...evs, ...manifest.authority_events]) {
      const epoch = u64(ev.body.writer_epoch);
      if (epoch < 1n || epoch > u64(trust.writer_epoch)) add("SIGNATURE_INVALID");
      if (ev.body.stream === manifest.commit_id) {
        if (epoch < lastEpoch) add("SIGNATURE_INVALID");
        lastEpoch = epoch;
      }
      if (!edVerify("event", ev.body as unknown as Json, trust.writer_key, ev.signature)) add("SIGNATURE_INVALID");
    }
    if (!edVerify("checkpoint", manifest.checkpoint.body as unknown as Json, trust.writer_key, manifest.checkpoint.signature)) add("SIGNATURE_INVALID");
    if (codes.size > before) return weakest();
  }

  // stages 5–7: transitions, authority, deadlines, allocation, receipts
  {
    const before = codes.size;
    try {
      revalidate(manifest, objects, policy!, trust, add);
    } catch (e) {
      if (e instanceof VErr) add(e.code); else throw e;
    }
    if (codes.size > before) return weakest();
  }

  // stage 8: minimum checkpoint pin
  {
    const pin = trust.minimum_checkpoint;
    if (pin) {
      const headSeq = evs.length ? BigInt(evs[evs.length - 1]!.body.seq) : 0n;
      const pinSeq = BigInt(pin.body.seq);
      if (headSeq < pinSeq) add("PIN_AHEAD");
      else {
        const atSeq = evs[Number(pinSeq) - 1];
        if (atSeq && atSeq.hash !== pin.body.head) add("PIN_MISMATCH");
      }
      if (codes.size) return weakest();
    }
  }

  const hasSettled = evs.some((e) => e.body.to === "SETTLED");
  const execution = hasSettled
    ? (manifest.custody_manifest.profile === "sim-ledger/1" ? "local-simulation-verified" : "custodian-attested")
    : "unknown";
  return {
    integrity: "verified", authorization: "verified", execution,
    conservation: "not-checked", freshness: trust.minimum_checkpoint ? "as-of-pin" : "unanchored",
    through_seq: evs.length ? evs[evs.length - 1]!.body.seq : "0", effects_enabled: false, codes: [],
  };
}

function manifestForDims(raw: unknown): T.ProofManifest | null {
  try { return validProofManifest(raw); } catch { return null; }
}

function dimsFromCodes(codes: Set<string>, manifest: T.ProofManifest | null): T.VerifyResult {
  let integrity: T.VerifyResult["integrity"] = "verified";
  let authorization: T.VerifyResult["authorization"] = "verified";
  for (const c of codes) {
    if (INCOMPLETE.has(c) && integrity === "verified") integrity = "incomplete";
    if (INTEGRITY_INVALID.has(c)) integrity = "invalid";
    if (AUTH_INCOMPLETE.has(c) && authorization === "verified") authorization = "incomplete";
    if (AUTH_INVALID.has(c)) authorization = "invalid";
  }
  const evs = manifest?.events ?? [];
  return {
    integrity, authorization, execution: "unknown", conservation: "not-checked",
    freshness: "unanchored", through_seq: evs.length ? evs[evs.length - 1]!.body.seq : "0",
    effects_enabled: false, codes: [...codes].sort(),
  };
}

/** Replay events: transitions, deadlines, authority, receipts, allocation conservation. */
function revalidate(
  manifest: T.ProofManifest,
  objects: Map<string, { kind: T.ObjectKind; body: T.ObjectBody }>,
  policy: T.Policy,
  trust: T.TrustPin,
  add: (c: string) => void,
): void {
  const members = new Map(policy.members.map((m) => [m.key_id, m]));
  const custodyKey = trust.custody_key;

  const revokeAtSeq: { seq: bigint; key_id: string }[] = [];
  for (const ev of manifest.authority_events) {
    const d = ev.body.data;
    if (d.kind === "ControlApplied") {
      const certObj = objects.get(d.certificate);
      if (certObj?.kind === "control") {
        const action = (certObj.body as T.ControlCertificate).body.action;
        if (action.kind === "revoke_key") revokeAtSeq.push({ seq: BigInt(ev.body.seq), key_id: action.key_id });
      }
    }
  }
  const revokedAt = (cut: bigint) => new Set(revokeAtSeq.filter((r) => r.seq <= cut).map((r) => r.key_id));

  const getObj = (id: string): { kind: T.ObjectKind; body: T.ObjectBody } => {
    const o = objects.get(id);
    if (!o) { add("OBJECT_MISSING"); throw new VErr("OBJECT_MISSING"); }
    return o;
  };

  let state: T.State | "absent" = "absent";
  let envelope: T.Envelope | null = null;
  const approvals = new Map<string, T.Approval>();
  let releaseAt: bigint | null = null;
  let decisionBy: bigint | null = null;
  let allocation: T.Allocation | null = null;

  const checkTransition = (ev: T.SignedEvent, legalFrom: (T.State | "absent")[], legalTo: T.State | null): boolean => {
    const b = ev.body;
    const fromOk = legalFrom.includes(b.from === null ? "absent" : b.from);
    const toOk = legalTo === null ? b.to === b.from : b.to === legalTo;
    const stateOk = b.from === (state === "absent" ? null : state);
    if (!fromOk || !toOk || !stateOk) { add("TRANSITION_INVALID"); return false; }
    if (b.to !== null) state = b.to;
    return true;
  };

  for (const ev of manifest.events) {
    const d = ev.body.data;
    const t = u64(ev.body.time_ms);
    const cut = u64(ev.body.authority_seq);
    switch (d.kind) {
      case "Proposed": {
        if (!checkTransition(ev, ["absent"], "PROPOSED")) break;
        const o = getObj(d.envelope);
        if (o.kind !== "envelope") { add("OBJECT_HASH_MISMATCH"); break; }
        envelope = o.body as T.Envelope;
        if (registryDigest("envelope", envelope) !== d.envelope_hash) add("OBJECT_HASH_MISMATCH");
        if (ev.body.policy_hash !== trust.genesis_policy_hash) add("POLICY_INVALID");
        if (!(u64(envelope.created_ms) <= t && t < u64(envelope.commit_by_ms) &&
              u64(envelope.commit_by_ms) <= u64(envelope.fund_by_ms) && u64(envelope.fund_by_ms) < u64(envelope.condition_by_ms))) {
          add("DEADLINE_INVALID");
        }
        break;
      }
      case "ApprovalAccepted": {
        if (!checkTransition(ev, ["PROPOSED"], "PROPOSED")) break;
        const o = getObj(d.approval);
        if (o.kind !== "approval") { add("OBJECT_HASH_MISMATCH"); break; }
        const ap = o.body as T.Approval;
        const m = members.get(ap.body.key_id);
        if (!m || !policy.approve.keys.includes(ap.body.key_id)) add("SIGNATURE_INVALID");
        else if (revokedAt(cut).has(ap.body.key_id)) add("KEY_REVOKED");
        else if (!edVerify("approval", ap.body as unknown as Json, m.public_key, ap.signature)) add("SIGNATURE_INVALID");
        if (envelope && (ap.body.envelope_hash !== registryDigest("envelope", envelope) || ap.body.policy_hash !== ev.body.policy_hash)) add("SIGNATURE_INVALID");
        approvals.set(d.key_id, ap);
        break;
      }
      case "CommitAuthorized": {
        if (!checkTransition(ev, ["PROPOSED"], "FUNDING")) break;
        if (envelope && t >= u64(envelope.commit_by_ms)) add("DEADLINE_INVALID");
        const revoked = revokedAt(cut);
        const principals = new Set<string>();
        let human = false;
        for (const k of approvals.keys()) {
          if (revoked.has(k)) continue;
          const m = members.get(k)!;
          principals.add(m.principal);
          if (m.kind === "human") human = true;
        }
        const mandatory = policy.approve.mandatory_principals.every((mp) => principals.has(mp));
        if (principals.size < policy.approve.threshold || !mandatory || !human) add("QUORUM_MISSING");
        if (envelope && d.reserve.envelope_hash !== registryDigest("envelope", envelope)) add("RECEIPT_INVALID");
        break;
      }
      case "EscrowHeld": {
        if (!checkTransition(ev, ["FUNDING", "FUNDING_UNKNOWN"], "ACTIVE")) break;
        const o = getObj(d.receipt);
        if (o.kind !== "custody") { add("RECEIPT_INVALID"); break; }
        const rc = o.body as T.CustodyReceipt;
        if (rc.body.status !== "applied" || !rc.body.final) add("RECEIPT_INVALID");
        else if (!edVerify("custody", rc.body as unknown as Json, custodyKey, rc.signature)) add("SIGNATURE_INVALID");
        break;
      }
      case "FundingUncertain": checkTransition(ev, ["FUNDING"], "FUNDING_UNKNOWN"); break;
      case "FundingFailed": checkTransition(ev, ["FUNDING", "FUNDING_UNKNOWN"], "UNFUNDED"); break;
      case "Cancelled": checkTransition(ev, ["PROPOSED"], "CANCELLED"); break;
      case "Expired": checkTransition(ev, ["PROPOSED"], "EXPIRED"); break;
      case "ConditionSatisfied": {
        if (!checkTransition(ev, ["ACTIVE"], "RELEASE_PENDING")) break;
        const o = getObj(d.evidence);
        if (o.kind !== "evidence") { add("OBJECT_HASH_MISMATCH"); break; }
        const es = o.body as T.EvidenceSet;
        if (!envelope) { add("OBJECT_MISSING"); break; }
        if (es.commit_id !== envelope.commit_id || es.envelope_hash !== registryDigest("envelope", envelope)) add("TRANSITION_INVALID");
        if (t >= u64(envelope.condition_by_ms)) add("DEADLINE_INVALID");
        if (u64(d.release_at_ms) !== t + u64(envelope.challenge_ms)) add("TRANSITION_INVALID");
        releaseAt = u64(d.release_at_ms);
        for (let i = 0; i < envelope.condition.clauses.length; i++) {
          const clause = envelope.condition.clauses[i]!;
          const item = es.items[i];
          if (!item || item.clause_id !== clause.id || item.kind !== clause.kind) { add("TRANSITION_INVALID"); continue; }
          if (item.kind === "attested" && clause.kind === "attested") {
            const cert = item.certificate;
            if (cert.body.clause_id !== clause.id || cert.body.predicate !== clause.predicate ||
                cert.body.envelope_hash !== registryDigest("envelope", envelope) ||
                !(u64(cert.body.issued_ms) <= t && t < u64(cert.body.valid_until_ms))) add("TRANSITION_INVALID");
            const principals = new Set<string>();
            let badSig = false;
            for (const s of cert.signatures) {
              const m = members.get(s.key_id);
              if (!m || !policy.attest.keys.includes(s.key_id) || !edVerify("attestation", cert.body as unknown as Json, m.public_key, s.sig)) badSig = true;
              else principals.add(m.principal);
            }
            if (badSig) add("SIGNATURE_INVALID");
            if (principals.size < policy.attest.threshold || !policy.attest.mandatory_principals.every((mp) => principals.has(mp))) add("QUORUM_MISSING");
          } else if (item.kind === "hashlock" && clause.kind === "hashlock") {
            const pre = decodeBase64urlCanonical(item.preimage_base64url);
            if (H(pre) !== clause.sha256) add("TRANSITION_INVALID");
          }
        }
        break;
      }
      case "DisputeOpened": {
        if (!checkTransition(ev, ["RELEASE_PENDING"], "DISPUTED")) break;
        if (releaseAt !== null && t >= releaseAt) add("DEADLINE_INVALID");
        decisionBy = u64(d.decision_by_ms);
        if (envelope && decisionBy !== releaseAt! + u64(envelope.dispute_ms)) add("TRANSITION_INVALID");
        break;
      }
      case "SettlementDecided": {
        const legal: Record<T.Disposition, (T.State | "absent")[]> = {
          release: ["RELEASE_PENDING"], condition_timeout: ["ACTIVE"], funding_late: ["ACTIVE"],
          award: ["DISPUTED"], dispute_timeout: ["DISPUTED"],
        };
        if (!checkTransition(ev, legal[d.reason] ?? [], "SETTLING")) break;
        allocation = d.allocation;
        if (!envelope) { add("OBJECT_MISSING"); break; }
        if (u64(d.allocation.pay_minor) + u64(d.allocation.return_minor) !== u64(envelope.amount_minor)) add("ALLOCATION_INVALID");
        if (d.reason === "release" && (releaseAt === null || t < releaseAt)) add("DEADLINE_INVALID");
        if (d.reason === "condition_timeout" && t < u64(envelope.condition_by_ms)) add("DEADLINE_INVALID");
        if (d.reason === "dispute_timeout" && (decisionBy === null || t < decisionBy)) add("DEADLINE_INVALID");
        if (d.reason === "award") {
          if (d.award === null) { add("OBJECT_MISSING"); break; }
          const o = getObj(d.award);
          if (o.kind !== "award") { add("OBJECT_HASH_MISMATCH"); break; }
          const aw = o.body as T.Award;
          if (aw.body.pay_minor !== d.allocation.pay_minor || aw.body.return_minor !== d.allocation.return_minor) add("ALLOCATION_INVALID");
          const principals = new Set<string>();
          let badSig = false;
          for (const s of aw.signatures) {
            const m = members.get(s.key_id);
            if (!m || !policy.arbitrate.keys.includes(s.key_id) || !edVerify("award", aw.body as unknown as Json, m.public_key, s.sig)) badSig = true;
            else principals.add(m.principal);
          }
          if (badSig) add("SIGNATURE_INVALID");
          if (principals.size < policy.arbitrate.threshold || !policy.arbitrate.mandatory_principals.every((mp) => principals.has(mp))) add("QUORUM_MISSING");
        }
        break;
      }
      case "SettlementUncertain": checkTransition(ev, ["SETTLING"], "SETTLEMENT_UNKNOWN"); break;
      case "SettlementBlocked": checkTransition(ev, ["SETTLING", "SETTLEMENT_UNKNOWN"], "SETTLEMENT_BLOCKED"); break;
      case "SettlementRetried": checkTransition(ev, ["SETTLEMENT_BLOCKED"], "SETTLING"); break;
      case "Settled": {
        if (!checkTransition(ev, ["SETTLING", "SETTLEMENT_UNKNOWN"], "SETTLED")) break;
        const o = getObj(d.receipt);
        if (o.kind !== "custody") { add("RECEIPT_INVALID"); break; }
        const rc = o.body as T.CustodyReceipt;
        if (rc.body.status !== "applied" || !rc.body.final) add("RECEIPT_INVALID");
        else if (!edVerify("custody", rc.body as unknown as Json, custodyKey, rc.signature)) add("SIGNATURE_INVALID");
        else if (rc.body.allocation === null || rc.body.allocation.pay_minor !== d.allocation.pay_minor || rc.body.allocation.return_minor !== d.allocation.return_minor) add("RECEIPT_INVALID");
        if (allocation && (d.allocation.pay_minor !== allocation.pay_minor || d.allocation.return_minor !== allocation.return_minor)) add("ALLOCATION_INVALID");
        break;
      }
      case "CustodyObservation": checkTransition(ev, ["FUNDING", "FUNDING_UNKNOWN", "SETTLING", "SETTLEMENT_UNKNOWN", "SETTLEMENT_BLOCKED"], null); break;
      case "ControlApplied": case "SafetyHalted": break;
    }
  }
}

// ---------- proof.verify RPC ----------

export function verifyProofRpc(ctx: CallCtx, manifestId: string, trustId: string): T.VerifyResult {
  const store = ctx.store;
  const mRow = store.getObject(manifestId);
  if (!mRow || mRow.kind !== "manifest") throw err("NOT_FOUND", "manifest object not found");
  const tRow = store.getObject(trustId);
  if (!tRow || tRow.kind !== "trust" || tRow.owner !== "__enrolled__") throw err("NOT_FOUND", "trust object not found or not operator-installed");
  const manifest = mRow.body as T.ProofManifest;
  const rows = manifest.objects
    .map((e) => store.getObject(e.id))
    .filter((x): x is NonNullable<typeof x> => x !== null)
    .map((r) => ({ id: r.object_id, kind: r.kind, body: r.body }));
  return verifyBundle(manifest, rows, tRow.body, {});
}
