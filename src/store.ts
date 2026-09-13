// SQLite persistence (§6). node:sqlite DatabaseSync; BEGIN IMMEDIATE for every
// mutating reducer; WAL + synchronous=FULL; one writer process.

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, writeFileSync, renameSync, openSync, fsyncSync, closeSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { H } from "./crypto.ts";
import { jcsBytes } from "./json/jcs.ts";
import type { Json } from "./json/strict.ts";
import type * as T from "./types.ts";

export const STORAGE_VERSION = 1;
export const PROTOCOL = "commit/1";

export interface ObjectRow {
  object_id: string; kind: T.ObjectKind; digest: string; bytes: number;
  path: string | null; owner: string | null; scope_commit: string | null;
  created_ms: bigint; referenced: number; body: T.ObjectBody;
}

export interface PromiseRow {
  commit_id: string; tenant: string; environment: string; business_id: string;
  envelope_object: string; envelope_hash: string; state: T.State; revision: bigint;
  payer: string; payee: string; amount: bigint; release_at: bigint | null;
  decision_by: bigint | null; allocation: T.Allocation | null;
  disposition: T.Disposition | null; next_due_ms: bigint | null;
  escrow_id: string | null; case_id: string | null; late_pending: number;
  consumed: number;
}

export interface OperationRow {
  operation_id: string; kind: "reserve" | "allocate"; commit_id: string;
  canonical_request: Buffer; request_hash: string; state: T.OperationState;
  attempts: number; last_provider_revision: string | null; last_receipt: string | null;
  first_dispatch_ms: bigint | null; next_attempt_ms: bigint | null;
}

export interface ReceiptRow {
  operation_id: string; provider_revision: string; attempt: number;
  body_hash: string; object_id: string; final: number; status: string;
}

export interface EventRow {
  stream: string; seq: bigint; prev: string; event_hash: string;
  canonical_body: Buffer; signature: string; key_id: string; transaction_id: bigint;
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  storage_version INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  tenant TEXT NOT NULL,
  environment TEXT NOT NULL,
  writer_epoch INTEGER NOT NULL,
  control_revision INTEGER NOT NULL,
  active_policy TEXT NOT NULL,
  last_clock_ms INTEGER NOT NULL,
  halted INTEGER NOT NULL DEFAULT 0,
  custody_revision INTEGER NOT NULL DEFAULT 0,
  export_seq INTEGER NOT NULL DEFAULT 0,
  delivery_seq INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS objects (
  object_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  digest TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  path TEXT,
  owner TEXT,
  scope_commit TEXT,
  created_ms INTEGER NOT NULL,
  referenced INTEGER NOT NULL DEFAULT 0,
  body TEXT NOT NULL,
  UNIQUE (kind, digest, object_id)
);
CREATE INDEX IF NOT EXISTS objects_owner ON objects(owner, referenced, created_ms);
CREATE TABLE IF NOT EXISTS policies (
  digest TEXT PRIMARY KEY,
  object_id TEXT NOT NULL UNIQUE,
  activated_control_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS promises (
  commit_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  environment TEXT NOT NULL,
  business_id TEXT NOT NULL,
  envelope_object TEXT NOT NULL,
  envelope_hash TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  revision INTEGER NOT NULL,
  payer TEXT NOT NULL,
  payee TEXT NOT NULL,
  amount INTEGER NOT NULL,
  release_at INTEGER,
  decision_by INTEGER,
  allocation TEXT,
  disposition TEXT,
  next_due_ms INTEGER,
  escrow_id TEXT,
  case_id TEXT,
  late_pending INTEGER NOT NULL DEFAULT 0,
  consumed INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant, environment, business_id)
);
CREATE INDEX IF NOT EXISTS promises_due ON promises(state, next_due_ms, commit_id);
CREATE TABLE IF NOT EXISTS events (
  stream TEXT NOT NULL,
  seq INTEGER NOT NULL,
  prev TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE,
  canonical_body BLOB NOT NULL,
  signature TEXT NOT NULL,
  key_id TEXT NOT NULL,
  transaction_id INTEGER NOT NULL,
  PRIMARY KEY (stream, seq)
);
CREATE INDEX IF NOT EXISTS events_tx ON events(transaction_id, stream, seq);
CREATE TABLE IF NOT EXISTS approvals (
  envelope_hash TEXT NOT NULL,
  key_id TEXT NOT NULL,
  approval_object TEXT NOT NULL,
  principal TEXT NOT NULL,
  accepted_seq INTEGER NOT NULL,
  response TEXT NOT NULL,
  PRIMARY KEY (envelope_hash, key_id),
  UNIQUE (envelope_hash, principal)
);
CREATE TABLE IF NOT EXISTS operations (
  operation_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  commit_id TEXT NOT NULL,
  canonical_request BLOB NOT NULL,
  request_hash TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_provider_revision TEXT,
  last_receipt TEXT,
  first_dispatch_ms INTEGER,
  next_attempt_ms INTEGER,
  UNIQUE (commit_id, kind)
);
CREATE INDEX IF NOT EXISTS operations_state ON operations(state, next_attempt_ms);
CREATE TABLE IF NOT EXISTS receipts (
  operation_id TEXT NOT NULL,
  provider_revision TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  body_hash TEXT NOT NULL,
  object_id TEXT NOT NULL,
  final INTEGER NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (operation_id, provider_revision)
);
CREATE INDEX IF NOT EXISTS receipts_final ON receipts(operation_id, final);
CREATE TABLE IF NOT EXISTS idempotency (
  principal TEXT NOT NULL,
  capability TEXT NOT NULL,
  method TEXT NOT NULL,
  request_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  canonical_response TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY (principal, capability, method, request_id)
);
CREATE TABLE IF NOT EXISTS exposure (
  commit_id TEXT PRIMARY KEY,
  amount INTEGER NOT NULL,
  operation_id TEXT,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_budget (
  tenant TEXT NOT NULL,
  environment TEXT NOT NULL,
  utc_day INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  charged_minor INTEGER NOT NULL,
  PRIMARY KEY (tenant, environment, utc_day, policy_hash)
);
CREATE TABLE IF NOT EXISTS accounts (
  custody TEXT NOT NULL,
  asset_code TEXT NOT NULL,
  principal TEXT NOT NULL,
  available_minor INTEGER NOT NULL CHECK (available_minor >= 0),
  held_minor INTEGER NOT NULL CHECK (held_minor >= 0),
  beneficial INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (custody, asset_code, principal)
);
CREATE TABLE IF NOT EXISTS ledger_journal (
  transaction_id INTEGER NOT NULL,
  line_no INTEGER NOT NULL,
  account TEXT NOT NULL,
  asset_code TEXT NOT NULL,
  side TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  commit_id TEXT,
  cause_seq INTEGER NOT NULL,
  PRIMARY KEY (transaction_id, line_no)
);
CREATE INDEX IF NOT EXISTS journal_cause ON ledger_journal(commit_id, cause_seq);
CREATE TABLE IF NOT EXISTS ledger_transactions (
  transaction_id INTEGER PRIMARY KEY,
  cause_stream TEXT NOT NULL,
  cause_seq INTEGER NOT NULL,
  total_debit INTEGER NOT NULL,
  total_credit INTEGER NOT NULL,
  asset_code TEXT NOT NULL,
  UNIQUE (cause_stream, cause_seq)
);
CREATE TABLE IF NOT EXISTS outbox (
  outbox_id INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  payload_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  lease_epoch INTEGER NOT NULL DEFAULT 0,
  next_attempt_ms INTEGER
);
CREATE INDEX IF NOT EXISTS outbox_ready ON outbox(state, next_attempt_ms);
CREATE TABLE IF NOT EXISTS audit_outbox (
  delivery_id TEXT PRIMARY KEY,
  stream TEXT NOT NULL,
  through_seq INTEGER NOT NULL,
  checkpoint_digest TEXT NOT NULL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  UNIQUE (stream, through_seq, checkpoint_digest)
);
CREATE TABLE IF NOT EXISTS security_incidents (
  incident_id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  redacted_evidence_digest TEXT NOT NULL,
  observed_ms INTEGER NOT NULL,
  resolved_control_seq INTEGER
);
CREATE INDEX IF NOT EXISTS incidents_code ON security_incidents(code, observed_ms);
CREATE TABLE IF NOT EXISTS checkpoints (
  stream TEXT NOT NULL,
  seq INTEGER NOT NULL,
  head TEXT NOT NULL,
  authority_head TEXT NOT NULL,
  ledger_root TEXT NOT NULL,
  object_id TEXT,
  PRIMARY KEY (stream, seq)
);
CREATE TABLE IF NOT EXISTS control_nonces (nonce TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS revoked_keys (key_id TEXT PRIMARY KEY, control_seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS control_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  status TEXT NOT NULL,
  incident_object TEXT
);
CREATE TABLE IF NOT EXISTS cursors (cursor_id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
`;

export class Store {
  readonly db: DatabaseSync;
  readonly dir: string;

  constructor(path: string, dir?: string) {
    this.db = new DatabaseSync(path);
    this.dir = dir ?? dirname(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA synchronous = FULL");
    this.db.exec("PRAGMA busy_timeout = 2000");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec(SCHEMA_SQL);
  }

  close(): void {
    this.db.close();
  }

  /** Every mutating reducer runs inside BEGIN IMMEDIATE … COMMIT (§6.3). */
  tx<R>(fn: () => R): R {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try { this.db.exec("ROLLBACK"); } catch { /* already rolled back */ }
      throw e;
    }
  }

  // ---- meta ----
  getMeta(): {
    storage_version: number; protocol: string; tenant: string; environment: string;
    writer_epoch: bigint; control_revision: bigint; active_policy: string;
    last_clock_ms: bigint; halted: number; custody_revision: bigint;
    export_seq: bigint; delivery_seq: bigint;
  } | null {
    const r = this.db.prepare("SELECT * FROM meta WHERE id = 1").get() as Record<string, unknown> | undefined;
    if (!r) return null;
    const bi = (v: unknown) => BigInt(v as number | bigint);
    return {
      storage_version: r.storage_version as number, protocol: r.protocol as string,
      tenant: r.tenant as string, environment: r.environment as string,
      writer_epoch: bi(r.writer_epoch), control_revision: bi(r.control_revision),
      active_policy: r.active_policy as string, last_clock_ms: bi(r.last_clock_ms),
      halted: r.halted as number, custody_revision: bi(r.custody_revision),
      export_seq: bi(r.export_seq), delivery_seq: bi(r.delivery_seq),
    };
  }

  setMeta(fields: Record<string, bigint | number | string>): void {
    const sets = Object.keys(fields).map((k) => `${k} = ?`).join(", ");
    this.db.prepare(`UPDATE meta SET ${sets} WHERE id = 1`).run(...Object.values(fields) as never[]);
  }

  initMeta(m: { tenant: string; environment: string; writer_epoch: bigint; active_policy: string; last_clock_ms: bigint }): void {
    this.db.prepare(
      "INSERT INTO meta (id, storage_version, protocol, tenant, environment, writer_epoch, control_revision, active_policy, last_clock_ms) VALUES (1, ?, ?, ?, ?, ?, 0, ?, ?)",
    ).run(STORAGE_VERSION, PROTOCOL, m.tenant, m.environment, m.writer_epoch, m.active_policy, m.last_clock_ms);
    this.db.prepare("INSERT INTO control_state (id, status, incident_object) VALUES (1, 'RUNNING', NULL)").run();
  }

  getControlState(): { status: "RUNNING" | "HALTED"; incident_object: string | null } {
    const r = this.db.prepare("SELECT status, incident_object FROM control_state WHERE id = 1").get() as { status: "RUNNING" | "HALTED"; incident_object: string | null };
    return r;
  }

  setControlState(status: "RUNNING" | "HALTED", incident: string | null = null): void {
    this.db.prepare("UPDATE control_state SET status = ?, incident_object = ? WHERE id = 1").run(status, incident);
  }

  // ---- objects ----
  putObject(row: { object_id: string; kind: T.ObjectKind; digest: string; bytes: number; path: string | null; owner: string | null; scope_commit: string | null; created_ms: bigint; referenced: number; body: T.ObjectBody }): void {
    this.db.prepare(
      "INSERT INTO objects (object_id, kind, digest, bytes, path, owner, scope_commit, created_ms, referenced, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(row.object_id, row.kind, row.digest, row.bytes, row.path, row.owner, row.scope_commit, row.created_ms, row.referenced, JSON.stringify(row.body));
  }

  getObject(id: string): ObjectRow | null {
    const r = this.db.prepare("SELECT * FROM objects WHERE object_id = ?").get(id) as Record<string, unknown> | undefined;
    if (!r) return null;
    return { ...(r as unknown as ObjectRow), body: JSON.parse(r.body as string) as T.ObjectBody, created_ms: BigInt(r.created_ms as number | bigint) };
  }

  markObjectReferenced(id: string, commit: string | null): void {
    if (commit === null) {
      this.db.prepare("UPDATE objects SET referenced = 1 WHERE object_id = ?").run(id);
    } else {
      this.db.prepare("UPDATE objects SET referenced = 1, scope_commit = ? WHERE object_id = ?").run(commit, id);
    }
  }

  countObjectsByOwner(owner: string): number {
    const r = this.db.prepare("SELECT COUNT(*) AS n FROM objects WHERE owner = ?").get(owner) as { n: number };
    return r.n;
  }

  unboundBytesByOwner(owner: string): bigint {
    const r = this.db.prepare("SELECT COALESCE(SUM(bytes),0) AS n FROM objects WHERE owner = ? AND referenced = 0").get(owner) as { n: bigint | number };
    return BigInt(r.n);
  }

  // ---- policies ----
  putPolicy(objectId: string, digest: string, controlSeq: bigint): void {
    this.db.prepare("INSERT INTO policies (digest, object_id, activated_control_seq) VALUES (?, ?, ?)").run(digest, objectId, controlSeq);
  }

  getPolicyByObject(objectId: string): { digest: string; object_id: string; activated_control_seq: bigint } | null {
    return (this.db.prepare("SELECT * FROM policies WHERE object_id = ?").get(objectId) as never) ?? null;
  }

  getPolicyByDigest(digest: string): { digest: string; object_id: string; activated_control_seq: bigint } | null {
    return (this.db.prepare("SELECT * FROM policies WHERE digest = ?").get(digest) as never) ?? null;
  }

  // ---- promises ----
  putPromise(p: PromiseRow): void {
    this.db.prepare(
      `INSERT INTO promises (commit_id, tenant, environment, business_id, envelope_object, envelope_hash, state, revision, payer, payee, amount, release_at, decision_by, allocation, disposition, next_due_ms, escrow_id, case_id, late_pending, consumed)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      p.commit_id, p.tenant, p.environment, p.business_id, p.envelope_object, p.envelope_hash,
      p.state, p.revision, p.payer, p.payee, p.amount, p.release_at, p.decision_by,
      p.allocation === null ? null : JSON.stringify(p.allocation), p.disposition, p.next_due_ms,
      p.escrow_id, p.case_id, p.late_pending, p.consumed,
    );
  }

  getPromise(id: string): PromiseRow | null {
    const r = this.db.prepare("SELECT * FROM promises WHERE commit_id = ?").get(id) as Record<string, unknown> | undefined;
    if (!r) return null;
    return {
      ...(r as unknown as Omit<PromiseRow, "allocation" | "revision" | "amount" | "release_at" | "decision_by" | "next_due_ms">),
      revision: BigInt(r.revision as number | bigint),
      amount: BigInt(r.amount as number | bigint),
      release_at: r.release_at === null ? null : BigInt(r.release_at as number | bigint),
      decision_by: r.decision_by === null ? null : BigInt(r.decision_by as number | bigint),
      next_due_ms: r.next_due_ms === null ? null : BigInt(r.next_due_ms as number | bigint),
      allocation: r.allocation === null ? null : (JSON.parse(r.allocation as string) as T.Allocation),
    } as PromiseRow;
  }

  getPromiseByBusiness(tenant: string, env: string, businessId: string): PromiseRow | null {
    const r = this.db.prepare("SELECT commit_id FROM promises WHERE tenant = ? AND environment = ? AND business_id = ?").get(tenant, env, businessId) as { commit_id: string } | undefined;
    return r ? this.getPromise(r.commit_id) : null;
  }

  updatePromise(id: string, fields: Partial<Record<"state" | "release_at" | "decision_by" | "disposition" | "next_due_ms" | "escrow_id" | "case_id" | "late_pending" | "consumed" | "revision", string | bigint | null | number>> & { allocation?: T.Allocation | null }): void {
    const sets: string[] = [];
    const vals: (string | bigint | number | null)[] = [];
    for (const [k, v] of Object.entries(fields)) {
      if (k === "allocation") continue;
      sets.push(`${k} = ?`);
      vals.push(v as string | bigint | number | null);
    }
    if ("allocation" in fields) {
      sets.push("allocation = ?");
      vals.push(fields.allocation == null ? null : JSON.stringify(fields.allocation));
    }
    this.db.prepare(`UPDATE promises SET ${sets.join(", ")} WHERE commit_id = ?`).run(...vals, id);
  }

  listPromises(state: string | null, principal: string | null, afterOrdinal: bigint, limit: number): PromiseRow[] {
    // Ordinal = rowid insertion order; cursor binds snapshot max ordinal + last ordinal.
    const conds: string[] = ["rowid > ?"];
    const vals: unknown[] = [afterOrdinal];
    if (state !== null) { conds.push("state = ?"); vals.push(state); }
    if (principal !== null) { conds.push("(payer = ? OR payee = ?)"); vals.push(principal, principal); }
    const rows = this.db.prepare(`SELECT commit_id FROM promises WHERE ${conds.join(" AND ")} ORDER BY rowid LIMIT ?`).all(...vals as never[]) as { commit_id: string }[];
    return rows.map((r) => this.getPromise(r.commit_id)!).slice(0, limit);
  }

  promiseOrdinal(id: string): bigint {
    const r = this.db.prepare("SELECT rowid AS o FROM promises WHERE commit_id = ?").get(id) as { o: bigint | number } | undefined;
    return BigInt(r?.o ?? 0);
  }

  maxPromiseOrdinal(): bigint {
    const r = this.db.prepare("SELECT COALESCE(MAX(rowid),0) AS o FROM promises").get() as { o: bigint | number };
    return BigInt(r.o);
  }

  duePromises(now: bigint): PromiseRow[] {
    const rows = this.db.prepare("SELECT commit_id FROM promises WHERE next_due_ms IS NOT NULL AND next_due_ms <= ? AND state IN ('PROPOSED','FUNDING','ACTIVE','RELEASE_PENDING','DISPUTED')").all(now) as { commit_id: string }[];
    return rows.map((r) => this.getPromise(r.commit_id)!);
  }

  // ---- events ----
  lastEvent(stream: string): EventRow | null {
    const r = this.db.prepare("SELECT * FROM events WHERE stream = ? ORDER BY seq DESC LIMIT 1").get(stream) as Record<string, unknown> | undefined;
    if (!r) return null;
    return { ...(r as unknown as EventRow), seq: BigInt(r.seq as number | bigint), transaction_id: BigInt(r.transaction_id as number | bigint) };
  }

  insertEvent(e: EventRow): void {
    this.db.prepare(
      "INSERT INTO events (stream, seq, prev, event_hash, canonical_body, signature, key_id, transaction_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(e.stream, e.seq, e.prev, e.event_hash, e.canonical_body, e.signature, e.key_id, e.transaction_id);
  }

  getEvent(stream: string, seq: bigint): EventRow | null {
    const r = this.db.prepare("SELECT * FROM events WHERE stream = ? AND seq = ?").get(stream, seq) as Record<string, unknown> | undefined;
    return r ? ({ ...(r as unknown as EventRow), seq: BigInt(r.seq as number | bigint), transaction_id: BigInt(r.transaction_id as number | bigint) }) : null;
  }

  listEvents(stream: string, afterSeq: bigint, limit: number): EventRow[] {
    const rows = this.db.prepare("SELECT * FROM events WHERE stream = ? AND seq > ? ORDER BY seq LIMIT ?").all(stream, afterSeq, limit) as Record<string, unknown>[];
    return rows.map((r) => ({ ...(r as unknown as EventRow), seq: BigInt(r.seq as number | bigint), transaction_id: BigInt(r.transaction_id as number | bigint) }));
  }

  allEvents(stream: string): EventRow[] {
    const rows = this.db.prepare("SELECT * FROM events WHERE stream = ? ORDER BY seq").all(stream) as Record<string, unknown>[];
    return rows.map((r) => ({ ...(r as unknown as EventRow), seq: BigInt(r.seq as number | bigint), transaction_id: BigInt(r.transaction_id as number | bigint) }));
  }

  // ---- approvals ----
  putApproval(a: { envelope_hash: string; key_id: string; approval_object: string; principal: string; accepted_seq: bigint; response: string }): void {
    this.db.prepare("INSERT INTO approvals (envelope_hash, key_id, approval_object, principal, accepted_seq, response) VALUES (?, ?, ?, ?, ?, ?)")
      .run(a.envelope_hash, a.key_id, a.approval_object, a.principal, a.accepted_seq, a.response);
  }

  getApproval(envelopeHash: string, keyId: string): { approval_object: string; principal: string; accepted_seq: bigint; response: string } | null {
    const r = this.db.prepare("SELECT * FROM approvals WHERE envelope_hash = ? AND key_id = ?").get(envelopeHash, keyId) as Record<string, unknown> | undefined;
    return r ? { approval_object: r.approval_object as string, principal: r.principal as string, accepted_seq: BigInt(r.accepted_seq as number | bigint), response: r.response as string } : null;
  }

  listApprovals(envelopeHash: string): { key_id: string; approval_object: string; principal: string }[] {
    return this.db.prepare("SELECT key_id, approval_object, principal FROM approvals WHERE envelope_hash = ? ORDER BY key_id").all(envelopeHash) as never[];
  }

  // ---- operations ----
  putOperation(o: { operation_id: string; kind: "reserve" | "allocate"; commit_id: string; canonical_request: Buffer; request_hash: string; state: T.OperationState; attempts: number }): void {
    this.db.prepare("INSERT INTO operations (operation_id, kind, commit_id, canonical_request, request_hash, state, attempts) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(o.operation_id, o.kind, o.commit_id, o.canonical_request, o.request_hash, o.state, o.attempts);
  }

  getOperation(id: string): OperationRow | null {
    const r = this.db.prepare("SELECT * FROM operations WHERE operation_id = ?").get(id) as Record<string, unknown> | undefined;
    if (!r) return null;
    return {
      ...(r as unknown as OperationRow),
      first_dispatch_ms: r.first_dispatch_ms === null ? null : BigInt(r.first_dispatch_ms as number | bigint),
      next_attempt_ms: r.next_attempt_ms === null ? null : BigInt(r.next_attempt_ms as number | bigint),
    };
  }

  getOperationFor(commitId: string, kind: "reserve" | "allocate"): OperationRow | null {
    const r = this.db.prepare("SELECT operation_id FROM operations WHERE commit_id = ? AND kind = ?").get(commitId, kind) as { operation_id: string } | undefined;
    return r ? this.getOperation(r.operation_id) : null;
  }

  latestOperation(commitId: string): OperationRow | null {
    const open = this.db.prepare(
      "SELECT operation_id FROM operations WHERE commit_id = ? AND state IN ('READY','DISPATCHED','UNKNOWN','BLOCKED') ORDER BY rowid DESC LIMIT 1",
    ).get(commitId) as { operation_id: string } | undefined;
    if (open) return this.getOperation(open.operation_id);
    const last = this.db.prepare("SELECT operation_id FROM operations WHERE commit_id = ? ORDER BY rowid DESC LIMIT 1").get(commitId) as { operation_id: string } | undefined;
    return last ? this.getOperation(last.operation_id) : null;
  }

  updateOperation(id: string, fields: Partial<Record<"state" | "attempts" | "last_provider_revision" | "last_receipt" | "first_dispatch_ms" | "next_attempt_ms", string | number | bigint | null>>): void {
    const sets = Object.keys(fields).map((k) => `${k} = ?`).join(", ");
    this.db.prepare(`UPDATE operations SET ${sets} WHERE operation_id = ?`).run(...Object.values(fields) as never[], id);
  }

  // ---- receipts ----
  putReceipt(r: ReceiptRow): void {
    this.db.prepare("INSERT INTO receipts (operation_id, provider_revision, attempt, body_hash, object_id, final, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(r.operation_id, r.provider_revision, r.attempt, r.body_hash, r.object_id, r.final, r.status);
  }

  getReceipt(opId: string, rev: string): ReceiptRow | null {
    return (this.db.prepare("SELECT * FROM receipts WHERE operation_id = ? AND provider_revision = ?").get(opId, rev) as ReceiptRow | undefined) ?? null;
  }

  latestReceipt(opId: string): ReceiptRow | null {
    const rows = this.db.prepare("SELECT * FROM receipts WHERE operation_id = ? ORDER BY CAST(provider_revision AS INTEGER) DESC LIMIT 1").all(opId) as unknown as ReceiptRow[];
    return rows[0] ?? null;
  }

  hasFinalReceipt(opId: string): ReceiptRow | null {
    return (this.db.prepare("SELECT * FROM receipts WHERE operation_id = ? AND final = 1 ORDER BY CAST(provider_revision AS INTEGER) DESC LIMIT 1").get(opId) as ReceiptRow | undefined) ?? null;
  }

  // ---- idempotency ----
  getIdempotent(principal: string, capability: string, method: string, requestId: string): { request_hash: string; canonical_response: string } | null {
    const r = this.db.prepare("SELECT request_hash, canonical_response FROM idempotency WHERE principal = ? AND capability = ? AND method = ? AND request_id = ?")
      .get(principal, capability, method, requestId) as { request_hash: string; canonical_response: string } | undefined;
    return r ?? null;
  }

  putIdempotent(principal: string, capability: string, method: string, requestId: string, requestHash: string, response: string, createdMs: bigint): void {
    this.db.prepare("INSERT INTO idempotency (principal, capability, method, request_id, request_hash, canonical_response, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(principal, capability, method, requestId, requestHash, response, createdMs);
  }

  // ---- exposure ----
  putExposure(commitId: string, amount: bigint, operationId: string | null, status: string): void {
    this.db.prepare("INSERT INTO exposure (commit_id, amount, operation_id, status) VALUES (?, ?, ?, ?)")
      .run(commitId, amount, operationId, status);
  }

  updateExposure(commitId: string, fields: { status?: string; operation_id?: string | null }): void {
    if (fields.status !== undefined) this.db.prepare("UPDATE exposure SET status = ? WHERE commit_id = ?").run(fields.status, commitId);
    if (fields.operation_id !== undefined) this.db.prepare("UPDATE exposure SET operation_id = ? WHERE commit_id = ?").run(fields.operation_id, commitId);
  }

  getExposure(commitId: string): { amount: bigint; operation_id: string | null; status: string } | null {
    const r = this.db.prepare("SELECT * FROM exposure WHERE commit_id = ?").get(commitId) as { amount: bigint | number; operation_id: string | null; status: string } | undefined;
    return r ? { amount: BigInt(r.amount), operation_id: r.operation_id, status: r.status } : null;
  }

  deleteExposure(commitId: string): void {
    this.db.prepare("DELETE FROM exposure WHERE commit_id = ?").run(commitId);
  }

  totalExposure(tenant: string, environment: string): bigint {
    const r = this.db.prepare(
      "SELECT COALESCE(SUM(e.amount),0) AS s FROM exposure e JOIN promises p ON p.commit_id = e.commit_id WHERE p.tenant = ? AND p.environment = ?",
    ).get(tenant, environment) as { s: bigint | number };
    return BigInt(r.s);
  }

  // ---- daily budget ----
  chargeDailyBudget(tenant: string, env: string, day: bigint, policyHash: string, amount: bigint): void {
    this.db.prepare(
      "INSERT INTO daily_budget (tenant, environment, utc_day, policy_hash, charged_minor) VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant, environment, utc_day, policy_hash) DO UPDATE SET charged_minor = charged_minor + excluded.charged_minor",
    ).run(tenant, env, day, policyHash, amount);
  }

  dailyBudgetCharged(tenant: string, env: string, day: bigint): bigint {
    const r = this.db.prepare("SELECT COALESCE(SUM(charged_minor),0) AS s FROM daily_budget WHERE tenant = ? AND environment = ? AND utc_day = ?")
      .get(tenant, env, day) as { s: bigint | number };
    return BigInt(r.s);
  }

  // ---- accounts / ledger ----
  getAccount(custody: string, asset: string, principal: string): { available_minor: bigint; held_minor: bigint; beneficial: number } | null {
    const r = this.db.prepare("SELECT available_minor, held_minor, beneficial FROM accounts WHERE custody = ? AND asset_code = ? AND principal = ?")
      .get(custody, asset, principal) as { available_minor: bigint | number; held_minor: bigint | number; beneficial: number } | undefined;
    return r ? { available_minor: BigInt(r.available_minor), held_minor: BigInt(r.held_minor), beneficial: r.beneficial } : null;
  }

  upsertAccount(custody: string, asset: string, principal: string, available: bigint, held: bigint, beneficial = 1): void {
    this.db.prepare(
      "INSERT INTO accounts (custody, asset_code, principal, available_minor, held_minor, beneficial) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (custody, asset_code, principal) DO UPDATE SET available_minor = excluded.available_minor, held_minor = excluded.held_minor",
    ).run(custody, asset, principal, available, held, beneficial);
  }

  allAccounts(custody: string, asset: string): { principal: string; available_minor: bigint; held_minor: bigint; beneficial: number }[] {
    const rows = this.db.prepare("SELECT principal, available_minor, held_minor, beneficial FROM accounts WHERE custody = ? AND asset_code = ? ORDER BY principal")
      .all(custody, asset) as { principal: string; available_minor: bigint | number; held_minor: bigint | number; beneficial: number }[];
    return rows.map((r) => ({ principal: r.principal, available_minor: BigInt(r.available_minor), held_minor: BigInt(r.held_minor), beneficial: r.beneficial }));
  }

  insertLedgerTransaction(causeStream: string, causeSeq: bigint, lines: { account: string; asset_code: string; side: "DEBIT" | "CREDIT"; amount_minor: bigint; commit_id: string | null }[]): bigint {
    let debit = 0n; let credit = 0n;
    for (const l of lines) (l.side === "DEBIT" ? (debit += l.amount_minor) : (credit += l.amount_minor));
    if (debit !== credit) throw new Error("ledger transaction unbalanced");
    const info = this.db.prepare("INSERT INTO ledger_transactions (cause_stream, cause_seq, total_debit, total_credit, asset_code) VALUES (?, ?, ?, ?, ?)")
      .run(causeStream, causeSeq, debit, credit, lines[0]?.asset_code ?? "");
    const txid = BigInt(info.lastInsertRowid);
    lines.forEach((l, i) => {
      this.db.prepare("INSERT INTO ledger_journal (transaction_id, line_no, account, asset_code, side, amount_minor, commit_id, cause_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .run(txid, i + 1, l.account, l.asset_code, l.side, l.amount_minor, l.commit_id, causeSeq);
    });
    return txid;
  }

  journalSums(causeStream: string, causeSeq: bigint): { debits: bigint; credits: bigint } {
    const r = this.db.prepare(
      "SELECT COALESCE(SUM(CASE WHEN side='DEBIT' THEN amount_minor END),0) AS d, COALESCE(SUM(CASE WHEN side='CREDIT' THEN amount_minor END),0) AS c FROM ledger_journal j JOIN ledger_transactions t ON t.transaction_id = j.transaction_id WHERE t.cause_stream = ? AND j.cause_seq = ?",
    ).get(causeStream, causeSeq) as { d: bigint | number; c: bigint | number };
    return { debits: BigInt(r.d), credits: BigInt(r.c) };
  }

  // ---- outbox ----
  putOutbox(operationId: string, payloadDigest: string, state: string, leaseEpoch: bigint, nextAttemptMs: bigint | null): void {
    this.db.prepare("INSERT INTO outbox (operation_id, payload_digest, state, lease_epoch, next_attempt_ms) VALUES (?, ?, ?, ?, ?)")
      .run(operationId, payloadDigest, state, leaseEpoch, nextAttemptMs);
  }

  updateOutbox(operationId: string, state: string, nextAttemptMs: bigint | null): void {
    this.db.prepare("UPDATE outbox SET state = ?, next_attempt_ms = ? WHERE operation_id = ?").run(state, nextAttemptMs, operationId);
  }

  deleteOutbox(operationId: string): void {
    this.db.prepare("DELETE FROM outbox WHERE operation_id = ?").run(operationId);
  }

  readyOutbox(now: bigint): { operation_id: string }[] {
    return this.db.prepare("SELECT operation_id FROM outbox WHERE state = 'READY' AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?)").all(now) as never[];
  }

  getOutbox(operationId: string): { state: string; payload_digest: string; lease_epoch: bigint; next_attempt_ms: bigint | null } | null {
    const r = this.db.prepare("SELECT state, payload_digest, lease_epoch, next_attempt_ms FROM outbox WHERE operation_id = ?").get(operationId) as Record<string, unknown> | undefined;
    return r ? { state: r.state as string, payload_digest: r.payload_digest as string, lease_epoch: BigInt(r.lease_epoch as number | bigint), next_attempt_ms: r.next_attempt_ms === null ? null : BigInt(r.next_attempt_ms as number | bigint) } : null;
  }

  // ---- audit outbox ----
  putAuditDelivery(deliveryId: string, stream: string, throughSeq: bigint, checkpointDigest: string): void {
    this.db.prepare("INSERT INTO audit_outbox (delivery_id, stream, through_seq, checkpoint_digest, state, attempts) VALUES (?, ?, ?, ?, 'PENDING', 0)")
      .run(deliveryId, stream, throughSeq, checkpointDigest);
  }

  pendingAuditDeliveries(): { delivery_id: string; stream: string; through_seq: bigint; checkpoint_digest: string; attempts: number }[] {
    const rows = this.db.prepare("SELECT * FROM audit_outbox WHERE state = 'PENDING'").all() as Record<string, unknown>[];
    return rows.map((r) => ({ delivery_id: r.delivery_id as string, stream: r.stream as string, through_seq: BigInt(r.through_seq as number | bigint), checkpoint_digest: r.checkpoint_digest as string, attempts: r.attempts as number }));
  }

  markAuditDelivered(deliveryId: string): void {
    this.db.prepare("UPDATE audit_outbox SET state = 'STORED' WHERE delivery_id = ?").run(deliveryId);
  }

  bumpAuditAttempt(deliveryId: string): void {
    this.db.prepare("UPDATE audit_outbox SET attempts = attempts + 1 WHERE delivery_id = ?").run(deliveryId);
  }

  // ---- security incidents ----
  putIncident(incidentId: string, code: string, evidenceDigest: string, observedMs: bigint): void {
    this.db.prepare("INSERT INTO security_incidents (incident_id, code, redacted_evidence_digest, observed_ms) VALUES (?, ?, ?, ?)")
      .run(incidentId, code, evidenceDigest, observedMs);
  }

  // ---- checkpoints ----
  putCheckpoint(stream: string, seq: bigint, head: string, authorityHead: string, ledgerRoot: string, objectId: string | null): void {
    this.db.prepare("INSERT INTO checkpoints (stream, seq, head, authority_head, ledger_root, object_id) VALUES (?, ?, ?, ?, ?, ?)")
      .run(stream, seq, head, authorityHead, ledgerRoot, objectId);
  }

  getCheckpoint(stream: string, seq: bigint): { head: string; authority_head: string; ledger_root: string; object_id: string | null } | null {
    return (this.db.prepare("SELECT head, authority_head, ledger_root, object_id FROM checkpoints WHERE stream = ? AND seq = ?").get(stream, seq) as never) ?? null;
  }

  latestCheckpoint(stream: string): { seq: bigint; head: string } | null {
    const r = this.db.prepare("SELECT seq, head FROM checkpoints WHERE stream = ? ORDER BY seq DESC LIMIT 1").get(stream) as { seq: bigint | number; head: string } | undefined;
    return r ? { seq: BigInt(r.seq), head: r.head } : null;
  }

  // ---- control ----
  putControlNonce(nonce: string): void {
    this.db.prepare("INSERT INTO control_nonces (nonce) VALUES (?)").run(nonce);
  }

  hasControlNonce(nonce: string): boolean {
    return this.db.prepare("SELECT nonce FROM control_nonces WHERE nonce = ?").get(nonce) !== undefined;
  }

  revokeKey(keyId: string, controlSeq: bigint): void {
    this.db.prepare("INSERT OR IGNORE INTO revoked_keys (key_id, control_seq) VALUES (?, ?)").run(keyId, controlSeq);
  }

  isKeyRevoked(keyId: string): boolean {
    return this.db.prepare("SELECT key_id FROM revoked_keys WHERE key_id = ?").get(keyId) !== undefined;
  }

  revokedKeys(): string[] {
    return (this.db.prepare("SELECT key_id FROM revoked_keys ORDER BY key_id").all() as { key_id: string }[]).map((r) => r.key_id);
  }

  // ---- cursors ----
  putCursor(id: string, payload: string, expiresMs: bigint): void {
    this.db.prepare("INSERT INTO cursors (cursor_id, payload, expires_ms) VALUES (?, ?, ?)").run(id, payload, expiresMs);
  }

  getCursor(id: string): { payload: string; expires_ms: bigint } | null {
    const r = this.db.prepare("SELECT payload, expires_ms FROM cursors WHERE cursor_id = ?").get(id) as { payload: string; expires_ms: bigint | number } | undefined;
    return r ? { payload: r.payload, expires_ms: BigInt(r.expires_ms) } : null;
  }

  /** Global monotone counter (serializes shared budgets/accounts across promises). */
  bumpCounter(name: string): bigint {
    this.db.prepare("INSERT INTO counters (name, value) VALUES (?, 1) ON CONFLICT (name) DO UPDATE SET value = value + 1").run(name);
    const r = this.db.prepare("SELECT value FROM counters WHERE name = ?").get(name) as { value: bigint | number };
    return BigInt(r.value);
  }

  counter(name: string): bigint {
    const r = this.db.prepare("SELECT value FROM counters WHERE name = ?").get(name) as { value: bigint | number } | undefined;
    return BigInt(r?.value ?? 0);
  }
}

// ---------- object file persistence (§6.1) ----------

/** Fsync temp-file → atomic rename → parent-dir fsync. */
export function writeObjectFile(objectsDir: string, digest: string, plaintext: Buffer): string {
  const sub = join(objectsDir, "sha256", digest.slice(0, 2));
  mkdirSync(sub, { recursive: true, mode: 0o700 });
  const final = join(sub, digest);
  if (existsSync(final)) return final;
  const tmp = join(sub, `.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`);
  writeFileSync(tmp, plaintext, { mode: 0o600 });
  const fd = openSync(tmp, "r");
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, final);
  const dfd = openSync(sub, "r");
  try { fsyncSync(dfd); } finally { closeSync(dfd); }
  return final;
}

export function objectFileDigestCheck(path: string): string {
  return H(path);
}
