// Offline store operations (§6.4, §10.1): verify, backup, migrate plan/apply.
// All run against a stopped store; none require the coordinator to be live.

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { D, edVerify, H } from "./crypto.ts";
import { err } from "./errors.ts";
import { jcsBytes } from "./json/jcs.ts";
import { parseStrictJson, type Json } from "./json/strict.ts";
import { validMigration, validTrustPin } from "./schema.ts";
import { Store } from "./store.ts";
import type * as T from "./types.ts";

export interface StoreVerifyResult {
  integrity: "verified" | "invalid" | "incomplete";
  projection_match: boolean;
  head: string;
  codes: string[];
}

/** Recompute projection state by folding promise + account tables. */
function projectionRoot(store: Store): string {
  const promises = store.db.prepare(
    "SELECT commit_id, state, revision, payer, payee, amount, disposition, allocation FROM promises ORDER BY commit_id",
  ).all() as Record<string, unknown>[];
  const accounts = store.db.prepare(
    "SELECT custody, asset_code, principal, available_minor, held_minor, beneficial FROM accounts ORDER BY custody, asset_code, principal",
  ).all() as Record<string, unknown>[];
  const ops = store.db.prepare(
    "SELECT operation_id, kind, commit_id, state, attempts, request_hash FROM operations ORDER BY operation_id",
  ).all() as Record<string, unknown>[];
  const norm = (rows: Record<string, unknown>[]) => rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, typeof v === "bigint" ? String(v) : v])));
  return H(jcsBytes({ promises: norm(promises), accounts: norm(accounts), operations: norm(ops) } as unknown as Json));
}

/** Full offline log/accounting check: chain integrity + journal conservation + pin compare. */
export function storeVerify(storeDir: string, trustRaw: unknown): StoreVerifyResult {
  const trust = validTrustPin(trustRaw);
  const store = new Store(join(storeDir, "store.db"), storeDir);
  try {
    // event chain: seq contiguity, prev links, hash recomputation, writer signature
    const streams = store.db.prepare("SELECT DISTINCT stream FROM events ORDER BY stream").all() as { stream: string }[];
    let integrity: StoreVerifyResult["integrity"] = "verified";
    const codes = new Set<string>();
    let head = "0".repeat(64);
    for (const { stream } of streams) {
      const evs = store.allEvents(stream);
      let prev = "0".repeat(64);
      for (let i = 0; i < evs.length; i++) {
        const ev = evs[i]!;
        const body = parseStrictJson(Buffer.from(ev.canonical_body as unknown as Uint8Array).toString("utf8")) as unknown as T.EventBody;
        if (BigInt(ev.seq) !== BigInt(i + 1) || ev.prev !== prev) { integrity = "invalid"; codes.add("CHAIN_GAP"); }
        if (D("event", body as unknown as Json) !== ev.event_hash) { integrity = "invalid"; codes.add("EVENT_HASH_MISMATCH"); }
        if (!edVerify("event", body as unknown as Json, trust.writer_key, ev.signature)) { integrity = "invalid"; codes.add("SIGNATURE_INVALID"); }
        prev = ev.event_hash;
      }
      if (evs.length && stream !== "control") head = evs[evs.length - 1]!.event_hash;
    }
    // journal conservation: every ledger transaction is balanced
    const unbalanced = store.db.prepare("SELECT COUNT(*) AS n FROM ledger_transactions WHERE total_debit <> total_credit").get() as { n: bigint | number };
    if (BigInt(unbalanced.n) !== 0n) { integrity = "invalid"; codes.add("ALLOCATION_INVALID"); }
    // accounts nonnegative
    const neg = store.db.prepare("SELECT COUNT(*) AS n FROM accounts WHERE available_minor < 0 OR held_minor < 0").get() as { n: bigint | number };
    if (BigInt(neg.n) !== 0n) { integrity = "invalid"; codes.add("ALLOCATION_INVALID"); }
    // pin compare
    if (trust.minimum_checkpoint) {
      const pin = trust.minimum_checkpoint;
      const evs = store.allEvents(pin.body.stream);
      const headSeq = evs.length ? BigInt(evs[evs.length - 1]!.seq) : 0n;
      if (headSeq < BigInt(pin.body.seq)) {
        integrity = "incomplete"; codes.add("PIN_AHEAD"); // supplied history ends before the pin
      } else if (pin.body.stream !== "control") {
        const at = evs[Number(pin.body.seq) - 1];
        if (at && at.event_hash !== pin.body.head) { integrity = "invalid"; codes.add("PIN_MISMATCH"); }
      }
    }
    return { integrity, projection_match: integrity !== "invalid", head, codes: [...codes].sort() };
  } finally {
    store.close();
  }
}

/** Consistent backup: WAL checkpoint then file copy + object manifest + head checkpoint. */
export function storeBackup(storeDir: string, outDir: string): { backup_digest: string; source_head: string } {
  if (existsSync(outDir)) throw err("OBJECT_CONFLICT", "backup output directory already exists");
  const store = new Store(join(storeDir, "store.db"), storeDir);
  try {
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    mkdirSync(outDir, { recursive: true, mode: 0o700 });
    copyFileSync(join(storeDir, "store.db"), join(outDir, "store.db"));
    const objects = store.db.prepare("SELECT object_id, kind, digest FROM objects ORDER BY object_id").all() as { object_id: string; kind: string; digest: string }[];
    const manifestRows = objects.map((o) => jcsBytes({ id: o.object_id, kind: o.kind, digest: o.digest } as unknown as Json).toString("utf8"));
    writeFileSync(join(outDir, "objects.manifest"), manifestRows.join("\n") + (manifestRows.length ? "\n" : ""), { mode: 0o600 });
    const heads = store.db.prepare("SELECT stream, MAX(seq) AS seq FROM events GROUP BY stream").all() as { stream: string; seq: bigint | number }[];
    const headMap: Record<string, { seq: string; head: string }> = {};
    for (const h of heads) {
      const ev = store.getEvent(h.stream, BigInt(h.seq));
      if (ev) headMap[h.stream] = { seq: String(ev.seq), head: ev.event_hash };
    }
    writeFileSync(join(outDir, "heads.json"), JSON.stringify(headMap), { mode: 0o600 });
    const digest = H(Buffer.concat([
      jcsBytes(headMap as unknown as Json), Buffer.from(manifestRows.join("\n")),
    ]));
    const main = heads.filter((h) => h.stream !== "control").sort((a, b) => a.stream < b.stream ? -1 : 1)[0];
    return { backup_digest: digest, source_head: headMap[main?.stream ?? ""]?.head ?? "0".repeat(64) };
  } finally {
    store.close();
  }
}

/** Migration plan (§10.1): immutable Migration + computed projection root; store unchanged. */
export function migratePlan(opts: {
  storeDir: string; targetStorage: number; binaryDigest: string; transformDigest: string;
  backupDigest: string; writerEpoch: bigint; outFile: string;
}): T.Migration {
  const store = new Store(join(opts.storeDir, "store.db"), opts.storeDir);
  try {
    const heads = store.db.prepare("SELECT stream, MAX(seq) AS seq FROM events GROUP BY stream").all() as { stream: string; seq: bigint | number }[];
    const main = heads.filter((h) => h.stream !== "control").sort((a, b) => a.stream < b.stream ? -1 : 1)[0];
    const head = main ? store.getEvent(main.stream, BigInt(main.seq))!.event_hash : "0".repeat(64);
    const migration: T.Migration = {
      v: 1, from_storage: 1, to_storage: opts.targetStorage, source_head: head,
      binary_digest: opts.binaryDigest, transform_digest: opts.transformDigest,
      expected_projection_root: projectionRoot(store), backup_digest: opts.backupDigest,
      writer_epoch: String(opts.writerEpoch),
    };
    writeFileSync(opts.outFile, jcsBytes(migration as unknown as Json).toString("utf8") + "\n", { mode: 0o600 });
    return migration;
  } finally {
    store.close();
  }
}

/** Migration apply: quorum-signed Migration over kind `migration`; identity transform in v1. */
export function migrateApply(opts: {
  storeDir: string; migration: T.Migration; signatures: { key_id: string; sig: string }[];
}): { from_storage: number; to_storage: number; head: string } {
  const store = new Store(join(opts.storeDir, "store.db"), opts.storeDir);
  try {
    const meta = store.getMeta()!;
    const polRow = store.getObject(meta.active_policy);
    if (!polRow || polRow.kind !== "policy") throw err("STORAGE_UNAVAILABLE", "active policy missing");
    const policy = polRow.body as T.Policy;
    const members = new Map(policy.members.map((m) => [m.key_id, m]));
    const principals = new Set<string>();
    for (const s of opts.signatures) {
      const m = members.get(s.key_id);
      if (!m || !policy.control.keys.includes(s.key_id) ||
          !edVerify("migration", opts.migration as unknown as Json, m.public_key, s.sig)) {
        throw err("SIGNATURE_INVALID", "migration signature invalid");
      }
      principals.add(m.principal);
    }
    const q = policy.control;
    if (principals.size < q.threshold || !q.mandatory_principals.every((mp) => principals.has(mp))) {
      throw err("QUORUM_MISSING", "migration lacks the bootstrap control quorum");
    }
    if (opts.migration.to_storage !== 1) {
      throw err("UNSUPPORTED_VERSION", "only storage version 1 exists in this edition; no transform available");
    }
    // verify source head unchanged since planning
    const heads = store.db.prepare("SELECT stream, MAX(seq) AS seq FROM events GROUP BY stream").all() as { stream: string; seq: bigint | number }[];
    const main = heads.filter((h) => h.stream !== "control").sort((a, b) => a.stream < b.stream ? -1 : 1)[0];
    const head = main ? store.getEvent(main.stream, BigInt(main.seq))!.event_hash : "0".repeat(64);
    if (head !== opts.migration.source_head) {
      throw err("CONTROL_STALE", "source head changed since the migration was planned");
    }
    if (projectionRoot(store) !== opts.migration.expected_projection_root) {
      throw err("CUSTODY_CONFLICT", "projection root differs from the approved plan");
    }
    return { from_storage: opts.migration.from_storage, to_storage: opts.migration.to_storage, head };
  } finally {
    store.close();
  }
}

export function readMigrationFile(path: string): T.Migration {
  return validMigration(parseStrictJson(readFileSync(path)));
}
