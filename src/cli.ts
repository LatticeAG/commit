// `commit` CLI (§4). One canonical JSON value + newline on stdout in --json
// mode; diagnostics on stderr; exit codes per the §4 family table.

import { existsSync, mkdirSync, openSync, readFileSync, readdirSync, readSync, closeSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import crypto from "node:crypto";
import { D, generateKeypair, publicKeyFromSeed } from "./crypto.ts";
import { err, exitCodeFor, isCommitError, NotImplementedSurface } from "./errors.ts";
import { jcs, jcsBytes } from "./json/jcs.ts";
import { checkArtifactBounds, parseStrictJson, type Json } from "./json/strict.ts";
import { objectBytes, registryDigest } from "./objects.ts";
import { isId } from "./scalars.ts";
import {
  validCustodyManifest, validObjectBody, validTrustPin, validAsset,
} from "./schema.ts";
import { loadConfig, parseConfig, parseToml } from "./config.ts";
import { initStore, loadGenesisArtifacts } from "./genesis.ts";
import { verifyBundle } from "./proof.ts";
import { signBody } from "./sign.ts";
import { migrateApply, migratePlan, readMigrationFile, storeBackup, storeVerify } from "./migrate.ts";
import { rpcCall } from "./server.ts";
import { decodeBase64urlCanonical } from "./scalars.ts";
import { OBJECT_KINDS } from "./types.ts";
import type * as T from "./types.ts";

const VERSION = "1.0.0";
const DEFAULT_CONFIG = "/etc/latticeagi/commit.toml";

interface Flags { [k: string]: string | boolean | undefined }

function parseArgs(argv: string[]): { flags: Flags; rest: string[] } {
  const flags: Flags = {};
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq >= 0) { flags[a.slice(2, eq)] = a.slice(eq + 1); continue; }
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--") && !isBoolFlag(name)) { flags[name] = next; i++; }
      else flags[name] = true;
    } else rest.push(a);
  }
  return { flags, rest };
}

const BOOL_FLAGS = new Set(["json", "help", "version", "replace-output"]);
function isBoolFlag(n: string): boolean { return BOOL_FLAGS.has(n); }

function fstr(flags: Flags, name: string): string | undefined {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

function req(flags: Flags, name: string): string {
  const v = fstr(flags, name);
  if (v === undefined) throw err("SCHEMA_INVALID", `missing required flag --${name}`);
  return v;
}

function reqId(flags: Flags, name: string): string {
  const v = req(flags, name);
  if (!isId(v)) throw err("SCHEMA_INVALID", `--${name} is not a valid Id`);
  return v;
}

function timeoutMs(flags: Flags): number {
  const v = fstr(flags, "timeout-ms");
  if (v === undefined) return 10000;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 300000) throw err("SCHEMA_INVALID", "--timeout-ms must be in 1..300000");
  return n;
}

function print(v: unknown, json: boolean): void {
  if (json) {
    process.stdout.write(jcs(v as Json) + "\n");
  } else {
    process.stdout.write(JSON.stringify(v, null, 2) + "\n");
  }
}

function readJsonFile(path: string): Json {
  let raw: Buffer;
  try { raw = readFileSync(path); } catch { throw err("STORAGE_UNAVAILABLE", `cannot read ${path}`); }
  const v = parseStrictJson(raw);
  checkArtifactBounds(v);
  return v;
}

function socketPath(flags: Flags): string {
  const explicit = fstr(flags, "socket");
  if (explicit) return explicit;
  const cfgPath = fstr(flags, "config") ?? process.env.COMMIT_CONFIG ?? DEFAULT_CONFIG;
  try {
    const cfg = loadConfig(cfgPath);
    return cfg.listen.slice("unix:".length);
  } catch {
    throw err("SCHEMA_INVALID", `no --socket and config ${cfgPath} unreadable`);
  }
}

async function rpc(flags: Flags, method: T.Method, params: Json, mutation: boolean): Promise<unknown> {
  const requestId = fstr(flags, "request-id");
  if (mutation && requestId === undefined) throw err("SCHEMA_INVALID", `mutation ${method} requires --request-id`);
  const capability = fstr(flags, "cap");
  if (capability === undefined) throw err("SCHEMA_INVALID", "missing --cap (capability id)");
  const req: T.Request = {
    v: 1,
    request_id: requestId ?? `req_${crypto.randomBytes(8).toString("hex")}`,
    capability: capability as T.Id,
    method, params,
  };
  const res = await rpcCall(socketPath(flags), req, { timeoutMs: timeoutMs(flags) });
  if (!res.ok) {
    const e = res.error;
    throw err(e.code, e.message, { retryable: e.retryable, currentRevision: e.current_revision });
  }
  return res.result;
}

function expectedRevision(flags: Flags): string {
  const v = req(flags, "expected-revision");
  if (!/^(0|[1-9][0-9]*)$/.test(v)) throw err("SCHEMA_INVALID", "--expected-revision must be a U64 string");
  return v;
}

function writeExclusive(path: string, data: Buffer, replace: boolean): void {
  if (existsSync(path)) {
    if (!replace) throw err("OBJECT_CONFLICT", `output ${path} exists; pass --replace-output to overwrite a file`);
    if (!statSync(path).isFile()) throw err("OBJECT_CONFLICT", "output path is not a regular file");
  }
  const fd = openSync(path, replace ? "w" : "wx", 0o600);
  try { writeFileSync(fd, data); } finally { closeSync(fd); }
}

function newDir(path: string): void {
  if (existsSync(path)) throw err("OBJECT_CONFLICT", `output directory ${path} already exists`);
  mkdirSync(path, { recursive: true, mode: 0o700 });
}

// ---------- offline commands ----------

function cmdCanonicalize(flags: Flags): unknown {
  const kind = req(flags, "kind");
  const file = req(flags, "file");
  const raw = readJsonFile(file);
  if (kind === "custody_manifest") {
    const body = validCustodyManifest(raw);
    return { kind, digest: D("custody_manifest", body as unknown as Json), bytes: jcsBytes(body as unknown as Json).length };
  }
  if (!OBJECT_KINDS.includes(kind as T.ObjectKind)) throw err("SCHEMA_INVALID", `kind ${kind} is not a registered structured kind`);
  const body = validObjectBody(kind as T.ObjectKind, raw);
  return { kind, digest: registryDigest(kind as T.ObjectKind, body), bytes: objectBytes(kind as T.ObjectKind, body) };
}

function cmdKeygen(flags: Flags): unknown {
  const dir = req(flags, "out");
  newDir(dir);
  const kp = generateKeypair();
  writeFileSync(join(dir, "secret.key"), kp.secretKeyHex + "\n", { mode: 0o600 });
  writeFileSync(join(dir, "public.key"), kp.publicKeyHex + "\n", { mode: 0o600 });
  return { public_key: kp.publicKeyHex };
}

function cmdSign(flags: Flags): unknown {
  const kind = req(flags, "kind");
  const bodyFile = req(flags, "body-file");
  const keyFd = req(flags, "key-fd");
  const keyId = reqId(flags, "key-id");
  const journalDir = req(flags, "journal-dir");
  const outPath = req(flags, "out");
  const fd = Number(keyFd);
  if (!Number.isInteger(fd) || fd < 0) throw err("SCHEMA_INVALID", "--key-fd must be a file descriptor number");
  let seedRaw: Buffer;
  try {
    seedRaw = Buffer.alloc(64);
    const n = readSync(fd, seedRaw, 0, 64, null);
    closeSync(fd);
    seedRaw = seedRaw.subarray(0, n);
  } catch {
    throw err("UNAUTHENTICATED", "key fd unreadable");
  }
  const hex = seedRaw.toString("utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw err("UNAUTHENTICATED", "key material must be 64 lowercase hex chars");
  // fixture-key refusal: deterministic public seeds must never sign live bodies
  const body = readJsonFile(bodyFile);
  const sig = signBody({ kind, bodyRaw: body, keyId, seed: Buffer.from(hex, "hex"), journalDir });
  writeExclusive(outPath, Buffer.from(jcs(sig as unknown as Json) + "\n"), flags["replace-output"] === true);
  return sig;
}

function cmdInit(flags: Flags): unknown {
  const cfgPath = req(flags, "config");
  const policyFile = req(flags, "policy-file");
  const trustFile = req(flags, "trust-file");
  const custodyFile = req(flags, "custody-manifest");
  const outDir = req(flags, "out");
  const cfg = loadConfig(cfgPath);
  const { policy, trust, custody } = loadGenesisArtifacts({ policyFile, trustFile, custodyManifestFile: custodyFile });
  if (cfg.mode === "live") {
    throw new NotImplementedSurface("live initialization", "live pilot requires Covenant v1 plus P0–P6 gates");
  }
  const writerSeed = (() => {
    const ref = cfg.writer_key_ref;
    if (ref.startsWith("file:")) return Buffer.from(readFileSync(ref.slice(5), "utf8").trim(), "hex");
    throw err("SCHEMA_INVALID", "init requires writer_key_ref = file:<path> (fd refs are for serve)");
  })();
  // sim-ledger/1 holds the receipt key locally; the operator provisions it via
  // `commit keygen` before pinning the manifest, and init consumes the same seed.
  const receiptSeed = (() => {
    if (custody.profile !== "sim-ledger/1") return undefined;
    const p = fstr(flags, "receipt-key-file");
    if (p === undefined) {
      throw err("SCHEMA_INVALID", "sim-ledger/1 requires --receipt-key-file (a `commit keygen` seed whose public key is pinned in the custody manifest)");
    }
    const hex = readFileSync(p, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw err("UNAUTHENTICATED", "receipt key file must contain 64 lowercase hex chars");
    return Buffer.from(hex, "hex");
  })();
  const r = initStore({
    storeDir: outDir, policy, policyObjectId: cfg.policy_object, trust, custody,
    writerPublicKey: publicKeyFromSeed(writerSeed), writerEpoch: cfg.writer_epoch,
    receiptSeed, mode: cfg.mode, simAccounts: cfg.sim_accounts, nowMs: BigInt(Date.now()),
  });
  return r;
}

function cmdStoreVerify(flags: Flags): unknown {
  const storeDir = req(flags, "store");
  const trustFile = req(flags, "trust-file");
  const trust = validTrustPin(readJsonFile(trustFile));
  return storeVerify(storeDir, trust);
}

function cmdStoreBackup(flags: Flags): unknown {
  const storeDir = req(flags, "store");
  const outDir = req(flags, "out");
  return storeBackup(storeDir, outDir);
}

function cmdMigratePlan(flags: Flags): unknown {
  const storeDir = req(flags, "store");
  const target = Number(req(flags, "target-storage"));
  if (!Number.isInteger(target) || target < 1) throw err("SCHEMA_INVALID", "--target-storage must be a positive integer");
  const binaryDigest = req(flags, "binary-digest");
  if (!/^[0-9a-f]{64}$/.test(binaryDigest)) throw err("SCHEMA_INVALID", "--binary-digest must be 64 lowercase hex");
  const outFile = req(flags, "out");
  const backup = storeBackup(storeDir, join(outFile + ".backup-tmp"));
  const m = migratePlan({
    storeDir, targetStorage: target, binaryDigest, transformDigest: binaryDigest,
    backupDigest: backup.backup_digest, writerEpoch: 1n, outFile,
  });
  return m;
}

function cmdMigrateApply(flags: Flags): unknown {
  const storeDir = req(flags, "store");
  const migrationFile = req(flags, "migration-file");
  const approvalFile = req(flags, "approval-file");
  const migration = readMigrationFile(migrationFile);
  const sigs = readJsonFile(approvalFile);
  if (!Array.isArray(sigs)) throw err("SCHEMA_INVALID", "approval file must be a Signature[] array");
  return migrateApply({ storeDir, migration, signatures: sigs as { key_id: string; sig: string }[] });
}

function cmdVerify(flags: Flags): unknown {
  const bundleDir = req(flags, "bundle-dir");
  const trustFile = req(flags, "trust-file");
  const trust = validTrustPin(readJsonFile(trustFile));
  const manifestRaw = readJsonFile(join(bundleDir, "manifest.json")) as { body?: unknown };
  const manifest = manifestRaw.body ?? manifestRaw;
  const objectsDir = join(bundleDir, "objects");
  const rows: { id: string; kind: string; body: unknown }[] = [];
  if (existsSync(objectsDir)) {
    for (const f of readdirSyncSorted(objectsDir)) {
      if (!f.endsWith(".json")) continue;
      const v = readJsonFile(join(objectsDir, f)) as { id?: string; kind?: string; body?: unknown };
      rows.push({ id: v.id ?? f.slice(0, -5), kind: v.kind ?? "", body: v.body ?? v });
    }
  }
  return verifyBundle(manifest, rows, trust, {});
}

function readdirSyncSorted(dir: string): string[] {
  return readdirSync(dir).sort();
}

// ---------- online commands ----------

async function cmdObjectPut(flags: Flags): Promise<unknown> {
  const id = reqId(flags, "id");
  const kind = req(flags, "kind");
  const body = readJsonFile(req(flags, "file"));
  return rpc(flags, "object.put", { object: id, kind, body } as Json, true);
}

async function cmdObjectGet(flags: Flags): Promise<unknown> {
  return rpc(flags, "object.get", { object: reqId(flags, "id") } as Json, false);
}

async function cmdPropose(flags: Flags): Promise<unknown> {
  return rpc(flags, "promise.propose", { envelope: reqId(flags, "envelope-object") } as Json, true);
}

async function cmdShow(flags: Flags): Promise<unknown> {
  return rpc(flags, "promise.get", { commit_id: reqId(flags, "id") } as Json, false);
}

async function cmdList(flags: Flags): Promise<unknown> {
  const limit = Number(req(flags, "limit"));
  if (!Number.isInteger(limit) || limit < 1) throw err("SCHEMA_INVALID", "--limit must be a positive integer");
  const state = fstr(flags, "state") ?? null;
  const cursor = fstr(flags, "cursor") ?? null;
  return rpc(flags, "promise.list", { state, cursor, limit } as unknown as Json, false);
}

async function cmdApprove(flags: Flags): Promise<unknown> {
  return rpc(flags, "approval.submit", {
    commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags), approval: reqId(flags, "approval-object"),
  } as Json, true);
}

async function cmdExecute(flags: Flags): Promise<unknown> {
  return rpc(flags, "promise.commit", { commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags) } as Json, true);
}

async function cmdCancel(flags: Flags): Promise<unknown> {
  return rpc(flags, "promise.cancel", { commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags) } as Json, true);
}

async function cmdSatisfy(flags: Flags): Promise<unknown> {
  return rpc(flags, "condition.submit", {
    commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags), evidence: reqId(flags, "evidence-object"),
  } as Json, true);
}

async function cmdDisputeOpen(flags: Flags): Promise<unknown> {
  const evidenceRef = readJsonFile(req(flags, "evidence-ref"));
  const reason = req(flags, "reason");
  return rpc(flags, "dispute.open", {
    commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags),
    case_id: reqId(flags, "case"), reason, evidence: evidenceRef,
  } as Json, true);
}

async function cmdDisputeResolve(flags: Flags): Promise<unknown> {
  return rpc(flags, "dispute.resolve", {
    commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags), award: reqId(flags, "award-object"),
  } as Json, true);
}

async function cmdAdvance(flags: Flags): Promise<unknown> {
  return rpc(flags, "promise.advance", { commit_id: reqId(flags, "id"), expected_revision: expectedRevision(flags) } as Json, true);
}

async function cmdCustodyReconcile(flags: Flags): Promise<unknown> {
  const receipt = fstr(flags, "receipt-object");
  return rpc(flags, "custody.reconcile", {
    operation_id: reqId(flags, "operation"), receipt: receipt === undefined ? null : receipt,
  } as Json, true);
}

async function cmdCustodyRetry(flags: Flags): Promise<unknown> {
  return rpc(flags, "custody.retry", {
    operation_id: reqId(flags, "operation"), no_effect_receipt: reqId(flags, "no-effect-receipt"),
  } as Json, true);
}

async function cmdAccount(flags: Flags): Promise<unknown> {
  const asset = validAsset(readJsonFile(req(flags, "asset-file")));
  return rpc(flags, "account.get", { principal: reqId(flags, "principal"), asset } as unknown as Json, false);
}

async function cmdEvents(flags: Flags): Promise<unknown> {
  const after = req(flags, "after");
  if (!/^(0|[1-9][0-9]*)$/.test(after)) throw err("SCHEMA_INVALID", "--after must be a U64 string");
  const limit = Number(req(flags, "limit"));
  if (!Number.isInteger(limit) || limit < 1) throw err("SCHEMA_INVALID", "--limit must be a positive integer");
  return rpc(flags, "event.list", { commit_id: reqId(flags, "id"), after_seq: after, limit } as Json, false);
}

async function cmdExport(flags: Flags): Promise<unknown> {
  const commitId = reqId(flags, "id");
  const disclosure = req(flags, "disclosure");
  if (disclosure !== "full" && disclosure !== "redacted") throw err("SCHEMA_INVALID", "--disclosure must be full|redacted");
  const outDir = req(flags, "out");
  let cursor: string | null = fstr(flags, "cursor") ?? null;
  newDir(outDir);
  mkdirSync(join(outDir, "objects"), { recursive: true, mode: 0o700 });
  let last: T.ExportResult | null = null;
  do {
    const r = await rpc(flags, "proof.export", { commit_id: commitId, disclosure, cursor } as unknown as Json, true) as T.ExportResult;
    last = r;
    cursor = r.next_cursor;
    // fetch chunk object and write raw bundle rows + manifest
    const chunkObj = await rpc(flags, "object.get", { object: r.chunk.object } as Json, false) as { body: T.BlobObject };
    const raw = decodeBase64urlCanonical(chunkObj.body.data);
    const lines = raw.toString("utf8").split("\n").filter((l) => l.length > 0);
    for (const line of lines) {
      const row = JSON.parse(line) as { id: string; kind: string; body: unknown };
      if (row.kind === "manifest") writeFileSync(join(outDir, "manifest.json"), line + "\n", { mode: 0o600 });
      else writeFileSync(join(outDir, "objects", `${row.id}.json`), line + "\n", { mode: 0o600 });
    }
  } while (cursor !== null);
  return last;
}

async function cmdControlApply(flags: Flags): Promise<unknown> {
  return rpc(flags, "control.apply", { certificate: reqId(flags, "certificate-object") } as Json, true);
}

async function cmdControlStatus(flags: Flags): Promise<unknown> {
  return rpc(flags, "control.status", {} as Json, false);
}

async function cmdHealth(flags: Flags): Promise<unknown> {
  return rpc(flags, "health.get", {} as Json, false);
}

const USAGE = `commit/1 — conditional transfer state machine

usage: commit [global flags] <command>

global flags: --config --socket --cap --request-id --json --timeout-ms --out --help --version

commands:
  object put --id --kind --file         object get --id
  propose --envelope-object             show --id
  list --limit [--state --cursor]       approve --id --approval-object --expected-revision
  execute --id --expected-revision      cancel --id --expected-revision
  satisfy --id --evidence-object --expected-revision
  dispute open --id --case --reason --evidence-ref --expected-revision
  dispute resolve --id --award-object --expected-revision
  advance --id --expected-revision
  custody reconcile --operation [--receipt-object]
  custody retry --operation --no-effect-receipt
  account --principal --asset-file      events --id --after --limit
  export --id --disclosure --out [--cursor]
  verify --bundle-dir --trust-file
  control apply --certificate-object    control status
  health
  canonicalize --kind --file            sign --kind --body-file --key-fd --key-id --journal-dir --out
  keygen --out                          init --config --policy-file --trust-file --custody-manifest --out
  serve --config                        store verify --store --trust-file
  store backup --store --out            store migrate plan|apply
`;

export async function main(argv: string[]): Promise<number> {
  const { flags, rest } = parseArgs(argv);
  try {
    if (flags.version === true) { process.stdout.write(`commit ${VERSION}\n`); return 0; }
    if (flags.help === true || rest.length === 0) { process.stderr.write(USAGE); return rest.length === 0 ? 2 : 0; }
    const json = flags.json === true;
    const cmd = rest.join(" ");
    let result: unknown;
    switch (cmd) {
      case "object put": result = await cmdObjectPut(flags); break;
      case "object get": result = await cmdObjectGet(flags); break;
      case "propose": result = await cmdPropose(flags); break;
      case "show": result = await cmdShow(flags); break;
      case "list": result = await cmdList(flags); break;
      case "approve": result = await cmdApprove(flags); break;
      case "execute": result = await cmdExecute(flags); break;
      case "cancel": result = await cmdCancel(flags); break;
      case "satisfy": result = await cmdSatisfy(flags); break;
      case "dispute open": result = await cmdDisputeOpen(flags); break;
      case "dispute resolve": result = await cmdDisputeResolve(flags); break;
      case "advance": result = await cmdAdvance(flags); break;
      case "custody reconcile": result = await cmdCustodyReconcile(flags); break;
      case "custody retry": result = await cmdCustodyRetry(flags); break;
      case "account": result = await cmdAccount(flags); break;
      case "events": result = await cmdEvents(flags); break;
      case "export": result = await cmdExport(flags); break;
      case "verify": result = cmdVerify(flags); break;
      case "control apply": result = await cmdControlApply(flags); break;
      case "control status": result = await cmdControlStatus(flags); break;
      case "health": {
        result = await cmdHealth(flags);
        print(result, json);
        return (result as T.HealthResult).ready ? 0 : 8;
      }
      case "canonicalize": result = cmdCanonicalize(flags); break;
      case "sign": result = cmdSign(flags); break;
      case "keygen": result = cmdKeygen(flags); break;
      case "init": result = cmdInit(flags); break;
      case "store verify": result = cmdStoreVerify(flags); break;
      case "store backup": result = cmdStoreBackup(flags); break;
      case "store migrate plan": result = cmdMigratePlan(flags); break;
      case "store migrate apply": result = cmdMigrateApply(flags); break;
      case "serve": {
        const { startDaemon } = await import("./daemon.ts");
        const d = startDaemon(req(flags, "config"), (m) => process.stderr.write(m + "\n"));
        void d;
        return await new Promise<number>(() => {}); // foreground until SIGTERM
      }
      default:
        throw err("SCHEMA_INVALID", `unknown command: ${cmd}`);
    }
    print(result, json);
    if (cmd === "verify") {
      const r = result as T.VerifyResult;
      if (r.integrity === "verified" && r.authorization === "verified") return 0;
      if (r.integrity === "incomplete" || r.authorization === "incomplete") return 7;
      return 4;
    }
    return 0;
  } catch (e) {
    if (e instanceof NotImplementedSurface) {
      process.stderr.write(`not implemented: ${e.message}\n`);
      return 8;
    }
    const code = isCommitError(e) ? e.code : "INTERNAL";
    const msg = isCommitError(e) ? e.message : String((e as Error).message ?? e);
    if (flags.json === true) {
      process.stdout.write(jcs({ ok: false, error: { code, retryable: isCommitError(e) ? e.retryable : false, message: msg, current_revision: isCommitError(e) ? (e.currentRevision ?? null) : null } } as Json) + "\n");
    } else {
      process.stderr.write(`error ${code}: ${msg}\n`);
    }
    return exitCodeFor(code);
  }
}
