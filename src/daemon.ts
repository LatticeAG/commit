// `commit serve` assembly: config → store → recovery → coordinator → unix
// server → dispatch/lookup/timer/audit workers.

import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { D, privateKeyFromSeed, publicKeyFromSeed } from "./crypto.ts";
import { err } from "./errors.ts";
import { parseStrictJson } from "./json/strict.ts";
import type { Json } from "./json/strict.ts";
import { validCustodyManifest, validPolicy, validTrustPin } from "./schema.ts";
import { Store } from "./store.ts";
import { CoordinatorClock } from "./clock.ts";
import { Coordinator, type CoordinatorDeps } from "./coordinator.ts";
import { serve } from "./server.ts";
import { loadConfig, type CoordinatorConfig } from "./config.ts";
import { CertifiedEscrowStub } from "./custody/certified.ts";
import type { CustodyAdapter } from "./custody/adapter.ts";
import type { CallCtx } from "./reducer/methods.ts";
import { dispatchTick, lookupTick, timerTick, recoverAfterRestart } from "./reducer/custody.ts";
import { drainAuditOutbox } from "./audit.ts";
import type * as T from "./types.ts";
import crypto from "node:crypto";

function readSecret(ref: string): Buffer {
  if (ref.startsWith("file:")) {
    const p = ref.slice(5);
    const raw = readFileSync(p);
    const hex = raw.toString("utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw err("SCHEMA_INVALID", `writer key file ${p} must be 64 lowercase hex chars`);
    const { mode } = statSync(p);
    if ((mode & 0o077) !== 0) throw err("FORBIDDEN", `writer key file ${p} must be mode 0600`);
    return Buffer.from(hex, "hex");
  }
  if (ref.startsWith("fd:")) {
    const fd = Number(ref.slice(3));
    const raw = readFileSync(fd);
    const hex = raw.toString("utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw err("SCHEMA_INVALID", "writer key fd must supply 64 lowercase hex chars");
    return Buffer.from(hex, "hex");
  }
  throw err("SCHEMA_INVALID", `unsupported key ref ${ref}`);
}

export function loadWriterSeed(cfg: CoordinatorConfig): Buffer {
  const seed = readSecret(cfg.writer_key_ref);
  return seed;
}

export interface Daemon {
  store: Store;
  coordinator: Coordinator;
  stop(): void;
  sockPath: string;
}

export function startDaemon(cfgPath: string, log: (m: string) => void = () => {}): Daemon {
  const cfg = loadConfig(cfgPath);
  const custody = validCustodyManifest(parseStrictJson(readFileSync(cfg.custody_manifest_file)));
  const trust = validTrustPin(parseStrictJson(readFileSync(cfg.trust_file)));

  const dbPath = join(cfg.store, "store.db");
  if (!existsSync(dbPath)) throw err("STORAGE_UNAVAILABLE", `no initialized store at ${dbPath}; run commit init`);
  const store = new Store(dbPath, cfg.store);
  const meta = store.getMeta();
  if (!meta) throw err("STORAGE_UNAVAILABLE", "store meta row missing; run commit init");
  if (meta.tenant !== cfg.tenant) throw err("SCHEMA_INVALID", "config tenant differs from store");
  if (meta.writer_epoch !== cfg.writer_epoch) throw err("FENCE_STALE", "config writer_epoch differs from store");

  const polObj = store.getObject(cfg.policy_object);
  if (!polObj || polObj.kind !== "policy") throw err("STORAGE_UNAVAILABLE", "active policy object missing from store");
  const policy = polObj.body as T.Policy;
  const writerSeed = loadWriterSeed(cfg);
  const writerPub = publicKeyFromSeed(writerSeed);
  if (writerPub !== trust.writer_key) throw err("TRUST_UNANCHORED", "writer key does not match the enrolled trust pin");

  let adapter: CustodyAdapter | null = null;
  const localCustody = custody.profile === "sim-ledger/1";
  if (!localCustody) adapter = new CertifiedEscrowStub(custody.custody);
  if (!localCustody && cfg.custody.egress_allowlist.length === 0) {
    throw err("SCHEMA_INVALID", "certified custody requires a nonempty egress_allowlist");
  }

  const clock = new CoordinatorClock(BigInt(Date.now()), cfg.clock_max_skew_ms);
  const cursorSecret = crypto.createHash("sha256").update(`cursor:${cfg.store}`).update(writerSeed).digest();

  const deps: CoordinatorDeps = {
    store, custody, policy, policyObjectId: cfg.policy_object,
    writerSeed, writerKeyId: "writer1", receiptSeed: localCustody ? writerSeed : null,
    receiptKeyId: "receipt1", writerEpoch: String(cfg.writer_epoch),
    adapter, localCustody,
    maxObjectsPerPrincipal: cfg.max_objects_per_principal,
    maxUnboundObjectBytes: cfg.max_unbound_object_bytes,
    objectDir: join(cfg.store, "objects"),
    cursorSecret,
    auditEvery: cfg.audit_socket !== null || true,
    clock,
    storageOk: () => {
      try { store.db.prepare("SELECT 1").get(); return true; } catch { return false; }
    },
  };

  // sim-ledger/1: receipt seed was generated at init and held store-locally.
  if (localCustody) {
    const keyPath = join(cfg.store, "receipt.key");
    if (!existsSync(keyPath)) throw err("STORAGE_UNAVAILABLE", "receipt.key missing; run commit init");
    const hex = readFileSync(keyPath, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw err("SCHEMA_INVALID", "receipt.key malformed");
    const rseed = Buffer.from(hex, "hex");
    if (publicKeyFromSeed(rseed) !== custody.receipt_key) {
      throw err("TRUST_UNANCHORED", "receipt key does not match custody manifest receipt_key");
    }
    deps.receiptSeed = rseed;
  }

  const coordinator = new Coordinator(deps);
  const capsByUid = new Map<number, T.Capability>();
  for (const p of cfg.principals) {
    if (capsByUid.has(p.uid)) throw err("SCHEMA_INVALID", `duplicate uid ${p.uid} in principals`);
    capsByUid.set(p.uid, p);
  }

  mkdirSync(cfg.store, { recursive: true });
  const sockPath = cfg.listen.slice("unix:".length);
  const server = serve(sockPath, coordinator, capsByUid, {
    maxFrameBytes: cfg.max_frame_bytes, maxInflight: cfg.max_inflight_requests,
  });

  // restart recovery before any sends: re-scan durable operation markers
  const sysCtx: CallCtx = {
    ...deps, now: clock.tick().now, wallNow: BigInt(Date.now()), clockSafe: true,
    actor: "ops" as T.Id, capability: cfg.principals[0]!, commandId: "sys_recover_0",
  };
  recoverAfterRestart(sysCtx);

  const timers: ReturnType<typeof setInterval>[] = [];
  timers.push(setInterval(() => {
    const r = clock.tick();
    const c: CallCtx = { ...deps, now: r.now, wallNow: r.wallNow, clockSafe: r.safe, actor: "ops" as T.Id, capability: cfg.principals[0]!, commandId: "sys_tick" };
    try { timerTick(c); } catch { /* durable errors are surfaced via events */ }
    void dispatchTick(c).then(() => lookupTick(c)).catch(() => {});
    drainAuditOutbox(store, cfg.audit_socket, cfg.proof_directory);
  }, cfg.timer_poll_ms));
  for (const t of timers) t.unref?.();

  const stop = () => {
    for (const t of timers) clearInterval(t);
    server.close();
    store.close();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  log(`commit/1 ready on ${sockPath}`);
  return { store, coordinator, stop, sockPath };
}
