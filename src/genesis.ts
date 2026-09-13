// Offline store bootstrap (`commit init`): create-only store construction,
// genesis policy/trust enrollment, and sim-ledger backing rows. Never used by
// a running coordinator — a second init on an existing store refuses.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import crypto from "node:crypto";
import { D, publicKeyFromSeed } from "./crypto.ts";
import { err, NotImplementedSurface } from "./errors.ts";
import { parseStrictJson } from "./json/strict.ts";
import type { Json } from "./json/strict.ts";
import { validCustodyManifest, validPolicy, validTrustPin } from "./schema.ts";
import { validatePolicySemantics } from "./objects.ts";
import { Store } from "./store.ts";
import type * as T from "./types.ts";
import type { CoordinatorConfig } from "./config.ts";

export interface GenesisResult {
  storage_version: number;
  genesis_digest: string;
  mode: "simulation" | "live";
}

/** Create a fresh store directory + SQLite database and enroll genesis objects. */
export function initStore(opts: {
  storeDir: string;
  policy: T.Policy;
  policyObjectId: string;
  trust: T.TrustPin;
  custody: T.CustodyManifest;
  writerPublicKey: string;
  writerEpoch: bigint;
  receiptSeed?: Buffer | undefined;
  mode: "simulation" | "live";
  simAccounts: { principal: string; available: bigint }[];
  nowMs: bigint;
}): GenesisResult {
  if (opts.mode === "live") {
    throw new NotImplementedSurface(
      "live initialization",
      "live-pilot initialization requires Covenant v1 plus completed P0–P6 gates and a separately enrolled custody manifest (§12)",
    );
  }
  if (existsSync(opts.storeDir) && readdirSync(opts.storeDir).some((f) => f === "store.db" || f.endsWith(".db"))) {
    throw err("OBJECT_CONFLICT", "init refuses an existing store directory");
  }
  mkdirSync(opts.storeDir, { recursive: true, mode: 0o700 });
  const store = new Store(join(opts.storeDir, "store.db"), opts.storeDir);
  try {
    store.tx(() => {
      validatePolicySemantics(opts.policy, opts.custody, opts.writerPublicKey);
      if (opts.trust.genesis_policy_hash !== D("policy", opts.policy as unknown as Json)) {
        throw err("TRUST_UNANCHORED", "trust genesis_policy_hash does not match the genesis policy");
      }
      if (opts.trust.custody_manifest_hash !== D("custody_manifest", opts.custody as unknown as Json)) {
        throw err("TRUST_UNANCHORED", "trust custody_manifest_hash does not match the manifest");
      }
      store.initMeta({
        tenant: opts.policy.tenant, environment: opts.policy.environment,
        writer_epoch: opts.writerEpoch, active_policy: opts.policyObjectId, last_clock_ms: opts.nowMs,
      });
      const polDigest = D("policy", opts.policy as unknown as Json);
      store.putObject({
        object_id: opts.policyObjectId, kind: "policy", digest: polDigest,
        bytes: Buffer.byteLength(JSON.stringify(opts.policy)), path: null, owner: null,
        scope_commit: null, created_ms: opts.nowMs, referenced: 1, body: opts.policy,
      });
      store.putPolicy(opts.policyObjectId, polDigest, 0n);
      const trustDigest = D("trust", opts.trust as unknown as Json);
      store.putObject({
        object_id: "trust0", kind: "trust", digest: trustDigest,
        bytes: Buffer.byteLength(JSON.stringify(opts.trust)), path: null, owner: "__enrolled__",
        scope_commit: null, created_ms: opts.nowMs, referenced: 1, body: opts.trust,
      });
      if (opts.simAccounts.length) {
        const lines: { account: string; asset_code: string; side: "DEBIT" | "CREDIT"; amount_minor: bigint; commit_id: string | null }[] = [];
        for (const a of opts.simAccounts) {
          store.upsertAccount(opts.custody.custody, opts.custody.asset.code, a.principal, a.available, 0n, 1);
          lines.push(
            { account: "backing", asset_code: opts.custody.asset.code, side: "DEBIT", amount_minor: a.available, commit_id: null },
            { account: a.principal, asset_code: opts.custody.asset.code, side: "CREDIT", amount_minor: a.available, commit_id: null },
          );
        }
        store.insertLedgerTransaction("genesis", 0n, lines);
      }
    });
    // sim-ledger/1: the receipt key is generated at init and held by the local
    // adapter module; persist the seed store-locally at mode 0600.
    if (opts.custody.profile === "sim-ledger/1") {
      const seed = opts.receiptSeed ?? crypto.randomBytes(32);
      if (publicKeyFromSeed(seed) !== opts.custody.receipt_key) {
        throw err("TRUST_UNANCHORED", "custody manifest receipt_key does not match the generated receipt key");
      }
      writeFileSync(join(opts.storeDir, "receipt.key"), seed.toString("hex") + "\n", { mode: 0o600 });
    }
    return { storage_version: 1, genesis_digest: D("policy", opts.policy as unknown as Json), mode: opts.mode };
  } finally {
    store.close();
  }
}

/** Load + validate the genesis JSON artifacts for init. */
export function loadGenesisArtifacts(files: { policyFile: string; trustFile: string; custodyManifestFile: string }): {
  policy: T.Policy; trust: T.TrustPin; custody: T.CustodyManifest;
} {
  const read = (p: string): Json => {
    let buf: Buffer;
    try { buf = readFileSync(p); } catch {
      throw err("STORAGE_UNAVAILABLE", `cannot read ${p}`);
    }
    return parseStrictJson(buf);
  };
  const policy = validPolicy(read(files.policyFile));
  const trust = validTrustPin(read(files.trustFile));
  const custody = validCustodyManifest(read(files.custodyManifestFile));
  return { policy, trust, custody };
}
