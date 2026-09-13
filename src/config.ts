// Strict TOML subset parser + §5 coordinator config validation.
// Supports exactly what the reference config needs: bare keys, strings,
// integers, booleans, string arrays, [tables], [[table arrays]].
// Unknown keys or omitted required keys reject startup.

import { readFileSync } from "node:fs";
import { err } from "./errors.ts";
import { isId, strictU64 } from "./scalars.ts";
import { METHODS, OBJECT_KINDS, type Capability, type Method, type ObjectKind } from "./types.ts";

type Toml = string | number | boolean | Toml[] | { [k: string]: Toml };

class TomlParser {
  private i = 0;
  private readonly src: string;
  constructor(src: string) { this.src = src; }

  parse(): { [k: string]: Toml } {
    const root: { [k: string]: Toml } = {};
    let table: string[] = [];
    while (true) {
      this.skipWsComments();
      if (this.i >= this.src.length) return root;
      if (this.src[this.i] === "[") {
        this.i++;
        const isArr = this.src[this.i] === "[";
        if (isArr) this.i++;
        this.skipInlineWs();
        const name = this.parseKeyPath();
        this.skipInlineWs();
        if (this.src[this.i] !== "]") this.fail("expected ]");
        this.i++;
        if (isArr) {
          if (this.src[this.i] !== "]") this.fail("expected ]]");
          this.i++;
        }
        this.newline();
        table = name;
        if (isArr) {
          const parent = this.dig(root, name.slice(0, -1), false);
          const key = name[name.length - 1]!;
          if (!(key in parent)) parent[key] = [];
          if (!Array.isArray(parent[key])) this.fail("table array conflicts with existing key");
          (parent[key] as Toml[]).push({});
        } else {
          const obj = this.dig(root, name, true);
          if (Object.keys(obj).length !== 0) this.fail(`table ${name.join(".")} redefined`);
        }
        continue;
      }
      const kp = this.parseKeyPath();
      this.skipInlineWs();
      if (this.src[this.i] !== "=") this.fail("expected =");
      this.i++;
      this.skipInlineWs();
      const value = this.parseValue();
      this.newline();
      const obj = table.length ? this.dig(root, table, false) : root;
      const key = kp[kp.length - 1]!;
      if (kp.length > 1) this.fail("dotted keys not supported");
      if (key in obj) this.fail(`key ${key} redefined`);
      obj[key] = value;
    }
  }

  private dig(root: { [k: string]: Toml }, path: string[], create: boolean): { [k: string]: Toml } {
    let cur = root;
    for (const part of path) {
      let next = cur[part];
      if (Array.isArray(next)) next = next[next.length - 1];
      if (next === undefined) {
        if (!create) throw err("SCHEMA_INVALID", `toml path ${path.join(".")} missing`);
        next = {};
        cur[part] = next;
      }
      if (typeof next !== "object" || next === null || Array.isArray(next)) this.fail("table path conflicts");
      cur = next as { [k: string]: Toml };
    }
    return cur;
  }

  private parseKeyPath(): string[] {
    const parts: string[] = [];
    while (true) {
      this.skipInlineWs();
      const m = /^[A-Za-z0-9_-]+/.exec(this.src.slice(this.i));
      if (!m) this.fail("expected key");
      parts.push(m[0]);
      this.i += m[0].length;
      this.skipInlineWs();
      if (this.src[this.i] === ".") { this.i++; continue; }
      return parts;
    }
  }

  private parseValue(): Toml {
    const c = this.src[this.i];
    if (c === '"') return this.parseString();
    if (c === "[") return this.parseArray();
    if (this.src.startsWith("true", this.i)) { this.i += 4; return true; }
    if (this.src.startsWith("false", this.i)) { this.i += 5; return false; }
    const m = /^-?[0-9][0-9_]*/.exec(this.src.slice(this.i));
    if (m) {
      this.i += m[0].length;
      return parseInt(m[0].replace(/_/g, ""), 10);
    }
    this.fail("invalid value");
  }

  private parseString(): string {
    this.i++; // "
    let out = "";
    while (this.i < this.src.length) {
      const c = this.src[this.i]!;
      if (c === '"') { this.i++; return out; }
      if (c === "\\") {
        const e = this.src[this.i + 1];
        this.i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "n": out += "\n"; break;
          case "t": out += "\t"; break;
          case "r": out += "\r"; break;
          case "u": out += String.fromCharCode(parseInt(this.src.slice(this.i, this.i + 4), 16)); this.i += 4; break;
          default: this.fail("invalid escape");
        }
        continue;
      }
      if (c === "\n") this.fail("newline in string");
      out += c;
      this.i++;
    }
    this.fail("unterminated string");
  }

  private parseArray(): Toml[] {
    this.i++; // [
    const out: Toml[] = [];
    while (true) {
      this.skipWsComments();
      if (this.src[this.i] === "]") { this.i++; return out; }
      out.push(this.parseValue());
      this.skipWsComments();
      if (this.src[this.i] === ",") { this.i++; continue; }
      if (this.src[this.i] === "]") { this.i++; return out; }
      this.fail("expected , or ]");
    }
  }

  private skipInlineWs(): void {
    while (this.src[this.i] === " " || this.src[this.i] === "\t") this.i++;
  }

  private skipWsComments(): void {
    while (true) {
      const c = this.src[this.i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") { this.i++; continue; }
      if (c === "#") { while (this.i < this.src.length && this.src[this.i] !== "\n") this.i++; continue; }
      return;
    }
  }

  private newline(): void {
    this.skipInlineWs();
    const c = this.src[this.i];
    if (c === "#") while (this.i < this.src.length && this.src[this.i] !== "\n") this.i++;
    if (this.i < this.src.length && this.src[this.i] !== "\n" && this.src[this.i] !== "\r") this.fail("trailing content on line");
    while (this.src[this.i] === "\n" || this.src[this.i] === "\r") this.i++;
  }

  private fail(msg: string): never {
    throw err("SCHEMA_INVALID", `config TOML: ${msg} at offset ${this.i}`);
  }
}

export function parseToml(src: string): { [k: string]: Toml } {
  return new TomlParser(src).parse();
}

// ---------- coordinator config (§5) ----------

export interface CoordinatorConfig {
  version: 1;
  mode: "simulation" | "live";
  tenant: string;
  listen: string;             // unix:/path
  store: string;              // directory
  policy_object: string;
  trust_file: string;
  custody_manifest_file: string;
  writer_key_ref: string;     // fd:N | file:/path (mode 0600)
  writer_epoch: bigint;
  max_frame_bytes: number;
  max_blob_bytes: number;
  max_inflight_requests: number;
  max_objects_per_principal: number;
  max_unbound_object_bytes: bigint;
  request_timeout_ms: number;
  clock_max_skew_ms: bigint;
  timer_poll_ms: number;
  clock_source: "host-synchronized";
  proof_directory: string;
  audit_socket: string | null;
  audit_delivery: "optional-local-outbox";
  storage: { schema: number; journal_mode: "WAL"; synchronous: "FULL"; busy_timeout_ms: number; min_free_bytes: bigint; backup_interval_ms: bigint; retain_unresolved: boolean; retain_economic_days: number };
  custody: { profile: "sim-ledger/1" | "certified-escrow/1"; credential_ref: string; egress_allowlist: string[]; lookup_interval_ms: number; max_lookup_interval_ms: number; max_attempts: number };
  principals: Capability[];
  sim_accounts: { principal: string; available: bigint }[]; // simulation-only backing rows
}

const TOP_KEYS = new Set([
  "version", "mode", "tenant", "listen", "store", "policy_object", "trust_file",
  "custody_manifest_file", "writer_key_ref", "writer_epoch", "max_frame_bytes",
  "max_blob_bytes", "max_inflight_requests", "max_objects_per_principal",
  "max_unbound_object_bytes", "request_timeout_ms", "clock_max_skew_ms",
  "timer_poll_ms", "clock_source", "proof_directory", "audit_socket",
  "audit_delivery", "storage", "custody", "principals", "sim_accounts",
]);

const STORAGE_KEYS = new Set(["schema", "journal_mode", "synchronous", "busy_timeout_ms", "min_free_bytes", "backup_interval_ms", "retain_unresolved", "retain_economic_days"]);
const CUSTODY_KEYS = new Set(["profile", "credential_ref", "egress_allowlist", "lookup_interval_ms", "max_lookup_interval_ms", "max_attempts"]);
const PRINCIPAL_KEYS = new Set(["uid", "principal", "capability", "methods", "object_kinds", "commit_ids", "max_amount_minor", "expires_ms"]);
const SIM_ACCT_KEYS = new Set(["principal", "available"]);

function need<T extends Toml>(obj: { [k: string]: Toml }, key: string, allowed: Set<string>): T {
  for (const k of Object.keys(obj)) if (!allowed.has(k)) throw err("SCHEMA_INVALID", `config: unknown key "${k}"`);
  const v = obj[key];
  if (v === undefined) throw err("SCHEMA_INVALID", `config: required key "${key}" missing`);
  return v as T;
}

function needStr(obj: { [k: string]: Toml }, key: string, allowed: Set<string>): string {
  const v = need<string>(obj, key, allowed);
  if (typeof v !== "string") throw err("SCHEMA_INVALID", `config: "${key}" must be a string`);
  return v;
}

function needNum(obj: { [k: string]: Toml }, key: string, allowed: Set<string>): number {
  const v = need<number>(obj, key, allowed);
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw err("SCHEMA_INVALID", `config: "${key}" must be a nonnegative integer`);
  return v;
}

function needU64(obj: { [k: string]: Toml }, key: string, allowed: Set<string>): bigint {
  const v = need<string>(obj, key, allowed);
  return strictU64(v, `config.${key}`);
}

export function loadConfig(path: string): CoordinatorConfig {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw err("STORAGE_UNAVAILABLE", `config file ${path} unreadable`);
  }
  return parseConfig(parseToml(text));
}

export function parseConfig(t: { [k: string]: Toml }): CoordinatorConfig {
  for (const k of Object.keys(t)) if (!TOP_KEYS.has(k)) throw err("SCHEMA_INVALID", `config: unknown top-level key "${k}"`);

  const version = needNum(t, "version", TOP_KEYS);
  if (version !== 1) throw err("UNSUPPORTED_VERSION", "config version must be 1");
  const mode = needStr(t, "mode", TOP_KEYS);
  if (mode !== "simulation" && mode !== "live") throw err("SCHEMA_INVALID", "config: mode invalid");
  const tenant = needStr(t, "tenant", TOP_KEYS);
  if (!isId(tenant)) throw err("SCHEMA_INVALID", "config: tenant invalid");
  const listen = needStr(t, "listen", TOP_KEYS);
  if (!listen.startsWith("unix:")) throw err("SCHEMA_INVALID", "config: listen must begin with unix:");
  const clockSource = needStr(t, "clock_source", TOP_KEYS);
  if (clockSource !== "host-synchronized") throw err("SCHEMA_INVALID", "config: clock_source must be host-synchronized");
  const auditDelivery = needStr(t, "audit_delivery", TOP_KEYS);
  if (auditDelivery !== "optional-local-outbox") throw err("SCHEMA_INVALID", "config: audit_delivery invalid");

  const storage = need<{ [k: string]: Toml }>(t, "storage", TOP_KEYS);
  if (typeof storage !== "object" || storage === null || Array.isArray(storage)) throw err("SCHEMA_INVALID", "config: [storage] required");
  if (needNum(storage, "schema", STORAGE_KEYS) !== 1) throw err("UNSUPPORTED_VERSION", "config: storage.schema must be 1");
  if (needStr(storage, "journal_mode", STORAGE_KEYS) !== "WAL") throw err("SCHEMA_INVALID", "config: journal_mode must be WAL");
  if (needStr(storage, "synchronous", STORAGE_KEYS) !== "FULL") throw err("SCHEMA_INVALID", "config: synchronous must be FULL");

  const custody = need<{ [k: string]: Toml }>(t, "custody", TOP_KEYS);
  if (typeof custody !== "object" || custody === null || Array.isArray(custody)) throw err("SCHEMA_INVALID", "config: [custody] required");
  const profile = needStr(custody, "profile", CUSTODY_KEYS);
  if (profile !== "sim-ledger/1" && profile !== "certified-escrow/1") throw err("SCHEMA_INVALID", "config: custody.profile invalid");
  const egress = need<string[]>(custody, "egress_allowlist", CUSTODY_KEYS);
  if (!Array.isArray(egress) || egress.some((x) => typeof x !== "string")) throw err("SCHEMA_INVALID", "config: egress_allowlist must be a string array");
  if (profile === "sim-ledger/1" && egress.length !== 0) throw err("SCHEMA_INVALID", "config: sim-ledger/1 requires empty egress_allowlist");
  if (mode === "live" && profile === "sim-ledger/1") throw err("SCHEMA_INVALID", "config: live mode cannot use sim-ledger/1");

  const principalsRaw = need<Toml[]>(t, "principals", TOP_KEYS);
  if (!Array.isArray(principalsRaw)) throw err("SCHEMA_INVALID", "config: [[principals]] required");
  const principals: Capability[] = principalsRaw.map((raw) => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw err("SCHEMA_INVALID", "config: principals entry invalid");
    const o = raw as { [k: string]: Toml };
    const uid = needNum(o, "uid", PRINCIPAL_KEYS);
    const principal = needStr(o, "principal", PRINCIPAL_KEYS);
    const capability = needStr(o, "capability", PRINCIPAL_KEYS);
    const methods = need<string[]>(o, "methods", PRINCIPAL_KEYS);
    const kinds = need<string[]>(o, "object_kinds", PRINCIPAL_KEYS);
    const commitIds = need<string[]>(o, "commit_ids", PRINCIPAL_KEYS);
    if (!isId(principal) || principal === "control") throw err("SCHEMA_INVALID", "config: principal invalid");
    if (!isId(capability)) throw err("SCHEMA_INVALID", "config: capability invalid");
    if (!Array.isArray(methods) || methods.some((m) => typeof m !== "string" || !METHODS.includes(m as Method))) throw err("SCHEMA_INVALID", "config: methods invalid");
    if (!Array.isArray(kinds) || kinds.some((k) => typeof k !== "string" || !OBJECT_KINDS.includes(k as ObjectKind))) throw err("SCHEMA_INVALID", "config: object_kinds invalid");
    if (!Array.isArray(commitIds) || commitIds.some((c) => typeof c !== "string" || !isId(c))) throw err("SCHEMA_INVALID", "config: commit_ids invalid");
    return {
      uid, principal, capability,
      methods: methods as Method[], object_kinds: kinds as ObjectKind[], commit_ids: commitIds as string[],
      max_amount_minor: String(needU64(o, "max_amount_minor", PRINCIPAL_KEYS)),
      expires_ms: String(needU64(o, "expires_ms", PRINCIPAL_KEYS)),
    };
  });

  const simAccounts: { principal: string; available: bigint }[] = [];
  const simRaw = t.sim_accounts;
  if (simRaw !== undefined) {
    if (mode !== "simulation") throw err("SCHEMA_INVALID", "config: sim_accounts forbidden outside simulation mode");
    if (!Array.isArray(simRaw)) throw err("SCHEMA_INVALID", "config: sim_accounts must be a table array");
    for (const raw of simRaw) {
      const o = raw as { [k: string]: Toml };
      const principal = needStr(o, "principal", SIM_ACCT_KEYS);
      if (!isId(principal)) throw err("SCHEMA_INVALID", "config: sim account principal invalid");
      simAccounts.push({ principal, available: needU64(o, "available", SIM_ACCT_KEYS) });
    }
  }

  const auditSocket = needStr(t, "audit_socket", TOP_KEYS);

  return {
    version: 1, mode, tenant, listen, store: needStr(t, "store", TOP_KEYS),
    policy_object: needStr(t, "policy_object", TOP_KEYS),
    trust_file: needStr(t, "trust_file", TOP_KEYS),
    custody_manifest_file: needStr(t, "custody_manifest_file", TOP_KEYS),
    writer_key_ref: needStr(t, "writer_key_ref", TOP_KEYS),
    writer_epoch: needU64(t, "writer_epoch", TOP_KEYS),
    max_frame_bytes: needNum(t, "max_frame_bytes", TOP_KEYS),
    max_blob_bytes: needNum(t, "max_blob_bytes", TOP_KEYS),
    max_inflight_requests: needNum(t, "max_inflight_requests", TOP_KEYS),
    max_objects_per_principal: needNum(t, "max_objects_per_principal", TOP_KEYS),
    max_unbound_object_bytes: needU64(t, "max_unbound_object_bytes", TOP_KEYS),
    request_timeout_ms: needNum(t, "request_timeout_ms", TOP_KEYS),
    clock_max_skew_ms: needU64(t, "clock_max_skew_ms", TOP_KEYS),
    timer_poll_ms: needNum(t, "timer_poll_ms", TOP_KEYS),
    clock_source: clockSource,
    proof_directory: needStr(t, "proof_directory", TOP_KEYS),
    audit_socket: auditSocket === "none" || auditSocket === "" ? null : auditSocket,
    audit_delivery: auditDelivery,
    storage: {
      schema: 1, journal_mode: "WAL", synchronous: "FULL",
      busy_timeout_ms: needNum(storage, "busy_timeout_ms", STORAGE_KEYS),
      min_free_bytes: needU64(storage, "min_free_bytes", STORAGE_KEYS),
      backup_interval_ms: needU64(storage, "backup_interval_ms", STORAGE_KEYS),
      retain_unresolved: storage.retain_unresolved === true,
      retain_economic_days: needNum(storage, "retain_economic_days", STORAGE_KEYS),
    },
    custody: {
      profile, credential_ref: needStr(custody, "credential_ref", CUSTODY_KEYS), egress_allowlist: egress as string[],
      lookup_interval_ms: needNum(custody, "lookup_interval_ms", CUSTODY_KEYS),
      max_lookup_interval_ms: needNum(custody, "max_lookup_interval_ms", CUSTODY_KEYS),
      max_attempts: needNum(custody, "max_attempts", CUSTODY_KEYS),
    },
    principals,
    sim_accounts: simAccounts,
  };
}
