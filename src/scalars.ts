// Scalar refinements from §1.1: Id, U64, Digest, Nonce, keys, base64url, bounds.

import { err } from "./errors.ts";

export const ID_RE = /^[a-z][a-z0-9_-]{0,63}$/;
export const DIGEST_RE = /^[0-9a-f]{64}$/;
export const NONCE_RE = /^[0-9a-f]{32}$/;
export const PUBKEY_RE = /^[0-9a-f]{64}$/;
export const SIG_RE = /^[0-9a-f]{128}$/;
export const ASSET_CODE_RE = /^[A-Z][A-Z0-9]{1,11}$/;
export const PREDICATE_RE = /^[a-z][a-z0-9_.-]{0,127}$/;
export const B64URL_RE = /^[A-Za-z0-9_-]*$/;
export const U64_MAX = 9223372036854775807n;
export const JSON_SAFE_MAX = 9007199254740991n;

export const STRING_BOUND_DEFAULT = 1024;
export const STRING_BOUND_PURPOSE = 512;
export const STRING_BOUND_EXTREF = 256;
export const MAX_BLOB_BYTES = 512 * 1024;
export const MAX_PREIMAGE_BYTES = 4096;
export const MAX_CLAUSES = 8;
export const MAX_PARENTS = 8;
export const MAX_QUORUM_KEYS = 16;
export const MAX_SIGNATURES = 16;
export const MAX_EVIDENCE_ITEMS = 8;
export const MAX_AWARD_EVIDENCE = 8;
export const MAX_EVENT_OBJECTS = 64;
export const MAX_POLICY_MEMBERS = 64;
export const MAX_ARTIFACT_BYTES = 64 * 1024;
export const MAX_ARTIFACT_DEPTH = 16;
export const MAX_OBJECT_MEMBERS = 256;
export const MAX_FRAME_BYTES = 2097152;
export const MAX_MANIFEST_BYTES = 768 * 1024;
export const MAX_MANIFEST_EVENTS = 256;
export const MAX_EXPORT_CHUNK = 1048576;
export const MAX_CURSOR_BYTES = 4096;
export const MAX_DURATION_MS = 2592000000n;

export function isId(v: unknown): v is string {
  return typeof v === "string" && ID_RE.test(v);
}

/** Ids that may name promises, objects, principals — "control" is reserved. */
export function isNamedId(v: unknown): v is string {
  return isId(v) && v !== "control";
}

export function isU64(v: unknown): v is string {
  if (typeof v !== "string") return false;
  if (!/^(0|[1-9][0-9]*)$/.test(v)) return false;
  return BigInt(v) <= U64_MAX;
}

export function u64(v: string): bigint {
  return BigInt(v);
}

export function u64str(v: bigint): string {
  return v.toString(10);
}

export function isDigest(v: unknown): v is string {
  return typeof v === "string" && DIGEST_RE.test(v);
}

export function isNonce(v: unknown): v is string {
  return typeof v === "string" && NONCE_RE.test(v);
}

export function isPublicKey(v: unknown): v is string {
  return typeof v === "string" && PUBKEY_RE.test(v);
}

export function isSig(v: unknown): v is string {
  return typeof v === "string" && SIG_RE.test(v);
}

export function isAscii(v: string): boolean {
  for (let i = 0; i < v.length; i++) if (v.charCodeAt(i) > 0x7f) return false;
  return true;
}

export function utf8Len(v: string): number {
  return Buffer.byteLength(v, "utf8");
}

export function checkStringBound(v: string, max: number, field: string): void {
  if (utf8Len(v) > max) throw err("SCHEMA_INVALID", `${field} exceeds ${max} UTF-8 bytes`);
}

/** Canonical unpadded base64url: decode + re-encode must round-trip. */
export function decodeBase64urlCanonical(v: string): Buffer {
  if (typeof v !== "string" || !B64URL_RE.test(v)) {
    throw err("SCHEMA_INVALID", "base64url is not canonical");
  }
  const buf = Buffer.from(v, "base64url");
  if (buf.toString("base64url") !== v) {
    throw err("SCHEMA_INVALID", "base64url is not canonical");
  }
  return buf;
}

/** Parse a monetary U64 field; noncanonical → SCHEMA_INVALID, over range → AMOUNT_OVERFLOW. */
export function moneyU64(v: unknown, field: string): bigint {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw err("SCHEMA_INVALID", `${field} is not a canonical decimal U64`);
  }
  const n = BigInt(v);
  if (n > U64_MAX) throw err("AMOUNT_OVERFLOW", `${field} exceeds int64 range`);
  return n;
}

/** Non-monetary U64 field: range violation is SCHEMA_INVALID. */
export function strictU64(v: unknown, field: string): bigint {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw err("SCHEMA_INVALID", `${field} is not a canonical decimal U64`);
  }
  const n = BigInt(v);
  if (n > U64_MAX) throw err("SCHEMA_INVALID", `${field} exceeds int64 range`);
  return n;
}

export function safeInt(v: unknown, field: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > Number.MAX_SAFE_INTEGER) {
    throw err("SCHEMA_INVALID", `${field} is not a nonnegative safe integer`);
  }
  return v;
}

export function sortedUnique(arr: string[]): boolean {
  for (let i = 1; i < arr.length; i++) if (arr[i]! <= arr[i - 1]!) return false;
  return true;
}
