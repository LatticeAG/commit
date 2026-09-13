// Hashes, signature domains, and Ed25519 (§1.3).
//
// D(k,x) = SHA256hex( UTF8("LAGI-COMMIT/"+k+"/1") || 0x00 || J(x) )
// Sign kind k over body: Ed25519( UTF8("LAGI-COMMIT-SIGN/"+k+"/1") || 0x00 || HEXDECODE(D(k,body)) )

import crypto from "node:crypto";
import { jcsBytes } from "./json/jcs.ts";
import type { Json } from "./json/strict.ts";

export type SigKind =
  | "policy" | "envelope" | "approval" | "attestation" | "evidence" | "award"
  | "control" | "custody" | "custody_manifest" | "event" | "checkpoint"
  | "manifest" | "trust" | "migration";

export const SIG_KINDS: ReadonlySet<string> = new Set([
  "policy", "envelope", "approval", "attestation", "evidence", "award",
  "control", "custody", "custody_manifest", "event", "checkpoint",
  "manifest", "trust", "migration",
]);

const ED25519_L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;

// Low-order / non-canonical Ed25519 public keys (libsodium blacklist).
const SMALL_ORDER_KEYS = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a8",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
]);

export function sha256(data: Buffer | string): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

export function H(data: Buffer | string): string {
  return sha256(data).toString("hex");
}

export function D(kind: SigKind | string, body: Json): string {
  return H(Buffer.concat([Buffer.from(`LAGI-COMMIT/${kind}/1\0`, "utf8"), jcsBytes(body)]));
}

export function signPayload(kind: string, bodyDigest: string): Buffer {
  return Buffer.concat([
    Buffer.from(`LAGI-COMMIT-SIGN/${kind}/1\0`, "utf8"),
    Buffer.from(bodyDigest, "hex"),
  ]);
}

export function privateKeyFromSeed(seed32: Buffer): crypto.KeyObject {
  if (seed32.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  return crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed32]),
    format: "der",
    type: "pkcs8",
  });
}

export function publicKeyFromSeed(seed32: Buffer): string {
  const pub = crypto.createPublicKey(privateKeyFromSeed(seed32));
  return Buffer.from(pub.export({ format: "der", type: "spki" })).subarray(-32).toString("hex");
}

export function generateKeypair(): { secretKeyHex: string; publicKeyHex: string } {
  const seed = crypto.randomBytes(32);
  return { secretKeyHex: seed.toString("hex"), publicKeyHex: publicKeyFromSeed(seed) };
}

export function edSign(kind: string, body: Json, seed32: Buffer): string {
  const msg = signPayload(kind, D(kind, body));
  return crypto.sign(null, msg, privateKeyFromSeed(seed32)).toString("hex");
}

export function edSignMessage(kind: string, bodyDigest: string, seed32: Buffer): string {
  return crypto.sign(null, signPayload(kind, bodyDigest), privateKeyFromSeed(seed32)).toString("hex");
}

function publicKeyObject(pubHex: string): crypto.KeyObject {
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubHex, "hex")]),
    format: "der",
    type: "spki",
  });
}

/** Signature S scalar must be canonical (< group order L). */
export function isCanonicalSignature(sigHex: string): boolean {
  if (!/^[0-9a-f]{128}$/.test(sigHex)) return false;
  const s = Buffer.from(sigHex.slice(64), "hex");
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(s[i]!);
  return v < ED25519_L;
}

export function isEligiblePublicKey(pubHex: string): boolean {
  return !SMALL_ORDER_KEYS.has(pubHex);
}

/** Strict Ed25519 verify: canonical encodings, no small-order keys. */
export function edVerify(kind: string, body: Json, pubHex: string, sigHex: string): boolean {
  if (!isCanonicalSignature(sigHex) || !isEligiblePublicKey(pubHex)) return false;
  try {
    return crypto.verify(null, signPayload(kind, D(kind, body)), publicKeyObject(pubHex), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

export function edVerifyMessage(kind: string, bodyDigest: string, pubHex: string, sigHex: string): boolean {
  if (!isCanonicalSignature(sigHex) || !isEligiblePublicKey(pubHex)) return false;
  try {
    return crypto.verify(null, signPayload(kind, bodyDigest), publicKeyObject(pubHex), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

export function randomNonceHex(): string {
  return crypto.randomBytes(16).toString("hex");
}

export function randomId(prefix: string): string {
  return `${prefix}${crypto.randomBytes(16).toString("hex")}`;
}
