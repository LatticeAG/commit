// `commit sign` — offline signer for approval/attestation/award/control/
// migration bodies. Persistent slot refusal: a durable journal refuses to
// sign a second distinct body for the same (key_id, kind, decision slot).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { D, edSignMessage } from "./crypto.ts";
import { err } from "./errors.ts";
import { jcsBytes } from "./json/jcs.ts";
import { parseStrictJson, type Json } from "./json/strict.ts";
import { isId } from "./scalars.ts";
import { validApprovalBody, validAttestationBody, validAwardBody, validControlBody, validMigration } from "./schema.ts";

const SIGNABLE = new Set(["approval", "attestation", "award", "control", "migration"]);

function slotScope(kind: string, body: Record<string, unknown>): string {
  const parts = [kind];
  for (const f of ["commit_id", "envelope_hash", "clause_id", "case_id", "source_head"]) {
    const v = body[f];
    if (typeof v === "string") parts.push(v);
  }
  return parts.join(":");
}

/** Sign `body` under kind; returns {key_id, sig}. Refuses slot conflicts durably. */
export function signBody(opts: {
  kind: string;
  bodyRaw: unknown;
  keyId: string;
  seed: Buffer;
  journalDir: string;
}): { key_id: string; sig: string } {
  const { kind, keyId, seed, journalDir } = opts;
  if (!SIGNABLE.has(kind)) throw err("SCHEMA_INVALID", `kind ${kind} is not signable by this tool`);
  if (!isId(keyId)) throw err("SCHEMA_INVALID", "key_id invalid");

  let body: Record<string, unknown>;
  switch (kind) {
    case "approval": body = validApprovalBody(opts.bodyRaw) as unknown as Record<string, unknown>; break;
    case "attestation": body = validAttestationBody(opts.bodyRaw) as unknown as Record<string, unknown>; break;
    case "award": body = validAwardBody(opts.bodyRaw) as unknown as Record<string, unknown>; break;
    case "control": body = validControlBody(opts.bodyRaw) as unknown as Record<string, unknown>; break;
    case "migration": body = validMigration(opts.bodyRaw) as unknown as Record<string, unknown>; break;
    default: throw err("SCHEMA_INVALID", "unreachable");
  }

  const digest = D(kind, body as unknown as Json);
  const slot = slotScope(kind, body);
  const dir = join(journalDir, keyId);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const slotFile = join(dir, Buffer.from(slot).toString("hex") + ".slot");
  const rec = { digest, sig: "" };
  if (existsSync(slotFile)) {
    const prior = JSON.parse(readFileSync(slotFile, "utf8")) as { digest: string; sig: string };
    if (prior.digest !== digest) {
      throw err("SIGNATURE_INVALID", "slot conflict: this key already signed a different body for this decision slot");
    }
    return { key_id: keyId, sig: prior.sig };
  }
  const sig = edSignMessage(kind, digest, seed);
  rec.sig = sig;
  writeFileSync(slotFile, jcsBytes({ slot, key_id: keyId, digest, sig } as unknown as Json), { mode: 0o600 });
  return { key_id: keyId, sig };
}
