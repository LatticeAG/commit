// RFC 8785 (JCS) canonicalization J(x).
//
// Object keys are ordered by UTF-16 code units (JavaScript's default string
// sort). Numbers serialize per ECMAScript Number::toString — identical to
// JSON.stringify for every finite double, which is exactly what RFC 8785
// requires. Strings are emitted with the minimal JSON escape set, which is the
// JCS escape set; unpaired surrogates never reach this layer because the raw
// parser rejects them.

import type { Json } from "./strict.ts";

export function jcs(value: Json): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(jcs).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(value[k]!)).join(",") + "}";
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error("JCS cannot serialize non-finite number");
  return JSON.stringify(n);
}

export function jcsBytes(value: Json): Buffer {
  return Buffer.from(jcs(value), "utf8");
}
