// Raw-input strict JSON parser for protocol JSON (§1.1).
//
// Rejects: invalid UTF-8, BOM, trailing bytes, duplicate object members at any
// depth, unpaired Unicode surrogates (escape or literal), and unescaped control
// characters — all INVALID_JSON. Number tokens are lexed with full JSON grammar
// then checked against the protocol rule (nonnegative integers, no fraction or
// exponent syntax, <= 2^53-1, -0 rejected): violations are SCHEMA_INVALID.

import { err } from "../errors.ts";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

class Parser {
  private i = 0;
  private readonly numLexemes: string[] = [];
  private readonly text: string;

  constructor(text: string) { this.text = text; }

  parse(): { value: Json; numbers: string[] } {
    this.ws();
    const value = this.value();
    this.ws();
    if (this.i !== this.text.length) throw err("INVALID_JSON", "trailing bytes after JSON value");
    for (const lexeme of this.numLexemes) this.checkNumber(lexeme);
    return { value, numbers: this.numLexemes };
  }

  private ws(): void {
    while (this.i < this.text.length) {
      const c = this.text.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private peek(): number {
    if (this.i >= this.text.length) throw err("INVALID_JSON", "unexpected end of input");
    return this.text.charCodeAt(this.i);
  }

  private value(): Json {
    const c = this.peek();
    if (c === 0x7b) return this.object(); // {
    if (c === 0x5b) return this.array(); // [
    if (c === 0x22) return this.string(); // "
    if (c === 0x74) return this.literal("true", true);
    if (c === 0x66) return this.literal("false", false);
    if (c === 0x6e) return this.literal("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    throw err("INVALID_JSON", `unexpected character 0x${c.toString(16)}`);
  }

  private literal(word: string, v: Json): Json {
    if (this.text.startsWith(word, this.i)) {
      this.i += word.length;
      return v;
    }
    throw err("INVALID_JSON", `invalid literal`);
  }

  private number(): number {
    const start = this.i;
    if (this.text.charCodeAt(this.i) === 0x2d) this.i++; // -
    if (this.peek() === 0x30) {
      this.i++;
    } else {
      this.digits();
    }
    if (this.text.charCodeAt(this.i) === 0x2e) {
      // .
      this.i++;
      this.digits();
    }
    const c = this.text.charCodeAt(this.i);
    if (c === 0x65 || c === 0x45) {
      // e E
      this.i++;
      const s = this.text.charCodeAt(this.i);
      if (s === 0x2b || s === 0x2d) this.i++; // + -
      this.digits();
    }
    const lexeme = this.text.slice(start, this.i);
    this.numLexemes.push(lexeme);
    return Number(lexeme);
  }

  private digits(): void {
    const c = this.peek();
    if (c < 0x30 || c > 0x39) throw err("INVALID_JSON", "expected digit");
    while (this.i < this.text.length) {
      const d = this.text.charCodeAt(this.i);
      if (d >= 0x30 && d <= 0x39) this.i++;
      else break;
    }
  }

  private string(): string {
    this.i++; // opening "
    let out = "";
    while (true) {
      if (this.i >= this.text.length) throw err("INVALID_JSON", "unterminated string");
      const c = this.text.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c === 0x5c) {
        // backslash escape
        this.i++;
        if (this.i >= this.text.length) throw err("INVALID_JSON", "unterminated escape");
        const e = this.text.charCodeAt(this.i);
        this.i++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            const hi = this.hex4();
            if (hi >= 0xd800 && hi <= 0xdbff) {
              if (this.text.charCodeAt(this.i) !== 0x5c || this.text.charCodeAt(this.i + 1) !== 0x75) {
                throw err("INVALID_JSON", "unpaired high surrogate escape");
              }
              this.i += 2;
              const lo = this.hex4();
              if (lo < 0xdc00 || lo > 0xdfff) throw err("INVALID_JSON", "unpaired high surrogate escape");
              out += String.fromCharCode(hi, lo);
            } else if (hi >= 0xdc00 && hi <= 0xdfff) {
              throw err("INVALID_JSON", "unpaired low surrogate escape");
            } else {
              out += String.fromCharCode(hi);
            }
            break;
          }
          default:
            throw err("INVALID_JSON", "invalid escape sequence");
        }
        continue;
      }
      if (c < 0x20) throw err("INVALID_JSON", "unescaped control character in string");
      if (c >= 0xd800 && c <= 0xdbff) {
        const lo = this.text.charCodeAt(this.i + 1);
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          out += this.text.slice(this.i, this.i + 2);
          this.i += 2;
          continue;
        }
        throw err("INVALID_JSON", "unpaired high surrogate");
      }
      if (c >= 0xdc00 && c <= 0xdfff) throw err("INVALID_JSON", "unpaired low surrogate");
      out += this.text[this.i]!;
      this.i++;
    }
  }

  private hex4(): number {
    if (this.i + 4 > this.text.length) throw err("INVALID_JSON", "short unicode escape");
    const s = this.text.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(s)) throw err("INVALID_JSON", "invalid unicode escape");
    this.i += 4;
    return parseInt(s, 16);
  }

  private array(): Json[] {
    this.i++; // [
    const arr: Json[] = [];
    this.ws();
    if (this.text.charCodeAt(this.i) === 0x5d) {
      this.i++;
      return arr;
    }
    while (true) {
      arr.push(this.value());
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        this.ws();
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        return arr;
      }
      throw err("INVALID_JSON", "expected , or ] in array");
    }
  }

  private object(): { [k: string]: Json } {
    this.i++; // {
    const obj: { [k: string]: Json } = {};
    this.ws();
    if (this.text.charCodeAt(this.i) === 0x7d) {
      this.i++;
      return obj;
    }
    while (true) {
      this.ws();
      if (this.peek() !== 0x22) throw err("INVALID_JSON", "object key must be a string");
      const key = this.string();
      if (Object.hasOwn(obj, key)) throw err("INVALID_JSON", `duplicate member "${key}"`);
      this.ws();
      if (this.peek() !== 0x3a) throw err("INVALID_JSON", "expected : in object");
      this.i++;
      this.ws();
      obj[key] = this.value();
      this.ws();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        return obj;
      }
      throw err("INVALID_JSON", "expected , or } in object");
    }
  }

  private checkNumber(lexeme: string): void {
    if (!/^(0|[1-9][0-9]*)$/.test(lexeme)) {
      throw err("SCHEMA_INVALID", `number token ${lexeme} is not a nonnegative integer`);
    }
    const v = BigInt(lexeme);
    if (v > 9007199254740991n) throw err("SCHEMA_INVALID", "number token exceeds 2^53-1");
  }
}

/**
 * Parse strict protocol JSON from raw text or bytes.
 * Throws CommitError INVALID_JSON (structure) or SCHEMA_INVALID (number tokens).
 */
export function parseStrictJson(input: string | Buffer | Uint8Array): Json {
  let text: string;
  if (typeof input === "string") {
    text = input;
    if (text.charCodeAt(0) === 0xfeff) throw err("INVALID_JSON", "byte order mark present");
  } else {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
    if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
      throw err("INVALID_JSON", "byte order mark present");
    }
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
      throw err("INVALID_JSON", "input is not valid UTF-8");
    }
  }
  return new Parser(text).parse().value;
}

/** Artifact structural bounds: depth <= 16, <= 256 members per object (§1.1). */
export function checkArtifactBounds(value: Json, depth = 0): void {
  if (depth > MAX_ARTIFACT_DEPTH_CHECK) throw err("LIMIT_EXCEEDED", "artifact depth exceeds 16");
  if (Array.isArray(value)) {
    for (const item of value) checkArtifactBounds(item, depth + 1);
  } else if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length > 256) throw err("LIMIT_EXCEEDED", "object member count exceeds 256");
    for (const k of keys) checkArtifactBounds(value[k]!, depth + 1);
  }
}
const MAX_ARTIFACT_DEPTH_CHECK = 16;
