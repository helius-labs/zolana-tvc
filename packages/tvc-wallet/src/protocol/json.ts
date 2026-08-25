import { TvcError } from "./error.js";

function skipWs(text: string, i: number): number {
  while (i < text.length && /\s/.test(text[i] ?? "")) i += 1;
  return i;
}

function parseString(text: string, start: number): { value: string; next: number } {
  if (text[start] !== '"') throw new TvcError("InvalidCanonicalJson");
  let i = start + 1;
  let value = "";
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') return { value, next: i + 1 };
    if (ch === "\\") {
      const next = text[i + 1];
      const map: Record<string, string> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (next && map[next] !== undefined) {
        value += map[next];
        i += 2;
        continue;
      }
      if (next === "u") {
        const hex = text.slice(i + 2, i + 6);
        value += String.fromCharCode(Number.parseInt(hex, 16));
        i += 6;
        continue;
      }
      throw new TvcError("InvalidCanonicalJson");
    }
    value += ch;
    i += 1;
  }
  throw new TvcError("InvalidCanonicalJson");
}

function parseValue(text: string, start: number): { next: number } {
  let i = skipWs(text, start);
  const ch = text[i];
  if (ch === "{") {
    i += 1;
    i = skipWs(text, i);
    const seen = new Set<string>();
    if (text[i] === "}") return { next: i + 1 };
    while (i < text.length) {
      i = skipWs(text, i);
      const key = parseString(text, i);
      if (seen.has(key.value)) throw new TvcError("DuplicateJsonField");
      seen.add(key.value);
      i = skipWs(text, key.next);
      if (text[i] !== ":") throw new TvcError("InvalidCanonicalJson");
      const nested = parseValue(text, i + 1);
      i = skipWs(text, nested.next);
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "}") return { next: i + 1 };
      throw new TvcError("InvalidCanonicalJson");
    }
    throw new TvcError("InvalidCanonicalJson");
  }
  if (ch === "[") {
    i += 1;
    i = skipWs(text, i);
    if (text[i] === "]") return { next: i + 1 };
    while (i < text.length) {
      const nested = parseValue(text, i);
      i = skipWs(text, nested.next);
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "]") return { next: i + 1 };
      throw new TvcError("InvalidCanonicalJson");
    }
    throw new TvcError("InvalidCanonicalJson");
  }
  if (ch === '"') return { next: parseString(text, i).next };
  if (ch === "t" || ch === "f" || ch === "n" || ch === "-" || (ch !== undefined && ch >= "0" && ch <= "9")) {
    while (i < text.length && /[0-9eE+.\-truefalsn]/.test(text[i] ?? "")) i += 1;
    return { next: i };
  }
  throw new TvcError("InvalidCanonicalJson");
}

export function parseStrictJson<T>(text: string, allowedKeys?: readonly string[]): T {
  const scanned = parseValue(text, 0);
  if (skipWs(text, scanned.next) !== text.length) {
    throw new TvcError("InvalidCanonicalJson");
  }
  const value = JSON.parse(text) as T;
  if (allowedKeys && value && typeof value === "object" && !Array.isArray(value)) {
    for (const key of Object.keys(value as object)) {
      if (!allowedKeys.includes(key)) throw new TvcError("UnknownJsonField");
    }
  }
  return value;
}
