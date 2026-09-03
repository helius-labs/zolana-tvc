import { TvcError } from "../protocol/error.js";

const td = new TextDecoder("utf-8", { fatal: true });

export function endpointUrl(endpoint: URL, path: string): URL {
  const base = new URL(endpoint);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
}

/**
 * Reads an untrusted response body without first buffering an attacker-chosen
 * amount of data. TVC responses are canonical JSON, so malformed UTF-8 is a
 * protocol error rather than text that may be repaired with U+FFFD.
 */
export async function readBoundedText(response: Response, maxBytes: bigint): Promise<string> {
  if (maxBytes <= 0n || maxBytes > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TvcError("ResponseTooLarge");
  }
  const limit = Number(maxBytes);
  if (!response.body) return response.text();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) throw new TvcError("ResponseTooLarge");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return td.decode(body);
  } catch {
    throw new TvcError("InvalidCanonicalJson");
  }
}

/**
 * Requires the object's own keys to be exactly `expected`. Rejecting only
 * unknown keys would let a peer omit a field and surface it downstream as an
 * `undefined` read rather than a protocol error.
 */
export function assertExactObjectKeys(
  value: unknown,
  expected: readonly string[],
  invalidObjectCode: string,
): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError(invalidObjectCode);
  }
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!expected.includes(key)) throw new TvcError("UnknownJsonField");
  }
  // serde surfaces a missing required field as a plain deserialization
  // failure, which the Rust protocol maps to InvalidCanonicalJson.
  if (keys.length !== expected.length) throw new TvcError("InvalidCanonicalJson");
}
