import { TvcError } from "../protocol/error.js";

export function endpointUrl(endpoint: URL, path: string): URL {
  const base = new URL(endpoint);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
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
