import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import { TvcError } from "./error.js";

export function encodeLowerHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function decodeLowerHex(input: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = hexToBytes(input);
  } catch {
    throw new TvcError("InvalidHex");
  }
  if (bytesToHex(decoded) !== input) throw new TvcError("InvalidHex");
  return decoded;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
