import { TvcError } from "./error.js";

const HEX = /^[0-9a-f]*$/;

export function encodeLowerHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function decodeLowerHex(input: string): Uint8Array {
  if (input.length % 2 !== 0 || input.startsWith("0x") || input.startsWith("0X") || !HEX.test(input)) {
    throw new TvcError("InvalidHex");
  }
  const out = new Uint8Array(input.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(input.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
