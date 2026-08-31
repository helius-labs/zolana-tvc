import { TvcError } from "./error.js";

export function encodeDecimalU64(value: bigint): string {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TvcError("InvalidDecimal");
  }
  return value.toString(10);
}

export function decodeDecimalU64(input: string): bigint {
  let value: bigint;
  try {
    value = BigInt(input);
  } catch {
    throw new TvcError("InvalidDecimal");
  }
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn || value.toString(10) !== input) {
    throw new TvcError("InvalidDecimal");
  }
  return value;
}
