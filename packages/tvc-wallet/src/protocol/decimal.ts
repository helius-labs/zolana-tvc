import { TvcError } from "./error.js";

export function encodeDecimalU64(value: bigint): string {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new TvcError("InvalidDecimal");
  }
  return value.toString(10);
}

export function decodeDecimalU64(input: string): bigint {
  if (!input || input.startsWith("+") || input.startsWith("-")) {
    throw new TvcError("InvalidDecimal");
  }
  if (input.length > 1 && input.startsWith("0")) {
    throw new TvcError("InvalidDecimal");
  }
  if (!/^[0-9]+$/.test(input)) {
    throw new TvcError("InvalidDecimal");
  }
  const value = BigInt(input);
  if (value > 0xffff_ffff_ffff_ffffn) {
    throw new TvcError("InvalidDecimal");
  }
  return value;
}
