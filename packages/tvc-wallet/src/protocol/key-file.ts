import { p256 } from "@noble/curves/p256";

import { TvcError } from "./error.js";
import { decodeLowerHex, encodeLowerHex } from "./hex.js";

/**
 * The P-256 secret from a key file (`{"private_key": hex}`, the Turnkey API
 * key layout), checked against `expectedPublicKey`. The caller wipes it after use.
 */
export function p256SecretFromKeyFile(
  keyJson: string,
  expectedPublicKey: string,
  codes: { readonly invalid: string; readonly wrong: string },
): Uint8Array {
  let stored: unknown;
  try {
    stored = JSON.parse(keyJson);
  } catch {
    throw new TvcError(codes.invalid, "not JSON");
  }
  const privateKey =
    typeof stored === "object" && stored !== null && "private_key" in stored
      ? stored.private_key
      : undefined;
  if (typeof privateKey !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new TvcError(codes.invalid, "private_key must be 32-byte hex");
  }
  const secret = decodeLowerHex(privateKey.replace(/^0x/, "").toLowerCase());
  if (encodeLowerHex(p256.getPublicKey(secret, false)) !== expectedPublicKey) {
    secret.fill(0);
    throw new TvcError(codes.wrong);
  }
  return secret;
}
