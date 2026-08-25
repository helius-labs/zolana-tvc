import { sha256 } from "@noble/hashes/sha256";
import { TvcError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import { MAX_SOLANA_TRANSACTION_BYTES } from "../protocol/constants.js";

const DEFAULT_RING_INTENT_DOMAIN = "ZOLANA_TVC_DEFAULT_RING_TRANSFER_INTENT_V1";
const DEFAULT_RING_SOL_WITHDRAWAL_INTENT_DOMAIN =
  "ZOLANA_TVC_DEFAULT_RING_SOL_WITHDRAWAL_INTENT_V1";
const textEncoder = new TextEncoder();

export type DefaultRingTransferIntentInput = {
  readonly walletId: string;
  readonly solanaAddress: string;
  readonly recipient: string;
  readonly asset:
    | Readonly<{ type: "Sol" }>
    | Readonly<{ type: "Spl"; mint: string; assetId: bigint }>;
  readonly amount: bigint;
  readonly unsignedTransaction: Uint8Array;
};

export type DefaultRingSolWithdrawalIntentInput = {
  readonly walletId: string;
  readonly solanaAddress: string;
  readonly recipient: string;
  readonly amount: bigint;
  readonly unsignedTransaction: Uint8Array;
};

function assertIntentFields(input: {
  readonly walletId: string;
  readonly solanaAddress: string;
  readonly recipient: string;
  readonly amount: bigint;
  readonly unsignedTransaction: Uint8Array;
}): void {
  if (
    input.walletId.length === 0 ||
    input.solanaAddress.length === 0 ||
    input.recipient.length === 0 ||
    input.amount <= 0n ||
    input.amount > 18_446_744_073_709_551_615n ||
    input.unsignedTransaction.length === 0 ||
    input.unsignedTransaction.length > MAX_SOLANA_TRANSACTION_BYTES
  ) {
    throw new TvcError("InvalidTransferIntent");
  }
}

function digestIntent(domain: string, value: unknown): Uint8Array {
  const canonical = canonicalizeJsonValue(value);
  return sha256(
    Uint8Array.from([
      ...textEncoder.encode(domain),
      0,
      ...textEncoder.encode(canonical),
    ]),
  );
}

/** Commits user-visible transfer semantics to the exact unsigned transaction. */
export function defaultRingTransferIntentDigest(input: DefaultRingTransferIntentInput): Uint8Array {
  assertIntentFields(input);
  if (input.asset.type === "Spl" && input.asset.assetId <= 1n) {
    throw new TvcError("InvalidTransferIntent");
  }
  return digestIntent(DEFAULT_RING_INTENT_DOMAIN, {
    type: "zolana.tvc.default_ring_transfer_intent.v1",
    version: 1,
    wallet_id: input.walletId,
    solana_address: input.solanaAddress,
    recipient: input.recipient,
    asset:
      input.asset.type === "Sol"
        ? { type: "Sol" }
        : {
            type: "Spl",
            mint: input.asset.mint,
            asset_id: input.asset.assetId.toString(),
          },
    amount: input.amount.toString(),
    unsigned_transaction_digest: encodeLowerHex(sha256(input.unsignedTransaction)),
  });
}

/** Commits a public SOL withdrawal intent to the exact unsigned transaction. */
export function defaultRingSolWithdrawalIntentDigest(
  input: DefaultRingSolWithdrawalIntentInput,
): Uint8Array {
  assertIntentFields(input);
  return digestIntent(DEFAULT_RING_SOL_WITHDRAWAL_INTENT_DOMAIN, {
    type: "zolana.tvc.default_ring_sol_withdrawal_intent.v1",
    version: 1,
    wallet_id: input.walletId,
    solana_address: input.solanaAddress,
    recipient: input.recipient,
    asset: { type: "Sol" },
    amount: input.amount.toString(),
    unsigned_transaction_digest: encodeLowerHex(sha256(input.unsignedTransaction)),
  });
}
