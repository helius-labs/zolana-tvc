import type { Address, Bytes32, ShieldedAddress, Wallet, WalletUtxo } from "@heliuslabs/zolana";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { Checkpoint, SpendAction, SpendResult } from "../protocol/types.js";
import type { TvcClient } from "./client.js";
import { MAX_SPEND_INPUTS } from "./operations.js";
import { splAssets } from "./sync.js";

export type Action =
  | { readonly kind: "transfer"; readonly recipient: ShieldedAddress; readonly asset: Address; readonly amount: bigint }
  | { readonly kind: "withdrawal"; readonly recipient: Address; readonly asset: Address; readonly amount: bigint };

export type SpendInput = {
  readonly client: TvcClient;
  readonly connection: VerifiedConnection;
  readonly checkpoint: Checkpoint;
  /** A synced wallet; see `syncWallet`. */
  readonly wallet: Wallet;
  readonly action: Action;
  /** Exact input commitments. Omitted selects largest-first until covered. */
  readonly inputs?: readonly Bytes32[];
};

export type Spent = {
  /** The signed Solana transaction, ready to send. */
  readonly transaction: Uint8Array;
  readonly signature: string;
  readonly inputs: readonly WalletUtxo[];
  readonly result: SpendResult;
};

/** Rust `is_plain_utxo`: what the default rail can prove. */
export function isPlain(entry: WalletUtxo): boolean {
  return (
    entry.utxo.ringProgramId === undefined &&
    entry.ringDataHash === undefined &&
    entry.dataHash === undefined &&
    entry.utxo.data.isEmpty()
  );
}

/**
 * Largest first, so a fragmented balance covers with the fewest inputs; every
 * input on one tree.
 */
export function selectInputs(wallet: Wallet, asset: Address, amount: bigint): readonly WalletUtxo[] {
  const candidates = wallet
    .utxos()
    .filter((entry) => !entry.spent && entry.utxo.asset === asset && isPlain(entry))
    .sort((left, right) => (left.utxo.amount > right.utxo.amount ? -1 : left.utxo.amount < right.utxo.amount ? 1 : 0));
  const trees = new Set(candidates.map((entry) => entry.outputContext.tree));
  if (trees.size > 1) throw new TvcError("MultipleInputTrees");
  const selected: WalletUtxo[] = [];
  let available = 0n;
  for (const entry of candidates.slice(0, MAX_SPEND_INPUTS)) {
    selected.push(entry);
    available += entry.utxo.amount;
    if (available >= amount) return selected;
  }
  const total = candidates.reduce((sum, entry) => sum + entry.utxo.amount, 0n);
  throw new TvcError(total >= amount ? "TooManySpendInputs" : "InsufficientBalance");
}

function namedInputs(wallet: Wallet, commitments: readonly Bytes32[]): readonly WalletUtxo[] {
  const wanted = commitments.map(encodeLowerHex);
  const known = new Map(
    wallet.utxos().map((entry) => [encodeLowerHex(entry.outputContext.hash), entry] as const),
  );
  return wanted.map((hash) => {
    const entry = known.get(hash);
    if (!entry || entry.spent || !isPlain(entry)) throw new TvcError("InputUtxoUnavailable");
    return entry;
  });
}

/**
 * Proves and signs one spend through the enclave over inputs selected here.
 * The returned transaction is submitted by the caller; the next `syncWallet`
 * marks the inputs spent.
 */
export async function spend(input: SpendInput): Promise<Spent> {
  const { action } = input;
  if (action.amount <= 0n) throw new TvcError("InvalidSpendAmount");
  const inputs = input.inputs
    ? namedInputs(input.wallet, input.inputs)
    : selectInputs(input.wallet, action.asset, action.amount);
  const tree = inputs[0]?.outputContext.tree;
  if (!tree || inputs.some((entry) => entry.outputContext.tree !== tree)) {
    throw new TvcError("MultipleInputTrees");
  }
  const wire: SpendAction =
    action.kind === "transfer"
      ? {
          type: "Transfer",
          recipient: encodeLowerHex(action.recipient.toBytes()),
          asset: action.asset,
          amount: encodeDecimalU64(action.amount),
        }
      : {
          type: "Withdrawal",
          recipient: action.recipient,
          asset: action.asset,
          amount: encodeDecimalU64(action.amount),
        };
  const result = await input.client.spend(input.connection, input.checkpoint, {
    tree,
    inputs: inputs.map((entry) => ({
      asset: entry.utxo.asset,
      amount: encodeDecimalU64(entry.utxo.amount),
      blinding: encodeLowerHex(entry.utxo.blinding),
    })),
    action: wire,
    assets: splAssets(input.wallet.registry),
  });
  return Object.freeze({
    transaction: decodeLowerHex(result.signed_transaction),
    signature: result.signature,
    inputs,
    result,
  });
}
