import {
  ViewingKey,
  type Bytes32,
  type DecryptRequest,
  type DeriveRequest,
  type P256PublicKey,
  type ShieldedAddress,
  type WalletKeys,
} from "@heliuslabs/zolana";
import {
  mergeProverRequestBody,
  parseProof,
  proverRequestBody,
  type MergeInputs,
  type Proof,
  type ProverInputs,
} from "@heliuslabs/zolana/client";
import type { TransactionKeyRequest } from "@heliuslabs/zolana/transaction";

import type { VerifiedConnection } from "../client/connection.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type {
  Checkpoint,
  DecryptItem,
  DecryptLabel,
  DeriveItem,
  TransactionKeyItem,
} from "../protocol/types.js";
import type { ShieldedIdentity, TvcClient } from "./client.js";
import { shieldedAddressOf } from "./identity.js";
import { MAX_ITEMS_PER_BATCH } from "./operations.js";

export type TvcKeysInput = {
  readonly client: TvcClient;
  readonly connection: VerifiedConnection;
  /** The sealed key state `bootstrap` returned. */
  readonly checkpoint: Checkpoint;
  /** The identity `bootstrap` returned; see `shieldedAddressOf`. */
  readonly identity: ShieldedIdentity;
};

const LABELS: Record<DecryptRequest["label"], DecryptLabel> = {
  transfer: "Transfer",
  ringDeposit: "RingDeposit",
};

/**
 * The Zolana SDK's `WalletKeys`, answered by the enclave. Hand it to
 * `syncWallet`, `buildTransferTransaction`, and every other SDK flow in place
 * of `LocalKeys`: each SDK request becomes one enclave operation per batch,
 * and the proof witness is completed with the nullifier secret inside the
 * enclave. Nothing here signs; the application's Solana signer does.
 */
export class TvcKeys implements WalletKeys {
  readonly #client: TvcClient;
  readonly #connection: VerifiedConnection;
  readonly #checkpoint: Checkpoint;
  readonly #address: ShieldedAddress;

  constructor(input: TvcKeysInput) {
    this.#client = input.client;
    this.#connection = input.connection;
    this.#checkpoint = input.checkpoint;
    this.#address = shieldedAddressOf(input.identity);
  }

  address(): ShieldedAddress {
    return this.#address;
  }

  viewingPublicKeys(): readonly P256PublicKey[] {
    return [this.#address.viewingPublicKey];
  }

  async decrypt(requests: readonly DecryptRequest[]): Promise<readonly Uint8Array[]> {
    const plaintexts = await this.#batched(
      requests.map(
        (request): DecryptItem => ({
          ciphertext: encodeLowerHex(request.ciphertext),
          viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
          transaction_viewing_public_key: encodeLowerHex(request.txViewingPublicKey.toBytes()),
          salt: encodeLowerHex(request.salt),
          slot_index: String(request.slotIndex),
          label: LABELS[request.label],
        }),
      ),
      (items) => this.#client.decrypt(this.#connection, this.#checkpoint, items),
    );
    return plaintexts.map(decodeLowerHex);
  }

  async derive(requests: readonly DeriveRequest[]): Promise<readonly Bytes32[]> {
    const values = await this.#batched(
      requests.map((request): DeriveItem => {
        switch (request.kind) {
          case "nullifier":
            return {
              kind: "Nullifier",
              utxo_hash: encodeLowerHex(request.utxoHash),
              blinding: encodeLowerHex(request.blinding),
            };
          case "mergeDummyNullifier":
            return {
              kind: "MergeDummyNullifier",
              first_nullifier: encodeLowerHex(request.firstNullifier),
              slot_index: encodeDecimalU64(BigInt(request.slotIndex)),
            };
          case "mergeOutputBlinding":
            return {
              kind: "MergeOutputBlinding",
              first_nullifier: encodeLowerHex(request.firstNullifier),
            };
        }
      }),
      (items) => this.#client.derive(this.#connection, this.#checkpoint, items),
    );
    return values.map((value) => decodeLowerHex(value) as Bytes32);
  }

  async transactionKeys(requests: readonly TransactionKeyRequest[]): Promise<readonly ViewingKey[]> {
    const secrets = await this.#batched(
      requests.map(
        (request): TransactionKeyItem => ({
          viewing_public_key: encodeLowerHex(request.viewingPublicKey.toBytes()),
          first_nullifier: encodeLowerHex(request.firstNullifier),
        }),
      ),
      (items) => this.#client.transactionKeys(this.#connection, this.#checkpoint, items),
    );
    const keys: ViewingKey[] = [];
    try {
      for (const secret of secrets) keys.push(ViewingKey.fromBytes(decodeLowerHex(secret) as Bytes32));
    } catch (cause) {
      for (const key of keys) key.destroy();
      throw cause;
    }
    return keys;
  }

  async prove(inputs: ProverInputs): Promise<Proof> {
    return parseProof(
      await this.#client.prove(this.#connection, this.#checkpoint, proverRequestBody(inputs)),
    );
  }

  async proveMerge(inputs: MergeInputs): Promise<Proof> {
    return parseProof(
      await this.#client.prove(this.#connection, this.#checkpoint, mergeProverRequestBody(inputs)),
    );
  }

  /** One enclave call per `MAX_ITEMS_PER_BATCH` items, answers in request order. */
  async #batched<TItem, TAnswer>(
    items: readonly TItem[],
    call: (batch: readonly TItem[]) => Promise<readonly TAnswer[]>,
  ): Promise<readonly TAnswer[]> {
    const answers: TAnswer[] = [];
    for (let start = 0; start < items.length; start += MAX_ITEMS_PER_BATCH) {
      const batch = items.slice(start, start + MAX_ITEMS_PER_BATCH);
      const answer = await call(batch);
      if (answer.length !== batch.length) throw new Error("BatchMismatch");
      answers.push(...answer);
    }
    return answers;
  }
}
