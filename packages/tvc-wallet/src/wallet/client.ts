import type { VerifiedConnection } from "../client/connection.js";
import { createTvcSession, type TvcSession, type TvcSessionConfig } from "../client/session.js";
import { TvcError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import type {
  BootstrapResult,
  Checkpoint,
  DecryptItem,
  DeriveItem,
  ProverRequest,
  TransactionKeyItem,
} from "../protocol/types.js";
import {
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
  type OperationOptions,
} from "./operations.js";

export type TvcClientConfig = TvcSessionConfig;

/**
 * The wallet's public shielded identity.
 *
 * The sealed key state is a replaceable cache, not the root of recovery: the
 * seed is a deterministic Turnkey signature over a fixed message, so
 * re-running bootstrap against a new release re-derives the same identity.
 * Pass the identity observed before, and bootstrap refuses to adopt another.
 */
export type ShieldedIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type BootstrapOptions = OperationOptions & {
  readonly expectedIdentity?: ShieldedIdentity;
};

/**
 * The five enclave operations over one verified connection, on the wire's
 * terms. `TvcKeys` is the same surface as the Zolana SDK's `WalletKeys`, which
 * is what an application normally holds. Every call but `bootstrap` presents
 * the checkpoint the bootstrap returned; the enclave cannot use it under
 * another descriptor or past a Quorum key rotation.
 */
export type TvcClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  /** Derives the shielded identity and returns it sealed. Also the recovery path. */
  bootstrap(connection: VerifiedConnection, options?: BootstrapOptions): Promise<BootstrapResult>;
  /** Opens each ciphertext with the wallet's viewing key; one plaintext per item. */
  decrypt(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    items: readonly DecryptItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Derives nullifiers and merge values; one value per item. */
  derive(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    items: readonly DeriveItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Mints per-transaction viewing secrets; one per item. */
  transactionKeys(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    items: readonly TransactionKeyItem[],
    options?: OperationOptions,
  ): Promise<readonly string[]>;
  /** Completes the prover request with the nullifier secret and returns the prover's answer. */
  prove(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    request: ProverRequest,
    options?: OperationOptions,
  ): Promise<unknown>;
};

export function identityOf(result: BootstrapResult): ShieldedIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

export function checkpointOf(result: BootstrapResult): Checkpoint {
  requireHex(result.sealed_wallet_state);
  return Object.freeze({ sealedWalletState: result.sealed_wallet_state });
}

function sameIdentity(a: ShieldedIdentity, b: ShieldedIdentity): boolean {
  return (
    a.solanaAddress === b.solanaAddress &&
    a.shieldedOwnerHash === b.shieldedOwnerHash &&
    a.shieldedNullifierPublicKey === b.shieldedNullifierPublicKey &&
    a.shieldedViewingPublicKey === b.shieldedViewingPublicKey
  );
}

export function clientFromSession(session: TvcSession): TvcClient {
  return {
    connectAndVerify: () => session.connectAndVerify(),

    async bootstrap(connection, options) {
      const context = session.requireOperationContext(connection);
      const result = await executeOperation(context, { type: "Bootstrap" }, undefined, options);
      if (result.solana_address !== context.operations.walletDescriptor.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      if (options?.expectedIdentity && !sameIdentity(identityOf(result), options.expectedIdentity)) {
        throw new TvcError("ShieldedIdentityChanged");
      }
      return result;
    },

    async decrypt(connection, checkpoint, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkDecrypt({ type: "Decrypt", items }),
        checkpoint,
        options,
      );
      return result.plaintexts;
    },

    async derive(connection, checkpoint, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkDerive({ type: "Derive", items }),
        checkpoint,
        options,
      );
      return result.values;
    },

    async transactionKeys(connection, checkpoint, items, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkTransactionKeys({ type: "TransactionKeys", items }),
        checkpoint,
        options,
      );
      return result.secrets;
    },

    async prove(connection, checkpoint, request, options) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkProve({ type: "Prove", request }),
        checkpoint,
        options,
      );
      return result.proof;
    },
  };
}

export function createTvcClient(config: TvcClientConfig): TvcClient {
  return clientFromSession(createTvcSession(config));
}
