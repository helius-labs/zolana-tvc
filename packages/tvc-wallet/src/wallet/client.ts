import type { TvcConnectionConfig, VerifiedConnection } from "../client/connection.js";
import type { OperationsConfig } from "../client/operation-executor.js";
import { createTvcSession, type TvcSession } from "../client/session.js";
import { TvcError } from "../protocol/error.js";
import { requireHex } from "../protocol/hex.js";
import type {
  BootstrapResult,
  Checkpoint,
  DecryptOperation,
  DecryptedPayload,
  SpendOperation,
  SpendResult,
} from "../protocol/types.js";
import { checkDecrypt, checkSpend, executeOperation } from "./operations.js";

export type TvcClientConfig = TvcConnectionConfig & {
  /** Descriptor-bound authority for the wallet operations. */
  operations?: OperationsConfig;
};

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

export type BootstrapOptions = {
  readonly expectedIdentity?: ShieldedIdentity;
};

/**
 * The four enclave operations over one verified connection. Every call but
 * `bootstrap` presents the checkpoint the bootstrap returned; the enclave
 * cannot use it under another descriptor or past a Quorum key rotation.
 */
export type TvcClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  /** Derives the shielded identity and returns it sealed. Also the recovery path. */
  bootstrap(connection: VerifiedConnection, options?: BootstrapOptions): Promise<BootstrapResult>;
  /** The stable tags the wallet's outputs are published under. */
  viewTags(connection: VerifiedConnection, checkpoint: Checkpoint): Promise<readonly string[]>;
  /** Opens fetched outputs as this wallet's UTXOs, each with commitment and nullifier. */
  decrypt(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    input: Omit<DecryptOperation, "type">,
  ): Promise<readonly DecryptedPayload[]>;
  /** Proves and signs one spend over the given inputs. The caller submits. */
  spend(
    connection: VerifiedConnection,
    checkpoint: Checkpoint,
    input: Omit<SpendOperation, "type">,
  ): Promise<SpendResult>;
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
      const result = await executeOperation(context, { type: "Bootstrap" });
      if (result.solana_address !== context.operations.walletDescriptor.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      if (options?.expectedIdentity && !sameIdentity(identityOf(result), options.expectedIdentity)) {
        throw new TvcError("ShieldedIdentityChanged");
      }
      return result;
    },

    async viewTags(connection, checkpoint) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        { type: "ViewTags" },
        checkpoint,
      );
      return result.view_tags;
    },

    async decrypt(connection, checkpoint, input) {
      const result = await executeOperation(
        session.requireOperationContext(connection),
        checkDecrypt({ type: "Decrypt", ...input }),
        checkpoint,
      );
      return result.payloads;
    },

    spend: (connection, checkpoint, input) =>
      executeOperation(
        session.requireOperationContext(connection),
        checkSpend({ type: "Spend", ...input }),
        checkpoint,
      ),
  };
}

export function createTvcClient(config: TvcClientConfig): TvcClient {
  return clientFromSession(createTvcSession(config));
}
