import { TvcError } from "../protocol/error.js";
import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapKeyholderResult,
  DecryptUtxosResult,
  DeriveViewTagsResult,
} from "../protocol/types.js";
import type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "../client/connection.js";
import {
  authorizeDefaultRingTransferOperation,
  type AuthorizeDefaultRingTransferInput,
} from "../client/operations.js";
import { createTvcSession } from "../client/session.js";
import {
  decryptUtxosOperation,
  deriveViewTagsOperation,
  executeKeyholderOperation,
  type DecryptUtxosInput,
  type DeriveViewTagsInput,
  type TvcKeyholderOperationsConfig,
} from "./operations.js";

export type TvcKeyholderClientConfig = TvcConnectionConfig & {
  /** Descriptor-bound authority for the keyholder operations. */
  operations?: TvcKeyholderOperationsConfig;
};

/**
 * Client for the keyholder profile, where the attested application holds the
 * wallet's privacy keys and answers key-dependent questions, reaching no
 * network but Turnkey.
 *
 * Every call except `bootstrapKeyholder` presents the sealed key state the
 * bootstrap returned. The browser cannot read that blob, cannot use it against
 * a different descriptor, and cannot replay it past a Quorum key rotation.
 *
 * This client makes no network call of its own beyond TVC. Fetching from the
 * indexer, proving, and submitting to the chain stay with the caller, which is
 * what keeps new protocol actions cheap to add.
 */
export type TvcKeyholderClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  /** Derives the shielded identity and returns it sealed. The seed never leaves. */
  bootstrapKeyholder(connection: VerifiedConnection): Promise<BootstrapKeyholderResult>;
  /** Derives one window of view tags so the caller can query the indexer. */
  deriveViewTags(
    connection: VerifiedConnection,
    input: DeriveViewTagsInput,
  ): Promise<DeriveViewTagsResult>;
  /**
   * Decrypts one batch of ciphertexts.
   *
   * The result does not say which payloads are this wallet's, because it cannot:
   * the shielded-pool transport cipher has no authentication tag, so a payload
   * for another wallet decrypts to garbage rather than failing. Deserialize each
   * plaintext and compare the recovered owner against your own.
   */
  decryptUtxos(
    connection: VerifiedConnection,
    input: DecryptUtxosInput,
  ): Promise<DecryptUtxosResult>;
  authorizeDefaultRingTransfer(
    connection: VerifiedConnection,
    input: AuthorizeDefaultRingTransferInput,
  ): Promise<AuthorizeDefaultRingTransferResult>;
};

export function createTvcKeyholderClient(config: TvcKeyholderClientConfig): TvcKeyholderClient {
  const session = createTvcSession(config);

  return {
    connectAndVerify: () => session.connectAndVerify(),

    async bootstrapKeyholder(connection) {
      const context = session.requireOperationContext(connection);
      const result = await executeKeyholderOperation(context, { type: "BootstrapKeyholder" });
      const target = context.operations.walletDescriptor.turnkey_signing_target;
      if (target.type !== "HdWalletAccount" || result.solana_address !== target.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    },

    deriveViewTags: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        deriveViewTagsOperation(input),
        input.checkpoint,
      ),

    decryptUtxos: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        decryptUtxosOperation(input),
        input.checkpoint,
      ),

    authorizeDefaultRingTransfer: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        authorizeDefaultRingTransferOperation(input),
      ),
  };
}

export {
  checkpointFromKeyholderResult,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  executeKeyholderOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_VIEW_TAGS_PER_WINDOW,
} from "./operations.js";
export type {
  DecryptUtxosInput,
  DeriveViewTagsInput,
  KeyholderResultFor,
  TvcKeyholderOperationsConfig,
} from "./operations.js";
export { syncKeyholderWallet } from "./sync.js";
export type {
  KeyholderSyncInput,
  KeyholderSyncResult,
  KeyholderTaggedFetch,
} from "./sync.js";
export type {
  AuthorizeDefaultRingTransferInput,
  AuthorizeDefaultRingTransferResult,
  BootstrapKeyholderResult,
  BootProofResolver,
  DecryptUtxosResult,
  DeriveViewTagsResult,
  ResolveBootProofInput,
  VerifiedConnection,
};
