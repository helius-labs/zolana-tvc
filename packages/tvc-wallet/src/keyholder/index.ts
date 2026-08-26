import { TvcError } from "../protocol/error.js";
import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapKeyholderResult,
  BuildSolWithdrawalResult,
  BuildTransferResult,
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
  buildKeyholderSolWithdrawalOperation,
  buildKeyholderTransferOperation,
  type BuildKeyholderSolWithdrawalInput,
  type BuildKeyholderTransferInput,
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
 * The wallet's public shielded identity.
 *
 * The sealed key state is a replaceable cache, not the root of recovery: the
 * seed comes from a deterministic Turnkey signature over a fixed message, so
 * re-running bootstrap against a new release with a new Quorum key re-derives
 * the same identity and seals it afresh. Losing the blob is survivable; the
 * Turnkey wallet is the thing that must not be lost.
 *
 * That makes the identity comparison load-bearing. Pass the identity previously
 * observed and bootstrap will refuse to adopt a different one, which is what
 * separates a legitimate rotation from an enclave handing back a wallet that is
 * not yours.
 */
export type KeyholderIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type BootstrapKeyholderOptions = {
  /** The identity a previous bootstrap produced, when re-bootstrapping. */
  readonly expectedIdentity?: KeyholderIdentity;
};

export function keyholderIdentityOf(result: BootstrapKeyholderResult): KeyholderIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

function assertSameIdentity(
  observed: KeyholderIdentity,
  expected: KeyholderIdentity,
): void {
  if (
    observed.solanaAddress !== expected.solanaAddress ||
    observed.shieldedOwnerHash !== expected.shieldedOwnerHash ||
    observed.shieldedNullifierPublicKey !== expected.shieldedNullifierPublicKey ||
    observed.shieldedViewingPublicKey !== expected.shieldedViewingPublicKey
  ) {
    throw new TvcError("ShieldedIdentityChanged");
  }
}

/**
 * Client for the keyholder profile, where the attested application holds the
 * wallet's privacy keys and answers key-dependent questions.
 *
 * Every call except `bootstrapKeyholder` presents the sealed key state the
 * bootstrap returned. The browser cannot read that blob, cannot use it against
 * a different descriptor, and cannot replay it past a Quorum key rotation.
 *
 * Oracle sync calls remain client-relayed. The disposable development spend is
 * the explicit exception: TVC reaches the pinned indexer, RPC, and external
 * prover and sends that prover a plaintext witness containing the nullifier
 * secret. Transaction submission always remains with the caller.
 */
export type TvcKeyholderClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  /**
   * Derives the shielded identity and returns it sealed. The seed never leaves.
   *
   * Repeatable by design: this is also the recovery and Quorum-key-rotation
   * path. Pass `expectedIdentity` whenever an identity is already known, so a
   * re-bootstrap that produces a different wallet fails loudly instead of
   * silently orphaning the old one.
   */
  bootstrapKeyholder(
    connection: VerifiedConnection,
    options?: BootstrapKeyholderOptions,
  ): Promise<BootstrapKeyholderResult>;
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
  /**
   * Disposable devnet spend. TVC sends the plaintext witness, including the
   * nullifier secret, to the pinned external prover before signing.
   */
  buildTransfer(
    connection: VerifiedConnection,
    input: BuildKeyholderTransferInput,
  ): Promise<BuildTransferResult>;
  /**
   * Disposable devnet public SOL withdrawal. The public recipient is explicit
   * and is never reinterpreted as a registered shielded recipient.
   */
  buildSolWithdrawal(
    connection: VerifiedConnection,
    input: BuildKeyholderSolWithdrawalInput,
  ): Promise<BuildSolWithdrawalResult>;
  authorizeDefaultRingTransfer(
    connection: VerifiedConnection,
    input: AuthorizeDefaultRingTransferInput,
  ): Promise<AuthorizeDefaultRingTransferResult>;
};

export function createTvcKeyholderClient(config: TvcKeyholderClientConfig): TvcKeyholderClient {
  const session = createTvcSession(config);

  return {
    connectAndVerify: () => session.connectAndVerify(),

    async bootstrapKeyholder(connection, options) {
      const context = session.requireOperationContext(connection);
      const result = await executeKeyholderOperation(context, { type: "BootstrapKeyholder" });
      const target = context.operations.walletDescriptor.turnkey_signing_target;
      if (target.type !== "HdWalletAccount" || result.solana_address !== target.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      // A rotation must land on the same wallet. Without this, a new release
      // could return a different shielded identity and the browser would adopt
      // it, leaving the old balance unreachable and unremarked.
      if (options?.expectedIdentity) {
        assertSameIdentity(keyholderIdentityOf(result), options.expectedIdentity);
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

    buildTransfer: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        buildKeyholderTransferOperation(input),
        input.checkpoint,
      ),

    buildSolWithdrawal: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        buildKeyholderSolWithdrawalOperation(input),
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
  buildKeyholderSolWithdrawalOperation,
  buildKeyholderTransferOperation,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  executeKeyholderOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_VIEW_TAGS_PER_WINDOW,
} from "./operations.js";
export type {
  DecryptUtxosInput,
  DeriveViewTagsInput,
  BuildKeyholderSolWithdrawalInput,
  BuildKeyholderTransferInput,
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
  BuildSolWithdrawalResult,
  BuildTransferResult,
  BootProofResolver,
  DecryptUtxosResult,
  DeriveViewTagsResult,
  ResolveBootProofInput,
  VerifiedConnection,
};
