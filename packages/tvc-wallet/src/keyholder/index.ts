import { TvcError } from "../protocol/error.js";
import type {
  BootstrapKeyholderResult,
  AuthorizeSpendResult,
  FinalizedSpendResult,
  PreparedExactSpendResult,
  PreparedSppSpendResult,
  PreparedSpendResult,
  DecryptUtxosResult,
  DeriveViewTagsResult,
} from "../protocol/types.js";
import type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "../client/connection.js";
import { createTvcSession } from "../client/session.js";
import {
  decryptUtxosOperation,
  deriveViewTagsOperation,
  finalizeSpendOperation,
  finalizeSppSpendOperation,
  prepareSpendOperation,
  prepareSppSpendOperation,
  type AuthorizeSpendInput,
  executeKeyholderOperation,
  type DecryptUtxosInput,
  type DeriveViewTagsInput,
  type FinalizeSpendInput,
  type FinalizeSppSpendInput,
  type PrepareSppSpendInput,
  type TvcWalletOperationsConfig,
} from "./operations.js";

export type TvcWalletClientConfig = TvcConnectionConfig & {
  /** Descriptor-bound authority for the keyholder operations. */
  operations?: TvcWalletOperationsConfig;
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
export type ShieldedIdentity = {
  readonly solanaAddress: string;
  readonly shieldedOwnerHash: string;
  readonly shieldedNullifierPublicKey: string;
  readonly shieldedViewingPublicKey: string;
};

export type BootstrapWalletOptions = {
  /** The identity a previous bootstrap produced, when re-bootstrapping. */
  readonly expectedIdentity?: ShieldedIdentity;
};

export function shieldedIdentityOf(result: BootstrapKeyholderResult): ShieldedIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

function assertSameIdentity(
  observed: ShieldedIdentity,
  expected: ShieldedIdentity,
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
export type TvcWalletClient = {
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
    options?: BootstrapWalletOptions,
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
   * High-level convenience flow that performs Prepare followed by Finalize.
   * The first request proves and seals the exact unsigned transaction; the
   * second asks Turnkey to sign it once as shielded owner and fee payer.
   *
   * Disposable devnet only. The pinned external prover receives the plaintext
   * witness, including the nullifier secret.
   */
  authorizeSpend(
    connection: VerifiedConnection,
    input: AuthorizeSpendInput,
  ): Promise<AuthorizeSpendResult>;
  /** Proves a spend and seals its exact unsigned transaction without signing. */
  prepareSpend(
    connection: VerifiedConnection,
    input: AuthorizeSpendInput,
  ): Promise<PreparedExactSpendResult>;
  /** Uses the short-lived capsule to sign the exact prepared transaction once. */
  finalizeSpend(
    connection: VerifiedConnection,
    input: FinalizeSpendInput,
  ): Promise<FinalizedSpendResult>;
  /** Prepares and proves a private-only SPP transition for an ecosystem program. */
  prepareSppSpend(
    connection: VerifiedConnection,
    input: PrepareSppSpendInput,
  ): Promise<PreparedSppSpendResult>;
  /** Finalizes one outer instruction carrying the exact prepared SPP transition. */
  finalizeSppSpend(
    connection: VerifiedConnection,
    input: FinalizeSppSpendInput,
  ): Promise<FinalizedSpendResult>;
};

function exactPrepared(result: PreparedSpendResult): PreparedExactSpendResult {
  if (result.prepared.type !== "ExactTransaction") {
    throw new TvcError("ReleaseBindingMismatch", "expected an exact transaction");
  }
  return result as PreparedExactSpendResult;
}

function sppPrepared(result: PreparedSpendResult): PreparedSppSpendResult {
  if (result.prepared.type !== "Spp") {
    throw new TvcError("ReleaseBindingMismatch", "expected an SPP transition");
  }
  return result as PreparedSppSpendResult;
}

function rethrowSpendPhase(phase: "Prepare" | "Finalize", error: unknown): never {
  if (error instanceof TvcError) {
    const prefix = `${error.code}: `;
    const detail = error.message.startsWith(prefix)
      ? error.message.slice(prefix.length)
      : error.message === error.code
        ? undefined
        : error.message;
    throw new TvcError(error.code, detail ? `${phase}: ${detail}` : phase);
  }
  throw error;
}

export function createTvcWalletClient(config: TvcWalletClientConfig): TvcWalletClient {
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
        assertSameIdentity(shieldedIdentityOf(result), options.expectedIdentity);
      }
      return result;
    },

    deriveViewTags: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        deriveViewTagsOperation(),
        input.checkpoint,
      ),

    decryptUtxos: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        decryptUtxosOperation(input),
        input.checkpoint,
      ),

    async authorizeSpend(connection, input) {
      const context = session.requireOperationContext(connection);
      let prepared: PreparedSpendResult;
      try {
        prepared = await executeKeyholderOperation(
          context,
          prepareSpendOperation(input),
          input.checkpoint,
        );
      } catch (error) {
        rethrowSpendPhase("Prepare", error);
      }
      try {
        return await executeKeyholderOperation(
          context,
          finalizeSpendOperation({
            checkpoint: input.checkpoint,
            sealedAuthorizationCapsule: prepared.sealed_authorization_capsule,
            unsignedTransaction: exactPrepared(prepared).prepared.unsigned_transaction,
          }),
          input.checkpoint,
        );
      } catch (error) {
        rethrowSpendPhase("Finalize", error);
      }
    },

    async prepareSpend(connection, input) {
      const result = await executeKeyholderOperation(
        session.requireOperationContext(connection),
        prepareSpendOperation(input),
        input.checkpoint,
      );
      return exactPrepared(result);
    },

    finalizeSpend: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        finalizeSpendOperation(input),
        input.checkpoint,
      ),

    async prepareSppSpend(connection, input) {
      const result = await executeKeyholderOperation(
        session.requireOperationContext(connection),
        prepareSppSpendOperation(input),
        input.checkpoint,
      );
      return sppPrepared(result);
    },

    finalizeSppSpend: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        finalizeSppSpendOperation(input),
        input.checkpoint,
      ),
  };
}

export {
  checkpointFromBootstrapResult,
  finalizeSpendOperation,
  finalizeSppSpendOperation,
  prepareSpendOperation,
  prepareSppSpendOperation,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
} from "./operations.js";
export type {
  DecryptUtxosInput,
  DeriveViewTagsInput,
  AuthorizeSpendInput,
  FinalizeSpendInput,
  FinalizeSppSpendInput,
  PrepareSppSpendInput,
  SpendSettlementInput,
  TvcWalletOperationsConfig,
} from "./operations.js";
export {
  createTvcOperationAuthorizer,
  authorizedRequestMessage,
} from "../platform/authorizer.js";
export type { TvcRequestSigner } from "../platform/authorizer.js";
export type {
  AuthorizeTvcRequestInput,
  TvcOperationAuthorizer,
} from "../client/operation-executor.js";
export { syncTvcWallet } from "./sync.js";
export type {
  TvcWalletSyncInput,
  TvcWalletSyncResult,
  TvcWalletFetchedPayload,
  TvcWalletSyncPayload,
  TvcWalletTaggedFetch,
} from "./sync.js";
export type {
  BootstrapKeyholderResult,
  AuthorizeSpendResult,
  FinalizedSpendResult,
  PreparedSpendResult,
  PreparedExactSpendResult,
  PreparedSppSpendResult,
  BootProofResolver,
  DecryptUtxosResult,
  DeriveViewTagsResult,
  ResolveBootProofInput,
  VerifiedConnection,
};
export type {
  AssetV1,
  PreparedSpendV1,
  SolanaAccountMetaV1,
  SolanaInstructionV1,
  SppMessageV1,
  SppPlanInputV1,
  SppPlanOutputV1,
  SppPlanV1,
  SppPublicEffectsV1,
  SppShapeV1,
} from "../protocol/types.js";
export {
  classifyTurnkeyPolicyEvidence,
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
} from "../verify/index.js";
export type {
  QosIdentityPcrIndex,
  QosIdentityPcrs,
  VerifyBootProofInput,
} from "../verify/index.js";
export {
  bindDiscoveryToPolicy,
  verifySignedReleasePolicy,
} from "../verify/release-policy.js";
export type { TvcTransport } from "../client/transport.js";
