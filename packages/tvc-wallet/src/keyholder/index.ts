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
import { buildTvcWalletClient } from "./client-core.js";
import type {
  AuthorizeSpendInput,
  DecryptUtxosInput,
  DeriveViewTagsInput,
  FinalizeSpendInput,
  PrepareSppSpendInput,
  TvcWalletOperationsConfig,
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

export { shieldedIdentityOf } from "./client-core.js";

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
  /** Derives the wallet's stable view tags so the caller can query the indexer. */
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
  /** Prepares and proves an asset-conserving SPP transition for an ecosystem program. */
  prepareSppSpend(
    connection: VerifiedConnection,
    input: PrepareSppSpendInput,
  ): Promise<PreparedSppSpendResult>;
};

export function createTvcWalletClient(config: TvcWalletClientConfig): TvcWalletClient {
  return buildTvcWalletClient(createTvcSession(config));
}

export {
  checkpointFromBootstrapResult,
  finalizeSpendOperation,
  prepareSpendOperation,
  prepareSppSpendOperation,
  decryptUtxosOperation,
  deriveViewTagsOperation,
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_SPENDABLE_OUTPUTS,
} from "./operations.js";
export type {
  DecryptUtxosInput,
  DeriveViewTagsInput,
  AuthorizeSpendInput,
  AssetInput,
  FinalizeSpendInput,
  PrepareSppSpendInput,
  PrivateDomainInput,
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
  SppShapeV1,
  SpendableOutputV1,
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
