export {
  checkpointOf,
  clientFromSession,
  createTvcClient,
  identityOf,
  type BootstrapOptions,
  type ShieldedIdentity,
  type TvcClient,
  type TvcClientConfig,
} from "./wallet/client.js";
export { shieldedAddressOf } from "./wallet/identity.js";
export {
  MAX_DECRYPT_PAYLOADS_PER_BATCH,
  MAX_SPEND_INPUTS,
  checkDecrypt,
  checkSpend,
  executeOperation,
  type ResultFor,
} from "./wallet/operations.js";
export { splAssets, syncWallet, type SyncInput } from "./wallet/sync.js";
export {
  isPlain,
  selectInputs,
  spend,
  type Action,
  type SpendInput,
  type Spent,
} from "./wallet/spend.js";
export type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "./client/connection.js";
export type {
  AuthorizeTvcRequestInput,
  OperationsConfig,
  TvcOperationAuthorizer,
} from "./client/operation-executor.js";
export type { TvcTransport } from "./client/transport.js";
export { authorizedRequestMessage, createTvcOperationAuthorizer } from "./platform/authorizer.js";
export type { TvcRequestSigner } from "./platform/authorizer.js";
export type {
  BootstrapResult,
  Checkpoint,
  DecryptPayload,
  DecryptedPayload,
  FailureStage,
  OperationKind,
  SpendAction,
  SpendOperation,
  SpendResult,
  SplAsset,
  WalletDescriptor,
} from "./protocol/types.js";
export {
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
  verifyTurnkeyAppProof,
} from "./verify/index.js";
export type { QosIdentityPcrIndex, QosIdentityPcrs, VerifyBootProofInput } from "./verify/index.js";
export { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "./verify/release-policy.js";
