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
export { TvcKeys, type TvcKeysInput } from "./wallet/keys.js";
export { snapshotCipher } from "./wallet/snapshot.js";
export {
  MAX_ITEMS_PER_BATCH,
  MAX_PROVE_INPUTS,
  checkDecrypt,
  checkDerive,
  checkProve,
  checkTransactionKeys,
  executeOperation,
  type ResultFor,
} from "./wallet/operations.js";
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
  DecryptItem,
  DecryptLabel,
  DeriveItem,
  FailureStage,
  OperationKind,
  ProverRequest,
  TransactionKeyItem,
  WalletDescriptor,
} from "./protocol/types.js";
export {
  computeQosLiveManifestCommitmentPcr,
  verifyBootProof,
  verifyTurnkeyAppProof,
} from "./verify/index.js";
export type { QosIdentityPcrIndex, QosIdentityPcrs, VerifyBootProofInput } from "./verify/index.js";
export { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "./verify/release-policy.js";
