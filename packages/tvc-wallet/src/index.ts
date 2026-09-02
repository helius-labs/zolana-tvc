export {
  checkpointOf,
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
export type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "./client/connection.js";
export type { OperationsConfig, TvcOperationAuthorizer } from "./client/operation-executor.js";
export { createTvcOperationAuthorizer, type TvcRequestSigner } from "./platform/authorizer.js";
export type { TvcTransport } from "./client/transport.js";
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
export type { QosIdentityPcrs } from "./verify/index.js";
export { bindDiscoveryToPolicy, verifySignedReleasePolicy } from "./verify/release-policy.js";
