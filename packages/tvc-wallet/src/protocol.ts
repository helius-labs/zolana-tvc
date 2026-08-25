export type {
  Environment,
  HealthResponseV1,
  OperationKind,
  ServiceInfoV1,
  SignedReleasePolicyV1,
  PinnedReleaseAuthoritiesV1,
  ReleasePolicyV1,
  TurnkeyEvidenceClassification,
} from "./protocol/types.js";
export {
  canonicalizeJsonValue,
  isRfc8785,
  parseStrictJson,
  encodeLowerHex,
  decodeLowerHex,
  encodeDecimalU64,
  decodeDecimalU64,
  requestDigest,
  clientAuthDigest,
  clientAuthMessage,
  descriptorDigestFromWallet,
  descriptorOwnerEvidenceDigest,
  descriptorProvisioningAuthDigest,
  resultDigest,
  artifactDigest,
  walletIdHash,
  requestIdHash,
  activityIdHash,
  releasePolicyDigest,
  stateCommitment,
} from "./protocol/index.js";
export type {
  OperationRequestV1,
  WalletOperationV1,
  WalletDescriptorV1,
} from "./protocol/types.js";
export { TvcError } from "./protocol/error.js";
