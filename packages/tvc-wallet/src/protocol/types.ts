export type Environment = "development" | "production";

export type OperationKind =
  | "BootstrapClientEd25519"
  | "AuthorizeDefaultRingTransfer";

export type HealthResponseV1 = {
  status: "Healthy";
};

export type ServiceInfoV1 = {
  version: number;
  environment: Environment;
  security_domain_id: string;
  release_id: string;
  manifest_digest: string;
  executable_digest: string;
  quorum_public_key: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  ephemeral_public_key: string;
  supported_operations: OperationKind[];
  max_encrypted_request_bytes: string;
  max_encrypted_response_bytes: string;
  proof_type: string;
  boot_proof_lookup_key: string;
};

export type ReleasePolicyV1 = {
  version: 1;
  releaseId: string;
  environment: Environment;
  tvcApplicationId: string;
  securityDomainId: string;
  acceptedManifestDigests: readonly string[];
  acceptedExecutableDigests: readonly string[];
  quorumKeyId: string;
  quorumKeyEpoch: string;
  quorumPublicKey: string;
  allowedOperations: readonly OperationKind[];
  maxEncryptedRequestBytes: number;
  maxEncryptedResponseBytes: number;
  turnkeyTrustRootId: string;
  turnkeyProofSchemaVersions: readonly string[];
  turnkeyVerifierVersion: string;
  validFromMs: string;
  expiresAtMs: string;
  revocationEpoch: string;
};

export type ReleaseAuthoritySignatureV1 = {
  keyId: string;
  scheme: "p256-sha256";
  signature: string;
};

export type SignedReleasePolicyV1 = {
  policy: ReleasePolicyV1;
  authoritySetId: string;
  signatures: readonly ReleaseAuthoritySignatureV1[];
};

export type ReleaseAuthorityKeyV1 = {
  keyId: string;
  publicKey: string;
};

export type PinnedReleaseAuthoritiesV1 = {
  authoritySetId: string;
  threshold: number;
  keys: readonly ReleaseAuthorityKeyV1[];
};

export type TurnkeyEvidenceClassification = "CryptographicallyValidButUnbound";

export type ClientAuthorizationScheme = "p256-sha256";

export type ClientGrantV1 = {
  client_key_id: string;
  scheme: ClientAuthorizationScheme;
  client_public_key: string;
  allowed_operations: OperationKind[];
  may_rotate_descriptor: boolean;
};

export type TurnkeySigningTargetV1 =
  | {
      type: "PrivateKey";
      private_key_id: string;
    }
  | {
      type: "HdWalletAccount";
      turnkey_wallet_id: string;
      wallet_account_id: string;
      address: string;
      derivation_path: string;
    };

/**
 * The development descriptor is provisioned out of band. This package never
 * manufactures or silently rotates descriptor authority.
 */
export type WalletDescriptorV1 = {
  version: 1;
  wallet_id: string;
  security_domain_id: string;
  turnkey_parent_organization_id: string;
  turnkey_organization_id: string;
  turnkey_signing_target: TurnkeySigningTargetV1;
  turnkey_service_user_id: string;
  turnkey_api_key_id: string;
  expected_ed25519_public_key: string;
  allowed_clients: ClientGrantV1[];
  policy_version: string;
  previous_descriptor_digest: string | null;
  environment: "development";
  provisioning_key_id: string;
  owner_authorization_key: null;
  recovery_binding: null;
  provisioning_signature: string;
  owner_authorization: null;
  prior_client_authorization: null;
};

export type BootstrapClientEd25519OperationV1 = {
  type: "BootstrapClientEd25519";
};

export type AuthorizeDefaultRingTransferOperationV1 = {
  type: "AuthorizeDefaultRingTransfer";
  intent_digest: string;
  unsigned_transaction: string;
};

export type WalletOperationV1 =
  | BootstrapClientEd25519OperationV1
  | AuthorizeDefaultRingTransferOperationV1;

export type ClientAuthorizationV1 = {
  client_key_id: string;
  scheme: ClientAuthorizationScheme;
  signature: string;
};

export type OperationRequestV1 = {
  version: 1;
  request_id: string;
  issued_at_ms: string;
  expires_at_ms: string;
  target_release_id: string;
  target_manifest_digest: string;
  target_executable_digest: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  wallet_descriptor: WalletDescriptorV1;
  sealed_wallet_state: string | null;
  expected_state_version: string | null;
  expected_state_digest: string | null;
  client_response_public_key: string;
  operation: WalletOperationV1;
  authorization: ClientAuthorizationV1;
};

export type TurnkeyVerifiedAppProofV1 = {
  scheme: string;
  public_key: string;
  proof_payload: string;
  signature: string;
};

type TurnkeyEvidenceResult = {
  turnkey_app_proofs: TurnkeyVerifiedAppProofV1[];
  evidence_classification: TurnkeyEvidenceClassification;
};

export type BootstrapClientEd25519Result = TurnkeyEvidenceResult & {
  type: "BootstrapClientEd25519";
  solana_address: string;
  shielded_owner_hash: string;
  shielded_nullifier_public_key: string;
  shielded_viewing_public_key: string;
  derivation_seed: string;
  derivation_suite: string;
  turnkey_activity_id: string;
};

export type AuthorizeDefaultRingTransferResult = TurnkeyEvidenceResult & {
  type: "AuthorizeDefaultRingTransfer";
  signed_transaction: string;
  transaction_signature: string;
  intent_digest: string;
  turnkey_activity_id: string;
};

export type WalletOperationResult =
  | BootstrapClientEd25519Result
  | AuthorizeDefaultRingTransferResult;

export const SERVICE_INFO_KEYS = [
  "version",
  "environment",
  "security_domain_id",
  "release_id",
  "manifest_digest",
  "executable_digest",
  "quorum_public_key",
  "quorum_key_id",
  "quorum_key_epoch",
  "ephemeral_public_key",
  "supported_operations",
  "max_encrypted_request_bytes",
  "max_encrypted_response_bytes",
  "proof_type",
  "boot_proof_lookup_key",
] as const;

export const HEALTH_KEYS = ["status"] as const;
