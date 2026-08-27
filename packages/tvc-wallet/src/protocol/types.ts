export type Environment = "development" | "production";

export type OperationKind =
  | "BuildTransfer"
  | "BuildSolWithdrawal"
  | "BootstrapKeyholder"
  | "DeriveViewTags"
  | "DecryptUtxos"
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

export type AuthorizeDefaultRingTransferOperationV1 = {
  type: "AuthorizeDefaultRingTransfer";
  intent_digest: string;
  unsigned_transaction: string;
};

export type AssetV1 =
  | { type: "Sol" }
  | { type: "Spl"; mint: string; asset_id: string };

/** Spend inside a custom ring rather than the default one. */
export type RingSpendV1 = {
  /** The ring program. Every input spent and output produced is bound to it. */
  program_id: string;
  /**
   * An address lookup table covering the transact's accounts. A custom-ring
   * transact does not fit a legacy packet, so the message must be v0 over a
   * table. The enclave checks the table against the accounts the instruction
   * needs, so naming one here is checked input rather than trusted input.
   */
  lookup_table: string;
};

export type BuildTransferOperationV1 = {
  type: "BuildTransfer";
  intent: {
    asset: AssetV1;
    recipient: string;
    amount: string;
    prover_profile_id: string;
    /** Absent spends the default ring. */
    ring: RingSpendV1 | null;
  };
};

export type BuildSolWithdrawalOperationV1 = {
  type: "BuildSolWithdrawal";
  intent: {
    recipient: string;
    amount: string;
    prover_profile_id: string;
    /** Absent withdraws from the default ring. */
    ring: RingSpendV1 | null;
  };
};

export type BootstrapKeyholderOperationV1 = {
  type: "BootstrapKeyholder";
};

export type DeriveViewTagsOperationV1 = {
  type: "DeriveViewTags";
};

/**
 * One ciphertext the client fetched, with the public material needed to decrypt
 * it. Everything here is already public on chain; only the viewing key is not,
 * and it stays in the enclave.
 */
export type EncryptedPayloadV1 =
  | {
      type: "Utxo";
      ciphertext: string;
      transaction_viewing_public_key: string;
      salt: string;
      slot_index: string;
    }
  | {
      type: "RingDeposit";
      ciphertext: string;
      transaction_viewing_public_key: string;
      salt: string;
    };

export type DecryptUtxosOperationV1 = {
  type: "DecryptUtxos";
  payloads: readonly EncryptedPayloadV1[];
};

export type WalletOperationV1 =
  | BootstrapKeyholderOperationV1
  | DeriveViewTagsOperationV1
  | DecryptUtxosOperationV1
  | BuildTransferOperationV1
  | BuildSolWithdrawalOperationV1
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

export type AuthorizeDefaultRingTransferResult = TurnkeyEvidenceResult & {
  type: "AuthorizeDefaultRingTransfer";
  signed_transaction: string;
  transaction_signature: string;
  intent_digest: string;
  turnkey_activity_id: string;
};

export type TvcWalletCheckpoint = {
  sealedWalletState: string;
  stateVersion: string;
  stateDigest: string;
};

type WalletStateResult = {
  sealed_wallet_state: string;
  state_version: string;
  state_digest: string;
};

export type BuildTransferResult = TurnkeyEvidenceResult &
  WalletStateResult & {
    type: "BuildTransfer";
    signed_transaction: string;
    transaction_signature: string;
    shielded_balance_before: string;
    turnkey_activity_id: string;
  };

export type BuildSolWithdrawalResult = TurnkeyEvidenceResult &
  WalletStateResult & {
    type: "BuildSolWithdrawal";
    signed_transaction: string;
    transaction_signature: string;
    shielded_balance_before: string;
    turnkey_activity_id: string;
  };

export type FailureResult = {
  type: "Failure";
  operation: OperationKind;
  stage: string;
};

export type BootstrapKeyholderResult = TurnkeyEvidenceResult & {
  type: "BootstrapKeyholder";
  solana_address: string;
  shielded_owner_hash: string;
  shielded_nullifier_public_key: string;
  shielded_viewing_public_key: string;
  /** The seed sealed to the Quorum key. No derivation seed appears here. */
  sealed_wallet_state: string;
  state_version: string;
  state_digest: string;
  derivation_suite: string;
  turnkey_activity_id: string;
};

export type DeriveViewTagsResult = {
  type: "DeriveViewTags";
  /**
   * The wallet's recipient bootstrap tags, one per viewing key the enclave
   * holds. These are the stable tags a wallet is found by; the indexer is
   * queried with them directly. A scan also needs the identity tag, which
   * derives from the signing public key, so the caller computes that itself.
   */
  view_tags: readonly string[];
};

/**
 * The outcome for one requested payload. `index` is the position in the
 * request, so results align without relying on ordering.
 *
 * The shielded-pool transport cipher is AES-CTR with no authentication tag, so
 * decryption cannot tell a payload addressed to this wallet from one addressed
 * to another: the second yields garbage bytes rather than an error. `Plaintext`
 * therefore means only that bytes came out. Deserialize them and compare the
 * recovered owner against your own before treating a payload as yours.
 */
export type DecryptedPayloadV1 =
  | { type: "Plaintext"; index: string; plaintext: string }
  | { type: "Malformed"; index: string };

export type DecryptUtxosResult = {
  type: "DecryptUtxos";
  payloads: readonly DecryptedPayloadV1[];
};

export type WalletOperationResult =
  | BootstrapKeyholderResult
  | DeriveViewTagsResult
  | DecryptUtxosResult
  | AuthorizeDefaultRingTransferResult
  | BuildTransferResult
  | BuildSolWithdrawalResult
  | FailureResult;

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
