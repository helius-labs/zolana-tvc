export type Environment = "development" | "production";

export type OperationKind =
  | "BootstrapKeyholder"
  | "DeriveViewTags"
  | "DecryptUtxos"
  | "AuthorizeSpend";

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

export type AssetV1 =
  | { type: "Sol" }
  | { type: "Spl"; mint: string; asset_id: string };

/** The policy domain of a private UTXO. Routes are derived from two domains. */
export type PrivateDomainV1 =
  | { type: "Default" }
  | {
      type: "Ring";
      program_id: string;
      /** Must be at least one slot old before the ring transact lands. */
      lookup_table: string;
    };

/**
 * What a ring spend settles to. Separate variants rather than a nullable
 * recipient pair, so a public withdrawal and private transfer cannot be confused.
 */
export type SpendSettlementV1 =
  | {
      type: "Transfer";
      asset: AssetV1;
      recipient: string;
      amount: string;
      destination: PrivateDomainV1;
    }
  | {
      type: "Withdrawal";
      asset: AssetV1;
      /** Public wallet owner; SPL settles to its associated token account. */
      recipient: string;
      amount: string;
    }
  | {
      /** Balance-neutral merge_8_1 of plain UTXOs in the default domain. */
      type: "Consolidate";
      asset: AssetV1;
    };

/** One direct private transition. */
export type SpendIntentV1 = {
  source: PrivateDomainV1;
  settlement: SpendSettlementV1;
  /** Exact default UTXOs required when the destination is a ring. */
  input_commitments: string[];
};

export type SppShapeV1 = {
  inputs: number;
  outputs: number;
};

export type SppPlanInputV1 =
  | { type: "Wallet"; commitment: string }
  | {
      type: "Program";
      commitment: string;
      authority_seeds: string[];
      asset: AssetV1;
      amount: string;
      blinding: string;
      data_hash: string | null;
      nullifier_secret: string;
    };

export type SppPlanOutputV1 = {
  recipient: string;
  asset: AssetV1;
  amount: string;
  blinding: string;
  data: string;
  data_hash: string | null;
  memo: string;
};

export type SppMessageV1 = {
  view_tag: string;
  data: string;
};

export type SppProgramAuthorityV1 = {
  /** PDA seeds, including the canonical bump, resolved under `program_id`. */
  seeds: string[];
};

export type SppPlanV1 = {
  program_id: string;
  input_tree: string;
  shape: SppShapeV1;
  inputs: SppPlanInputV1[];
  program_authorities: SppProgramAuthorityV1[];
  outputs: SppPlanOutputV1[];
  messages: SppMessageV1[];
  expires_at_ms: string;
};

export type SpendPlanV1 =
  | { type: "Direct"; transition: SpendIntentV1 }
  | { type: "Program"; transition: SppPlanV1 };

export type SolanaAccountMetaV1 = {
  address: string;
  is_signer: boolean;
  is_writable: boolean;
};

export type SolanaInstructionV1 = {
  program_id: string;
  accounts: SolanaAccountMetaV1[];
  data: string;
};

export type PrepareSpendOperationV1 = {
  type: "AuthorizeSpend";
  spend: {
    phase: "Prepare";
    plan: SpendPlanV1;
  };
};

export type FinalizeSpendOperationV1 = {
  type: "AuthorizeSpend";
  spend: {
    phase: "Finalize";
    sealed_authorization_capsule: string;
    unsigned_transaction: string;
  };
};

export type AuthorizeSpendOperationV1 = PrepareSpendOperationV1 | FinalizeSpendOperationV1;

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
  include_spendable_outputs: boolean;
};

export type WalletOperationV1 =
  | BootstrapKeyholderOperationV1
  | DeriveViewTagsOperationV1
  | DecryptUtxosOperationV1
  | AuthorizeSpendOperationV1;

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

export type PreparedSpendV1 =
  | {
      type: "ExactTransaction";
      unsigned_transaction: string;
      transaction_digest: string;
    }
  | {
      type: "Spp";
      program_id: string;
      input_tree: string;
      plan_digest: string;
      transact: string;
      transact_digest: string;
      private_tx_hash: string;
      external_data_hash: string;
    };

export type PreparedSpendResult = WalletStateResult & {
  type: "AuthorizeSpend";
  phase: "Prepare";
  prepared: PreparedSpendV1;
  sealed_authorization_capsule: string;
  shielded_balance_before: string;
};

export type PreparedExactSpendResult = PreparedSpendResult & {
  prepared: Extract<PreparedSpendV1, { type: "ExactTransaction" }>;
};

export type PreparedSppSpendResult = PreparedSpendResult & {
  prepared: Extract<PreparedSpendV1, { type: "Spp" }>;
};

export type FinalizedSpendResult = TurnkeyEvidenceResult &
  WalletStateResult & {
    type: "AuthorizeSpend";
    phase: "Finalize";
    signed_transaction: string;
    transaction_signature: string;
    shielded_balance_before: string;
    turnkey_activity_id: string;
  };

/** High-level wallet result after its internal prepare/finalize sequence. */
export type AuthorizeSpendResult = FinalizedSpendResult;

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

/** Public metadata for an output TVC verified is currently unspent. */
export type SpendableOutputV1 = {
  commitment: string;
  asset: AssetV1;
  amount: string;
  ring_program_id: string | null;
};

export type DecryptUtxosResult = {
  type: "DecryptUtxos";
  payloads: readonly DecryptedPayloadV1[];
  spendable_outputs: readonly SpendableOutputV1[] | null;
};

export type WalletOperationResult =
  | BootstrapKeyholderResult
  | DeriveViewTagsResult
  | DecryptUtxosResult
  | PreparedSpendResult
  | FinalizedSpendResult
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
