//! Versioned request, response, discovery, and evidence types.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::encoding::{
    self, decimal_u64, hex32, hex32_vec, hex_bytes, option_decimal_u64, option_hex32,
    option_hex_bytes,
};
use crate::error::{ErrorCode, TvcError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientAuthorizationScheme {
    #[serde(rename = "p256-sha256")]
    P256Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OperationKind {
    BootstrapKeyholder,
    DeriveViewTags,
    DecryptUtxos,
    BuildTransfer,
    BuildSolWithdrawal,
    AuthorizeDefaultRingTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HealthStatus {
    Healthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponseV1 {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfoV1 {
    pub version: u8,
    pub environment: Environment,
    #[serde(with = "hex32")]
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    #[serde(with = "hex32")]
    pub manifest_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub executable_digest: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub quorum_public_key: Vec<u8>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex_bytes")]
    pub ephemeral_public_key: Vec<u8>,
    pub supported_operations: Vec<OperationKind>,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_request_bytes: u64,
    #[serde(with = "decimal_u64")]
    pub max_encrypted_response_bytes: u64,
    pub proof_type: String,
    #[serde(with = "hex_bytes")]
    pub boot_proof_lookup_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantV1 {
    pub client_key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex_bytes")]
    pub client_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
    pub may_rotate_descriptor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerChallengeV1 {
    pub version: u8,
    pub purpose: String,
    #[serde(with = "hex32")]
    pub ceremony_id: [u8; 32],
    #[serde(with = "hex32")]
    pub descriptor_digest: [u8; 32],
    #[serde(with = "option_hex32")]
    pub previous_descriptor_digest: Option<[u8; 32]>,
    #[serde(with = "decimal_u64")]
    pub owner_generation: u64,
    #[serde(with = "decimal_u64")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAuthorizationKeyV1 {
    pub scheme: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "decimal_u64")]
    pub generation: u64,
    pub policy_id: String,
    pub turnkey_user_id: String,
    pub turnkey_authenticator_id: String,
    pub backup_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAuthorizationV1 {
    pub challenge: OwnerChallengeV1,
    #[serde(with = "hex_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub authenticator_data: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub client_data_json: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub signature_der: Vec<u8>,
    #[serde(with = "option_hex_bytes")]
    pub user_handle: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorRotationAuthorizationV1 {
    #[serde(with = "hex32")]
    pub previous_descriptor_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub descriptor_digest: [u8; 32],
    pub scheme: ClientAuthorizationScheme,
    pub client_key_id: String,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDescriptorV1 {
    pub version: u8,
    pub wallet_id: String,
    #[serde(with = "hex32")]
    pub security_domain_id: [u8; 32],
    pub turnkey_parent_organization_id: String,
    pub turnkey_organization_id: String,
    pub turnkey_signing_target: TurnkeySigningTargetV1,
    pub turnkey_service_user_id: String,
    pub turnkey_api_key_id: String,
    #[serde(with = "hex32")]
    pub expected_ed25519_public_key: [u8; 32],
    pub allowed_clients: Vec<ClientGrantV1>,
    #[serde(with = "decimal_u64")]
    pub policy_version: u64,
    #[serde(with = "option_hex32")]
    pub previous_descriptor_digest: Option<[u8; 32]>,
    pub environment: Environment,
    pub provisioning_key_id: String,
    pub owner_authorization_key: Option<OwnerAuthorizationKeyV1>,
    pub recovery_binding: Option<serde_json::Value>,
    #[serde(with = "hex_bytes")]
    pub provisioning_signature: Vec<u8>,
    pub owner_authorization: Option<OwnerAuthorizationV1>,
    pub prior_client_authorization: Option<DescriptorRotationAuthorizationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum TurnkeySigningTargetV1 {
    PrivateKey {
        private_key_id: String,
    },
    HdWalletAccount {
        turnkey_wallet_id: String,
        wallet_account_id: String,
        address: String,
        derivation_path: String,
    },
}

impl TurnkeySigningTargetV1 {
    pub fn sign_with(&self) -> &str {
        match self {
            Self::PrivateKey { private_key_id } => private_key_id,
            Self::HdWalletAccount { address, .. } => address,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthorizationV1 {
    pub client_key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// One ciphertext the client fetched, with the public material needed to
/// decrypt it. The viewing key stays in the enclave; everything here is already
/// public on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum EncryptedPayloadV1 {
    /// A UTXO ciphertext in a numbered output slot of a shielded transaction.
    Utxo {
        #[serde(with = "hex_bytes")]
        ciphertext: Vec<u8>,
        #[serde(with = "hex_bytes")]
        transaction_viewing_public_key: Vec<u8>,
        #[serde(with = "hex_bytes")]
        salt: Vec<u8>,
        #[serde(with = "decimal_u64")]
        slot_index: u64,
    },
    /// A self-contained ring-deposit ciphertext, which carries no slot index.
    RingDeposit {
        #[serde(with = "hex_bytes")]
        ciphertext: Vec<u8>,
        #[serde(with = "hex_bytes")]
        transaction_viewing_public_key: Vec<u8>,
        #[serde(with = "hex_bytes")]
        salt: Vec<u8>,
    },
}

/// The outcome for one requested payload. `index` refers to the position in the
/// request, so a client can align results without relying on ordering.
///
/// The shielded-pool transport cipher is AES-CTR with no authentication tag, so
/// decryption cannot tell a payload addressed to this wallet from one addressed
/// to another: the second case yields garbage bytes rather than an error. This
/// type therefore never claims ownership. `Plaintext` means only that bytes came
/// out; the caller must deserialize them and check the recovered `owner_pubkey`
/// against its own before treating a payload as its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DecryptedPayloadV1 {
    Plaintext {
        #[serde(with = "decimal_u64")]
        index: u64,
        #[serde(with = "hex_bytes")]
        plaintext: Vec<u8>,
    },
    /// The ciphertext was structurally unusable, for example too short for its
    /// scheme. This is a statement about the bytes, not about ownership.
    Malformed {
        #[serde(with = "decimal_u64")]
        index: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OperationV1 {
    /// Derives the shielded identity and seals it to the Quorum key. The client
    /// stores an opaque blob and presents it on every later request.
    BootstrapKeyholder,
    /// Derives the wallet's recipient bootstrap view tags, one per viewing key
    /// the application holds.
    ///
    /// These are the stable tags a wallet is found by, not a window: the
    /// indexer is queried with them directly. The other tag a scan needs is the
    /// identity tag, which derives from the signing *public* key, so the client
    /// computes that one itself and never asks for it.
    DeriveViewTags,
    /// Decrypts one batch of ciphertexts the client fetched from the indexer.
    /// A payload that is not this wallet's decrypts to garbage rather than
    /// failing, because the transport cipher is unauthenticated; see
    /// [`DecryptedPayloadV1`] for what the result does and does not assert.
    DecryptUtxos { payloads: Vec<EncryptedPayloadV1> },
    /// Closed no-production-funds profile used by the attested feasibility
    /// deployment. Production transfer requests carry authenticated chain
    /// input instead of selecting a network service by identifier.
    BuildTransfer { intent: TransferIntentV1 },
    /// Closed development-only public SOL withdrawal. Unlike `BuildTransfer`,
    /// this never attempts to resolve the recipient as a registered shielded
    /// address, so withdrawing to the descriptor-bound public wallet remains
    /// unambiguous even though that wallet is registered.
    BuildSolWithdrawal { intent: SolWithdrawalIntentV1 },
    /// Sign one client-built default-ring transfer after validating its fixed
    /// Solana transaction shape. The intent digest is client-authenticated and
    /// proof-bound; this operation is not a generic transaction signer.
    AuthorizeDefaultRingTransfer {
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
        #[serde(with = "hex_bytes")]
        unsigned_transaction: Vec<u8>,
    },
}

/// Spend inside a custom ring rather than the default one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingSpendV1 {
    /// The ring program. Every input spent and output produced is bound to it,
    /// and the shielded commitment covers that binding.
    pub program_id: String,
    /// An address lookup table covering the transact's accounts. A custom-ring
    /// transact does not fit a legacy packet, so the message must be v0 over a
    /// table. The application checks the table against the accounts the
    /// instruction actually needs, so this is verified input, not trusted input.
    pub lookup_table: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferIntentV1 {
    pub asset: AssetV1,
    pub recipient: String,
    #[serde(with = "decimal_u64")]
    pub amount: u64,
    pub prover_profile_id: String,
    /// Absent spends the default ring.
    pub ring: Option<RingSpendV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolWithdrawalIntentV1 {
    pub recipient: String,
    #[serde(with = "decimal_u64")]
    pub amount: u64,
    pub prover_profile_id: String,
    /// Absent withdraws from the default ring. A ring exit is public the same
    /// way, and the ring's own proof still covers it.
    pub ring: Option<RingSpendV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum AssetV1 {
    Sol,
    Spl {
        mint: String,
        #[serde(with = "decimal_u64")]
        asset_id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequestV1 {
    pub version: u8,
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "decimal_u64")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    pub target_release_id: String,
    #[serde(with = "hex32")]
    pub target_manifest_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub target_executable_digest: [u8; 32],
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    pub wallet_descriptor: WalletDescriptorV1,
    #[serde(with = "option_hex_bytes")]
    pub sealed_wallet_state: Option<Vec<u8>>,
    #[serde(with = "option_decimal_u64")]
    pub expected_state_version: Option<u64>,
    #[serde(with = "option_hex32")]
    pub expected_state_digest: Option<[u8; 32]>,
    #[serde(with = "hex_bytes")]
    pub client_response_public_key: Vec<u8>,
    pub operation: OperationV1,
    pub authorization: ClientAuthorizationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRequestV1 {
    pub version: u8,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedWalletStateV1 {
    pub version: u8,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub wallet_id_hash: [u8; 32],
    pub state_version: u64,
    pub previous_state_digest: Option<[u8; 32]>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TvcAppProofV1 {
    pub scheme: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub proof_payload: String,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Canonical connection challenge encrypted to the QOS Quorum encryption
/// subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingChallengeV1 {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
}

/// Public wrapper carrying only a QOS-encrypted ping challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingRequestV1 {
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub encrypted_challenge: Vec<u8>,
}

/// A pet-only proof that the running enclave decrypted with the Quorum key and
/// signed the exact challenge bytes with its Ephemeral signing subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingResponseV1 {
    pub version: u8,
    pub tvc_app_proof: TvcAppProofV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedResponseV1 {
    pub version: u8,
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub encrypted_result: Vec<u8>,
    pub tvc_app_proof: TvcAppProofV1,
}

/// The exact typed Turnkey proof fields returned by `turnkey_client`.
/// Their policy evidence remains cryptographically valid but unbound until
/// Turnkey publishes a decision-context binding that covers our intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyVerifiedAppProofV1 {
    pub scheme: String,
    pub public_key: String,
    pub proof_payload: String,
    pub signature: String,
}

/// Coarse, non-secret stage marker returned only by the disposable development
/// pet inside its authenticated encrypted response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureStage {
    ResolveAsset,
    SyncWallet,
    ShieldedBalanceNotReady,
    CreateTransfer,
    CreateWithdrawal,
    SignShieldedTransaction,
    LatestBlockhash,
    FinishSubmission,
    IndexerProofs,
    /// Reading or validating the ring transact's address lookup table.
    LookupTable,
    ProofAssembly,
    ExternalProver,
    LocalProofVerification,
    SignTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OperationResultV1 {
    BootstrapKeyholder {
        solana_address: String,
        #[serde(with = "hex32")]
        shielded_owner_hash: [u8; 32],
        #[serde(with = "hex32")]
        shielded_nullifier_public_key: [u8; 32],
        #[serde(with = "hex_bytes")]
        shielded_viewing_public_key: Vec<u8>,
        /// The seed sealed to the Quorum key. No derivation seed appears
        /// anywhere in this result.
        #[serde(with = "hex_bytes")]
        sealed_wallet_state: Vec<u8>,
        #[serde(with = "decimal_u64")]
        state_version: u64,
        #[serde(with = "hex32")]
        state_digest: [u8; 32],
        derivation_suite: String,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
        evidence_classification: TurnkeyEvidenceClassification,
    },
    DeriveViewTags {
        #[serde(with = "hex32_vec")]
        view_tags: Vec<[u8; 32]>,
    },
    DecryptUtxos {
        payloads: Vec<DecryptedPayloadV1>,
    },
    BuildTransfer {
        #[serde(with = "hex_bytes")]
        signed_transaction: Vec<u8>,
        transaction_signature: String,
        #[serde(with = "hex_bytes")]
        sealed_wallet_state: Vec<u8>,
        #[serde(with = "decimal_u64")]
        state_version: u64,
        #[serde(with = "hex32")]
        state_digest: [u8; 32],
        #[serde(with = "decimal_u64")]
        shielded_balance_before: u64,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
        evidence_classification: TurnkeyEvidenceClassification,
    },
    BuildSolWithdrawal {
        #[serde(with = "hex_bytes")]
        signed_transaction: Vec<u8>,
        transaction_signature: String,
        #[serde(with = "hex_bytes")]
        sealed_wallet_state: Vec<u8>,
        #[serde(with = "decimal_u64")]
        state_version: u64,
        #[serde(with = "hex32")]
        state_digest: [u8; 32],
        #[serde(with = "decimal_u64")]
        shielded_balance_before: u64,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
        evidence_classification: TurnkeyEvidenceClassification,
    },
    AuthorizeDefaultRingTransfer {
        #[serde(with = "hex_bytes")]
        signed_transaction: Vec<u8>,
        transaction_signature: String,
        #[serde(with = "hex32")]
        intent_digest: [u8; 32],
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
        evidence_classification: TurnkeyEvidenceClassification,
    },
    Failure {
        operation: OperationKind,
        stage: FailureStage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TvcOperationProofPayloadV1 {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "hex32")]
    pub request_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub result_digest: [u8; 32],
    pub operation: OperationKind,
    #[serde(with = "hex32")]
    pub state_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum TurnkeyIntentV1 {
    SignRawPayloadV2 {
        #[serde(with = "hex_bytes")]
        payload: Vec<u8>,
        encoding: String,
        hash_function: String,
    },
    SignTransactionV2 {
        #[serde(with = "hex_bytes")]
        unsigned_transaction: Vec<u8>,
        transaction_type: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyAppProofV1 {
    pub proof_type: String,
    #[serde(with = "hex_bytes")]
    pub proof_body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyActivityEvidenceV1 {
    pub version: u8,
    pub activity_id: String,
    pub activity_type: String,
    pub activity_status: String,
    pub request_fingerprint: Option<String>,
    pub organization_id: String,
    pub sign_with: String,
    #[serde(with = "hex_bytes")]
    pub exact_request_body: Vec<u8>,
    pub canonical_intent: TurnkeyIntentV1,
    #[serde(with = "hex_bytes")]
    pub activity_response: Vec<u8>,
    pub app_proofs: Vec<TurnkeyAppProofV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TurnkeyEvidenceClassification {
    CryptographicallyValidButUnbound,
    Invalid,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePolicyV1 {
    pub version: u8,
    pub release_id: String,
    pub environment: Environment,
    pub tvc_application_id: String,
    #[serde(with = "hex32")]
    pub security_domain_id: [u8; 32],
    pub accepted_manifest_digests: Vec<String>,
    pub accepted_executable_digests: Vec<String>,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex_bytes")]
    pub quorum_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
    pub max_encrypted_request_bytes: u32,
    pub max_encrypted_response_bytes: u32,
    pub turnkey_trust_root_id: String,
    pub turnkey_proof_schema_versions: Vec<String>,
    pub turnkey_verifier_version: String,
    #[serde(with = "decimal_u64")]
    pub valid_from_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthoritySignatureV1 {
    pub key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePolicyV1 {
    pub policy: ReleasePolicyV1,
    pub authority_set_id: String,
    pub signatures: Vec<ReleaseAuthoritySignatureV1>,
}

impl OperationV1 {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::BootstrapKeyholder => OperationKind::BootstrapKeyholder,
            Self::DeriveViewTags => OperationKind::DeriveViewTags,
            Self::DecryptUtxos { .. } => OperationKind::DecryptUtxos,
            Self::BuildTransfer { .. } => OperationKind::BuildTransfer,
            Self::BuildSolWithdrawal { .. } => OperationKind::BuildSolWithdrawal,
            Self::AuthorizeDefaultRingTransfer { .. } => {
                OperationKind::AuthorizeDefaultRingTransfer
            }
        }
    }
}

pub fn parse_operation_request(json: &str) -> Result<OperationRequestV1, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_encrypted_request(json: &str) -> Result<EncryptedRequestV1, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_service_info(json: &str) -> Result<ServiceInfoV1, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_health(json: &str) -> Result<HealthResponseV1, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_request(json: &str) -> Result<QosPingRequestV1, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_challenge(json: &str) -> Result<QosPingChallengeV1, TvcError> {
    encoding::parse_strict_json(json)
}

/// Preserve exact UTF-8 proof payload bytes. Do not parse-and-reserialize before the signature check.
pub fn proof_payload_bytes(proof_payload: &str) -> &[u8] {
    proof_payload.as_bytes()
}

pub fn reject_production_environment(environment: Environment) -> Result<(), TvcError> {
    match environment {
        Environment::Development => Ok(()),
        Environment::Production => Err(TvcError::new(ErrorCode::ProductionClaimRejected)),
    }
}
