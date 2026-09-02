//! Wire types: discovery, requests, results, sealed state, release policy.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::encoding::{self, decimal_u64, hex32, hex32_vec, hex_bytes, option_hex_bytes};
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

/// What a request asks for, as advertised by `/v1/info`, granted by a
/// descriptor, and named in the App Proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OperationKind {
    Bootstrap,
    ViewTags,
    Decrypt,
    Spend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HealthStatus {
    Healthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
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
pub struct ClientGrant {
    #[serde(with = "hex_bytes")]
    pub client_public_key: Vec<u8>,
    pub allowed_operations: Vec<OperationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDescriptor {
    pub version: u8,
    #[serde(with = "hex32")]
    pub security_domain_id: [u8; 32],
    pub environment: Environment,
    pub turnkey_organization_id: String,
    pub turnkey_wallet_id: String,
    pub address: String,
    pub allowed_clients: Vec<ClientGrant>,
    #[serde(with = "hex_bytes")]
    pub provisioning_signature: Vec<u8>,
}

impl WalletDescriptor {
    pub fn wallet_id(&self) -> String {
        format!("wallet-{}", self.turnkey_wallet_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuthorization {
    pub client_key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// A classic SPL mint the shielded pool registered under a compact asset id.
/// SOL needs no entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplAsset {
    pub mint: String,
    #[serde(with = "decimal_u64")]
    pub asset_id: u64,
}

/// One output the client wants opened as a UTXO of this wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DecryptPayload {
    /// A UTXO ciphertext in a numbered output slot, with the public material
    /// needed to decrypt it.
    Encrypted {
        #[serde(with = "hex_bytes")]
        ciphertext: Vec<u8>,
        #[serde(with = "hex_bytes")]
        transaction_viewing_public_key: Vec<u8>,
        #[serde(with = "hex_bytes")]
        salt: Vec<u8>,
        #[serde(with = "decimal_u64")]
        slot_index: u64,
    },
    /// An opening already published in the clear, such as a deposit. Nothing
    /// to decrypt; the client needs its nullifier.
    Plain {
        asset: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
        #[serde(with = "hex32")]
        blinding: [u8; 32],
    },
}

/// The outcome for one requested payload, by request position.
///
/// The transport cipher is unauthenticated, so another wallet's payload decrypts
/// to garbage rather than failing. `Utxo` therefore means "decodes as a plain
/// UTXO of this wallet under the supplied assets", and the client MUST compare
/// `commitment` with the indexed output before adopting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DecryptedPayload {
    Utxo {
        #[serde(with = "decimal_u64")]
        index: u64,
        asset: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
        #[serde(with = "hex32")]
        blinding: [u8; 32],
        ring_program_id: Option<String>,
        #[serde(with = "hex32")]
        commitment: [u8; 32],
        #[serde(with = "hex32")]
        nullifier: [u8; 32],
    },
    Unreadable {
        #[serde(with = "decimal_u64")]
        index: u64,
    },
}

/// A plain default-pool UTXO owned by this wallet, as the client decrypted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendInput {
    pub asset: String,
    #[serde(with = "decimal_u64")]
    pub amount: u64,
    #[serde(with = "hex32")]
    pub blinding: [u8; 32],
}

/// What the spend settles to. Amounts are in the asset's base units; `asset`
/// is the mint, `SOL_MINT` for SOL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum SpendAction {
    /// Private transfer to a shielded address, in its 99-byte wire form.
    Transfer {
        #[serde(with = "hex_bytes")]
        recipient: Vec<u8>,
        asset: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
    },
    /// Public withdrawal to a Solana address. SPL settles to the recipient's
    /// associated token account.
    Withdrawal {
        recipient: String,
        asset: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Operation {
    /// Derives the shielded identity and seals it to the Quorum key. The client
    /// stores the opaque blob and presents it on every later request.
    Bootstrap,
    /// The stable recipient tags a wallet is found by; the client queries the
    /// indexer with them directly. The identity tag derives from the public
    /// signing key, so the client computes that one itself.
    ViewTags,
    /// Opens fetched outputs as this wallet's UTXOs, each with its commitment
    /// and nullifier. `assets` resolves compact SPL asset ids to mints.
    Decrypt {
        payloads: Vec<DecryptPayload>,
        assets: Vec<SplAsset>,
    },
    /// Proves and signs one default-pool spend over the client-selected inputs.
    /// The signed transaction is returned; the client submits it.
    Spend {
        tree: String,
        inputs: Vec<SpendInput>,
        action: SpendAction,
        assets: Vec<SplAsset>,
    },
}

impl Operation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Bootstrap => OperationKind::Bootstrap,
            Self::ViewTags => OperationKind::ViewTags,
            Self::Decrypt { .. } => OperationKind::Decrypt,
            Self::Spend { .. } => OperationKind::Spend,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
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
    pub wallet_descriptor: WalletDescriptor,
    #[serde(with = "option_hex_bytes")]
    pub sealed_wallet_state: Option<Vec<u8>>,
    #[serde(with = "hex_bytes")]
    pub client_response_public_key: Vec<u8>,
    pub operation: Operation,
    pub authorization: ClientAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedRequest {
    pub version: u8,
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedWalletState {
    pub version: u8,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub wallet_id_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppProof {
    pub scheme: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub proof_payload: String,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Connection challenge encrypted to the QOS Quorum encryption subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingChallenge {
    pub r#type: String,
    pub version: u8,
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingRequest {
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub encrypted_challenge: Vec<u8>,
}

/// Proof that the running enclave decrypted with the Quorum key and signed the
/// exact challenge bytes with its Ephemeral signing subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QosPingResponse {
    pub version: u8,
    pub tvc_app_proof: AppProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedResponse {
    pub version: u8,
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub encrypted_result: Vec<u8>,
    pub tvc_app_proof: AppProof,
}

/// The typed Turnkey proof fields returned by `turnkey_client`. Their policy
/// evidence is cryptographically valid but unbound to our intent until
/// Turnkey publishes a decision-context binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyAppProof {
    pub scheme: String,
    pub public_key: String,
    pub proof_payload: String,
    pub signature: String,
}

/// Coarse, non-secret failure marker, returned only inside the encrypted result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureStage {
    /// Reading or validating the shielded pool's SPL asset registry.
    AssetRegistry,
    /// Fetching input or nullifier proofs from the pinned indexer.
    IndexerProofs,
    Prover,
    ProofVerification,
    Blockhash,
    TransactionAssembly,
    /// Turnkey declined to sign.
    TurnkeySigning,
    /// Turnkey answered with a different transaction, or without a valid
    /// signature over the one it was given.
    SignedTransactionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum OperationResult {
    Bootstrap {
        solana_address: String,
        #[serde(with = "hex32")]
        shielded_owner_hash: [u8; 32],
        #[serde(with = "hex32")]
        shielded_nullifier_public_key: [u8; 32],
        #[serde(with = "hex_bytes")]
        shielded_viewing_public_key: Vec<u8>,
        /// The seed sealed to the Quorum key. No secret appears elsewhere in
        /// this result.
        #[serde(with = "hex_bytes")]
        sealed_wallet_state: Vec<u8>,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyAppProof>,
    },
    ViewTags {
        #[serde(with = "hex32_vec")]
        view_tags: Vec<[u8; 32]>,
    },
    Decrypt {
        payloads: Vec<DecryptedPayload>,
    },
    Spend {
        #[serde(with = "hex_bytes")]
        signed_transaction: Vec<u8>,
        /// Base58 signature of the signed transaction.
        signature: String,
        turnkey_activity_id: String,
        turnkey_app_proofs: Vec<TurnkeyAppProof>,
    },
    Failure {
        operation: OperationKind,
        stage: FailureStage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProofPayload {
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePolicy {
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
    #[serde(with = "decimal_u64")]
    pub valid_from_ms: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
    #[serde(with = "decimal_u64")]
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthoritySignature {
    pub key_id: String,
    pub scheme: ClientAuthorizationScheme,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleasePolicy {
    pub policy: ReleasePolicy,
    pub authority_set_id: String,
    pub signatures: Vec<ReleaseAuthoritySignature>,
}

pub fn parse_operation_request(json: &str) -> Result<OperationRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_encrypted_request(json: &str) -> Result<EncryptedRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_service_info(json: &str) -> Result<ServiceInfo, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_request(json: &str) -> Result<QosPingRequest, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn parse_qos_ping_challenge(json: &str) -> Result<QosPingChallenge, TvcError> {
    encoding::parse_strict_json(json)
}

pub fn reject_production_environment(environment: Environment) -> Result<(), TvcError> {
    match environment {
        Environment::Development => Ok(()),
        Environment::Production => Err(TvcError::new(ErrorCode::ProductionClaimRejected)),
    }
}
