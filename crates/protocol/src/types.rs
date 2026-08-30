//! Versioned request, response, discovery, and evidence types.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::encoding::{
    self, decimal_u64, hex32, hex32_vec, hex_bytes, hex_bytes_vec, option_decimal_u64,
    option_hex32, option_hex_bytes,
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
/// What a request asks for, as advertised by `/v1/info`, granted by a
/// descriptor, and named in the App Proof.
///
pub enum OperationKind {
    BootstrapKeyholder,
    DeriveViewTags,
    DecryptUtxos,
    AuthorizeSpend,
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

/// Public metadata for one output the enclave has verified is currently
/// spendable by this wallet. Secret UTXO material and nullifiers never leave
/// the enclave; the commitment lets the client filter its locally decrypted
/// openings without trusting browser-side spent-UTXO bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendableOutputV1 {
    #[serde(with = "hex32")]
    pub commitment: [u8; 32],
    pub asset: AssetV1,
    #[serde(with = "decimal_u64")]
    pub amount: u64,
    pub ring_program_id: Option<String>,
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
    DecryptUtxos {
        payloads: Vec<EncryptedPayloadV1>,
        /// Also reconcile the wallet against the pinned chain/indexer view and
        /// return its currently spendable outputs. Clients normally request
        /// this once after paging ciphertext decryption.
        include_spendable_outputs: bool,
    },
    /// Prepares or finalizes one private spend. The phase is nested so strict
    /// serde parsing can reject unknown fields without a custom wire parser.
    AuthorizeSpend { spend: AuthorizeSpendRequestV1 },
}

/// The only two protocol phases of `AuthorizeSpend`. A wallet SDK may expose a
/// one-call convenience method, but the enclave protocol has no execute mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub enum AuthorizeSpendRequestV1 {
    /// Produces either an exact direct transaction or a generic proved SPP
    /// transition, plus a short-lived sealed authorization capsule. It does
    /// not call Turnkey.
    Prepare { plan: SpendPlanV1 },
    /// Finalizes only the artifact and authority committed by the capsule.
    Finalize {
        #[serde(with = "hex_bytes")]
        sealed_authorization_capsule: Vec<u8>,
        /// One complete, unsigned Solana transaction. The sealed capsule
        /// decides whether it must match an exact direct transaction or carry
        /// a program instruction bound to a prepared private transition.
        #[serde(with = "hex_bytes")]
        unsigned_transaction: Vec<u8>,
    },
}

/// A direct wallet transition or a program-neutral private SPP transition. Both
/// variants use the same prepare/finalize protocol; the direct adapter keeps
/// the basic wallet UI small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum SpendPlanV1 {
    /// A canonical wallet transfer, withdrawal, or custom-ring transition.
    /// TVC returns the complete transaction ready for final authorization.
    Direct { transition: SpendIntentV1 },
    /// A program-neutral private transition. The ecosystem SDK composes the
    /// returned hash-bound transition into a complete Solana transaction.
    Program { transition: SppPlanV1 },
}

/// One program-neutral, asset-conserving SPP transition. The target program may
/// interpret data and prove arbitrary business semantics, but all value stays
/// private and its instruction must carry the prepared `private_tx_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SppPlanV1 {
    pub program_id: String,
    pub input_tree: String,
    pub shape: SppShapeV1,
    pub inputs: Vec<SppPlanInputV1>,
    /// Program PDAs that the target may promote to CPI signers. Seeds include
    /// the canonical bump and are resolved under `program_id` during prepare.
    pub program_authorities: Vec<SppProgramAuthorityV1>,
    pub outputs: Vec<SppPlanOutputV1>,
    pub messages: Vec<SppMessageV1>,
    #[serde(with = "decimal_u64")]
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SppProgramAuthorityV1 {
    #[serde(with = "hex_bytes_vec")]
    pub seeds: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SppShapeV1 {
    pub inputs: u8,
    pub outputs: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum SppPlanInputV1 {
    /// A commitment TVC must rediscover as an unspent UTXO owned by this wallet.
    Wallet {
        #[serde(with = "hex32")]
        commitment: [u8; 32],
    },
    /// A program-PDA-owned UTXO. The opening is a bearer capability supplied
    /// by the program SDK; TVC verifies both its commitment and PDA derivation.
    Program {
        #[serde(with = "hex32")]
        commitment: [u8; 32],
        #[serde(with = "hex_bytes_vec")]
        authority_seeds: Vec<Vec<u8>>,
        asset: AssetV1,
        #[serde(with = "decimal_u64")]
        amount: u64,
        #[serde(with = "hex32")]
        blinding: [u8; 32],
        #[serde(with = "option_hex32")]
        data_hash: Option<[u8; 32]>,
        #[serde(with = "hex_bytes")]
        nullifier_secret: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SppPlanOutputV1 {
    /// Base58 Zolana shielded address, including owner, nullifier, and viewing
    /// public keys.
    pub recipient: String,
    pub asset: AssetV1,
    #[serde(with = "decimal_u64")]
    pub amount: u64,
    #[serde(with = "hex32")]
    pub blinding: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
    #[serde(with = "option_hex32")]
    pub data_hash: Option<[u8; 32]>,
    #[serde(with = "hex_bytes")]
    pub memo: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SppMessageV1 {
    #[serde(with = "hex32")]
    pub view_tag: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
}

/// What a ring spend settles to. Separate variants rather than a nullable
/// recipient pair, so a public withdrawal and private transfer cannot be confused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum SpendSettlementV1 {
    Transfer {
        asset: AssetV1,
        /// Registered shielded recipient.
        recipient: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
        /// Where the recipient UTXO will live. The route is derived from the
        /// source and destination domains; it is never supplied separately.
        destination: PrivateDomainV1,
    },
    SolWithdrawal {
        /// Public recipient, never resolved as a shielded address.
        recipient: String,
        #[serde(with = "decimal_u64")]
        amount: u64,
    },
}

/// One direct private transition. TVC rediscovers the source UTXOs and derives
/// any ring boundary crossing from the source and destination domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendIntentV1 {
    pub source: PrivateDomainV1,
    pub settlement: SpendSettlementV1,
    /// Exact default-ring inputs for a transition into a ring. Requiring the
    /// caller to name the bridge UTXO prevents unrelated default-ring value
    /// from following it into the custom ring.
    #[serde(with = "hex32_vec")]
    pub input_commitments: Vec<[u8; 32]>,
}

/// The policy domain of a private UTXO. A direction is deliberately absent:
/// Default -> Ring, Ring -> Default, and Ring -> the same Ring are derived from
/// the source and destination values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum PrivateDomainV1 {
    Default,
    Ring {
        /// The ring program bound into input and output commitments.
        program_id: String,
        /// A lookup table covering the ring transact's stable accounts.
        lookup_table: String,
    },
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

/// Public envelope for a prepared-spend authorization. The ciphertext is
/// opaque outside the enclave; the visible bindings allow cheap rejection of
/// a capsule replayed for another wallet or Quorum epoch before decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSpendAuthorizationV1 {
    pub version: u8,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
    pub wallet_id_hash: [u8; 32],
    pub prepare_request_id: [u8; 32],
    pub expires_at_ms: u64,
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

/// Coarse, non-secret stage marker returned only inside the authenticated,
/// encrypted operation response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureStage {
    /// Reading or validating the shielded pool's classic SPL asset registry.
    AssetRegistry,
    /// The bounded balance scan could not read or decode the pinned index.
    WalletIndexRead,
    /// Indexed records were readable, but could not be reconstructed under the
    /// sealed wallet authority.
    WalletReconstruction,
    /// Owned outputs were reconstructed, but their nullifier status could not
    /// be read from the pinned index.
    WalletNullifierRead,
    /// The complete spendable snapshot exceeds the protocol response bound.
    WalletSnapshotTooLarge,
    /// The complete balance reconciliation exceeded its request deadline.
    WalletSync,
    ShieldedBalanceNotReady,
    /// The spendable balance sits inside a custom ring, which the default-ring
    /// path cannot spend.
    FundsAreRingBound,
    SettlementConstruction,
    /// The selected default-ring UTXOs do not fit any installed SPP circuit
    /// shape. Callers can retry with a smaller amount or consolidate UTXOs.
    UnsupportedProofShape,
    /// A UTXO selected for the default transact rail does not use its required
    /// Ed25519 owner encoding.
    UnsupportedShieldedOwner,
    /// The wallet changed between construction and shielded finalization.
    ShieldedInputChanged,
    /// The restored authority and the synced wallet identity disagree.
    ShieldedIdentityMismatch,
    PrivateTransitionAssembly,
    LatestBlockhash,
    TransactionAssembly,
    RpcValidation,
    IndexerProofs,
    /// Reading or validating the ring transact's address lookup table.
    LookupTable,
    /// Reading or validating the ring program's own config account, which is
    /// where the auditor key comes from.
    RingConfig,
    /// Reading or validating the state tree the spent outputs live in.
    InputTree,
    /// Turnkey answered, but not with the transaction it was asked to sign, or
    /// not with a signature over it. Distinct from `TurnkeySigning`, which is
    /// Turnkey declining to sign at all.
    SignedTransactionMismatch,
    ProofAssembly,
    ExternalProver,
    LocalProofVerification,
    TurnkeySigning,
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
        /// Present exactly when the request set `include_spendable_outputs`.
        /// `null` is explicit on the wire so strict clients cannot confuse an
        /// older response with a deliberately omitted snapshot.
        spendable_outputs: Option<Vec<SpendableOutputV1>>,
    },
    AuthorizeSpend {
        #[serde(flatten)]
        result: AuthorizeSpendResultV1,
    },
    Failure {
        operation: OperationKind,
        stage: FailureStage,
    },
}

/// The two results of the split authorization protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
pub enum AuthorizeSpendResultV1 {
    Prepare {
        prepared: PreparedSpendV1,
        #[serde(with = "hex_bytes")]
        sealed_authorization_capsule: Vec<u8>,
        #[serde(with = "hex_bytes")]
        sealed_wallet_state: Vec<u8>,
        #[serde(with = "decimal_u64")]
        state_version: u64,
        #[serde(with = "hex32")]
        state_digest: [u8; 32],
        #[serde(with = "decimal_u64")]
        shielded_balance_before: u64,
    },
    Finalize {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum PreparedSpendV1 {
    ExactTransaction {
        #[serde(with = "hex_bytes")]
        unsigned_transaction: Vec<u8>,
        #[serde(with = "hex32")]
        transaction_digest: [u8; 32],
    },
    Spp {
        program_id: String,
        input_tree: String,
        #[serde(with = "hex32")]
        plan_digest: [u8; 32],
        #[serde(with = "hex_bytes")]
        transact: Vec<u8>,
        #[serde(with = "hex32")]
        transact_digest: [u8; 32],
        #[serde(with = "hex32")]
        private_tx_hash: [u8; 32],
        #[serde(with = "hex32")]
        external_data_hash: [u8; 32],
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
            Self::AuthorizeSpend { .. } => OperationKind::AuthorizeSpend,
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
