//! Encrypted operations for the privacy wallet's keyholder security model.
//!
//! This service is a stateless oracle for the wallet's privacy keys. It holds
//! the derivation seed only for the duration of one request, unsealed from a
//! blob the client presents and stores nothing across requests. The client
//! performs the normal sync calls. The disposable development spend is the
//! explicit exception: TVC syncs from the pinned indexer and sends a plaintext
//! witness to the pinned prover before it signs the resulting transaction.
//!
//! Only bootstrap and transaction authorization reach Turnkey. `DeriveViewTags`
//! and `DecryptUtxos` derive everything they need from the unsealed seed, so
//! they make no outbound call at all.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Response, StatusCode};
use borsh::{BorshDeserialize, BorshSerialize};
use custom_ring_sdk::{
    AsyncTransferProofEnvironment, CustomRing, CustomRingTransfer, CustomRingTransferInput,
    TransferError,
};
use sha2::{Digest as _, Sha256};
use solana_address::Address;
use solana_address_lookup_table_interface::state::AddressLookupTable;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use turnkey_client::generated::immutable::{
    activity::v1::{SignRawPayloadIntentV2, SignTransactionIntentV2},
    common::v1::{HashFunction, PayloadEncoding, TransactionType},
};
use turnkey_client::{ActivityResult, TurnkeyClient};
use zeroize::{Zeroize, Zeroizing};
use zolana_client::{
    assemble, verify_confidential_transfer_inputs, AsyncProverClient, AsyncRpc, ClientError,
    ProofCompressed, ProverInputs, SppProofInputUtxo, ZolanaClient,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::MessageData, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts,
    },
    pda,
    state::SplAssetRegistry,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::shielded::ShieldedAddress;
use zolana_keypair::viewing_key::Salt;
use zolana_keypair::{
    constants::BLINDING_LEN, derivation, Curve, NullifierKey, P256Pubkey, PublicKey,
    ShieldedKeypairTrait, ViewingKey,
};
use zolana_keypair_turnkey::{
    TurnkeyActivities, TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
};
use zolana_transaction::instructions::transact::{
    encrypt_transaction_data, get_transaction_viewing_key, ConfidentialTransfer, ExternalData,
    SettlementTarget, Shape, SppProofInputs, SppProofOutputUtxo, SPP_SUPPORTED_SHAPES,
};
use zolana_transaction::wallet::authority::WalletAuthority;
use zolana_transaction::{AssetRegistry, TransactionError, Utxo, Wallet, SOL_MINT};
use zolana_tvc_protocol::bindings::{
    check_encrypted_request_bindings, check_request_bindings, RunningEnclave,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES, MAX_CLOCK_SKEW_MS,
    MAX_DECRYPT_PAYLOADS_PER_BATCH, MAX_REQUEST_AGE_MS, TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{qos_encrypt, verify_p256_prehash, QosP256Public};
use zolana_tvc_protocol::digest::{
    artifact_digest, descriptor_digest_from_wallet, owner_auth_evidence_digest,
    provisioning_auth_digest, request_digest, result_digest, state_digest, wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, AssetV1, AuthorizeSpendRequestV1,
    AuthorizeSpendResultV1, DecryptedPayloadV1, EncryptedPayloadV1, EncryptedResponseV1,
    Environment, FailureStage, OperationKind, OperationRequestV1, OperationResultV1, OperationV1,
    PreparedSpendV1, RingDirectionV1, SealedSpendAuthorizationV1, SealedWalletStateV1,
    SolanaInstructionV1, SpendFinalizationV1, SpendIntentV1, SpendPlanV1, SpendSettlementV1,
    SppPlanInputV1, SppPlanV1, SppPublicEffectsV1, TurnkeyEvidenceClassification,
    TurnkeySigningTargetV1, TurnkeyVerifiedAppProofV1, TvcAppProofV1, TvcOperationProofPayloadV1,
};
use zolana_tvc_protocol::{public_http_error, PublicError};
use zolana_wallet::{
    create_transfer, create_withdrawal, sign_shielded_transaction, sync_wallet_with_config_async,
    try_resolve_registered_address_async, KeypairWalletAuthority, SyncWalletConfig, TransferParams,
    WithdrawalLeg, WithdrawalParams,
};

use crate::solana_rpc::SolanaRpc;
use crate::turnkey::QosTurnkeyStamper;
use crate::{into_response, sign_ephemeral_low_s, AppState, RuntimeKeys};

const TURNKEY_DERIVATION_PATH: &str = "m/44'/501'/0'/0'";
const PROVISIONING_KEY_ID: &str = "wallet-dev-e2e-provisioner-v1";
const BROWSER_CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
const MAX_SOLANA_TRANSACTION_BYTES: usize = 1_232;
const MAX_GENERIC_ACCOUNTS: usize = 64;
const MAX_GENERIC_LOOKUP_TABLES: usize = 4;
const MAX_GENERIC_INSTRUCTION_BYTES: usize = 8_192;
const MAX_GENERIC_DATA_BYTES: usize = 4_096;
const MAX_GENERIC_MESSAGES: usize = 8;
const MAX_GENERIC_PROGRAM_AUTHORITIES: usize = 8;
const DEVNET_EXTERNAL_PROVER_PROFILE_ID: &str = "zolnet-devnet-external-http-v1";
const EXPECTED_EXTERNAL_ORIGIN: &str =
    "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
/// The prover a custom-ring spend proves against.
///
/// A ring spend proves twice through one client: the pooled `transfer-ring`
/// proof, and then the `custom-ring` proof over the public-input chain the
/// first one produced. Only this deployment carries the second circuit, so the
/// whole ring path goes here rather than to the default prover.
///
/// Like the default origin this is fixed in the image. A caller names which
/// ring to spend in, never which prover proves it.
const EXPECTED_CUSTOM_RING_PROVER_ORIGIN: &str = "https://d30sgubc9yxiri.cloudfront.net";
const DEVNET_DEFAULT_TREE: &str = "trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho";

/// The exact grant a privacy-wallet descriptor must carry. Bootstrap seals the key
/// state; the two oracle operations read it; authorization signs. Nothing here
/// releases a key.
///
/// This profile grants the whole set or nothing, so listing the custom-ring
/// spends separately does not narrow what a browser descriptor may do. It makes
/// the authority nameable: `/v1/info` can advertise it, the App Proof records
/// which one was exercised, and a profile that wants to withhold it can.
const KEYHOLDER_OPERATIONS: [OperationKind; 4] = [
    OperationKind::BootstrapKeyholder,
    OperationKind::DeriveViewTags,
    OperationKind::DecryptUtxos,
    OperationKind::AuthorizeSpend,
];

// Disposable development provisioner key. Only the public half is present in
// the image; its private half remains outside TVC.
const PROVISIONING_PUBLIC: [u8; 65] = [
    0x04, 0x94, 0xc6, 0x1a, 0x25, 0xe2, 0xd5, 0x0e, 0x7e, 0x20, 0xc8, 0xfc, 0xd7, 0xe2, 0xa9, 0x39,
    0x45, 0x22, 0x76, 0x04, 0x78, 0xd7, 0xe6, 0xe7, 0x93, 0x1a, 0xc6, 0x09, 0x59, 0xdb, 0x24, 0xe0,
    0xa8, 0x28, 0x38, 0x9f, 0x39, 0x0f, 0x75, 0xbf, 0x00, 0xfb, 0xac, 0x61, 0x63, 0x84, 0x86, 0x78,
    0x2b, 0x78, 0x5c, 0x40, 0xba, 0x8e, 0x33, 0x4e, 0x21, 0x5b, 0x47, 0x6d, 0x9d, 0x1f, 0x22, 0x3f,
    0x4f,
];

type TvcTurnkeyClient = TurnkeyClient<QosTurnkeyStamper>;

struct ValidatedWallet<'a> {
    organization_id: &'a str,
    sign_with: &'a str,
    address: Pubkey,
    expected_ed25519_public_key: [u8; 32],
}

#[derive(Debug)]
enum OperationFailure {
    Invalid,
    Unavailable,
    Failed(FailureStage),
}

pub(crate) async fn handle_operation(state: &AppState, body: &[u8]) -> Response<Body> {
    match execute(state, body).await {
        Ok(response) => into_response(zolana_tvc_protocol::PublicHttpResponse {
            status: StatusCode::OK.as_u16(),
            content_type: "application/json",
            body: response.into_bytes(),
        }),
        Err(OperationFailure::Invalid) => {
            into_response(public_http_error(PublicError::InvalidRequest))
        }
        Err(OperationFailure::Unavailable | OperationFailure::Failed(_)) => {
            into_response(public_http_error(PublicError::Unavailable))
        }
    }
}

async fn execute(state: &AppState, body: &[u8]) -> Result<String, OperationFailure> {
    let keys = state.keys.as_ref().ok_or(OperationFailure::Unavailable)?;
    let body = std::str::from_utf8(body).map_err(|_| OperationFailure::Invalid)?;
    let encrypted = parse_encrypted_request(body).map_err(|_| OperationFailure::Invalid)?;
    let running = running_enclave(state);
    check_encrypted_request_bindings(&encrypted, &running)
        .map_err(|_| OperationFailure::Invalid)?;

    let plaintext = Zeroizing::new(
        keys.quorum
            .decrypt(&encrypted.ciphertext)
            .map_err(|_| OperationFailure::Invalid)?,
    );
    let plaintext_utf8 = std::str::from_utf8(&plaintext).map_err(|_| OperationFailure::Invalid)?;
    if !is_rfc8785(plaintext_utf8) {
        return Err(OperationFailure::Invalid);
    }
    let request = parse_operation_request(plaintext_utf8).map_err(|_| OperationFailure::Invalid)?;
    let wallet = validate_request(&request, &running, state)?;
    let request_hash = request_digest(&request).map_err(|_| OperationFailure::Invalid)?;
    let client_response_key = QosP256Public::from_bytes(&request.client_response_public_key)
        .map_err(|_| OperationFailure::Invalid)?;

    // Every result carries the digest of the sealed state it was computed
    // against, so the App Proof binds the answer to one specific key state
    // rather than merely to the request.
    let (result, proof_state_digest) = match &request.operation {
        OperationV1::BootstrapKeyholder => bootstrap_keyholder(&request, &wallet, keys).await?,
        OperationV1::DeriveViewTags => derive_view_tags(&request, keys)?,
        OperationV1::DecryptUtxos { payloads } => decrypt_utxos(&request, keys, payloads)?,
        OperationV1::AuthorizeSpend { spend } => {
            match authorize_spend(&request, &wallet, spend, keys).await {
                Ok(result) => result,
                Err(OperationFailure::Failed(stage)) => (
                    OperationResultV1::Failure {
                        operation: request.operation.kind(),
                        stage,
                    },
                    request.expected_state_digest.unwrap_or([0; 32]),
                ),
                Err(error) => return Err(error),
            }
        }
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| OperationFailure::Unavailable)?);
    let encrypted_result =
        qos_encrypt(&client_response_key.encryption, result_plaintext.as_bytes())
            .map_err(|_| OperationFailure::Unavailable)?;
    if encrypted_result.len() as u64 > DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(OperationFailure::Unavailable);
    }

    let result_hash = result_digest(&encrypted_result);
    let proof_payload = jcs_serialize(&TvcOperationProofPayloadV1 {
        r#type: TVC_APP_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest: request_hash,
        result_digest: result_hash,
        operation: request.operation.kind(),
        state_digest: proof_state_digest,
    })
    .map_err(|_| OperationFailure::Unavailable)?;
    let signature = sign_ephemeral_low_s(&keys.ephemeral, proof_payload.as_bytes())
        .map_err(|_| OperationFailure::Unavailable)?;
    let response = EncryptedResponseV1 {
        version: API_VERSION,
        request_id: request.request_id,
        encrypted_result,
        tvc_app_proof: TvcAppProofV1 {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: keys.ephemeral.public_key().to_bytes(),
            proof_payload,
            signature,
        },
    };
    jcs_serialize(&response).map_err(|_| OperationFailure::Unavailable)
}

fn running_enclave(state: &AppState) -> RunningEnclave {
    RunningEnclave {
        release_id: state.info.release_id.clone(),
        manifest_digest: state.info.manifest_digest,
        executable_digest: state.info.executable_digest,
        security_domain_id: state.info.security_domain_id,
        quorum_key_id: state.info.quorum_key_id.clone(),
        quorum_key_epoch: state.info.quorum_key_epoch,
        environment: state.info.environment,
    }
}

fn validate_request<'a>(
    request: &'a OperationRequestV1,
    running: &RunningEnclave,
    state: &AppState,
) -> Result<ValidatedWallet<'a>, OperationFailure> {
    check_request_bindings(request, running).map_err(|_| OperationFailure::Invalid)?;
    if running.environment != Environment::Development
        || !state
            .info
            .supported_operations
            .contains(&request.operation.kind())
        || !operation_state_fields_are_valid(request)
    {
        return Err(OperationFailure::Invalid);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperationFailure::Unavailable)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| OperationFailure::Unavailable)?;
    if request.expires_at_ms < now
        || request.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || request.expires_at_ms < request.issued_at_ms
        || request.expires_at_ms - request.issued_at_ms > MAX_REQUEST_AGE_MS
    {
        return Err(OperationFailure::Invalid);
    }

    let wallet = validate_descriptor(request)?;
    let grant = request
        .wallet_descriptor
        .allowed_clients
        .iter()
        .find(|grant| grant.client_key_id == request.authorization.client_key_id)
        .ok_or(OperationFailure::Invalid)?;
    zolana_tvc_protocol::verify_client_authorization(request, &grant.client_public_key)
        .map_err(|_| OperationFailure::Invalid)?;
    if grant.scheme != request.authorization.scheme
        || !grant.allowed_operations.contains(&request.operation.kind())
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(wallet)
}

/// Enforces the checkpoint shape before descriptor validation or any outbound
/// call. Oracle operations need the complete state tuple they answer against;
/// bootstrap and the signing rail must remain independent of caller-selected
/// state. Partial tuples are always invalid.
fn operation_state_fields_are_valid(request: &OperationRequestV1) -> bool {
    let has_no_state = request.sealed_wallet_state.is_none()
        && request.expected_state_version.is_none()
        && request.expected_state_digest.is_none();
    let has_complete_state = request.sealed_wallet_state.is_some()
        && request.expected_state_version.is_some()
        && request.expected_state_digest.is_some();

    match &request.operation {
        OperationV1::BootstrapKeyholder => has_no_state,
        OperationV1::DeriveViewTags
        | OperationV1::DecryptUtxos { .. }
        | OperationV1::AuthorizeSpend { .. } => has_complete_state,
    }
}

fn validate_descriptor(
    request: &OperationRequestV1,
) -> Result<ValidatedWallet<'_>, OperationFailure> {
    let descriptor = &request.wallet_descriptor;
    let TurnkeySigningTargetV1::HdWalletAccount {
        turnkey_wallet_id,
        wallet_account_id,
        address,
        derivation_path,
    } = &descriptor.turnkey_signing_target
    else {
        return Err(OperationFailure::Invalid);
    };
    let address_pubkey = Pubkey::from_str(address).map_err(|_| OperationFailure::Invalid)?;
    if address_pubkey.to_bytes() != descriptor.expected_ed25519_public_key {
        return Err(OperationFailure::Invalid);
    }
    if descriptor.version != API_VERSION
        || !is_uuid(&descriptor.turnkey_parent_organization_id)
        || !is_uuid(&descriptor.turnkey_organization_id)
        || !is_uuid(&descriptor.turnkey_service_user_id)
        || !is_uuid(&descriptor.turnkey_api_key_id)
        || descriptor.wallet_id != format!("wallet-{turnkey_wallet_id}")
        || turnkey_wallet_id.is_empty()
        || turnkey_wallet_id.len() > 128
        || wallet_account_id.is_empty()
        || wallet_account_id.len() > 128
        || derivation_path != TURNKEY_DERIVATION_PATH
        || descriptor.policy_version != 1
        || descriptor.previous_descriptor_digest.is_some()
        || descriptor.environment != Environment::Development
        || descriptor.provisioning_key_id != PROVISIONING_KEY_ID
        || descriptor.owner_authorization_key.is_some()
        || descriptor.recovery_binding.is_some()
        || descriptor.owner_authorization.is_some()
        || descriptor.prior_client_authorization.is_some()
        || descriptor.allowed_clients.len() != 1
    {
        return Err(OperationFailure::Invalid);
    }

    let descriptor_hash =
        descriptor_digest_from_wallet(descriptor).map_err(|_| OperationFailure::Invalid)?;
    let owner_evidence_hash = owner_auth_evidence_digest(
        &descriptor.owner_authorization_key,
        &descriptor.owner_authorization,
        &descriptor.prior_client_authorization,
    )
    .map_err(|_| OperationFailure::Invalid)?;
    let provisioning_hash = provisioning_auth_digest(&descriptor_hash, &owner_evidence_hash);
    verify_p256_prehash(
        &PROVISIONING_PUBLIC,
        &provisioning_hash,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| OperationFailure::Invalid)?;

    let grant = descriptor
        .allowed_clients
        .first()
        .ok_or(OperationFailure::Invalid)?;
    let expected_client_key_id = format!(
        "{BROWSER_CLIENT_KEY_ID_PREFIX}{}",
        hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
    );
    if grant.client_key_id != expected_client_key_id
        || grant.client_public_key.len() != 65
        || grant.allowed_operations != KEYHOLDER_OPERATIONS
        || grant.scheme != zolana_tvc_protocol::types::ClientAuthorizationScheme::P256Sha256
        || grant.may_rotate_descriptor
    {
        return Err(OperationFailure::Invalid);
    }

    Ok(ValidatedWallet {
        organization_id: &descriptor.turnkey_organization_id,
        sign_with: address,
        address: address_pubkey,
        expected_ed25519_public_key: descriptor.expected_ed25519_public_key,
    })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}

fn turnkey_client(keys: &RuntimeKeys) -> Result<Arc<TvcTurnkeyClient>, OperationFailure> {
    let stamper = QosTurnkeyStamper::new(Arc::clone(&keys.quorum));
    let client = TurnkeyClient::builder()
        .api_key(stamper)
        .build()
        .map_err(|_| OperationFailure::Unavailable)?
        .with_app_proofs();
    Ok(Arc::new(client))
}

/// Borsh-sealed contents of the key state. The seed is the only secret; every
/// other field exists so the blob cannot be replayed against a different
/// descriptor, wallet, or Quorum key epoch.
#[derive(BorshSerialize, BorshDeserialize)]
struct KeyStatePlaintextV1 {
    version: u8,
    quorum_key_id: String,
    quorum_key_epoch: u64,
    wallet_id: String,
    descriptor_digest: [u8; 32],
    policy_version: u64,
    state_version: u64,
    previous_state_digest: Option<[u8; 32]>,
    ed25519_public_key: [u8; 32],
    derivation_suite: String,
    derivation_seed: [u8; 64],
}

impl Drop for KeyStatePlaintextV1 {
    fn drop(&mut self) {
        self.derivation_seed.zeroize();
    }
}

/// Enclave-only contents of a prepared-spend capsule. It commits to one exact
/// built-in transaction or one exact generic SPP transition, plus all ambient
/// authority that made preparation valid. Finalization is stateless: the
/// caller stores and returns the sealed capsule but cannot alter these fields.
#[derive(BorshSerialize, BorshDeserialize)]
struct SpendAuthorizationPlaintextV1 {
    version: u8,
    quorum_key_id: String,
    quorum_key_epoch: u64,
    wallet_id: String,
    descriptor_digest: [u8; 32],
    policy_version: u64,
    state_version: u64,
    state_digest: [u8; 32],
    target_release_id: String,
    target_manifest_digest: [u8; 32],
    target_executable_digest: [u8; 32],
    prepare_request_id: [u8; 32],
    expires_at_ms: u64,
    artifact: SpendAuthorizationArtifactV1,
    shielded_balance_before: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum SpendAuthorizationArtifactV1 {
    ExactTransaction {
        transaction_digest: [u8; 32],
    },
    Spp {
        program_id: [u8; 32],
        input_tree: [u8; 32],
        program_authorities: Vec<[u8; 32]>,
        plan_digest: [u8; 32],
        prepared_transact: Vec<u8>,
        transact_digest: [u8; 32],
        private_tx_hash: [u8; 32],
    },
}

async fn bootstrap_keyholder(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    // A bootstrap request must not carry a prior state: accepting one would let
    // a caller pick which key state a fresh derivation appears to continue.
    if request.sealed_wallet_state.is_some()
        || request.expected_state_version.is_some()
        || request.expected_state_digest.is_some()
    {
        return Err(OperationFailure::Invalid);
    }

    let client = turnkey_client(keys)?;
    let envelope = derivation::ed25519_derivation_message(&wallet.expected_ed25519_public_key);
    let activity = client
        .sign_raw_payload(
            wallet.organization_id.to_owned(),
            u128::from(request.issued_at_ms),
            SignRawPayloadIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                payload: hex::encode(&envelope),
                encoding: PayloadEncoding::Hexadecimal,
                hash_function: HashFunction::NotApplicable,
            },
        )
        .await
        .map_err(|_| OperationFailure::Unavailable)?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Unavailable);
    }

    let mut seed = Zeroizing::new([0u8; 64]);
    decode_signature_component(&activity.result.r, &mut seed[..32])?;
    decode_signature_component(&activity.result.s, &mut seed[32..])?;
    let activities: Arc<dyn TurnkeyActivities> =
        Arc::new(TurnkeyApiActivities::new(Arc::clone(&client)));
    let keypair = TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        activities,
        TurnkeyKeyRef::new(wallet.organization_id, wallet.sign_with),
        wallet.expected_ed25519_public_key,
        &seed,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let shielded_address = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Unavailable)?;
    let (_, sealed_bytes, digest) = seal_state(
        keys,
        KeyStatePlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id.clone(),
            descriptor_digest: descriptor_hash,
            policy_version: request.wallet_descriptor.policy_version,
            state_version: 1,
            previous_state_digest: None,
            ed25519_public_key: wallet.expected_ed25519_public_key,
            derivation_suite: DERIVATION_SUITE.to_owned(),
            derivation_seed: *seed,
        },
    )?;

    let turnkey_app_proofs = app_proofs(&activity);
    Ok((
        OperationResultV1::BootstrapKeyholder {
            solana_address: wallet.sign_with.to_owned(),
            shielded_owner_hash: shielded_address
                .owner_hash()
                .map_err(|_| OperationFailure::Unavailable)?,
            shielded_nullifier_public_key: shielded_address.nullifier_pubkey,
            shielded_viewing_public_key: shielded_address.viewing_pubkey.as_bytes().to_vec(),
            sealed_wallet_state: sealed_bytes,
            state_version: 1,
            state_digest: digest,
            derivation_suite: DERIVATION_SUITE.to_owned(),
            turnkey_activity_id: activity.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

/// Rebuilds the wallet's registered Ed25519 identity from sealed state.
///
/// The deployed custom-ring program authorizes `RingEddsa`: the same Turnkey
/// wallet key is both the ring owner and the Solana fee payer. The derivation
/// seed supplies the private nullifier and viewing roles without exposing
/// either role to the browser.
fn default_keypair(
    client: &Arc<TvcTurnkeyClient>,
    wallet: &ValidatedWallet<'_>,
    inner: &KeyStatePlaintextV1,
) -> Result<TurnkeyEd25519ShieldedKeypair, OperationFailure> {
    let activities: Arc<dyn TurnkeyActivities> =
        Arc::new(TurnkeyApiActivities::new(Arc::clone(client)));
    TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        activities,
        TurnkeyKeyRef::new(wallet.organization_id, wallet.sign_with),
        inner.ed25519_public_key,
        &inner.derivation_seed,
    )
    .map_err(|_| OperationFailure::Invalid)
}

/// Syncs a fresh wallet for one shielded identity.
async fn synced_wallet<A: WalletAuthority + ?Sized>(
    owner: ShieldedAddress,
    authority: &A,
    assets: AssetRegistry,
    zolana: &ZolanaClient<SolanaRpc>,
) -> Result<Wallet, OperationFailure> {
    let mut wallet = Wallet::new(owner, assets).map_err(|_| OperationFailure::Unavailable)?;
    // Pin every indexer query to a slot already observed through the chain RPC.
    // Without this gate, a just-confirmed spend can be absent from the
    // indexer's nullifier stream and the fresh wallet may select that note
    // again. SPP then rejects the duplicate nullifier on chain as 7002.
    let require_slot = zolana
        .rpc()
        .get_slot()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))?;
    sync_wallet_with_config_async(
        &mut wallet,
        authority,
        zolana,
        SyncWalletConfig::at_slot(require_slot),
    )
    .await
    .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))?;
    Ok(wallet)
}

/// Recovers the viewing key for one request. The seed is unsealed, expanded,
/// and dropped with the returned `Zeroizing` seed at the end of the call.
fn viewing_key_for(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
) -> Result<(ViewingKey, [u8; 32]), OperationFailure> {
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let (_nullifier_key, viewing_key) =
        derivation::expand_roles(&inner.derivation_seed, Curve::Ed25519)
            .map_err(|_| OperationFailure::Invalid)?;
    Ok((viewing_key, digest))
}

/// Derives the wallet's recipient bootstrap view tags. No outbound call: the
/// tags come straight from the unsealed seed.
///
/// One tag per viewing key the application holds. These are the stable tags a
/// wallet is found by, so the client queries the indexer with them directly.
/// The scan's other tag is the identity tag, which derives from the signing
/// *public* key; the client computes that itself rather than asking, so this
/// operation never reveals more than it must.
fn derive_view_tags(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let (viewing_key, digest) = viewing_key_for(request, keys)?;
    Ok((
        OperationResultV1::DeriveViewTags {
            view_tags: vec![viewing_key.recipient_bootstrap_view_tag()],
        },
        digest,
    ))
}

/// Decrypts one batch of ciphertexts the client fetched.
///
/// The shielded-pool transport cipher is AES-CTR with no authentication tag, so
/// this operation cannot tell a payload addressed to this wallet from one
/// addressed to another -- the second decrypts to garbage rather than failing.
/// It therefore never asserts ownership. The client deserializes each plaintext
/// and checks the recovered owner against its own; that check is the one that
/// decides, and it belongs where the SDK already lives.
fn decrypt_utxos(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    payloads: &[EncryptedPayloadV1],
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if payloads.is_empty() || payloads.len() as u64 > MAX_DECRYPT_PAYLOADS_PER_BATCH {
        return Err(OperationFailure::Invalid);
    }
    let (viewing_key, digest) = viewing_key_for(request, keys)?;

    let mut results = Vec::with_capacity(payloads.len());
    for (position, payload) in payloads.iter().enumerate() {
        let index = position as u64;
        let plaintext = match payload {
            EncryptedPayloadV1::Utxo {
                ciphertext,
                transaction_viewing_public_key,
                salt,
                slot_index,
            } => {
                let slot = u32::try_from(*slot_index).map_err(|_| OperationFailure::Invalid)?;
                viewing_key
                    .decrypt_utxo(
                        ciphertext,
                        &transaction_viewing_key(transaction_viewing_public_key)?,
                        decode_salt(salt)?,
                        slot,
                    )
                    .ok()
            }
            EncryptedPayloadV1::RingDeposit {
                ciphertext,
                transaction_viewing_public_key,
                salt,
            } => viewing_key
                .decrypt_ring_deposit(
                    ciphertext,
                    &transaction_viewing_key(transaction_viewing_public_key)?,
                    decode_salt(salt)?,
                )
                .ok(),
        };
        results.push(match plaintext {
            Some(plaintext) => DecryptedPayloadV1::Plaintext { index, plaintext },
            // Reached only when the ciphertext is structurally unusable, for
            // example shorter than its scheme's minimum.
            None => DecryptedPayloadV1::Malformed { index },
        });
    }
    Ok((
        OperationResultV1::DecryptUtxos { payloads: results },
        digest,
    ))
}

fn transaction_viewing_key(bytes: &[u8]) -> Result<P256Pubkey, OperationFailure> {
    let encoded: [u8; 33] = bytes.try_into().map_err(|_| OperationFailure::Invalid)?;
    P256Pubkey::from_bytes(encoded).map_err(|_| OperationFailure::Invalid)
}

fn decode_salt(bytes: &[u8]) -> Result<Salt, OperationFailure> {
    bytes.try_into().map_err(|_| OperationFailure::Invalid)
}

fn seal_state(
    keys: &RuntimeKeys,
    inner: KeyStatePlaintextV1,
) -> Result<(SealedWalletStateV1, Vec<u8>, [u8; 32]), OperationFailure> {
    let plaintext =
        Zeroizing::new(borsh::to_vec(&inner).map_err(|_| OperationFailure::Unavailable)?);
    let ciphertext = keys
        .quorum
        .public_key()
        .encrypt(&plaintext)
        .map_err(|_| OperationFailure::Unavailable)?;
    let sealed = SealedWalletStateV1 {
        version: API_VERSION,
        quorum_key_id: inner.quorum_key_id.clone(),
        quorum_key_epoch: inner.quorum_key_epoch,
        wallet_id_hash: wallet_id_hash(&inner.wallet_id),
        state_version: inner.state_version,
        previous_state_digest: inner.previous_state_digest,
        ciphertext,
    };
    let digest = state_digest(&sealed).map_err(|_| OperationFailure::Unavailable)?;
    let bytes = borsh::to_vec(&sealed).map_err(|_| OperationFailure::Unavailable)?;
    Ok((sealed, bytes, digest))
}

/// Unseals the key state and checks it twice: the envelope against the request,
/// then the decrypted contents against both the envelope and the descriptor. A
/// blob is therefore usable only by the descriptor and Quorum key epoch it was
/// issued under.
fn unseal_state(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    sealed_bytes: &[u8],
) -> Result<(KeyStatePlaintextV1, [u8; 32]), OperationFailure> {
    let sealed =
        SealedWalletStateV1::try_from_slice(sealed_bytes).map_err(|_| OperationFailure::Invalid)?;
    let digest = state_digest(&sealed).map_err(|_| OperationFailure::Invalid)?;
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id)
        || request.expected_state_version != Some(sealed.state_version)
        || request.expected_state_digest != Some(digest)
    {
        return Err(OperationFailure::Invalid);
    }
    let plaintext = Zeroizing::new(
        keys.quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| OperationFailure::Invalid)?,
    );
    let inner =
        KeyStatePlaintextV1::try_from_slice(&plaintext).map_err(|_| OperationFailure::Invalid)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id
        || inner.descriptor_digest != descriptor_hash
        || inner.policy_version != request.wallet_descriptor.policy_version
        || inner.state_version != sealed.state_version
        || inner.previous_state_digest != sealed.previous_state_digest
        || inner.ed25519_public_key != request.wallet_descriptor.expected_ed25519_public_key
        || inner.derivation_suite != DERIVATION_SUITE
    {
        return Err(OperationFailure::Invalid);
    }
    Ok((inner, digest))
}

fn current_time_ms() -> Result<u64, OperationFailure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperationFailure::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| OperationFailure::Unavailable)
}

fn seal_spend_authorization(
    keys: &RuntimeKeys,
    inner: SpendAuthorizationPlaintextV1,
) -> Result<Vec<u8>, OperationFailure> {
    let plaintext =
        Zeroizing::new(borsh::to_vec(&inner).map_err(|_| OperationFailure::Unavailable)?);
    let ciphertext = keys
        .quorum
        .public_key()
        .encrypt(&plaintext)
        .map_err(|_| OperationFailure::Unavailable)?;
    let sealed = SealedSpendAuthorizationV1 {
        version: API_VERSION,
        quorum_key_id: inner.quorum_key_id,
        quorum_key_epoch: inner.quorum_key_epoch,
        wallet_id_hash: wallet_id_hash(&inner.wallet_id),
        prepare_request_id: inner.prepare_request_id,
        expires_at_ms: inner.expires_at_ms,
        ciphertext,
    };
    borsh::to_vec(&sealed).map_err(|_| OperationFailure::Unavailable)
}

fn unseal_spend_authorization(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    sealed_bytes: &[u8],
    state_digest_bytes: [u8; 32],
) -> Result<SpendAuthorizationPlaintextV1, OperationFailure> {
    let sealed = SealedSpendAuthorizationV1::try_from_slice(sealed_bytes)
        .map_err(|_| OperationFailure::Invalid)?;
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id)
        || sealed.expires_at_ms < current_time_ms()?
    {
        return Err(OperationFailure::Invalid);
    }
    let plaintext = Zeroizing::new(
        keys.quorum
            .decrypt(&sealed.ciphertext)
            .map_err(|_| OperationFailure::Invalid)?,
    );
    let inner = SpendAuthorizationPlaintextV1::try_from_slice(&plaintext)
        .map_err(|_| OperationFailure::Invalid)?;
    let descriptor_hash = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id
        || inner.descriptor_digest != descriptor_hash
        || inner.policy_version != request.wallet_descriptor.policy_version
        || Some(inner.state_version) != request.expected_state_version
        || inner.state_digest != state_digest_bytes
        || Some(inner.state_digest) != request.expected_state_digest
        || inner.target_release_id != request.target_release_id
        || inner.target_manifest_digest != request.target_manifest_digest
        || inner.target_executable_digest != request.target_executable_digest
        || inner.prepare_request_id != sealed.prepare_request_id
        || inner.expires_at_ms != sealed.expires_at_ms
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(inner)
}

/// Disposable devnet spend path.
///
/// Unlike the two key-oracle calls, this operation deliberately performs its
/// own pinned Photon, Solana RPC, and prover calls. The external prover request
/// contains the plaintext witness, including the long-lived nullifier secret.
/// This closes the PoC without returning that secret to the browser, but it is
/// not an acceptable production boundary.
/// The one spend authority exposed by the enclave. Prepare proves and seals an
/// exact unsigned transaction; finalize independently revalidates the capsule
/// and transaction before invoking Turnkey once. There is no one-call protocol
/// variant.
async fn authorize_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    spend: &AuthorizeSpendRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    match spend {
        AuthorizeSpendRequestV1::Prepare { plan } => match plan {
            SpendPlanV1::Builtin { intent } => {
                let prepared = prepare_builtin_spend(request, target, intent, keys).await?;
                prepared_builtin_spend_result(request, keys, prepared)
            }
            SpendPlanV1::Spp { plan } => {
                let prepared = prepare_generic_spp(request, target, plan, keys).await?;
                prepared_generic_spend_result(request, keys, prepared)
            }
        },
        AuthorizeSpendRequestV1::Finalize {
            sealed_authorization_capsule,
            finalization,
        } => match finalization {
            SpendFinalizationV1::ExactTransaction {
                unsigned_transaction,
            } => {
                finalize_prepared_transaction(
                    request,
                    target,
                    keys,
                    sealed_authorization_capsule,
                    unsigned_transaction,
                )
                .await
            }
            SpendFinalizationV1::SppProgram {
                instruction,
                address_lookup_tables,
            } => {
                finalize_generic_spp(
                    request,
                    target,
                    keys,
                    sealed_authorization_capsule,
                    instruction,
                    address_lookup_tables,
                )
                .await
            }
        },
    }
}

struct PreparedBuiltinSpend {
    unsigned: VersionedTransaction,
    sealed_wallet_state: Vec<u8>,
    state_digest: [u8; 32],
    shielded_balance_before: u64,
}

struct PreparedGenericSpend {
    program_id: Address,
    input_tree: Address,
    program_authorities: Vec<Address>,
    plan_digest: [u8; 32],
    transact: Vec<u8>,
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    sealed_wallet_state: Vec<u8>,
    state_digest: [u8; 32],
    shielded_balance_before: u64,
    expires_at_ms: u64,
}

struct AuthorizedSpend {
    signed_transaction: Vec<u8>,
    transaction_signature: String,
    sealed_wallet_state: Vec<u8>,
    state_version: u64,
    state_digest: [u8; 32],
    shielded_balance_before: u64,
    turnkey_activity_id: String,
    turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
    evidence_classification: TurnkeyEvidenceClassification,
}

/// Builds and proves the existing default/custom-ring spend, but deliberately
/// stops before the only billable Turnkey transaction-signing activity.
async fn prepare_builtin_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: &SpendIntentV1,
    keys: &RuntimeKeys,
) -> Result<PreparedBuiltinSpend, OperationFailure> {
    let (recipient, amount) = match &intent.settlement {
        SpendSettlementV1::Transfer {
            recipient, amount, ..
        }
        | SpendSettlementV1::SolWithdrawal { recipient, amount } => (recipient, *amount),
    };
    if amount == 0 || intent.prover_profile_id != DEVNET_EXTERNAL_PROVER_PROFILE_ID {
        return Err(OperationFailure::Invalid);
    }
    if intent.ring.is_none() && !intent.input_commitments.is_empty() {
        return Err(OperationFailure::Invalid);
    }
    let recipient = Pubkey::from_str(recipient).map_err(|_| OperationFailure::Invalid)?;
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let client = turnkey_client(keys)?;
    let keypair = default_keypair(&client, target, &inner)?;

    let tree = Address::from_str(DEVNET_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let (asset, asset_registry) = match &intent.settlement {
        SpendSettlementV1::Transfer { asset, .. } => resolve_asset(&rpc, asset).await?,
        SpendSettlementV1::SolWithdrawal { .. } => (SOL_MINT, AssetRegistry::default()),
    };
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        EXPECTED_EXTERNAL_ORIGIN,
        EXPECTED_EXTERNAL_ORIGIN,
        tree,
    );
    let payer = Address::new_from_array(target.address.to_bytes());
    let authority = KeypairWalletAuthority::with_viewing_keys(
        payer,
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let mut wallet = synced_wallet(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        &authority,
        asset_registry,
        &zolana,
    )
    .await?;
    let selected_ring = match intent.ring.as_ref() {
        Some(ring) if ring.direction == RingDirectionV1::Exit => {
            Some(Address::from_str(&ring.program_id).map_err(|_| OperationFailure::Invalid)?)
        }
        Some(_) | None => None,
    };
    let shielded_balance_before = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent && entry.utxo.asset == asset && entry.utxo.ring_program_id == selected_ring
        })
        .fold(0u64, |total, entry| total.saturating_add(entry.utxo.amount));

    let unsigned = if intent.ring.is_some() {
        let prover = AsyncProverClient::new(EXPECTED_CUSTOM_RING_PROVER_ORIGIN.to_owned());
        build_ring_transaction(
            intent,
            amount,
            RingSpendContext {
                keypair: &keypair,
                wallet: &wallet,
                zolana: &zolana,
                rpc: zolana.rpc(),
                prover: &prover,
                assets: &wallet.registry,
                tree,
                asset,
                payer,
                recipient,
            },
        )
        .await?
    } else {
        prioritize_default_spend_inputs(&mut wallet, asset);
        build_default_transaction(
            intent,
            amount,
            DefaultSpendContext {
                wallet: &wallet,
                authority: &authority,
                zolana: &zolana,
                payer,
                recipient,
                asset,
            },
        )
        .await?
    };
    Ok(PreparedBuiltinSpend {
        unsigned,
        sealed_wallet_state: sealed_bytes.to_vec(),
        state_digest: digest,
        shielded_balance_before,
    })
}

/// Builds the common SPP transition for an arbitrary private program without
/// interpreting that program's data. Wallet inputs are independently
/// rediscovered; program inputs must be owned by a PDA derived under the target
/// program and provide a commitment opening. No public interface transfer is
/// admitted on this path.
async fn prepare_generic_spp(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    plan: &SppPlanV1,
    keys: &RuntimeKeys,
) -> Result<PreparedGenericSpend, OperationFailure> {
    if plan.prover_profile_id != DEVNET_EXTERNAL_PROVER_PROFILE_ID
        || !matches!(plan.public_effects, SppPublicEffectsV1::PrivateOnly)
        || plan.inputs.is_empty()
        || plan.outputs.is_empty()
        || plan.outputs.len() != usize::from(plan.shape.outputs)
        || plan.inputs.len() > usize::from(plan.shape.inputs)
        || plan.messages.len() > MAX_GENERIC_MESSAGES
        || plan.program_authorities.len() > MAX_GENERIC_PROGRAM_AUTHORITIES
    {
        return Err(OperationFailure::Invalid);
    }
    let now_ms = current_time_ms()?;
    let latest_expiry = now_ms
        .checked_add(MAX_REQUEST_AGE_MS)
        .ok_or(OperationFailure::Unavailable)?;
    if plan.expires_at_ms < now_ms || plan.expires_at_ms > latest_expiry {
        return Err(OperationFailure::Invalid);
    }

    let program_id = Address::from_str(&plan.program_id).map_err(|_| OperationFailure::Invalid)?;
    if program_id.to_bytes() == SHIELDED_POOL_PROGRAM_ID || reserved_signer_program(program_id) {
        return Err(OperationFailure::Invalid);
    }
    let input_tree = Address::from_str(&plan.input_tree).map_err(|_| OperationFailure::Invalid)?;
    let shape = Shape::new(
        usize::from(plan.shape.inputs),
        usize::from(plan.shape.outputs),
    );
    if !SPP_SUPPORTED_SHAPES.contains(&shape) {
        return Err(OperationFailure::Invalid);
    }
    if plan
        .messages
        .iter()
        .any(|message| message.data.len() > MAX_GENERIC_DATA_BYTES)
        || plan.outputs.iter().any(|output| {
            output.data.len() > MAX_GENERIC_DATA_BYTES
                || output.memo.len() > MAX_GENERIC_DATA_BYTES
                || (!output.data.is_empty() && output.data_hash.is_none())
        })
    {
        return Err(OperationFailure::Invalid);
    }

    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, state_digest_bytes) = unseal_state(request, keys, sealed_bytes)?;
    let client = turnkey_client(keys)?;
    let keypair = default_keypair(&client, target, &inner)?;
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let registry = generic_asset_registry(&rpc, plan).await?;
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        EXPECTED_EXTERNAL_ORIGIN,
        EXPECTED_EXTERNAL_ORIGIN,
        input_tree,
    );
    let payer = Address::new_from_array(target.address.to_bytes());
    let authority = KeypairWalletAuthority::with_viewing_keys(
        payer,
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let wallet = synced_wallet(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        &authority,
        registry.clone(),
        &zolana,
    )
    .await?;

    let mut input_utxos = Vec::with_capacity(usize::from(plan.shape.inputs));
    let mut seen_commitments = Vec::with_capacity(plan.inputs.len());
    let mut input_totals: Vec<(Address, u128)> = Vec::new();
    let program = Pubkey::new_from_array(program_id.to_bytes());
    let mut program_authorities = Vec::with_capacity(plan.program_authorities.len());
    for authority in &plan.program_authorities {
        let pda = derive_program_authority(&program, &authority.seeds)?;
        if program_authorities.contains(&pda) {
            return Err(OperationFailure::Invalid);
        }
        program_authorities.push(pda);
    }
    let mut shielded_balance_before = 0u64;
    for input in &plan.inputs {
        let (commitment, spend) = match input {
            SppPlanInputV1::Wallet { commitment } => {
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.output_context.tree == input_tree
                            && entry.output_context.hash == *commitment
                    })
                    .ok_or(OperationFailure::Invalid)?;
                if entry.utxo.owner != keypair.signing_pubkey()
                    || entry.utxo.ring_program_id.is_some()
                {
                    return Err(OperationFailure::Invalid);
                }
                shielded_balance_before = shielded_balance_before
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                add_asset_amount(&mut input_totals, entry.utxo.asset, entry.utxo.amount)?;
                let mut spend = SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key());
                if let Some(data_hash) = entry.data_hash {
                    spend = spend.with_data_hash(data_hash);
                }
                if let Some(ring_data_hash) = entry.ring_data_hash {
                    spend = spend.with_ring_data_hash(ring_data_hash);
                }
                (*commitment, spend)
            }
            SppPlanInputV1::Program {
                commitment,
                authority_seeds,
                asset,
                amount,
                blinding,
                data_hash,
                nullifier_secret,
            } => {
                let pda_address = derive_program_authority(&program, authority_seeds)?;
                if !program_authorities.contains(&pda_address) {
                    if program_authorities.len() == MAX_GENERIC_PROGRAM_AUTHORITIES {
                        return Err(OperationFailure::Invalid);
                    }
                    program_authorities.push(pda_address);
                }
                let asset = generic_asset_address(asset)?;
                add_asset_amount(&mut input_totals, asset, *amount)?;
                let secret: [u8; BLINDING_LEN] = nullifier_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| OperationFailure::Invalid)?;
                let utxo = Utxo {
                    owner: PublicKey::from_pda(&pda_address),
                    asset,
                    amount: *amount,
                    blinding: *blinding,
                    ring_program_id: None,
                    data: Default::default(),
                };
                let mut spend = SppProofInputUtxo::new(utxo, NullifierKey::from_secret(secret));
                if let Some(data_hash) = data_hash {
                    spend = spend.with_data_hash(*data_hash);
                }
                if spend.hash().map_err(|_| OperationFailure::Invalid)? != *commitment {
                    return Err(OperationFailure::Invalid);
                }
                (*commitment, spend)
            }
        };
        if seen_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        seen_commitments.push(commitment);
        input_utxos.push(spend);
    }
    while input_utxos.len() < usize::from(plan.shape.inputs) {
        input_utxos.push(SppProofInputUtxo::new_dummy());
    }

    let mut outputs = Vec::with_capacity(plan.outputs.len());
    let mut output_totals: Vec<(Address, u128)> = Vec::new();
    let mut output_commitments = Vec::with_capacity(plan.outputs.len());
    for output in &plan.outputs {
        let recipient =
            ShieldedAddress::from_str(&output.recipient).map_err(|_| OperationFailure::Invalid)?;
        let asset = generic_asset_address(&output.asset)?;
        add_asset_amount(&mut output_totals, asset, output.amount)?;
        let mut prepared = SppProofOutputUtxo {
            asset,
            amount: output.amount,
            blinding: output.blinding,
            owner_address: Some(recipient),
            owner_tag: Some(
                recipient
                    .signing_pubkey
                    .confidential_view_tag()
                    .map_err(|_| OperationFailure::Invalid)?,
            ),
            ..Default::default()
        };
        if let Some(data_hash) = output.data_hash {
            prepared = prepared.with_utxo_data(output.data.clone(), data_hash);
        }
        if !output.memo.is_empty() {
            prepared = prepared.with_memo(output.memo.clone());
        }
        let commitment = prepared.hash().map_err(|_| OperationFailure::Invalid)?;
        if output_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        output_commitments.push(commitment);
        outputs.push(prepared);
    }
    if input_totals != output_totals {
        sort_asset_totals(&mut input_totals);
        sort_asset_totals(&mut output_totals);
        if input_totals != output_totals {
            return Err(OperationFailure::Invalid);
        }
    }

    let transaction_viewing_key = get_transaction_viewing_key(&keypair, &input_utxos)
        .map_err(|_| OperationFailure::Invalid)?;
    let encoded = encrypt_transaction_data(&outputs, &registry, &transaction_viewing_key)
        .map_err(|_| OperationFailure::Invalid)?;
    let messages = plan
        .messages
        .iter()
        .map(|message| MessageData {
            view_tag: message.view_tag,
            data: message.data.clone(),
        })
        .collect();
    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        messages,
    );
    external_data.expiry_unix_ts = plan.expires_at_ms.div_ceil(1_000);
    let proof_inputs = SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer);
    proof_inputs
        .check_shape()
        .map_err(|_| OperationFailure::Invalid)?;
    let external_data_hash = proof_inputs
        .external_data
        .hash()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_contexts = proof_inputs
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_proofs = zolana
        .get_input_merkle_proofs_for_tree(input_tree, &input_contexts, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let dummy_nullifiers = proof_inputs
        .dummy_nullifiers()
        .map_err(|_| OperationFailure::Invalid)?;
    let dummy_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(input_tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    let assembled = assemble(proof_inputs, &input_proofs, &dummy_proofs)
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(EXPECTED_EXTERNAL_ORIGIN.to_owned());
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => {
            let proof = prover
                .prove_transfer(inputs)
                .await
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            proof
        }
    };
    let transact = assembled.with_proof(
        ProofCompressed::try_from(proof)
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .to_transact_proof(),
    );
    let private_tx_hash = transact.private_tx_hash;
    let transact = wincode::serialize(&transact).map_err(|_| OperationFailure::Unavailable)?;
    let plan_json = jcs_serialize(plan).map_err(|_| OperationFailure::Invalid)?;
    Ok(PreparedGenericSpend {
        program_id,
        input_tree,
        program_authorities,
        plan_digest: artifact_digest(plan_json.as_bytes()),
        transact,
        private_tx_hash,
        external_data_hash,
        sealed_wallet_state: sealed_bytes.to_vec(),
        state_digest: state_digest_bytes,
        shielded_balance_before,
        expires_at_ms: plan.expires_at_ms,
    })
}

fn derive_program_authority(
    program: &Pubkey,
    authority_seeds: &[Vec<u8>],
) -> Result<Address, OperationFailure> {
    if authority_seeds.is_empty()
        || authority_seeds.len() > 16
        || authority_seeds.iter().any(|seed| seed.len() > 32)
    {
        return Err(OperationFailure::Invalid);
    }
    let seed_refs = authority_seeds
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let pda = Pubkey::create_program_address(&seed_refs, program)
        .map_err(|_| OperationFailure::Invalid)?;
    Ok(Address::new_from_array(pda.to_bytes()))
}

fn add_asset_amount(
    totals: &mut Vec<(Address, u128)>,
    asset: Address,
    amount: u64,
) -> Result<(), OperationFailure> {
    if let Some((_, total)) = totals.iter_mut().find(|(existing, _)| *existing == asset) {
        *total = total
            .checked_add(u128::from(amount))
            .ok_or(OperationFailure::Unavailable)?;
    } else {
        totals.push((asset, u128::from(amount)));
    }
    Ok(())
}

fn sort_asset_totals(totals: &mut [(Address, u128)]) {
    totals.sort_by_key(|(asset, _)| asset.to_bytes());
}

fn generic_asset_address(asset: &AssetV1) -> Result<Address, OperationFailure> {
    match asset {
        AssetV1::Sol => Ok(SOL_MINT),
        AssetV1::Spl { mint, .. } => Address::from_str(mint).map_err(|_| OperationFailure::Invalid),
    }
}

async fn generic_asset_registry(
    rpc: &SolanaRpc,
    plan: &SppPlanV1,
) -> Result<AssetRegistry, OperationFailure> {
    let mut registry = AssetRegistry::default();
    for asset in plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            SppPlanInputV1::Program { asset, .. } => Some(asset),
            SppPlanInputV1::Wallet { .. } => None,
        })
        .chain(plan.outputs.iter().map(|output| &output.asset))
    {
        let (mint, _) = resolve_asset(rpc, asset).await?;
        if let AssetV1::Spl { asset_id, .. } = asset {
            match registry.asset_id(&mint) {
                Ok(existing) if existing == *asset_id => {}
                Ok(_) => return Err(OperationFailure::Invalid),
                Err(_) => registry
                    .insert(*asset_id, mint)
                    .map_err(|_| OperationFailure::Invalid)?,
            }
        }
    }
    Ok(registry)
}

fn prepared_builtin_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedBuiltinSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let unsigned_transaction =
        bincode1::serialize(&prepared.unsigned).map_err(|_| OperationFailure::Unavailable)?;
    if unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_digest = artifact_digest(&unsigned_transaction);
    let state_version = request
        .expected_state_version
        .ok_or(OperationFailure::Invalid)?;
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    // Five minutes leaves room for a normal program proof while sharply
    // limiting how long an abandoned authorization remains signable.
    let expires_at_ms = current_time_ms()?
        .checked_add(MAX_REQUEST_AGE_MS)
        .ok_or(OperationFailure::Unavailable)?;
    let sealed_authorization_capsule = seal_spend_authorization(
        keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id.clone(),
            descriptor_digest,
            policy_version: request.wallet_descriptor.policy_version,
            state_version,
            state_digest: prepared.state_digest,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: request.request_id,
            expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest },
            shielded_balance_before: prepared.shielded_balance_before,
        },
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Prepare {
                prepared: PreparedSpendV1::ExactTransaction {
                    unsigned_transaction,
                    transaction_digest,
                },
                sealed_authorization_capsule,
                sealed_wallet_state: prepared.sealed_wallet_state,
                state_version,
                state_digest: prepared.state_digest,
                shielded_balance_before: prepared.shielded_balance_before,
            },
        },
        prepared.state_digest,
    ))
}

fn prepared_generic_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedGenericSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let transact_digest = artifact_digest(&prepared.transact);
    let state_version = request
        .expected_state_version
        .ok_or(OperationFailure::Invalid)?;
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    let sealed_authorization_capsule = seal_spend_authorization(
        keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id.clone(),
            descriptor_digest,
            policy_version: request.wallet_descriptor.policy_version,
            state_version,
            state_digest: prepared.state_digest,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: request.request_id,
            expires_at_ms: prepared.expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::Spp {
                program_id: prepared.program_id.to_bytes(),
                input_tree: prepared.input_tree.to_bytes(),
                program_authorities: prepared
                    .program_authorities
                    .iter()
                    .map(Address::to_bytes)
                    .collect(),
                plan_digest: prepared.plan_digest,
                prepared_transact: prepared.transact.clone(),
                transact_digest,
                private_tx_hash: prepared.private_tx_hash,
            },
            shielded_balance_before: prepared.shielded_balance_before,
        },
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Prepare {
                prepared: PreparedSpendV1::Spp {
                    program_id: prepared.program_id.to_string(),
                    input_tree: prepared.input_tree.to_string(),
                    plan_digest: prepared.plan_digest,
                    transact: prepared.transact,
                    transact_digest,
                    private_tx_hash: prepared.private_tx_hash,
                    external_data_hash: prepared.external_data_hash,
                },
                sealed_authorization_capsule,
                sealed_wallet_state: prepared.sealed_wallet_state,
                state_version,
                state_digest: prepared.state_digest,
                shielded_balance_before: prepared.shielded_balance_before,
            },
        },
        prepared.state_digest,
    ))
}

async fn finalize_prepared_transaction(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    sealed_authorization_capsule: &[u8],
    unsigned_transaction: &[u8],
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let sealed_wallet_state = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    // Unseal the wallet state independently. A valid capsule alone is never a
    // bearer credential for Turnkey signing.
    let (_, state_digest_bytes) = unseal_state(request, keys, sealed_wallet_state)?;
    let authorization = unseal_spend_authorization(
        request,
        keys,
        sealed_authorization_capsule,
        state_digest_bytes,
    )?;
    let SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest } =
        authorization.artifact
    else {
        return Err(OperationFailure::Invalid);
    };
    if artifact_digest(unsigned_transaction) != transaction_digest
        || unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES
    {
        return Err(OperationFailure::Invalid);
    }
    let unsigned: VersionedTransaction =
        bincode1::deserialize(unsigned_transaction).map_err(|_| OperationFailure::Invalid)?;
    // Reject alternate encodings and any transaction already carrying a
    // signature. The capsule commits to the canonical bytes TVC prepared.
    if bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Invalid)?
        != unsigned_transaction
        || unsigned.signatures.as_slice() != [Signature::default()]
    {
        return Err(OperationFailure::Invalid);
    }
    let client = turnkey_client(keys)?;
    let signed =
        sign_versioned_transaction(&client, target, request.issued_at_ms, unsigned).await?;
    let authorized = authorized_spend(
        signed,
        request,
        sealed_wallet_state,
        state_digest_bytes,
        authorization.shielded_balance_before,
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Finalize {
                signed_transaction: authorized.signed_transaction,
                transaction_signature: authorized.transaction_signature,
                sealed_wallet_state: authorized.sealed_wallet_state,
                state_version: authorized.state_version,
                state_digest: authorized.state_digest,
                shielded_balance_before: authorized.shielded_balance_before,
                turnkey_activity_id: authorized.turnkey_activity_id,
                turnkey_app_proofs: authorized.turnkey_app_proofs,
                evidence_classification: authorized.evidence_classification,
            },
        },
        state_digest_bytes,
    ))
}

async fn finalize_generic_spp(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    sealed_authorization_capsule: &[u8],
    instruction: &SolanaInstructionV1,
    address_lookup_tables: &[String],
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let sealed_wallet_state = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (_, state_digest_bytes) = unseal_state(request, keys, sealed_wallet_state)?;
    let authorization = unseal_spend_authorization(
        request,
        keys,
        sealed_authorization_capsule,
        state_digest_bytes,
    )?;
    let SpendAuthorizationArtifactV1::Spp {
        program_id,
        input_tree,
        program_authorities,
        plan_digest: _,
        prepared_transact,
        transact_digest,
        private_tx_hash,
    } = authorization.artifact
    else {
        return Err(OperationFailure::Invalid);
    };
    if prepared_transact.is_empty()
        || artifact_digest(&prepared_transact) != transact_digest
        || !prepared_transact
            .windows(private_tx_hash.len())
            .any(|window| window == private_tx_hash)
    {
        return Err(OperationFailure::Invalid);
    }
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let payer = Address::new_from_array(target.address.to_bytes());
    let instruction = validate_private_program_instruction(
        &rpc,
        payer,
        Address::new_from_array(program_id),
        Address::new_from_array(input_tree),
        &program_authorities,
        instruction,
        private_tx_hash,
    )
    .await?;
    if address_lookup_tables.len() > MAX_GENERIC_LOOKUP_TABLES {
        return Err(OperationFailure::Invalid);
    }
    let mut seen_tables = Vec::with_capacity(address_lookup_tables.len());
    let mut tables = Vec::with_capacity(address_lookup_tables.len());
    for table in address_lookup_tables {
        let address = Address::from_str(table).map_err(|_| OperationFailure::Invalid)?;
        if seen_tables.contains(&address) {
            return Err(OperationFailure::Invalid);
        }
        seen_tables.push(address);
        tables.push(read_generic_lookup_table(&rpc, address).await?);
    }
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let (blockhash, _) = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = v0::Message::try_compile(&payer, &[compute, instruction], &tables, blockhash)
        .map_err(|_| OperationFailure::Invalid)?;
    let unsigned = VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(message),
    };
    let unsigned_bytes =
        bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Unavailable)?;
    if unsigned_bytes.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Invalid);
    }
    let client = turnkey_client(keys)?;
    let signed =
        sign_versioned_transaction(&client, target, request.issued_at_ms, unsigned).await?;
    let authorized = authorized_spend(
        signed,
        request,
        sealed_wallet_state,
        state_digest_bytes,
        authorization.shielded_balance_before,
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Finalize {
                signed_transaction: authorized.signed_transaction,
                transaction_signature: authorized.transaction_signature,
                sealed_wallet_state: authorized.sealed_wallet_state,
                state_version: authorized.state_version,
                state_digest: authorized.state_digest,
                shielded_balance_before: authorized.shielded_balance_before,
                turnkey_activity_id: authorized.turnkey_activity_id,
                turnkey_app_proofs: authorized.turnkey_app_proofs,
                evidence_classification: authorized.evidence_classification,
            },
        },
        state_digest_bytes,
    ))
}

async fn validate_private_program_instruction(
    rpc: &SolanaRpc,
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    instruction: &SolanaInstructionV1,
    private_tx_hash: [u8; 32],
) -> Result<Instruction, OperationFailure> {
    let (program_id, parsed_accounts) = validate_private_program_shape(
        payer,
        authorized_program,
        authorized_tree,
        authorized_program_accounts,
        instruction,
        private_tx_hash,
    )?;
    let program_account = rpc
        .get_account(program_id)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    if !program_account.executable {
        return Err(OperationFailure::Invalid);
    }

    let system_program = Address::default();
    let mut shielded_pool_executable = false;
    let mut authorized_tree_present = false;
    let mut accounts = Vec::with_capacity(instruction.accounts.len());
    for meta in parsed_accounts {
        let account = rpc
            .get_account(meta.address)
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?;
        if meta.address == authorized_tree {
            let tree = account.as_ref().ok_or(OperationFailure::Invalid)?;
            if !meta.is_writable
                || meta.is_signer
                || tree.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID
            {
                return Err(OperationFailure::Invalid);
            }
            authorized_tree_present = true;
        }
        if let Some(account) = account {
            if meta.address != authorized_tree
                && meta.is_writable
                && account.owner.to_bytes() == SHIELDED_POOL_PROGRAM_ID
            {
                return Err(OperationFailure::Invalid);
            }
            if account.executable {
                if meta.address.to_bytes() == SHIELDED_POOL_PROGRAM_ID {
                    if meta.is_signer || meta.is_writable {
                        return Err(OperationFailure::Invalid);
                    }
                    shielded_pool_executable = true;
                } else if meta.address != system_program || meta.is_signer || meta.is_writable {
                    return Err(OperationFailure::Invalid);
                }
            }
        } else if !authorized_program_accounts.contains(&meta.address.to_bytes()) {
            return Err(OperationFailure::Invalid);
        }
        accounts.push(if meta.is_writable {
            AccountMeta::new(meta.address, meta.is_signer)
        } else {
            AccountMeta::new_readonly(meta.address, meta.is_signer)
        });
    }
    if !shielded_pool_executable || !authorized_tree_present {
        return Err(OperationFailure::Invalid);
    }
    Ok(Instruction {
        program_id,
        accounts,
        data: instruction.data.clone(),
    })
}

struct PrivateProgramAccount {
    address: Address,
    is_signer: bool,
    is_writable: bool,
}

fn validate_private_program_shape(
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    instruction: &SolanaInstructionV1,
    private_tx_hash: [u8; 32],
) -> Result<(Address, Vec<PrivateProgramAccount>), OperationFailure> {
    let program_id =
        Address::from_str(&instruction.program_id).map_err(|_| OperationFailure::Invalid)?;
    if program_id != authorized_program
        || reserved_signer_program(program_id)
        || instruction.accounts.is_empty()
        || instruction.accounts.len() > MAX_GENERIC_ACCOUNTS
        || instruction.data.len() > MAX_GENERIC_INSTRUCTION_BYTES
        || instruction
            .data
            .windows(private_tx_hash.len())
            .filter(|window| *window == private_tx_hash)
            .count()
            != 1
    {
        return Err(OperationFailure::Invalid);
    }

    let shielded_pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let system_program = Address::default();
    let mut payer_signer = false;
    let mut shielded_pool_present = false;
    let mut system_program_present = false;
    let mut authorized_tree_present = false;
    let mut seen_program_accounts = vec![false; authorized_program_accounts.len()];
    let mut accounts = Vec::with_capacity(instruction.accounts.len());
    for meta in &instruction.accounts {
        let address = Address::from_str(&meta.address).map_err(|_| OperationFailure::Invalid)?;
        if reserved_signer_program(address) && address != system_program {
            return Err(OperationFailure::Invalid);
        }
        if meta.is_signer {
            if address != payer {
                return Err(OperationFailure::Invalid);
            }
            payer_signer = true;
        }
        if address == shielded_pool {
            if meta.is_signer || meta.is_writable {
                return Err(OperationFailure::Invalid);
            }
            shielded_pool_present = true;
        }
        if address == system_program {
            if meta.is_signer || meta.is_writable {
                return Err(OperationFailure::Invalid);
            }
            system_program_present = true;
        }
        if address == authorized_tree {
            if meta.is_signer || !meta.is_writable {
                return Err(OperationFailure::Invalid);
            }
            authorized_tree_present = true;
        }
        for (index, authorized) in authorized_program_accounts.iter().enumerate() {
            if address.to_bytes() == *authorized {
                seen_program_accounts[index] = true;
            }
        }
        accounts.push(PrivateProgramAccount {
            address,
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        });
    }
    if !payer_signer
        || !shielded_pool_present
        || !system_program_present
        || !authorized_tree_present
        || seen_program_accounts.iter().any(|seen| !seen)
    {
        return Err(OperationFailure::Invalid);
    }
    Ok((program_id, accounts))
}

fn reserved_signer_program(program_id: Address) -> bool {
    const RESERVED: [&str; 10] = [
        "11111111111111111111111111111111",
        "ComputeBudget111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "NativeLoader1111111111111111111111111111111",
        "BPFLoader1111111111111111111111111111111111",
        "BPFLoader2111111111111111111111111111111111",
        "BPFLoaderUpgradeab1e11111111111111111111111",
        "LoaderV411111111111111111111111111111111111",
    ];
    RESERVED
        .iter()
        .any(|reserved| Address::from_str(reserved).is_ok_and(|address| address == program_id))
}

/// Reads a caller-named table from the pinned chain without treating its
/// entries as authority. Message compilation matches entries only to literal
/// accounts in the enclave-built instruction; missing entries remain static
/// keys, and unrelated entries are ignored.
async fn read_generic_lookup_table(
    rpc: &SolanaRpc,
    address: Address,
) -> Result<AddressLookupTableAccount, OperationFailure> {
    let account = rpc
        .get_account(address)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LookupTable))?
        .ok_or(OperationFailure::Failed(FailureStage::LookupTable))?;
    if account.owner.to_bytes() != solana_address_lookup_table_interface::program::ID.to_bytes() {
        return Err(OperationFailure::Invalid);
    }
    let parsed =
        AddressLookupTable::deserialize(&account.data).map_err(|_| OperationFailure::Invalid)?;
    Ok(AddressLookupTableAccount {
        key: address,
        addresses: parsed.addresses.to_vec(),
    })
}

/// Builds and proves a default-ring transaction without exposing any spend
/// role to the caller. The returned legacy message has exactly one empty
/// signature slot, shared by the shielded owner and fee payer.
async fn build_default_transaction(
    intent: &SpendIntentV1,
    amount: u64,
    cx: DefaultSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
    let DefaultSpendContext {
        wallet,
        authority,
        zolana,
        payer,
        recipient,
        asset,
    } = cx;
    let unsigned = match &intent.settlement {
        SpendSettlementV1::Transfer { .. } => {
            let created = create_transfer(TransferParams {
                rpc: zolana.rpc(),
                wallet,
                payer,
                recipient,
                asset,
                amount,
            })
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;
            if created.recipient.is_public_withdrawal() {
                return Err(OperationFailure::Invalid);
            }
            created.transaction
        }
        SpendSettlementV1::SolWithdrawal { .. } => {
            create_withdrawal(WithdrawalParams {
                wallet,
                payer,
                legs: vec![WithdrawalLeg {
                    recipient,
                    asset: SOL_MINT,
                    amount,
                    spl_token_program: None,
                }],
            })
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .transaction
        }
    };
    let shielded = sign_shielded_transaction(unsigned, wallet, authority)
        .await
        // Despite the upstream name, this assembles the proved private
        // transition; the only Solana owner signature is requested from
        // Turnkey during AuthorizeSpend::Finalize.
        .map_err(|error| OperationFailure::Failed(private_transition_stage(&error)))?;
    let transaction = zolana
        .finish_submission_unsigned(&shielded, Pubkey::new_from_array(payer.to_bytes()))
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    Ok(VersionedTransaction {
        signatures: transaction.signatures,
        message: VersionedMessage::Legacy(transaction.message),
    })
}

/// Prefer larger default-ring notes before the SDK's stable input scan.
///
/// The installed SPP circuits accept at most five inputs. Index order can pick
/// six pieces of dust even when a later note covers the spend by itself.
fn prioritize_default_spend_inputs(wallet: &mut Wallet, asset: Address) {
    wallet.utxos.sort_by(|left, right| {
        let left_eligible =
            !left.spent && left.utxo.asset == asset && left.utxo.ring_program_id.is_none();
        let right_eligible =
            !right.spent && right.utxo.asset == asset && right.utxo.ring_program_id.is_none();
        right_eligible
            .cmp(&left_eligible)
            .then_with(|| right.utxo.amount.cmp(&left.utxo.amount))
    });
}

struct DefaultSpendContext<'a> {
    wallet: &'a Wallet,
    authority: &'a KeypairWalletAuthority<'a, TurnkeyEd25519ShieldedKeypair>,
    zolana: &'a ZolanaClient<SolanaRpc>,
    payer: Address,
    recipient: Pubkey,
    asset: Address,
}

struct RingSpendContext<'a> {
    keypair: &'a TurnkeyEd25519ShieldedKeypair,
    wallet: &'a Wallet,
    zolana: &'a ZolanaClient<SolanaRpc>,
    rpc: &'a SolanaRpc,
    prover: &'a AsyncProverClient,
    assets: &'a AssetRegistry,
    tree: Address,
    asset: Address,
    payer: Address,
    recipient: Pubkey,
}

/// Builds one custom-ring spend and returns the unsigned v0 transaction.
///
/// Separate from the default-ring path rather than a flag on it: a ring spend
/// runs the ring circuit over an auditor-encrypted transaction viewing key, and
/// the result does not fit a legacy packet, so it must go out as a v0 message
/// over an address lookup table.
async fn build_ring_transaction(
    intent: &SpendIntentV1,
    amount: u64,
    cx: RingSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
    let ring = intent.ring.as_ref().ok_or(OperationFailure::Invalid)?;
    let RingSpendContext {
        keypair,
        wallet,
        zolana,
        rpc,
        prover,
        assets,
        tree,
        asset,
        payer,
        recipient,
    } = cx;
    let program_id = Address::from_str(&ring.program_id).map_err(|_| OperationFailure::Invalid)?;
    let table_address =
        Address::from_str(&ring.lookup_table).map_err(|_| OperationFailure::Invalid)?;
    let custom_ring = CustomRing::new(program_id);

    let nullifier_key = keypair.nullifier_key();
    let (inputs, available) = match ring.direction {
        RingDirectionV1::Exit => {
            if !intent.input_commitments.is_empty() {
                return Err(OperationFailure::Invalid);
            }
            let mut candidates = wallet
                .utxos
                .iter()
                .filter(|entry| {
                    !entry.spent
                        && entry.utxo.asset == asset
                        && entry.utxo.ring_program_id == Some(program_id)
                        && entry.output_context.tree == tree
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
            let mut inputs = Vec::new();
            let mut available: u64 = 0;
            for entry in candidates {
                inputs.push(SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key));
                available = available
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                if available >= amount {
                    break;
                }
            }
            (inputs, available)
        }
        RingDirectionV1::Enter => {
            if intent.input_commitments.is_empty() || intent.input_commitments.len() > 5 {
                return Err(OperationFailure::Invalid);
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut inputs = Vec::with_capacity(intent.input_commitments.len());
            let mut available: u64 = 0;
            for commitment in &intent.input_commitments {
                if !seen.insert(*commitment) {
                    return Err(OperationFailure::Invalid);
                }
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.utxo.asset == asset
                            && entry.utxo.ring_program_id.is_none()
                            && entry.output_context.tree == tree
                            && entry.output_context.hash == *commitment
                    })
                    .ok_or(OperationFailure::Failed(
                        FailureStage::ShieldedBalanceNotReady,
                    ))?;
                available = available
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                inputs.push(SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key));
            }
            // The bridge output is deliberately exact. Accepting change here
            // would silently move unrelated default-pool value into the ring.
            if available != amount {
                return Err(OperationFailure::Invalid);
            }
            (inputs, available)
        }
    };
    if available < amount {
        return Err(OperationFailure::Failed(
            FailureStage::ShieldedBalanceNotReady,
        ));
    }

    let owner = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    // A padded change slot pushes the instruction past the packet limit even
    // behind a lookup table, and every published slot must be one the auditor
    // can open, so the ring path requires compact change.
    let mut transfer = ConfidentialTransfer::new(owner, inputs, payer)
        .with_compact_change()
        .with_ring_program_id(program_id);
    let interface_transfer_accounts = match &intent.settlement {
        SpendSettlementV1::Transfer { .. } => {
            let recipient_address = try_resolve_registered_address_async(
                zolana,
                Address::new_from_array(recipient.to_bytes()),
            )
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .ok_or(OperationFailure::Invalid)?;
            match ring.direction {
                RingDirectionV1::Enter => transfer
                    .send(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
                RingDirectionV1::Exit => transfer
                    .send_default_ring(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
            };
            Vec::new()
        }
        SpendSettlementV1::SolWithdrawal { .. } => {
            if ring.direction == RingDirectionV1::Enter {
                return Err(OperationFailure::Invalid);
            }
            transfer
                .withdraw(
                    SOL_MINT,
                    amount,
                    SettlementTarget::Sol {
                        user_sol_account: Address::new_from_array(recipient.to_bytes()),
                    },
                )
                .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;
            vec![TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts { recipient },
            )]
        }
    };
    let prepared = transfer
        .prepare()
        .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;

    let proven = CustomRingTransfer::new(CustomRingTransferInput {
        ring: custom_ring,
        sender: keypair,
        prepared,
    })
    .with_tree(tree)
    .with_assets(assets)
    .with_interface_transfer_accounts(interface_transfer_accounts)
    .prove_async(AsyncTransferProofEnvironment {
        indexer: zolana,
        rpc: zolana,
        prover,
    })
    .await
    // Proving walks the indexer, the tree proofs and the prover in turn, and
    // any of them can be the one that failed. Naming the prover for all of
    // them sends the reader to the wrong service.
    .map_err(|error| OperationFailure::Failed(ring_transfer_stage(&error)))?;

    let instruction = proven
        .instruction()
        .map_err(|_| OperationFailure::Unavailable)?;
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(
        custom_ring_sdk::TRANSACT_COMPUTE_UNIT_LIMIT,
    );
    // The browser creates one reusable table for the ring's stable accounts.
    // Settlement accounts such as a withdrawal recipient are deliberately
    // absent: `try_compile` keeps those keys in the static account list while
    // resolving every matching stable key through the table.
    let table = read_generic_lookup_table(rpc, table_address).await?;
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = v0::Message::try_compile(
        &payer,
        &[compute, instruction],
        core::slice::from_ref(&table),
        blockhash,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    Ok(VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(message),
    })
}

fn authorized_spend(
    signed: ActivityResult<(VersionedTransaction, Vec<TurnkeyVerifiedAppProofV1>)>,
    request: &OperationRequestV1,
    sealed_bytes: &[u8],
    digest: [u8; 32],
    shielded_balance_before: u64,
) -> Result<AuthorizedSpend, OperationFailure> {
    let (transaction, turnkey_app_proofs) = signed.result;
    let signed_bytes =
        bincode1::serialize(&transaction).map_err(|_| OperationFailure::Unavailable)?;
    // A v0 message over a lookup table is what keeps this inside the packet
    // limit; past it, nothing can submit the transaction.
    if signed_bytes.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = transaction
        .signatures
        .first()
        .ok_or(OperationFailure::Unavailable)?
        .to_string();
    let state_version = request
        .expected_state_version
        .ok_or(OperationFailure::Invalid)?;
    Ok(AuthorizedSpend {
        transaction_signature,
        signed_transaction: signed_bytes,
        sealed_wallet_state: sealed_bytes.to_vec(),
        state_version,
        state_digest: digest,
        shielded_balance_before,
        turnkey_activity_id: signed.activity_id,
        turnkey_app_proofs,
        evidence_classification: TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
    })
}

async fn resolve_asset(
    rpc: &SolanaRpc,
    requested: &AssetV1,
) -> Result<(Address, AssetRegistry), OperationFailure> {
    match requested {
        AssetV1::Sol => Ok((SOL_MINT, AssetRegistry::default())),
        AssetV1::Spl { mint, asset_id } => {
            if *asset_id <= 1 {
                return Err(OperationFailure::Invalid);
            }
            let mint = Pubkey::from_str(mint).map_err(|_| OperationFailure::Invalid)?;
            let registry_address = pda::spl_asset_registry(&mint);
            let account = rpc
                .get_account(Address::new_from_array(registry_address.to_bytes()))
                .await
                .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?
                .ok_or(OperationFailure::Invalid)?;
            if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
                return Err(OperationFailure::Invalid);
            }
            let registry = SplAssetRegistry::from_account_bytes(&account.data)
                .map_err(|_| OperationFailure::Invalid)?;
            let mint_address = Address::new_from_array(mint.to_bytes());
            if registry.mint != mint_address || registry.asset_id != *asset_id {
                return Err(OperationFailure::Invalid);
            }
            let assets = AssetRegistry::new([(*asset_id, mint_address)])
                .map_err(|_| OperationFailure::Invalid)?;
            Ok((mint_address, assets))
        }
    }
}

/// The stage a custom-ring transfer failed at.
///
/// The ring path proves in one call that reads the ring config, the tree, the
/// indexer's proofs and the prover, so the error type is the only thing that
/// says which of them gave up. Reporting the prover for all of them would send
/// every reader to the same wrong service.
fn ring_transfer_stage(error: &TransferError) -> FailureStage {
    match error {
        TransferError::Client(inner) => client_error_stage(inner),
        // `AccountRead` belongs here rather than with the tree: the only
        // account this path reads that way is the ring's config.
        TransferError::MissingRingConfig | TransferError::AccountRead(_) => {
            FailureStage::RingConfig
        }
        TransferError::MissingTree
        | TransferError::InvalidTreeOwner
        | TransferError::InvalidTreeDiscriminator
        | TransferError::TreeRequired
        | TransferError::Tree(_) => FailureStage::InputTree,
        TransferError::IncompleteProofSet => FailureStage::IndexerProofs,
        TransferError::ProofInput(_)
        | TransferError::PaddedChange
        | TransferError::InvalidDummyOutput
        | TransferError::MissingAssetRegistry
        | TransferError::ForeignRing(_) => FailureStage::ProofAssembly,
        TransferError::Proof(_) | TransferError::IncompleteInputSet => FailureStage::ExternalProver,
        TransferError::Keypair(_) => FailureStage::PrivateTransitionAssembly,
        _ => FailureStage::SettlementConstruction,
    }
}

/// The stage a client error belongs to, for any call that walks the indexer,
/// the proofs, the prover and submission in one step.
fn client_error_stage(error: &ClientError) -> FailureStage {
    match error {
        ClientError::Indexer(_)
        | ClientError::IndexerUnavailable(_)
        | ClientError::UnsupportedRpcMethod(_)
        | ClientError::IndexerNotCaughtUp { .. }
        | ClientError::IncompleteInputProofs { .. }
        | ClientError::StateProofLeafMismatch { .. }
        | ClientError::StateProofTreeMismatch { .. }
        | ClientError::NullifierProofLeafMismatch { .. }
        | ClientError::NullifierProofTreeMismatch { .. } => FailureStage::IndexerProofs,
        ClientError::MissingInputMerkleProof { .. }
        | ClientError::ProofPathLength { .. }
        | ClientError::WitnessInputCountMismatch { .. }
        | ClientError::InputTreeIndexCountMismatch { .. } => FailureStage::ProofAssembly,
        ClientError::ProverServer(_) | ClientError::ProofParse(_) | ClientError::Prover(_) => {
            FailureStage::ExternalProver
        }
        ClientError::ProofVerification(_) => FailureStage::LocalProofVerification,
        _ => FailureStage::TransactionAssembly,
    }
}

/// Preserve actionable, non-secret causes from local default-rail assembly.
/// None of these variants carries note hashes, amounts, keys, or prover input.
fn private_transition_stage(error: &ClientError) -> FailureStage {
    match error {
        ClientError::UnsupportedShape { .. }
        | ClientError::TooManyInputs { .. }
        | ClientError::TooManyOutputs { .. }
        | ClientError::Transaction(
            TransactionError::UnsupportedShape { .. }
            | TransactionError::TooManyInputs { .. }
            | TransactionError::TooManyOutputsForShape { .. },
        ) => FailureStage::UnsupportedProofShape,
        ClientError::Transaction(TransactionError::P256TransactUnsupported) => {
            FailureStage::UnsupportedShieldedOwner
        }
        ClientError::UnsignedInputUnavailable { .. } => FailureStage::ShieldedInputChanged,
        ClientError::Transaction(
            TransactionError::WalletAuthorityMismatch
            | TransactionError::MissingCurrentViewingKey
            | TransactionError::AuthorityViewingKeyMismatch,
        ) => FailureStage::ShieldedIdentityMismatch,
        _ => FailureStage::PrivateTransitionAssembly,
    }
}

/// Signs a v0 transaction through Turnkey.
///
/// A custom-ring transact does not fit a legacy packet, so it goes out as a
/// versioned message over an address lookup table. Turnkey takes both forms on
/// the same intent; only the encoding differs, and the checks below are the
/// legacy ones restated for a versioned message.
async fn sign_versioned_transaction(
    client: &TvcTurnkeyClient,
    wallet: &ValidatedWallet<'_>,
    timestamp_ms: u64,
    unsigned: VersionedTransaction,
) -> Result<ActivityResult<(VersionedTransaction, Vec<TurnkeyVerifiedAppProofV1>)>, OperationFailure>
{
    if unsigned.signatures.len() != 1 || unsigned.signatures[0] != Signature::default() {
        return Err(OperationFailure::Unavailable);
    }
    let unsigned_bytes =
        bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Unavailable)?;
    // Turnkey declining to sign and Turnkey signing something else are
    // different problems with different owners, so they are different stages.
    let activity = client
        .sign_transaction(
            wallet.organization_id.to_owned(),
            u128::from(timestamp_ms),
            SignTransactionIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                unsigned_transaction: hex::encode(unsigned_bytes),
                r#type: TransactionType::Solana,
            },
        )
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::TurnkeySigning))?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Failed(FailureStage::TurnkeySigning));
    }
    let signed: VersionedTransaction = bincode1::deserialize(
        &hex::decode(&activity.result.signed_transaction)
            .map_err(|_| OperationFailure::Failed(FailureStage::SignedTransactionMismatch))?,
    )
    .map_err(|_| OperationFailure::Failed(FailureStage::SignedTransactionMismatch))?;
    // The message must come back byte for byte: Turnkey is asked to sign this
    // transaction, not to produce one. Verifying the signature over a message
    // it chose would prove nothing about what was authorized.
    if signed.message != unsigned.message
        || signed.signatures.len() != 1
        || signed.signatures[0] == Signature::default()
        || !signed.signatures[0].verify(
            wallet.expected_ed25519_public_key.as_ref(),
            &signed.message.serialize(),
        )
    {
        return Err(OperationFailure::Failed(
            FailureStage::SignedTransactionMismatch,
        ));
    }
    let proofs = app_proofs(&activity);
    Ok(ActivityResult {
        result: (signed, proofs),
        activity_id: activity.activity_id,
        status: activity.status,
        app_proofs: activity.app_proofs,
    })
}

fn decode_signature_component(encoded: &str, output: &mut [u8]) -> Result<(), OperationFailure> {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded))
        .map_err(|_| OperationFailure::Unavailable)?;
    if bytes.len() != output.len() {
        return Err(OperationFailure::Unavailable);
    }
    output.copy_from_slice(&bytes);
    Ok(())
}

fn app_proofs<T>(activity: &ActivityResult<T>) -> Vec<TurnkeyVerifiedAppProofV1> {
    activity.app_proofs.iter().map(convert_app_proof).collect()
}

fn convert_app_proof(
    proof: &turnkey_client::generated::external::data::v1::AppProof,
) -> TurnkeyVerifiedAppProofV1 {
    TurnkeyVerifiedAppProofV1 {
        scheme: proof.scheme.as_str_name().to_owned(),
        public_key: proof.public_key.clone(),
        proof_payload: proof.proof_payload.clone(),
        signature: proof.signature.clone(),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use zolana_tvc_protocol::types::{CustomRingV1, SolanaAccountMetaV1};

    use qos_p256::P256Pair;
    use zolana_tvc_protocol::types::{
        ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1, WalletDescriptorV1,
    };

    const TEST_SEED: [u8; 64] = [0x5a; 64];

    fn runtime_keys() -> RuntimeKeys {
        RuntimeKeys {
            ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
            quorum: Arc::new(P256Pair::generate().expect("quorum")),
        }
    }

    fn descriptor() -> WalletDescriptorV1 {
        WalletDescriptorV1 {
            version: API_VERSION,
            wallet_id: "wallet-keyholder-test".to_owned(),
            security_domain_id: [0x11; 32],
            turnkey_parent_organization_id: "00000000-0000-0000-0000-00000000000a".to_owned(),
            turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
            turnkey_signing_target: TurnkeySigningTargetV1::HdWalletAccount {
                turnkey_wallet_id: "keyholder-test".to_owned(),
                wallet_account_id: "account".to_owned(),
                address: Pubkey::new_from_array([0x22; 32]).to_string(),
                derivation_path: TURNKEY_DERIVATION_PATH.to_owned(),
            },
            turnkey_service_user_id: "00000000-0000-0000-0000-00000000000c".to_owned(),
            turnkey_api_key_id: "00000000-0000-0000-0000-00000000000d".to_owned(),
            expected_ed25519_public_key: [0x22; 32],
            allowed_clients: vec![ClientGrantV1 {
                client_key_id: "tvc-browser-p256-test".to_owned(),
                scheme: ClientAuthorizationScheme::P256Sha256,
                client_public_key: vec![0x04; 65],
                allowed_operations: KEYHOLDER_OPERATIONS.to_vec(),
                may_rotate_descriptor: false,
            }],
            policy_version: 1,
            previous_descriptor_digest: None,
            environment: Environment::Development,
            provisioning_key_id: PROVISIONING_KEY_ID.to_owned(),
            owner_authorization_key: None,
            recovery_binding: None,
            provisioning_signature: vec![0u8; 64],
            owner_authorization: None,
            prior_client_authorization: None,
        }
    }

    fn request(operation: OperationV1, descriptor: WalletDescriptorV1) -> OperationRequestV1 {
        OperationRequestV1 {
            version: API_VERSION,
            request_id: [0x01; 32],
            issued_at_ms: 1_750_000_000_000,
            expires_at_ms: 1_750_000_060_000,
            target_release_id: "keyholder-test".to_owned(),
            target_manifest_digest: [0x33; 32],
            target_executable_digest: [0x44; 32],
            quorum_key_id: "keyholder-quorum".to_owned(),
            quorum_key_epoch: 1,
            wallet_descriptor: descriptor,
            sealed_wallet_state: None,
            expected_state_version: None,
            expected_state_digest: None,
            client_response_public_key: vec![0u8; 130],
            operation,
            authorization: ClientAuthorizationV1 {
                client_key_id: "tvc-browser-p256-test".to_owned(),
                scheme: ClientAuthorizationScheme::P256Sha256,
                signature: vec![0u8; 64],
            },
        }
    }

    /// Seals `TEST_SEED` and returns a request that presents the resulting blob.
    fn sealed_request(keys: &RuntimeKeys, operation: OperationV1) -> OperationRequestV1 {
        let descriptor = descriptor();
        let bootstrap = request(OperationV1::BootstrapKeyholder, descriptor.clone());
        let (_, bytes, digest) = seal_state(
            keys,
            KeyStatePlaintextV1 {
                version: API_VERSION,
                quorum_key_id: bootstrap.quorum_key_id.clone(),
                quorum_key_epoch: bootstrap.quorum_key_epoch,
                wallet_id: descriptor.wallet_id.clone(),
                descriptor_digest: descriptor_digest_from_wallet(&descriptor).expect("digest"),
                policy_version: descriptor.policy_version,
                state_version: 1,
                previous_state_digest: None,
                ed25519_public_key: descriptor.expected_ed25519_public_key,
                derivation_suite: DERIVATION_SUITE.to_owned(),
                derivation_seed: TEST_SEED,
            },
        )
        .expect("seal");

        let mut next = request(operation, descriptor);
        next.sealed_wallet_state = Some(bytes);
        next.expected_state_version = Some(1);
        next.expected_state_digest = Some(digest);
        next
    }

    fn ring_intent(program: Pubkey) -> SpendIntentV1 {
        SpendIntentV1 {
            ring: Some(CustomRingV1 {
                direction: RingDirectionV1::Exit,
                program_id: program.to_string(),
                lookup_table: Pubkey::new_from_array([0x44; 32]).to_string(),
            }),
            settlement: SpendSettlementV1::SolWithdrawal {
                recipient: Pubkey::new_from_array([0x55; 32]).to_string(),
                amount: 1,
            },
            prover_profile_id: DEVNET_EXTERNAL_PROVER_PROFILE_ID.to_owned(),
            input_commitments: Vec::new(),
        }
    }

    fn wallet(payer: Pubkey) -> ValidatedWallet<'static> {
        ValidatedWallet {
            organization_id: "00000000-0000-0000-0000-000000000000",
            sign_with: "payer",
            address: payer,
            expected_ed25519_public_key: payer.to_bytes(),
        }
    }

    fn private_program_instruction(
        payer: Address,
        program: Address,
        input_tree: Address,
        transact: &[u8],
    ) -> SolanaInstructionV1 {
        SolanaInstructionV1 {
            program_id: program.to_string(),
            accounts: vec![
                SolanaAccountMetaV1 {
                    address: payer.to_string(),
                    is_signer: true,
                    is_writable: true,
                },
                SolanaAccountMetaV1 {
                    address: input_tree.to_string(),
                    is_signer: false,
                    is_writable: true,
                },
                SolanaAccountMetaV1 {
                    address: Address::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string(),
                    is_signer: false,
                    is_writable: false,
                },
                SolanaAccountMetaV1 {
                    address: Address::default().to_string(),
                    is_signer: false,
                    is_writable: false,
                },
            ],
            data: [b"program-prefix".as_slice(), transact].concat(),
        }
    }

    #[test]
    fn reusable_lookup_table_can_omit_a_dynamic_withdrawal_recipient() {
        let payer = Address::new_from_array([0x61; 32]);
        let stable_ring_account = Address::new_from_array([0x62; 32]);
        let recipient = Address::new_from_array([0x63; 32]);
        let program = Address::new_from_array([0x64; 32]);
        let table_address = Address::new_from_array([0x65; 32]);
        let instruction = Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new_readonly(stable_ring_account, false),
                AccountMeta::new(recipient, false),
            ],
            data: Vec::new(),
        };
        let table = AddressLookupTableAccount {
            key: table_address,
            addresses: vec![stable_ring_account],
        };

        let message = v0::Message::try_compile(
            &payer,
            &[instruction],
            &[table],
            solana_hash::Hash::default(),
        )
        .expect("compile with recipient outside reusable table");

        assert!(message.account_keys.contains(&recipient));
        assert!(!message.account_keys.contains(&stable_ring_account));
        assert_eq!(message.address_table_lookups.len(), 1);
    }

    #[test]
    fn bootstrap_rejects_presented_state() {
        let keys = runtime_keys();

        assert!(operation_state_fields_are_valid(&request(
            OperationV1::BootstrapKeyholder,
            descriptor(),
        )));
        assert!(!operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::BootstrapKeyholder,
        )));
    }

    #[test]
    fn stateful_keyholder_operations_require_the_complete_state_tuple() {
        let keys = runtime_keys();
        let tags = OperationV1::DeriveViewTags;
        let complete = sealed_request(&keys, tags.clone());
        assert!(operation_state_fields_are_valid(&complete));

        let mut missing_blob = complete.clone();
        missing_blob.sealed_wallet_state = None;
        assert!(!operation_state_fields_are_valid(&missing_blob));

        let mut missing_version = complete.clone();
        missing_version.expected_state_version = None;
        assert!(!operation_state_fields_are_valid(&missing_version));

        let mut missing_digest = complete;
        missing_digest.expected_state_digest = None;
        assert!(!operation_state_fields_are_valid(&missing_digest));

        assert!(!operation_state_fields_are_valid(&request(
            tags,
            descriptor()
        )));
        assert!(operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::DecryptUtxos {
                payloads: Vec::new(),
            },
        )));
        assert!(operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::AuthorizeSpend {
                spend: AuthorizeSpendRequestV1::Prepare {
                    plan: SpendPlanV1::Builtin {
                        intent: ring_intent(Pubkey::new_unique()),
                    },
                },
            },
        )));
    }

    #[test]
    fn sealed_key_state_hides_the_seed_and_round_trips() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
        let sealed = request.sealed_wallet_state.as_deref().expect("sealed");

        // The blob the browser stores must not contain the seed in the clear.
        assert!(sealed
            .windows(TEST_SEED.len())
            .all(|window| window != TEST_SEED));

        let (inner, _) = unseal_state(&request, &keys, sealed).expect("unseal");
        assert_eq!(inner.derivation_seed, TEST_SEED);
        assert_eq!(inner.derivation_suite, DERIVATION_SUITE);
    }

    #[test]
    fn prepared_spend_capsule_is_bound_to_wallet_release_state_and_transaction() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::DeriveViewTags);
        let state_digest_bytes = request.expected_state_digest.expect("state digest");
        let transaction_digest = artifact_digest(b"one exact unsigned transaction");
        let expires_at_ms = current_time_ms().expect("clock") + 60_000;
        let descriptor_digest =
            descriptor_digest_from_wallet(&request.wallet_descriptor).expect("descriptor digest");
        let capsule = seal_spend_authorization(
            &keys,
            SpendAuthorizationPlaintextV1 {
                version: API_VERSION,
                quorum_key_id: request.quorum_key_id.clone(),
                quorum_key_epoch: request.quorum_key_epoch,
                wallet_id: request.wallet_descriptor.wallet_id.clone(),
                descriptor_digest,
                policy_version: request.wallet_descriptor.policy_version,
                state_version: request.expected_state_version.expect("state version"),
                state_digest: state_digest_bytes,
                target_release_id: request.target_release_id.clone(),
                target_manifest_digest: request.target_manifest_digest,
                target_executable_digest: request.target_executable_digest,
                prepare_request_id: [41; 32],
                expires_at_ms,
                artifact: SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest },
                shielded_balance_before: 99,
            },
        )
        .expect("seal authorization");

        let opened = unseal_spend_authorization(&request, &keys, &capsule, state_digest_bytes)
            .expect("open authorization");
        assert!(matches!(
            opened.artifact,
            SpendAuthorizationArtifactV1::ExactTransaction {
                transaction_digest: opened_digest,
            } if opened_digest == transaction_digest
        ));
        assert_eq!(opened.shielded_balance_before, 99);

        let mut wrong_release = request.clone();
        wrong_release.target_release_id = "another-release".to_owned();
        assert!(
            unseal_spend_authorization(&wrong_release, &keys, &capsule, state_digest_bytes,)
                .is_err()
        );

        let mut tampered = capsule;
        *tampered.last_mut().expect("capsule byte") ^= 1;
        assert!(
            unseal_spend_authorization(&request, &keys, &tampered, state_digest_bytes,).is_err()
        );
    }

    #[test]
    fn generic_capsule_seals_the_exact_program_and_transact() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::DeriveViewTags);
        let state_digest_bytes = request.expected_state_digest.expect("state digest");
        let program_id = [0x35; 32];
        let prepared_transact = b"one exact spp transact".to_vec();
        let transact_digest = artifact_digest(&prepared_transact);
        let capsule = seal_spend_authorization(
            &keys,
            SpendAuthorizationPlaintextV1 {
                version: API_VERSION,
                quorum_key_id: request.quorum_key_id.clone(),
                quorum_key_epoch: request.quorum_key_epoch,
                wallet_id: request.wallet_descriptor.wallet_id.clone(),
                descriptor_digest: descriptor_digest_from_wallet(&request.wallet_descriptor)
                    .expect("descriptor digest"),
                policy_version: request.wallet_descriptor.policy_version,
                state_version: request.expected_state_version.expect("state version"),
                state_digest: state_digest_bytes,
                target_release_id: request.target_release_id.clone(),
                target_manifest_digest: request.target_manifest_digest,
                target_executable_digest: request.target_executable_digest,
                prepare_request_id: [0x36; 32],
                expires_at_ms: current_time_ms().expect("clock") + 60_000,
                artifact: SpendAuthorizationArtifactV1::Spp {
                    program_id,
                    input_tree: [0x39; 32],
                    program_authorities: vec![[0x3a; 32]],
                    plan_digest: [0x37; 32],
                    prepared_transact: prepared_transact.clone(),
                    transact_digest,
                    private_tx_hash: [0x38; 32],
                },
                shielded_balance_before: 7,
            },
        )
        .expect("seal authorization");

        let opened = unseal_spend_authorization(&request, &keys, &capsule, state_digest_bytes)
            .expect("open authorization");
        assert!(matches!(
            opened.artifact,
            SpendAuthorizationArtifactV1::Spp {
                program_id: opened_program,
                prepared_transact: opened_transact,
                transact_digest: opened_digest,
                ..
            } if opened_program == program_id
                && opened_transact == prepared_transact
                && opened_digest == transact_digest
        ));
    }

    #[test]
    fn generic_outer_instruction_binds_private_hash_and_rejects_signer_capability() {
        let payer = Address::new_from_array([0x41; 32]);
        let program = Address::new_from_array([0x42; 32]);
        let input_tree = Address::new_from_array([0x44; 32]);
        let private_tx_hash = [0x47; 32];
        let valid = private_program_instruction(payer, program, input_tree, &private_tx_hash);
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &valid,
            private_tx_hash,
        )
        .is_ok());

        let mut substituted = valid.clone();
        substituted.data = b"different-transact".to_vec();
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &substituted,
            private_tx_hash,
        )
        .is_err());

        let mut ambiguous = valid.clone();
        ambiguous.data.extend_from_slice(&private_tx_hash);
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &ambiguous,
            private_tx_hash,
        )
        .is_err());

        let mut extra_signer = valid.clone();
        extra_signer.accounts.push(SolanaAccountMetaV1 {
            address: Address::new_from_array([0x43; 32]).to_string(),
            is_signer: true,
            is_writable: false,
        });
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &extra_signer,
            private_tx_hash
        )
        .is_err());

        let mut writable_pool = valid.clone();
        writable_pool.accounts[2].is_writable = true;
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &writable_pool,
            private_tx_hash
        )
        .is_err());

        let wrong_tree = Address::new_from_array([0x45; 32]);
        assert!(validate_private_program_shape(
            payer,
            program,
            wrong_tree,
            &[],
            &valid,
            private_tx_hash,
        )
        .is_err());

        let program_authority = Address::new_from_array([0x46; 32]);
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[program_authority.to_bytes()],
            &valid,
            private_tx_hash,
        )
        .is_err());
        let mut with_program_authority = valid.clone();
        with_program_authority.accounts.push(SolanaAccountMetaV1 {
            address: program_authority.to_string(),
            is_signer: false,
            is_writable: false,
        });
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[program_authority.to_bytes()],
            &with_program_authority,
            private_tx_hash,
        )
        .is_ok());

        let system = Address::default();
        let mut missing_system = valid.clone();
        missing_system
            .accounts
            .retain(|account| account.address != system.to_string());
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &missing_system,
            private_tx_hash,
        )
        .is_err());
        let mut writable_system = valid.clone();
        writable_system.accounts[3].is_writable = true;
        assert!(validate_private_program_shape(
            payer,
            program,
            input_tree,
            &[],
            &writable_system,
            private_tx_hash,
        )
        .is_err());
        let reserved = private_program_instruction(payer, system, input_tree, &private_tx_hash);
        assert!(validate_private_program_shape(
            payer,
            system,
            input_tree,
            &[],
            &reserved,
            private_tx_hash
        )
        .is_err());
    }

    #[test]
    fn generic_program_authority_seeds_are_bound_to_the_target() {
        let program = Pubkey::new_from_array([0x51; 32]);
        let seed = b"order_authority".to_vec();
        let (expected, bump) = Pubkey::find_program_address(&[seed.as_slice()], &program);
        let derived = derive_program_authority(&program, &[seed, vec![bump]])
            .expect("derive declared authority");
        assert_eq!(derived.to_bytes(), expected.to_bytes());
        assert!(derive_program_authority(&program, &[]).is_err());
        assert!(derive_program_authority(&program, &[vec![0; 33]]).is_err());
    }

    #[test]
    fn sealed_key_state_is_bound_to_its_descriptor_and_quorum_epoch() {
        let keys = runtime_keys();
        let base = sealed_request(&keys, OperationV1::BootstrapKeyholder);
        let sealed = base.sealed_wallet_state.clone().expect("sealed");

        // Each mutation is one thing a stolen blob could be replayed against.
        let mut wrong_epoch = base.clone();
        wrong_epoch.quorum_key_epoch = 2;
        assert!(unseal_state(&wrong_epoch, &keys, &sealed).is_err());

        let mut wrong_quorum_key = base.clone();
        wrong_quorum_key.quorum_key_id = "other-quorum".to_owned();
        assert!(unseal_state(&wrong_quorum_key, &keys, &sealed).is_err());

        let mut wrong_wallet = base.clone();
        wrong_wallet.wallet_descriptor.wallet_id = "wallet-someone-else".to_owned();
        assert!(unseal_state(&wrong_wallet, &keys, &sealed).is_err());

        // A descriptor change the envelope cannot see is caught by the inner
        // descriptor digest, which is why the check is done twice.
        let mut wrong_policy = base.clone();
        wrong_policy.wallet_descriptor.policy_version = 2;
        assert!(unseal_state(&wrong_policy, &keys, &sealed).is_err());

        let mut wrong_digest = base.clone();
        wrong_digest.expected_state_digest = Some([0xff; 32]);
        assert!(unseal_state(&wrong_digest, &keys, &sealed).is_err());

        let mut wrong_version = base.clone();
        wrong_version.expected_state_version = Some(2);
        assert!(unseal_state(&wrong_version, &keys, &sealed).is_err());

        // A different enclave's Quorum key cannot open it at all.
        assert!(unseal_state(&base, &runtime_keys(), &sealed).is_err());
    }

    #[test]
    fn the_same_seed_reseals_under_a_new_quorum_key_without_becoming_portable() {
        // The sealed key state is a replaceable cache, not the root of recovery.
        // A new release with a new Quorum key re-runs bootstrap, gets the same
        // deterministic Turnkey signature, and seals the same seed afresh.
        let old_keys = runtime_keys();
        let new_keys = runtime_keys();

        let old_request = sealed_request(&old_keys, OperationV1::BootstrapKeyholder);
        let new_request = sealed_request(&new_keys, OperationV1::BootstrapKeyholder);
        let old_sealed = old_request.sealed_wallet_state.clone().expect("old");
        let new_sealed = new_request.sealed_wallet_state.clone().expect("new");

        // Different Quorum keys must produce different blobs...
        assert_ne!(old_sealed, new_sealed);
        // ...that nonetheless recover the identical seed, which is what makes
        // the identity survive the rotation.
        let (old_inner, _) = unseal_state(&old_request, &old_keys, &old_sealed).expect("old");
        let (new_inner, _) = unseal_state(&new_request, &new_keys, &new_sealed).expect("new");
        assert_eq!(old_inner.derivation_seed, new_inner.derivation_seed);
        assert_eq!(
            derivation::expand_roles(&old_inner.derivation_seed, Curve::Ed25519)
                .expect("old roles")
                .1
                .pubkey()
                .as_bytes(),
            derivation::expand_roles(&new_inner.derivation_seed, Curve::Ed25519)
                .expect("new roles")
                .1
                .pubkey()
                .as_bytes(),
        );

        // Neither enclave can open the other's blob. Losing a blob is therefore
        // survivable, but a blob is never portable between deployments.
        assert!(unseal_state(&new_request, &new_keys, &old_sealed).is_err());
        assert!(unseal_state(&old_request, &old_keys, &new_sealed).is_err());
    }

    #[test]
    fn view_tags_are_the_stable_tags_a_wallet_is_found_by() {
        // These are the tags the indexer is queried with, so they must equal
        // what a wallet holding the same viewing key would compute. Deriving a
        // window of sender tags instead -- which an earlier version did -- is
        // well-formed and finds nothing, because no query uses that family.
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::DeriveViewTags);
        let (result, digest) = derive_view_tags(&request, &keys).expect("tags");
        assert_eq!(Some(digest), request.expected_state_digest);

        let (_, viewing_key) =
            derivation::expand_roles(&TEST_SEED, Curve::Ed25519).expect("expand");
        let OperationResultV1::DeriveViewTags { view_tags } = result else {
            panic!("wrong result variant");
        };
        assert_eq!(view_tags, vec![viewing_key.recipient_bootstrap_view_tag()]);

        // Stable, not positional: asking twice answers the same.
        let (again, _) = derive_view_tags(&request, &keys).expect("tags");
        let OperationResultV1::DeriveViewTags { view_tags: repeat } = again else {
            panic!("wrong result variant");
        };
        assert_eq!(repeat, view_tags);

        // The identity tag is deliberately absent: it derives from the signing
        // public key, so the client computes it without asking.
        assert_eq!(view_tags.len(), 1);
    }

    #[test]
    fn decrypt_returns_plaintext_without_asserting_ownership() {
        let keys = runtime_keys();
        let (_, viewing_key) =
            derivation::expand_roles(&TEST_SEED, Curve::Ed25519).expect("expand");
        let sender = ViewingKey::new();
        let salt: Salt = [0x7c; 16];
        let mine = sender
            .encrypt_slot(&viewing_key.pubkey(), b"utxo-plaintext", salt, 2)
            .expect("encrypt");
        let ring = sender
            .encrypt_ring_deposit(&viewing_key.pubkey(), b"ring-plaintext", salt)
            .expect("encrypt ring");
        let stranger = sender
            .encrypt_slot(&ViewingKey::new().pubkey(), b"not-yours", salt, 2)
            .expect("encrypt other");

        let payloads = vec![
            EncryptedPayloadV1::Utxo {
                ciphertext: mine,
                transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
                salt: salt.to_vec(),
                slot_index: 2,
            },
            EncryptedPayloadV1::Utxo {
                ciphertext: stranger,
                transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
                salt: salt.to_vec(),
                slot_index: 2,
            },
            EncryptedPayloadV1::RingDeposit {
                ciphertext: ring,
                transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
                salt: salt.to_vec(),
            },
        ];
        let request = sealed_request(
            &keys,
            OperationV1::DecryptUtxos {
                payloads: payloads.clone(),
            },
        );
        let (result, _) = decrypt_utxos(&request, &keys, &payloads).expect("decrypt");
        let OperationResultV1::DecryptUtxos { payloads: results } = result else {
            panic!("wrong result variant");
        };

        assert_eq!(
            results.first(),
            Some(&DecryptedPayloadV1::Plaintext {
                index: 0,
                plaintext: b"utxo-plaintext".to_vec(),
            })
        );
        assert_eq!(
            results.get(2),
            Some(&DecryptedPayloadV1::Plaintext {
                index: 2,
                plaintext: b"ring-plaintext".to_vec(),
            })
        );

        // The transport cipher has no authentication tag, so a payload for a
        // different wallet decrypts to garbage instead of failing. This
        // operation must not pretend otherwise: it returns bytes and leaves the
        // ownership decision to the caller, which checks the deserialized owner.
        let Some(DecryptedPayloadV1::Plaintext { plaintext, .. }) = results.get(1) else {
            panic!("a foreign payload still yields bytes, it does not error");
        };
        assert_ne!(plaintext.as_slice(), b"not-yours");
        assert_eq!(plaintext.len(), b"not-yours".len());
    }

    #[test]
    fn decrypt_batches_are_bounded_and_reject_malformed_public_material() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
        assert!(decrypt_utxos(&request, &keys, &[]).is_err());

        let filler = EncryptedPayloadV1::RingDeposit {
            ciphertext: vec![0u8; 16],
            transaction_viewing_public_key: vec![0x02; 33],
            salt: vec![0x00; 16],
        };
        let oversized = vec![filler.clone(); (MAX_DECRYPT_PAYLOADS_PER_BATCH + 1) as usize];
        assert!(decrypt_utxos(&request, &keys, &oversized).is_err());

        // A wrong-length viewing key or salt is a malformed request, not a
        // ciphertext that happens to belong to someone else.
        assert!(decrypt_utxos(
            &request,
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 32],
                salt: vec![0x00; 16],
            }]
        )
        .is_err());
        assert!(decrypt_utxos(
            &request,
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 33],
                salt: vec![0x00; 8],
            }]
        )
        .is_err());
    }

    #[test]
    fn oracle_operations_require_a_sealed_state() {
        let keys = runtime_keys();
        let bare = request(OperationV1::BootstrapKeyholder, descriptor());
        assert!(derive_view_tags(&bare, &keys).is_err());
        assert!(decrypt_utxos(
            &bare,
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 33],
                salt: vec![0x00; 16],
            }]
        )
        .is_err());
    }

    #[tokio::test]
    async fn bootstrap_refuses_to_continue_a_presented_state() {
        // Accepting one would let a caller choose which key state a fresh
        // derivation appears to follow. The guard runs before any Turnkey call,
        // so this test needs no network.
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
        let payer = Pubkey::new_from_array([0x22; 32]);
        assert!(bootstrap_keyholder(&request, &wallet(payer), &keys)
            .await
            .is_err());
    }

    #[test]
    fn descriptor_ids_must_be_lowercase_uuids() {
        assert!(is_uuid("a7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("A7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("../../wallet-organization"));
    }
}
