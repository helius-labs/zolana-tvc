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
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::{versioned::VersionedTransaction, Transaction};
use turnkey_client::generated::immutable::{
    activity::v1::{SignRawPayloadIntentV2, SignTransactionIntentV2},
    common::v1::{HashFunction, PayloadEncoding, TransactionType},
};
use turnkey_client::{ActivityResult, TurnkeyClient};
use zeroize::{Zeroize, Zeroizing};
use zolana_client::AsyncProverClient;
use zolana_client::SppProofInputUtxo;
use zolana_client::{AsyncRpc, ClientError, ZolanaClient};
use zolana_interface::{instruction::tag, pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::viewing_key::Salt;
use zolana_keypair::{derivation, Curve, P256Pubkey, ShieldedKeypairTrait, ViewingKey};
use zolana_keypair_turnkey::{
    TurnkeyActivities, TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
};
use zolana_transaction::instructions::transact::{ConfidentialTransfer, SettlementTarget};
use zolana_transaction::{AssetRegistry, Wallet, SOL_MINT};
use zolana_tvc_protocol::bindings::{
    check_encrypted_request_bindings, check_request_bindings, RunningEnclave,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_CLOCK_SKEW_MS, MAX_DECRYPT_PAYLOADS_PER_BATCH, MAX_REQUEST_AGE_MS,
    PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES, TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{qos_encrypt, verify_p256_prehash, QosP256Public};
use zolana_tvc_protocol::digest::{
    descriptor_digest_from_wallet, owner_auth_evidence_digest, provisioning_auth_digest,
    request_digest, result_digest, state_digest, wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, AssetV1, DecryptedPayloadV1,
    EncryptedPayloadV1, EncryptedResponseV1, Environment, FailureStage, OperationKind,
    OperationRequestV1, OperationResultV1, OperationV1, RingSpendV1, SealedWalletStateV1,
    SolWithdrawalIntentV1, TransferIntentV1, TurnkeyEvidenceClassification, TurnkeySigningTargetV1,
    TurnkeyVerifiedAppProofV1, TvcAppProofV1, TvcOperationProofPayloadV1,
};
use zolana_tvc_protocol::{public_http_error, PublicError};
use zolana_wallet::{
    create_transfer, create_withdrawal, sign_shielded_transaction, sync_wallet_async,
    try_resolve_registered_address_async, KeypairWalletAuthority, TransferParams, WithdrawalLeg,
    WithdrawalParams,
};

use crate::solana_rpc::SolanaRpc;
use crate::turnkey::QosTurnkeyStamper;
use crate::{into_response, sign_ephemeral_low_s, AppState, RuntimeKeys};

const TURNKEY_DERIVATION_PATH: &str = "m/44'/501'/0'/0'";
const PROVISIONING_KEY_ID: &str = "wallet-dev-e2e-provisioner-v1";
const BROWSER_CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
const MAX_SOLANA_TRANSACTION_BYTES: usize = 1_232;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
const MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS: u64 = 1_000_000;
const NO_SERVER_STATE_DIGEST: [u8; 32] = [0; 32];
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
const KEYHOLDER_OPERATIONS: [OperationKind; 8] = [
    OperationKind::BootstrapKeyholder,
    OperationKind::DeriveViewTags,
    OperationKind::DecryptUtxos,
    OperationKind::BuildTransfer,
    OperationKind::BuildCustomRingTransfer,
    OperationKind::BuildSolWithdrawal,
    OperationKind::BuildCustomRingSolWithdrawal,
    OperationKind::AuthorizeDefaultRingTransfer,
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
        OperationV1::BuildTransfer { intent } => {
            match build_spend(&request, &wallet, SpendIntent::Transfer(intent), keys).await {
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
        OperationV1::BuildSolWithdrawal { intent } => {
            match build_spend(&request, &wallet, SpendIntent::SolWithdrawal(intent), keys).await {
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
        OperationV1::AuthorizeDefaultRingTransfer {
            intent_digest,
            unsigned_transaction,
        } => {
            // Signing does not touch the privacy keys, so it needs no sealed
            // state and binds no state digest.
            let signed = authorize_default_ring_transfer(
                &request,
                &wallet,
                keys,
                *intent_digest,
                unsigned_transaction,
            )
            .await?;
            (signed, NO_SERVER_STATE_DIGEST)
        }
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| OperationFailure::Unavailable)?);
    let encrypted_result =
        qos_encrypt(&client_response_key.encryption, result_plaintext.as_bytes())
            .map_err(|_| OperationFailure::Unavailable)?;
    if encrypted_result.len() as u64 > PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES {
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
        OperationV1::BootstrapKeyholder | OperationV1::AuthorizeDefaultRingTransfer { .. } => {
            has_no_state
        }
        OperationV1::DeriveViewTags
        | OperationV1::DecryptUtxos { .. }
        | OperationV1::BuildTransfer { .. }
        | OperationV1::BuildSolWithdrawal { .. } => has_complete_state,
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

/// Disposable devnet spend path.
///
/// Unlike the two key-oracle calls, this operation deliberately performs its
/// own pinned Photon, Solana RPC, and prover calls. The external prover request
/// contains the plaintext witness, including the long-lived nullifier secret.
/// This closes the PoC without returning that secret to the browser, but it is
/// not an acceptable production boundary.
#[derive(Clone, Copy)]
enum SpendIntent<'a> {
    Transfer(&'a TransferIntentV1),
    SolWithdrawal(&'a SolWithdrawalIntentV1),
}

impl<'a> SpendIntent<'a> {
    fn recipient(self) -> &'a str {
        match self {
            Self::Transfer(intent) => &intent.recipient,
            Self::SolWithdrawal(intent) => &intent.recipient,
        }
    }

    fn amount(self) -> u64 {
        match self {
            Self::Transfer(intent) => intent.amount,
            Self::SolWithdrawal(intent) => intent.amount,
        }
    }

    /// The custom ring this spend belongs to, absent for the default ring.
    fn ring(self) -> Option<&'a RingSpendV1> {
        match self {
            Self::Transfer(intent) => intent.ring.as_ref(),
            Self::SolWithdrawal(intent) => intent.ring.as_ref(),
        }
    }

    fn prover_profile_id(self) -> &'a str {
        match self {
            Self::Transfer(intent) => &intent.prover_profile_id,
            Self::SolWithdrawal(intent) => &intent.prover_profile_id,
        }
    }
}

async fn build_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: SpendIntent<'_>,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if intent.amount() == 0 || intent.prover_profile_id() != DEVNET_EXTERNAL_PROVER_PROFILE_ID {
        return Err(OperationFailure::Invalid);
    }
    let recipient = Pubkey::from_str(intent.recipient()).map_err(|_| OperationFailure::Invalid)?;
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let client = turnkey_client(keys)?;
    let activities: Arc<dyn TurnkeyActivities> =
        Arc::new(TurnkeyApiActivities::new(Arc::clone(&client)));
    let keypair = TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        activities,
        TurnkeyKeyRef::new(target.organization_id, target.sign_with),
        inner.ed25519_public_key,
        &inner.derivation_seed,
    )
    .map_err(|_| OperationFailure::Invalid)?;
    let tree = Address::from_str(DEVNET_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let (asset, asset_registry) = match intent {
        SpendIntent::Transfer(intent) => resolve_asset(&rpc, &intent.asset).await?,
        SpendIntent::SolWithdrawal(_) => (SOL_MINT, AssetRegistry::default()),
    };
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        EXPECTED_EXTERNAL_ORIGIN,
        EXPECTED_EXTERNAL_ORIGIN,
        tree,
    );
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::new_from_array(target.address.to_bytes()),
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let mut wallet = Wallet::new(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        asset_registry,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    sync_wallet_async(&mut wallet, &authority, &zolana)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::SyncWallet))?;
    let shielded_balance_before = wallet
        .balance(asset, None)
        .map_err(|_| OperationFailure::Unavailable)?
        .amount;
    if shielded_balance_before < intent.amount() {
        return Err(OperationFailure::Failed(
            FailureStage::ShieldedBalanceNotReady,
        ));
    }
    // Value does not cross a ring boundary inside a spend: a utxo's commitment
    // binds it to one ring, and each circuit covers only its own. So the
    // balance that matters is the balance in the ring being spent from.
    let requested_ring = intent
        .ring()
        .map(|ring| Address::from_str(&ring.program_id))
        .transpose()
        .map_err(|_| OperationFailure::Invalid)?;
    let (reachable, elsewhere) = wallet
        .utxos
        .iter()
        .filter(|entry| !entry.spent && entry.utxo.asset == asset)
        .fold((0u64, 0u64), |(here, other), entry| {
            if entry.utxo.ring_program_id == requested_ring {
                (here.saturating_add(entry.utxo.amount), other)
            } else {
                (here, other.saturating_add(entry.utxo.amount))
            }
        });
    if reachable < intent.amount() {
        // Naming the ring is the difference between "you have no funds" and
        // "your funds are somewhere this spend cannot reach".
        return Err(OperationFailure::Failed(if elsewhere > 0 {
            FailureStage::FundsAreRingBound
        } else {
            FailureStage::ShieldedBalanceNotReady
        }));
    }
    let payer = Address::new_from_array(target.address.to_bytes());

    // A custom-ring transact runs a different circuit and does not fit a legacy
    // packet, so it is built and signed as a versioned transaction end to end.
    if let Some(ring) = intent.ring() {
        let prover = AsyncProverClient::new(EXPECTED_CUSTOM_RING_PROVER_ORIGIN.to_owned());
        let unsigned = build_ring_transaction(
            ring,
            &intent,
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
        .await?;
        let signed =
            sign_versioned_transaction(&client, target, request.issued_at_ms, unsigned).await?;
        return ring_spend_result(
            &intent,
            signed,
            request,
            sealed_bytes,
            digest,
            shielded_balance_before,
        );
    }

    let transaction = match intent {
        SpendIntent::Transfer(intent) => {
            create_transfer(TransferParams {
                rpc: &zolana,
                wallet: &wallet,
                payer,
                recipient,
                asset,
                amount: intent.amount,
            })
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::CreateTransfer))?
            .transaction
        }
        SpendIntent::SolWithdrawal(intent) => {
            create_withdrawal(WithdrawalParams {
                wallet: &wallet,
                payer,
                legs: vec![WithdrawalLeg {
                    recipient,
                    asset: SOL_MINT,
                    amount: intent.amount,
                    spl_token_program: None,
                }],
            })
            .map_err(|_| OperationFailure::Failed(FailureStage::CreateWithdrawal))?
            .transaction
        }
    };
    let shielded = sign_shielded_transaction(transaction, &wallet, &authority)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::SignShieldedTransaction))?;
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let unsigned = zolana
        .finish_submission_unsigned(&shielded, target.address, blockhash)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let signed = sign_transaction(&client, target, request.issued_at_ms, unsigned)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::SignTransaction))?;
    let signed_bytes =
        bincode1::serialize(&signed.result.0).map_err(|_| OperationFailure::Unavailable)?;
    if signed_bytes.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = signed.result.0.signatures[0].to_string();
    let turnkey_app_proofs = signed.result.1;
    let state_version = request
        .expected_state_version
        .ok_or(OperationFailure::Invalid)?;
    let result = match intent {
        SpendIntent::Transfer(_) => OperationResultV1::BuildTransfer {
            transaction_signature,
            signed_transaction: signed_bytes,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version,
            state_digest: digest,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        SpendIntent::SolWithdrawal(_) => OperationResultV1::BuildSolWithdrawal {
            transaction_signature,
            signed_transaction: signed_bytes,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version,
            state_digest: digest,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
    };
    Ok((result, digest))
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
    ring: &RingSpendV1,
    intent: &SpendIntent<'_>,
    cx: RingSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
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

    // Inputs must already belong to this ring: value does not cross a ring
    // boundary inside a transfer, and the commitment binds each utxo to one.
    let nullifier_key = keypair.nullifier_key();
    let mut inputs = Vec::new();
    let mut available: u64 = 0;
    for entry in wallet.utxos.iter().filter(|entry| {
        !entry.spent
            && entry.utxo.asset == asset
            && entry.utxo.ring_program_id == Some(program_id)
            && entry.output_context.tree == tree
    }) {
        inputs.push(SppProofInputUtxo::new(entry.utxo.clone(), &nullifier_key));
        available = available
            .checked_add(entry.utxo.amount)
            .ok_or(OperationFailure::Unavailable)?;
        if available >= intent.amount() {
            break;
        }
    }
    if available < intent.amount() {
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
    match intent {
        SpendIntent::Transfer(transfer_intent) => {
            // A ring transfer only sends to a registered shielded identity; the
            // public-exit form is `withdraw`, which is the other arm.
            let recipient_address = try_resolve_registered_address_async(
                zolana,
                Address::new_from_array(recipient.to_bytes()),
            )
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::CreateTransfer))?
            .ok_or(OperationFailure::Invalid)?;
            transfer
                .send(&recipient_address.address, asset, transfer_intent.amount)
                .map_err(|_| OperationFailure::Failed(FailureStage::CreateTransfer))?;
        }
        SpendIntent::SolWithdrawal(withdrawal) => {
            transfer
                .withdraw(
                    SOL_MINT,
                    withdrawal.amount,
                    SettlementTarget::Sol {
                        user_sol_account: Address::new_from_array(recipient.to_bytes()),
                    },
                )
                .map_err(|_| OperationFailure::Failed(FailureStage::CreateWithdrawal))?;
        }
    }
    let prepared = transfer
        .prepare()
        .map_err(|_| OperationFailure::Failed(FailureStage::CreateTransfer))?;

    let proven = CustomRingTransfer::new(CustomRingTransferInput {
        ring: custom_ring,
        sender: keypair,
        prepared,
    })
    .with_tree(tree)
    .with_assets(assets)
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
    let table = read_lookup_table(rpc, table_address, &instruction, compute.program_id).await?;
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

/// Reads the lookup table and checks it covers every account the instruction
/// needs. The caller names the table, so it is verified rather than trusted: a
/// table missing a key would compile a message the runtime rejects, and one the
/// caller controls must not be able to steer which accounts the instruction
/// resolves to.
async fn read_lookup_table(
    rpc: &SolanaRpc,
    address: Address,
    instruction: &Instruction,
    compute_program: Address,
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
    let addresses = parsed.addresses.to_vec();
    for required in custom_ring_sdk::lookup_table_addresses(instruction, compute_program) {
        if !addresses.contains(&required) {
            return Err(OperationFailure::Invalid);
        }
    }
    Ok(AddressLookupTableAccount {
        key: address,
        addresses,
    })
}

/// Packages a signed ring spend into its operation result.
///
/// Same shape as the default path's, over a versioned transaction: the browser
/// submits the exact bytes either way, and already reads both forms.
fn ring_spend_result(
    intent: &SpendIntent<'_>,
    signed: ActivityResult<(VersionedTransaction, Vec<TurnkeyVerifiedAppProofV1>)>,
    request: &OperationRequestV1,
    sealed_bytes: &[u8],
    digest: [u8; 32],
    shielded_balance_before: u64,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
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
    let result = match intent {
        SpendIntent::Transfer(_) => OperationResultV1::BuildTransfer {
            transaction_signature,
            signed_transaction: signed_bytes,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version,
            state_digest: digest,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        SpendIntent::SolWithdrawal(_) => OperationResultV1::BuildSolWithdrawal {
            transaction_signature,
            signed_transaction: signed_bytes,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version,
            state_digest: digest,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
    };
    Ok((result, digest))
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
                .map_err(|_| OperationFailure::Failed(FailureStage::ResolveAsset))?
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
        TransferError::Keypair(_) => FailureStage::SignShieldedTransaction,
        _ => FailureStage::CreateTransfer,
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
        _ => FailureStage::FinishSubmission,
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
        .map_err(|_| OperationFailure::Failed(FailureStage::SignTransaction))?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Failed(FailureStage::SignTransaction));
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

async fn sign_transaction(
    client: &TvcTurnkeyClient,
    wallet: &ValidatedWallet<'_>,
    timestamp_ms: u64,
    unsigned: Transaction,
) -> Result<ActivityResult<(Transaction, Vec<TurnkeyVerifiedAppProofV1>)>, OperationFailure> {
    if unsigned.signatures.len() != 1 || unsigned.signatures[0] != Signature::default() {
        return Err(OperationFailure::Unavailable);
    }
    let unsigned_bytes =
        bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Unavailable)?;
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
        .map_err(|_| OperationFailure::Unavailable)?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Unavailable);
    }
    let signed: Transaction = bincode1::deserialize(
        &hex::decode(&activity.result.signed_transaction)
            .map_err(|_| OperationFailure::Unavailable)?,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    if signed.message != unsigned.message
        || signed.signatures.len() != 1
        || signed.signatures[0] == Signature::default()
        || !signed.signatures[0].verify(
            wallet.expected_ed25519_public_key.as_ref(),
            &signed.message_data(),
        )
    {
        return Err(OperationFailure::Unavailable);
    }
    let proofs = app_proofs(&activity);
    Ok(ActivityResult {
        result: (signed, proofs),
        activity_id: activity.activity_id,
        status: activity.status,
        app_proofs: activity.app_proofs,
    })
}

async fn authorize_default_ring_transfer(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    intent_digest: [u8; 32],
    unsigned_transaction: &[u8],
) -> Result<OperationResultV1, OperationFailure> {
    if intent_digest == [0; 32] || unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Invalid);
    }
    let unsigned: Transaction =
        bincode1::deserialize(unsigned_transaction).map_err(|_| OperationFailure::Invalid)?;
    let canonical = bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Invalid)?;
    if canonical != unsigned_transaction {
        return Err(OperationFailure::Invalid);
    }
    validate_default_ring_transaction(&unsigned, wallet)?;

    let client = turnkey_client(keys)?;
    let activity = client
        .sign_transaction(
            wallet.organization_id.to_owned(),
            u128::from(request.issued_at_ms),
            SignTransactionIntentV2 {
                sign_with: wallet.sign_with.to_owned(),
                unsigned_transaction: hex::encode(unsigned_transaction),
                r#type: TransactionType::Solana,
            },
        )
        .await
        .map_err(|_| OperationFailure::Unavailable)?;
    if activity.app_proofs.is_empty() {
        return Err(OperationFailure::Unavailable);
    }

    let signed: Transaction = bincode1::deserialize(
        &hex::decode(&activity.result.signed_transaction)
            .map_err(|_| OperationFailure::Unavailable)?,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    if signed.message != unsigned.message
        || signed.signatures.len() != 1
        || signed.signatures[0] == Signature::default()
        || !signed.signatures[0].verify(
            wallet.expected_ed25519_public_key.as_ref(),
            &signed.message_data(),
        )
    {
        return Err(OperationFailure::Unavailable);
    }
    let signed_transaction =
        bincode1::serialize(&signed).map_err(|_| OperationFailure::Unavailable)?;
    if signed_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }

    let turnkey_app_proofs = app_proofs(&activity);
    Ok(OperationResultV1::AuthorizeDefaultRingTransfer {
        transaction_signature: signed.signatures[0].to_string(),
        signed_transaction,
        intent_digest,
        turnkey_activity_id: activity.activity_id,
        turnkey_app_proofs,
        evidence_classification: TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
    })
}

fn validate_default_ring_transaction(
    transaction: &Transaction,
    wallet: &ValidatedWallet<'_>,
) -> Result<(), OperationFailure> {
    let message = &transaction.message;
    if transaction.signatures != [Signature::default()]
        || message.header.num_required_signatures != 1
        || message.header.num_readonly_signed_accounts != 0
        || message.account_keys.first() != Some(&wallet.address)
        || message.recent_blockhash == Hash::default()
        || !(message.instructions.len() == 2 || message.instructions.len() == 3)
    {
        return Err(OperationFailure::Invalid);
    }
    for instruction in &message.instructions {
        if usize::from(instruction.program_id_index) >= message.account_keys.len()
            || instruction
                .accounts
                .iter()
                .any(|index| usize::from(*index) >= message.account_keys.len())
        {
            return Err(OperationFailure::Invalid);
        }
    }

    let compute_limit = &message.instructions[0];
    if program_id(message, compute_limit) != Some(solana_compute_budget_interface::id())
        || !compute_limit.accounts.is_empty()
        || !valid_compute_limit(&compute_limit.data)
    {
        return Err(OperationFailure::Invalid);
    }
    if message.instructions.len() == 3 {
        let compute_price = &message.instructions[1];
        if program_id(message, compute_price) != Some(solana_compute_budget_interface::id())
            || !compute_price.accounts.is_empty()
            || !valid_compute_price(&compute_price.data)
        {
            return Err(OperationFailure::Invalid);
        }
    }

    let transfer = message
        .instructions
        .last()
        .ok_or(OperationFailure::Invalid)?;
    if program_id(message, transfer) != Some(Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID))
        || transfer.data.first() != Some(&tag::TRANSACT)
        || !transfer.accounts.contains(&0)
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(())
}

fn program_id(
    message: &solana_message::Message,
    instruction: &solana_message::compiled_instruction::CompiledInstruction,
) -> Option<Pubkey> {
    message
        .account_keys
        .get(usize::from(instruction.program_id_index))
        .copied()
}

fn valid_compute_limit(data: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 4]>::try_from(data.get(1..).unwrap_or_default()) else {
        return false;
    };
    data.first() == Some(&2) && (1..=MAX_COMPUTE_UNIT_LIMIT).contains(&u32::from_le_bytes(bytes))
}

fn valid_compute_price(data: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 8]>::try_from(data.get(1..).unwrap_or_default()) else {
        return false;
    };
    data.first() == Some(&3) && u64::from_le_bytes(bytes) <= MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS
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
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;

    use super::*;

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

    fn wallet(payer: Pubkey) -> ValidatedWallet<'static> {
        ValidatedWallet {
            organization_id: "00000000-0000-0000-0000-000000000000",
            sign_with: "payer",
            address: payer,
            expected_ed25519_public_key: payer.to_bytes(),
        }
    }

    fn valid_transfer(payer: Pubkey) -> Transaction {
        let transfer = Instruction {
            program_id: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            accounts: vec![AccountMeta::new_readonly(payer, true)],
            data: vec![tag::TRANSACT, 0xaa],
        };
        let mut transaction = Transaction::new_unsigned(Message::new(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(300_000),
                transfer,
            ],
            Some(&payer),
        ));
        transaction.message.recent_blockhash = Hash::new_from_array([0x44; 32]);
        transaction
    }

    #[test]
    fn bootstrap_and_signing_reject_presented_state() {
        let keys = runtime_keys();
        let bootstrap = request(OperationV1::BootstrapKeyholder, descriptor());
        assert!(operation_state_fields_are_valid(&bootstrap));
        assert!(!operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::BootstrapKeyholder,
        )));

        let authorize = OperationV1::AuthorizeDefaultRingTransfer {
            intent_digest: [0x55; 32],
            unsigned_transaction: Vec::new(),
        };
        assert!(operation_state_fields_are_valid(&request(
            authorize.clone(),
            descriptor(),
        )));
        assert!(!operation_state_fields_are_valid(&sealed_request(
            &keys, authorize,
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
            OperationV1::BuildTransfer {
                intent: zolana_tvc_protocol::types::TransferIntentV1 {
                    asset: AssetV1::Sol,
                    recipient: Pubkey::new_unique().to_string(),
                    amount: 1,
                    prover_profile_id: DEVNET_EXTERNAL_PROVER_PROFILE_ID.to_owned(),
                    ring: None,
                },
            },
        )));
        assert!(operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::BuildSolWithdrawal {
                intent: zolana_tvc_protocol::types::SolWithdrawalIntentV1 {
                    recipient: Pubkey::new_unique().to_string(),
                    amount: 1,
                    prover_profile_id: DEVNET_EXTERNAL_PROVER_PROFILE_ID.to_owned(),
                    ring: None,
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
    fn accepts_only_fixed_default_ring_transaction_shape() {
        let payer = Pubkey::new_from_array([0x22; 32]);
        let transaction = valid_transfer(payer);
        assert!(validate_default_ring_transaction(&transaction, &wallet(payer)).is_ok());

        let mut wrong_program = transaction.clone();
        let program_index = usize::from(
            wrong_program
                .message
                .instructions
                .last()
                .unwrap()
                .program_id_index,
        );
        wrong_program.message.account_keys[program_index] = Pubkey::new_from_array([0x99; 32]);
        assert!(validate_default_ring_transaction(&wrong_program, &wallet(payer)).is_err());

        let mut wrong_tag = transaction.clone();
        wrong_tag.message.instructions.last_mut().unwrap().data[0] = tag::DEPOSIT;
        assert!(validate_default_ring_transaction(&wrong_tag, &wallet(payer)).is_err());

        let mut pre_signed = transaction;
        pre_signed.signatures[0] = Signature::from([0x33; 64]);
        assert!(validate_default_ring_transaction(&pre_signed, &wallet(payer)).is_err());
    }

    #[test]
    fn compute_budget_is_bounded() {
        assert!(valid_compute_limit(&[2, 0xe0, 0x93, 0x04, 0x00]));
        assert!(!valid_compute_limit(&[2, 0, 0, 0, 0]));
        assert!(!valid_compute_limit(&[2, 1, 2]));
        assert!(valid_compute_price(&[3, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!valid_compute_price(&[4, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn descriptor_ids_must_be_lowercase_uuids() {
        assert!(is_uuid("a7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("A7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("../../wallet-organization"));
    }
}
