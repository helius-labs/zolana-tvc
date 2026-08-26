//! Encrypted operations for the keyholder profile.
//!
//! This service is a stateless oracle for the wallet's privacy keys. It holds
//! the derivation seed only for the duration of one request, unsealed from a
//! blob the client presents and stores nothing across requests. The client
//! performs every network call -- indexer, prover, RPC -- and builds every
//! transaction, but never holds a key it could read that data with.
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
use sha2::{Digest as _, Sha256};
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use turnkey_client::generated::immutable::{
    activity::v1::{SignRawPayloadIntentV2, SignTransactionIntentV2},
    common::v1::{HashFunction, PayloadEncoding, TransactionType},
};
use turnkey_client::{ActivityResult, TurnkeyClient};
use zeroize::{Zeroize, Zeroizing};
use zolana_interface::{instruction::tag, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::viewing_key::Salt;
use zolana_keypair::{derivation, Curve, P256Pubkey, ShieldedKeypairTrait, ViewingKey};
use zolana_keypair_turnkey::{
    TurnkeyActivities, TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
};
use zolana_tvc_protocol::bindings::{
    check_encrypted_request_bindings, check_request_bindings, RunningEnclave,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_CLOCK_SKEW_MS, MAX_DECRYPT_PAYLOADS_PER_BATCH, MAX_REQUEST_AGE_MS,
    MAX_VIEW_TAGS_PER_WINDOW, PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES, TVC_APP_PROOF_SCHEME,
    TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{qos_encrypt, verify_p256_prehash, QosP256Public};
use zolana_tvc_protocol::digest::{
    descriptor_digest_from_wallet, owner_auth_evidence_digest, provisioning_auth_digest,
    request_digest, result_digest, state_digest, wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, DecryptedPayloadV1, EncryptedPayloadV1,
    EncryptedResponseV1, Environment, OperationKind, OperationRequestV1, OperationResultV1,
    OperationV1, SealedWalletStateV1, TurnkeyEvidenceClassification, TurnkeySigningTargetV1,
    TurnkeyVerifiedAppProofV1, TvcAppProofV1, TvcOperationProofPayloadV1,
};
use zolana_tvc_protocol::{public_http_error, PublicError};

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

/// The exact grant a keyholder descriptor must carry. Bootstrap seals the key
/// state; the two oracle operations read it; authorization signs. Nothing here
/// releases a key.
const KEYHOLDER_OPERATIONS: [OperationKind; 4] = [
    OperationKind::BootstrapKeyholder,
    OperationKind::DeriveViewTags,
    OperationKind::DecryptUtxos,
    OperationKind::AuthorizeDefaultRingTransfer,
];

// Disposable development provisioner key. Only the public half is present in
// the image; its private half remains outside TVC.
const DEVELOPMENT_PROVISIONING_PUBLIC: [u8; 65] = [
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
        Err(OperationFailure::Unavailable) => {
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
        OperationV1::DeriveViewTags {
            from_tx_count,
            count,
        } => derive_view_tags(&request, keys, *from_tx_count, *count)?,
        OperationV1::DecryptUtxos { payloads } => decrypt_utxos(&request, keys, payloads)?,
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
        _ => return Err(OperationFailure::Invalid),
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
        OperationV1::DeriveViewTags { .. } | OperationV1::DecryptUtxos { .. } => has_complete_state,
        _ => false,
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
        &DEVELOPMENT_PROVISIONING_PUBLIC,
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

/// Derives one window of sender view tags. No outbound call: the window is
/// answered entirely from the unsealed seed.
fn derive_view_tags(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    from_tx_count: u64,
    count: u64,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if count == 0 || count > MAX_VIEW_TAGS_PER_WINDOW {
        return Err(OperationFailure::Invalid);
    }
    // Reject a window that would wrap rather than silently truncating it, so a
    // client never receives tags for a range it did not ask for.
    let last = from_tx_count
        .checked_add(count - 1)
        .ok_or(OperationFailure::Invalid)?;

    let (viewing_key, digest) = viewing_key_for(request, keys)?;
    let mut view_tags = Vec::with_capacity(count as usize);
    for tx_count in from_tx_count..=last {
        view_tags.push(
            viewing_key
                .get_sender_view_tag(tx_count)
                .map_err(|_| OperationFailure::Unavailable)?,
        );
    }
    Ok((
        OperationResultV1::DeriveViewTags {
            from_tx_count,
            view_tags,
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
    fn oracle_operations_require_the_complete_state_tuple() {
        let keys = runtime_keys();
        let tags = OperationV1::DeriveViewTags {
            from_tx_count: 0,
            count: 1,
        };
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
        assert!(!operation_state_fields_are_valid(&request(
            OperationV1::CreateWallet,
            descriptor(),
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
    fn view_tags_match_the_wallet_key_and_stay_within_the_window() {
        let keys = runtime_keys();
        let request = sealed_request(
            &keys,
            OperationV1::DeriveViewTags {
                from_tx_count: 7,
                count: 3,
            },
        );
        let (result, digest) = derive_view_tags(&request, &keys, 7, 3).expect("tags");
        assert_eq!(Some(digest), request.expected_state_digest);

        let (_, viewing_key) =
            derivation::expand_roles(&TEST_SEED, Curve::Ed25519).expect("expand");
        let OperationResultV1::DeriveViewTags {
            from_tx_count,
            view_tags,
        } = result
        else {
            panic!("wrong result variant");
        };
        assert_eq!(from_tx_count, 7);
        let expected: Vec<[u8; 32]> = (7..10)
            .map(|n| viewing_key.get_sender_view_tag(n).expect("tag"))
            .collect();
        assert_eq!(view_tags, expected);
    }

    #[test]
    fn view_tag_windows_are_bounded_and_never_wrap() {
        let keys = runtime_keys();
        let request = sealed_request(
            &keys,
            OperationV1::DeriveViewTags {
                from_tx_count: 0,
                count: 1,
            },
        );
        assert!(derive_view_tags(&request, &keys, 0, 0).is_err());
        assert!(derive_view_tags(&request, &keys, 0, MAX_VIEW_TAGS_PER_WINDOW + 1).is_err());
        // Wrapping would answer a range the caller did not ask for.
        assert!(derive_view_tags(&request, &keys, u64::MAX, 2).is_err());
        assert!(derive_view_tags(&request, &keys, 0, MAX_VIEW_TAGS_PER_WINDOW).is_ok());
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
        assert!(derive_view_tags(&bare, &keys, 0, 1).is_err());
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
