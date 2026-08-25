//! Encrypted operations for the lightweight client-owned wallet profile.
//!
//! The client owns derived viewing/nullifier material, wallet synchronization,
//! proof construction, proof verification, and chain submission. This service
//! performs only deterministic bootstrap and one fixed-shape default-ring
//! transaction authorization through Turnkey.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Response, StatusCode};
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
use zolana_keypair::{derivation, ShieldedKeypairTrait};
use zolana_keypair_turnkey::{
    TurnkeyActivities, TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
};
use zolana_tvc_protocol::bindings::{
    check_encrypted_request_bindings, check_request_bindings, RunningEnclave,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, MAX_CLOCK_SKEW_MS, MAX_REQUEST_AGE_MS, PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
    TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{qos_encrypt, verify_p256_prehash, QosP256Public};
use zolana_tvc_protocol::digest::{
    descriptor_digest_from_wallet, owner_auth_evidence_digest, provisioning_auth_digest,
    request_digest, result_digest,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, EncryptedResponseV1, Environment,
    OperationKind, OperationRequestV1, OperationResultV1, OperationV1,
    TurnkeyEvidenceClassification, TurnkeySigningTargetV1, TurnkeyVerifiedAppProofV1,
    TvcAppProofV1, TvcOperationProofPayloadV1,
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

    let mut result = match &request.operation {
        OperationV1::BootstrapClientEd25519 => bootstrap_client(&request, &wallet, keys).await?,
        OperationV1::AuthorizeDefaultRingTransfer {
            intent_digest,
            unsigned_transaction,
        } => {
            authorize_default_ring_transfer(
                &request,
                &wallet,
                keys,
                *intent_digest,
                unsigned_transaction,
            )
            .await?
        }
        _ => return Err(OperationFailure::Invalid),
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| OperationFailure::Unavailable)?);
    if let OperationResultV1::BootstrapClientEd25519 {
        derivation_seed, ..
    } = &mut result
    {
        derivation_seed.zeroize();
    }
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
        state_digest: NO_SERVER_STATE_DIGEST,
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
        || request.sealed_wallet_state.is_some()
        || request.expected_state_version.is_some()
        || request.expected_state_digest.is_some()
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

    let grant = &descriptor.allowed_clients[0];
    let expected_client_key_id = format!(
        "{BROWSER_CLIENT_KEY_ID_PREFIX}{}",
        hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
    );
    if grant.client_key_id != expected_client_key_id
        || grant.client_public_key.len() != 65
        || grant.allowed_operations
            != [
                OperationKind::BootstrapClientEd25519,
                OperationKind::AuthorizeDefaultRingTransfer,
            ]
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

async fn bootstrap_client(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
) -> Result<OperationResultV1, OperationFailure> {
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

    let turnkey_app_proofs = app_proofs(&activity);
    Ok(OperationResultV1::BootstrapClientEd25519 {
        solana_address: wallet.sign_with.to_owned(),
        shielded_owner_hash: shielded_address
            .owner_hash()
            .map_err(|_| OperationFailure::Unavailable)?,
        shielded_nullifier_public_key: shielded_address.nullifier_pubkey,
        shielded_viewing_public_key: shielded_address.viewing_pubkey.as_bytes().to_vec(),
        derivation_seed: seed.to_vec(),
        derivation_suite: DERIVATION_SUITE.to_owned(),
        turnkey_activity_id: activity.activity_id,
        turnkey_app_proofs,
        evidence_classification: TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
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
