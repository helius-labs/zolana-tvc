//! Encrypted development wallet operations for the disposable TVC pet.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Response, StatusCode};
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest as _, Sha256};
use solana_address::Address;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use turnkey_client::generated::immutable::{
    activity::v1::{CreateWalletIntent, SignRawPayloadIntentV2, SignTransactionIntentV2},
    common::v1::{
        AddressFormat, Curve, HashFunction, PathFormat, PayloadEncoding, TransactionType,
    },
};
use turnkey_client::generated::services::coordinator::public::v1::GetWalletAccountsRequest;
use turnkey_client::generated::WalletAccountParams;
use turnkey_client::{ActivityResult, TurnkeyClient};
use zeroize::{Zeroize, Zeroizing};
use zolana_client::{AsyncRpc, ClientError, ZolanaClient};
use zolana_interface::{pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::{derivation, ShieldedKeypairTrait};
use zolana_keypair_turnkey::{
    TurnkeyActivities, TurnkeyApiActivities, TurnkeyEd25519ShieldedKeypair, TurnkeyKeyRef,
};
use zolana_transaction::SOL_MINT;
use zolana_transaction::{AssetRegistry, Wallet};
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
    request_digest, result_digest, state_digest, wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, DevelopmentAssetV1, DevelopmentFailureStage,
    EncryptedResponseV1, Environment, OperationRequestV1, OperationResultV1, OperationV1,
    SealedWalletStateV1, TurnkeyEvidenceClassification, TurnkeySigningTargetV1,
    TurnkeyVerifiedAppProofV1, TvcAppProofV1, TvcOperationProofPayloadV1,
};
use zolana_tvc_protocol::{public_http_error, PublicError};
use zolana_wallet::{
    build_registration_transaction, create_deposit, create_transfer, sign_shielded_transaction,
    sync_wallet_async, DepositParams, KeypairWalletAuthority, TransferParams,
};

use crate::development_prover::{
    DEVELOPMENT_DEFAULT_TREE, DEVELOPMENT_EXTERNAL_PHOTON_URL,
    DEVELOPMENT_EXTERNAL_PROVER_PROFILE_ID, DEVELOPMENT_EXTERNAL_PROVER_URL,
};
use crate::development_rpc::DevelopmentSolanaRpc;
use crate::turnkey::QosTurnkeyStamper;
use crate::{into_response, sign_ephemeral_low_s, AppState, RuntimeKeys};

const WALLET_ID: &str = "wallet-dev-e2e-0690e9e7";
const TURNKEY_PARENT_ORGANIZATION_ID: &str = "69febc39-7ac1-42c1-9786-f20f9cc52c5b";
const TURNKEY_ORGANIZATION_ID: &str = "69febc39-7ac1-42c1-9786-f20f9cc52c5b";
const TURNKEY_WALLET_ID: &str = "0690e9e7-8e6c-5e81-ab19-93c53a9acc74";
const TURNKEY_WALLET_ACCOUNT_ID: &str = "1f9a1265-49bb-4f6a-899c-85409119035b";
const TURNKEY_ADDRESS: &str = "D3Es9fdLDxtxA6dWRNdJt5uzoVtxuMHHYYoDWrhNGAp";
const TURNKEY_DERIVATION_PATH: &str = "m/44'/501'/0'/0'";
const TURNKEY_SERVICE_USER_ID: &str = "9d86106d-5340-46d6-a05d-9e5ea9f5e019";
const TURNKEY_API_KEY_ID: &str = "218b879b-5e81-4843-bee7-7811a7fd0979";
const CLIENT_KEY_ID: &str = "wallet-dev-e2e-client-v1";
const PROVISIONING_KEY_ID: &str = "wallet-dev-e2e-provisioner-v1";
const MAX_SHIELD_SOL_LAMPORTS: u64 = 1_000_000_000;
const PUBLIC_SOL_FEE_RESERVE_LAMPORTS: u64 = 5_000_000;
const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
const WALLET_NAME_PREFIX: &str = "zolana-tvc-";
const DEVELOPMENT_WALLET_MNEMONIC_LENGTH: i32 = 24;
const BROWSER_CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";

const EXPECTED_ED25519_PUBLIC_KEY: [u8; 32] = [
    0x03, 0x15, 0x80, 0x5c, 0x22, 0x06, 0x41, 0x2e, 0x1a, 0x2b, 0x16, 0xe4, 0xae, 0x11, 0xa4, 0x29,
    0xed, 0x59, 0x40, 0x7d, 0x50, 0x6e, 0x0a, 0x73, 0x52, 0x12, 0x84, 0x28, 0x29, 0x77, 0xfd, 0xfd,
];

// Disposable development client/provisioner key. Only the public half is in
// the image; its private half remains in the operator's local credential file.
const DEVELOPMENT_CLIENT_PUBLIC: [u8; 65] = [
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum DescriptorProfile {
    Operator,
    Browser,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct WalletStatePlaintextV1 {
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

impl Drop for WalletStatePlaintextV1 {
    fn drop(&mut self) {
        self.derivation_seed.zeroize();
    }
}

enum OperationFailure {
    Invalid,
    Unavailable,
    Development(DevelopmentFailureStage),
}

pub(crate) async fn handle_operation(state: &AppState, body: &[u8]) -> Response<Body> {
    let result = execute(state, body).await;
    match result {
        Ok(response) => into_response(zolana_tvc_protocol::PublicHttpResponse {
            status: StatusCode::OK.as_u16(),
            content_type: "application/json",
            body: response.into_bytes(),
        }),
        Err(OperationFailure::Invalid) => {
            into_response(public_http_error(PublicError::InvalidRequest))
        }
        Err(OperationFailure::Unavailable | OperationFailure::Development(_)) => {
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
    let request_digest = request_digest(&request).map_err(|_| OperationFailure::Invalid)?;

    let client_response_key = QosP256Public::from_bytes(&request.client_response_public_key)
        .map_err(|_| OperationFailure::Invalid)?;
    let (result, result_state_digest) = match &request.operation {
        OperationV1::CreateWallet => match create_wallet(&request, keys).await {
            Ok(result) => result,
            Err(OperationFailure::Development(stage)) => (
                OperationResultV1::DevelopmentFailure {
                    operation: request.operation.kind(),
                    stage,
                },
                [0; 32],
            ),
            Err(error) => return Err(error),
        },
        OperationV1::BootstrapEd25519 => bootstrap(&request, &wallet, keys).await?,
        OperationV1::PrepareWallet { recent_blockhash } => {
            match prepare_wallet(&request, &wallet, keys, *recent_blockhash).await {
                Ok(result) => result,
                Err(OperationFailure::Development(stage)) => (
                    OperationResultV1::DevelopmentFailure {
                        operation: request.operation.kind(),
                        stage,
                    },
                    request.expected_state_digest.unwrap_or([0; 32]),
                ),
                Err(error) => return Err(error),
            }
        }
        OperationV1::ShieldSpl {
            mint,
            asset_id,
            amount,
        } => shield_spl(&request, &wallet, keys, mint, *asset_id, *amount).await?,
        OperationV1::ShieldSol { amount } => {
            match shield_sol(&request, &wallet, keys, *amount).await {
                Ok(result) => result,
                Err(OperationFailure::Development(stage)) => (
                    OperationResultV1::DevelopmentFailure {
                        operation: request.operation.kind(),
                        stage,
                    },
                    request.expected_state_digest.unwrap_or([0; 32]),
                ),
                Err(error) => return Err(error),
            }
        }
        OperationV1::BuildTransfer { intent } => {
            match build_transfer(&request, &wallet, intent, keys).await {
                Ok(result) => result,
                Err(OperationFailure::Development(stage)) => (
                    OperationResultV1::DevelopmentFailure {
                        operation: request.operation.kind(),
                        stage,
                    },
                    request.expected_state_digest.unwrap_or([0; 32]),
                ),
                Err(error) => return Err(error),
            }
        }
        _ => return Err(OperationFailure::Invalid),
    };
    let result_plaintext = jcs_serialize(&result).map_err(|_| OperationFailure::Unavailable)?;
    let encrypted_result =
        qos_encrypt(&client_response_key.encryption, result_plaintext.as_bytes())
            .map_err(|_| OperationFailure::Unavailable)?;
    if encrypted_result.len() as u64 > PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let result_digest = result_digest(&encrypted_result);
    let proof_payload = jcs_serialize(&TvcOperationProofPayloadV1 {
        r#type: TVC_APP_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest,
        result_digest,
        operation: request.operation.kind(),
        state_digest: result_state_digest,
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
    let (profile, wallet) = validate_descriptor(request)?;
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
    if (request.operation.kind() == zolana_tvc_protocol::types::OperationKind::CreateWallet)
        != (profile == DescriptorProfile::Operator)
    {
        return Err(OperationFailure::Invalid);
    }
    match (
        request.expected_state_version,
        request.expected_state_digest,
    ) {
        (None, None) | (Some(_), Some(_)) => Ok(wallet),
        _ => Err(OperationFailure::Invalid),
    }
}

fn validate_descriptor(
    request: &OperationRequestV1,
) -> Result<(DescriptorProfile, ValidatedWallet<'_>), OperationFailure> {
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
    let operator_target = matches!(
        &descriptor.turnkey_signing_target,
        TurnkeySigningTargetV1::HdWalletAccount {
            turnkey_wallet_id,
            wallet_account_id,
            address,
            derivation_path,
        } if turnkey_wallet_id == TURNKEY_WALLET_ID
            && wallet_account_id == TURNKEY_WALLET_ACCOUNT_ID
            && address == TURNKEY_ADDRESS
            && derivation_path == TURNKEY_DERIVATION_PATH
    );
    let valid_parent_organization = if operator_target {
        descriptor.turnkey_parent_organization_id == TURNKEY_PARENT_ORGANIZATION_ID
    } else {
        is_uuid(&descriptor.turnkey_parent_organization_id)
    };
    if descriptor.version != API_VERSION
        || !valid_parent_organization
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
    let descriptor_digest =
        descriptor_digest_from_wallet(descriptor).map_err(|_| OperationFailure::Invalid)?;
    let owner_evidence_digest = owner_auth_evidence_digest(
        &descriptor.owner_authorization_key,
        &descriptor.owner_authorization,
        &descriptor.prior_client_authorization,
    )
    .map_err(|_| OperationFailure::Invalid)?;
    let provisioning_digest = provisioning_auth_digest(&descriptor_digest, &owner_evidence_digest);
    verify_p256_prehash(
        &DEVELOPMENT_CLIENT_PUBLIC,
        &provisioning_digest,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| OperationFailure::Invalid)?;

    let grant = &descriptor.allowed_clients[0];
    let profile = if operator_target {
        if descriptor.turnkey_organization_id != TURNKEY_ORGANIZATION_ID
            || descriptor.turnkey_service_user_id != TURNKEY_SERVICE_USER_ID
            || descriptor.turnkey_api_key_id != TURNKEY_API_KEY_ID
            || descriptor.wallet_id != WALLET_ID
            || descriptor.expected_ed25519_public_key != EXPECTED_ED25519_PUBLIC_KEY
            || grant.client_key_id != CLIENT_KEY_ID
            || grant.client_public_key != DEVELOPMENT_CLIENT_PUBLIC
            || grant.allowed_operations
                != [
                    zolana_tvc_protocol::types::OperationKind::CreateWallet,
                    zolana_tvc_protocol::types::OperationKind::BootstrapEd25519,
                    zolana_tvc_protocol::types::OperationKind::PrepareWallet,
                    zolana_tvc_protocol::types::OperationKind::ShieldSol,
                    zolana_tvc_protocol::types::OperationKind::BuildTransfer,
                ]
        {
            return Err(OperationFailure::Invalid);
        }
        DescriptorProfile::Operator
    } else {
        let expected_wallet_id = format!("wallet-{turnkey_wallet_id}");
        let expected_client_key_id = format!(
            "{BROWSER_CLIENT_KEY_ID_PREFIX}{}",
            hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
        );
        if turnkey_wallet_id.is_empty()
            || turnkey_wallet_id.len() > 128
            || wallet_account_id.is_empty()
            || wallet_account_id.len() > 128
            || !is_uuid(&descriptor.turnkey_organization_id)
            || !is_uuid(&descriptor.turnkey_service_user_id)
            || !is_uuid(&descriptor.turnkey_api_key_id)
            || descriptor.wallet_id != expected_wallet_id
            || derivation_path != TURNKEY_DERIVATION_PATH
            || grant.client_key_id != expected_client_key_id
            || grant.client_public_key.len() != 65
            || grant.allowed_operations
                != [
                    zolana_tvc_protocol::types::OperationKind::BootstrapEd25519,
                    zolana_tvc_protocol::types::OperationKind::PrepareWallet,
                    zolana_tvc_protocol::types::OperationKind::ShieldSol,
                    zolana_tvc_protocol::types::OperationKind::BuildTransfer,
                ]
        {
            return Err(OperationFailure::Invalid);
        }
        DescriptorProfile::Browser
    };
    if grant.scheme != zolana_tvc_protocol::types::ClientAuthorizationScheme::P256Sha256
        || grant.may_rotate_descriptor
    {
        return Err(OperationFailure::Invalid);
    }

    Ok((
        profile,
        ValidatedWallet {
            organization_id: &descriptor.turnkey_organization_id,
            sign_with: address,
            address: address_pubkey,
            expected_ed25519_public_key: descriptor.expected_ed25519_public_key,
        },
    ))
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

async fn create_wallet(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if request.sealed_wallet_state.is_some()
        || request.expected_state_version.is_some()
        || request.expected_state_digest.is_some()
    {
        return Err(OperationFailure::Invalid);
    }
    let wallet_name = wallet_name(&request.request_id);
    let wallet_account_name = wallet_account_name(&request.request_id);
    let client = turnkey_client(keys)?;
    let activity = client
        .create_wallet(
            TURNKEY_ORGANIZATION_ID.to_owned(),
            u128::from(request.issued_at_ms),
            CreateWalletIntent {
                wallet_name: wallet_name.clone(),
                accounts: vec![WalletAccountParams {
                    curve: Curve::Ed25519,
                    path_format: PathFormat::Bip32,
                    path: TURNKEY_DERIVATION_PATH.to_owned(),
                    address_format: AddressFormat::Solana,
                    name: Some(wallet_account_name),
                }],
                mnemonic_length: Some(DEVELOPMENT_WALLET_MNEMONIC_LENGTH),
            },
        )
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::TurnkeyCreateWallet))?;
    if activity.app_proofs.is_empty()
        || activity.result.wallet_id.is_empty()
        || activity.result.addresses.len() != 1
        || Pubkey::from_str(&activity.result.addresses[0]).is_err()
    {
        return Err(OperationFailure::Unavailable);
    }
    let accounts = client
        .get_wallet_accounts(GetWalletAccountsRequest {
            organization_id: TURNKEY_ORGANIZATION_ID.to_owned(),
            wallet_id: Some(activity.result.wallet_id.clone()),
            include_wallet_details: Some(false),
            pagination_options: None,
        })
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::TurnkeyCreateWallet))?
        .accounts;
    if accounts.len() != 1 {
        return Err(OperationFailure::Unavailable);
    }
    let account = &accounts[0];
    let address = Pubkey::from_str(&account.address).map_err(|_| OperationFailure::Unavailable)?;
    let public_key = account
        .public_key
        .as_deref()
        .ok_or(OperationFailure::Unavailable)?;
    let public_key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))
        .map_err(|_| OperationFailure::Unavailable)?;
    if account.wallet_account_id.is_empty()
        || account.organization_id != TURNKEY_ORGANIZATION_ID
        || account.wallet_id != activity.result.wallet_id
        || account.curve != Curve::Ed25519
        || account.path_format != PathFormat::Bip32
        || account.path != TURNKEY_DERIVATION_PATH
        || account.address_format != AddressFormat::Solana
        || account.address != activity.result.addresses[0]
        || public_key.as_slice() != address.to_bytes()
    {
        return Err(OperationFailure::Unavailable);
    }
    Ok((
        OperationResultV1::CreateWallet {
            wallet_name,
            turnkey_wallet_id: activity.result.wallet_id.clone(),
            turnkey_wallet_account_id: account.wallet_account_id.clone(),
            solana_address: activity.result.addresses[0].clone(),
            derivation_path: TURNKEY_DERIVATION_PATH.to_owned(),
            turnkey_activity_id: activity.activity_id.clone(),
            turnkey_app_proofs: app_proofs(&activity),
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        [0; 32],
    ))
}

fn wallet_name(request_id: &[u8; 32]) -> String {
    format!("{WALLET_NAME_PREFIX}{}", hex::encode(&request_id[..8]))
}

fn wallet_account_name(request_id: &[u8; 32]) -> String {
    format!("solana-tvc-{}", hex::encode(&request_id[..8]))
}

async fn bootstrap(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
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
    let shielded_owner_hash = shielded_address
        .owner_hash()
        .map_err(|_| OperationFailure::Unavailable)?;
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    let inner = WalletStatePlaintextV1 {
        version: API_VERSION,
        quorum_key_id: request.quorum_key_id.clone(),
        quorum_key_epoch: request.quorum_key_epoch,
        wallet_id: request.wallet_descriptor.wallet_id.clone(),
        descriptor_digest,
        policy_version: request.wallet_descriptor.policy_version,
        state_version: 1,
        previous_state_digest: None,
        ed25519_public_key: wallet.expected_ed25519_public_key,
        derivation_suite: DERIVATION_SUITE.to_owned(),
        derivation_seed: *seed,
    };
    let (sealed, sealed_bytes, digest) = seal_state(keys, inner)?;
    debug_assert_eq!(sealed.state_version, 1);
    let turnkey_app_proofs = app_proofs(&activity);
    Ok((
        OperationResultV1::BootstrapEd25519 {
            solana_address: wallet.sign_with.to_owned(),
            shielded_owner_hash,
            shielded_nullifier_public_key: shielded_address.nullifier_pubkey,
            shielded_viewing_public_key: shielded_address.viewing_pubkey.as_bytes().to_vec(),
            sealed_wallet_state: sealed_bytes,
            state_version: 1,
            state_digest: digest,
            turnkey_activity_id: activity.activity_id,
            turnkey_app_proofs,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

async fn prepare_wallet(
    request: &OperationRequestV1,
    wallet: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    recent_blockhash: [u8; 32],
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if recent_blockhash == [0; 32] {
        return Err(OperationFailure::Invalid);
    }
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (sealed, inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let client = turnkey_client(keys)?;
    let activities: Arc<dyn TurnkeyActivities> =
        Arc::new(TurnkeyApiActivities::new(Arc::clone(&client)));
    let keypair = TurnkeyEd25519ShieldedKeypair::restore_from_seed(
        activities,
        TurnkeyKeyRef::new(wallet.organization_id, wallet.sign_with),
        inner.ed25519_public_key,
        &inner.derivation_seed,
    )
    .map_err(|_| OperationFailure::Invalid)?;
    let tree =
        Address::from_str(DEVELOPMENT_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = DevelopmentSolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        DEVELOPMENT_EXTERNAL_PHOTON_URL,
        DEVELOPMENT_EXTERNAL_PROVER_URL,
        tree,
    );
    let shielded_address = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    let mut registration =
        build_registration_transaction(&zolana, wallet.address, &shielded_address, None)
            .await
            .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::BuildRegistration))?
            .ok_or(OperationFailure::Development(
                DevelopmentFailureStage::BuildRegistration,
            ))?;
    registration.message.recent_blockhash = Hash::new_from_array(recent_blockhash);
    let signed = sign_transaction(&client, wallet, request.issued_at_ms, registration)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SignRegistration))?;
    let transaction_bytes =
        bincode1::serialize(&signed.result.0).map_err(|_| OperationFailure::Unavailable)?;
    if transaction_bytes.len() > 1_232 {
        return Err(OperationFailure::Unavailable);
    }
    Ok((
        OperationResultV1::PrepareWallet {
            signed_registration_transaction: transaction_bytes,
            registration_signature: signed.result.0.signatures[0].to_string(),
            registration_activity_id: signed.activity_id,
            registration_app_proofs: signed.result.1,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version: sealed.state_version,
            state_digest: digest,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

async fn build_transfer(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: &zolana_tvc_protocol::types::DevelopmentTransferIntentV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if intent.amount == 0 || intent.prover_profile_id != DEVELOPMENT_EXTERNAL_PROVER_PROFILE_ID {
        return Err(OperationFailure::Invalid);
    }
    let recipient = Pubkey::from_str(&intent.recipient).map_err(|_| OperationFailure::Invalid)?;
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (sealed, inner, digest) = unseal_state(request, keys, sealed_bytes)?;
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
    let owner = target.address;
    let tree =
        Address::from_str(DEVELOPMENT_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = DevelopmentSolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let (asset, asset_registry) = development_asset(&rpc, &intent.asset).await?;
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        DEVELOPMENT_EXTERNAL_PHOTON_URL,
        DEVELOPMENT_EXTERNAL_PROVER_URL,
        tree,
    );
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::new_from_array(owner.to_bytes()),
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
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SyncWallet))?;
    let shielded_balance_before = wallet
        .balance(asset, None)
        .map_err(|_| OperationFailure::Unavailable)?
        .amount;
    if shielded_balance_before < intent.amount {
        return Err(OperationFailure::Development(
            DevelopmentFailureStage::ShieldedBalanceNotReady,
        ));
    }
    let created = create_transfer(TransferParams {
        rpc: &zolana,
        wallet: &wallet,
        payer: Address::new_from_array(owner.to_bytes()),
        recipient,
        asset,
        amount: intent.amount,
    })
    .await
    .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::CreateTransfer))?;
    let shielded = sign_shielded_transaction(created.transaction, &wallet, &authority)
        .await
        .map_err(|_| {
            OperationFailure::Development(DevelopmentFailureStage::SignShieldedTransaction)
        })?;
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::LatestBlockhash))?;
    let unsigned = zolana
        .finish_submission_unsigned(&shielded, owner, blockhash)
        .await
        .map_err(|error| OperationFailure::Development(finish_submission_stage(&error)))?;
    let signed = sign_transaction(&client, target, request.issued_at_ms, unsigned)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SignTransaction))?;
    let signed_bytes =
        bincode1::serialize(&signed.result.0).map_err(|_| OperationFailure::Unavailable)?;
    if signed_bytes.len() > 1_232 {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = signed.result.0.signatures[0].to_string();
    let state_version = sealed.state_version;
    Ok((
        OperationResultV1::BuildTransfer {
            signed_transaction: signed_bytes,
            transaction_signature,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version,
            state_digest: digest,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs: signed.result.1,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

async fn shield_sol(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    amount: u64,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if amount == 0 || amount > MAX_SHIELD_SOL_LAMPORTS {
        return Err(OperationFailure::Invalid);
    }
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (sealed, inner, digest) = unseal_state(request, keys, sealed_bytes)?;
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
    let owner = target.address;
    let tree =
        Address::from_str(DEVELOPMENT_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = DevelopmentSolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        DEVELOPMENT_EXTERNAL_PHOTON_URL,
        DEVELOPMENT_EXTERNAL_PROVER_URL,
        tree,
    );
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::new_from_array(owner.to_bytes()),
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let mut private_wallet = Wallet::new(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        AssetRegistry::default(),
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    sync_wallet_async(&mut private_wallet, &authority, &zolana)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SyncWallet))?;
    let shielded_balance_before = private_wallet
        .balance(SOL_MINT, None)
        .map_err(|_| OperationFailure::Unavailable)?
        .amount;
    let owner_address = Address::new_from_array(owner.to_bytes());
    let public_balance_before = zolana.rpc().get_balance(owner_address).await.map_err(|_| {
        OperationFailure::Development(DevelopmentFailureStage::PublicBalanceNotReady)
    })?;
    if public_balance_before < amount.saturating_add(PUBLIC_SOL_FEE_RESERVE_LAMPORTS) {
        return Err(OperationFailure::Development(
            DevelopmentFailureStage::PublicBalanceNotReady,
        ));
    }
    let shielded_address = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    let deposit = create_deposit(DepositParams {
        recipient: &shielded_address,
        asset: SOL_MINT,
        amount,
        spl_token_account: None,
        spl_token_program: None,
        memo: Some(b"zolana-tvc-shield-sol-v1".to_vec()),
    })
    .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::CreateDeposit))?;
    let unsigned = deposit
        .build_transaction(
            zolana.rpc(),
            owner,
            Pubkey::new_from_array(tree.to_bytes()),
            owner,
        )
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::CreateDeposit))?;
    let signed = sign_transaction(&client, target, request.issued_at_ms, unsigned)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SignTransaction))?;
    let signed_bytes =
        bincode1::serialize(&signed.result.0).map_err(|_| OperationFailure::Unavailable)?;
    if signed_bytes.len() > 1_232 {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = signed.result.0.signatures[0].to_string();
    Ok((
        OperationResultV1::ShieldSol {
            signed_transaction: signed_bytes,
            transaction_signature,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version: sealed.state_version,
            state_digest: digest,
            public_balance_before,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs: signed.result.1,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

/// Closed SPL deposit from the descriptor-bound public wallet into its own
/// shielded identity.
///
/// Mirrors `shield_sol`, with three differences that SPL forces: the asset is
/// resolved through the shielded-pool registry rather than assumed, the token
/// program comes from the mint account's owner rather than being hardcoded, and
/// the public balance read is the associated token account's balance rather
/// than the native one.
async fn shield_spl(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    mint: &str,
    asset_id: u64,
    amount: u64,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if amount == 0 {
        return Err(OperationFailure::Invalid);
    }
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (sealed, inner, digest) = unseal_state(request, keys, sealed_bytes)?;
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
    let owner = target.address;
    let tree =
        Address::from_str(DEVELOPMENT_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
    let rpc = DevelopmentSolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
    let requested = DevelopmentAssetV1::Spl {
        mint: mint.to_owned(),
        asset_id,
    };
    let (asset, asset_registry) = development_asset(&rpc, &requested).await?;
    let mint_key = Pubkey::new_from_array(asset.to_bytes());
    let token_program = spl_token_program_for_mint(&rpc, &mint_key).await?;
    let user_token_account = pda::associated_token_address_with_program(
        &Pubkey::new_from_array(owner.to_bytes()),
        &mint_key,
        &token_program,
    );
    let zolana = ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        DEVELOPMENT_EXTERNAL_PHOTON_URL,
        DEVELOPMENT_EXTERNAL_PROVER_URL,
        tree,
    );
    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::new_from_array(owner.to_bytes()),
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let mut private_wallet = Wallet::new(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        asset_registry,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    sync_wallet_async(&mut private_wallet, &authority, &zolana)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SyncWallet))?;
    let shielded_balance_before = private_wallet
        .balance(asset, None)
        .map_err(|_| OperationFailure::Unavailable)?
        .amount;
    let public_balance_before = spl_token_account_amount(
        &zolana,
        Address::new_from_array(user_token_account.to_bytes()),
    )
    .await?;
    if public_balance_before < amount {
        return Err(OperationFailure::Development(
            DevelopmentFailureStage::PublicBalanceNotReady,
        ));
    }
    let shielded_address = keypair
        .shielded_address()
        .map_err(|_| OperationFailure::Unavailable)?;
    let deposit = create_deposit(DepositParams {
        recipient: &shielded_address,
        asset,
        amount,
        spl_token_account: Some(user_token_account),
        spl_token_program: Some(token_program),
        memo: Some(b"zolana-tvc-shield-spl-v1".to_vec()),
    })
    .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::CreateDeposit))?;
    let unsigned = deposit
        .build_transaction(
            zolana.rpc(),
            owner,
            Pubkey::new_from_array(tree.to_bytes()),
            owner,
        )
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::CreateDeposit))?;
    let signed = sign_transaction(&client, target, request.issued_at_ms, unsigned)
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::SignTransaction))?;
    let signed_bytes =
        bincode1::serialize(&signed.result.0).map_err(|_| OperationFailure::Unavailable)?;
    if signed_bytes.len() > 1_232 {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = signed.result.0.signatures[0].to_string();
    Ok((
        OperationResultV1::ShieldSpl {
            signed_transaction: signed_bytes,
            transaction_signature,
            sealed_wallet_state: sealed_bytes.to_vec(),
            state_version: sealed.state_version,
            state_digest: digest,
            mint: mint_key.to_string(),
            asset_id,
            public_balance_before,
            shielded_balance_before,
            turnkey_activity_id: signed.activity_id,
            turnkey_app_proofs: signed.result.1,
            evidence_classification:
                TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
        },
        digest,
    ))
}

/// Reads the token program from the mint account's owner rather than trusting
/// the caller, so a deposit cannot be routed through an unexpected program.
async fn spl_token_program_for_mint(
    rpc: &DevelopmentSolanaRpc,
    mint: &Pubkey,
) -> Result<Pubkey, OperationFailure> {
    let account = rpc
        .get_account(Address::new_from_array(mint.to_bytes()))
        .await
        .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::ResolveAsset))?
        .ok_or(OperationFailure::Invalid)?;
    let owner = Pubkey::new_from_array(account.owner.to_bytes());
    if owner == pda::spl_token_program_id() || owner == pda::spl_token_2022_program_id() {
        Ok(owner)
    } else {
        Err(OperationFailure::Invalid)
    }
}

/// SPL token-account balance, read from the account the deposit will debit.
async fn spl_token_account_amount(
    zolana: &ZolanaClient<DevelopmentSolanaRpc>,
    token_account: Address,
) -> Result<u64, OperationFailure> {
    let account = zolana
        .rpc()
        .get_account(token_account)
        .await
        .map_err(|_| {
            OperationFailure::Development(DevelopmentFailureStage::PublicBalanceNotReady)
        })?
        .ok_or(OperationFailure::Development(
            DevelopmentFailureStage::PublicBalanceNotReady,
        ))?;
    // SPL token account layout: mint(32) ‖ owner(32) ‖ amount(u64 LE).
    let amount = account
        .data
        .get(64..72)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_le_bytes)
        .ok_or(OperationFailure::Development(
            DevelopmentFailureStage::PublicBalanceNotReady,
        ))?;
    Ok(amount)
}

async fn development_asset(
    rpc: &DevelopmentSolanaRpc,
    requested: &DevelopmentAssetV1,
) -> Result<(Address, AssetRegistry), OperationFailure> {
    match requested {
        DevelopmentAssetV1::Sol => Ok((SOL_MINT, AssetRegistry::default())),
        DevelopmentAssetV1::Spl { mint, asset_id } => {
            if *asset_id <= 1 {
                return Err(OperationFailure::Invalid);
            }
            let mint = Pubkey::from_str(mint).map_err(|_| OperationFailure::Invalid)?;
            let registry_address = pda::spl_asset_registry(&mint);
            let account = rpc
                .get_account(Address::new_from_array(registry_address.to_bytes()))
                .await
                .map_err(|_| OperationFailure::Development(DevelopmentFailureStage::ResolveAsset))?
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

fn finish_submission_stage(error: &ClientError) -> DevelopmentFailureStage {
    match error {
        ClientError::Indexer(_)
        | ClientError::IndexerUnavailable(_)
        | ClientError::UnsupportedRpcMethod(_)
        | ClientError::IndexerNotCaughtUp { .. }
        | ClientError::IncompleteInputProofs { .. }
        | ClientError::StateProofLeafMismatch { .. }
        | ClientError::StateProofTreeMismatch { .. }
        | ClientError::NullifierProofLeafMismatch { .. }
        | ClientError::NullifierProofTreeMismatch { .. } => DevelopmentFailureStage::IndexerProofs,
        ClientError::MissingInputMerkleProof { .. }
        | ClientError::ProofPathLength { .. }
        | ClientError::WitnessInputCountMismatch { .. }
        | ClientError::InputTreeIndexCountMismatch { .. } => DevelopmentFailureStage::ProofAssembly,
        ClientError::ProverServer(_) | ClientError::ProofParse(_) | ClientError::Prover(_) => {
            DevelopmentFailureStage::ExternalProver
        }
        ClientError::ProofVerification(_) => DevelopmentFailureStage::LocalProofVerification,
        _ => DevelopmentFailureStage::FinishSubmission,
    }
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
    let proofs = activity.app_proofs.iter().map(convert_app_proof).collect();
    Ok(ActivityResult {
        result: (signed, proofs),
        activity_id: activity.activity_id,
        status: activity.status,
        app_proofs: activity.app_proofs,
    })
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

fn seal_state(
    keys: &RuntimeKeys,
    inner: WalletStatePlaintextV1,
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

fn unseal_state(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    sealed_bytes: &[u8],
) -> Result<(SealedWalletStateV1, WalletStatePlaintextV1, [u8; 32]), OperationFailure> {
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
    let inner = WalletStatePlaintextV1::try_from_slice(&plaintext)
        .map_err(|_| OperationFailure::Invalid)?;
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id
        || inner.descriptor_digest != descriptor_digest
        || inner.policy_version != request.wallet_descriptor.policy_version
        || inner.state_version != sealed.state_version
        || inner.previous_state_digest != sealed.previous_state_digest
        || inner.ed25519_public_key != request.wallet_descriptor.expected_ed25519_public_key
        || inner.derivation_suite != DERIVATION_SUITE
    {
        return Err(OperationFailure::Invalid);
    }
    Ok((sealed, inner, digest))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_name_is_fixed_and_request_bound() {
        assert_eq!(wallet_name(&[0xab; 32]), "zolana-tvc-abababababababab");
        assert_eq!(wallet_name(&[0xab; 32]).len(), 27);
        assert_eq!(
            wallet_account_name(&[0xab; 32]),
            "solana-tvc-abababababababab"
        );
        assert_eq!(wallet_account_name(&[0xab; 32]).len(), 27);
    }

    #[test]
    fn dynamic_descriptor_ids_must_be_lowercase_uuids() {
        assert!(is_uuid("a7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("A7db47e5-baca-41df-9c5a-e1ca746e6c37"));
        assert!(!is_uuid("a7db47e5baca41df9c5ae1ca746e6c37"));
        assert!(!is_uuid("../../wallet-organization"));
    }

    #[test]
    fn dynamic_parent_org_may_differ_from_the_operator_parent() {
        let embedded_wallet_parent = "c8563ee7-3949-410c-b013-44bc0a041040";
        assert!(is_uuid(embedded_wallet_parent));
        assert_ne!(embedded_wallet_parent, TURNKEY_PARENT_ORGANIZATION_ID);
    }
}
