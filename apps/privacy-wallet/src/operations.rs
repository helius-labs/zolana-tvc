//! Encrypted operations for the privacy wallet's keyholder security model.
//!
//! This service is a stateless oracle for the wallet's privacy keys. It holds
//! the derivation seed only for the duration of one request, unsealed from a
//! blob the client presents and stores nothing across requests. The client
//! relays ciphertext discovery; TVC performs the nullifier-aware reconciliation
//! used by balance snapshots and spend construction. A disposable development
//! spend also sends a plaintext witness to the pinned prover before signing.
//!
//! Only bootstrap and transaction authorization reach Turnkey. `DeriveViewTags`
//! and `DecryptUtxos` derive everything they need from the unsealed seed, so
//! neither reaches Turnkey. A requested spendable-output snapshot makes the
//! same pinned chain/indexer calls used by spend authorization.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use solana_message::v0::LoadedAddresses;
use solana_message::{v0, AccountKeys, AddressLookupTableAccount, Message, VersionedMessage};
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
    MergeProver, MergeWitness, ProofCompressed, ProverInputs, SpendProof, SppProofInputUtxo,
    ZolanaClient,
};
use zolana_interface::{
    instruction::{
        instruction_data::transact::MessageData, MergeTransact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
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
use zolana_transaction::instructions::merge::{Merge, MERGE_INPUTS};
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
    MAX_DECRYPT_PAYLOADS_PER_BATCH, MAX_REQUEST_AGE_MS, MAX_SPENDABLE_OUTPUTS,
    TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{parse_uncompressed_sec1, qos_encrypt, verify_p256_prehash};
use zolana_tvc_protocol::digest::{
    artifact_digest, descriptor_digest_from_wallet, request_digest, result_digest, state_digest,
    wallet_id_hash,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, AssetV1, AuthorizeSpendRequestV1,
    AuthorizeSpendResultV1, DecryptedPayloadV1, EncryptedPayloadV1, EncryptedResponseV1,
    Environment, FailureStage, OperationKind, OperationRequestV1, OperationResultV1, OperationV1,
    PreparedSpendV1, PrivateDomainV1, SealedSpendAuthorizationV1, SealedWalletStateV1,
    SpendIntentV1, SpendPlanV1, SpendSettlementV1, SpendableOutputV1, SppPlanInputV1, SppPlanV1,
    TurnkeyEvidenceClassification, TurnkeyVerifiedAppProofV1, TvcAppProofV1,
    TvcOperationProofPayloadV1,
};
use zolana_tvc_protocol::{public_http_error, PublicError};
use zolana_user_registry_interface::user_record_pda;
use zolana_wallet::{
    create_transfer, create_withdrawal, sign_shielded_transaction, sync_wallet_with_config_async,
    try_resolve_registered_address_async, ClientEd25519WalletAuthority, KeypairWalletAuthority,
    SyncWalletConfig, TransferParams, WithdrawalLeg, WithdrawalParams,
};

use crate::solana_rpc::SolanaRpc;
use crate::turnkey::QosTurnkeyStamper;
use crate::{into_response, sign_ephemeral_low_s, AppState, RuntimeKeys};

const BROWSER_CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
const MAX_SOLANA_TRANSACTION_BYTES: usize = 1_232;
const MAX_GENERIC_ACCOUNTS: usize = 64;
const MAX_GENERIC_LOOKUP_TABLES: usize = 4;
const MAX_GENERIC_INSTRUCTION_BYTES: usize = 8_192;
const MAX_GENERIC_DATA_BYTES: usize = 4_096;
const MAX_GENERIC_MESSAGES: usize = 8;
const MAX_GENERIC_PROGRAM_AUTHORITIES: usize = 8;
const SNAPSHOT_NULLIFIER_CHUNK: usize = 64;
const SNAPSHOT_PAGE_LIMIT: u32 = 1_000;
const WALLET_SYNC_TIMEOUT: Duration = Duration::from_secs(60);
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
    parse_uncompressed_sec1(&request.client_response_public_key)
        .map_err(|_| OperationFailure::Invalid)?;

    // Every result carries the digest of the sealed state it was computed
    // against, so the App Proof binds the answer to one specific key state
    // rather than merely to the request.
    let (result, proof_state_digest) = match &request.operation {
        OperationV1::BootstrapKeyholder => bootstrap_keyholder(&request, &wallet, keys).await?,
        OperationV1::DeriveViewTags => derive_view_tags(&request, keys)?,
        OperationV1::DecryptUtxos {
            payloads,
            include_spendable_outputs,
        } => match decrypt_utxos(
            &request,
            &wallet,
            keys,
            payloads,
            *include_spendable_outputs,
        )
        .await
        {
            Ok(result) => result,
            Err(OperationFailure::Failed(stage)) => (
                OperationResultV1::Failure {
                    operation: request.operation.kind(),
                    stage,
                },
                request
                    .sealed_wallet_state
                    .as_deref()
                    .map(state_digest)
                    .unwrap_or([0; 32]),
            ),
            Err(error) => return Err(error),
        },
        OperationV1::AuthorizeSpend { spend } => {
            match authorize_spend(&request, &wallet, spend, keys).await {
                Ok(result) => result,
                Err(OperationFailure::Failed(stage)) => (
                    OperationResultV1::Failure {
                        operation: request.operation.kind(),
                        stage,
                    },
                    request
                        .sealed_wallet_state
                        .as_deref()
                        .map(state_digest)
                        .unwrap_or([0; 32]),
                ),
                Err(error) => return Err(error),
            }
        }
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| OperationFailure::Unavailable)?);
    let encrypted_result = qos_encrypt(
        &request.client_response_public_key,
        result_plaintext.as_bytes(),
    )
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
        .first()
        .ok_or(OperationFailure::Invalid)?;
    let expected_client_key_id = format!(
        "{BROWSER_CLIENT_KEY_ID_PREFIX}{}",
        hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
    );
    if request.authorization.client_key_id != expected_client_key_id {
        return Err(OperationFailure::Invalid);
    }
    zolana_tvc_protocol::verify_client_authorization(request, &grant.client_public_key)
        .map_err(|_| OperationFailure::Invalid)?;
    if !grant.allowed_operations.contains(&request.operation.kind()) {
        return Err(OperationFailure::Invalid);
    }
    Ok(wallet)
}

/// Oracle operations answer against a presented sealed key state; bootstrap
/// must stay independent of caller-selected state.
fn operation_state_fields_are_valid(request: &OperationRequestV1) -> bool {
    match &request.operation {
        OperationV1::BootstrapKeyholder => request.sealed_wallet_state.is_none(),
        OperationV1::DeriveViewTags
        | OperationV1::DecryptUtxos { .. }
        | OperationV1::AuthorizeSpend { .. } => request.sealed_wallet_state.is_some(),
    }
}

fn validate_descriptor(
    request: &OperationRequestV1,
) -> Result<ValidatedWallet<'_>, OperationFailure> {
    let descriptor = &request.wallet_descriptor;
    let address_pubkey =
        Pubkey::from_str(&descriptor.address).map_err(|_| OperationFailure::Invalid)?;
    if descriptor.version != API_VERSION
        || !is_uuid(&descriptor.turnkey_organization_id)
        || descriptor.turnkey_wallet_id.is_empty()
        || descriptor.turnkey_wallet_id.len() > 128
        || descriptor.environment != Environment::Development
        || descriptor.allowed_clients.len() != 1
    {
        return Err(OperationFailure::Invalid);
    }

    let descriptor_hash =
        descriptor_digest_from_wallet(descriptor).map_err(|_| OperationFailure::Invalid)?;
    verify_p256_prehash(
        &PROVISIONING_PUBLIC,
        &descriptor_hash,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| OperationFailure::Invalid)?;

    let grant = descriptor
        .allowed_clients
        .first()
        .ok_or(OperationFailure::Invalid)?;
    if grant.client_public_key.len() != 65 || grant.allowed_operations != KEYHOLDER_OPERATIONS {
        return Err(OperationFailure::Invalid);
    }

    Ok(ValidatedWallet {
        organization_id: &descriptor.turnkey_organization_id,
        sign_with: &descriptor.address,
        address: address_pubkey,
        expected_ed25519_public_key: address_pubkey.to_bytes(),
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
/// direct transaction or one exact program SPP transition, plus all ambient
/// authority that made preparation valid. Finalization is stateless: the
/// caller stores and returns the sealed capsule but cannot alter these fields.
#[derive(BorshSerialize, BorshDeserialize)]
struct SpendAuthorizationPlaintextV1 {
    version: u8,
    quorum_key_id: String,
    quorum_key_epoch: u64,
    wallet_id: String,
    descriptor_digest: [u8; 32],
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
    if request.sealed_wallet_state.is_some() {
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
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest: descriptor_hash,
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
    // indexer's nullifier stream and the fresh wallet may select that UTXO
    // again. SPP then rejects the duplicate nullifier on chain as 7002.
    tokio::time::timeout(WALLET_SYNC_TIMEOUT, async {
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
        .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))
    })
    .await
    .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))??;
    Ok(wallet)
}

/// Reads the latest internally consistent snapshot already available from the
/// private index.
///
/// Balance display must not require the index to have reached a separately
/// sampled Solana RPC slot. A small, normal indexing delay would otherwise
/// turn a read-only refresh into a hard failure. Spend preparation continues
/// to use `synced_wallet`, whose chain-tip gate prevents selection of a UTXO
/// that has already been spent on chain but is not indexed yet.
async fn indexed_wallet_snapshot<A: WalletAuthority + ?Sized>(
    owner: ShieldedAddress,
    authority: &A,
    zolana: &ZolanaClient<SolanaRpc>,
) -> Result<Wallet, OperationFailure> {
    // Ring deposits publish the mint address directly, so decoding them does
    // not produce the `unknown_asset_ids` signal used by the SDK's lazy
    // registry refresh. Load the small canonical pool registry up front so
    // both ring deposits and compact-id confidential outputs have the same
    // complete, chain-derived mapping.
    let accounts = zolana
        .rpc()
        .get_program_accounts(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID))
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?;
    let assets = AssetRegistry::new(accounts.into_iter().filter_map(|(_, account)| {
        SplAssetRegistry::from_account_bytes(&account.data)
            .ok()
            .map(|registry| (registry.asset_id, registry.mint))
    }))
    .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?;
    let mut wallet = Wallet::new(owner, assets).map_err(|_| OperationFailure::Unavailable)?;
    tokio::time::timeout(WALLET_SYNC_TIMEOUT, async {
        // Balance display needs owned outputs, not the wallet's complete
        // counterparty history. With a fresh wallet and a zero tag window the
        // first round queries exactly the two stable discovery tags: the
        // Ed25519 owner tag and the viewing-key bootstrap tag. Expanding every
        // historical sender/recipient window on every stateless refresh made
        // read cost grow with transaction history and eventually timed out.
        sync_wallet_with_config_async(
            &mut wallet,
            authority,
            zolana,
            SyncWalletConfig {
                tag_window: 0,
                rounds: 1,
                ..SyncWalletConfig::default()
            },
        )
        .await
        .map_err(|error| {
            OperationFailure::Failed(match error {
                ClientError::Transaction(_) | ClientError::Keypair(_) | ClientError::Hasher(_) => {
                    FailureStage::WalletReconstruction
                }
                _ => FailureStage::WalletIndexRead,
            })
        })?;

        // The one bounded discovery round computes nullifiers inside TVC but
        // cannot observe a spend with no self-owned change output. Reconcile
        // those nullifiers directly against the pinned index. A nullifier is
        // used at most once, so chunks never need to replay wallet history.
        let candidates = wallet
            .utxos
            .iter()
            .filter(|entry| !entry.spent)
            .map(|entry| entry.nullifier)
            .collect::<Vec<_>>();
        let mut spent = HashSet::new();
        for chunk in candidates.chunks(SNAPSHOT_NULLIFIER_CHUNK) {
            let mut cursor = None;
            loop {
                let response = zolana
                    .get_shielded_transactions_by_nullifiers(
                        chunk.to_vec(),
                        cursor,
                        Some(SNAPSHOT_PAGE_LIMIT),
                        None,
                    )
                    .await
                    .map_err(|_| OperationFailure::Failed(FailureStage::WalletNullifierRead))?;
                for transaction in response.transactions {
                    spent.extend(transaction.nullifiers);
                }
                let Some(next) = response.next_cursor else {
                    break;
                };
                cursor = Some(next);
            }
        }
        for entry in &mut wallet.utxos {
            entry.spent |= spent.contains(&entry.nullifier);
        }
        Ok::<(), OperationFailure>(())
    })
    .await
    .map_err(|_| OperationFailure::Failed(FailureStage::WalletSync))??;
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
async fn decrypt_utxos(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    keys: &RuntimeKeys,
    payloads: &[EncryptedPayloadV1],
    include_spendable_outputs: bool,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    if (payloads.is_empty() && !include_spendable_outputs)
        || payloads.len() as u64 > MAX_DECRYPT_PAYLOADS_PER_BATCH
    {
        return Err(OperationFailure::Invalid);
    }
    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, digest) = unseal_state(request, keys, sealed_bytes)?;
    let (_nullifier_key, viewing_key) =
        derivation::expand_roles(&inner.derivation_seed, Curve::Ed25519)
            .map_err(|_| OperationFailure::Invalid)?;

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
    let spendable_outputs = if include_spendable_outputs {
        let payer = Address::new_from_array(target.address.to_bytes());
        let authority =
            ClientEd25519WalletAuthority::from_derivation_seed(payer, &inner.derivation_seed)
                .map_err(|_| OperationFailure::Invalid)?;
        let tree =
            Address::from_str(DEVNET_DEFAULT_TREE).map_err(|_| OperationFailure::Unavailable)?;
        let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
        let zolana = ZolanaClient::from_urls_allowing_insecure_http(
            rpc,
            EXPECTED_EXTERNAL_ORIGIN,
            EXPECTED_EXTERNAL_ORIGIN,
            tree,
        );
        let wallet = indexed_wallet_snapshot(
            authority
                .shielded_address()
                .await
                .map_err(|_| OperationFailure::Unavailable)?,
            &authority,
            &zolana,
        )
        .await?;
        let mut outputs = wallet
            .utxos
            .iter()
            .filter(|entry| !entry.spent)
            .map(|entry| {
                let asset = if entry.utxo.asset == SOL_MINT {
                    AssetV1::Sol
                } else {
                    AssetV1::Spl {
                        mint: entry.utxo.asset.to_string(),
                        asset_id: wallet
                            .registry
                            .asset_id(&entry.utxo.asset)
                            .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?,
                    }
                };
                Ok(SpendableOutputV1 {
                    commitment: entry.output_context.hash,
                    asset,
                    amount: entry.utxo.amount,
                    ring_program_id: entry.utxo.ring_program_id.map(|id| id.to_string()),
                })
            })
            .collect::<Result<Vec<_>, OperationFailure>>()?;
        if outputs.len() as u64 > MAX_SPENDABLE_OUTPUTS {
            return Err(OperationFailure::Failed(
                FailureStage::WalletSnapshotTooLarge,
            ));
        }
        outputs.sort_unstable_by_key(|output| output.commitment);
        Some(outputs)
    } else {
        None
    };

    Ok((
        OperationResultV1::DecryptUtxos {
            payloads: results,
            spendable_outputs,
        },
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
        ciphertext,
    };
    let bytes = borsh::to_vec(&sealed).map_err(|_| OperationFailure::Unavailable)?;
    let digest = state_digest(&bytes);
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
    let digest = state_digest(sealed_bytes);
    if sealed.version != API_VERSION
        || sealed.quorum_key_id != request.quorum_key_id
        || sealed.quorum_key_epoch != request.quorum_key_epoch
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id())
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
    let expected_ed25519 = Pubkey::from_str(&request.wallet_descriptor.address)
        .map_err(|_| OperationFailure::Invalid)?
        .to_bytes();
    if inner.version != API_VERSION
        || inner.quorum_key_id != sealed.quorum_key_id
        || inner.quorum_key_epoch != sealed.quorum_key_epoch
        || inner.wallet_id != request.wallet_descriptor.wallet_id()
        || inner.descriptor_digest != descriptor_hash
        || inner.ed25519_public_key != expected_ed25519
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
        || sealed.wallet_id_hash != wallet_id_hash(&request.wallet_descriptor.wallet_id())
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
        || inner.wallet_id != request.wallet_descriptor.wallet_id()
        || inner.descriptor_digest != descriptor_hash
        || inner.state_digest != state_digest_bytes
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

/// The one spend authority exposed by the enclave. Prepare proves and seals an
/// exact unsigned transaction; finalize independently revalidates the capsule
/// and transaction before invoking Turnkey once. There is no one-call protocol
/// variant.
///
/// The development implementation performs pinned Photon, Solana RPC, and
/// prover calls inside this operation. Its common prover still receives the
/// plaintext witness, including the long-lived nullifier secret; this boundary
/// must change before a production privacy claim.
async fn authorize_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    spend: &AuthorizeSpendRequestV1,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    match spend {
        AuthorizeSpendRequestV1::Prepare { plan } => match plan {
            SpendPlanV1::Direct { transition } => {
                let prepared = prepare_direct_spend(request, target, transition, keys).await?;
                prepared_direct_spend_result(request, keys, prepared)
            }
            SpendPlanV1::Program { transition } => {
                let prepared = prepare_generic_spp(request, target, transition, keys).await?;
                prepared_generic_spend_result(request, keys, prepared)
            }
        },
        AuthorizeSpendRequestV1::Finalize {
            sealed_authorization_capsule,
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
    }
}

struct PreparedDirectSpend {
    unsigned: VersionedTransaction,
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
    state_digest: [u8; 32],
    shielded_balance_before: u64,
    expires_at_ms: u64,
}

struct AuthorizedSpend {
    signed_transaction: Vec<u8>,
    transaction_signature: String,
    shielded_balance_before: u64,
    turnkey_activity_id: String,
    turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
    evidence_classification: TurnkeyEvidenceClassification,
}

fn domain_ring(domain: &PrivateDomainV1) -> Option<(&str, &str)> {
    match domain {
        PrivateDomainV1::Default => None,
        PrivateDomainV1::Ring {
            program_id,
            lookup_table,
        } => Some((program_id, lookup_table)),
    }
}

/// Returns the one custom-ring boundary involved in a direct transition.
/// Direct Ring(A) -> Ring(B) is intentionally impossible: the wallet composes
/// two independent transitions through an exact self-owned default UTXO.
fn transaction_ring(intent: &SpendIntentV1) -> Result<Option<(&str, &str)>, OperationFailure> {
    let source = domain_ring(&intent.source);
    let destination = match &intent.settlement {
        SpendSettlementV1::Transfer { destination, .. } => domain_ring(destination),
        SpendSettlementV1::Withdrawal { .. } | SpendSettlementV1::Consolidate { .. } => None,
    };
    match (source, destination) {
        (Some(source), Some(destination)) if source != destination => {
            Err(OperationFailure::Invalid)
        }
        (Some(ring), _) | (_, Some(ring)) => Ok(Some(ring)),
        (None, None) => Ok(None),
    }
}

/// Builds and proves the existing default/custom-ring spend, but deliberately
/// stops before the only billable Turnkey transaction-signing activity.
async fn prepare_direct_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    intent: &SpendIntentV1,
    keys: &RuntimeKeys,
) -> Result<PreparedDirectSpend, OperationFailure> {
    let (recipient, amount) = match &intent.settlement {
        SpendSettlementV1::Transfer {
            recipient, amount, ..
        }
        | SpendSettlementV1::Withdrawal {
            recipient, amount, ..
        } => (Some(recipient.as_str()), Some(*amount)),
        SpendSettlementV1::Consolidate { .. } => (None, None),
    };
    if amount == Some(0) {
        return Err(OperationFailure::Invalid);
    }
    let consolidates = matches!(&intent.settlement, SpendSettlementV1::Consolidate { .. });
    if consolidates && !matches!(intent.source, PrivateDomainV1::Default) {
        return Err(OperationFailure::Invalid);
    }
    let transaction_ring = transaction_ring(intent)?;
    let enters_ring = matches!(intent.source, PrivateDomainV1::Default)
        && matches!(
            intent.settlement,
            SpendSettlementV1::Transfer {
                destination: PrivateDomainV1::Ring { .. },
                ..
            }
        );
    if (enters_ring && intent.input_commitments.is_empty())
        || (!enters_ring && !intent.input_commitments.is_empty())
    {
        return Err(OperationFailure::Invalid);
    }
    let recipient = recipient
        .map(Pubkey::from_str)
        .transpose()
        .map_err(|_| OperationFailure::Invalid)?;
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
        SpendSettlementV1::Transfer { asset, .. }
        | SpendSettlementV1::Withdrawal { asset, .. }
        | SpendSettlementV1::Consolidate { asset } => resolve_asset(&rpc, asset).await?,
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
    let selected_ring = match &intent.source {
        PrivateDomainV1::Default => None,
        PrivateDomainV1::Ring { program_id, .. } => {
            Some(Address::from_str(program_id).map_err(|_| OperationFailure::Invalid)?)
        }
    };
    let shielded_balance_before = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent && entry.utxo.asset == asset && entry.utxo.ring_program_id == selected_ring
        })
        .fold(0u64, |total, entry| total.saturating_add(entry.utxo.amount));

    let unsigned = if consolidates {
        build_merge_transaction(&keypair, &wallet, &zolana, payer, asset, tree).await?
    } else if transaction_ring.is_some() {
        let prover = AsyncProverClient::new(EXPECTED_CUSTOM_RING_PROVER_ORIGIN.to_owned());
        build_ring_transaction(
            intent,
            amount.ok_or(OperationFailure::Invalid)?,
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
                recipient: recipient.ok_or(OperationFailure::Invalid)?,
            },
        )
        .await?
    } else {
        prioritize_default_spend_inputs(&mut wallet, asset);
        build_default_transaction(
            intent,
            amount.ok_or(OperationFailure::Invalid)?,
            DefaultSpendContext {
                wallet: &wallet,
                authority: &authority,
                zolana: &zolana,
                payer,
                recipient: recipient.ok_or(OperationFailure::Invalid)?,
                asset,
            },
        )
        .await?
    };
    Ok(PreparedDirectSpend {
        unsigned,
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
    if plan.inputs.is_empty()
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

fn prepared_direct_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedDirectSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let unsigned_transaction =
        bincode1::serialize(&prepared.unsigned).map_err(|_| OperationFailure::Unavailable)?;
    if unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_digest = artifact_digest(&unsigned_transaction);
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
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest,
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
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    let sealed_authorization_capsule = seal_spend_authorization(
        keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest,
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
    if unsigned_transaction.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Invalid);
    }
    let mut unsigned: VersionedTransaction =
        bincode1::deserialize(unsigned_transaction).map_err(|_| OperationFailure::Invalid)?;
    if bincode1::serialize(&unsigned).map_err(|_| OperationFailure::Invalid)?
        != unsigned_transaction
        || unsigned.signatures.as_slice() != [Signature::default()]
        || unsigned.message.sanitize().is_err()
        || unsigned.message.header().num_required_signatures != 1
        || unsigned.message.static_account_keys().first().copied()
            != Some(Address::new_from_array(target.address.to_bytes()))
    {
        return Err(OperationFailure::Invalid);
    }
    let shielded_balance_before = authorization.shielded_balance_before;
    match authorization.artifact {
        SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest } => {
            // A direct capsule commits to every byte, including its blockhash.
            if artifact_digest(unsigned_transaction) != transaction_digest {
                return Err(OperationFailure::Invalid);
            }
        }
        SpendAuthorizationArtifactV1::Spp {
            program_id,
            input_tree,
            program_authorities,
            plan_digest: _,
            prepared_transact,
            transact_digest,
            private_tx_hash,
        } => {
            if prepared_transact.is_empty()
                || artifact_digest(&prepared_transact) != transact_digest
                || !prepared_transact
                    .windows(private_tx_hash.len())
                    .any(|window| window == private_tx_hash)
            {
                return Err(OperationFailure::Invalid);
            }
            let rpc = SolanaRpc::new().map_err(|_| OperationFailure::Unavailable)?;
            validate_private_program_transaction(
                &rpc,
                Address::new_from_array(target.address.to_bytes()),
                Address::new_from_array(program_id),
                Address::new_from_array(input_tree),
                &program_authorities,
                private_tx_hash,
                &mut unsigned,
            )
            .await?;
        }
    }
    if bincode1::serialize(&unsigned)
        .map_err(|_| OperationFailure::Unavailable)?
        .len()
        > MAX_SOLANA_TRANSACTION_BYTES
    {
        return Err(OperationFailure::Invalid);
    }
    let client = turnkey_client(keys)?;
    let signed =
        sign_versioned_transaction(&client, target, request.issued_at_ms, unsigned).await?;
    let authorized = authorized_spend(signed, shielded_balance_before)?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Finalize {
                signed_transaction: authorized.signed_transaction,
                transaction_signature: authorized.transaction_signature,
                shielded_balance_before: authorized.shielded_balance_before,
                turnkey_activity_id: authorized.turnkey_activity_id,
                turnkey_app_proofs: authorized.turnkey_app_proofs,
                evidence_classification: authorized.evidence_classification,
            },
        },
        state_digest_bytes,
    ))
}

async fn validate_private_program_transaction(
    rpc: &SolanaRpc,
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    unsigned: &mut VersionedTransaction,
) -> Result<(), OperationFailure> {
    if reserved_signer_program(authorized_program) {
        return Err(OperationFailure::Invalid);
    }
    let program_account = rpc
        .get_account(authorized_program)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    if !program_account.executable {
        return Err(OperationFailure::Invalid);
    }

    let loaded = load_transaction_addresses(rpc, &unsigned.message).await?;
    validate_private_program_message(
        payer,
        authorized_program,
        authorized_tree,
        authorized_program_accounts,
        private_tx_hash,
        &unsigned.message,
        &loaded,
    )?;
    let shielded_pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let tree = rpc
        .get_account(authorized_tree)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    let pool = rpc
        .get_account(shielded_pool)
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::RpcValidation))?
        .ok_or(OperationFailure::Invalid)?;
    if tree.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID || !pool.executable {
        return Err(OperationFailure::Invalid);
    }

    // The caller approves the instruction set; TVC supplies only transaction
    // freshness. Program-specific proofs bind private effects to the prepared
    // hash, while any additional public behavior follows normal wallet trust.
    let (blockhash, _) = rpc
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    unsigned.message.set_recent_blockhash(blockhash);
    Ok(())
}

fn validate_private_program_message(
    payer: Address,
    authorized_program: Address,
    authorized_tree: Address,
    authorized_program_accounts: &[[u8; 32]],
    private_tx_hash: [u8; 32],
    message: &VersionedMessage,
    loaded: &LoadedAddresses,
) -> Result<(), OperationFailure> {
    if reserved_signer_program(authorized_program) {
        return Err(OperationFailure::Invalid);
    }
    let account_keys = AccountKeys::new(message.static_account_keys(), Some(loaded));
    let hash_occurrences = message
        .instructions()
        .iter()
        .map(|instruction| {
            instruction
                .data
                .windows(private_tx_hash.len())
                .filter(|window| *window == private_tx_hash)
                .count()
        })
        .sum::<usize>();
    if hash_occurrences != 1 {
        return Err(OperationFailure::Invalid);
    }
    let binding = message
        .instructions()
        .iter()
        .find(|instruction| {
            account_keys
                .get(usize::from(instruction.program_id_index))
                .is_some_and(|program_id| *program_id == authorized_program)
                && instruction
                    .data
                    .windows(private_tx_hash.len())
                    .any(|window| window == private_tx_hash)
        })
        .ok_or(OperationFailure::Invalid)?;
    if binding.accounts.is_empty()
        || binding.accounts.len() > MAX_GENERIC_ACCOUNTS
        || binding.data.len() > MAX_GENERIC_INSTRUCTION_BYTES
    {
        return Err(OperationFailure::Invalid);
    }

    let system_program = Address::default();
    let shielded_pool = Address::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let mut payer_signer = false;
    let mut shielded_pool_present = false;
    let mut system_program_present = false;
    let mut authorized_tree_present = false;
    let mut seen_program_accounts = vec![false; authorized_program_accounts.len()];
    for account_index in &binding.accounts {
        let index = usize::from(*account_index);
        let address = *account_keys.get(index).ok_or(OperationFailure::Invalid)?;
        let is_signer = message.is_signer(index);
        let is_writable = message_account_is_writable(message, loaded, index);
        if is_signer {
            if address != payer {
                return Err(OperationFailure::Invalid);
            }
            payer_signer = true;
        }
        if address == shielded_pool {
            if is_signer || is_writable {
                return Err(OperationFailure::Invalid);
            }
            shielded_pool_present = true;
        }
        if address == system_program {
            if is_signer || is_writable {
                return Err(OperationFailure::Invalid);
            }
            system_program_present = true;
        }
        if address == authorized_tree {
            if is_signer || !is_writable {
                return Err(OperationFailure::Invalid);
            }
            authorized_tree_present = true;
        }
        for (index, authorized) in authorized_program_accounts.iter().enumerate() {
            if address.to_bytes() == *authorized {
                seen_program_accounts[index] = true;
            }
        }
    }
    if !payer_signer
        || !shielded_pool_present
        || !system_program_present
        || !authorized_tree_present
        || seen_program_accounts.iter().any(|seen| !seen)
    {
        return Err(OperationFailure::Invalid);
    }
    Ok(())
}

async fn load_transaction_addresses(
    rpc: &SolanaRpc,
    message: &VersionedMessage,
) -> Result<LoadedAddresses, OperationFailure> {
    let message = match message {
        VersionedMessage::Legacy(_) => return Ok(LoadedAddresses::default()),
        VersionedMessage::V1(_) => return Err(OperationFailure::Invalid),
        VersionedMessage::V0(message) => message,
    };
    if message.address_table_lookups.len() > MAX_GENERIC_LOOKUP_TABLES {
        return Err(OperationFailure::Invalid);
    }
    let mut seen = Vec::with_capacity(message.address_table_lookups.len());
    let mut writable = Vec::new();
    let mut readonly = Vec::new();
    for lookup in &message.address_table_lookups {
        if seen.contains(&lookup.account_key) {
            return Err(OperationFailure::Invalid);
        }
        seen.push(lookup.account_key);
        let table = read_generic_lookup_table(rpc, lookup.account_key).await?;
        for index in &lookup.writable_indexes {
            writable.push(
                *table
                    .addresses
                    .get(usize::from(*index))
                    .ok_or(OperationFailure::Invalid)?,
            );
        }
        for index in &lookup.readonly_indexes {
            readonly.push(
                *table
                    .addresses
                    .get(usize::from(*index))
                    .ok_or(OperationFailure::Invalid)?,
            );
        }
    }
    Ok(LoadedAddresses { writable, readonly })
}

fn message_account_is_writable(
    message: &VersionedMessage,
    loaded: &LoadedAddresses,
    index: usize,
) -> bool {
    let static_len = message.static_account_keys().len();
    if index >= static_len {
        return index - static_len < loaded.writable.len();
    }
    let header = message.header();
    let signed = usize::from(header.num_required_signatures);
    if index < signed {
        index < signed.saturating_sub(usize::from(header.num_readonly_signed_accounts))
    } else {
        index < static_len.saturating_sub(usize::from(header.num_readonly_unsigned_accounts))
    }
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
/// role to the caller. The returned Solana legacy-format message has exactly
/// one empty signature slot, shared by the shielded owner and fee payer.
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
        SpendSettlementV1::Withdrawal { .. } => {
            create_withdrawal(WithdrawalParams {
                wallet,
                payer,
                legs: vec![WithdrawalLeg {
                    recipient,
                    asset,
                    amount,
                    spl_token_program: (asset != SOL_MINT).then(pda::spl_token_program_id),
                }],
            })
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .transaction
        }
        SpendSettlementV1::Consolidate { .. } => return Err(OperationFailure::Invalid),
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

/// Prefer larger default-ring UTXOs before the SDK's stable input scan.
///
/// The installed SPP circuits accept at most five inputs. Index order can pick
/// six pieces of dust even when a later UTXO covers the spend by itself.
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

/// Consolidate up to eight plain default-domain UTXOs through Zolana's
/// dedicated `merge_8_1` circuit. This path is balance-neutral and needs no
/// shielded transaction signature: ownership is proven from the enclave-held
/// nullifier key, while the public wallet remains the transaction fee payer.
async fn build_merge_transaction(
    keypair: &TurnkeyEd25519ShieldedKeypair,
    wallet: &Wallet,
    zolana: &ZolanaClient<SolanaRpc>,
    payer: Address,
    asset: Address,
    tree: Address,
) -> Result<VersionedTransaction, OperationFailure> {
    let mut candidates = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent
                && entry.utxo.asset == asset
                && entry.output_context.tree == tree
                && entry.utxo.ring_program_id.is_none()
                && entry.data_hash.is_none()
                && entry.ring_data_hash.is_none()
                && entry.utxo.data.is_empty()
        })
        .collect::<Vec<_>>();
    // This rail is entered because a concrete transfer could not fit the
    // ordinary <=5-input circuit. Merging the largest fragments makes the
    // saved transfer resumable with the fewest extra transactions.
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
    candidates.truncate(MERGE_INPUTS);
    if candidates.len() < 2 {
        return Err(OperationFailure::Failed(
            FailureStage::UnsupportedProofShape,
        ));
    }

    let inputs = candidates
        .into_iter()
        .map(|entry| SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key()))
        .collect();
    let prepared = Merge::new(keypair, inputs)
        .map_err(|_| OperationFailure::Failed(FailureStage::PrivateTransitionAssembly))?
        .prepare();
    let commitments = prepared
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let proofs = zolana
        .get_input_merkle_proofs_for_tree(tree, &commitments, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    ensure_merge_proofs_match_tree(&proofs, tree)?;

    let nullifier_key = keypair.nullifier_key();
    let dummy_nullifiers = prepared
        .dummy_nullifiers(&nullifier_key)
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    if dummy_nullifier_proofs
        .iter()
        .any(|proof| proof.merkle_context.tree != tree)
    {
        return Err(OperationFailure::Failed(FailureStage::InputTree));
    }

    let built = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key,
        proofs,
        dummy_nullifier_proofs,
    })
    .and_then(MergeProver::build)
    .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(EXPECTED_EXTERNAL_ORIGIN.to_owned());
    let proof = prover
        .prove_merge(&built.inputs)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let packed = ProofCompressed::try_from(proof)
        .and_then(|proof| proof.to_merge_proof())
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let payer = Pubkey::new_from_array(payer.to_bytes());
    let merge = MergeTransact {
        input_tree: Pubkey::new_from_array(tree.to_bytes()),
        output_tree: Pubkey::new_from_array(tree.to_bytes()),
        payer,
        user_record: user_record_pda(&payer).0,
        data: built.instruction_data(packed),
    }
    .instruction();
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = Message::new_with_blockhash(&[compute, merge], Some(&payer), &blockhash);
    Ok(VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::Legacy(message),
    })
}

fn ensure_merge_proofs_match_tree(
    proofs: &[SpendProof],
    tree: Address,
) -> Result<(), OperationFailure> {
    if proofs.iter().any(|proof| {
        proof.state.merkle_context.tree != tree || proof.nullifier.merkle_context.tree != tree
    }) {
        return Err(OperationFailure::Failed(FailureStage::InputTree));
    }
    Ok(())
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
/// runs the ring circuit over an auditor-encrypted transaction viewing key and
/// needs a v0 message so an address lookup table can keep it within Solana's
/// packet limit.
async fn build_ring_transaction(
    intent: &SpendIntentV1,
    amount: u64,
    cx: RingSpendContext<'_>,
) -> Result<VersionedTransaction, OperationFailure> {
    let (ring_program_id, ring_lookup_table) =
        transaction_ring(intent)?.ok_or(OperationFailure::Invalid)?;
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
    let program_id = Address::from_str(ring_program_id).map_err(|_| OperationFailure::Invalid)?;
    let table_address =
        Address::from_str(ring_lookup_table).map_err(|_| OperationFailure::Invalid)?;
    let custom_ring = CustomRing::new(program_id);

    let nullifier_key = keypair.nullifier_key();
    let (inputs, available) = match &intent.source {
        PrivateDomainV1::Ring { .. } => {
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
        PrivateDomainV1::Default => {
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
        SpendSettlementV1::Transfer { destination, .. } => {
            let recipient_address = try_resolve_registered_address_async(
                zolana,
                Address::new_from_array(recipient.to_bytes()),
            )
            .await
            .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?
            .ok_or(OperationFailure::Invalid)?;
            match destination {
                PrivateDomainV1::Ring { .. } => transfer
                    .send(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
                PrivateDomainV1::Default => transfer
                    .send_default_ring(&recipient_address.address, asset, amount)
                    .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?,
            };
            Vec::new()
        }
        SpendSettlementV1::Withdrawal { .. } => {
            let (target, accounts) = if asset == SOL_MINT {
                (
                    SettlementTarget::Sol {
                        user_sol_account: Address::new_from_array(recipient.to_bytes()),
                    },
                    TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts {
                        recipient,
                    }),
                )
            } else {
                let mint = Pubkey::new_from_array(asset.to_bytes());
                let token_program = pda::spl_token_program_id();
                let user_spl_token =
                    pda::associated_token_address_with_program(&recipient, &mint, &token_program);
                let spl_interface = pda::spl_interface(&mint);
                (
                    SettlementTarget::Spl {
                        user_spl_token: Address::new_from_array(user_spl_token.to_bytes()),
                        spl_token_interface: Address::new_from_array(spl_interface.to_bytes()),
                    },
                    TransactInterfaceTransferAccounts::SplWithdrawal(
                        TransactSplWithdrawalAccounts {
                            mint,
                            spl_interface,
                            user_token_account: user_spl_token,
                            token_program,
                        },
                    ),
                )
            };
            transfer
                .withdraw(asset, amount, target)
                .map_err(|_| OperationFailure::Failed(FailureStage::SettlementConstruction))?;
            vec![accounts]
        }
        SpendSettlementV1::Consolidate { .. } => return Err(OperationFailure::Invalid),
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
    Ok(AuthorizedSpend {
        transaction_signature,
        signed_transaction: signed_bytes,
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
            let mint_address = Address::new_from_array(mint.to_bytes());
            let mint_account = rpc
                .get_account(mint_address)
                .await
                .map_err(|_| OperationFailure::Failed(FailureStage::AssetRegistry))?
                .ok_or(OperationFailure::Invalid)?;
            if mint_account.owner.to_bytes() != pda::spl_token_program_id().to_bytes() {
                return Err(OperationFailure::Invalid);
            }
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
/// None of these variants carries UTXO hashes, amounts, keys, or prover input.
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
/// A custom-ring transact needs a v0 message so an address lookup table can
/// keep it within Solana's packet limit. Turnkey accepts both Solana message
/// formats for the same signing intent; only the encoding-specific validation
/// differs below.
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

/// Decodes straight into the caller's buffer, the seed halves never live in a
/// temporary allocation.
fn decode_signature_component(encoded: &str, output: &mut [u8]) -> Result<(), OperationFailure> {
    hex::decode_to_slice(encoded.strip_prefix("0x").unwrap_or(encoded), output)
        .map_err(|_| OperationFailure::Unavailable)
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
    use solana_instruction::{AccountMeta, Instruction};

    use qos_p256::P256Pair;
    use zolana_tvc_protocol::types::{
        ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1, SppMessageV1,
        SppPlanOutputV1, SppShapeV1, WalletDescriptorV1,
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
            security_domain_id: [0x11; 32],
            environment: Environment::Development,
            turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
            turnkey_wallet_id: "keyholder-test".to_owned(),
            address: Pubkey::new_from_array([0x22; 32]).to_string(),
            allowed_clients: vec![ClientGrantV1 {
                client_public_key: vec![0x04; 65],
                allowed_operations: KEYHOLDER_OPERATIONS.to_vec(),
            }],
            provisioning_signature: vec![0u8; 64],
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
            client_response_public_key: vec![0u8; 65],
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
        let (_, bytes, _) = seal_state(
            keys,
            KeyStatePlaintextV1 {
                version: API_VERSION,
                quorum_key_id: bootstrap.quorum_key_id.clone(),
                quorum_key_epoch: bootstrap.quorum_key_epoch,
                wallet_id: descriptor.wallet_id(),
                descriptor_digest: descriptor_digest_from_wallet(&descriptor).expect("digest"),
                ed25519_public_key: [0x22; 32],
                derivation_suite: DERIVATION_SUITE.to_owned(),
                derivation_seed: TEST_SEED,
            },
        )
        .expect("seal");

        let mut next = request(operation, descriptor);
        next.sealed_wallet_state = Some(bytes);
        next
    }

    fn ring_intent(program: Pubkey) -> SpendIntentV1 {
        SpendIntentV1 {
            source: PrivateDomainV1::Ring {
                program_id: program.to_string(),
                lookup_table: Pubkey::new_from_array([0x44; 32]).to_string(),
            },
            settlement: SpendSettlementV1::Withdrawal {
                asset: AssetV1::Sol,
                recipient: Pubkey::new_from_array([0x55; 32]).to_string(),
                amount: 1,
            },
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

    fn private_program_message(
        payer: Address,
        program: Address,
        input_tree: Address,
        transact: &[u8],
        extra_accounts: Vec<AccountMeta>,
        extra_instructions: Vec<Instruction>,
    ) -> VersionedMessage {
        let mut accounts = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(input_tree, false),
            AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Address::default(), false),
        ];
        accounts.extend(extra_accounts);
        let instruction = Instruction {
            program_id: program,
            accounts,
            data: [b"program-prefix".as_slice(), transact].concat(),
        };
        let mut instructions = vec![instruction];
        instructions.extend(extra_instructions);
        VersionedMessage::V0(
            v0::Message::try_compile(&payer, &instructions, &[], solana_hash::Hash::default())
                .expect("compile program transaction"),
        )
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
    fn stateful_keyholder_operations_require_the_sealed_state() {
        let keys = runtime_keys();
        let tags = OperationV1::DeriveViewTags;
        let complete = sealed_request(&keys, tags.clone());
        assert!(operation_state_fields_are_valid(&complete));

        let mut missing_blob = complete.clone();
        missing_blob.sealed_wallet_state = None;
        assert!(!operation_state_fields_are_valid(&missing_blob));

        assert!(!operation_state_fields_are_valid(&request(
            tags,
            descriptor()
        )));
        assert!(operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::DecryptUtxos {
                payloads: Vec::new(),
                include_spendable_outputs: true,
            },
        )));
        assert!(operation_state_fields_are_valid(&sealed_request(
            &keys,
            OperationV1::AuthorizeSpend {
                spend: AuthorizeSpendRequestV1::Prepare {
                    plan: SpendPlanV1::Direct {
                        transition: ring_intent(Pubkey::new_unique()),
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
        let state_digest_bytes = state_digest(
            request
                .sealed_wallet_state
                .as_deref()
                .expect("sealed state"),
        );
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
                wallet_id: request.wallet_descriptor.wallet_id(),
                descriptor_digest,
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
        let state_digest_bytes = state_digest(
            request
                .sealed_wallet_state
                .as_deref()
                .expect("sealed state"),
        );
        let program_id = [0x35; 32];
        let prepared_transact = b"one exact spp transact".to_vec();
        let transact_digest = artifact_digest(&prepared_transact);
        let capsule = seal_spend_authorization(
            &keys,
            SpendAuthorizationPlaintextV1 {
                version: API_VERSION,
                quorum_key_id: request.quorum_key_id.clone(),
                quorum_key_epoch: request.quorum_key_epoch,
                wallet_id: request.wallet_descriptor.wallet_id(),
                descriptor_digest: descriptor_digest_from_wallet(&request.wallet_descriptor)
                    .expect("descriptor digest"),
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
    fn generic_transaction_binds_private_hash_and_allows_normal_composition() {
        let payer = Address::new_from_array([0x41; 32]);
        let program = Address::new_from_array([0x42; 32]);
        let input_tree = Address::new_from_array([0x44; 32]);
        let private_tx_hash = [0x47; 32];
        let valid = private_program_message(
            payer,
            program,
            input_tree,
            &private_tx_hash,
            Vec::new(),
            vec![Instruction {
                program_id: Address::new_from_array([0x70; 32]),
                accounts: vec![AccountMeta::new_readonly(payer, true)],
                data: b"another user-approved instruction".to_vec(),
            }],
        );
        assert!(validate_private_program_message(
            payer,
            program,
            input_tree,
            &[],
            private_tx_hash,
            &valid,
            &LoadedAddresses::default(),
        )
        .is_ok());

        let substituted = private_program_message(
            payer,
            program,
            input_tree,
            b"different-transact",
            Vec::new(),
            Vec::new(),
        );
        assert!(validate_private_program_message(
            payer,
            program,
            input_tree,
            &[],
            private_tx_hash,
            &substituted,
            &LoadedAddresses::default(),
        )
        .is_err());

        let ambiguous = private_program_message(
            payer,
            program,
            input_tree,
            &[private_tx_hash, private_tx_hash].concat(),
            Vec::new(),
            Vec::new(),
        );
        assert!(validate_private_program_message(
            payer,
            program,
            input_tree,
            &[],
            private_tx_hash,
            &ambiguous,
            &LoadedAddresses::default(),
        )
        .is_err());

        let program_authority = Address::new_from_array([0x46; 32]);
        assert!(validate_private_program_message(
            payer,
            program,
            input_tree,
            &[program_authority.to_bytes()],
            private_tx_hash,
            &valid,
            &LoadedAddresses::default(),
        )
        .is_err());
        let with_program_authority = private_program_message(
            payer,
            program,
            input_tree,
            &private_tx_hash,
            vec![AccountMeta::new_readonly(program_authority, false)],
            Vec::new(),
        );
        assert!(validate_private_program_message(
            payer,
            program,
            input_tree,
            &[program_authority.to_bytes()],
            private_tx_hash,
            &with_program_authority,
            &LoadedAddresses::default(),
        )
        .is_ok());
        let reserved = private_program_message(
            payer,
            Address::default(),
            input_tree,
            &private_tx_hash,
            Vec::new(),
            Vec::new(),
        );
        assert!(validate_private_program_message(
            payer,
            Address::default(),
            input_tree,
            &[],
            private_tx_hash,
            &reserved,
            &LoadedAddresses::default(),
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
    fn direct_route_is_derived_from_source_and_destination_domains() {
        let ring_a = PrivateDomainV1::Ring {
            program_id: Pubkey::new_from_array([0x61; 32]).to_string(),
            lookup_table: Pubkey::new_from_array([0x62; 32]).to_string(),
        };
        let ring_b = PrivateDomainV1::Ring {
            program_id: Pubkey::new_from_array([0x63; 32]).to_string(),
            lookup_table: Pubkey::new_from_array([0x64; 32]).to_string(),
        };
        let transfer = |source: PrivateDomainV1, destination: PrivateDomainV1| SpendIntentV1 {
            source,
            settlement: SpendSettlementV1::Transfer {
                asset: AssetV1::Sol,
                recipient: Pubkey::new_from_array([0x65; 32]).to_string(),
                amount: 1,
                destination,
            },
            input_commitments: Vec::new(),
        };

        let enters = transfer(PrivateDomainV1::Default, ring_a.clone());
        assert_eq!(
            transaction_ring(&enters).expect("default to ring"),
            domain_ring(&ring_a),
        );
        let same_ring = transfer(ring_a.clone(), ring_a.clone());
        assert_eq!(
            transaction_ring(&same_ring).expect("same ring"),
            domain_ring(&ring_a),
        );
        assert!(transaction_ring(&transfer(ring_a, ring_b)).is_err());

        let consolidate = SpendIntentV1 {
            source: PrivateDomainV1::Default,
            settlement: SpendSettlementV1::Consolidate {
                asset: AssetV1::Sol,
            },
            input_commitments: Vec::new(),
        };
        assert_eq!(transaction_ring(&consolidate).expect("default merge"), None);
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
        wrong_wallet.wallet_descriptor.turnkey_wallet_id = "someone-else".to_owned();
        assert!(unseal_state(&wrong_wallet, &keys, &sealed).is_err());

        // A descriptor change the envelope cannot see is caught by the inner
        // descriptor digest, which is why the check is done twice.
        let mut wrong_descriptor = base.clone();
        wrong_descriptor.wallet_descriptor.turnkey_organization_id =
            "00000000-0000-0000-0000-00000000000f".to_owned();
        assert!(unseal_state(&wrong_descriptor, &keys, &sealed).is_err());

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
        assert_eq!(
            digest,
            state_digest(request.sealed_wallet_state.as_deref().expect("sealed"))
        );

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

    #[tokio::test]
    async fn decrypt_returns_plaintext_without_asserting_ownership() {
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
                include_spendable_outputs: false,
            },
        );
        let payer = Pubkey::new_from_array([0x22; 32]);
        let (result, _) = decrypt_utxos(&request, &wallet(payer), &keys, &payloads, false)
            .await
            .expect("decrypt");
        let OperationResultV1::DecryptUtxos {
            payloads: results,
            spendable_outputs,
        } = result
        else {
            panic!("wrong result variant");
        };
        assert_eq!(spendable_outputs, None);

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

    #[tokio::test]
    async fn decrypt_batches_are_bounded_and_reject_malformed_public_material() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
        let payer = Pubkey::new_from_array([0x22; 32]);
        let target = wallet(payer);
        assert!(decrypt_utxos(&request, &target, &keys, &[], false)
            .await
            .is_err());

        let filler = EncryptedPayloadV1::RingDeposit {
            ciphertext: vec![0u8; 16],
            transaction_viewing_public_key: vec![0x02; 33],
            salt: vec![0x00; 16],
        };
        let oversized = vec![filler.clone(); (MAX_DECRYPT_PAYLOADS_PER_BATCH + 1) as usize];
        assert!(decrypt_utxos(&request, &target, &keys, &oversized, false)
            .await
            .is_err());

        // A wrong-length viewing key or salt is a malformed request, not a
        // ciphertext that happens to belong to someone else.
        assert!(decrypt_utxos(
            &request,
            &target,
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 32],
                salt: vec![0x00; 16],
            }],
            false,
        )
        .await
        .is_err());
        assert!(decrypt_utxos(
            &request,
            &target,
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 33],
                salt: vec![0x00; 8],
            }],
            false,
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn oracle_operations_require_a_sealed_state() {
        let keys = runtime_keys();
        let bare = request(OperationV1::BootstrapKeyholder, descriptor());
        assert!(derive_view_tags(&bare, &keys).is_err());
        let payer = Pubkey::new_from_array([0x22; 32]);
        assert!(decrypt_utxos(
            &bare,
            &wallet(payer),
            &keys,
            &[EncryptedPayloadV1::RingDeposit {
                ciphertext: vec![0u8; 16],
                transaction_viewing_public_key: vec![0x02; 33],
                salt: vec![0x00; 16],
            }],
            false,
        )
        .await
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

    fn generic_plan(now_ms: u64) -> SppPlanV1 {
        SppPlanV1 {
            program_id: Pubkey::new_from_array([0x99; 32]).to_string(),
            input_tree: Pubkey::new_from_array([0x66; 32]).to_string(),
            shape: SppShapeV1 {
                inputs: 1,
                outputs: 1,
            },
            inputs: vec![SppPlanInputV1::Wallet {
                commitment: [0x77; 32],
            }],
            program_authorities: Vec::new(),
            outputs: vec![sample_output()],
            messages: Vec::new(),
            expires_at_ms: now_ms + 100_000,
        }
    }

    fn sample_output() -> SppPlanOutputV1 {
        SppPlanOutputV1 {
            recipient: "recipient".to_owned(),
            asset: AssetV1::Sol,
            amount: 1,
            blinding: [0x88; 32],
            data: Vec::new(),
            data_hash: None,
            memo: Vec::new(),
        }
    }

    /// Every case below must be refused before the first outbound call.
    #[tokio::test]
    async fn generic_spp_rejects_malformed_plans_before_any_outbound_call() {
        let keys = runtime_keys();
        let request = sealed_request(&keys, OperationV1::DeriveViewTags);
        let payer = Pubkey::new_from_array([0x22; 32]);
        let target = wallet(payer);
        let now_ms = current_time_ms().expect("clock");

        let mut plans = Vec::new();
        let mut empty_inputs = generic_plan(now_ms);
        empty_inputs.inputs.clear();
        plans.push(("empty inputs", empty_inputs));
        let mut extra_output = generic_plan(now_ms);
        extra_output.outputs.push(sample_output());
        plans.push(("outputs exceed the shape", extra_output));
        let mut extra_input = generic_plan(now_ms);
        extra_input.inputs.push(SppPlanInputV1::Wallet {
            commitment: [0x78; 32],
        });
        plans.push(("inputs exceed the shape", extra_input));
        let mut too_many_messages = generic_plan(now_ms);
        too_many_messages.messages = (0..9)
            .map(|_| SppMessageV1 {
                view_tag: [0x11; 32],
                data: Vec::new(),
            })
            .collect();
        plans.push(("message count", too_many_messages));
        let mut expired = generic_plan(now_ms);
        expired.expires_at_ms = now_ms.saturating_sub(1_000);
        plans.push(("expired plan", expired));
        let mut distant = generic_plan(now_ms);
        distant.expires_at_ms = now_ms + 400_000;
        plans.push(("expiry beyond the window", distant));
        let mut pool_target = generic_plan(now_ms);
        pool_target.program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
        plans.push(("shielded pool as target", pool_target));
        let mut unsupported_shape = generic_plan(now_ms);
        unsupported_shape.shape = SppShapeV1 {
            inputs: 1,
            outputs: 5,
        };
        unsupported_shape.outputs = (0..5).map(|_| sample_output()).collect();
        plans.push(("unsupported shape", unsupported_shape));
        let mut oversized_message = generic_plan(now_ms);
        oversized_message.messages = vec![SppMessageV1 {
            view_tag: [0x11; 32],
            data: vec![0u8; 4_097],
        }];
        plans.push(("oversized message data", oversized_message));
        let mut oversized_memo = generic_plan(now_ms);
        oversized_memo.outputs[0].memo = vec![0u8; 4_097];
        plans.push(("oversized output memo", oversized_memo));
        let mut unhashed_data = generic_plan(now_ms);
        unhashed_data.outputs[0].data = vec![1];
        plans.push(("output data without a hash", unhashed_data));

        for (name, plan) in plans {
            let result = prepare_generic_spp(&request, &target, &plan, &keys).await;
            assert!(result.is_err(), "{name}");
        }
    }

    #[test]
    fn asset_totals_accumulate_sort_and_fail_closed_on_overflow() {
        let a = Address::new_from_array([2; 32]);
        let b = Address::new_from_array([1; 32]);
        let mut totals = Vec::new();
        add_asset_amount(&mut totals, a, 5).expect("add");
        add_asset_amount(&mut totals, a, 7).expect("add");
        add_asset_amount(&mut totals, b, 1).expect("add");
        assert_eq!(totals, vec![(a, 12), (b, 1)]);
        sort_asset_totals(&mut totals);
        assert_eq!(totals, vec![(b, 1), (a, 12)]);

        let mut saturated = vec![(a, u128::MAX)];
        assert!(add_asset_amount(&mut saturated, a, 1).is_err());
    }
}
