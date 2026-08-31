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
use zolana_transaction::{AssetRegistry, TransactionError, Utxo, Wallet, WalletUtxo, SOL_MINT};
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

mod assets;
mod keyholder;
mod request;
mod sealed;
mod signer;
mod spend;
mod stage;
#[cfg(test)]
mod tests;
mod wallet_sync;

use assets::*;
use keyholder::*;
use request::*;
use sealed::*;
use signer::*;
use spend::*;
use stage::*;
use wallet_sync::*;

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
/// Both endpoints are the one pinned devnet origin.
fn pinned_zolana_client(rpc: SolanaRpc, tree: Address) -> ZolanaClient<SolanaRpc> {
    ZolanaClient::from_urls_allowing_insecure_http(
        rpc,
        EXPECTED_EXTERNAL_ORIGIN,
        EXPECTED_EXTERNAL_ORIGIN,
        tree,
    )
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
