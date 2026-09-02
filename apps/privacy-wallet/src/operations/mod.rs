//! The encrypted operation endpoint.
//!
//! The enclave is a stateless oracle over the wallet's privacy roles. It holds
//! the derivation seed only for one request, unsealed from the blob the client
//! presents, and stores nothing across requests. Only bootstrap and spend reach
//! the custodian; view tags and decryption need nothing but the seed.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Response, StatusCode};
use sha2::{Digest as _, Sha256};
use solana_pubkey::Pubkey;
use zeroize::Zeroizing;
use zolana_tvc_protocol::bindings::{
    check_encrypted_request_bindings, check_request_bindings, RunningEnclave,
};
use zolana_tvc_protocol::constants::{
    API_VERSION, DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES, MAX_CLOCK_SKEW_MS, MAX_REQUEST_AGE_MS,
    TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::crypto::{parse_uncompressed_sec1, qos_encrypt, verify_p256_prehash};
use zolana_tvc_protocol::digest::{descriptor_digest, request_digest, result_digest};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_encrypted_request, parse_operation_request, AppProof, EncryptedResponse, Environment,
    FailureStage, Operation, OperationKind, OperationProofPayload, OperationRequest,
    OperationResult,
};
use zolana_tvc_protocol::{public_http_error, PublicError, PublicHttpResponse};

use crate::custody::{CustodyError, WalletKey};
use crate::{into_response, sign_ephemeral_low_s, AppState, Runtime};

mod bootstrap;
mod sealed;
mod spend;
#[cfg(test)]
mod tests;
mod view;

/// Every operation this application serves. A descriptor grants the whole set.
pub const OPERATIONS: [OperationKind; 4] = [
    OperationKind::Bootstrap,
    OperationKind::ViewTags,
    OperationKind::Decrypt,
    OperationKind::Spend,
];

const CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const DERIVATION_SUITE: &str = "zolana-ed25519-role-expansion-v1";
const SPEND_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const DEVNET_ORIGIN: &str =
    "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
// Disposable development provisioner key. Its private half stays outside TVC.
pub(crate) const PROVISIONING_PUBLIC: [u8; 65] = [
    0x04, 0x94, 0xc6, 0x1a, 0x25, 0xe2, 0xd5, 0x0e, 0x7e, 0x20, 0xc8, 0xfc, 0xd7, 0xe2, 0xa9, 0x39,
    0x45, 0x22, 0x76, 0x04, 0x78, 0xd7, 0xe6, 0xe7, 0x93, 0x1a, 0xc6, 0x09, 0x59, 0xdb, 0x24, 0xe0,
    0xa8, 0x28, 0x38, 0x9f, 0x39, 0x0f, 0x75, 0xbf, 0x00, 0xfb, 0xac, 0x61, 0x63, 0x84, 0x86, 0x78,
    0x2b, 0x78, 0x5c, 0x40, 0xba, 0x8e, 0x33, 0x4e, 0x21, 0x5b, 0x47, 0x6d, 0x9d, 0x1f, 0x22, 0x3f,
    0x4f,
];

/// How an operation did not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The request is malformed or not authorized; answered with a generic 400.
    Invalid,
    /// The enclave cannot serve; answered with a generic 503.
    Unavailable,
    /// The operation ran and failed at a named stage; answered inside the
    /// encrypted result so only the requester learns which.
    Stage(FailureStage),
}

impl From<CustodyError> for Failure {
    fn from(error: CustodyError) -> Self {
        match error {
            CustodyError::Unavailable => Self::Unavailable,
            CustodyError::Declined => Self::Stage(FailureStage::TurnkeySigning),
            CustodyError::Mismatch => Self::Stage(FailureStage::SignedTransactionMismatch),
        }
    }
}

pub(crate) async fn handle(state: &AppState, body: &[u8]) -> Response<Body> {
    match execute(state, body).await {
        Ok(response) => into_response(PublicHttpResponse {
            status: StatusCode::OK.as_u16(),
            content_type: "application/json",
            body: response.into_bytes(),
        }),
        Err(Failure::Invalid) => into_response(public_http_error(PublicError::InvalidRequest)),
        Err(Failure::Unavailable | Failure::Stage(_)) => {
            into_response(public_http_error(PublicError::Unavailable))
        }
    }
}

async fn execute(state: &AppState, body: &[u8]) -> Result<String, Failure> {
    let runtime = state.runtime.as_ref().ok_or(Failure::Unavailable)?;
    let body = std::str::from_utf8(body).map_err(|_| Failure::Invalid)?;
    let encrypted = parse_encrypted_request(body).map_err(|_| Failure::Invalid)?;
    let running = running_enclave(state);
    check_encrypted_request_bindings(&encrypted, &running).map_err(|_| Failure::Invalid)?;

    let plaintext = Zeroizing::new(
        runtime
            .quorum
            .decrypt(&encrypted.ciphertext)
            .map_err(|_| Failure::Invalid)?,
    );
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| Failure::Invalid)?;
    if !is_rfc8785(plaintext) {
        return Err(Failure::Invalid);
    }
    let request = parse_operation_request(plaintext).map_err(|_| Failure::Invalid)?;
    let wallet = validate(&request, &running, state, runtime)?;
    let request_hash = request_digest(&request).map_err(|_| Failure::Invalid)?;
    parse_uncompressed_sec1(&request.client_response_public_key).map_err(|_| Failure::Invalid)?;

    // Every result carries the digest of the sealed state it was computed
    // against, so the App Proof binds the answer to one key state, not merely
    // to the request.
    let (result, proof_state_digest) = match &request.operation {
        Operation::Bootstrap => bootstrap::run(&request, &wallet, runtime).await?,
        Operation::ViewTags => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            (view::tags(&roles), digest)
        }
        Operation::Decrypt { payloads, assets } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            (view::decrypt(&roles, payloads, assets)?, digest)
        }
        Operation::Spend {
            tree,
            inputs,
            action,
            assets,
        } => {
            let (roles, digest) = sealed::unseal(&request, runtime)?;
            let spend = spend::Spend {
                request: &request,
                wallet: &wallet,
                roles: &roles,
                runtime,
                tree,
                inputs,
                action,
                assets,
            };
            let result = match tokio::time::timeout(SPEND_TIMEOUT, spend.run()).await {
                Ok(Ok(result)) => result,
                Ok(Err(Failure::Stage(stage))) => OperationResult::Failure {
                    operation: OperationKind::Spend,
                    stage,
                },
                Ok(Err(failure)) => return Err(failure),
                Err(_) => OperationResult::Failure {
                    operation: OperationKind::Spend,
                    stage: FailureStage::Prover,
                },
            };
            (result, digest)
        }
    };

    let result_plaintext =
        Zeroizing::new(jcs_serialize(&result).map_err(|_| Failure::Unavailable)?);
    let encrypted_result = qos_encrypt(
        &request.client_response_public_key,
        result_plaintext.as_bytes(),
    )
    .map_err(|_| Failure::Unavailable)?;
    if encrypted_result.len() as u64 > DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES {
        return Err(Failure::Unavailable);
    }

    let proof_payload = jcs_serialize(&OperationProofPayload {
        r#type: TVC_APP_PROOF_TYPE.to_owned(),
        version: API_VERSION,
        request_id: request.request_id,
        request_digest: request_hash,
        result_digest: result_digest(&encrypted_result),
        operation: request.operation.kind(),
        state_digest: proof_state_digest,
    })
    .map_err(|_| Failure::Unavailable)?;
    let signature = sign_ephemeral_low_s(&runtime.ephemeral, proof_payload.as_bytes())
        .map_err(|_| Failure::Unavailable)?;
    jcs_serialize(&EncryptedResponse {
        version: API_VERSION,
        request_id: request.request_id,
        encrypted_result,
        tvc_app_proof: AppProof {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: runtime.ephemeral.public_key().to_bytes(),
            proof_payload,
            signature,
        },
    })
    .map_err(|_| Failure::Unavailable)
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

/// Binds the request to this release, checks its freshness, verifies the
/// provisioner's signature over the descriptor and the client's signature over
/// the request, and returns the Turnkey key the descriptor names.
fn validate<'a>(
    request: &'a OperationRequest,
    running: &RunningEnclave,
    state: &AppState,
    runtime: &Runtime,
) -> Result<WalletKey<'a>, Failure> {
    check_request_bindings(request, running).map_err(|_| Failure::Invalid)?;
    let kind = request.operation.kind();
    // Bootstrap derives a fresh state; every other operation answers against
    // the presented one.
    let expects_state = kind != OperationKind::Bootstrap;
    if running.environment != Environment::Development
        || !state.info.supported_operations.contains(&kind)
        || request.sealed_wallet_state.is_some() != expects_state
    {
        return Err(Failure::Invalid);
    }

    let now = now_ms()?;
    if request.expires_at_ms < now
        || request.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || request.expires_at_ms < request.issued_at_ms
        || request.expires_at_ms - request.issued_at_ms > MAX_REQUEST_AGE_MS
    {
        return Err(Failure::Invalid);
    }

    let descriptor = &request.wallet_descriptor;
    let address = Pubkey::from_str(&descriptor.address).map_err(|_| Failure::Invalid)?;
    if descriptor.version != API_VERSION
        || !is_canonical_uuid(&descriptor.turnkey_organization_id)
        || descriptor.turnkey_wallet_id.is_empty()
        || descriptor.turnkey_wallet_id.len() > 128
        || descriptor.environment != Environment::Development
        || descriptor.allowed_clients.len() != 1
    {
        return Err(Failure::Invalid);
    }
    let digest = descriptor_digest(descriptor).map_err(|_| Failure::Invalid)?;
    verify_p256_prehash(
        &runtime.provisioning_public,
        &digest,
        &descriptor.provisioning_signature,
    )
    .map_err(|_| Failure::Invalid)?;

    let grant = &descriptor.allowed_clients[0];
    let expected_client_key_id = format!(
        "{CLIENT_KEY_ID_PREFIX}{}",
        hex::encode(&Sha256::digest(&grant.client_public_key)[..16])
    );
    if grant.client_public_key.len() != 65
        || grant.allowed_operations != OPERATIONS
        || request.authorization.client_key_id != expected_client_key_id
    {
        return Err(Failure::Invalid);
    }
    zolana_tvc_protocol::verify_client_authorization(request, &grant.client_public_key)
        .map_err(|_| Failure::Invalid)?;

    Ok(WalletKey {
        organization_id: &descriptor.turnkey_organization_id,
        sign_with: &descriptor.address,
        public_key: address.to_bytes(),
    })
}

fn is_canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

fn now_ms() -> Result<u64, Failure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Unavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| Failure::Unavailable)
}
