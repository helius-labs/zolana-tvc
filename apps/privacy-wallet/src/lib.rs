//! No-production-funds privacy-wallet TVC service using the keyholder model.
//!
//! This service exposes discovery, an encrypted QOS key-path smoke test, and a
//! closed development-only key bootstrap, sync oracle, and transaction construction
//! path. Boot Proof verification remains a relying-party responsibility.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use p256::ecdsa::Signature;
use qos_core::handles::Handles;
use qos_core::{EPHEMERAL_KEY_FILE, MANIFEST_FILE, PIVOT_FILE, QUORUM_FILE};
use qos_p256::P256Pair;
use zolana_tvc_protocol::constants::{
    API_VERSION, DEVNET_MAX_ENCRYPTED_REQUEST_BYTES, DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
    TVC_APP_PROOF_SCHEME, TVC_APP_PROOF_TYPE, TVC_QOS_PING_PROOF_TYPE,
};
use zolana_tvc_protocol::encoding::{is_rfc8785, jcs_serialize};
use zolana_tvc_protocol::types::{
    parse_qos_ping_challenge, parse_qos_ping_request, Environment, OperationKind,
    QosPingResponseV1, ServiceInfoV1, TvcAppProofV1,
};
use zolana_tvc_protocol::{handle_public_http, public_http_error, PublicError, PublicHttpResponse};

mod operations;
mod solana_rpc;
mod turnkey;

#[cfg(feature = "local-dev")]
mod local_dev;
#[cfg(feature = "local-dev")]
pub use local_dev::local_testkit_qos_seeds;
#[cfg(feature = "local-dev")]
use local_dev::{local_provisioning_public, local_testkit_fixture, LocalWalletState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
}

#[derive(Clone)]
struct ServiceEndpoints {
    solana_rpc_url: String,
    indexer_url: String,
    prover_url: String,
    custom_ring_prover_url: String,
    default_tree: String,
    allow_insecure_http: bool,
}

impl ServiceEndpoints {
    fn production() -> Self {
        Self {
            solana_rpc_url: solana_rpc::DEVNET_SOLANA_RPC_URL.to_owned(),
            indexer_url: operations::EXPECTED_EXTERNAL_ORIGIN.to_owned(),
            prover_url: operations::EXPECTED_EXTERNAL_ORIGIN.to_owned(),
            custom_ring_prover_url: operations::EXPECTED_CUSTOM_RING_PROVER_ORIGIN.to_owned(),
            default_tree: operations::DEVNET_DEFAULT_TREE.to_owned(),
            allow_insecure_http: false,
        }
    }
}

/// Local-only service addresses. They never enter the production constructor.
#[cfg(feature = "local-dev")]
#[derive(Debug, Clone)]
pub struct LocalServiceConfig {
    pub solana_rpc_url: String,
    pub indexer_url: String,
    pub prover_url: String,
    pub default_tree: String,
}

struct RuntimeKeys {
    ephemeral: Arc<P256Pair>,
    quorum: Arc<P256Pair>,
}

#[derive(Clone)]
pub struct AppState {
    info: Arc<ServiceInfoV1>,
    keys: Option<Arc<RuntimeKeys>>,
    services: Arc<ServiceEndpoints>,
    #[cfg(feature = "local-dev")]
    local_wallet: Option<Arc<LocalWalletState>>,
    ready: bool,
}

impl AppState {
    pub fn ready(info: ServiceInfoV1, ephemeral: P256Pair, quorum: P256Pair) -> Self {
        Self {
            info: Arc::new(info),
            keys: Some(Arc::new(RuntimeKeys {
                ephemeral: Arc::new(ephemeral),
                quorum: Arc::new(quorum),
            })),
            services: Arc::new(ServiceEndpoints::production()),
            #[cfg(feature = "local-dev")]
            local_wallet: None,
            ready: true,
        }
    }

    pub fn unavailable(info: ServiceInfoV1) -> Self {
        Self {
            info: Arc::new(info),
            keys: None,
            services: Arc::new(ServiceEndpoints::production()),
            #[cfg(feature = "local-dev")]
            local_wallet: None,
            ready: false,
        }
    }

    pub fn service_info(&self) -> &ServiceInfoV1 {
        &self.info
    }
}

/// Construct the separate, explicitly unattested local development state.
///
/// The production binary never enables `local-dev`, so this function and its
/// mock custody key are absent from `/tvc_app`.
#[cfg(feature = "local-dev")]
pub fn local_unattested_state(
    ephemeral: P256Pair,
    quorum: P256Pair,
    wallet_secret: [u8; 32],
    services: LocalServiceConfig,
) -> AppState {
    use zolana_tvc_protocol::digest::sha256;

    let fixture = local_testkit_fixture();
    let ephemeral_public_key = ephemeral.public_key().to_bytes();
    let info = ServiceInfoV1 {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: sha256(fixture.security_domain_label.as_bytes()),
        release_id: fixture.release_id.clone(),
        manifest_digest: sha256(fixture.manifest_label.as_bytes()),
        executable_digest: sha256(fixture.executable_label.as_bytes()),
        quorum_public_key: quorum.public_key().to_bytes(),
        quorum_key_id: fixture.quorum_key_id.clone(),
        quorum_key_epoch: 1,
        ephemeral_public_key: ephemeral_public_key.clone(),
        supported_operations: fixture.operations.clone(),
        max_encrypted_request_bytes: DEVNET_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: ephemeral_public_key,
    };

    AppState {
        info: Arc::new(info),
        keys: Some(Arc::new(RuntimeKeys {
            ephemeral: Arc::new(ephemeral),
            quorum: Arc::new(quorum),
        })),
        services: Arc::new(ServiceEndpoints {
            solana_rpc_url: services.solana_rpc_url,
            indexer_url: services.indexer_url,
            prover_url: services.prover_url.clone(),
            custom_ring_prover_url: services.prover_url,
            default_tree: services.default_tree,
            allow_insecure_http: true,
        }),
        local_wallet: Some(Arc::new(LocalWalletState::from_secret(wallet_secret))),
        ready: true,
    }
}

/// Load QOS-owned state from the canonical paths and bind discovery to the
/// approved manifest. All failures are deliberately free of key material.
pub fn load_qos_state(config: DiscoveryConfig) -> io::Result<AppState> {
    if config.release_id.is_empty() || config.quorum_key_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "release and quorum key identifiers must not be empty",
        ));
    }

    let handles = Handles::new(
        EPHEMERAL_KEY_FILE.to_owned(),
        QUORUM_FILE.to_owned(),
        MANIFEST_FILE.to_owned(),
        PIVOT_FILE.to_owned(),
    );
    let ephemeral = handles
        .get_ephemeral_key()
        .map_err(|_| io::Error::other("failed to load QOS ephemeral key"))?;
    let quorum = handles
        .get_quorum_key()
        .map_err(|_| io::Error::other("failed to load QOS quorum key"))?;
    let envelope = handles
        .get_manifest_envelope()
        .map_err(|_| io::Error::other("failed to load QOS manifest"))?;

    let manifest_digest = envelope.manifest_hash();
    let executable_digest = *envelope.pivot_hash();
    let manifest = envelope.manifest();
    let quorum_public_key = quorum.public_key().to_bytes();
    if manifest.namespace().quorum_key != quorum_public_key {
        return Err(io::Error::other(
            "QOS quorum key does not match the approved manifest",
        ));
    }

    let ephemeral_public_key = ephemeral.public_key().to_bytes();
    let info = ServiceInfoV1 {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: config.security_domain_id,
        release_id: config.release_id,
        manifest_digest,
        executable_digest,
        quorum_public_key,
        quorum_key_id: config.quorum_key_id,
        quorum_key_epoch: config.quorum_key_epoch,
        ephemeral_public_key: ephemeral_public_key.clone(),
        supported_operations: vec![
            OperationKind::BootstrapKeyholder,
            OperationKind::DeriveViewTags,
            OperationKind::DecryptUtxos,
            OperationKind::AuthorizeSpend,
        ],
        max_encrypted_request_bytes: DEVNET_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: ephemeral_public_key,
    };

    Ok(AppState::ready(info, ephemeral, quorum))
}

pub fn router(state: AppState) -> Router {
    Router::new().fallback(dispatch).with_state(state)
}

async fn dispatch(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body_limit = usize::try_from(
        state
            .info
            .max_encrypted_request_bytes
            .min(DEVNET_MAX_ENCRYPTED_REQUEST_BYTES),
    )
    .unwrap_or(usize::MAX);
    let body = match to_bytes(body, body_limit).await {
        Ok(body) => body,
        Err(_) => return into_response(public_http_error(PublicError::RequestTooLarge)),
    };

    if parts.uri.path() == "/v1/ping" {
        if parts.method != Method::POST {
            return into_response(public_http_error(PublicError::MethodNotAllowed));
        }
        if !has_json_content_type(&parts.headers) {
            return into_response(public_http_error(PublicError::InvalidRequest));
        }
        return handle_ping(&state, &body);
    }

    if parts.uri.path() == "/v1/operations" {
        if parts.method != Method::POST {
            return into_response(public_http_error(PublicError::MethodNotAllowed));
        }
        if !has_json_content_type(&parts.headers) {
            return into_response(public_http_error(PublicError::InvalidRequest));
        }
        return operations::handle_operation(&state, &body).await;
    }

    into_response(handle_public_http(
        parts.method.as_str(),
        parts.uri.path(),
        &body,
        state.ready,
        &state.info,
    ))
}

fn has_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim() == "application/json")
}

fn handle_ping(state: &AppState, body: &[u8]) -> Response<Body> {
    let Some(keys) = state.keys.as_ref() else {
        return into_response(public_http_error(PublicError::Unavailable));
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    let Ok(request) = parse_qos_ping_request(body) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    if request.version != API_VERSION {
        return into_response(public_http_error(PublicError::InvalidRequest));
    }

    let Ok(plaintext) = keys.quorum.decrypt(&request.encrypted_challenge) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    let Ok(proof_payload) = std::str::from_utf8(&plaintext) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    let Ok(challenge) = parse_qos_ping_challenge(proof_payload) else {
        return into_response(public_http_error(PublicError::InvalidRequest));
    };
    if challenge.version != API_VERSION
        || challenge.r#type != TVC_QOS_PING_PROOF_TYPE
        || !is_rfc8785(proof_payload)
    {
        return into_response(public_http_error(PublicError::InvalidRequest));
    }

    let ephemeral_public_key = keys.ephemeral.public_key().to_bytes();
    let Ok(signature) = sign_ephemeral_low_s(&keys.ephemeral, proof_payload.as_bytes()) else {
        return into_response(public_http_error(PublicError::Unavailable));
    };

    let response = QosPingResponseV1 {
        version: API_VERSION,
        tvc_app_proof: TvcAppProofV1 {
            scheme: TVC_APP_PROOF_SCHEME.to_owned(),
            public_key: ephemeral_public_key,
            proof_payload: proof_payload.to_owned(),
            signature,
        },
    };
    let Ok(body) = jcs_serialize(&response) else {
        return into_response(public_http_error(PublicError::Unavailable));
    };
    into_response(PublicHttpResponse {
        status: StatusCode::OK.as_u16(),
        content_type: "application/json",
        body: body.into_bytes(),
    })
}

fn sign_ephemeral_low_s(ephemeral: &P256Pair, message: &[u8]) -> Result<Vec<u8>, ()> {
    let raw = ephemeral.sign(message).map_err(|_| ())?;
    let signature = Signature::from_slice(&raw).map_err(|_| ())?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    Ok(normalized.to_bytes().to_vec())
}

pub(crate) fn into_response(response: PublicHttpResponse) -> Response<Body> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, response.content_type)],
        response.body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use zeroize::Zeroizing;
    use zolana_tvc_protocol::constants::{QOS_P256_PUBLIC_LEN, RAW_P256_SIGNATURE_LEN};
    use zolana_tvc_protocol::crypto::{verify_p256_message, QosP256Public};
    use zolana_tvc_protocol::encoding::{jcs_serialize, parse_strict_json};
    use zolana_tvc_protocol::types::{
        Environment, QosPingChallengeV1, QosPingRequestV1, QosPingResponseV1,
    };

    use super::*;

    fn info(quorum: &P256Pair, ephemeral: &P256Pair) -> ServiceInfoV1 {
        ServiceInfoV1 {
            version: API_VERSION,
            environment: Environment::Development,
            security_domain_id: [0x11; 32],
            release_id: "tvc-pet-test".to_owned(),
            manifest_digest: [0x22; 32],
            executable_digest: [0x33; 32],
            quorum_public_key: quorum.public_key().to_bytes(),
            quorum_key_id: "quorum-test".to_owned(),
            quorum_key_epoch: 1,
            ephemeral_public_key: ephemeral.public_key().to_bytes(),
            supported_operations: Vec::new(),
            max_encrypted_request_bytes: DEVNET_MAX_ENCRYPTED_REQUEST_BYTES,
            max_encrypted_response_bytes: DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
            proof_type: TVC_APP_PROOF_TYPE.to_owned(),
            boot_proof_lookup_key: ephemeral.public_key().to_bytes(),
        }
    }

    async fn response_body(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn health_is_exact_and_unavailable_is_generic() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let service_info = info(&quorum, &ephemeral);

        let response = router(AppState::ready(service_info.clone(), ephemeral, quorum))
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, r#"{"status":"Healthy"}"#);

        let response = router(AppState::unavailable(service_info))
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response_body(response).await, r#"{"error":"Unavailable"}"#);
    }

    #[tokio::test]
    async fn info_is_untrusted_discovery_bound_to_runtime_public_keys() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let expected = info(&quorum, &ephemeral);
        let response = router(AppState::ready(expected.clone(), ephemeral, quorum))
            .oneshot(Request::get("/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let actual: ServiceInfoV1 = parse_strict_json(&response_body(response).await).unwrap();
        assert_eq!(actual, expected);
        assert!(actual.supported_operations.is_empty());
        assert_eq!(actual.boot_proof_lookup_key, actual.ephemeral_public_key);
    }

    #[tokio::test]
    async fn ping_decrypts_with_quorum_and_signs_exact_utf8_with_ephemeral() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let quorum_public = quorum.public_key();
        let ephemeral_public = ephemeral.public_key();
        let proof_payload = jcs_serialize(&QosPingChallengeV1 {
            r#type: TVC_QOS_PING_PROOF_TYPE.to_owned(),
            version: API_VERSION,
            challenge: [0x44; 32],
        })
        .unwrap();
        let encrypted_challenge = quorum_public.encrypt(proof_payload.as_bytes()).unwrap();
        let request_body = jcs_serialize(&QosPingRequestV1 {
            version: API_VERSION,
            encrypted_challenge,
        })
        .unwrap();
        let response = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ))
        .oneshot(
            Request::post("/v1/ping")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response: QosPingResponseV1 =
            parse_strict_json(&response_body(response).await).unwrap();
        let proof = response.tvc_app_proof;
        assert_eq!(proof.scheme, TVC_APP_PROOF_SCHEME);
        assert_eq!(proof.public_key, ephemeral_public.to_bytes());
        assert_eq!(proof.public_key.len(), QOS_P256_PUBLIC_LEN);
        assert_eq!(proof.proof_payload.as_bytes(), proof_payload.as_bytes());
        assert_eq!(proof.signature.len(), RAW_P256_SIGNATURE_LEN);
        ephemeral_public
            .verify(proof.proof_payload.as_bytes(), &proof.signature)
            .unwrap();
        assert!(quorum_public
            .verify(proof.proof_payload.as_bytes(), &proof.signature)
            .is_err());
        let parsed = QosP256Public::from_bytes(&proof.public_key).unwrap();
        verify_p256_message(
            &parsed.signing,
            proof.proof_payload.as_bytes(),
            &proof.signature,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn ping_rejects_ephemeral_encryption_and_noncanonical_plaintext_generically() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let noncanonical = format!(
            r#"{{"version":1,"type":"{TVC_QOS_PING_PROOF_TYPE}","challenge":"{}"}}"#,
            "55".repeat(32)
        );
        let cases = [
            ephemeral
                .public_key()
                .encrypt(b"not for the quorum")
                .unwrap(),
            quorum
                .public_key()
                .encrypt(noncanonical.as_bytes())
                .unwrap(),
        ];
        let app = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ));

        for encrypted_challenge in cases {
            let body = jcs_serialize(&QosPingRequestV1 {
                version: API_VERSION,
                encrypted_challenge,
            })
            .unwrap();
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/ping")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_body(response).await,
                r#"{"error":"InvalidRequest"}"#
            );
        }
    }

    #[tokio::test]
    async fn ping_rejects_wrong_method_and_oversized_body() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let app = router(AppState::ready(
            info(&quorum, &ephemeral),
            ephemeral,
            quorum,
        ));

        let response = app
            .clone()
            .oneshot(Request::get("/v1/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let response = app
            .oneshot(
                Request::post("/v1/ping")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![
                        0u8;
                        DEVNET_MAX_ENCRYPTED_REQUEST_BYTES as usize
                            + 1
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn qos_signatures_are_normalized_to_low_s_for_the_wire() {
        let message = b"zolana tvc low-s interop";
        for seed_byte in 0u8..=u8::MAX {
            let pair = P256Pair::from_master_seed(&Zeroizing::new([seed_byte; 32])).unwrap();
            let raw = pair.sign(message).unwrap();
            let raw = Signature::from_slice(&raw).unwrap();
            if raw.normalize_s().is_some() {
                let normalized = sign_ephemeral_low_s(&pair, message).unwrap();
                let normalized = Signature::from_slice(&normalized).unwrap();
                assert!(normalized.normalize_s().is_none());
                pair.public_key()
                    .verify(message, &normalized.to_bytes())
                    .unwrap();
                return;
            }
        }
        panic!("fixed QOS seed corpus did not produce a high-S signature");
    }
}
