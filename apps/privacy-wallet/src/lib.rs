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
    API_VERSION, PHASE0_MAX_ENCRYPTED_REQUEST_BYTES, PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
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
use local_dev::{handle_local_bootstrap, LocalWalletState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub security_domain_id: [u8; 32],
    pub release_id: String,
    pub quorum_key_id: String,
    pub quorum_key_epoch: u64,
}

struct RuntimeKeys {
    ephemeral: Arc<P256Pair>,
    quorum: Arc<P256Pair>,
}

#[derive(Clone)]
pub struct AppState {
    info: Arc<ServiceInfoV1>,
    keys: Option<Arc<RuntimeKeys>>,
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
            #[cfg(feature = "local-dev")]
            local_wallet: None,
            ready: true,
        }
    }

    pub fn unavailable(info: ServiceInfoV1) -> Self {
        Self {
            info: Arc::new(info),
            keys: None,
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
pub fn local_unattested_state(ephemeral: P256Pair, quorum: P256Pair) -> io::Result<AppState> {
    use zolana_tvc_protocol::digest::sha256;

    let ephemeral_public_key = ephemeral.public_key().to_bytes();
    let info = ServiceInfoV1 {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: sha256(b"ZOLANA_TVC_LOCAL_UNATTESTED_SECURITY_DOMAIN_V1"),
        release_id: "local-unattested-do-not-deploy".to_owned(),
        manifest_digest: sha256(b"ZOLANA_TVC_LOCAL_UNATTESTED_MANIFEST_V1"),
        executable_digest: sha256(b"ZOLANA_TVC_LOCAL_UNATTESTED_EXECUTABLE_V1"),
        quorum_public_key: quorum.public_key().to_bytes(),
        quorum_key_id: "local-unattested-quorum".to_owned(),
        quorum_key_epoch: 1,
        ephemeral_public_key: ephemeral_public_key.clone(),
        supported_operations: Vec::new(),
        max_encrypted_request_bytes: PHASE0_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: ephemeral_public_key,
    };

    Ok(AppState {
        info: Arc::new(info),
        keys: Some(Arc::new(RuntimeKeys {
            ephemeral: Arc::new(ephemeral),
            quorum: Arc::new(quorum),
        })),
        local_wallet: Some(Arc::new(LocalWalletState::generate()?)),
        ready: true,
    })
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
            OperationKind::BuildTransfer,
            OperationKind::BuildCustomRingTransfer,
            OperationKind::BuildSolWithdrawal,
            OperationKind::BuildCustomRingSolWithdrawal,
        ],
        max_encrypted_request_bytes: PHASE0_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
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
            .min(PHASE0_MAX_ENCRYPTED_REQUEST_BYTES),
    )
    .unwrap_or(usize::MAX);
    let body = match to_bytes(body, body_limit).await {
        Ok(body) => body,
        Err(_) => return into_response(public_http_error(PublicError::RequestTooLarge)),
    };

    #[cfg(feature = "local-dev")]
    if parts.uri.path() == "/dev/v1/bootstrap-ed25519" {
        if parts.method != Method::POST {
            return into_response(public_http_error(PublicError::MethodNotAllowed));
        }
        if !has_json_content_type(&parts.headers) {
            return into_response(public_http_error(PublicError::InvalidRequest));
        }
        return handle_local_bootstrap(state.local_wallet.as_deref(), &body).await;
    }

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
            max_encrypted_request_bytes: PHASE0_MAX_ENCRYPTED_REQUEST_BYTES,
            max_encrypted_response_bytes: PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
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
                        PHASE0_MAX_ENCRYPTED_REQUEST_BYTES as usize
                            + 1
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[cfg(feature = "local-dev")]
    #[tokio::test]
    async fn local_bootstrap_uses_real_turnkey_rail_and_is_explicitly_unattested() {
        let quorum = P256Pair::generate().unwrap();
        let ephemeral = P256Pair::generate().unwrap();
        let app = router(AppState {
            info: Arc::new(info(&quorum, &ephemeral)),
            keys: Some(Arc::new(RuntimeKeys {
                ephemeral: Arc::new(ephemeral),
                quorum: Arc::new(quorum),
            })),
            local_wallet: Some(Arc::new(LocalWalletState::deterministic([0x77; 32]))),
            ready: true,
        });
        let request = || {
            Request::post("/dev/v1/bootstrap-ed25519")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"version":1}"#))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first = response_body(first).await;
        assert!(first.contains(r#""trust":"local-unattested""#));
        assert!(first.contains(r#""custody":"disposable-in-process-mock-turnkey""#));
        assert!(first.contains(r#""solana_address":""#));
        assert!(!first.contains("secret"));

        let second = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response_body(second).await, first);

        let invalid = app
            .oneshot(
                Request::post("/dev/v1/bootstrap-ed25519")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"unknown":true,"version":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_body(invalid).await,
            r#"{"error":"InvalidRequest"}"#
        );
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
