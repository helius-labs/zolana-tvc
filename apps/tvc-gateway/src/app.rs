use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use cadence_macros::statsd_time;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zolana_tvc_protocol::{EncryptedRequest, WalletDescriptor};

use crate::config::Config;
use crate::enrollment::{Enrollment, EnrollmentRequest};
use crate::error::ApiError;
use crate::limits::{InFlightLimiter, ReplayGuard};
use crate::project::Gatekeeper;
use crate::provisioner::{self, Provisioner};
use crate::turnkey::{ClaimedWallet, Turnkey};
use crate::upstream::Enclave;
use crate::wallet_grant::WalletGrants;

pub const ROUTE_PREFIX: &str = "/v1/private-wallet";

pub struct AppState {
    pub origin_auth_header: String,
    pub max_enclave_body_bytes: usize,
    pub enclave: Enclave,
    pub turnkey: Turnkey,
    pub provisioner: Provisioner,
    pub enrollment: Enrollment,
    pub wallet_grants: WalletGrants,
    pub limiter: InFlightLimiter,
    pub replay: ReplayGuard,
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            origin_auth_header: config.origin_auth_header.clone(),
            max_enclave_body_bytes: config.enclave.max_body_bytes,
            enclave: Enclave::new(config.enclave.clone())?,
            turnkey: Turnkey::new(&config.turnkey)?,
            provisioner: Provisioner::new(&config.provisioning)?,
            enrollment: Enrollment::new(&config.turnkey.waas_parent_organization_id),
            wallet_grants: WalletGrants::new(&config.wallet_grant)?,
            limiter: InFlightLimiter::new(config.enclave.max_in_flight_per_project),
            replay: ReplayGuard::connect(
                Duration::from_secs(config.enclave.replay_window_secs),
                config.enclave.replay_max_entries,
                config.enclave.replay_redis_url.as_deref(),
            )
            .await?,
        })
    }
}

pub fn router(state: Arc<AppState>, max_body_bytes: usize) -> Router {
    let private_wallet = Router::new()
        .route("/session", post(session))
        .route("/enroll", post(enroll))
        .route("/operations", post(operations));
    Router::new()
        .route("/health", get(health))
        .nest(ROUTE_PREFIX, private_wallet)
        .fallback(not_found)
        .layer(middleware::from_fn(track))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

/// `/session`: the enclave's discovery document, its answer to the client's
/// encrypted ping, and the Boot Proof of the replica that answered.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Session {
    info: Box<RawValue>,
    ping: Box<RawValue>,
    boot_proof: Box<RawValue>,
}

#[derive(Serialize)]
struct Enrolled {
    descriptor: WalletDescriptor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    descriptor: WalletDescriptor,
    request: EncryptedRequest,
}

/// `/operations`: the enclave's encrypted response and the Boot Proof of the
/// replica that answered.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Operated {
    response: Box<RawValue>,
    boot_proof: Box<RawValue>,
}

/// The app proof an enclave answer carries, as far as locating its Boot Proof.
#[derive(Deserialize)]
struct AppProofCarrier {
    tvc_app_proof: AppProofKey,
}

#[derive(Deserialize)]
struct AppProofKey {
    public_key: String,
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

/// The body is the enclave ping request, whose challenge the client encrypted
/// to the quorum key it pins.
async fn session(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Response, ApiError> {
    state.check_enclave_body(&body)?;
    let _permit = state.limiter.try_acquire(&project)?;
    let (info, ping) = tokio::try_join!(state.enclave.info(), state.enclave.ping(body))?;
    if !info.is_success() {
        return Ok(info.into_response());
    }
    if !ping.is_success() {
        return Ok(ping.into_response());
    }
    let boot_proof = state
        .turnkey
        .boot_proof(&app_proof_key(ping.body())?)
        .await?;
    Ok(no_store(Json(Session {
        info: raw_json(info.body())?,
        ping: raw_json(ping.body())?,
        boot_proof: raw_json(&boot_proof)?,
    })))
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request: EnrollmentRequest = parse_json(&body)?;
    let (input, _) = state.enrollment.verify(&request, clock_ms()?)?;
    state
        .wallet_grants
        .check_client_key(&input.client_public_key)?;
    let wallet = ClaimedWallet {
        organization_id: &input.organization_id,
        wallet_id: &input.turnkey_wallet_id,
        address: &input.solana_address,
    };
    state.turnkey.verify_ownership(&project, &wallet).await?;
    let descriptor = state.provisioner.sign(&input)?;
    Ok(no_store(Json(Enrolled { descriptor })))
}

/// Forwards the client's encrypted request with a wallet grant this gateway
/// signs for the descriptor's client key and the caller's project.
async fn operations(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Response, ApiError> {
    state.check_enclave_body(&body)?;
    let Operation {
        descriptor,
        mut request,
    } = serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest("InvalidOperation"))?;
    state.provisioner.verify(&descriptor)?;
    let [client] = descriptor.allowed_clients.as_slice() else {
        return Err(ApiError::Forbidden("InvalidDescriptor"));
    };
    state
        .wallet_grants
        .check_client_key(&client.client_public_key)?;
    let _permit = state.limiter.try_acquire(&project)?;
    state.replay.check(&request.ciphertext).await?;
    state
        .turnkey
        .verify_sub_org_project(&project, &descriptor.turnkey_organization_id)
        .await?;
    request.wallet_grant = Some(
        state
            .wallet_grants
            .issue(&project, &descriptor, clock_ms()?)?,
    );
    let forwarded_body = serde_json::to_vec(&request).map_err(|error| {
        tracing::error!(%error, "encrypted request did not serialize");
        ApiError::BadRequest("InvalidOperation")
    })?;
    let forwarded = state
        .enclave
        .operations(Bytes::from(forwarded_body))
        .await?;
    if !forwarded.is_success() {
        return Ok(forwarded.into_response());
    }
    let boot_proof = state
        .turnkey
        .boot_proof(&app_proof_key(forwarded.body())?)
        .await?;
    Ok(no_store(Json(Operated {
        response: raw_json(forwarded.body())?,
        boot_proof: raw_json(&boot_proof)?,
    })))
}

async fn track(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("unmatched", |path| route_name(path.as_str()));
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    statsd_time!("request.latency", started.elapsed(), "route" => route, "status" => status.as_str());
    response
}

fn route_name(matched: &str) -> &'static str {
    match matched.strip_prefix(ROUTE_PREFIX) {
        Some("/session") => "session",
        Some("/enroll") => "enroll",
        Some("/operations") => "operations",
        Some(_) | None => "other",
    }
}

impl AppState {
    fn check_enclave_body(&self, body: &Bytes) -> Result<(), ApiError> {
        if body.len() > self.max_enclave_body_bytes {
            return Err(ApiError::RequestTooLarge);
        }
        Ok(())
    }
}

fn parse_json<'a, T: Deserialize<'a>>(body: &'a Bytes) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("InvalidJson"))
}

fn clock_ms() -> Result<u64, ApiError> {
    provisioner::now_ms().map_err(|error| {
        tracing::error!(%error, "system clock unavailable");
        ApiError::Unavailable("ClockUnavailable")
    })
}

/// The Boot Proof lookup key of the replica that signed an enclave answer.
fn app_proof_key(body: &[u8]) -> Result<String, ApiError> {
    serde_json::from_slice::<AppProofCarrier>(body)
        .map(|carrier| carrier.tvc_app_proof.public_key)
        .map_err(|_| ApiError::Upstream("InvalidEnclaveAnswer"))
}

fn raw_json(body: &[u8]) -> Result<Box<RawValue>, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::Upstream("InvalidEnclaveAnswer"))
}

fn no_store(answer: impl IntoResponse) -> Response {
    let mut response = answer.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::config::EnclaveConfig;
    use crate::limits::LocalReplayGuard;
    use crate::project::PROJECT_ID_HEADER;

    const ORIGIN_AUTH: &str = "Bearer gatekeeper-test";
    const PROJECT: &str = "project-a";
    const UNREACHABLE: &str = "http://127.0.0.1:9";

    fn state() -> Arc<AppState> {
        crate::metrics::init_for_tests();
        let enclave = EnclaveConfig {
            base_url: UNREACHABLE.to_owned(),
            request_timeout_ms: 2_000,
            max_body_bytes: 4_096,
            max_in_flight_per_project: 4,
            replay_window_secs: 360,
            replay_max_entries: 1_000,
            replay_redis_url: None,
        };
        let Ok(enclave) = Enclave::new(enclave) else {
            panic!("test state did not build");
        };
        Arc::new(AppState {
            origin_auth_header: ORIGIN_AUTH.to_owned(),
            max_enclave_body_bytes: 4_096,
            enclave,
            turnkey: Turnkey::for_tests(UNREACHABLE),
            provisioner: crate::provisioner::tests::provisioner(),
            enrollment: Enrollment::new(crate::enrollment::tests::PARENT),
            wallet_grants: crate::wallet_grant::tests::grants(Vec::new()),
            limiter: InFlightLimiter::new(4),
            replay: ReplayGuard::Local(LocalReplayGuard::new(Duration::from_secs(360), 1_000)),
        })
    }

    fn request(method: &str, path: &str, body: &str) -> HttpRequest<Body> {
        let built = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, ORIGIN_AUTH)
            .header(PROJECT_ID_HEADER, PROJECT)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()));
        let Ok(built) = built else {
            panic!("test request did not build");
        };
        built
    }

    async fn call(state: &Arc<AppState>, request: HttpRequest<Body>) -> (StatusCode, String) {
        let response = match router(Arc::clone(state), 16_384).oneshot(request).await {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        };
        let status = response.status();
        let Ok(body) = axum::body::to_bytes(response.into_body(), 65_536).await else {
            panic!("body did not read");
        };
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn descriptor(state: &AppState) -> WalletDescriptor {
        let Ok(descriptor) = state.provisioner.sign(&crate::enrollment::tests::input()) else {
            panic!("descriptor did not sign");
        };
        descriptor
    }

    fn operation(descriptor: &WalletDescriptor, ciphertext: &str) -> String {
        serde_json::json!({
            "descriptor": descriptor,
            "request": {
                "version": 1,
                "quorum_key_id": "q",
                "quorum_key_epoch": "1",
                "ciphertext": ciphertext,
            },
        })
        .to_string()
    }

    #[tokio::test]
    async fn health_needs_no_credentials() {
        let state = state();
        let Ok(bare) = HttpRequest::builder().uri("/health").body(Body::empty()) else {
            panic!("test request did not build");
        };
        assert_eq!(call(&state, bare).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn requests_without_gatekeepers_credential_or_project_are_refused() {
        let state = state();
        let mut unauthenticated = request("POST", "/v1/private-wallet/session", "{}");
        unauthenticated.headers_mut().remove(header::AUTHORIZATION);
        assert_eq!(
            call(&state, unauthenticated).await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"OriginAuthRequired"}"#.to_owned()
            )
        );
        let mut anonymous = request("POST", "/v1/private-wallet/session", "{}");
        anonymous.headers_mut().remove(PROJECT_ID_HEADER);
        assert_eq!(
            call(&state, anonymous).await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"ProjectRequired"}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn an_operation_needs_a_descriptor_this_gateway_provisioned() {
        let state = state();
        let operations = |body: String| {
            call(
                &state,
                request("POST", "/v1/private-wallet/operations", &body),
            )
        };
        let invalid_operation = (
            StatusCode::BAD_REQUEST,
            r#"{"error":"InvalidOperation"}"#.to_owned(),
        );
        assert_eq!(
            operations(r#"{"request":{}}"#.to_owned()).await,
            invalid_operation
        );
        let mut tampered = descriptor(&state);
        tampered.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e".to_owned();
        assert_eq!(
            operations(operation(&tampered, "abcd")).await,
            (
                StatusCode::FORBIDDEN,
                r#"{"error":"InvalidDescriptor"}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn a_resent_ciphertext_is_refused_before_turnkey_is_asked() {
        let state = state();
        let descriptor = descriptor(&state);
        let operations = |body: String| {
            call(
                &state,
                request("POST", "/v1/private-wallet/operations", &body),
            )
        };
        let first = operations(operation(&descriptor, "abcd")).await;
        assert_eq!(first.0, StatusCode::FAILED_DEPENDENCY);
        let replayed = (
            StatusCode::CONFLICT,
            r#"{"error":"ReplayedRequest"}"#.to_owned(),
        );
        assert_eq!(operations(operation(&descriptor, "abcd")).await, replayed);
        let reordered = format!(
            r#"{{"request":{{"ciphertext":"abcd","quorum_key_epoch":"1","quorum_key_id":"q","version":1}},"descriptor":{}}}"#,
            serde_json::to_string(&descriptor).unwrap_or_default()
        );
        assert_eq!(operations(reordered).await, replayed);
    }

    #[tokio::test]
    async fn a_stale_or_malformed_enrollment_is_refused_before_turnkey_is_asked() {
        let state = state();
        let future = crate::enrollment::tests::signed_request(crate::enrollment::tests::NOW);
        let body = serde_json::json!({
            "parentOrganizationId": future.parent_organization_id,
            "organizationId": future.organization_id,
            "walletName": future.wallet_name,
            "turnkeyWalletId": future.turnkey_wallet_id,
            "solanaAddress": future.solana_address,
            "clientPublicKey": future.client_public_key,
            "issuedAtMs": future.issued_at_ms,
            "ownerSignature": future.owner_signature,
        })
        .to_string();
        assert_eq!(
            call(&state, request("POST", "/v1/private-wallet/enroll", &body)).await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"StaleEnrollment"}"#.to_owned()
            )
        );
        assert_eq!(
            call(&state, request("POST", "/v1/private-wallet/enroll", "{}")).await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"InvalidJson"}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn oversized_enclave_bodies_and_other_routes_are_refused() {
        let state = state();
        let oversized = "x".repeat(8_192);
        assert_eq!(
            call(
                &state,
                request("POST", "/v1/private-wallet/session", &oversized)
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        for (method, path) in [
            ("GET", "/v1/private-wallet/info"),
            ("POST", "/v1/private-wallet/ping"),
            ("GET", "/v1/private-wallet/policy"),
            ("POST", "/v1/private-wallet/wallet-grant"),
            ("POST", "/v1/private-wallet/enrollment-challenge"),
        ] {
            assert_eq!(
                call(&state, request(method, path, "{}")).await.0,
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }
}
