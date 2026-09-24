use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Path, Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use cadence_macros::statsd_time;
use serde::{Deserialize, Serialize};
use zolana_tvc_protocol::{EncryptedRequest, WalletDescriptor, WalletGrant};

use crate::config::Config;
use crate::enrollment::{Challenge, Enrollment, EnrollmentRequest, Redemption};
use crate::error::ApiError;
use crate::limits::{InFlightLimiter, ReplayGuard};
use crate::project::Gatekeeper;
use crate::provisioner::{self, Provisioner};
use crate::turnkey::{ClaimedWallet, Turnkey};
use crate::upstream::{Enclave, Forwarded};
use crate::wallet_grant::{self, Renewal, WalletGrants};

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
            enrollment: Enrollment::new(
                &config.provisioning.enrollment_secret,
                &config.turnkey.waas_parent_organization_id,
            )?,
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
        .route("/info", get(info))
        .route("/ping", post(ping))
        .route("/operations", post(operations))
        .route("/boot-proof/{ephemeral_key}", get(boot_proof))
        .route("/policy", get(policy))
        .route("/enrollment-challenge", post(enrollment_challenge))
        .route("/provision-descriptor", post(provision_descriptor))
        .route("/wallet-grant", post(renew_wallet_grant));
    Router::new()
        .route("/health", get(health))
        .nest(ROUTE_PREFIX, private_wallet)
        .fallback(not_found)
        .layer(middleware::from_fn(track))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProvisionedWallet {
    descriptor: WalletDescriptor,
    wallet_grant: WalletGrant,
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

async fn info(
    State(state): State<Arc<AppState>>,
    Gatekeeper(_): Gatekeeper,
) -> Result<Forwarded, ApiError> {
    state.enclave.info().await
}

async fn ping(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Forwarded, ApiError> {
    state.check_enclave_body(&body)?;
    let _permit = state.limiter.try_acquire(&project)?;
    state.enclave.ping(body).await
}

async fn operations(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Forwarded, ApiError> {
    state.check_enclave_body(&body)?;
    let encrypted: EncryptedRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("InvalidEncryptedRequest"))?;
    let grant = encrypted
        .wallet_grant
        .as_ref()
        .ok_or(ApiError::Unauthorized("WalletGrantRequired"))?;
    state.wallet_grants.verify(grant, &project, clock_ms()?)?;
    let _permit = state.limiter.try_acquire(&project)?;
    state.replay.check(&encrypted.ciphertext).await?;
    state.enclave.operations(body).await
}

async fn boot_proof(
    State(state): State<Arc<AppState>>,
    Gatekeeper(_): Gatekeeper,
    Path(ephemeral_key): Path<String>,
) -> Result<Response, ApiError> {
    let body = state.turnkey.boot_proof(&ephemeral_key).await?;
    Ok(json_bytes(body, "public, max-age=86400, immutable"))
}

async fn policy(State(state): State<Arc<AppState>>, Gatekeeper(_): Gatekeeper) -> Response {
    json_bytes(state.provisioner.signed_policy_json(), "no-cache")
}

async fn enrollment_challenge(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Json<Challenge>, ApiError> {
    let request: EnrollmentRequest = parse_json(&body)?;
    let nonce = rand::random::<[u8; 16]>();
    let challenge = state
        .enrollment
        .challenge(request, &project, clock_ms()?, nonce)?;
    Ok(Json(challenge))
}

async fn provision_descriptor(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Json<ProvisionedWallet>, ApiError> {
    let redemption: Redemption = parse_json(&body)?;
    let now_ms = clock_ms()?;
    let input = state.enrollment.redeem(&redemption, &project, now_ms)?;
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
    let wallet_grant = state.wallet_grants.issue(&project, &descriptor, now_ms)?;
    Ok(Json(ProvisionedWallet {
        descriptor,
        wallet_grant,
    }))
}

async fn renew_wallet_grant(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    body: Bytes,
) -> Result<Json<WalletGrant>, ApiError> {
    let renewal: Renewal = parse_json(&body)?;
    let now_ms = clock_ms()?;
    state.provisioner.verify(&renewal.descriptor)?;
    wallet_grant::verify_renewal(&renewal, now_ms)?;
    let organization_id = &renewal.descriptor.turnkey_organization_id;
    state
        .turnkey
        .verify_sub_org_project(&project, organization_id)
        .await?;
    let grant = state
        .wallet_grants
        .issue(&project, &renewal.descriptor, now_ms)?;
    Ok(Json(grant))
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
        Some("/info") => "info",
        Some("/ping") => "ping",
        Some("/operations") => "operations",
        Some("/boot-proof/{ephemeral_key}") => "boot_proof",
        Some("/policy") => "policy",
        Some("/enrollment-challenge") => "enrollment_challenge",
        Some("/provision-descriptor") => "provision_descriptor",
        Some("/wallet-grant") => "wallet_grant",
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

fn json_bytes(body: Bytes, cache_control: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
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
    use crate::project::{PROJECT_ID_HEADER, ProjectId};

    const ORIGIN_AUTH: &str = "Bearer gatekeeper-test";
    const PROJECT: &str = "project-a";
    const UNREACHABLE: &str = "http://127.0.0.1:9";

    fn state() -> Arc<AppState> {
        crate::metrics::init_for_tests();
        let enclave = EnclaveConfig {
            base_url: UNREACHABLE.to_owned(),
            request_timeout_ms: 2_000,
            max_body_bytes: 1_024,
            max_in_flight_per_project: 4,
            replay_window_secs: 360,
            replay_max_entries: 1_000,
            replay_redis_url: None,
        };
        let (Ok(enclave), Ok(enrollment)) = (
            Enclave::new(enclave),
            Enrollment::new(
                "fedcba9876543210fedcba9876543210",
                crate::enrollment::tests::PARENT,
            ),
        ) else {
            panic!("test state did not build");
        };
        Arc::new(AppState {
            origin_auth_header: ORIGIN_AUTH.to_owned(),
            max_enclave_body_bytes: 1_024,
            enclave,
            turnkey: Turnkey::for_tests(UNREACHABLE),
            provisioner: crate::provisioner::tests::provisioner(),
            enrollment,
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
        let response = match router(Arc::clone(state), 8_192).oneshot(request).await {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        };
        let status = response.status();
        let Ok(body) = axum::body::to_bytes(response.into_body(), 65_536).await else {
            panic!("body did not read");
        };
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn wallet_grant(state: &AppState) -> WalletGrant {
        let Ok(descriptor) = state.provisioner.sign(&crate::enrollment::tests::input()) else {
            panic!("descriptor did not sign");
        };
        let project = ProjectId::for_tests(PROJECT);
        let Ok(grant) = state
            .wallet_grants
            .issue(&project, &descriptor, clock_ms().unwrap_or(0))
        else {
            panic!("wallet grant did not issue");
        };
        grant
    }

    fn encrypted_request(ciphertext: &str, grant: Option<&WalletGrant>) -> String {
        let mut value = serde_json::json!({
            "version": 1,
            "quorum_key_id": "q",
            "quorum_key_epoch": "1",
            "ciphertext": ciphertext,
        });
        if let Some(grant) = grant {
            value["wallet_grant"] = serde_json::json!(grant);
        }
        value.to_string()
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
        let mut unauthenticated = request("GET", "/v1/private-wallet/policy", "");
        unauthenticated.headers_mut().remove(header::AUTHORIZATION);
        assert_eq!(
            call(&state, unauthenticated).await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"OriginAuthRequired"}"#.to_owned()
            )
        );
        let mut anonymous = request("GET", "/v1/private-wallet/policy", "");
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
    async fn operations_need_a_wallet_grant_for_the_callers_project() {
        let state = state();
        let operations = |body: String| {
            call(
                &state,
                request("POST", "/v1/private-wallet/operations", &body),
            )
        };
        assert_eq!(
            operations(encrypted_request("abcd", None)).await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"WalletGrantRequired"}"#.to_owned()
            )
        );
        let mut forged = wallet_grant(&state);
        forged.expires_at_ms = forged.expires_at_ms.saturating_add(1);
        assert_eq!(
            operations(encrypted_request("abcd", Some(&forged))).await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"error":"InvalidWalletGrant"}"#.to_owned()
            )
        );
        let body = encrypted_request("abcd", Some(&wallet_grant(&state)));
        let mut other_project = request("POST", "/v1/private-wallet/operations", &body);
        other_project
            .headers_mut()
            .insert(PROJECT_ID_HEADER, HeaderValue::from_static("project-b"));
        assert_eq!(
            call(&state, other_project).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn an_unreachable_enclave_is_a_424_and_a_resent_ciphertext_is_refused() {
        let state = state();
        let grant = wallet_grant(&state);
        let operations = |body: String| {
            call(
                &state,
                request("POST", "/v1/private-wallet/operations", &body),
            )
        };
        let original = encrypted_request("abcd", Some(&grant));
        let grant_json = serde_json::to_string(&grant).unwrap_or_default();
        let reencoded = format!(
            r#"{{ "wallet_grant": {grant_json}, "ciphertext": "abcd", "quorum_key_epoch": "1", "quorum_key_id": "q", "version": 1 }}"#
        );
        let unavailable = (
            StatusCode::FAILED_DEPENDENCY,
            r#"{"error":"EnclaveUnavailable"}"#.to_owned(),
        );
        let replayed = (
            StatusCode::CONFLICT,
            r#"{"error":"ReplayedRequest"}"#.to_owned(),
        );
        assert_eq!(operations(original.clone()).await, unavailable);
        assert_eq!(operations(original).await, replayed);
        assert_eq!(operations(reencoded).await, replayed);
        assert_eq!(
            operations(r#"{"version":1}"#.to_owned()).await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"InvalidEncryptedRequest"}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn oversized_enclave_bodies_and_unknown_routes_are_refused() {
        let state = state();
        let oversized = "x".repeat(2_048);
        assert_eq!(
            call(
                &state,
                request("POST", "/v1/private-wallet/ping", &oversized)
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            call(
                &state,
                request("POST", "/v1/private-wallet/zolana/indexer/getSlot", "{}")
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&state, request("GET", "/v1/private-wallet/nope", ""))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn a_malformed_ephemeral_key_is_refused_before_turnkey() {
        let state = state();
        assert_eq!(
            call(
                &state,
                request("GET", "/v1/private-wallet/boot-proof/abc", "")
            )
            .await,
            (
                StatusCode::BAD_REQUEST,
                r#"{"error":"InvalidEphemeralKey"}"#.to_owned()
            )
        );
    }
}
