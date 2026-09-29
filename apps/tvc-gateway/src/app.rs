use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use cadence_macros::statsd_time;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tower_http::set_header::SetResponseHeaderLayer;
use zolana_tvc_protocol::{EncryptedRequest, QosPingRequest, WalletDescriptor};

use crate::config::Config;
use crate::enrollment::{Enrollment, EnrollmentRequest};
use crate::error::ApiError;
use crate::json::ApiJson;
use crate::limits::InFlightLimiter;
use crate::project::Gatekeeper;
use crate::provisioner::{self, Provisioner};
use crate::replay::{Claim, Outcome, ReplayLedger};
use crate::turnkey::{ClaimedWallet, Turnkey};
use crate::upstream::Enclave;
use crate::wallet_grant::WalletGrants;

pub const ROUTE_PREFIX: &str = "/v1/private-wallet";
/// Marks an `/operations` answer that repeats an earlier request's outcome.
pub const IDEMPOTENT_REPLAYED: HeaderName = HeaderName::from_static("idempotent-replayed");

pub struct AppState {
    pub origin_auth_header: String,
    pub enclave: Enclave,
    pub turnkey: Turnkey,
    pub provisioner: Provisioner,
    pub enrollment: Enrollment,
    pub wallet_grants: WalletGrants,
    pub limiter: InFlightLimiter,
    pub replay: ReplayLedger,
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            origin_auth_header: config.origin_auth_header.clone(),
            enclave: Enclave::new(config.enclave.clone())?,
            turnkey: Turnkey::new(&config.turnkey)?,
            provisioner: Provisioner::new(&config.provisioning)?,
            enrollment: Enrollment::new(&config.enrollment.domain),
            wallet_grants: WalletGrants::new(&config.wallet_grant)?,
            limiter: InFlightLimiter::new(config.enclave.max_in_flight_per_project),
            replay: ReplayLedger::connect(
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
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
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
    ApiJson(ping): ApiJson<QosPingRequest>,
) -> Result<Response, ApiError> {
    let _permit = state.limiter.try_acquire(&project)?;
    let (info, ping) = tokio::try_join!(state.enclave.info(), state.enclave.ping(&ping))?;
    if !info.is_success() {
        return Ok(info.into_response());
    }
    if !ping.is_success() {
        return Ok(ping.into_response());
    }
    let boot_proof = state
        .turnkey
        .boot_proof(&app_proof_key(&ping.body)?)
        .await?;
    Ok(Json(Session {
        info: raw_json(&info.body)?,
        ping: raw_json(&ping.body)?,
        boot_proof: raw_json(&boot_proof)?,
    })
    .into_response())
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    ApiJson(request): ApiJson<EnrollmentRequest>,
) -> Result<Json<Enrolled>, ApiError> {
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
    Ok(Json(Enrolled { descriptor }))
}

/// Forwards the client's encrypted request with a wallet grant this gateway
/// signs for the descriptor's client key and the caller's project. A resent
/// request gets the first request's outcome.
async fn operations(
    State(state): State<Arc<AppState>>,
    Gatekeeper(project): Gatekeeper,
    ApiJson(Operation {
        descriptor,
        mut request,
    }): ApiJson<Operation>,
) -> Result<Response, ApiError> {
    state.provisioner.verify(&descriptor)?;
    let [client] = descriptor.allowed_clients.as_slice() else {
        return Err(ApiError::InvalidDescriptor);
    };
    state
        .wallet_grants
        .check_client_key(&client.client_public_key)?;
    let _permit = state.limiter.try_acquire(&project)?;
    let key = match state.replay.claim(&project, &request.ciphertext).await? {
        Claim::New(key) => key,
        Claim::Answered(outcome) => {
            let mut response = answer(&state, outcome).await;
            response
                .headers_mut()
                .insert(IDEMPOTENT_REPLAYED, HeaderValue::from_static("true"));
            return Ok(response);
        }
    };
    let granted = async {
        state
            .turnkey
            .verify_sub_org_project(&project, &descriptor.turnkey_organization_id)
            .await?;
        state
            .wallet_grants
            .issue(&project, &descriptor, clock_ms()?)
    }
    .await;
    let grant = match granted {
        Ok(grant) => grant,
        Err(error) => {
            state.replay.release(key).await;
            return Err(error);
        }
    };
    request.wallet_grant = Some(grant);
    let outcome = state.enclave.operations(&request).await;
    state.replay.record(key, &project, &outcome).await;
    Ok(answer(&state, outcome).await)
}

/// The client's answer to an enclave outcome: a success with the Boot Proof
/// of the replica that answered, the enclave's refusal as it is, or the
/// failure.
async fn answer(state: &AppState, outcome: Outcome) -> Response {
    let answered = async {
        let forwarded = outcome?;
        if !forwarded.is_success() {
            return Ok(forwarded.into_response());
        }
        let boot_proof = state
            .turnkey
            .boot_proof(&app_proof_key(&forwarded.body)?)
            .await?;
        Ok(Json(Operated {
            response: raw_json(&forwarded.body)?,
            boot_proof: raw_json(&boot_proof)?,
        })
        .into_response())
    }
    .await;
    answered.unwrap_or_else(|error: ApiError| error.into_response())
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

fn clock_ms() -> Result<u64, ApiError> {
    provisioner::now_ms().map_err(|error| {
        tracing::error!(%error, "system clock unavailable");
        ApiError::ClockUnavailable
    })
}

/// The Boot Proof lookup key of the replica that signed an enclave answer.
fn app_proof_key(body: &[u8]) -> Result<String, ApiError> {
    serde_json::from_slice::<AppProofCarrier>(body)
        .map(|carrier| carrier.tvc_app_proof.public_key)
        .map_err(|_| ApiError::InvalidEnclaveAnswer)
}

fn raw_json(body: &[u8]) -> Result<Box<RawValue>, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::InvalidEnclaveAnswer)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::config::EnclaveConfig;
    use crate::project::PROJECT_ID_HEADER;
    use crate::replay::LocalLedger;

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
        let enclave = Enclave::new(enclave).expect("test state did not build");
        Arc::new(AppState {
            origin_auth_header: ORIGIN_AUTH.to_owned(),
            enclave,
            turnkey: Turnkey::for_tests(UNREACHABLE),
            provisioner: crate::provisioner::tests::provisioner(),
            enrollment: Enrollment::new(crate::enrollment::tests::DOMAIN),
            wallet_grants: crate::wallet_grant::tests::grants(Vec::new()),
            limiter: InFlightLimiter::new(4),
            replay: ReplayLedger::Local(LocalLedger::new(Duration::from_secs(360), 1_000)),
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
        built.expect("test request did not build")
    }

    async fn call(state: &Arc<AppState>, request: HttpRequest<Body>) -> (StatusCode, String) {
        let response = match router(Arc::clone(state), 4_096).oneshot(request).await {
            Ok(response) => response,
            Err(infallible) => match infallible {},
        };
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .expect("body did not read");
        let problem_code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|problem| problem["code"].as_str().map(str::to_owned));
        (
            status,
            problem_code.unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned()),
        )
    }

    fn descriptor(state: &AppState) -> WalletDescriptor {
        state
            .provisioner
            .sign(&crate::enrollment::tests::input())
            .expect("descriptor did not sign")
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
        let bare = HttpRequest::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("test request did not build");
        assert_eq!(call(&state, bare).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn requests_without_gatekeepers_credential_or_project_are_refused() {
        let state = state();
        let mut unauthenticated = request("POST", "/v1/private-wallet/session", "{}");
        unauthenticated.headers_mut().remove(header::AUTHORIZATION);
        assert_eq!(
            call(&state, unauthenticated).await,
            (StatusCode::UNAUTHORIZED, "OriginAuthRequired".to_owned())
        );
        let mut anonymous = request("POST", "/v1/private-wallet/session", "{}");
        anonymous.headers_mut().remove(PROJECT_ID_HEADER);
        assert_eq!(
            call(&state, anonymous).await,
            (StatusCode::UNAUTHORIZED, "ProjectRequired".to_owned())
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
        assert_eq!(
            operations(r#"{"request":{}}"#.to_owned()).await,
            (StatusCode::BAD_REQUEST, "InvalidJson".to_owned())
        );
        let mut tampered = descriptor(&state);
        tampered.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e".to_owned();
        assert_eq!(
            operations(operation(&tampered, "abcd")).await,
            (StatusCode::FORBIDDEN, "InvalidDescriptor".to_owned())
        );
    }

    #[tokio::test]
    async fn a_ciphertext_that_never_reached_the_enclave_can_be_resent() {
        let state = state();
        let descriptor = descriptor(&state);
        let operations = |body: String| {
            call(
                &state,
                request("POST", "/v1/private-wallet/operations", &body),
            )
        };
        let unreachable_turnkey = (
            StatusCode::FAILED_DEPENDENCY,
            "TurnkeyUnavailable".to_owned(),
        );
        assert_eq!(
            operations(operation(&descriptor, "abcd")).await,
            unreachable_turnkey
        );
        assert_eq!(
            operations(operation(&descriptor, "abcd")).await,
            unreachable_turnkey
        );
    }

    #[tokio::test]
    async fn a_stale_or_malformed_enrollment_is_refused_before_turnkey_is_asked() {
        let state = state();
        let future = crate::enrollment::tests::signed_request(crate::enrollment::tests::NOW);
        let body = serde_json::json!({
            "organizationId": future.organization_id,
            "turnkeyWalletId": future.turnkey_wallet_id,
            "solanaAddress": future.solana_address,
            "clientPublicKey": future.client_public_key,
            "issuedAtMs": future.issued_at_ms,
            "ownerSignature": future.owner_signature,
        })
        .to_string();
        assert_eq!(
            call(&state, request("POST", "/v1/private-wallet/enroll", &body)).await,
            (StatusCode::BAD_REQUEST, "StaleEnrollment".to_owned())
        );
        assert_eq!(
            call(&state, request("POST", "/v1/private-wallet/enroll", "{}")).await,
            (StatusCode::BAD_REQUEST, "InvalidJson".to_owned())
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
