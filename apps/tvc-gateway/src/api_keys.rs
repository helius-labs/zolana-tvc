//! Helius API keys a direct caller sends, resolved to their project by the
//! Helius API's `GET /waas/config`.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use cadence_macros::statsd_count;
use reqwest::StatusCode;
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::HeliusApiConfig;
use crate::error::ApiError;
use crate::project::ProjectId;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const REJECTION_TTL: Duration = Duration::from_secs(30);
const CACHE_CAPACITY: usize = 100_000;
const MAX_API_KEY_LEN: usize = 64;

/// `GET /waas/config`, as far as the project.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaasConfig {
    project_id: Option<String>,
}

/// A key's project, or `None` for a key the Helius API refused.
type Resolved = Option<ProjectId>;

pub struct ApiKeys {
    http: reqwest::Client,
    waas_config_url: String,
    project_ttl: Duration,
    /// Keyed by the SHA-256 of the API key.
    cache: Mutex<HashMap<[u8; 32], (Resolved, Instant)>>,
}

impl ApiKeys {
    pub fn new(config: &HeliusApiConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(LOOKUP_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            waas_config_url: format!("{}/waas/config", config.base_url),
            project_ttl: Duration::from_secs(config.project_cache_secs),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The project `api_key` belongs to.
    pub async fn project(&self, api_key: &str) -> Result<ProjectId, ApiError> {
        if !is_api_key(api_key) {
            statsd_count!("api_key.rejected", 1, "reason" => "shape");
            return Err(ApiError::ApiKeyInvalid);
        }
        let digest: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        let resolved = match self.cached(&digest) {
            Some(resolved) => {
                statsd_count!("api_key.cache_hit", 1);
                resolved
            }
            None => {
                let resolved = self.fetch(api_key).await?;
                self.store(digest, resolved.clone());
                resolved
            }
        };
        resolved.ok_or_else(|| {
            statsd_count!("api_key.rejected", 1, "reason" => "unknown");
            ApiError::ApiKeyInvalid
        })
    }

    async fn fetch(&self, api_key: &str) -> Result<Resolved, ApiError> {
        let response = self
            .http
            .get(&self.waas_config_url)
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(lookup_failed)?;
        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => return Ok(None),
            status if !status.is_success() => return Err(lookup_failed(status)),
            _ => {}
        }
        let config: WaasConfig = response.json().await.map_err(lookup_failed)?;
        let project = config.project_id.as_deref().and_then(ProjectId::parse);
        project
            .map(Some)
            .ok_or_else(|| lookup_failed("the answer names no valid projectId"))
    }

    fn cached(&self, digest: &[u8; 32]) -> Option<Resolved> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let (resolved, fetched_at) = cache.get(digest)?;
        let ttl = if resolved.is_some() {
            self.project_ttl
        } else {
            REJECTION_TTL
        };
        (fetched_at.elapsed() < ttl).then(|| resolved.clone())
    }

    fn store(&self, digest: [u8; 32], resolved: Resolved) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(digest, (resolved, Instant::now()));
    }
}

fn lookup_failed(reason: impl Display) -> ApiError {
    tracing::warn!(%reason, "api key lookup failed");
    statsd_count!("api_key.lookup_failed", 1);
    ApiError::HeliusApiUnavailable
}

/// A Helius API key is a UUID; anything else is refused before the lookup.
#[inline]
fn is_api_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_API_KEY_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
impl ApiKeys {
    pub(crate) fn for_tests(base_url: &str) -> Self {
        Self::new(&HeliusApiConfig {
            base_url: base_url.to_owned(),
            project_cache_secs: 300,
        })
        .expect("test api keys did not build")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::http::HeaderMap;
    use axum::response::{IntoResponse, Json};
    use axum::routing::get;

    use super::*;

    const KEY: &str = "0b4a3a9e-5f7e-4b4f-9c1e-0d9f2a1b3c4d";
    const FAILING_KEY: &str = "5e5e5e5e-5f7e-4b4f-9c1e-0d9f2a1b3c4d";

    /// A Helius API that knows `KEY` as `project-a`, fails for `FAILING_KEY`,
    /// and counts its lookups.
    async fn helius_api() -> (String, Arc<AtomicUsize>) {
        crate::metrics::init_for_tests();
        let lookups = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&lookups);
        let app = Router::new().route(
            "/v0/waas/config",
            get(move |headers: HeaderMap| {
                counted.fetch_add(1, Ordering::SeqCst);
                async move {
                    match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
                        Some(KEY) => Json(serde_json::json!({
                            "projectId": "project-a",
                            "organizationId": "9b98a0d8-04a4-47a3-9dc3-afa84c686de4",
                        }))
                        .into_response(),
                        Some(FAILING_KEY) => StatusCode::BAD_GATEWAY.into_response(),
                        _ => StatusCode::UNAUTHORIZED.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let address = listener.local_addr().expect("listener has an address");
        tokio::spawn(async move { axum::serve(listener, app).await });
        (format!("http://{address}/v0"), lookups)
    }

    #[tokio::test]
    async fn a_known_key_resolves_to_its_project_once_per_ttl() {
        let (url, lookups) = helius_api().await;
        let keys = ApiKeys::for_tests(&url);
        for _ in 0..3 {
            assert_eq!(
                keys.project(KEY).await,
                Ok(ProjectId::for_tests("project-a"))
            );
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_key_is_refused_and_the_refusal_is_cached() {
        let (url, lookups) = helius_api().await;
        let keys = ApiKeys::for_tests(&url);
        let unknown = "11111111-2222-4333-8444-555555555555";
        for _ in 0..2 {
            assert_eq!(keys.project(unknown).await, Err(ApiError::ApiKeyInvalid));
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_malformed_key_is_refused_without_a_lookup() {
        let (url, lookups) = helius_api().await;
        let keys = ApiKeys::for_tests(&url);
        for malformed in ["", "a b", "key%20", &"a".repeat(65)] {
            assert_eq!(keys.project(malformed).await, Err(ApiError::ApiKeyInvalid));
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failed_lookup_is_a_424_and_is_not_cached() {
        let (url, lookups) = helius_api().await;
        let keys = ApiKeys::for_tests(&url);
        for _ in 0..2 {
            assert_eq!(
                keys.project(FAILING_KEY).await,
                Err(ApiError::HeliusApiUnavailable)
            );
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
        let unreachable = ApiKeys::for_tests("http://127.0.0.1:9");
        assert_eq!(
            unreachable.project(KEY).await,
            Err(ApiError::HeliusApiUnavailable)
        );
    }
}
