use std::time::{Duration, Instant};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::{Bytes, BytesMut};
use cadence_macros::{statsd_count, statsd_time};
use reqwest::redirect::Policy;

use crate::config::EnclaveConfig;
use crate::error::ApiError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const JSON: HeaderValue = HeaderValue::from_static("application/json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Info,
    Ping,
    Operations,
}

impl Target {
    #[inline]
    const fn name(self) -> &'static str {
        match self {
            Self::Info => "enclave_info",
            Self::Ping => "enclave_ping",
            Self::Operations => "enclave_operations",
        }
    }
}

const ENCLAVE_UNAVAILABLE: ApiError = ApiError::Upstream("EnclaveUnavailable");

/// An enclave answer passed to the client: its status, content type and body.
pub struct Forwarded {
    status: StatusCode,
    content_type: HeaderValue,
    body: Bytes,
}

impl IntoResponse for Forwarded {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.body).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, self.content_type);
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// The TVC enclave's public ingress.
pub struct Enclave {
    http: reqwest::Client,
    config: EnclaveConfig,
}

impl Enclave {
    pub fn new(config: EnclaveConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .build()?;
        Ok(Self { http, config })
    }

    pub async fn info(&self) -> Result<Forwarded, ApiError> {
        let url = format!("{}/v1/info", self.config.base_url);
        self.send(Target::Info, self.http.get(url)).await
    }

    pub async fn ping(&self, body: Bytes) -> Result<Forwarded, ApiError> {
        let url = format!("{}/v1/ping", self.config.base_url);
        self.send(Target::Ping, self.post_json(url, body)).await
    }

    pub async fn operations(&self, body: Bytes) -> Result<Forwarded, ApiError> {
        let url = format!("{}/v1/operations", self.config.base_url);
        self.send(Target::Operations, self.post_json(url, body))
            .await
    }

    fn post_json(&self, url: String, body: Bytes) -> reqwest::RequestBuilder {
        self.http
            .post(url)
            .header(header::CONTENT_TYPE, JSON)
            .body(body)
    }

    async fn send(
        &self,
        target: Target,
        request: reqwest::RequestBuilder,
    ) -> Result<Forwarded, ApiError> {
        let started = Instant::now();
        let result = request
            .header(header::ACCEPT, JSON)
            .timeout(Duration::from_millis(self.config.request_timeout_ms))
            .send()
            .await;
        let response = result.map_err(|error| {
            tracing::warn!(target = target.name(), %error, "enclave request failed");
            statsd_count!("upstream.failed", 1, "target" => target.name());
            ENCLAVE_UNAVAILABLE
        })?;
        let status = response.status();
        statsd_time!("upstream.latency", started.elapsed(), "target" => target.name(), "status" => status.as_str());
        if status.is_server_error() {
            tracing::warn!(target = target.name(), %status, "enclave answered with a server error");
            return Err(ENCLAVE_UNAVAILABLE);
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or(JSON);
        let body = read_capped(target, response, self.config.max_body_bytes).await?;
        Ok(Forwarded {
            status,
            content_type,
            body,
        })
    }
}

async fn read_capped(
    target: Target,
    mut response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<Bytes, ApiError> {
    let too_large = || {
        statsd_count!("upstream.response_too_large", 1, "target" => target.name());
        ApiError::Upstream("UpstreamResponseTooLarge")
    };
    if response
        .content_length()
        .is_some_and(|len| len > max_body_bytes as u64)
    {
        return Err(too_large());
    }
    let mut body = BytesMut::new();
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            tracing::warn!(target = target.name(), %error, "enclave body read failed");
            ENCLAVE_UNAVAILABLE
        })?;
        let Some(chunk) = chunk else {
            return Ok(body.freeze());
        };
        if body.len().saturating_add(chunk.len()) > max_body_bytes {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
}
