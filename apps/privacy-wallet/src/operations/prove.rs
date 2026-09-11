//! Proving: the one place the nullifier secret is consumed rather than derived
//! from. The client assembles the whole prover request, with `null` in every
//! nullifier secret slot that is this wallet's to fill; the enclave fills those
//! slots, changes nothing else, and forwards the request to the pinned prover.
//!
//! Ownership of the inputs is not checked: a slot filled for a UTXO this wallet
//! does not own yields a witness the circuit rejects, and a proof reveals
//! nothing about the secret either way. The prover sees the plaintext witness,
//! as documented in the network boundary.

use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use zolana_tvc_protocol::constants::MAX_PROVE_INPUTS;
use zolana_tvc_protocol::types::{FailureStage, OperationResult};

use super::Failure;

const PROVE_PATH: &str = "/prove";
const STATUS_PATH: &str = "/prove/status";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The prover's answer is a proof, kilobytes at most.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Writes `secret` as the prover's field encoding: the big-endian integer in
/// lowercase hex without leading zeros, as the Zolana SDK writes every field.
fn field_hex(secret: &[u8]) -> String {
    let hex = hex::encode(secret);
    let digits = hex.trim_start_matches('0');
    format!("0x{}", if digits.is_empty() { "0" } else { digits })
}

fn fill(slot: &mut Value, secret: &str, filled: &mut usize) -> Result<(), Failure> {
    match slot {
        Value::Null => {
            *slot = Value::String(secret.to_owned());
            *filled += 1;
            Ok(())
        }
        Value::String(_) => Ok(()),
        _ => Err(Failure::Invalid),
    }
}

fn object(value: &mut Value) -> Result<&mut Map<String, Value>, Failure> {
    value.as_object_mut().ok_or(Failure::Invalid)
}

/// The request with this wallet's secret in every open slot. Refuses a body
/// that names an unknown circuit, that has no slot to fill, or that asks for
/// the secret in a padding slot.
pub(super) fn complete(request: &Value, nullifier_secret: &[u8]) -> Result<Value, Failure> {
    let mut request = request.clone();
    let body = object(&mut request)?;
    let circuit = body
        .get("circuitType")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?
        .to_owned();
    let secret = field_hex(nullifier_secret);
    let mut filled = 0;
    match circuit.as_str() {
        "transfer-confidential" | "transfer-ring" => {
            let inputs = body
                .get_mut("inputs")
                .and_then(Value::as_array_mut)
                .ok_or(Failure::Invalid)?;
            if inputs.is_empty() || inputs.len() > MAX_PROVE_INPUTS {
                return Err(Failure::Invalid);
            }
            for input in inputs {
                let input = object(input)?;
                let dummy = input
                    .get("isDummy")
                    .and_then(Value::as_str)
                    .ok_or(Failure::Invalid)?
                    != "0x0";
                let slot = input.get_mut("nullifierSecret").ok_or(Failure::Invalid)?;
                if dummy && slot.is_null() {
                    return Err(Failure::Invalid);
                }
                fill(slot, &secret, &mut filled)?;
            }
        }
        "merge" => {
            let inputs = body
                .get("inputs")
                .and_then(Value::as_array)
                .ok_or(Failure::Invalid)?;
            if inputs.is_empty() || inputs.len() > MAX_PROVE_INPUTS {
                return Err(Failure::Invalid);
            }
            let slot = body
                .get_mut("userNullifierSecret")
                .ok_or(Failure::Invalid)?;
            fill(slot, &secret, &mut filled)?;
        }
        _ => return Err(Failure::Invalid),
    }
    if filled == 0 {
        return Err(Failure::Invalid);
    }
    Ok(request)
}

/// The pinned prover. `X-Sync` asks for the proof in the response; a prover
/// that queues instead answers with a job id, which is polled until the
/// deadline. The origin is compiled in, so its scheme is the policy: an
/// `https` origin never downgrades, and redirects are refused either way.
pub(super) struct Prover {
    client: reqwest::Client,
    origin: String,
}

impl Prover {
    pub(super) fn new(origin: &str) -> Result<Self, Failure> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(origin.starts_with("https://"))
            .build()
            .map_err(|_| Failure::Unavailable)?;
        Ok(Self {
            client,
            origin: origin.trim_end_matches('/').to_owned(),
        })
    }

    pub(super) async fn prove(
        &self,
        request: &Value,
        deadline: Instant,
    ) -> Result<OperationResult, Failure> {
        let prover = || Failure::Stage(FailureStage::Prover);
        let mut sync = true;
        loop {
            let mut post = self
                .client
                .post(format!("{}{PROVE_PATH}", self.origin))
                .json(request);
            if sync {
                post = post.header("X-Sync", "true");
            }
            let response = post.send().await.map_err(|_| prover())?;
            if response.status().as_u16() == 429 && sync {
                sync = false;
                continue;
            }
            if !response.status().is_success() {
                return Err(prover());
            }
            let answer = read_json(response).await?;
            let job = match answer.get("jobId").and_then(Value::as_str) {
                Some(job) if answer.get("proof").is_none() => job.to_owned(),
                _ => return Ok(OperationResult::Prove { proof: answer }),
            };
            return self.poll(&job, deadline).await;
        }
    }

    async fn poll(&self, job: &str, deadline: Instant) -> Result<OperationResult, Failure> {
        let prover = || Failure::Stage(FailureStage::Prover);
        if job.is_empty()
            || job.len() > 256
            || !job
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(prover());
        }
        let mut interval = INITIAL_POLL_INTERVAL;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(prover());
            }
            tokio::time::sleep(interval.min(remaining)).await;
            interval = (interval * 2).min(MAX_POLL_INTERVAL);
            let response = self
                .client
                .get(format!("{}{STATUS_PATH}", self.origin))
                .query(&[("jobId", job)])
                .send()
                .await;
            let response = match response {
                Ok(response) if response.status().is_client_error() => return Err(prover()),
                Ok(response) if response.status().is_success() => response,
                // A server error or a transport failure is transient.
                _ => continue,
            };
            let status = read_json(response).await?;
            match status.get("status").and_then(Value::as_str) {
                Some("failed") => return Err(prover()),
                Some("completed") => {
                    let proof = status.get("result").cloned().unwrap_or(status);
                    return Ok(OperationResult::Prove { proof });
                }
                _ => {}
            }
        }
    }
}

async fn read_json(mut response: reqwest::Response) -> Result<Value, Failure> {
    let prover = || Failure::Stage(FailureStage::Prover);
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(prover());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| prover())? {
        if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
            return Err(prover());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| prover())
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use std::io::{Read, Write};

    // No Content-Length and no terminating chunk: the reader must reject as
    // soon as the limit is crossed, without waiting for EOF or the timeout.
    #[tokio::test]
    async fn rejects_an_oversized_chunked_response_before_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .unwrap();
            let chunk = vec![b' '; 16 * 1024];
            for _ in 0..=MAX_RESPONSE_BYTES / chunk.len() {
                if write!(stream, "{:x}\r\n", chunk.len())
                    .and_then(|()| stream.write_all(&chunk))
                    .and_then(|()| stream.write_all(b"\r\n"))
                    .is_err()
                {
                    break;
                }
            }
            let _ = wait.recv_timeout(Duration::from_secs(5));
        });
        let response = reqwest::get(format!("http://{address}")).await.unwrap();
        assert_eq!(response.content_length(), None);
        let result = tokio::time::timeout(Duration::from_secs(2), read_json(response)).await;
        let _ = release.send(());
        server.join().unwrap();
        assert!(matches!(
            result,
            Ok(Err(Failure::Stage(FailureStage::Prover)))
        ));
    }

    #[tokio::test]
    async fn accepts_the_limit_and_rejects_larger_or_invalid_json() {
        for (length, valid_json, accepted) in [
            (MAX_RESPONSE_BYTES, true, true),
            (MAX_RESPONSE_BYTES + 1, true, false),
            (32, false, false),
        ] {
            let mut body = vec![b' '; length];
            body[..2].copy_from_slice(if valid_json { b"{}" } else { b"xx" });
            let response = reqwest::Response::from(
                axum::http::Response::builder()
                    .header("content-length", length)
                    .body(body)
                    .unwrap(),
            );
            assert_eq!(read_json(response).await.is_ok(), accepted);
        }
    }
}
