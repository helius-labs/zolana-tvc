//! Complete encrypted handlers, with client work outside the measured interval.
//! Run via scripts/bench-operations.py; its prover stub is a separate process.
//! An example binary keeps normal all-targets tests independent of that stub.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::Router;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use nix::time::{clock_gettime, ClockId};
use qos_p256::P256Pair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_pubkey::Pubkey;
use tower::ServiceExt;
use zolana_keypair::{derivation, ViewingKey};
use zolana_tvc_privacy_wallet::{
    local_testkit_qos_seeds, local_unattested_state, router, OPERATIONS,
};
use zolana_tvc_protocol::auth::authorize_operation_request;
use zolana_tvc_protocol::constants::{
    API_VERSION, DEVNET_MAX_ENCRYPTED_REQUEST_BYTES, DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
    MAX_REQUEST_AGE_MS,
};
use zolana_tvc_protocol::crypto::{
    public_key_uncompressed, qos_decrypt, qos_encrypt, sign_p256_prehash, verify_p256_message,
    QosP256Public,
};
use zolana_tvc_protocol::digest::{descriptor_digest, request_digest, result_digest, sha256};
use zolana_tvc_protocol::encoding::{decode_lower_hex_array, jcs_serialize, parse_strict_json};
use zolana_tvc_protocol::types::{
    ClientAuthorization, ClientAuthorizationScheme, ClientGrant, DecryptItem, DecryptLabel,
    DeriveItem, EncryptedRequest, EncryptedResponse, Operation, OperationProofPayload,
    OperationRequest, OperationResult, ServiceInfo, TransactionKeyItem, WalletDescriptor,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    prover_url: String,
    #[arg(long, default_value_t = 1.0)]
    seconds: f64,
    #[arg(long, default_value_t = 100)]
    samples: usize,
    #[arg(long, default_value_t = 3)]
    repeats: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Testkit {
    provisioning_private_key_hex: String,
    client_private_key_hex: String,
    organization_id: String,
    wallet_id: String,
}

struct Harness {
    app: Router,
    info: ServiceInfo,
    descriptor: WalletDescriptor,
    client_secret: [u8; 32],
    response_secret: [u8; 32],
    viewing: ViewingKey,
}

struct Fixture {
    body: Bytes,
    request: OperationRequest,
}

struct Case {
    name: String,
    batch_size: usize,
    operation: Operation,
    expected: Option<OperationResult>,
    min_samples: usize,
}

#[derive(Serialize)]
struct Measurement {
    name: String,
    batch_size: usize,
    repeat: usize,
    samples: usize,
    request_bytes: usize,
    response_bytes: usize,
    cpu_mean_ms: f64,
    cpu_p50_ms: f64,
    cpu_p95_ms: f64,
    wall_mean_ms: f64,
    wall_p50_ms: f64,
    wall_p95_ms: f64,
    cpu_clock_pair_ns: u64,
}

fn cpu_ns() -> u64 {
    let t = clock_gettime(ClockId::CLOCK_PROCESS_CPUTIME_ID).expect("process CPU clock");
    t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn field(index: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    value
}

impl Harness {
    async fn new(prover_url: &str) -> Self {
        let keys: Testkit = serde_json::from_str(include_str!(
            "../../../packages/tvc-wallet/src/local-testkit.json"
        ))
        .unwrap();
        // Public, disposable fixture material, never a real wallet.
        let wallet = SigningKey::from_bytes(&[7; 32]);
        let public = wallet.verifying_key().to_bytes();
        let seed = wallet
            .sign(&derivation::ed25519_derivation_message(&public))
            .to_bytes();
        let (_, viewing) = derivation::expand_roles(&seed, zolana_keypair::Curve::Ed25519).unwrap();
        let (ephemeral, quorum) = local_testkit_qos_seeds();
        let app = router(local_unattested_state(
            P256Pair::from_master_seed(&ephemeral.into()).unwrap(),
            P256Pair::from_master_seed(&quorum.into()).unwrap(),
            [7; 32],
            prover_url.to_owned(),
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let info: ServiceInfo = serde_json::from_slice(&bytes).unwrap();
        let client_secret = decode_lower_hex_array(&keys.client_private_key_hex).unwrap();
        let client_public = public_key_uncompressed(
            &p256::SecretKey::from_slice(&client_secret)
                .unwrap()
                .public_key(),
        );
        let mut descriptor = WalletDescriptor {
            version: API_VERSION,
            security_domain_id: info.security_domain_id,
            environment: info.environment,
            turnkey_organization_id: keys.organization_id,
            turnkey_wallet_id: keys.wallet_id,
            address: Pubkey::new_from_array(public).to_string(),
            allowed_clients: vec![ClientGrant {
                client_public_key: client_public.to_vec(),
                allowed_operations: OPERATIONS.to_vec(),
            }],
            provisioning_signature: Vec::new(),
        };
        descriptor.provisioning_signature = sign_p256_prehash(
            &decode_lower_hex_array(&keys.provisioning_private_key_hex).unwrap(),
            &descriptor_digest(&descriptor).unwrap(),
        )
        .unwrap()
        .to_vec();
        Self {
            app,
            info,
            descriptor,
            client_secret,
            response_secret: [0x42; 32],
            viewing,
        }
    }

    fn fixture(&self, operation: Operation, sealed: Option<Vec<u8>>, index: usize) -> Fixture {
        let client_key_id = format!(
            "tvc-browser-p256-{}",
            hex::encode(&sha256(&self.descriptor.allowed_clients[0].client_public_key)[..16])
        );
        let request = authorize_operation_request(
            OperationRequest {
                version: API_VERSION,
                request_id: sha256(format!("benchmark-{index}").as_bytes()),
                issued_at_ms: now_ms(),
                expires_at_ms: now_ms() + MAX_REQUEST_AGE_MS - 1000,
                target_release_id: self.info.release_id.clone(),
                target_manifest_digest: self.info.manifest_digest,
                target_executable_digest: self.info.executable_digest,
                quorum_key_id: self.info.quorum_key_id.clone(),
                quorum_key_epoch: self.info.quorum_key_epoch,
                wallet_descriptor: self.descriptor.clone(),
                sealed_seed: sealed,
                client_response_public_key: public_key_uncompressed(
                    &p256::SecretKey::from_slice(&self.response_secret)
                        .unwrap()
                        .public_key(),
                )
                .to_vec(),
                operation,
                authorization: ClientAuthorization {
                    client_key_id,
                    scheme: ClientAuthorizationScheme::P256Sha256,
                    signature: Vec::new(),
                },
            },
            &self.client_secret,
        )
        .unwrap();
        let quorum = QosP256Public::from_bytes(&self.info.quorum_public_key).unwrap();
        let ciphertext = qos_encrypt(
            &quorum.encryption,
            jcs_serialize(&request).unwrap().as_bytes(),
        )
        .unwrap();
        let body = jcs_serialize(&EncryptedRequest {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            ciphertext,
        })
        .unwrap();
        assert!(body.len() <= DEVNET_MAX_ENCRYPTED_REQUEST_BYTES as usize);
        Fixture {
            body: Bytes::from(body),
            request,
        }
    }

    async fn timed_call(&self, fixture: &Fixture) -> (Bytes, u64, u64) {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/operations")
            .header("content-type", "application/json")
            .body(Body::from(fixture.body.clone()))
            .unwrap();
        let app = self.app.clone();
        let cpu_start = cpu_ns();
        let wall_start = Instant::now();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(
            response.into_body(),
            (DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES * 2) as usize,
        )
        .await
        .unwrap();
        let wall = wall_start.elapsed().as_nanos() as u64;
        let cpu = cpu_ns() - cpu_start;
        assert_eq!(
            status,
            StatusCode::OK,
            "operation failed: {}",
            String::from_utf8_lossy(&body)
        );
        (body, cpu, wall)
    }

    fn verify(&self, fixture: &Fixture, bytes: &[u8]) -> OperationResult {
        let response: EncryptedResponse =
            parse_strict_json(std::str::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(response.request_id, fixture.request.request_id);
        let proof = response.tvc_app_proof;
        assert_eq!(proof.public_key, self.info.ephemeral_public_key);
        let ephemeral = QosP256Public::from_bytes(&proof.public_key).unwrap();
        verify_p256_message(
            &ephemeral.signing,
            proof.proof_payload.as_bytes(),
            &proof.signature,
        )
        .unwrap();
        let payload: OperationProofPayload = parse_strict_json(&proof.proof_payload).unwrap();
        assert_eq!(
            payload.request_digest,
            request_digest(&fixture.request).unwrap()
        );
        assert_eq!(
            payload.result_digest,
            result_digest(&response.encrypted_result)
        );
        assert_eq!(payload.operation, fixture.request.operation.kind());
        let plaintext = qos_decrypt(&self.response_secret, &response.encrypted_result).unwrap();
        let result: OperationResult =
            parse_strict_json(std::str::from_utf8(&plaintext).unwrap()).unwrap();
        assert!(
            !matches!(result, OperationResult::Failure { .. }),
            "encrypted operation failure"
        );
        if let OperationResult::Bootstrap {
            solana_address,
            shielded_viewing_public_key,
            sealed_seed,
            ..
        } = &result
        {
            assert_eq!(solana_address, &self.descriptor.address);
            assert_eq!(
                shielded_viewing_public_key,
                self.viewing.pubkey().as_bytes()
            );
            assert!(!sealed_seed.is_empty());
        }
        result
    }
}

fn cases(h: &Harness, args: &Args) -> Vec<Case> {
    let mut cases = vec![Case {
        name: "Bootstrap/local-signer".into(),
        batch_size: 1,
        operation: Operation::Bootstrap,
        expected: None,
        min_samples: args.samples,
    }];
    let wallet = SigningKey::from_bytes(&[7; 32]);
    let seed = wallet
        .sign(&derivation::ed25519_derivation_message(
            &wallet.verifying_key().to_bytes(),
        ))
        .to_bytes();
    let (nullifier, _) = derivation::expand_roles(&seed, zolana_keypair::Curve::Ed25519).unwrap();
    let transaction_key = ViewingKey::new();
    let plaintext = vec![0x5a; 128];
    for size in [1, 16, 64, 128] {
        let items = (0..size)
            .map(|i| DeriveItem::Nullifier {
                utxo_hash: field(i),
                blinding: field(i + size),
            })
            .collect();
        let values = (0..size)
            .map(|i| nullifier.nullifier(&field(i), &field(i + size)).unwrap())
            .collect();
        cases.push(Case {
            name: "Derive/nullifier".into(),
            batch_size: size,
            operation: Operation::Derive { items },
            expected: Some(OperationResult::Derive { values }),
            min_samples: args.samples,
        });
        let items = (0..size)
            .map(|i| TransactionKeyItem {
                viewing_public_key: h.viewing.pubkey().as_bytes().to_vec(),
                first_nullifier: field(i),
            })
            .collect();
        let secrets = (0..size)
            .map(|i| {
                *h.viewing
                    .get_transaction_viewing_key(&field(i))
                    .unwrap()
                    .secret_bytes()
            })
            .collect();
        cases.push(Case {
            name: "TransactionKeys".into(),
            batch_size: size,
            operation: Operation::TransactionKeys { items },
            expected: Some(OperationResult::TransactionKeys { secrets }),
            min_samples: args.samples,
        });
        for (label, name) in [
            (DecryptLabel::Transfer, "Decrypt/transfer"),
            (DecryptLabel::RingDeposit, "Decrypt/ring-deposit"),
        ] {
            let items = (0..size)
                .map(|i| {
                    let salt: [u8; 16] = field(i)[16..].try_into().unwrap();
                    let ciphertext = match label {
                        DecryptLabel::Transfer => transaction_key
                            .encrypt_slot(&h.viewing.pubkey(), &plaintext, salt, i as u32)
                            .unwrap(),
                        DecryptLabel::RingDeposit => transaction_key
                            .encrypt_ring_deposit(&h.viewing.pubkey(), &plaintext, salt)
                            .unwrap(),
                    };
                    DecryptItem {
                        ciphertext,
                        viewing_public_key: h.viewing.pubkey().as_bytes().to_vec(),
                        transaction_viewing_public_key: transaction_key
                            .pubkey()
                            .as_bytes()
                            .to_vec(),
                        salt: salt.to_vec(),
                        slot_index: if matches!(label, DecryptLabel::Transfer) {
                            i as u64
                        } else {
                            0
                        },
                        label,
                    }
                })
                .collect();
            cases.push(Case {
                name: name.into(),
                batch_size: size,
                operation: Operation::Decrypt { items },
                expected: Some(OperationResult::Decrypt {
                    plaintexts: vec![plaintext.clone(); size],
                }),
                min_samples: args.samples,
            });
        }
    }
    for (padding, inputs, delay) in [(4096, 1, 0), (65536, 8, 0), (4096, 1, 50)] {
        let operation = Operation::Prove {
            request: json!({
                "circuitType": "transfer-ring",
                "inputs": (0..inputs).map(|_| json!({"isDummy":"0x0", "nullifierSecret":null})).collect::<Vec<_>>(),
                "benchmarkPadding": "x".repeat(padding),
                "benchmarkDelayMs": delay,
            }),
        };
        cases.push(Case {
            name: format!("Prove/stub-{}KiB-{delay}ms-wait", padding / 1024),
            batch_size: inputs,
            operation,
            expected: Some(OperationResult::Prove {
                proof: json!({"proof":"benchmark-stub"}),
            }),
            min_samples: if delay == 0 {
                args.samples
            } else {
                args.samples.min(20)
            },
        });
    }
    cases
}

fn percentile(values: &mut [u64], p: f64) -> f64 {
    values.sort_unstable();
    values[((values.len() as f64 * p).ceil() as usize).saturating_sub(1)] as f64 / 1_000_000.0
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    assert!(args.seconds.is_finite() && args.seconds > 0.0 && args.seconds <= 30.0);
    assert!(args.samples > 0 && args.repeats > 0);
    // Refuse accidental calls to the real prover: the runner binds a local stub.
    let url = reqwest::Url::parse(&args.prover_url).unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    let h = Harness::new(&args.prover_url).await;
    let bootstrap = h.fixture(Operation::Bootstrap, None, 0);
    let (bytes, _, _) = h.timed_call(&bootstrap).await;
    let OperationResult::Bootstrap { sealed_seed, .. } = h.verify(&bootstrap, &bytes) else {
        panic!("bootstrap result")
    };
    let mut cases = cases(&h, &args);
    let clock_overhead = (0..1000)
        .map(|_| {
            let start = cpu_ns();
            cpu_ns() - start
        })
        .min()
        .unwrap();
    let mut measurements = Vec::new();
    for repeat in 1..=args.repeats {
        // Reverse order between repetitions to expose warm-up/order effects.
        if repeat > 1 {
            cases.reverse();
        }
        for (index, case) in cases.iter().enumerate() {
            let sealed = if matches!(case.operation, Operation::Bootstrap) {
                None
            } else {
                Some(sealed_seed.clone())
            };
            let fixture = h.fixture(case.operation.clone(), sealed, repeat * 1000 + index);
            for _ in 0..10 {
                let (bytes, _, _) = h.timed_call(&fixture).await;
                let result = h.verify(&fixture, &bytes);
                if let Some(expected) = &case.expected {
                    assert_eq!(&result, expected);
                }
            }
            let mut cpu = Vec::new();
            let mut wall = Vec::new();
            let mut measured_wall = Duration::ZERO;
            let mut response_bytes = 0;
            while cpu.len() < case.min_samples || measured_wall.as_secs_f64() < args.seconds {
                let (bytes, cpu_ns, wall_ns) = h.timed_call(&fixture).await;
                // Every response is authenticated and checked outside the clocks.
                let result = h.verify(&fixture, &bytes);
                if let Some(expected) = &case.expected {
                    assert_eq!(&result, expected);
                }
                if matches!(case.operation, Operation::Bootstrap) {
                    assert!(matches!(result, OperationResult::Bootstrap { .. }));
                }
                response_bytes = bytes.len();
                cpu.push(cpu_ns);
                wall.push(wall_ns);
                measured_wall += Duration::from_nanos(wall_ns);
            }
            let measurement = Measurement {
                name: case.name.clone(),
                batch_size: case.batch_size,
                repeat,
                samples: cpu.len(),
                request_bytes: fixture.body.len(),
                response_bytes,
                cpu_mean_ms: cpu.iter().sum::<u64>() as f64 / cpu.len() as f64 / 1_000_000.0,
                cpu_p50_ms: percentile(&mut cpu, 0.5),
                cpu_p95_ms: percentile(&mut cpu, 0.95),
                wall_mean_ms: wall.iter().sum::<u64>() as f64 / wall.len() as f64 / 1_000_000.0,
                wall_p50_ms: percentile(&mut wall, 0.5),
                wall_p95_ms: percentile(&mut wall, 0.95),
                cpu_clock_pair_ns: clock_overhead,
            };
            eprintln!(
                "{}/{} {} [{}]: {:.3} CPU ms, {:.3} wall ms, {} samples",
                repeat,
                args.repeats,
                measurement.name,
                measurement.batch_size,
                measurement.cpu_mean_ms,
                measurement.wall_mean_ms,
                measurement.samples
            );
            measurements.push(measurement);
        }
    }
    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}
