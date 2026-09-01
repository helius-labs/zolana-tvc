//! Protocol conformance: canonical encoding, P-256, QOS envelope, bindings, and HTTP.

use std::path::PathBuf;
use std::sync::OnceLock;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use sha2::{Digest, Sha256};
use zolana_tvc_protocol::crypto::{
    parse_uncompressed_sec1, qos_decrypt, reject_double_hashed_signature, sign_p256_prehash,
    verify_p256_prehash,
};
use zolana_tvc_protocol::encoding::{
    canonicalize_json_str, decode_decimal_u64, decode_lower_hex, parse_strict_json,
};
use zolana_tvc_protocol::error::ErrorCode;
mod fixtures;

use fixtures::{verify_fixtures, write_fixtures};
use zolana_tvc_protocol::http::handle_public_http;
use zolana_tvc_protocol::release::{bind_discovery_to_policy, verify_signed_release_policy};
use zolana_tvc_protocol::types::{
    AssetV1, AuthorizeSpendRequestV1, HealthResponseV1, OperationV1, PrivateDomainV1,
    ServiceInfoV1, SpendPlanV1, SpendSettlementV1,
};
use zolana_tvc_protocol::{
    PinnedReleaseAuthoritiesV1, PublicError, ReleasePolicyV1, SignedReleasePolicyV1,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn verify_committed_fixtures() {
    static FIXTURES: OnceLock<()> = OnceLock::new();
    FIXTURES.get_or_init(|| verify_fixtures(&fixtures_dir()).unwrap());
}

#[test]
fn verifies_committed_content_addressed_fixtures() {
    verify_committed_fixtures();
}

#[test]
#[ignore = "run explicitly through `just regenerate-protocol-fixtures`"]
fn regenerate_content_addressed_fixtures() {
    write_fixtures(&fixtures_dir()).unwrap();
    verify_fixtures(&fixtures_dir()).unwrap();
}

#[test]
fn jcs_sorts_keys_and_round_trips() {
    let canonical = canonicalize_json_str(r#"{"b":1,"a":2}"#).unwrap();
    assert_eq!(canonical, r#"{"a":2,"b":1}"#);
    let unicode = canonicalize_json_str(r#"{"é":1,"a":2}"#).unwrap();
    assert!(unicode.starts_with('{'));
}

#[test]
fn canonical_u64_rejects_leading_zeros_and_signs() {
    assert_eq!(decode_decimal_u64("0").unwrap(), 0);
    assert_eq!(
        decode_decimal_u64("1700000000000").unwrap(),
        1_700_000_000_000
    );
    assert_eq!(decode_decimal_u64(&u64::MAX.to_string()).unwrap(), u64::MAX);
    assert_eq!(
        decode_decimal_u64("01").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
    assert_eq!(
        decode_decimal_u64("+1").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
    assert_eq!(
        decode_decimal_u64("1.0").unwrap_err().code,
        ErrorCode::InvalidDecimal
    );
}

#[test]
fn unknown_and_duplicate_json_fields_are_rejected() {
    let unknown = parse_strict_json::<HealthResponseV1>(r#"{"status":"Healthy","extra":true}"#);
    assert_eq!(unknown.unwrap_err().code, ErrorCode::UnknownJsonField);
    let duplicate =
        parse_strict_json::<HealthResponseV1>(r#"{"status":"Healthy","status":"Healthy"}"#);
    assert_eq!(duplicate.unwrap_err().code, ErrorCode::DuplicateJsonField);
}

#[test]
fn authorize_spend_covers_default_and_custom_rings() {
    let ring = r#"{"type":"Ring","program_id":"8QqsEqz1ff1YYt6hH7VNq6VVzq5TGWQ66bkdtrALbhn6","lookup_table":"11111111111111111111111111111111"}"#;
    let spend: OperationV1 = parse_strict_json(&format!(
        r#"{{"type":"AuthorizeSpend","spend":{{"phase":"Prepare","plan":{{"type":"Direct","transition":{{"source":{ring},"settlement":{{"type":"Transfer","asset":{{"type":"Spl","mint":"BEZe5CuQxzjwTHoqobHA3XJw34GJTph8nrXqP9zJRLjx","asset_id":"14"}},"recipient":"11111111111111111111111111111111","amount":"1","destination":{ring}}},"input_commitments":[]}}}}}}}}"#
    ))
    .unwrap();
    let OperationV1::AuthorizeSpend {
        spend:
            AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Direct { transition },
            },
    } = spend
    else {
        panic!("expected a ring spend");
    };
    assert_eq!(
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Direct {
                    transition: transition.clone(),
                },
            },
        }
        .kind(),
        zolana_tvc_protocol::OperationKind::AuthorizeSpend
    );
    let SpendSettlementV1::Transfer { asset, .. } = &transition.settlement else {
        panic!("expected a transfer settlement");
    };
    assert!(matches!(asset, AssetV1::Spl { asset_id: 14, .. }));
    assert!(matches!(transition.source, PrivateDomainV1::Ring { .. }));

    let default: OperationV1 = parse_strict_json(
        r#"{"type":"AuthorizeSpend","spend":{"phase":"Prepare","plan":{"type":"Direct","transition":{"source":{"type":"Default"},"settlement":{"type":"Withdrawal","asset":{"type":"Spl","mint":"So11111111111111111111111111111111111111112","asset_id":"14"},"recipient":"11111111111111111111111111111111","amount":"1"},"input_commitments":[]}}}}"#,
    )
    .unwrap();
    assert!(matches!(
        default,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Direct { transition }
            }
        } if matches!(transition.source, PrivateDomainV1::Default)
            && matches!(transition.settlement, SpendSettlementV1::Withdrawal {
                asset: AssetV1::Spl { asset_id: 14, .. }, ..
            })
    ));

    let consolidate: OperationV1 = parse_strict_json(
        r#"{"type":"AuthorizeSpend","spend":{"phase":"Prepare","plan":{"type":"Direct","transition":{"source":{"type":"Default"},"settlement":{"type":"Consolidate","asset":{"type":"Sol"}},"input_commitments":[]}}}}"#,
    )
    .unwrap();
    assert!(matches!(
        consolidate,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Direct { transition }
            }
        } if matches!(transition.source, PrivateDomainV1::Default)
            && matches!(transition.settlement, SpendSettlementV1::Consolidate {
                asset: AssetV1::Sol
            })
    ));

    let finalize: OperationV1 = parse_strict_json(
        r#"{"type":"AuthorizeSpend","spend":{"phase":"Finalize","sealed_authorization_capsule":"aa","unsigned_transaction":"bb"}}"#,
    )
    .unwrap();
    assert!(matches!(
        finalize,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Finalize {
                sealed_authorization_capsule,
                unsigned_transaction,
            }
        } if sealed_authorization_capsule == [0xaa] && unsigned_transaction == [0xbb]
    ));

    // Removed operations, an unknown operation, and non-canonical integers are
    // all rejected. Old intent shapes are not accepted by the breaking domain
    // contract.
    for body in [
        r#"{"type":"BuildTransfer","intent":{"asset":{"type":"Sol"},"recipient":"11111111111111111111111111111111","amount":"1","prover_profile_id":"devnet"}}"#,
        r#"{"type":"BuildSolWithdrawal","intent":{"recipient":"11111111111111111111111111111111","amount":"1","prover_profile_id":"devnet"}}"#,
        r#"{"type":"ShieldSol","amount":"1"}"#,
        r#"{"type":"AuthorizeSpend","intent":{"ring":null,"settlement":{"type":"SolWithdrawal","recipient":"11111111111111111111111111111111","amount":"1"},"prover_profile_id":"devnet"}}"#,
        r#"{"type":"AuthorizeSpend","spend":{"phase":"Finalize","sealed_authorization_capsule":"aa","unsigned_transaction":"bb","extra":true}}"#,
    ] {
        assert!(parse_strict_json::<OperationV1>(body).is_err(), "{body}");
    }
    assert!(parse_strict_json::<OperationV1>(&format!(
        r#"{{"type":"AuthorizeSpend","spend":{{"phase":"Prepare","plan":{{"type":"Direct","transition":{{"source":{ring},"settlement":{{"type":"Withdrawal","asset":{{"type":"Sol"}},"recipient":"11111111111111111111111111111111","amount":"01"}},"input_commitments":[]}}}}}}}}"#
    ))
    .is_err());
}

#[test]
fn authorize_spend_covers_program_neutral_spp_prepare_and_finalize() {
    let prepare: OperationV1 = parse_strict_json(&format!(
        r#"{{"type":"AuthorizeSpend","spend":{{"phase":"Prepare","plan":{{"type":"Program","transition":{{"program_id":"11111111111111111111111111111111","input_tree":"11111111111111111111111111111111","shape":{{"inputs":2,"outputs":1}},"inputs":[{{"type":"Wallet","commitment":"{}"}}],"program_authorities":[],"outputs":[{{"recipient":"shielded-recipient","asset":{{"type":"Sol"}},"amount":"7","blinding":"{}","data":"aabb","data_hash":null,"memo":""}}],"messages":[{{"view_tag":"{}","data":"cc"}}],"expires_at_ms":"1750000000000"}}}}}}}}"#,
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
    ))
    .unwrap();
    assert!(matches!(
        prepare,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Program { transition }
            }
        } if transition.shape.inputs == 2 && transition.shape.outputs == 1
    ));

    let finalize: OperationV1 = parse_strict_json(
        r#"{"type":"AuthorizeSpend","spend":{"phase":"Finalize","sealed_authorization_capsule":"aa","unsigned_transaction":"bb"}}"#,
    )
    .unwrap();
    assert!(matches!(
        finalize,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Finalize {
                unsigned_transaction,
                ..
            }
        } if unsigned_transaction == [0xbb]
    ));
}

#[test]
fn p256_rejects_der_high_s_compressed_and_double_hash() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("p256-signatures.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let public = decode_lower_hex(value["public_key"].as_str().unwrap()).unwrap();
    let digest: [u8; 32] = decode_lower_hex(value["digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let raw = decode_lower_hex(value["raw_low_s"].as_str().unwrap()).unwrap();
    let der = decode_lower_hex(value["der"].as_str().unwrap()).unwrap();
    let high = decode_lower_hex(value["high_s"].as_str().unwrap()).unwrap();
    let compressed = decode_lower_hex(value["compressed_public_key"].as_str().unwrap()).unwrap();
    let double_sig = decode_lower_hex(value["double_hash_signature"].as_str().unwrap()).unwrap();

    verify_p256_prehash(&public, &digest, &raw).unwrap();
    assert_eq!(
        verify_p256_prehash(&public, &digest, &der)
            .unwrap_err()
            .code,
        ErrorCode::DerSignatureRejected
    );
    assert_eq!(
        verify_p256_prehash(&public, &digest, &high)
            .unwrap_err()
            .code,
        ErrorCode::HighSSignature
    );
    assert_eq!(
        parse_uncompressed_sec1(&compressed).unwrap_err().code,
        ErrorCode::CompressedKeyRejected
    );
    reject_double_hashed_signature(&public, &digest, &double_sig).unwrap();
}

#[test]
fn qos_envelope_rejects_truncation_and_wrong_key() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("qos-negative.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let truncated = decode_lower_hex(value["truncated_envelope"].as_str().unwrap()).unwrap();
    let envelope = decode_lower_hex(value["envelope"].as_str().unwrap()).unwrap();
    let wrong: [u8; 32] = decode_lower_hex(value["wrong_receiver_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        qos_decrypt(&wrong, &envelope).unwrap_err().code,
        ErrorCode::InvalidEncryptedEnvelope
    );
    assert_eq!(
        qos_decrypt(&wrong, &truncated).unwrap_err().code,
        ErrorCode::InvalidEncryptedEnvelope
    );
}

#[test]
fn health_does_not_leak_deployment_details() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("http-skeleton.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["health_body"], r#"{"status":"Healthy"}"#);
    assert_eq!(value["health_has_release_id"], false);
    assert_eq!(value["health_status"], 200);
    let info: ServiceInfoV1 = parse_strict_json(value["info_body"].as_str().unwrap()).unwrap();
    assert_eq!(info.version, 1);
}

#[test]
fn oversized_public_request_is_rejected() {
    verify_committed_fixtures();
    let info_json = std::fs::read_to_string(fixtures_dir().join("http-skeleton.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&info_json).unwrap();
    let info: ServiceInfoV1 = parse_strict_json(value["info_body"].as_str().unwrap()).unwrap();
    let body = vec![0u8; 262_145];
    let response = handle_public_http("GET", "/health", &body, true, &info);
    assert_eq!(response.status, PublicError::RequestTooLarge.status());
}

#[test]
fn uppercase_hex_is_rejected() {
    assert_eq!(
        decode_lower_hex("AA").unwrap_err().code,
        ErrorCode::InvalidHex
    );
    assert_eq!(
        decode_lower_hex("0xab").unwrap_err().code,
        ErrorCode::InvalidHex
    );
}

#[test]
fn sign_prehash_is_stable_for_test_scalar() {
    let sk = Sha256::digest(b"zolana-tvc-test-client-sk");
    let digest = Sha256::digest(b"digest");
    let a = sign_p256_prehash(&sk.into(), &digest.into()).unwrap();
    let b = sign_p256_prehash(&sk.into(), &digest.into()).unwrap();
    assert_eq!(a, b);
    let _ = SecretKey::from_slice(sk.as_slice())
        .unwrap()
        .public_key()
        .to_encoded_point(false);
}

#[test]
fn discovery_binding_matches_fixture() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("discovery-binding.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let policy: ReleasePolicyV1 = serde_json::from_value(value["policy"].clone()).unwrap();
    let info: ServiceInfoV1 = serde_json::from_value(value["info"].clone()).unwrap();
    bind_discovery_to_policy(&info, &policy).unwrap();
    for case in value["cases"].as_array().unwrap() {
        let mutated: ServiceInfoV1 = serde_json::from_value(case["info"].clone()).unwrap();
        let error = bind_discovery_to_policy(&mutated, &policy).unwrap_err();
        assert_eq!(
            error.code.as_str(),
            case["error"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn signed_release_policy_rejects_empty_duplicate_unknown_and_mutated() {
    verify_committed_fixtures();
    let body = std::fs::read_to_string(fixtures_dir().join("signed-release-policy.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let signed: SignedReleasePolicyV1 = serde_json::from_value(value["signed"].clone()).unwrap();
    let authorities: PinnedReleaseAuthoritiesV1 =
        serde_json::from_value(value["authorities"].clone()).unwrap();
    let now_ms = decode_decimal_u64(value["now_ms"].as_str().unwrap()).unwrap();
    verify_signed_release_policy(&signed, &authorities, now_ms).unwrap();
    assert_eq!(value["empty_signatures"], "ReleasePolicyInvalid");
    assert_eq!(value["duplicate_key_id"], "ReleasePolicyInvalid");
    assert_eq!(value["unknown_key_id"], "ReleasePolicyInvalid");
    assert_eq!(value["mutated_policy"], "InvalidSignature");
    assert_eq!(value["wrong_trust_root"], "ReleasePolicyInvalid");
    assert_eq!(value["revoked_epoch"], "ReleasePolicyInvalid");
}
