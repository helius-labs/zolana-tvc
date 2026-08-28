//! Committed, content-addressed protocol conformance fixtures.

use std::collections::BTreeMap;
use std::path::Path;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::auth::{authorize_operation_request, verify_client_authorization};
use crate::bindings::{check_request_bindings, RunningEnclave};
use crate::constants::{
    API_VERSION, PHASE0_MAX_ENCRYPTED_REQUEST_BYTES, PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
    QOS_P256_PUBLIC_LEN, TVC_APP_PROOF_TYPE,
};
use crate::crypto::{
    public_key_uncompressed, qos_decrypt, qos_encrypt_with, qos_public_from_secrets,
    reject_double_hashed_signature, sign_p256_prehash, verify_p256_prehash, QosP256Public,
};
use crate::digest::{
    artifact_digest, client_auth_digest, descriptor_digest_from_wallet, owner_auth_evidence_digest,
    provisioning_auth_digest, request_digest, request_id_hash, result_digest, state_commitment,
    wallet_id_hash,
};
use crate::encoding::{
    canonicalize_json_str, canonicalize_json_value, encode_decimal_u64, encode_lower_hex,
};
use crate::evidence::classify_turnkey_policy_evidence;
use crate::http::handle_public_http;
use crate::release::{
    sign_release_policy, verify_signed_release_policy, PinnedReleaseAuthoritiesV1,
    ReleaseAuthorityKeyV1,
};
use crate::types::{
    ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1, Environment, OperationKind,
    OperationRequestV1, OperationV1, ReleaseAuthoritySignatureV1, ReleasePolicyV1, ServiceInfoV1,
    SignedReleasePolicyV1, TurnkeySigningTargetV1, WalletDescriptorV1,
};

const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

fn sha256_label(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn sub_mod_n(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let n = P256_N[i] as u16;
        let v = s[i] as u16;
        let sub = n.wrapping_sub(v).wrapping_sub(borrow);
        out[i] = sub as u8;
        borrow = if n < v + borrow { 1 } else { 0 };
    }
    out
}

fn high_s_signature(low_s: &[u8; 64]) -> [u8; 64] {
    let mut s = [0u8; 32];
    s.copy_from_slice(&low_s[32..]);
    let high = sub_mod_n(&s);
    let mut out = *low_s;
    out[32..].copy_from_slice(&high);
    out
}

fn der_encode_signature(raw: &[u8; 64]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend_from_slice(&v);
        out
    }
    let r = integer(&raw[..32]);
    let s = integer(&raw[32..]);
    let mut seq = r;
    seq.extend_from_slice(&s);
    let mut out = vec![0x30, seq.len() as u8];
    out.extend_from_slice(&seq);
    out
}

fn sample_descriptor(client_public: &[u8], security_domain: [u8; 32]) -> WalletDescriptorV1 {
    WalletDescriptorV1 {
        version: API_VERSION,
        wallet_id: "wallet-phase0-1".to_owned(),
        security_domain_id: security_domain,
        turnkey_parent_organization_id: "parent-org".to_owned(),
        turnkey_organization_id: "child-org".to_owned(),
        turnkey_signing_target: TurnkeySigningTargetV1::HdWalletAccount {
            turnkey_wallet_id: "turnkey-wallet".to_owned(),
            wallet_account_id: "turnkey-wallet-account".to_owned(),
            address: "4E2agEUkMiuP3ABYbYTYXuU7bYyqPb3uGsLqs7RDd1U5".to_owned(),
            derivation_path: "m/44'/501'/0'/0'".to_owned(),
        },
        turnkey_ring_signing_key_id: None,
        turnkey_service_user_id: "service-user".to_owned(),
        turnkey_api_key_id: "api-key".to_owned(),
        expected_ed25519_public_key: sha256_label("zolana-tvc-test-ed25519-pk"),
        allowed_clients: vec![ClientGrantV1 {
            client_key_id: "client-1".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            client_public_key: client_public.to_vec(),
            allowed_operations: vec![
                OperationKind::BootstrapKeyholder,
                OperationKind::DeriveViewTags,
                OperationKind::DecryptUtxos,
                OperationKind::BuildTransfer,
                OperationKind::BuildCustomRingTransfer,
                OperationKind::BuildSolWithdrawal,
                OperationKind::BuildCustomRingSolWithdrawal,
                OperationKind::AuthorizeDefaultRingTransfer,
            ],
            may_rotate_descriptor: false,
        }],
        policy_version: 1,
        previous_descriptor_digest: None,
        environment: Environment::Development,
        provisioning_key_id: "provisioner-1".to_owned(),
        owner_authorization_key: None,
        recovery_binding: None,
        provisioning_signature: vec![0u8; 64],
        owner_authorization: None,
        prior_client_authorization: None,
    }
}

fn sample_request(client_public: &[u8], running: &RunningEnclave) -> OperationRequestV1 {
    OperationRequestV1 {
        version: API_VERSION,
        request_id: sha256_label("zolana-tvc-test-request-id"),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_300_000,
        target_release_id: running.release_id.clone(),
        target_manifest_digest: running.manifest_digest,
        target_executable_digest: running.executable_digest,
        quorum_key_id: running.quorum_key_id.clone(),
        quorum_key_epoch: running.quorum_key_epoch,
        wallet_descriptor: sample_descriptor(client_public, running.security_domain_id),
        sealed_wallet_state: None,
        expected_state_version: None,
        expected_state_digest: None,
        client_response_public_key: client_public.to_vec(),
        operation: OperationV1::BootstrapKeyholder,
        authorization: ClientAuthorizationV1 {
            client_key_id: "client-1".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: Vec::new(),
        },
    }
}

fn sample_running() -> RunningEnclave {
    RunningEnclave {
        release_id: "tvc-dev-phase0".to_owned(),
        manifest_digest: sha256_label("zolana-tvc-test-manifest"),
        executable_digest: sha256_label("zolana-tvc-test-executable"),
        security_domain_id: sha256_label("zolana-tvc-test-security-domain"),
        quorum_key_id: "quorum-dev-1".to_owned(),
        quorum_key_epoch: 1,
        environment: Environment::Development,
    }
}

fn sample_info(quorum: &QosP256Public, ephemeral: &QosP256Public) -> ServiceInfoV1 {
    let running = sample_running();
    ServiceInfoV1 {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: running.security_domain_id,
        release_id: running.release_id,
        manifest_digest: running.manifest_digest,
        executable_digest: running.executable_digest,
        quorum_public_key: quorum.to_bytes().to_vec(),
        quorum_key_id: running.quorum_key_id,
        quorum_key_epoch: running.quorum_key_epoch,
        ephemeral_public_key: ephemeral.to_bytes().to_vec(),
        supported_operations: vec![
            OperationKind::BootstrapKeyholder,
            OperationKind::DeriveViewTags,
            OperationKind::DecryptUtxos,
            OperationKind::BuildTransfer,
            OperationKind::BuildCustomRingTransfer,
            OperationKind::BuildSolWithdrawal,
            OperationKind::BuildCustomRingSolWithdrawal,
            OperationKind::AuthorizeDefaultRingTransfer,
        ],
        max_encrypted_request_bytes: PHASE0_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: PHASE0_MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: ephemeral.to_bytes().to_vec(),
    }
}

fn sample_policy(info: &ServiceInfoV1) -> ReleasePolicyV1 {
    ReleasePolicyV1 {
        version: API_VERSION,
        release_id: info.release_id.clone(),
        environment: Environment::Development,
        tvc_application_id: "zolana-tvc-privacy-wallet".to_owned(),
        security_domain_id: info.security_domain_id,
        accepted_manifest_digests: vec![encode_lower_hex(&info.manifest_digest)],
        accepted_executable_digests: vec![encode_lower_hex(&info.executable_digest)],
        quorum_key_id: info.quorum_key_id.clone(),
        quorum_key_epoch: info.quorum_key_epoch,
        quorum_public_key: info.quorum_public_key.clone(),
        allowed_operations: info.supported_operations.clone(),
        max_encrypted_request_bytes: u32::try_from(info.max_encrypted_request_bytes).expect("u32"),
        max_encrypted_response_bytes: u32::try_from(info.max_encrypted_response_bytes)
            .expect("u32"),
        turnkey_trust_root_id: "turnkey-dev".to_owned(),
        turnkey_proof_schema_versions: vec!["v1".to_owned()],
        turnkey_verifier_version: "unbound-poc".to_owned(),
        valid_from_ms: 1_700_000_000_000,
        expires_at_ms: 1_800_000_000_000,
        revocation_epoch: 0,
    }
}

fn authority_public(secret: &[u8; 32]) -> Vec<u8> {
    public_key_uncompressed(
        &SecretKey::from_slice(secret)
            .expect("authority scalar")
            .public_key(),
    )
    .to_vec()
}

/// Build the committed fixture set. File bodies are compact JSON objects.
pub fn fixture_files() -> Result<BTreeMap<String, String>, crate::error::TvcError> {
    let client_sk = sha256_label("zolana-tvc-test-client-sk");
    let encryption_sk = sha256_label("zolana-tvc-test-encryption-sk");
    let signing_sk = sha256_label("zolana-tvc-test-signing-sk");
    let ephemeral_sk = sha256_label("zolana-tvc-test-ephemeral-sk");
    let wrong_sk = sha256_label("zolana-tvc-test-wrong-sk");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sha256_label("zolana-tvc-test-nonce")[..12]);

    let client_public = public_key_uncompressed(
        &SecretKey::from_slice(&client_sk)
            .expect("test client scalar")
            .public_key(),
    );
    let quorum = qos_public_from_secrets(&encryption_sk, &signing_sk)?;
    let ephemeral = qos_public_from_secrets(&ephemeral_sk, &signing_sk)?;
    let running = sample_running();
    let request =
        authorize_operation_request(sample_request(&client_public, &running), &client_sk)?;
    let request_digest_bytes = request_digest(&request)?;
    let client_auth = client_auth_digest(&request_digest_bytes);
    verify_client_authorization(&request, &client_public).expect("signed request verifies");

    let plaintext = b"qos-envelope-plaintext";
    let envelope = qos_encrypt_with(&quorum.encryption, plaintext, &ephemeral_sk, &nonce)?;
    let decrypted = qos_decrypt(&encryption_sk, &envelope)?;
    assert_eq!(decrypted.as_slice(), plaintext);

    let mut files = BTreeMap::new();

    let jcs_input = json!({"b": 1, "a": {"d": true, "c": "z"}, "arr": [2, 1]});
    let jcs = canonicalize_json_value(&jcs_input)?;
    files.insert(
        "jcs-object-sort.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "jcs-object-sort",
            "input": jcs_input,
            "canonical_json": jcs,
            "canonical_sha256": encode_lower_hex(&Sha256::digest(jcs.as_bytes())),
        }))
        .expect("fixture json"),
    );

    files.insert(
        "canonical-u64.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "canonical-u64",
            "values": [
                {"input": encode_decimal_u64(0), "encoded": encode_decimal_u64(0)},
                {"input": encode_decimal_u64(1), "encoded": encode_decimal_u64(1)},
                {"input": encode_decimal_u64(1_700_000_000_000), "encoded": encode_decimal_u64(1_700_000_000_000)},
                {"input": encode_decimal_u64(u64::MAX), "encoded": encode_decimal_u64(u64::MAX)},
            ],
            "negative": ["01", "+1", "1.0", "0x1", ""],
        }))
        .expect("fixture json"),
    );

    files.insert(
        "request-digest.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "request-digest",
            "request": serde_json::to_value(&request).expect("request"),
            "request_digest": encode_lower_hex(&request_digest_bytes),
            "client_auth_digest": encode_lower_hex(&client_auth),
            "includes_client_key_id": true,
            "excludes_signature_only": true,
        }))
        .expect("fixture json"),
    );

    let mut mutated_key = request.clone();
    mutated_key.authorization.client_key_id = "client-2".to_owned();
    files.insert(
        "authorization-mutation.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "authorization-mutation",
            "original_digest": encode_lower_hex(&request_digest_bytes),
            "mutated_client_key_id_digest": encode_lower_hex(&request_digest(&mutated_key)?),
            "mutated_client_key_id_verifies": verify_client_authorization(&mutated_key, &client_public).is_ok(),
        }))
        .expect("fixture json"),
    );

    let message = b"ZOLANA_TVC_CLIENT_AUTH_V1";
    let raw_sig = sign_p256_prehash(&client_sk, &client_auth)?;
    verify_p256_prehash(&client_public, &client_auth, &raw_sig).expect("raw sig");
    let der = der_encode_signature(&raw_sig);
    let high = high_s_signature(&raw_sig);
    let compressed = SecretKey::from_slice(&client_sk)
        .expect("client")
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let double_hash: [u8; 32] = Sha256::digest(client_auth).into();
    let double_sig = sign_p256_prehash(&client_sk, &double_hash)?;

    files.insert(
        "p256-signatures.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "p256-signatures",
            "public_key": encode_lower_hex(&client_public),
            "digest": encode_lower_hex(&client_auth),
            "raw_low_s": encode_lower_hex(&raw_sig),
            "der": encode_lower_hex(&der),
            "high_s": encode_lower_hex(&high),
            "compressed_public_key": encode_lower_hex(&compressed),
            "double_hash_digest": encode_lower_hex(&double_hash),
            "double_hash_signature": encode_lower_hex(&double_sig),
            "message_domain": encode_lower_hex(message),
        }))
        .expect("fixture json"),
    );

    files.insert(
        "qos-p256-public.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "qos-p256-public",
            "public_key": encode_lower_hex(&quorum.to_bytes()),
            "length": QOS_P256_PUBLIC_LEN,
            "encryption_sec1": encode_lower_hex(&quorum.encryption),
            "signing_sec1": encode_lower_hex(&quorum.signing),
        }))
        .expect("fixture json"),
    );

    files.insert(
        "qos-borsh-envelope.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "qos-borsh-envelope",
            "receiver_encryption_public": encode_lower_hex(&quorum.encryption),
            "ephemeral_secret": encode_lower_hex(&ephemeral_sk),
            "nonce": encode_lower_hex(&nonce),
            "plaintext": encode_lower_hex(plaintext),
            "envelope": encode_lower_hex(&envelope),
        }))
        .expect("fixture json"),
    );

    let mut truncated = envelope.clone();
    truncated.truncate(envelope.len().saturating_sub(8));
    let _wrong_plain = qos_decrypt(&wrong_sk, &envelope);
    files.insert(
        "qos-negative.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "qos-negative",
            "truncated_envelope": encode_lower_hex(&truncated),
            "wrong_receiver_secret": encode_lower_hex(&wrong_sk),
            "envelope": encode_lower_hex(&envelope),
        }))
        .expect("fixture json"),
    );

    let mut wrong_epoch = request.clone();
    wrong_epoch.quorum_key_epoch = 9;
    let mut wrong_release = request.clone();
    wrong_release.target_release_id = "other-release".to_owned();
    let mut wrong_manifest = request.clone();
    wrong_manifest.target_manifest_digest = sha256_label("wrong-manifest");
    let mut wrong_executable = request.clone();
    wrong_executable.target_executable_digest = sha256_label("wrong-executable");
    let mut wrong_quorum = request.clone();
    wrong_quorum.quorum_key_id = "other-quorum".to_owned();
    files.insert(
        "request-bindings.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "request-bindings",
            "ok": check_request_bindings(&request, &running).is_ok(),
            "wrong_epoch": check_request_bindings(&wrong_epoch, &running).unwrap_err().code.as_str(),
            "wrong_release": check_request_bindings(&wrong_release, &running).unwrap_err().code.as_str(),
            "wrong_manifest": check_request_bindings(&wrong_manifest, &running).unwrap_err().code.as_str(),
            "wrong_executable": check_request_bindings(&wrong_executable, &running).unwrap_err().code.as_str(),
            "wrong_quorum_key": check_request_bindings(&wrong_quorum, &running).unwrap_err().code.as_str(),
        }))
        .expect("fixture json"),
    );

    files.insert(
        "json-reject.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "json-reject",
            "unknown_field": "{\"status\":\"Healthy\",\"extra\":true}",
            "duplicate_field": "{\"status\":\"Healthy\",\"status\":\"Healthy\"}",
        }))
        .expect("fixture json"),
    );

    let proof_payload = canonicalize_json_str(
        r#"{"outcome":"Completed","type":"APP_PROOF_TYPE_POLICY_OUTCOME","version":1}"#,
    )?;
    let proof_sig = crate::crypto::sign_p256_message(&signing_sk, proof_payload.as_bytes())?;
    files.insert(
        "proof-payload-utf8.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "proof-payload-utf8",
            "proof_payload": proof_payload,
            "proof_payload_hex": encode_lower_hex(proof_payload.as_bytes()),
            "public_key": encode_lower_hex(&quorum.to_bytes()),
            "signature": encode_lower_hex(&proof_sig),
            "classification": "CryptographicallyValidButUnbound",
        }))
        .expect("fixture json"),
    );

    let info = sample_info(&quorum, &ephemeral);
    let health = handle_public_http("GET", "/health", &[], true, &info);
    let discovery = handle_public_http("GET", "/v1/info", &[], true, &info);
    files.insert(
        "http-skeleton.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "http-skeleton",
            "health_status": health.status,
            "health_body": String::from_utf8(health.body.clone()).expect("utf8"),
            "info_status": discovery.status,
            "info_body": String::from_utf8(discovery.body.clone()).expect("utf8"),
            "health_has_release_id": String::from_utf8_lossy(&health.body).contains("tvc-dev-phase0"),
        }))
        .expect("fixture json"),
    );

    files.insert(
        "digests.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "digests",
            "wallet_id_hash": encode_lower_hex(&wallet_id_hash("wallet-phase0-1")),
            "request_id_hash": encode_lower_hex(&request_id_hash(&request.request_id)),
            "result_digest": encode_lower_hex(&result_digest(b"encrypted-result")),
            "artifact_digest": encode_lower_hex(&artifact_digest(b"artifact")),
            "state_commitment": encode_lower_hex(&state_commitment(
                &request.wallet_descriptor.expected_ed25519_public_key,
                1,
                &sha256_label("state"),
                &sha256_label("descriptor"),
                1,
                0,
                &sha256_label("salt"),
            )),
        }))
        .expect("fixture json"),
    );

    let classification =
        classify_turnkey_policy_evidence(&proof_payload, &quorum.to_bytes(), &proof_sig)?;
    assert_eq!(
        classification,
        crate::types::TurnkeyEvidenceClassification::CryptographicallyValidButUnbound
    );
    reject_double_hashed_signature(&client_public, &client_auth, &double_sig)?;

    let authority_sk1 = sha256_label("zolana-tvc-test-release-authority-1");
    let authority_sk2 = sha256_label("zolana-tvc-test-release-authority-2");
    let authority_sk3 = sha256_label("zolana-tvc-test-release-authority-3");
    let policy = sample_policy(&info);
    let authorities = PinnedReleaseAuthoritiesV1 {
        authority_set_id: "dev-release-1".to_owned(),
        threshold: 1,
        keys: vec![
            ReleaseAuthorityKeyV1 {
                key_id: "release-1".to_owned(),
                public_key: authority_public(&authority_sk1),
            },
            ReleaseAuthorityKeyV1 {
                key_id: "release-2".to_owned(),
                public_key: authority_public(&authority_sk2),
            },
            ReleaseAuthorityKeyV1 {
                key_id: "release-3".to_owned(),
                public_key: authority_public(&authority_sk3),
            },
        ],
    };
    let signature = sign_release_policy(&policy, &authority_sk1)?;
    let signed = SignedReleasePolicyV1 {
        policy: policy.clone(),
        authority_set_id: authorities.authority_set_id.clone(),
        signatures: vec![ReleaseAuthoritySignatureV1 {
            key_id: "release-1".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: signature.to_vec(),
        }],
    };
    verify_signed_release_policy(&signed, &authorities, 1_750_000_000_000).expect("signed policy");
    let mut unsigned = signed.clone();
    unsigned.signatures.clear();
    let mut duplicate = signed.clone();
    duplicate.signatures.push(signed.signatures[0].clone());
    let mut unknown = signed.clone();
    unknown.signatures[0].key_id = "release-unknown".to_owned();
    let mut mutated = signed.clone();
    mutated.policy.release_id = "other-release".to_owned();
    let zero_threshold = PinnedReleaseAuthoritiesV1 {
        threshold: 0,
        ..authorities.clone()
    };
    files.insert(
        "signed-release-policy.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "signed-release-policy",
            "now_ms": "1750000000000",
            "authorities": authorities,
            "signed": signed,
            "policy_digest": encode_lower_hex(&crate::release::policy_signing_digest(&policy)?),
            "empty_signatures": verify_signed_release_policy(&unsigned, &authorities, 1_750_000_000_000).unwrap_err().code.as_str(),
            "empty_signatures_input": unsigned,
            "duplicate_key_id": verify_signed_release_policy(&duplicate, &authorities, 1_750_000_000_000).unwrap_err().code.as_str(),
            "duplicate_key_id_input": duplicate,
            "unknown_key_id": verify_signed_release_policy(&unknown, &authorities, 1_750_000_000_000).unwrap_err().code.as_str(),
            "unknown_key_id_input": unknown,
            "mutated_policy": verify_signed_release_policy(&mutated, &authorities, 1_750_000_000_000).unwrap_err().code.as_str(),
            "mutated_policy_input": mutated,
            "zero_threshold": verify_signed_release_policy(&signed, &zero_threshold, 1_750_000_000_000).unwrap_err().code.as_str(),
            "zero_threshold_authorities": zero_threshold,
            "expired": verify_signed_release_policy(&signed, &authorities, 1_900_000_000_000).unwrap_err().code.as_str(),
            "expired_now_ms": "1900000000000",
        }))
        .expect("fixture json"),
    );

    let descriptor = sample_descriptor(&client_public, sample_running().security_domain_id);
    let descriptor_digest = descriptor_digest_from_wallet(&descriptor)?;
    let owner_evidence = owner_auth_evidence_digest(&None, &None, &None)?;
    files.insert(
        "descriptor-digest.json".to_owned(),
        serde_json::to_string(&json!({
            "id": "descriptor-digest",
            "descriptor": descriptor,
            "descriptor_digest": encode_lower_hex(&descriptor_digest),
            "owner_evidence_digest": encode_lower_hex(&owner_evidence),
            "provisioning_auth_digest": encode_lower_hex(&provisioning_auth_digest(
                &descriptor_digest,
                &owner_evidence,
            )),
        }))
        .expect("fixture json"),
    );

    Ok(files)
}

pub fn manifest_for(files: &BTreeMap<String, String>) -> Value {
    let mut entries = serde_json::Map::new();
    for (name, body) in files {
        entries.insert(
            name.clone(),
            json!(encode_lower_hex(&Sha256::digest(body.as_bytes()))),
        );
    }
    json!({
        "algorithm": "sha256",
        "files": Value::Object(entries),
    })
}

pub fn write_fixtures(dir: &Path) -> Result<(), crate::error::TvcError> {
    std::fs::create_dir_all(dir).expect("create fixtures dir");
    let files = fixture_files()?;
    let manifest = serde_json::to_string_pretty(&manifest_for(&files)).expect("manifest");
    for (name, body) in &files {
        std::fs::write(dir.join(name), body.as_bytes()).expect("write fixture");
    }
    std::fs::write(dir.join("MANIFEST.json"), manifest.as_bytes()).expect("write manifest");
    Ok(())
}

pub fn verify_fixtures(dir: &Path) -> Result<(), crate::error::TvcError> {
    let files = fixture_files()?;
    let committed_manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("MANIFEST.json")).expect("read manifest"))
            .expect("parse manifest");
    let expected_manifest = manifest_for(&files);
    assert_eq!(
        committed_manifest, expected_manifest,
        "fixture manifest mismatch"
    );
    for (name, body) in files {
        let committed = std::fs::read_to_string(dir.join(&name)).expect("read fixture");
        assert_eq!(committed, body, "fixture {name} mismatch");
    }
    Ok(())
}
