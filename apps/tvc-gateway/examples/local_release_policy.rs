//! Writes a signed release policy and its authority set for the local
//! unattested testkit (`packages/tvc-wallet/src/local-testkit.json`), so the
//! gateway can run against it:
//!
//!   cargo run --example local_release_policy -- <out-dir>
//!
//! Writes `<out-dir>/release-policy.json` and `<out-dir>/release-authorities.json`.
//! The authority key is a fixed test key; never deploy the output.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use tvc_gateway::provisioner::now_ms;
use zolana_tvc_protocol::digest::sha256;
use zolana_tvc_protocol::{
    ClientAuthorizationScheme, Environment, OperationKind, PinnedReleaseAuthorities,
    ReleaseAuthorityKey, ReleaseAuthoritySignature, ReleasePolicy, SignedReleasePolicy,
    sign_release_policy,
};

const TESTKIT_JSON: &str = include_str!("../../../packages/tvc-wallet/src/local-testkit.json");
const AUTHORITY_SECRET: [u8; 32] = [0x33; 32];
const AUTHORITY_SET_ID: &str = "local-testkit";
const AUTHORITY_KEY_ID: &str = "local-testkit-authority-1";
const VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Testkit {
    release_id: String,
    quorum_key_id: String,
    security_domain_label: String,
    manifest_label: String,
    executable_label: String,
    quorum_public_key: String,
    operations: Vec<OperationKind>,
}

fn main() -> anyhow::Result<()> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: local_release_policy <out-dir>")?,
    );
    let testkit: Testkit = serde_json::from_str(TESTKIT_JSON)?;
    let now = now_ms()?;
    let validity_ms = u64::try_from(VALIDITY.as_millis())?;
    let policy = ReleasePolicy {
        version: 1,
        release_id: testkit.release_id,
        environment: Environment::Development,
        tvc_application_id: "local-testkit".to_owned(),
        security_domain_id: sha256(testkit.security_domain_label.as_bytes()),
        accepted_manifest_digests: vec![hex::encode(sha256(testkit.manifest_label.as_bytes()))],
        accepted_executable_digests: vec![hex::encode(sha256(testkit.executable_label.as_bytes()))],
        quorum_key_id: testkit.quorum_key_id,
        quorum_key_epoch: 1,
        quorum_public_key: hex::decode(testkit.quorum_public_key)?,
        allowed_operations: testkit.operations,
        max_encrypted_request_bytes: 262_144,
        max_encrypted_response_bytes: 262_144,
        turnkey_trust_root_id: "aws-nitro-root-g1".to_owned(),
        turnkey_proof_schema_versions: vec!["turnkey.boot_proof.v1".to_owned()],
        valid_from_ms: now.saturating_sub(60 * 60 * 1_000),
        expires_at_ms: now.saturating_add(validity_ms),
        revocation_epoch: 0,
    };
    let signature = sign_release_policy(&policy, &AUTHORITY_SECRET)
        .map_err(|error| anyhow::anyhow!("signing failed: {error:?}"))?;
    let signed = SignedReleasePolicy {
        policy,
        authority_set_id: AUTHORITY_SET_ID.to_owned(),
        signatures: vec![ReleaseAuthoritySignature {
            key_id: AUTHORITY_KEY_ID.to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: signature.to_vec(),
        }],
    };
    let authority_public = SecretKey::from_slice(&AUTHORITY_SECRET)?
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let authorities = PinnedReleaseAuthorities {
        authority_set_id: AUTHORITY_SET_ID.to_owned(),
        threshold: 1,
        keys: vec![ReleaseAuthorityKey {
            key_id: AUTHORITY_KEY_ID.to_owned(),
            public_key: authority_public,
        }],
        minimum_revocation_epoch: 0,
    };
    std::fs::create_dir_all(&out_dir)?;
    std::fs::write(
        out_dir.join("release-policy.json"),
        serde_json::to_vec_pretty(&signed)?,
    )?;
    std::fs::write(
        out_dir.join("release-authorities.json"),
        serde_json::to_vec_pretty(&authorities)?,
    )?;
    Ok(())
}
