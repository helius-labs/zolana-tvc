//! Sign one release policy with a one-time authority key.
//!
//! Usage:
//!
//! ```sh
//! cargo run -p zolana-tvc-protocol --example sign-release-policy \
//!     -- policy.json <authority-set-id>
//! ```
//!
//! `policy.json` is a `ReleasePolicy` in the same camelCase shape the client
//! pins. The output is the two objects a client needs: the signed policy and
//! the pinned authority set.
//!
//! The signing key is generated here, used once, and never written anywhere.
//! That is the property being bought: a policy cannot be quietly re-signed
//! later, because doing so requires a new authority set, and a new authority
//! set is a change every client must be updated to accept. The private half
//! existing anywhere afterwards would defeat it, so this prints only the
//! public half.
//!
//! Entropy comes from `/dev/urandom` rather than a dependency, so an operator
//! running the ceremony can see exactly where the key came from.

use std::fs;
use std::io::Read;
use std::process::ExitCode;

use zeroize::Zeroizing;

use zolana_tvc_protocol::crypto::{public_key_uncompressed, sign_p256_prehash};
use zolana_tvc_protocol::release::{
    policy_signing_digest, verify_signed_release_policy, PinnedReleaseAuthorities,
    ReleaseAuthorityKey,
};
use zolana_tvc_protocol::types::{
    ClientAuthorizationScheme, ReleaseAuthoritySignature, ReleasePolicy, SignedReleasePolicy,
};

fn urandom_scalar() -> Result<Zeroizing<[u8; 32]>, String> {
    // A uniformly random 32-byte string is only a valid P-256 scalar when it
    // is in range and non-zero. Rejection keeps the distribution honest; a
    // reduction would not.
    let mut source = fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    for _ in 0..64 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        source
            .read_exact(bytes.as_mut())
            .map_err(|error| error.to_string())?;
        if p256::ecdsa::SigningKey::from_slice(bytes.as_ref()).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not draw a valid P-256 scalar".to_owned())
}

fn run() -> Result<String, String> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(authority_set_id)) = (args.next(), args.next()) else {
        return Err("usage: sign-release-policy <policy.json> <authority-set-id>".to_owned());
    };
    let policy: ReleasePolicy = serde_json::from_str(
        &fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?,
    )
    .map_err(|error| format!("{path}: {error}"))?;

    let secret = urandom_scalar()?;
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(secret.as_ref()).map_err(|error| error.to_string())?;
    let public = public_key_uncompressed(&p256::PublicKey::from(signing_key.verifying_key()));
    let digest = policy_signing_digest(&policy).map_err(|error| format!("{error:?}"))?;
    let signature = sign_p256_prehash(&secret, &digest).map_err(|error| format!("{error:?}"))?;

    let key_id = format!("{}-authority-1", policy.release_id);
    let signed = SignedReleasePolicy {
        policy,
        authority_set_id: authority_set_id.clone(),
        signatures: vec![ReleaseAuthoritySignature {
            key_id: key_id.clone(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: signature.to_vec(),
        }],
    };
    let authorities = PinnedReleaseAuthorities {
        authority_set_id,
        threshold: 1,
        minimum_revocation_epoch: 0,
        keys: vec![ReleaseAuthorityKey {
            key_id,
            public_key: public.to_vec(),
        }],
    };
    // Verify before printing. The private half is gone the moment this
    // returns, so an output that does not verify could never be repaired.
    verify_signed_release_policy(&signed, &authorities, signed.policy.valid_from_ms)
        .map_err(|error| format!("signed policy failed its own verification: {error:?}"))?;

    serde_json::to_string_pretty(&serde_json::json!({
        "releasePolicy": signed,
        "releaseAuthorities": authorities,
    }))
    .map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
