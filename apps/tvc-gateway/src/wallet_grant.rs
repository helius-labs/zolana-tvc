//! Wallet grants gate the enclave operations: the enclave refuses a request
//! without a current grant for its descriptor and client key, so a revoked
//! client key stops within one grant lifetime. One is issued with each
//! descriptor and renewed by the descriptor's client key signing
//! `WALLET_GRANT_RENEWAL_DOMAIN || 0x00 || descriptor_digest || be_u64(issued_at_ms)`
//! (ECDSA P-256 / SHA-256, raw 64-byte `r || s`).

use std::collections::HashSet;

use anyhow::Context;
use p256::SecretKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::{API_VERSION, MAX_WALLET_GRANT_LIFETIME_MS};
use zolana_tvc_protocol::crypto::verify_p256_prehash;
use zolana_tvc_protocol::digest::{descriptor_digest, domain_separated_hash, wallet_grant_digest};
use zolana_tvc_protocol::{WalletDescriptor, WalletGrant, sign_wallet_grant};

use crate::config::WalletGrantConfig;
use crate::error::ApiError;
use crate::project::ProjectId;

pub const WALLET_GRANT_RENEWAL_DOMAIN: &[u8] = b"HELIUS_TVC_GATEWAY_WALLET_GRANT_RENEWAL_V1";
const CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";
const MAX_RENEWAL_SKEW_MS: u64 = 60_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Renewal {
    pub descriptor: WalletDescriptor,
    pub issued_at_ms: u64,
    /// Raw 64-byte P-256 signature by the descriptor's client key, hex.
    pub signature: String,
}

pub struct WalletGrants {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 65],
    lifetime_ms: u64,
    revoked_client_key_ids: HashSet<String>,
}

impl WalletGrants {
    pub fn new(config: &WalletGrantConfig) -> anyhow::Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(config.private_key.trim(), secret.as_mut_slice())
            .context("wallet_grant.private_key must be 32 bytes of hex")?;
        let public_key: [u8; 65] = SecretKey::from_slice(secret.as_slice())
            .context("invalid P-256 wallet-grant key")?
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .context("P-256 public key is not 65 bytes")?;
        anyhow::ensure!(
            hex::encode(public_key) == config.expected_public_key,
            "wallet_grant.private_key does not match wallet_grant.expected_public_key"
        );
        let lifetime_ms = config.ttl_secs.saturating_mul(1_000);
        anyhow::ensure!(
            lifetime_ms > 0 && lifetime_ms <= MAX_WALLET_GRANT_LIFETIME_MS,
            "wallet_grant.ttl_secs must be positive and at most {} seconds",
            MAX_WALLET_GRANT_LIFETIME_MS / 1_000
        );
        Ok(Self {
            secret,
            public_key,
            lifetime_ms,
            revoked_client_key_ids: config.revoked_client_key_ids.iter().cloned().collect(),
        })
    }

    pub fn issue(
        &self,
        project: &ProjectId,
        descriptor: &WalletDescriptor,
        now_ms: u64,
    ) -> Result<WalletGrant, ApiError> {
        let unavailable = ApiError::Upstream("WalletGrantUnavailable");
        let [client] = descriptor.allowed_clients.as_slice() else {
            return Err(ApiError::Forbidden("InvalidDescriptor"));
        };
        let client_key_id = self.unrevoked(client_key_id(&client.client_public_key))?;
        let unsigned = WalletGrant {
            version: API_VERSION,
            descriptor_digest: descriptor_digest(descriptor).map_err(|_| unavailable)?,
            client_key_id,
            project_id: project.as_str().to_owned(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(self.lifetime_ms),
            signature: Vec::new(),
        };
        sign_wallet_grant(unsigned, &self.secret).map_err(|error| {
            tracing::error!(?error, "wallet grant signing failed");
            unavailable
        })
    }

    /// Accepts an unexpired, unrevoked grant this gateway issued to `project`.
    /// The enclave binds it to the operation's descriptor and client key.
    pub fn verify(
        &self,
        grant: &WalletGrant,
        project: &ProjectId,
        now_ms: u64,
    ) -> Result<(), ApiError> {
        let invalid = ApiError::Unauthorized("InvalidWalletGrant");
        let digest = wallet_grant_digest(grant).map_err(|_| invalid)?;
        verify_p256_prehash(&self.public_key, &digest, &grant.signature).map_err(|_| invalid)?;
        if grant.version != API_VERSION
            || grant.expires_at_ms < now_ms
            || grant.project_id != project.as_str()
        {
            return Err(invalid);
        }
        self.unrevoked(grant.client_key_id.clone()).map(|_| ())
    }

    /// Refuses a revoked client key before any Turnkey call is spent on it.
    pub fn check_client_key(&self, client_public_key: &[u8]) -> Result<(), ApiError> {
        self.unrevoked(client_key_id(client_public_key)).map(|_| ())
    }

    fn unrevoked(&self, client_key_id: String) -> Result<String, ApiError> {
        if self.revoked_client_key_ids.contains(&client_key_id) {
            return Err(ApiError::Forbidden("ClientKeyRevoked"));
        }
        Ok(client_key_id)
    }
}

/// Checks the client key's renewal signature and freshness. The caller has
/// already verified the descriptor's provisioning signature.
pub fn verify_renewal(renewal: &Renewal, now_ms: u64) -> Result<(), ApiError> {
    let invalid = ApiError::Unauthorized("InvalidRenewalSignature");
    if now_ms.abs_diff(renewal.issued_at_ms) > MAX_RENEWAL_SKEW_MS {
        return Err(ApiError::Unauthorized("StaleRenewal"));
    }
    let [client] = renewal.descriptor.allowed_clients.as_slice() else {
        return Err(ApiError::Forbidden("InvalidDescriptor"));
    };
    let digest = renewal_digest(&renewal.descriptor, renewal.issued_at_ms)?;
    let key = VerifyingKey::from_sec1_bytes(&client.client_public_key).map_err(|_| invalid)?;
    let mut raw = [0u8; 64];
    hex::decode_to_slice(&renewal.signature, &mut raw).map_err(|_| invalid)?;
    let signature = Signature::from_slice(&raw).map_err(|_| invalid)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify_prehash(&digest, &signature).map_err(|_| invalid)
}

pub fn renewal_digest(
    descriptor: &WalletDescriptor,
    issued_at_ms: u64,
) -> Result<[u8; 32], ApiError> {
    let descriptor_digest =
        descriptor_digest(descriptor).map_err(|_| ApiError::Forbidden("InvalidDescriptor"))?;
    let mut payload = [0u8; 40];
    payload[..32].copy_from_slice(&descriptor_digest);
    payload[32..].copy_from_slice(&issued_at_ms.to_be_bytes());
    Ok(domain_separated_hash(WALLET_GRANT_RENEWAL_DOMAIN, &payload))
}

/// The enclave's name for a client key.
pub fn client_key_id(client_public_key: &[u8]) -> String {
    let digest = Sha256::digest(client_public_key);
    format!("{CLIENT_KEY_ID_PREFIX}{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
pub(crate) mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use zolana_tvc_protocol::verify_wallet_grant;

    use super::*;

    pub const GRANT_SECRET_HEX: &str =
        "0606060606060606060606060606060606060606060606060606060606060606";
    const NOW: u64 = 1_800_000_000_000;

    pub fn grants(revoked: Vec<String>) -> WalletGrants {
        let public = SecretKey::from_slice(&[6; 32])
            .map(|secret| hex::encode(secret.public_key().to_encoded_point(false).as_bytes()))
            .unwrap_or_default();
        let config = WalletGrantConfig {
            private_key: GRANT_SECRET_HEX.to_owned(),
            expected_public_key: public,
            ttl_secs: 900,
            revoked_client_key_ids: revoked,
        };
        let Ok(grants) = WalletGrants::new(&config) else {
            panic!("wallet grant key is invalid");
        };
        grants
    }

    fn descriptor() -> WalletDescriptor {
        let provisioner = crate::provisioner::tests::provisioner();
        let Ok(descriptor) = provisioner.sign(&crate::enrollment::tests::input()) else {
            panic!("signing failed");
        };
        descriptor
    }

    fn client() -> SigningKey {
        let Ok(key) = SigningKey::from_slice(&[5; 32]) else {
            panic!("test client key is invalid");
        };
        key
    }

    fn renewal(issued_at_ms: u64, signer: &SigningKey) -> Renewal {
        let descriptor = descriptor();
        let Ok(digest) = renewal_digest(&descriptor, issued_at_ms) else {
            panic!("digest failed");
        };
        let signed: Result<Signature, _> = signer.sign_prehash(&digest);
        let Ok(signature) = signed else {
            panic!("signing failed");
        };
        Renewal {
            descriptor,
            issued_at_ms,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    #[test]
    fn an_issued_grant_satisfies_the_enclave_and_this_gateway_for_its_project() {
        let grants = grants(Vec::new());
        let project = ProjectId::for_tests("project-a");
        let descriptor = descriptor();
        let Ok(grant) = grants.issue(&project, &descriptor, NOW) else {
            panic!("issue failed");
        };
        let client_key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
        assert!(
            verify_wallet_grant(
                &grant,
                &grants.public_key,
                &descriptor,
                &client_key_id,
                NOW + 1
            )
            .is_ok()
        );
        assert_eq!(grants.verify(&grant, &project, NOW + 1), Ok(()));
        let invalid = Err(ApiError::Unauthorized("InvalidWalletGrant"));
        assert_eq!(
            grants.verify(&grant, &ProjectId::for_tests("project-b"), NOW + 1),
            invalid
        );
        assert_eq!(
            grants.verify(&grant, &project, grant.expires_at_ms + 1),
            invalid
        );
        let mut altered = grant.clone();
        altered.project_id = "project-b".to_owned();
        assert_eq!(
            grants.verify(&altered, &ProjectId::for_tests("project-b"), NOW + 1),
            invalid
        );
    }

    #[test]
    fn a_revoked_client_key_gets_no_grant_and_its_grants_stop_working() {
        let project = ProjectId::for_tests("project-a");
        let descriptor = descriptor();
        let Ok(grant) = grants(Vec::new()).issue(&project, &descriptor, NOW) else {
            panic!("issue failed");
        };
        let key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
        let revoking = grants(vec![key_id]);
        let revoked = ApiError::Forbidden("ClientKeyRevoked");
        assert_eq!(
            revoking.issue(&project, &descriptor, NOW).err(),
            Some(revoked)
        );
        assert_eq!(revoking.verify(&grant, &project, NOW), Err(revoked));
    }

    #[test]
    fn a_renewal_needs_the_descriptors_client_key_and_a_fresh_timestamp() {
        assert_eq!(
            verify_renewal(&renewal(NOW, &client()), NOW + 1_000),
            Ok(())
        );
        let Ok(intruder) = SigningKey::from_slice(&[6; 32]) else {
            panic!("intruder key is invalid");
        };
        assert_eq!(
            verify_renewal(&renewal(NOW, &intruder), NOW),
            Err(ApiError::Unauthorized("InvalidRenewalSignature"))
        );
        assert_eq!(
            verify_renewal(&renewal(NOW, &client()), NOW + MAX_RENEWAL_SKEW_MS + 1),
            Err(ApiError::Unauthorized("StaleRenewal"))
        );
    }

    #[test]
    fn client_key_id_matches_the_enclave_format() {
        let id = client_key_id(&[4; 65]);
        assert!(id.starts_with(CLIENT_KEY_ID_PREFIX));
        assert_eq!(id.len(), CLIENT_KEY_ID_PREFIX.len() + 32);
    }
}
