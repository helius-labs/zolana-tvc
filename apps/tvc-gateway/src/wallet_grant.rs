//! Wallet grants gate the enclave operations: the enclave refuses a request
//! without a current grant for its descriptor and client key. The gateway
//! signs one for each operation it forwards, so a revoked client key stops at
//! once.

use std::collections::HashSet;

use anyhow::Context;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zolana_tvc_protocol::constants::{API_VERSION, MAX_WALLET_GRANT_LIFETIME_MS};
use zolana_tvc_protocol::digest::descriptor_digest;
use zolana_tvc_protocol::{WalletDescriptor, WalletGrant, sign_wallet_grant};

use crate::config::WalletGrantConfig;
use crate::error::ApiError;
use crate::project::ProjectId;

const CLIENT_KEY_ID_PREFIX: &str = "tvc-browser-p256-";

pub struct WalletGrants {
    secret: Zeroizing<[u8; 32]>,
    lifetime_ms: u64,
    revoked_client_key_ids: HashSet<String>,
}

impl WalletGrants {
    pub fn new(config: &WalletGrantConfig) -> anyhow::Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(config.private_key.trim(), secret.as_mut_slice())
            .context("wallet_grant.private_key must be 32 bytes of hex")?;
        let public_key = SecretKey::from_slice(secret.as_slice())
            .context("invalid P-256 wallet-grant key")?
            .public_key()
            .to_encoded_point(false);
        anyhow::ensure!(
            hex::encode(public_key.as_bytes()) == config.expected_public_key,
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
            lifetime_ms,
            revoked_client_key_ids: config.revoked_client_key_ids.iter().cloned().collect(),
        })
    }

    /// A grant for `descriptor`'s only client key, attributed to `project`.
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

/// The enclave's name for a client key.
pub fn client_key_id(client_public_key: &[u8]) -> String {
    let digest = Sha256::digest(client_public_key);
    format!("{CLIENT_KEY_ID_PREFIX}{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
pub(crate) mod tests {
    use zolana_tvc_protocol::verify_wallet_grant;

    use super::*;

    pub const GRANT_SECRET_HEX: &str =
        "0606060606060606060606060606060606060606060606060606060606060606";
    const NOW: u64 = 1_800_000_000_000;

    fn grant_public_key() -> [u8; 65] {
        let point = SecretKey::from_slice(&[6; 32])
            .map(|secret| secret.public_key().to_encoded_point(false))
            .ok();
        let Some(Ok(public_key)) = point.map(|point| point.as_bytes().try_into()) else {
            panic!("test grant key is invalid");
        };
        public_key
    }

    pub fn grants(revoked: Vec<String>) -> WalletGrants {
        let config = WalletGrantConfig {
            private_key: GRANT_SECRET_HEX.to_owned(),
            expected_public_key: hex::encode(grant_public_key()),
            ttl_secs: 120,
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

    #[test]
    fn an_issued_grant_satisfies_the_enclave_for_its_lifetime() {
        let descriptor = descriptor();
        let Ok(grant) =
            grants(Vec::new()).issue(&ProjectId::for_tests("project-a"), &descriptor, NOW)
        else {
            panic!("issue failed");
        };
        let client_key_id = client_key_id(&descriptor.allowed_clients[0].client_public_key);
        assert_eq!(grant.project_id, "project-a");
        assert_eq!(grant.expires_at_ms, NOW + 120_000);
        assert!(
            verify_wallet_grant(
                &grant,
                &grant_public_key(),
                &descriptor,
                &client_key_id,
                NOW + 1
            )
            .is_ok()
        );
    }

    #[test]
    fn a_revoked_client_key_gets_no_grant() {
        let descriptor = descriptor();
        let key = &descriptor.allowed_clients[0].client_public_key;
        let revoking = grants(vec![client_key_id(key)]);
        let revoked = Some(ApiError::Forbidden("ClientKeyRevoked"));
        assert_eq!(
            revoking
                .issue(&ProjectId::for_tests("project-a"), &descriptor, NOW)
                .err(),
            revoked
        );
        assert_eq!(revoking.check_client_key(key).err(), revoked);
    }

    #[test]
    fn client_key_id_matches_the_enclave_format() {
        let id = client_key_id(&[4; 65]);
        assert!(id.starts_with(CLIENT_KEY_ID_PREFIX));
        assert_eq!(id.len(), CLIENT_KEY_ID_PREFIX.len() + 32);
    }
}
