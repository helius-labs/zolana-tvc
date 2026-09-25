//! Service configuration: YAML file with `TVC_GATEWAY_` env overrides
//! (nested fields split on `__`, e.g. `TVC_GATEWAY_PROVISIONING__PRIVATE_KEY`).

use std::net::SocketAddr;
use std::path::PathBuf;

use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Dev,
    Prod,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub stage: Stage,
    pub listen: SocketAddr,
    pub metrics: MetricsConfig,
    /// `Authorization` value gatekeeper sends on every origin request. Secret.
    pub origin_auth_header: String,
    pub enclave: EnclaveConfig,
    pub turnkey: TurnkeyConfig,
    pub provisioning: ProvisioningConfig,
    pub wallet_token: WalletTokenConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub statsd_endpoint: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveConfig {
    /// TVC public ingress, without a trailing slash.
    pub base_url: String,
    pub request_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub max_in_flight_per_project: u32,
    pub replay_window_secs: u64,
    pub replay_max_entries: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyConfig {
    pub api_base_url: String,
    /// Organization that owns the TVC application; Boot Proofs are read here.
    pub tvc_organization_id: String,
    /// Helius WaaS organization; every end-user wallet is in one of its sub-orgs.
    pub waas_parent_organization_id: String,
    pub boot_proof_api_key: TurnkeyApiKey,
    pub waas_api_key: TurnkeyApiKey,
    pub ownership_cache_secs: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnkeyApiKey {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningConfig {
    /// 32-byte P-256 secret, hex. Signs wallet descriptors. Secret.
    pub private_key: String,
    /// Uncompressed SEC1 hex of the key the enclave is built with.
    pub expected_public_key: String,
    /// HMAC key for enrollment challenges, at least 32 bytes. Secret.
    pub enrollment_secret: String,
    /// `SignedReleasePolicy` JSON the clients pin.
    pub release_policy_path: PathBuf,
    /// `PinnedReleaseAuthorities` JSON the policy must verify against.
    pub release_authorities_path: PathBuf,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletTokenConfig {
    /// HMAC key for wallet tokens, at least 32 bytes. Secret.
    pub secret: String,
    pub ttl_secs: u64,
    /// Client key IDs (`tvc-browser-p256-…`) refused a wallet token.
    #[serde(default)]
    pub revoked_client_key_ids: Vec<String>,
}

pub const MIN_SECRET_LEN: usize = 32;

pub fn load(path: &str) -> anyhow::Result<Config> {
    let config: Config = Figment::new()
        .merge(Yaml::file(path))
        .merge(Env::prefixed("TVC_GATEWAY_").split("__"))
        .extract()?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.origin_auth_header.len() >= MIN_SECRET_LEN,
            "origin_auth_header must be at least {MIN_SECRET_LEN} bytes"
        );
        anyhow::ensure!(
            !self.enclave.base_url.ends_with('/'),
            "enclave.base_url must not end with '/'"
        );
        anyhow::ensure!(
            self.enclave.max_in_flight_per_project > 0,
            "enclave.max_in_flight_per_project must be positive"
        );
        anyhow::ensure!(
            self.enclave.replay_window_secs > 0 && self.enclave.replay_max_entries > 0,
            "enclave replay window and capacity must be positive"
        );
        anyhow::ensure!(
            self.provisioning.enrollment_secret.len() >= MIN_SECRET_LEN,
            "provisioning.enrollment_secret must be at least {MIN_SECRET_LEN} bytes"
        );
        anyhow::ensure!(
            self.wallet_token.secret.len() >= MIN_SECRET_LEN,
            "wallet_token.secret must be at least {MIN_SECRET_LEN} bytes"
        );
        anyhow::ensure!(
            self.wallet_token.ttl_secs > 0,
            "wallet_token.ttl_secs must be positive"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use figment::providers::Serialized;

    use super::*;

    fn committed_config_with(origin_auth_header: &str) -> anyhow::Result<Config> {
        let secrets = serde_json::json!({
            "origin_auth_header": origin_auth_header,
            "provisioning": {
                "private_key": "11".repeat(32),
                "enrollment_secret": "e".repeat(MIN_SECRET_LEN),
            },
            "wallet_token": { "secret": "w".repeat(MIN_SECRET_LEN) },
            "turnkey": {
                "boot_proof_api_key": { "public_key": "02", "private_key": "01" },
                "waas_api_key": { "public_key": "02", "private_key": "01" },
            },
        });
        let config: Config = Figment::new()
            .merge(Yaml::file("configs/config.yaml"))
            .merge(Serialized::defaults(secrets))
            .extract()?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn the_committed_config_requires_a_full_length_origin_secret() {
        assert!(committed_config_with(&"a".repeat(MIN_SECRET_LEN)).is_ok());
        assert!(committed_config_with("").is_err());
        assert!(committed_config_with("Bearer short").is_err());
    }
}
