use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cadence_macros::statsd_count;
use tokio::sync::{Semaphore, SemaphorePermit};
use turnkey_client::generated::external::options::v1::Pagination;
use turnkey_client::generated::services::coordinator::public::v1::{
    GetBootProofRequest, GetWalletAccountsRequest, GetWhoamiRequest,
};
use turnkey_client::{TurnkeyClient, TurnkeyClientError, TurnkeyP256ApiKey};

use crate::config::{TurnkeyApiKey, TurnkeyConfig};
use crate::error::ApiError;
use crate::project::ProjectId;

const TURNKEY_TIMEOUT: Duration = Duration::from_secs(15);
/// Both Turnkey keys are shared by every project, so their call rate is too.
const MAX_CONCURRENT_TURNKEY_CALLS: usize = 32;
const WALLET_ACCOUNTS_PAGE: &str = "100";
const BOOT_PROOF_CACHE_CAPACITY: usize = 256;
const OWNERSHIP_CACHE_CAPACITY: usize = 100_000;
/// `boot_proof_lookup_key` from `/v1/info`: 130 bytes, lowercase hex.
const EPHEMERAL_KEY_HEX_LEN: usize = 260;

/// The wallet a descriptor names, as the client claims it.
pub struct ClaimedWallet<'a> {
    pub organization_id: &'a str,
    pub wallet_id: &'a str,
    pub address: &'a str,
}

pub struct Turnkey {
    tvc_organization_id: String,
    boot_proofs: TurnkeyClient<TurnkeyP256ApiKey>,
    waas: TurnkeyClient<TurnkeyP256ApiKey>,
    boot_proof_cache: Mutex<HashMap<String, Bytes>>,
    ownership_ttl: Duration,
    sub_org_projects: Mutex<HashMap<String, (String, Instant)>>,
    calls: Semaphore,
}

impl Turnkey {
    pub fn new(config: &TurnkeyConfig) -> anyhow::Result<Self> {
        Ok(Self {
            tvc_organization_id: config.tvc_organization_id.clone(),
            boot_proofs: client(&config.api_base_url, &config.boot_proof_api_key)?,
            waas: client(&config.api_base_url, &config.waas_api_key)?,
            boot_proof_cache: Mutex::new(HashMap::new()),
            ownership_ttl: Duration::from_secs(config.ownership_cache_secs),
            sub_org_projects: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
        })
    }

    /// The Boot Proof JSON for one replica. A replica's proof never changes.
    pub async fn boot_proof(&self, ephemeral_key: &str) -> Result<Bytes, ApiError> {
        if !is_lower_hex(ephemeral_key, EPHEMERAL_KEY_HEX_LEN) {
            return Err(ApiError::BadRequest("InvalidEphemeralKey"));
        }
        if let Some(cached) = self.cached_boot_proof(ephemeral_key) {
            statsd_count!("boot_proof.cache_hit", 1);
            return Ok(cached);
        }
        let _call = self.call_permit()?;
        let response = self
            .boot_proofs
            .get_boot_proof(GetBootProofRequest {
                organization_id: self.tvc_organization_id.clone(),
                ephemeral_key: ephemeral_key.to_owned(),
            })
            .await
            .map_err(|error| turnkey_failure("get_boot_proof", &error, ApiError::NotFound))?;
        let boot_proof = response.boot_proof.ok_or(ApiError::NotFound)?;
        let body = serde_json::to_vec(&boot_proof).map_err(|error| {
            tracing::error!(%error, "boot proof did not serialize");
            ApiError::Upstream("BootProofInvalid")
        })?;
        let body = Bytes::from(body);
        self.cache_boot_proof(ephemeral_key, &body);
        Ok(body)
    }

    /// Refuses a wallet that is not in a sub-org of the caller's project, or
    /// whose account does not have the claimed address.
    pub async fn verify_ownership(
        &self,
        project: &ProjectId,
        wallet: &ClaimedWallet<'_>,
    ) -> Result<(), ApiError> {
        self.verify_sub_org_project(project, wallet.organization_id)
            .await?;
        let _call = self.call_permit()?;
        let accounts = self
            .waas
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: wallet.organization_id.to_owned(),
                wallet_id: Some(wallet.wallet_id.to_owned()),
                include_wallet_details: None,
                pagination_options: Some(Pagination {
                    limit: WALLET_ACCOUNTS_PAGE.to_owned(),
                    before: String::new(),
                    after: String::new(),
                }),
            })
            .await
            .map_err(|error| turnkey_failure("get_wallet_accounts", &error, NOT_OWNED))?;
        let owned = accounts.accounts.iter().any(|account| {
            account.wallet_id == wallet.wallet_id && account.address == wallet.address
        });
        if !owned {
            statsd_count!("ownership.rejected", 1, "reason" => "wallet");
            return Err(ApiError::Forbidden("WalletNotOwned"));
        }
        Ok(())
    }

    /// Refuses a sub-org that is not named after the caller's project. Whoami
    /// through the parent key only resolves the parent's own sub-orgs.
    pub async fn verify_sub_org_project(
        &self,
        project: &ProjectId,
        organization_id: &str,
    ) -> Result<(), ApiError> {
        let name = match self.cached_sub_org_project(organization_id) {
            Some(name) => name,
            None => self.fetch_sub_org_project(organization_id).await?,
        };
        if name != project.as_str() {
            statsd_count!("ownership.rejected", 1, "reason" => "project");
            return Err(ApiError::Forbidden("SubOrganizationNotOwned"));
        }
        Ok(())
    }

    async fn fetch_sub_org_project(&self, organization_id: &str) -> Result<String, ApiError> {
        let _call = self.call_permit()?;
        let whoami = self
            .waas
            .get_whoami(GetWhoamiRequest {
                organization_id: organization_id.to_owned(),
            })
            .await
            .map_err(|error| turnkey_failure("get_whoami", &error, NOT_OWNED))?;
        let mut cache = self
            .sub_org_projects
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= OWNERSHIP_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(
            organization_id.to_owned(),
            (whoami.organization_name.clone(), Instant::now()),
        );
        Ok(whoami.organization_name)
    }

    fn call_permit(&self) -> Result<SemaphorePermit<'_>, ApiError> {
        self.calls.try_acquire().map_err(|_| {
            statsd_count!("turnkey.concurrency_rejected", 1);
            ApiError::TooManyInFlight
        })
    }

    fn cached_sub_org_project(&self, organization_id: &str) -> Option<String> {
        let cache = self
            .sub_org_projects
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (name, fetched_at) = cache.get(organization_id)?;
        (fetched_at.elapsed() < self.ownership_ttl).then(|| name.clone())
    }

    fn cached_boot_proof(&self, ephemeral_key: &str) -> Option<Bytes> {
        self.boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(ephemeral_key)
            .cloned()
    }

    fn cache_boot_proof(&self, ephemeral_key: &str, body: &Bytes) {
        let mut cache = self
            .boot_proof_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= BOOT_PROOF_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(ephemeral_key.to_owned(), body.clone());
    }
}

fn client(base_url: &str, key: &TurnkeyApiKey) -> anyhow::Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    let api_key = TurnkeyP256ApiKey::from_strings(&key.private_key, Some(&key.public_key))?;
    Ok(TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(base_url)
        .timeout(TURNKEY_TIMEOUT)
        .build()?)
}

const NOT_OWNED: ApiError = ApiError::Forbidden("TurnkeyRejected");

/// A 400, 403 or 404 is the caller's claim failing: `rejected` for the call.
/// A 401 is this gateway's key, a 429 Turnkey's limit, and anything else an
/// outage; all three are `Upstream`.
fn turnkey_failure(call: &'static str, error: &TurnkeyClientError, rejected: ApiError) -> ApiError {
    let status = if let TurnkeyClientError::UnexpectedHttpStatus(status, _) = error {
        Some(*status)
    } else {
        None
    };
    let mapped = turnkey_status(status, rejected);
    if let ApiError::Upstream(code) = mapped {
        tracing::warn!(call, code, error = %error, "turnkey call failed");
        statsd_count!("turnkey.failed", 1, "call" => call, "code" => code);
    } else {
        statsd_count!("turnkey.rejected", 1, "call" => call);
    }
    mapped
}

const fn turnkey_status(status: Option<u16>, rejected: ApiError) -> ApiError {
    match status {
        Some(400 | 403 | 404) => rejected,
        Some(401) => ApiError::Upstream("TurnkeyUnauthorized"),
        Some(429) => ApiError::Upstream("TurnkeyRateLimited"),
        Some(_) | None => ApiError::Upstream("TurnkeyUnavailable"),
    }
}

#[inline]
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
impl Turnkey {
    pub(crate) fn for_tests(api_base_url: &str) -> Self {
        let key = || {
            let Ok(key) = TurnkeyP256ApiKey::from_strings("08".repeat(32), None) else {
                panic!("test turnkey key is invalid");
            };
            key
        };
        let build = || {
            let Ok(client) = TurnkeyClient::builder()
                .api_key(key())
                .base_url(api_base_url)
                .build()
            else {
                panic!("test turnkey client did not build");
            };
            client
        };
        Self {
            tvc_organization_id: "69febc39-7ac1-42c1-9786-f20f9cc52c5b".to_owned(),
            boot_proofs: build(),
            waas: build(),
            boot_proof_cache: Mutex::new(HashMap::new()),
            ownership_ttl: Duration::from_secs(600),
            sub_org_projects: Mutex::new(HashMap::new()),
            calls: Semaphore::new(MAX_CONCURRENT_TURNKEY_CALLS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turnkey_statuses_split_between_the_callers_claim_and_upstream() {
        assert_eq!(turnkey_status(Some(403), NOT_OWNED), NOT_OWNED);
        assert_eq!(
            turnkey_status(Some(404), ApiError::NotFound),
            ApiError::NotFound
        );
        assert_eq!(
            turnkey_status(Some(401), NOT_OWNED),
            ApiError::Upstream("TurnkeyUnauthorized")
        );
        assert_eq!(
            turnkey_status(Some(429), NOT_OWNED),
            ApiError::Upstream("TurnkeyRateLimited")
        );
        assert_eq!(
            turnkey_status(Some(503), NOT_OWNED),
            ApiError::Upstream("TurnkeyUnavailable")
        );
        assert_eq!(
            turnkey_status(None, NOT_OWNED),
            ApiError::Upstream("TurnkeyUnavailable")
        );
    }

    #[test]
    fn ephemeral_key_must_be_lower_hex_of_the_exact_length() {
        assert!(is_lower_hex(&"ab".repeat(130), EPHEMERAL_KEY_HEX_LEN));
        assert!(!is_lower_hex(&"AB".repeat(130), EPHEMERAL_KEY_HEX_LEN));
        assert!(!is_lower_hex(&"ab".repeat(129), EPHEMERAL_KEY_HEX_LEN));
    }
}
