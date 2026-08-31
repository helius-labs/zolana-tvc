//! Minimal, closed Solana RPC surface for the disposable development spend.

use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use solana_account::Account;
use solana_address::Address;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use zolana_client::{AsyncRpc, ClientError};
use zolana_interface::{pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};

pub(crate) const DEVNET_SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";
const MAX_ASSET_REGISTRY_ACCOUNTS: usize = 4_096;

pub(crate) struct SolanaRpc {
    client: reqwest::Client,
    url: String,
}

impl SolanaRpc {
    pub(crate) fn new(url: &str, allow_insecure_http: bool) -> Result<Self, ClientError> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if !allow_insecure_http {
            builder = builder.https_only(true);
        }
        let client = builder
            .build()
            .map_err(|error| ClientError::Rpc(format!("build development RPC client: {error}")))?;
        Ok(Self {
            client,
            url: url.to_owned(),
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<T, ClientError> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|error| ClientError::Rpc(format!("{method} transport: {error}")))?;
        if !response.status().is_success() {
            return Err(ClientError::Rpc(format!(
                "{method} returned HTTP {}",
                response.status()
            )));
        }
        let response: JsonRpcResponse<T> = response
            .json()
            .await
            .map_err(|error| ClientError::Rpc(format!("{method} response decode: {error}")))?;
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (_, Some(error)) => Err(ClientError::Rpc(format!(
                "{method} failed ({}): {}",
                error.code, error.message
            ))),
            _ => Err(ClientError::Rpc(format!("{method} returned no result"))),
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct ContextValue<T> {
    value: T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UiAccount {
    lamports: u64,
    data: (String, String),
    owner: String,
    executable: bool,
    rent_epoch: u64,
}

impl UiAccount {
    fn into_account(self, method: &'static str) -> Result<Account, ClientError> {
        if self.data.1 != "base64" {
            return Err(ClientError::Rpc(format!(
                "{method} returned a non-base64 account"
            )));
        }
        Ok(Account {
            lamports: self.lamports,
            data: STANDARD
                .decode(self.data.0)
                .map_err(|error| ClientError::Rpc(format!("{method} base64 decode: {error}")))?,
            owner: Pubkey::from_str(&self.owner)
                .map_err(|error| ClientError::Rpc(format!("{method} owner decode: {error}")))?,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        })
    }
}

#[derive(Deserialize)]
struct UiKeyedAccount {
    pubkey: String,
    account: UiAccount,
}

fn decode_program_accounts(
    response: Vec<UiKeyedAccount>,
) -> Result<Vec<(Address, Account)>, ClientError> {
    if response.len() > MAX_ASSET_REGISTRY_ACCOUNTS {
        return Err(ClientError::Rpc(
            "getProgramAccounts asset registry response is too large".to_owned(),
        ));
    }

    response
        .into_iter()
        .map(|entry| {
            let address = Address::from_str(&entry.pubkey).map_err(|error| {
                ClientError::Rpc(format!("getProgramAccounts pubkey decode: {error}"))
            })?;
            let account = entry.account.into_account("getProgramAccounts")?;
            if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
                return Err(ClientError::Rpc(
                    "getProgramAccounts returned an account with the wrong owner".to_owned(),
                ));
            }
            let registry =
                SplAssetRegistry::from_account_bytes(&account.data).map_err(|error| {
                    ClientError::Rpc(format!(
                        "getProgramAccounts returned an invalid asset registry: {error:?}"
                    ))
                })?;
            let expected =
                pda::spl_asset_registry(&Pubkey::new_from_array(registry.mint.to_bytes()));
            if address.to_bytes() != expected.to_bytes() {
                return Err(ClientError::Rpc(
                    "getProgramAccounts returned a non-canonical asset registry".to_owned(),
                ));
            }
            Ok((address, account))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LatestBlockhash {
    blockhash: String,
    last_valid_block_height: u64,
}

#[async_trait]
impl AsyncRpc for SolanaRpc {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        let response: ContextValue<Option<UiAccount>> = self
            .call(
                "getAccountInfo",
                json!([
                    address.to_string(),
                    { "commitment": "confirmed", "encoding": "base64" }
                ]),
            )
            .await?;
        response
            .value
            .map(|account| account.into_account("getAccountInfo"))
            .transpose()
    }

    async fn get_program_accounts(
        &self,
        program_id: Address,
    ) -> Result<Vec<(Address, Account)>, ClientError> {
        // This enclave adapter intentionally exposes only the one bounded
        // program-account scan needed to recover the shielded pool's compact
        // SPL asset-id mapping. It is not a general Solana RPC proxy.
        if program_id.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
            return Err(ClientError::UnsupportedRpcMethod(
                "get_program_accounts for non-shielded-pool program",
            ));
        }
        let response: Vec<UiKeyedAccount> = self
            .call(
                "getProgramAccounts",
                json!([
                    program_id.to_string(),
                    {
                        "commitment": "confirmed",
                        "encoding": "base64",
                        "filters": [{ "dataSize": SplAssetRegistry::SIZE }]
                    }
                ]),
            )
            .await?;
        decode_program_accounts(response)
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        let response: ContextValue<LatestBlockhash> = self
            .call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))
            .await?;
        let blockhash = Hash::from_str(&response.value.blockhash)
            .map_err(|error| ClientError::Rpc(format!("latest blockhash decode: {error}")))?;
        Ok((blockhash, response.value.last_valid_block_height))
    }

    async fn get_balance(&self, address: Address) -> Result<u64, ClientError> {
        let response: ContextValue<u64> = self
            .call(
                "getBalance",
                json!([address.to_string(), { "commitment": "confirmed" }]),
            )
            .await?;
        Ok(response.value)
    }

    async fn get_slot(&self) -> Result<u64, ClientError> {
        self.call("getSlot", json!([{ "commitment": "confirmed" }]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_entry(mint: Address, asset_id: u64) -> UiKeyedAccount {
        let address = pda::spl_asset_registry(&Pubkey::new_from_array(mint.to_bytes()));
        UiKeyedAccount {
            pubkey: address.to_string(),
            account: UiAccount {
                lamports: 1,
                data: (
                    STANDARD.encode(SplAssetRegistry::account_bytes(mint, asset_id)),
                    "base64".to_owned(),
                ),
                owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string(),
                executable: false,
                rent_epoch: 0,
            },
        }
    }

    fn error_text<T>(result: Result<T, ClientError>) -> String {
        match result {
            Ok(_) => panic!("expected RPC validation error"),
            Err(error) => format!("{error:?}"),
        }
    }

    #[test]
    fn ui_account_requires_base64_and_valid_owner() {
        let mut entry = registry_entry(Address::new_from_array([3; 32]), 2);
        entry.account.data.1 = "base58".to_owned();
        assert!(error_text(entry.account.into_account("test")).contains("non-base64"));

        let mut entry = registry_entry(Address::new_from_array([3; 32]), 2);
        entry.account.data.0 = "not base64".to_owned();
        assert!(error_text(entry.account.into_account("test")).contains("base64 decode"));

        let mut entry = registry_entry(Address::new_from_array([3; 32]), 2);
        entry.account.owner = "not-a-pubkey".to_owned();
        assert!(error_text(entry.account.into_account("test")).contains("owner decode"));
    }

    #[test]
    fn program_accounts_require_pool_ownership_and_canonical_registry_pdas() {
        let mint = Address::new_from_array([4; 32]);
        let decoded = decode_program_accounts(vec![registry_entry(mint, 2)]).expect("registry");
        assert_eq!(decoded.len(), 1);

        let mut wrong_owner = registry_entry(mint, 2);
        wrong_owner.account.owner = Pubkey::new_from_array([5; 32]).to_string();
        assert!(error_text(decode_program_accounts(vec![wrong_owner])).contains("wrong owner"));

        let mut wrong_pda = registry_entry(mint, 2);
        wrong_pda.pubkey = Pubkey::new_from_array([6; 32]).to_string();
        assert!(error_text(decode_program_accounts(vec![wrong_pda])).contains("non-canonical"));

        let mut invalid_registry = registry_entry(mint, 2);
        invalid_registry.account.data.0 = STANDARD.encode([0u8; SplAssetRegistry::SIZE]);
        assert!(error_text(decode_program_accounts(vec![invalid_registry]))
            .contains("invalid asset registry"));
    }

    #[test]
    fn program_account_scan_is_bounded_before_decode() {
        let oversized = (0..=MAX_ASSET_REGISTRY_ACCOUNTS)
            .map(|_| registry_entry(Address::new_from_array([7; 32]), 2))
            .collect();
        assert!(error_text(decode_program_accounts(oversized)).contains("too large"));
    }
}
