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
}

impl SolanaRpc {
    pub(crate) fn new() -> Result<Self, ClientError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| ClientError::Rpc(format!("build development RPC client: {error}")))?;
        Ok(Self { client })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<T, ClientError> {
        let response = self
            .client
            .post(DEVNET_SOLANA_RPC_URL)
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
                if let Ok(registry) = SplAssetRegistry::from_account_bytes(&account.data) {
                    let expected =
                        pda::spl_asset_registry(&Pubkey::new_from_array(registry.mint.to_bytes()));
                    if address.to_bytes() != expected.to_bytes() {
                        return Err(ClientError::Rpc(
                            "getProgramAccounts returned a non-canonical asset registry".to_owned(),
                        ));
                    }
                }
                Ok((address, account))
            })
            .collect()
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
