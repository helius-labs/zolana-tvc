//! Minimal, closed Solana RPC surface for the disposable development spend.

use std::str::FromStr;

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

pub(crate) const DEVNET_SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

pub(crate) struct SolanaRpc {
    client: reqwest::Client,
}

impl SolanaRpc {
    pub(crate) fn new() -> Result<Self, ClientError> {
        let client = reqwest::Client::builder()
            .https_only(true)
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
            .map(|account| {
                if account.data.1 != "base64" {
                    return Err(ClientError::Rpc(
                        "getAccountInfo returned a non-base64 account".to_owned(),
                    ));
                }
                Ok(Account {
                    lamports: account.lamports,
                    data: STANDARD.decode(account.data.0).map_err(|error| {
                        ClientError::Rpc(format!("getAccountInfo base64 decode: {error}"))
                    })?,
                    owner: Pubkey::from_str(&account.owner).map_err(|error| {
                        ClientError::Rpc(format!("getAccountInfo owner decode: {error}"))
                    })?,
                    executable: account.executable,
                    rent_epoch: account.rent_epoch,
                })
            })
            .transpose()
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
}
