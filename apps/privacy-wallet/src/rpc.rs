//! The two Solana RPC reads a spend needs: an account and a recent blockhash.

use std::str::FromStr;
use std::time::Duration;

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
            .map_err(|error| ClientError::Rpc(format!("build RPC client: {error}")))?;
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
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
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
    fn into_account(self) -> Result<Account, ClientError> {
        if self.data.1 != "base64" {
            return Err(ClientError::Rpc("non-base64 account data".to_owned()));
        }
        Ok(Account {
            lamports: self.lamports,
            data: STANDARD
                .decode(self.data.0)
                .map_err(|error| ClientError::Rpc(format!("account base64: {error}")))?,
            owner: Pubkey::from_str(&self.owner)
                .map_err(|error| ClientError::Rpc(format!("account owner: {error}")))?,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        })
    }
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
                json!([address.to_string(), { "commitment": "confirmed", "encoding": "base64" }]),
            )
            .await?;
        response.value.map(UiAccount::into_account).transpose()
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        let response: ContextValue<LatestBlockhash> = self
            .call("getLatestBlockhash", json!([{ "commitment": "confirmed" }]))
            .await?;
        let blockhash = Hash::from_str(&response.value.blockhash)
            .map_err(|error| ClientError::Rpc(format!("blockhash decode: {error}")))?;
        Ok((blockhash, response.value.last_valid_block_height))
    }
}
