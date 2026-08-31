use crate::*;

pub(crate) const MAKE_INPUTS: u8 = 2;
pub(crate) const MAKE_OUTPUTS: u8 = 2;
pub(crate) const TAKE_INPUTS: u8 = 2;
pub(crate) const TAKE_OUTPUTS: u8 = 2;
pub(crate) const CANCEL_INPUTS: u8 = 1;
pub(crate) const CANCEL_OUTPUTS: u8 = 1;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(crate) enum AssetJson {
    Sol,
    Spl { mint: String, asset_id: String },
}
impl AssetJson {
    pub(crate) fn mint(&self) -> Result<Address> {
        match self {
            Self::Sol => Ok(zolana_transaction::SOL_MINT),
            Self::Spl { mint, .. } => Address::from_str(mint).context("invalid SPL mint"),
        }
    }

    pub(crate) fn asset_id(&self) -> Result<u64> {
        match self {
            Self::Sol => Ok(zolana_transaction::SOL_ASSET_ID),
            Self::Spl { asset_id, .. } => asset_id.parse().context("invalid SPL asset id"),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MakePlanRequest {
    pub(crate) payer: String,
    pub(crate) maker_address: String,
    pub(crate) taker_address: String,
    pub(crate) input_tree: String,
    pub(crate) input_commitment: String,
    pub(crate) input_amount: String,
    pub(crate) source_asset: AssetJson,
    pub(crate) source_amount: String,
    pub(crate) destination_asset: AssetJson,
    pub(crate) destination_amount: String,
    pub(crate) expires_at_ms: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MakeContext {
    pub(crate) payer: String,
    pub(crate) input_commitment: String,
    pub(crate) change_blinding: String,
    pub(crate) change_amount: String,
    pub(crate) order: OrderContext,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProveMakeRequest {
    pub(crate) transact: String,
    pub(crate) private_tx_hash: String,
    pub(crate) external_data_hash: String,
    pub(crate) context: MakeContext,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OrderContext {
    pub(crate) tree: String,
    pub(crate) order_commitment: String,
    pub(crate) maker_pubkey: String,
    pub(crate) maker_address: String,
    pub(crate) taker_address: String,
    pub(crate) source_asset: AssetJson,
    pub(crate) source_amount: String,
    pub(crate) destination_asset: AssetJson,
    pub(crate) destination_amount: String,
    pub(crate) expiry_unix_ts: String,
    pub(crate) take_mode: String,
    pub(crate) order_blinding: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecodeOrderRequest {
    pub(crate) tree: String,
    pub(crate) output_hash: String,
    pub(crate) plaintext: String,
    pub(crate) marker_data: String,
    pub(crate) maker_address: String,
    pub(crate) taker_address: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TakePlanRequest {
    pub(crate) payer: String,
    pub(crate) wallet_input_commitment: String,
    pub(crate) wallet_input_blinding: String,
    pub(crate) expires_at_ms: String,
    pub(crate) order: OrderContext,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TakeContext {
    pub(crate) payer: String,
    pub(crate) wallet_input_commitment: String,
    pub(crate) wallet_input_blinding: String,
    pub(crate) source_output_blinding: String,
    pub(crate) order: OrderContext,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProveTakeRequest {
    pub(crate) transact: String,
    pub(crate) private_tx_hash: String,
    pub(crate) external_data_hash: String,
    pub(crate) context: TakeContext,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancelPlanRequest {
    pub(crate) payer: String,
    pub(crate) expires_at_ms: String,
    pub(crate) order: OrderContext,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancelContext {
    pub(crate) payer: String,
    pub(crate) source_output_blinding: String,
    pub(crate) order: OrderContext,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProveCancelRequest {
    pub(crate) transact: String,
    pub(crate) private_tx_hash: String,
    pub(crate) external_data_hash: String,
    pub(crate) context: CancelContext,
}
#[derive(Debug, Serialize)]
pub(crate) struct InstructionAccountJson {
    pub(crate) address: String,
    pub(crate) is_signer: bool,
    pub(crate) is_writable: bool,
}
#[derive(Debug, Serialize)]
pub(crate) struct InstructionJson {
    pub(crate) program_id: String,
    pub(crate) accounts: Vec<InstructionAccountJson>,
    pub(crate) data: String,
}
