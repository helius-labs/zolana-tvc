//! TVC integration for the canonical Zolana confidential swap.
//!
//! Swap program semantics and proving remain owned by the sibling Zolana
//! checkout. This adapter translates wallet requests into program-neutral TVC
//! plans and binds the resulting swap instructions to `private_tx_hash`.

use std::{io::Read, str::FromStr};

use anyhow::{bail, Context, Result};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_address::Address;
use solana_pubkey::Pubkey;
use swap_prover::TAKE_MODE_DERIVED;
use swap_sdk::{
    instructions::{
        cancel::{Cancel, CancelProofInputParams},
        make::{Make, MakeProofInputParams, OrderMarker, SppTxHashes},
        take::{Take, TakeProofInputParams},
    },
    prover::SwapProverClient,
    state::{OrderTerms, OrderUtxo, PlainTextData},
    MarkerData, ORDER_AUTHORITY_PDA_SEED,
};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
use zolana_keypair::{constants::BLINDING_LEN, ShieldedAddress};
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo,
    serialization::confidential::ConfidentialOutputPlaintext,
};

mod cancel;
mod codec;
mod make;
mod order;
mod take;
mod wire;

use cancel::*;
use codec::*;
use make::*;
use order::*;
use take::*;
use wire::*;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let output = match command.as_str() {
        "make-plan" => make_plan(serde_json::from_str(&input)?)?,
        "prove-make" => prove_make(serde_json::from_str(&input)?)?,
        "decode-order" => decode_order(serde_json::from_str(&input)?)?,
        "take-plan" => take_plan(serde_json::from_str(&input)?)?,
        "prove-take" => prove_take(serde_json::from_str(&input)?)?,
        "cancel-plan" => cancel_plan(serde_json::from_str(&input)?)?,
        "prove-cancel" => prove_cancel(serde_json::from_str(&input)?)?,
        _ => bail!("unknown command {command:?}"),
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAKER: &str = "nXCAmMVUZp1ZmFhfCNEzqubevSpVL99efGHhs67HUAoZz9N586mg7z3dJC8yA5GrQWaryp1aLvUb1QCfD7an7BgndNmGsxELB3ekLcUND29g1bsvqJdBLpvoGJ8nN3oY3UWRVd";
    const TAKER: &str = "voLjBXYEkm7ANBA2Rfz7vdBfMhYbu3Desx2KNHPYLqTtvhaBYgzsZjCwKM1TRNPL1jX53bGwRoauu9U1xFqb9QhvDwi13fnTzPSeXkSM1HEPxjPXexe9irZA7r7DVocXkXJ3TK";
    const PAYER: &str = "AFRUJXNTGMZQo59gGetRNBSZwK9vBUCZMdJXgSac9kKd";

    fn request() -> MakePlanRequest {
        MakePlanRequest {
            payer: PAYER.to_owned(),
            maker_address: MAKER.to_owned(),
            taker_address: TAKER.to_owned(),
            input_tree: "11111111111111111111111111111111".to_owned(),
            input_commitment: "11".repeat(32),
            input_amount: "3000000".to_owned(),
            source_asset: AssetJson::Sol,
            source_amount: "2000000".to_owned(),
            destination_asset: AssetJson::Sol,
            destination_amount: "1000000".to_owned(),
            expires_at_ms: "2000000000000".to_owned(),
        }
    }

    #[test]
    fn make_plan_is_tvc_spp_shape_and_program_bound() {
        let output = make_plan(request()).expect("make plan");
        let plan = &output["plan"];
        assert_eq!(plan["program_id"], swap_program::ID.to_string());
        assert_eq!(plan["shape"], json!({ "inputs": 2, "outputs": 2 }));
        assert_eq!(plan["inputs"][0]["commitment"], "11".repeat(32));
        assert_eq!(
            plan["program_authorities"][0]["seeds"][0],
            "6f726465725f617574686f72697479"
        );
        assert_eq!(plan["outputs"][0]["amount"], "1000000");
        assert_eq!(plan["outputs"][1]["amount"], "2000000");
        assert_eq!(plan["messages"][0]["data"].as_str().unwrap().len(), 128);
        assert_eq!(output["context"]["payer"], PAYER);
    }

    #[test]
    fn make_plan_rejects_a_maker_not_owned_by_the_payer() {
        let mut request = request();
        request.payer = "11111111111111111111111111111111".to_owned();
        assert!(make_plan(request).is_err());
    }

    #[test]
    fn decode_order_reconstructs_the_make_commitment() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let order = order_from_context(&context.order).expect("order");
        let taker = ShieldedAddress::from_str(TAKER).expect("taker");
        let output = order.output_utxo(taker.viewing_pubkey).expect("output");
        let plaintext = ConfidentialOutputPlaintext {
            asset_id: context.order.source_asset.asset_id().expect("asset"),
            amount: output.amount,
            blinding: output.blinding,
            ring_program_id: None,
            data: output.data,
        }
        .serialize()
        .expect("plaintext");
        let marker = borsh::to_vec(&MarkerData {
            order_utxo_hash: decode_array(&context.order.order_commitment).expect("hash"),
            maker_pubkey: Pubkey::from_str(PAYER).expect("payer").to_bytes(),
        })
        .expect("marker");
        let decoded = decode_order(DecodeOrderRequest {
            tree: context.order.tree.clone(),
            output_hash: context.order.order_commitment.clone(),
            plaintext: encode_hex(&plaintext),
            marker_data: encode_hex(&marker),
            maker_address: MAKER.to_owned(),
            taker_address: TAKER.to_owned(),
        })
        .expect("decode order");
        assert_eq!(
            decoded["order"]["order_commitment"],
            context.order.order_commitment
        );
        assert_eq!(decoded["order"]["maker_pubkey"], PAYER);
    }

    #[test]
    fn take_plan_spends_program_order_before_exact_wallet_utxo() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let taker = ShieldedAddress::from_str(TAKER).expect("taker");
        let wallet_input = SppProofOutputUtxo {
            asset: zolana_transaction::SOL_MINT,
            amount: 1_000_000,
            blinding: [7u8; 32],
            owner_address: Some(taker),
            owner_tag: Some(taker.signing_pubkey.confidential_view_tag().expect("tag")),
            ..Default::default()
        };
        let plan = take_plan(TakePlanRequest {
            payer: taker.solana_address().expect("payer").to_string(),
            wallet_input_commitment: encode_hex(&wallet_input.hash().expect("hash")),
            wallet_input_blinding: encode_hex(&wallet_input.blinding),
            expires_at_ms: "2000000000000".to_owned(),
            order: context.order,
        })
        .expect("take plan");
        assert_eq!(plan["plan"]["shape"], json!({ "inputs": 2, "outputs": 2 }));
        assert_eq!(plan["plan"]["inputs"][0]["type"], "Program");
        assert_eq!(plan["plan"]["inputs"][1]["type"], "Wallet");
    }

    #[test]
    fn cancel_plan_is_a_program_only_refund() {
        let made = make_plan(request()).expect("make plan");
        let context: MakeContext =
            serde_json::from_value(made["context"].clone()).expect("make context");
        let plan = cancel_plan(CancelPlanRequest {
            payer: PAYER.to_owned(),
            expires_at_ms: "2000000000000".to_owned(),
            order: context.order,
        })
        .expect("cancel plan");
        assert_eq!(plan["plan"]["shape"], json!({ "inputs": 1, "outputs": 1 }));
        assert_eq!(plan["plan"]["inputs"][0]["type"], "Program");
        assert_eq!(plan["plan"]["outputs"][0]["amount"], "2000000");
    }
}
