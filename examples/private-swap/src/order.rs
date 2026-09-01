use crate::*;

pub(crate) fn decode_order(request: DecodeOrderRequest) -> Result<Value> {
    let marker = MarkerData::try_from_slice(&decode_hex(&request.marker_data)?)
        .context("invalid order marker")?;
    let output_hash: [u8; 32] = decode_array(&request.output_hash)?;
    if marker.order_utxo_hash != output_hash {
        bail!("marker does not name this output");
    }
    let maker = ShieldedAddress::from_str(&request.maker_address)
        .context("invalid maker shielded address")?;
    if maker.solana_address()?.to_bytes() != marker.maker_pubkey {
        bail!("resolved maker address does not match marker owner");
    }
    let taker = ShieldedAddress::from_str(&request.taker_address)
        .context("invalid taker shielded address")?;
    let plaintext = ConfidentialOutputPlaintext::deserialize(&decode_hex(&request.plaintext)?)
        .context("invalid confidential order plaintext")?;
    if plaintext.ring_program_id.is_some() {
        bail!("swap order output is not in the default ring");
    }
    let order_data = PlainTextData::deserialize(
        plaintext
            .data
            .utxo_data()
            .context("order plaintext has no utxo data")?,
    )?;
    if order_data.taker != taker.solana_address()? {
        bail!("order is assigned to a different taker");
    }
    if order_data.take_mode != TAKE_MODE_DERIVED {
        bail!("unsupported order take mode");
    }
    let source_asset = asset_from_id(plaintext.asset_id)?;
    let destination_asset = asset_from_id(order_data.destination_asset_id)?;
    let order = OrderUtxo {
        terms: OrderTerms {
            destination_mint: destination_asset.mint()?,
            destination_amount: order_data.destination_amount,
            destination: maker,
            taker: order_data.taker,
            expiry: order_data.expiry,
            take_mode: order_data.take_mode,
        },
        blinding: plaintext.blinding,
        source_mint: source_asset.mint()?,
        source_amount: plaintext.amount,
        destination_asset_id: order_data.destination_asset_id,
    };
    let reconstructed = order.output_utxo(taker.viewing_pubkey)?.hash()?;
    if reconstructed != output_hash {
        bail!("reconstructed order does not match its on-chain commitment");
    }
    let context = OrderContext {
        tree: request.tree,
        order_commitment: request.output_hash,
        maker_pubkey: Pubkey::new_from_array(marker.maker_pubkey).to_string(),
        maker_address: request.maker_address,
        taker_address: request.taker_address,
        source_asset,
        source_amount: plaintext.amount.to_string(),
        destination_asset,
        destination_amount: order_data.destination_amount.to_string(),
        expiry_unix_ts: order_data.expiry.to_string(),
        take_mode: order_data.take_mode.to_string(),
        order_blinding: encode_hex(&plaintext.blinding),
    };
    Ok(json!({ "order": context }))
}
pub(crate) fn order_from_context(context: &OrderContext) -> Result<OrderUtxo> {
    let maker = ShieldedAddress::from_str(&context.maker_address)?;
    let taker = ShieldedAddress::from_str(&context.taker_address)?;
    let maker_pubkey = Address::from_str(&context.maker_pubkey)?;
    if maker.solana_address()? != maker_pubkey {
        bail!("maker shielded address does not match marker owner");
    }
    let take_mode = parse_u64("take_mode", &context.take_mode)?;
    if take_mode != TAKE_MODE_DERIVED {
        bail!("unsupported order take mode");
    }
    Ok(OrderUtxo {
        terms: OrderTerms {
            destination_mint: context.destination_asset.mint()?,
            destination_amount: parse_u64("destination_amount", &context.destination_amount)?,
            destination: maker,
            taker: taker.solana_address()?,
            expiry: parse_u64("expiry_unix_ts", &context.expiry_unix_ts)?,
            take_mode,
        },
        blinding: decode_array(&context.order_blinding)?,
        source_mint: context.source_asset.mint()?,
        source_amount: parse_u64("source_amount", &context.source_amount)?,
        destination_asset_id: context.destination_asset.asset_id()?,
    })
}
pub(crate) fn check_order_commitment(order: &OrderUtxo, context: &OrderContext) -> Result<()> {
    let taker = ShieldedAddress::from_str(&context.taker_address)?;
    if order.output_utxo(taker.viewing_pubkey)?.hash()? != decode_array(&context.order_commitment)?
    {
        bail!("order context does not match its commitment");
    }
    if order.to_input_utxo()?.hash()? != decode_array(&context.order_commitment)? {
        bail!("order output and program spend commitments differ");
    }
    Ok(())
}
pub(crate) fn asset_from_id(asset_id: u64) -> Result<AssetJson> {
    if asset_id == zolana_transaction::SOL_ASSET_ID {
        Ok(AssetJson::Sol)
    } else {
        bail!("this demo currently discovers SOL swap orders only")
    }
}
pub(crate) fn order_authority() -> Result<Vec<String>> {
    let (_, bump) = Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_program::ID);
    Ok(vec![
        encode_hex(ORDER_AUTHORITY_PDA_SEED),
        encode_hex(&[bump]),
    ])
}
pub(crate) fn program_order_input(
    order: &OrderUtxo,
    context: &OrderContext,
    authority: &[String],
) -> Result<Value> {
    Ok(json!({
        "type": "Program",
        "commitment": context.order_commitment,
        "authority_seeds": authority,
        "asset": context.source_asset,
        "amount": context.source_amount,
        "blinding": context.order_blinding,
        "data_hash": encode_hex(&order.terms.data_hash()?),
        // Swap order convention, the order-authority PDA signer authorizes the
        // spend and the committed owner hash pins Poseidon(0) as the secret.
        "nullifier_secret": encode_hex(&[0u8; BLINDING_LEN]),
    }))
}
