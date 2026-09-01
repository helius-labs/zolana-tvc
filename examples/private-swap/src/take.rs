use crate::*;

pub(crate) fn take_plan(request: TakePlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    parse_u64("expires_at_ms", &request.expires_at_ms)?;
    let order = order_from_context(&request.order)?;
    check_order_commitment(&order, &request.order)?;
    let taker = ShieldedAddress::from_str(&request.order.taker_address)?;
    if taker.solana_address()? != payer || order.terms.taker != payer {
        bail!("order is assigned to a different taker");
    }
    let taker_in = SppProofOutputUtxo {
        asset: order.terms.destination_mint,
        amount: order.terms.destination_amount,
        blinding: decode_array(&request.wallet_input_blinding)?,
        owner_address: Some(taker),
        owner_tag: Some(taker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    if taker_in.hash()? != decode_array(&request.wallet_input_commitment)? {
        bail!("wallet input opening does not match its commitment");
    }
    let source_output = order.source_output(taker, zolana_keypair::random_blinding());
    let destination_output = order.derived_destination_output(order.terms.destination)?;
    let authority = order_authority()?;
    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.order.tree,
        "shape": { "inputs": TAKE_INPUTS, "outputs": TAKE_OUTPUTS },
        "inputs": [
            program_order_input(&order, &request.order, &authority)?,
            { "type": "Wallet", "commitment": request.wallet_input_commitment },
        ],
        "program_authorities": [{ "seeds": authority }],
        "outputs": [
            output_json(&source_output, &request.order.source_asset)?,
            output_json(&destination_output, &request.order.destination_asset)?,
        ],
        "messages": [],
        "expires_at_ms": request.expires_at_ms,
    });
    let context = TakeContext {
        payer: request.payer,
        wallet_input_commitment: request.wallet_input_commitment,
        wallet_input_blinding: request.wallet_input_blinding,
        source_output_blinding: encode_hex(&source_output.blinding),
        order: request.order,
    };
    Ok(json!({ "plan": plan, "context": context }))
}
pub(crate) fn prove_take(request: ProveTakeRequest) -> Result<Value> {
    let context = request.context;
    let payer = Pubkey::from_str(&context.payer)?;
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    let taker = ShieldedAddress::from_str(&context.order.taker_address)?;
    if taker.solana_address()?.to_bytes() != payer.to_bytes()
        || order.terms.taker.to_bytes() != payer.to_bytes()
    {
        bail!("order is assigned to a different taker");
    }
    let taker_in = SppProofOutputUtxo {
        asset: order.terms.destination_mint,
        amount: order.terms.destination_amount,
        blinding: decode_array(&context.wallet_input_blinding)?,
        owner_address: Some(taker),
        owner_tag: Some(taker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    if taker_in.hash()? != decode_array(&context.wallet_input_commitment)? {
        bail!("wallet input opening does not match its commitment");
    }
    let source_output = order.source_output(taker, decode_array(&context.source_output_blinding)?);
    let destination_output = order.derived_destination_output(order.terms.destination)?;
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = TakeProofInputParams {
        order_utxo: order,
        taker_in,
        source_output,
        destination_output,
        external_data_hash: decode_array(&request.external_data_hash)?,
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("take context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_take(&proof_inputs)?;
    let transact = decode_transact(&request.transact, &expected_private_tx_hash)?;
    let instruction = Take {
        payer,
        tree: Pubkey::from_str(&context.order.tree)?,
        take_proof: proof.into(),
        spp_proof: transact,
    }
    .instruction()?;
    check_private_tx_binding(&instruction.data, &expected_private_tx_hash)?;
    Ok(json!({ "instruction": instruction_json(instruction) }))
}
