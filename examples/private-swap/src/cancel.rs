use crate::*;

pub(crate) fn cancel_plan(request: CancelPlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    parse_u64("expires_at_ms", &request.expires_at_ms)?;
    let order = order_from_context(&request.order)?;
    check_order_commitment(&order, &request.order)?;
    if order.terms.destination.solana_address()? != payer
        || Address::from_str(&request.order.maker_pubkey)? != payer
    {
        bail!("order maker does not match payer");
    }
    let source_output =
        order.source_output(order.terms.destination, zolana_keypair::random_blinding());
    let authority = order_authority()?;
    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.order.tree,
        "shape": { "inputs": CANCEL_INPUTS, "outputs": CANCEL_OUTPUTS },
        "inputs": [program_order_input(&order, &request.order, &authority)?],
        "program_authorities": [{ "seeds": authority }],
        "outputs": [output_json(&source_output, &request.order.source_asset)?],
        "messages": [],
        "expires_at_ms": request.expires_at_ms,
    });
    let context = CancelContext {
        payer: request.payer,
        source_output_blinding: encode_hex(&source_output.blinding),
        order: request.order,
    };
    Ok(json!({ "plan": plan, "context": context }))
}
pub(crate) fn prove_cancel(request: ProveCancelRequest) -> Result<Value> {
    let context = request.context;
    let payer = Pubkey::from_str(&context.payer)?;
    let maker = Pubkey::from_str(&context.order.maker_pubkey)?;
    if payer != maker {
        bail!("order maker does not match payer");
    }
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    if order.terms.destination.solana_address()?.to_bytes() != maker.to_bytes() {
        bail!("maker shielded address does not match payer");
    }
    let taker = ShieldedAddress::from_str(&context.order.taker_address)?;
    let source_output = order.source_output(
        order.terms.destination,
        decode_array(&context.source_output_blinding)?,
    );
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = CancelProofInputParams {
        order_utxo: order.clone(),
        taker_viewing_pubkey: taker.viewing_pubkey,
        source_output,
        external_data_hash: decode_array(&request.external_data_hash)?,
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("cancel context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_cancel(&proof_inputs)?;
    let transact = decode_transact(&request.transact, &expected_private_tx_hash)?;
    let instruction = Cancel {
        maker,
        payer,
        tree: Pubkey::from_str(&context.order.tree)?,
        cancel_proof: proof.into(),
        order_expiry: order.terms.expiry,
        spp_proof: transact,
    }
    .instruction()?;
    check_private_tx_binding(&instruction.data, &expected_private_tx_hash)?;
    Ok(json!({ "instruction": instruction_json(instruction) }))
}
