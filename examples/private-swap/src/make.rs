use crate::*;

pub(crate) fn make_plan(request: MakePlanRequest) -> Result<Value> {
    let payer = Address::from_str(&request.payer).context("invalid payer")?;
    let maker = ShieldedAddress::from_str(&request.maker_address)
        .context("invalid maker shielded address")?;
    let taker = ShieldedAddress::from_str(&request.taker_address)
        .context("invalid taker shielded address")?;
    if maker.solana_address()? != payer {
        bail!("maker address is not owned by payer");
    }
    let input_amount = parse_u64("input_amount", &request.input_amount)?;
    let source_amount = parse_u64("source_amount", &request.source_amount)?;
    let destination_amount = parse_u64("destination_amount", &request.destination_amount)?;
    let expires_at_ms = parse_u64("expires_at_ms", &request.expires_at_ms)?;
    if source_amount == 0 || destination_amount == 0 || source_amount > input_amount {
        bail!("invalid swap amounts");
    }
    let source_mint = request.source_asset.mint()?;
    let destination_mint = request.destination_asset.mint()?;
    let expiry_unix_ts = expires_at_ms.div_ceil(1_000);
    let terms = OrderTerms {
        destination_mint,
        destination_amount,
        destination: maker,
        taker: taker.solana_address()?,
        expiry: expiry_unix_ts,
        take_mode: TAKE_MODE_DERIVED,
    };
    let order = OrderUtxo {
        terms,
        blinding: zolana_keypair::random_blinding(),
        source_mint,
        source_amount,
        destination_asset_id: request.destination_asset.asset_id()?,
    };
    let order_output = order.output_utxo(taker.viewing_pubkey)?;
    let change = SppProofOutputUtxo::new(source_mint, input_amount - source_amount, maker)?;
    let order_hash = order_output.hash()?;
    let marker = OrderMarker {
        order_utxo_hash: order_hash,
        maker_pubkey: Pubkey::new_from_array(payer.to_bytes()),
        taker_address: taker,
    }
    .message()?;
    let (_, order_authority_bump) =
        Pubkey::find_program_address(&[ORDER_AUTHORITY_PDA_SEED], &swap_program::ID);

    let plan = json!({
        "program_id": swap_program::ID.to_string(),
        "input_tree": request.input_tree,
        "shape": { "inputs": MAKE_INPUTS, "outputs": MAKE_OUTPUTS },
        "inputs": [{ "type": "Wallet", "commitment": request.input_commitment }],
        "program_authorities": [{
            "seeds": [
                encode_hex(ORDER_AUTHORITY_PDA_SEED),
                encode_hex(&[order_authority_bump]),
            ],
        }],
        "outputs": [
            output_json(&change, &request.source_asset)?,
            output_json(&order_output, &request.source_asset)?,
        ],
        "messages": [{
            "view_tag": encode_hex(&marker.view_tag),
            "data": encode_hex(&marker.data),
        }],
        "expires_at_ms": request.expires_at_ms,
    });
    let context = MakeContext {
        payer: request.payer,
        input_commitment: plan["inputs"][0]["commitment"]
            .as_str()
            .context("commitment")?
            .to_owned(),
        change_blinding: encode_hex(&change.blinding),
        change_amount: change.amount.to_string(),
        order: OrderContext {
            tree: plan["input_tree"].as_str().context("tree")?.to_owned(),
            order_commitment: encode_hex(&order_hash),
            maker_pubkey: payer.to_string(),
            maker_address: request.maker_address,
            taker_address: request.taker_address,
            source_asset: request.source_asset,
            source_amount: source_amount.to_string(),
            destination_asset: request.destination_asset,
            destination_amount: destination_amount.to_string(),
            expiry_unix_ts: expiry_unix_ts.to_string(),
            take_mode: TAKE_MODE_DERIVED.to_string(),
            order_blinding: encode_hex(&order.blinding),
        },
    };
    Ok(json!({ "plan": plan, "context": context }))
}
pub(crate) fn prove_make(request: ProveMakeRequest) -> Result<Value> {
    let context = request.context;
    let maker = ShieldedAddress::from_str(&context.order.maker_address)?;
    let payer = Pubkey::from_str(&context.payer)?;
    if maker.solana_address()?.to_bytes() != payer.to_bytes() {
        bail!("maker address is not owned by payer");
    }
    let order = order_from_context(&context.order)?;
    check_order_commitment(&order, &context.order)?;
    let change = SppProofOutputUtxo {
        asset: context.order.source_asset.mint()?,
        amount: parse_u64("change_amount", &context.change_amount)?,
        blinding: decode_array(&context.change_blinding)?,
        owner_address: Some(maker),
        owner_tag: Some(maker.signing_pubkey.confidential_view_tag()?),
        ..Default::default()
    };
    let expected_private_tx_hash: [u8; 32] = decode_array(&request.private_tx_hash)?;
    let proof_inputs = MakeProofInputParams {
        order_utxo: order,
        change,
        spp_tx_hashes: SppTxHashes {
            source_input_hash: decode_array(&context.input_commitment)?,
            external_data_hash: decode_array(&request.external_data_hash)?,
        },
    }
    .to_proof_inputs()?;
    if proof_inputs.private_tx_hash != expected_private_tx_hash {
        bail!("make context does not match prepared private_tx_hash");
    }
    let proof = SwapProverClient::new().prove_make(&proof_inputs)?;
    let transact = decode_transact(&request.transact, &expected_private_tx_hash)?;
    let instruction = Make {
        payer,
        tree: Pubkey::from_str(&context.order.tree)?,
        make_proof: proof.into(),
        spp_proof: transact,
    }
    .instruction()?;
    check_private_tx_binding(&instruction.data, &expected_private_tx_hash)?;
    Ok(json!({
        "instruction": instruction_json(instruction)
    }))
}
