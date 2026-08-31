use super::*;

/// Builds the common SPP transition for an arbitrary private program without
/// interpreting that program's data. Wallet inputs are independently
/// rediscovered; program inputs must be owned by a PDA derived under the target
/// program and provide a commitment opening. No public interface transfer is
/// admitted on this path.
pub(in crate::operations) async fn prepare_generic_spp(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    plan: &SppPlanV1,
    state: &AppState,
    keys: &RuntimeKeys,
) -> Result<PreparedGenericSpend, OperationFailure> {
    if plan.inputs.is_empty()
        || plan.outputs.is_empty()
        || plan.outputs.len() != usize::from(plan.shape.outputs)
        || plan.inputs.len() > usize::from(plan.shape.inputs)
        || plan.messages.len() > MAX_GENERIC_MESSAGES
        || plan.program_authorities.len() > MAX_GENERIC_PROGRAM_AUTHORITIES
    {
        return Err(OperationFailure::Invalid);
    }
    let now_ms = current_time_ms()?;
    let latest_expiry = now_ms
        .checked_add(MAX_REQUEST_AGE_MS)
        .ok_or(OperationFailure::Unavailable)?;
    if plan.expires_at_ms < now_ms || plan.expires_at_ms > latest_expiry {
        return Err(OperationFailure::Invalid);
    }

    let program_id = Address::from_str(&plan.program_id).map_err(|_| OperationFailure::Invalid)?;
    if program_id.to_bytes() == SHIELDED_POOL_PROGRAM_ID || reserved_signer_program(program_id) {
        return Err(OperationFailure::Invalid);
    }
    let input_tree = Address::from_str(&plan.input_tree).map_err(|_| OperationFailure::Invalid)?;
    let shape = Shape::new(
        usize::from(plan.shape.inputs),
        usize::from(plan.shape.outputs),
    );
    if !SPP_SUPPORTED_SHAPES.contains(&shape) {
        return Err(OperationFailure::Invalid);
    }
    if plan
        .messages
        .iter()
        .any(|message| message.data.len() > MAX_GENERIC_DATA_BYTES)
        || plan.outputs.iter().any(|output| {
            output.data.len() > MAX_GENERIC_DATA_BYTES
                || output.memo.len() > MAX_GENERIC_DATA_BYTES
                || (!output.data.is_empty() && output.data_hash.is_none())
        })
    {
        return Err(OperationFailure::Invalid);
    }

    let sealed_bytes = request
        .sealed_wallet_state
        .as_deref()
        .ok_or(OperationFailure::Invalid)?;
    let (inner, state_digest_bytes) = unseal_state(request, keys, sealed_bytes)?;
    let keypair = default_keypair(state, keys, target, &inner)?;
    let rpc = SolanaRpc::new(
        &state.services.solana_rpc_url,
        state.services.allow_insecure_http,
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let registry = generic_asset_registry(&rpc, plan).await?;
    let zolana = pinned_zolana_client(state, rpc, input_tree);
    let payer = Address::new_from_array(target.address.to_bytes());
    let authority = KeypairWalletAuthority::with_viewing_keys(
        payer,
        &keypair,
        vec![keypair.viewing_key().clone()],
    )
    .map_err(|_| OperationFailure::Unavailable)?;
    let wallet = synced_wallet(
        keypair
            .shielded_address()
            .map_err(|_| OperationFailure::Unavailable)?,
        &authority,
        registry.clone(),
        &zolana,
    )
    .await?;

    let mut input_utxos = Vec::with_capacity(usize::from(plan.shape.inputs));
    let mut seen_commitments = Vec::with_capacity(plan.inputs.len());
    let mut input_totals: Vec<(Address, u128)> = Vec::new();
    let program = Pubkey::new_from_array(program_id.to_bytes());
    let mut program_authorities = Vec::with_capacity(plan.program_authorities.len());
    for authority in &plan.program_authorities {
        let pda = derive_program_authority(&program, &authority.seeds)?;
        if program_authorities.contains(&pda) {
            return Err(OperationFailure::Invalid);
        }
        program_authorities.push(pda);
    }
    let mut shielded_balance_before = 0u64;
    for input in &plan.inputs {
        let (commitment, spend) = match input {
            SppPlanInputV1::Wallet { commitment } => {
                let entry = wallet
                    .utxos
                    .iter()
                    .find(|entry| {
                        !entry.spent
                            && entry.output_context.tree == input_tree
                            && entry.output_context.hash == *commitment
                    })
                    .ok_or(OperationFailure::Invalid)?;
                if entry.utxo.owner != keypair.signing_pubkey()
                    || entry.utxo.ring_program_id.is_some()
                {
                    return Err(OperationFailure::Invalid);
                }
                shielded_balance_before = shielded_balance_before
                    .checked_add(entry.utxo.amount)
                    .ok_or(OperationFailure::Unavailable)?;
                add_asset_amount(&mut input_totals, entry.utxo.asset, entry.utxo.amount)?;
                let mut spend = SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key());
                if let Some(data_hash) = entry.data_hash {
                    spend = spend.with_data_hash(data_hash);
                }
                if let Some(ring_data_hash) = entry.ring_data_hash {
                    spend = spend.with_ring_data_hash(ring_data_hash);
                }
                (*commitment, spend)
            }
            SppPlanInputV1::Program {
                commitment,
                authority_seeds,
                asset,
                amount,
                blinding,
                data_hash,
                nullifier_secret,
            } => {
                let pda_address = derive_program_authority(&program, authority_seeds)?;
                if !program_authorities.contains(&pda_address) {
                    if program_authorities.len() == MAX_GENERIC_PROGRAM_AUTHORITIES {
                        return Err(OperationFailure::Invalid);
                    }
                    program_authorities.push(pda_address);
                }
                let asset = generic_asset_address(asset)?;
                add_asset_amount(&mut input_totals, asset, *amount)?;
                let secret: [u8; BLINDING_LEN] = nullifier_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| OperationFailure::Invalid)?;
                let utxo = Utxo {
                    owner: PublicKey::from_pda(&pda_address),
                    asset,
                    amount: *amount,
                    blinding: *blinding,
                    ring_program_id: None,
                    data: Default::default(),
                };
                let mut spend = SppProofInputUtxo::new(utxo, NullifierKey::from_secret(secret));
                if let Some(data_hash) = data_hash {
                    spend = spend.with_data_hash(*data_hash);
                }
                if spend.hash().map_err(|_| OperationFailure::Invalid)? != *commitment {
                    return Err(OperationFailure::Invalid);
                }
                (*commitment, spend)
            }
        };
        if seen_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        seen_commitments.push(commitment);
        input_utxos.push(spend);
    }
    while input_utxos.len() < usize::from(plan.shape.inputs) {
        input_utxos.push(SppProofInputUtxo::new_dummy());
    }

    let mut outputs = Vec::with_capacity(plan.outputs.len());
    let mut output_totals: Vec<(Address, u128)> = Vec::new();
    let mut output_commitments = Vec::with_capacity(plan.outputs.len());
    for output in &plan.outputs {
        let recipient =
            ShieldedAddress::from_str(&output.recipient).map_err(|_| OperationFailure::Invalid)?;
        let asset = generic_asset_address(&output.asset)?;
        add_asset_amount(&mut output_totals, asset, output.amount)?;
        let mut prepared = SppProofOutputUtxo {
            asset,
            amount: output.amount,
            blinding: output.blinding,
            owner_address: Some(recipient),
            owner_tag: Some(
                recipient
                    .signing_pubkey
                    .confidential_view_tag()
                    .map_err(|_| OperationFailure::Invalid)?,
            ),
            ..Default::default()
        };
        if let Some(data_hash) = output.data_hash {
            prepared = prepared.with_utxo_data(output.data.clone(), data_hash);
        }
        if !output.memo.is_empty() {
            prepared = prepared.with_memo(output.memo.clone());
        }
        let commitment = prepared.hash().map_err(|_| OperationFailure::Invalid)?;
        if output_commitments.contains(&commitment) {
            return Err(OperationFailure::Invalid);
        }
        output_commitments.push(commitment);
        outputs.push(prepared);
    }
    if input_totals != output_totals {
        sort_asset_totals(&mut input_totals);
        sort_asset_totals(&mut output_totals);
        if input_totals != output_totals {
            return Err(OperationFailure::Invalid);
        }
    }

    let transaction_viewing_key = get_transaction_viewing_key(&keypair, &input_utxos)
        .map_err(|_| OperationFailure::Invalid)?;
    let encoded = encrypt_transaction_data(&outputs, &registry, &transaction_viewing_key)
        .map_err(|_| OperationFailure::Invalid)?;
    let messages = plan
        .messages
        .iter()
        .map(|message| MessageData {
            view_tag: message.view_tag,
            data: message.data.clone(),
        })
        .collect();
    let mut external_data = ExternalData::new(
        *transaction_viewing_key.pubkey().as_bytes(),
        encoded.salt,
        encoded.outputs,
        encoded.resolved_owner_tags,
        messages,
    );
    external_data.expiry_unix_ts = plan.expires_at_ms.div_ceil(1_000);
    let proof_inputs = SppProofInputs::new(input_utxos, encoded.output_utxos, external_data, payer);
    proof_inputs
        .check_shape()
        .map_err(|_| OperationFailure::Invalid)?;
    let external_data_hash = proof_inputs
        .external_data
        .hash()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_contexts = proof_inputs
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Invalid)?;
    let input_proofs = zolana
        .get_input_merkle_proofs_for_tree(input_tree, &input_contexts, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let dummy_nullifiers = proof_inputs
        .dummy_nullifiers()
        .map_err(|_| OperationFailure::Invalid)?;
    let dummy_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(input_tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    let assembled = assemble(proof_inputs, &input_proofs, &dummy_proofs)
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(state.services.prover_url.clone());
    let proof = match &assembled.prover_inputs {
        ProverInputs::Eddsa(inputs) => {
            let proof = prover
                .prove_transfer(inputs)
                .await
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            verify_confidential_transfer_inputs(inputs, assembled.public_input_hash, &proof)
                .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
            proof
        }
    };
    let transact = assembled.with_proof(
        ProofCompressed::try_from(proof)
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .to_transact_proof(),
    );
    let private_tx_hash = transact.private_tx_hash;
    let transact = wincode::serialize(&transact).map_err(|_| OperationFailure::Unavailable)?;
    let plan_json = jcs_serialize(plan).map_err(|_| OperationFailure::Invalid)?;
    Ok(PreparedGenericSpend {
        program_id,
        input_tree,
        program_authorities,
        plan_digest: artifact_digest(plan_json.as_bytes()),
        transact,
        private_tx_hash,
        external_data_hash,
        state_digest: state_digest_bytes,
        shielded_balance_before,
        expires_at_ms: plan.expires_at_ms,
    })
}
pub(in crate::operations) fn derive_program_authority(
    program: &Pubkey,
    authority_seeds: &[Vec<u8>],
) -> Result<Address, OperationFailure> {
    if authority_seeds.is_empty()
        || authority_seeds.len() > 16
        || authority_seeds.iter().any(|seed| seed.len() > 32)
    {
        return Err(OperationFailure::Invalid);
    }
    let seed_refs = authority_seeds
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let pda = Pubkey::create_program_address(&seed_refs, program)
        .map_err(|_| OperationFailure::Invalid)?;
    Ok(Address::new_from_array(pda.to_bytes()))
}
pub(in crate::operations) fn prepared_generic_spend_result(
    request: &OperationRequestV1,
    keys: &RuntimeKeys,
    prepared: PreparedGenericSpend,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    let transact_digest = artifact_digest(&prepared.transact);
    let descriptor_digest = descriptor_digest_from_wallet(&request.wallet_descriptor)
        .map_err(|_| OperationFailure::Invalid)?;
    let sealed_authorization_capsule = seal_spend_authorization(
        keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest,
            state_digest: prepared.state_digest,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: request.request_id,
            expires_at_ms: prepared.expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::Spp {
                program_id: prepared.program_id.to_bytes(),
                input_tree: prepared.input_tree.to_bytes(),
                program_authorities: prepared
                    .program_authorities
                    .iter()
                    .map(Address::to_bytes)
                    .collect(),
                plan_digest: prepared.plan_digest,
                prepared_transact: prepared.transact.clone(),
                transact_digest,
                private_tx_hash: prepared.private_tx_hash,
            },
            shielded_balance_before: prepared.shielded_balance_before,
        },
    )?;
    Ok((
        OperationResultV1::AuthorizeSpend {
            result: AuthorizeSpendResultV1::Prepare {
                prepared: PreparedSpendV1::Spp {
                    program_id: prepared.program_id.to_string(),
                    input_tree: prepared.input_tree.to_string(),
                    plan_digest: prepared.plan_digest,
                    transact: prepared.transact,
                    transact_digest,
                    private_tx_hash: prepared.private_tx_hash,
                    external_data_hash: prepared.external_data_hash,
                },
                sealed_authorization_capsule,
                shielded_balance_before: prepared.shielded_balance_before,
            },
        },
        prepared.state_digest,
    ))
}
