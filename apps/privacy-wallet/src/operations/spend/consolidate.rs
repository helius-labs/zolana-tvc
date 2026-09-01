use super::*;

/// Consolidate up to eight plain default-domain UTXOs through Zolana's
/// dedicated `merge_8_1` circuit. This path is balance-neutral and needs no
/// shielded transaction signature: ownership is proven from the enclave-held
/// nullifier key, while the public wallet remains the transaction fee payer.
pub(super) async fn build_merge_transaction(
    keypair: &TurnkeyEd25519ShieldedKeypair,
    wallet: &Wallet,
    zolana: &ZolanaClient<SolanaRpc>,
    prover_url: &str,
    payer: Address,
    asset: Address,
    tree: Address,
) -> Result<VersionedTransaction, OperationFailure> {
    let candidates = select_merge_candidates(wallet, asset, tree);
    if candidates.len() < 2 {
        return Err(OperationFailure::Failed(
            FailureStage::UnsupportedProofShape,
        ));
    }

    let inputs = candidates
        .into_iter()
        .map(|entry| SppProofInputUtxo::new(entry.utxo.clone(), keypair.nullifier_key()))
        .collect();
    let prepared = Merge::new(keypair, inputs)
        .map_err(|_| OperationFailure::Failed(FailureStage::PrivateTransitionAssembly))?
        .prepare();
    let commitments = prepared
        .input_utxo_hashes()
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let proofs = zolana
        .get_input_merkle_proofs_for_tree(tree, &commitments, None)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;

    let nullifier_key = keypair.nullifier_key();
    let dummy_nullifiers = prepared
        .dummy_nullifiers(&nullifier_key)
        .map_err(|_| OperationFailure::Failed(FailureStage::ProofAssembly))?;
    let dummy_nullifier_proofs = if dummy_nullifiers.is_empty() {
        Vec::new()
    } else {
        zolana
            .get_non_inclusion_proofs(tree, dummy_nullifiers, None)
            .await
            .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?
            .proofs
    };
    ensure_dummy_proofs_match_tree(&dummy_nullifier_proofs, tree)?;

    let built = MergeProver::try_from(MergeWitness {
        prepared,
        nullifier_key,
        proofs,
        dummy_nullifier_proofs,
    })
    .and_then(MergeProver::build)
    .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let prover = AsyncProverClient::new(prover_url.to_owned());
    let proof = prover
        .prove_merge(&built.inputs)
        .await
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let packed = ProofCompressed::try_from(proof)
        .and_then(|proof| proof.to_merge_proof())
        .map_err(|error| OperationFailure::Failed(client_error_stage(&error)))?;
    let payer = Pubkey::new_from_array(payer.to_bytes());
    let merge = MergeTransact {
        input_tree: Pubkey::new_from_array(tree.to_bytes()),
        output_tree: Pubkey::new_from_array(tree.to_bytes()),
        payer,
        user_record: user_record_pda(&payer).0,
        data: built.instruction_data(packed),
    }
    .instruction();
    let compute = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let (blockhash, _) = zolana
        .rpc()
        .get_latest_blockhash()
        .await
        .map_err(|_| OperationFailure::Failed(FailureStage::LatestBlockhash))?;
    let message = Message::new_with_blockhash(&[compute, merge], Some(&payer), &blockhash);
    Ok(VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::Legacy(message),
    })
}

pub(in crate::operations) fn select_merge_candidates(
    wallet: &Wallet,
    asset: Address,
    tree: Address,
) -> Vec<&WalletUtxo> {
    let mut candidates = wallet
        .utxos
        .iter()
        .filter(|entry| {
            !entry.spent
                && entry.utxo.asset == asset
                && entry.output_context.tree == tree
                && entry.utxo.ring_program_id.is_none()
                && entry.data_hash.is_none()
                && entry.ring_data_hash.is_none()
                && entry.utxo.data.is_empty()
        })
        .collect::<Vec<_>>();
    // This rail is entered because a concrete transfer could not fit the
    // ordinary <=5-input circuit. Merging the largest fragments makes the
    // saved transfer resumable with the fewest extra transactions.
    candidates.sort_by_key(|entry| std::cmp::Reverse(entry.utxo.amount));
    candidates.truncate(MERGE_INPUTS);
    candidates
}
