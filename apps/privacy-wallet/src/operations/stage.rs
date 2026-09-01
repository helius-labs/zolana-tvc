use super::*;

/// The stage a custom-ring transfer failed at.
///
/// The ring path proves in one call that reads the ring config, the tree, the
/// indexer's proofs and the prover, so the error type is the only thing that
/// says which of them gave up. Reporting the prover for all of them would send
/// every reader to the same wrong service.
pub(super) fn ring_transfer_stage(error: &TransferError) -> FailureStage {
    match error {
        TransferError::Client(inner) => client_error_stage(inner),
        // `AccountRead` belongs here rather than with the tree: the only
        // account this path reads that way is the ring's config.
        TransferError::MissingRingConfig | TransferError::AccountRead(_) => {
            FailureStage::RingConfig
        }
        TransferError::MissingTree
        | TransferError::InvalidTreeOwner
        | TransferError::InvalidTreeDiscriminator
        | TransferError::TreeRequired
        | TransferError::Tree(_) => FailureStage::InputTree,
        TransferError::IncompleteProofSet => FailureStage::IndexerProofs,
        TransferError::ProofInput(_)
        | TransferError::PaddedChange
        | TransferError::InvalidDummyOutput
        | TransferError::MissingAssetRegistry
        | TransferError::ForeignRing(_) => FailureStage::ProofAssembly,
        TransferError::Proof(_) | TransferError::IncompleteInputSet => FailureStage::ExternalProver,
        TransferError::Keypair(_) => FailureStage::PrivateTransitionAssembly,
        _ => FailureStage::SettlementConstruction,
    }
}
/// The stage a client error belongs to, for any call that walks the indexer,
/// the proofs, the prover and submission in one step.
pub(super) fn client_error_stage(error: &ClientError) -> FailureStage {
    match error {
        ClientError::Indexer(_)
        | ClientError::IndexerUnavailable(_)
        | ClientError::UnsupportedRpcMethod(_)
        | ClientError::IndexerNotCaughtUp { .. }
        | ClientError::IncompleteInputProofs { .. }
        | ClientError::StateProofLeafMismatch { .. }
        | ClientError::StateProofTreeMismatch { .. }
        | ClientError::NullifierProofLeafMismatch { .. }
        | ClientError::NullifierProofTreeMismatch { .. } => FailureStage::IndexerProofs,
        ClientError::MissingInputMerkleProof { .. }
        | ClientError::ProofPathLength { .. }
        | ClientError::WitnessInputCountMismatch { .. }
        | ClientError::InputTreeIndexCountMismatch { .. } => FailureStage::ProofAssembly,
        ClientError::ProverServer(_) | ClientError::ProofParse(_) | ClientError::Prover(_) => {
            FailureStage::ExternalProver
        }
        ClientError::ProofVerification(_) => FailureStage::LocalProofVerification,
        _ => FailureStage::TransactionAssembly,
    }
}
/// Preserve actionable, non-secret causes from local default-rail assembly.
/// None of these variants carries UTXO hashes, amounts, keys, or prover input.
pub(super) fn private_transition_stage(error: &ClientError) -> FailureStage {
    match error {
        ClientError::UnsupportedShape { .. }
        | ClientError::TooManyInputs { .. }
        | ClientError::TooManyOutputs { .. }
        | ClientError::Transaction(
            TransactionError::UnsupportedShape { .. }
            | TransactionError::TooManyInputs { .. }
            | TransactionError::TooManyOutputsForShape { .. },
        ) => FailureStage::UnsupportedProofShape,
        ClientError::Transaction(TransactionError::P256TransactUnsupported) => {
            FailureStage::UnsupportedShieldedOwner
        }
        ClientError::UnsignedInputUnavailable { .. } => FailureStage::ShieldedInputChanged,
        ClientError::Transaction(
            TransactionError::WalletAuthorityMismatch
            | TransactionError::MissingCurrentViewingKey
            | TransactionError::AuthorityViewingKeyMismatch,
        ) => FailureStage::ShieldedIdentityMismatch,
        _ => FailureStage::PrivateTransitionAssembly,
    }
}
