use super::*;

mod consolidate;
mod direct;
mod finalize;
mod generic;
mod message;
mod ring;

use consolidate::build_merge_transaction;
#[cfg(test)]
pub(in crate::operations) use consolidate::select_merge_candidates;
pub(in crate::operations) use direct::*;
pub(in crate::operations) use finalize::*;
pub(in crate::operations) use generic::*;
pub(in crate::operations) use message::*;
#[cfg(test)]
pub(in crate::operations) use ring::select_exact_default_ring_inputs;
use ring::{build_ring_transaction, RingSpendContext};

/// The one spend authority exposed by the enclave. Prepare proves and seals an
/// exact unsigned transaction; finalize independently revalidates the capsule
/// and transaction before invoking Turnkey once. There is no one-call protocol
/// variant.
///
/// The development implementation performs pinned Photon, Solana RPC, and
/// prover calls inside this operation. Its common prover still receives the
/// plaintext witness, including the long-lived nullifier secret; this boundary
/// must change before a production privacy claim.
pub(super) async fn authorize_spend(
    request: &OperationRequestV1,
    target: &ValidatedWallet<'_>,
    spend: &AuthorizeSpendRequestV1,
    state: &AppState,
    keys: &RuntimeKeys,
) -> Result<(OperationResultV1, [u8; 32]), OperationFailure> {
    match spend {
        AuthorizeSpendRequestV1::Prepare { plan } => match plan {
            SpendPlanV1::Direct { transition } => {
                let prepared =
                    prepare_direct_spend(request, target, transition, state, keys).await?;
                prepared_direct_spend_result(request, keys, prepared)
            }
            SpendPlanV1::Program { transition } => {
                let prepared =
                    prepare_generic_spp(request, target, transition, state, keys).await?;
                prepared_generic_spend_result(request, keys, prepared)
            }
        },
        AuthorizeSpendRequestV1::Finalize {
            sealed_authorization_capsule,
            unsigned_transaction,
        } => {
            finalize_prepared_transaction(
                request,
                target,
                state,
                keys,
                sealed_authorization_capsule,
                unsigned_transaction,
            )
            .await
        }
    }
}
pub(super) struct PreparedDirectSpend {
    unsigned: VersionedTransaction,
    state_digest: [u8; 32],
    shielded_balance_before: u64,
}
pub(super) struct PreparedGenericSpend {
    program_id: Address,
    input_tree: Address,
    program_authorities: Vec<Address>,
    plan_digest: [u8; 32],
    transact: Vec<u8>,
    private_tx_hash: [u8; 32],
    external_data_hash: [u8; 32],
    state_digest: [u8; 32],
    shielded_balance_before: u64,
    expires_at_ms: u64,
}
pub(super) struct AuthorizedSpend {
    signed_transaction: Vec<u8>,
    transaction_signature: String,
    shielded_balance_before: u64,
    turnkey_activity_id: String,
    turnkey_app_proofs: Vec<TurnkeyVerifiedAppProofV1>,
    evidence_classification: TurnkeyEvidenceClassification,
}
pub(super) fn domain_ring(domain: &PrivateDomainV1) -> Option<(&str, &str)> {
    match domain {
        PrivateDomainV1::Default => None,
        PrivateDomainV1::Ring {
            program_id,
            lookup_table,
        } => Some((program_id, lookup_table)),
    }
}
/// Returns the one custom-ring boundary involved in a direct transition.
/// Direct Ring(A) -> Ring(B) is intentionally impossible: the wallet composes
/// two independent transitions through an exact self-owned default UTXO.
pub(super) fn transaction_ring(
    intent: &SpendIntentV1,
) -> Result<Option<(&str, &str)>, OperationFailure> {
    let source = domain_ring(&intent.source);
    let destination = match &intent.settlement {
        SpendSettlementV1::Transfer { destination, .. } => domain_ring(destination),
        SpendSettlementV1::Withdrawal { .. } | SpendSettlementV1::Consolidate { .. } => None,
    };
    match (source, destination) {
        (Some(source), Some(destination)) if source != destination => {
            Err(OperationFailure::Invalid)
        }
        (Some(ring), _) | (_, Some(ring)) => Ok(Some(ring)),
        (None, None) => Ok(None),
    }
}
pub(super) fn authorized_spend(
    signed: CustodySignedTransaction,
    shielded_balance_before: u64,
) -> Result<AuthorizedSpend, OperationFailure> {
    let transaction = signed.transaction;
    let signed_bytes =
        bincode1::serialize(&transaction).map_err(|_| OperationFailure::Unavailable)?;
    // A v0 message over a lookup table is what keeps this inside the packet
    // limit; past it, nothing can submit the transaction.
    if signed_bytes.len() > MAX_SOLANA_TRANSACTION_BYTES {
        return Err(OperationFailure::Unavailable);
    }
    let transaction_signature = transaction
        .signatures
        .first()
        .ok_or(OperationFailure::Unavailable)?
        .to_string();
    Ok(AuthorizedSpend {
        transaction_signature,
        signed_transaction: signed_bytes,
        shielded_balance_before,
        turnkey_activity_id: signed.activity_id,
        turnkey_app_proofs: signed.app_proofs,
        evidence_classification: TurnkeyEvidenceClassification::CryptographicallyValidButUnbound,
    })
}
