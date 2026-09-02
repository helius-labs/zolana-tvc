//! One default-pool spend over inputs the client selected: build the private
//! transition, prove it through the pinned prover, and have the custodian sign
//! the resulting Solana transaction.

use std::str::FromStr;

use solana_address::Address;
use solana_hash::Hash;
use zolana_client::{AsyncRpc as _, ClientError, SignedPrivateTransaction, ZolanaClient};
use zolana_interface::instruction::{
    TransactInterfaceTransferAccounts, TransactSolTransferAccounts, TransactSplWithdrawalAccounts,
};
use zolana_interface::{pda, state::SplAssetRegistry, SHIELDED_POOL_PROGRAM_ID};
use zolana_keypair::random_salt;
use zolana_keypair::shielded::{ShieldedAddress, SHIELDED_ADDRESS_LEN};
use zolana_transaction::instructions::transact::{
    encode_confidential_slots, ConfidentialTransfer, SettlementTarget,
};
use zolana_transaction::instructions::types::SppProofInputUtxo;
use zolana_transaction::{AssetRegistry, Data, Utxo, SOL_MINT};
use zolana_tvc_protocol::constants::MAX_SPEND_INPUTS;
use zolana_tvc_protocol::types::{
    FailureStage, OperationRequest, OperationResult, SpendAction, SpendInput, SplAsset,
};

use super::sealed::Roles;
use super::{view, Failure};
use crate::custody::WalletKey;
use crate::rpc::SolanaRpc;
use crate::Runtime;

/// Solana's packet limit; nothing larger can be submitted.
const MAX_TRANSACTION_BYTES: usize = 1_232;

pub(super) struct Spend<'a> {
    pub request: &'a OperationRequest,
    pub wallet: &'a WalletKey<'a>,
    pub roles: &'a Roles,
    pub runtime: &'a Runtime,
    pub tree: &'a str,
    pub inputs: &'a [SpendInput],
    pub action: &'a SpendAction,
    pub assets: &'a [SplAsset],
}

impl Spend<'_> {
    pub(super) async fn run(self) -> Result<OperationResult, Failure> {
        let (SpendAction::Transfer { amount, .. } | SpendAction::Withdrawal { amount, .. }) =
            self.action;
        if self.inputs.is_empty() || self.inputs.len() > MAX_SPEND_INPUTS || *amount == 0 {
            return Err(Failure::Invalid);
        }
        let tree = Address::from_str(self.tree).map_err(|_| Failure::Invalid)?;
        let payer = Address::new_from_array(self.wallet.public_key);
        let services = &self.runtime.services;
        let rpc = SolanaRpc::new(&services.solana_rpc_url, services.allow_insecure_http)
            .map_err(|_| Failure::Unavailable)?;
        let registry = verified_registry(&rpc, self.assets).await?;

        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                let utxo = Utxo {
                    owner: self.roles.owner,
                    asset: Address::from_str(&input.asset).map_err(|_| Failure::Invalid)?,
                    amount: input.amount,
                    blinding: input.blinding,
                    ring_program_id: None,
                    data: Data::default(),
                };
                Ok(SppProofInputUtxo::new(utxo, &self.roles.nullifier_key))
            })
            .collect::<Result<Vec<_>, Failure>>()?;
        let mut transfer = ConfidentialTransfer::new(self.roles.address()?, inputs, payer);
        let settlement_transfers = match self.action {
            SpendAction::Transfer {
                recipient,
                asset,
                amount,
            } => {
                let recipient: &[u8; SHIELDED_ADDRESS_LEN] = recipient
                    .as_slice()
                    .try_into()
                    .map_err(|_| Failure::Invalid)?;
                let recipient =
                    ShieldedAddress::from_bytes(recipient).map_err(|_| Failure::Invalid)?;
                let asset = Address::from_str(asset).map_err(|_| Failure::Invalid)?;
                transfer
                    .send(&recipient, asset, *amount)
                    .map_err(|_| Failure::Invalid)?;
                Vec::new()
            }
            SpendAction::Withdrawal {
                recipient,
                asset,
                amount,
            } => {
                let recipient = Address::from_str(recipient).map_err(|_| Failure::Invalid)?;
                let asset = Address::from_str(asset).map_err(|_| Failure::Invalid)?;
                let (target, accounts) = withdrawal_target(recipient, asset);
                transfer
                    .withdraw(asset, *amount, target)
                    .map_err(|_| Failure::Invalid)?;
                vec![accounts]
            }
        };
        let prepared = transfer.prepare().map_err(|_| Failure::Invalid)?;

        let transaction_key = self
            .roles
            .viewing_key
            .get_transaction_viewing_key(&prepared.first_nullifier)
            .map_err(|_| Failure::Invalid)?;
        let salt = random_salt();
        let slots = encode_confidential_slots(&prepared.outputs, &registry, &transaction_key, salt)
            .map_err(|_| Failure::Invalid)?;
        let proof_inputs = prepared
            .finalize(transaction_key.pubkey(), salt, slots)
            .map_err(|_| Failure::Invalid)?;
        let signed = SignedPrivateTransaction {
            transaction: proof_inputs,
            settlement_transfers,
            input_tree: tree,
        };

        let zolana = ZolanaClient::from_urls_allowing_insecure_http(
            rpc,
            &services.indexer_url,
            &services.prover_url,
            tree,
        );
        // The blockhash goes in after the expensive proof, so a slow prover
        // cannot consume its lifetime before the transaction exists.
        let mut unsigned = zolana
            .finish_submission_unsigned(&signed, payer, Hash::default())
            .await
            .map_err(|error| Failure::Stage(stage(&error)))?;
        let (blockhash, _) = zolana
            .rpc()
            .get_latest_blockhash()
            .await
            .map_err(|_| Failure::Stage(FailureStage::Blockhash))?;
        unsigned.message.recent_blockhash = blockhash;

        let signed = self
            .runtime
            .custody
            .sign_transaction(self.wallet, unsigned, self.request.issued_at_ms)
            .await?;
        let signed_transaction = bincode1::serialize(&signed.transaction)
            .map_err(|_| Failure::Stage(FailureStage::TransactionAssembly))?;
        if signed_transaction.len() > MAX_TRANSACTION_BYTES {
            return Err(Failure::Stage(FailureStage::TransactionAssembly));
        }
        Ok(OperationResult::Spend {
            signature: signed.transaction.signatures[0].to_string(),
            signed_transaction,
            turnkey_activity_id: signed.evidence.activity_id,
            turnkey_app_proofs: signed.evidence.app_proofs,
        })
    }
}

/// The client's compact asset ids, confirmed against the pool's on-chain
/// registry. A wrong id would encrypt an output the recipient cannot decode.
async fn verified_registry(rpc: &SolanaRpc, assets: &[SplAsset]) -> Result<AssetRegistry, Failure> {
    let registry = view::registry(assets)?;
    for asset in assets {
        let mint = Address::from_str(&asset.mint).map_err(|_| Failure::Invalid)?;
        let account = rpc
            .get_account(pda::spl_asset_registry(&mint))
            .await
            .map_err(|_| Failure::Stage(FailureStage::AssetRegistry))?
            .ok_or(Failure::Invalid)?;
        if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
            return Err(Failure::Invalid);
        }
        let registered =
            SplAssetRegistry::from_account_bytes(&account.data).map_err(|_| Failure::Invalid)?;
        if registered.mint != mint || registered.asset_id != asset.asset_id {
            return Err(Failure::Invalid);
        }
    }
    Ok(registry)
}

/// Where a withdrawal lands: the recipient itself for SOL, its associated
/// token account under the classic SPL Token program otherwise.
fn withdrawal_target(
    recipient: Address,
    asset: Address,
) -> (SettlementTarget, TransactInterfaceTransferAccounts) {
    if asset == SOL_MINT {
        return (
            SettlementTarget::Sol {
                user_sol_account: recipient,
            },
            TransactInterfaceTransferAccounts::Sol(TransactSolTransferAccounts { recipient }),
        );
    }
    let token_program = pda::spl_token_program_id();
    let user_token_account =
        pda::associated_token_address_with_program(&recipient, &asset, &token_program);
    let spl_interface = pda::spl_interface(&asset);
    (
        SettlementTarget::Spl {
            user_spl_token: user_token_account,
            spl_token_interface: spl_interface,
        },
        TransactInterfaceTransferAccounts::SplWithdrawal(TransactSplWithdrawalAccounts {
            mint: asset,
            spl_interface,
            user_token_account,
            token_program,
        }),
    )
}

/// Which service a proving failure belongs to. The prover is named for prover
/// errors only; sending every reader there would be wrong most of the time.
fn stage(error: &ClientError) -> FailureStage {
    match error {
        ClientError::Indexer(_)
        | ClientError::IndexerUnavailable(_)
        | ClientError::IndexerNotCaughtUp { .. }
        | ClientError::IncompleteInputProofs { .. }
        | ClientError::MissingInputMerkleProof { .. }
        | ClientError::StateProofLeafMismatch { .. }
        | ClientError::StateProofTreeMismatch { .. }
        | ClientError::NullifierProofLeafMismatch { .. }
        | ClientError::NullifierProofTreeMismatch { .. } => FailureStage::IndexerProofs,
        ClientError::ProverServer(_) | ClientError::ProofParse(_) | ClientError::Prover(_) => {
            FailureStage::Prover
        }
        ClientError::ProofVerification(_) => FailureStage::ProofVerification,
        _ => FailureStage::TransactionAssembly,
    }
}
