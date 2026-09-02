//! Derives the shielded identity from the custodian's signature over the
//! wallet's derivation message and seals the seed to the Quorum key.

use zeroize::Zeroizing;
use zolana_keypair::derivation;
use zolana_tvc_protocol::types::{OperationRequest, OperationResult};

use super::sealed::{seal, Roles};
use super::Failure;
use crate::custody::WalletKey;
use crate::Runtime;

pub(super) async fn run(
    request: &OperationRequest,
    wallet: &WalletKey<'_>,
    runtime: &Runtime,
) -> Result<(OperationResult, [u8; 32]), Failure> {
    let message = derivation::ed25519_derivation_message(&wallet.public_key);
    let signed = runtime
        .custody
        .sign_raw(wallet, &message, request.issued_at_ms)
        .await?;
    let seed = Zeroizing::new(signed.signature);
    let roles = Roles::from_seed(&wallet.public_key, &seed).map_err(|_| Failure::Unavailable)?;
    let address = roles.address()?;
    let (sealed_wallet_state, digest) = seal(request, runtime, wallet.public_key, *seed)?;
    Ok((
        OperationResult::Bootstrap {
            solana_address: wallet.sign_with.to_owned(),
            shielded_owner_hash: address.owner_hash().map_err(|_| Failure::Unavailable)?,
            shielded_nullifier_public_key: address.nullifier_pubkey,
            shielded_viewing_public_key: address.viewing_pubkey.as_bytes().to_vec(),
            sealed_wallet_state,
            turnkey_activity_id: signed.evidence.activity_id,
            turnkey_app_proofs: signed.evidence.app_proofs,
        },
        digest,
    ))
}
