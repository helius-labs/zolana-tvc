//! The viewing side: the tags a wallet is found by, and opening the outputs
//! found under them as this wallet's UTXOs.

use std::str::FromStr;

use solana_address::Address;
use zolana_keypair::viewing_key::Salt;
use zolana_keypair::P256Pubkey;
use zolana_transaction::instructions::types::SppProofInputUtxo;
use zolana_transaction::serialization::confidential::ConfidentialOutputPlaintext;
use zolana_transaction::{AssetRegistry, Data, Utxo};
use zolana_tvc_protocol::constants::MAX_DECRYPT_PAYLOADS_PER_BATCH;
use zolana_tvc_protocol::types::{DecryptPayload, DecryptedPayload, OperationResult, SplAsset};

use super::sealed::Roles;
use super::Failure;

pub(super) fn tags(roles: &Roles) -> OperationResult {
    OperationResult::ViewTags {
        view_tags: vec![roles.viewing_key.recipient_bootstrap_view_tag()],
    }
}

/// Opens each payload as a UTXO of this wallet and returns it with its
/// commitment and nullifier.
///
/// The transport cipher is unauthenticated, so another wallet's ciphertext
/// decrypts to bytes that almost never decode; when they do, the returned
/// commitment will not match the indexed output, which is the check the client
/// makes. A UTXO carrying data is reported unreadable: its commitment needs
/// hashes this rail does not carry, and it cannot be spent here.
pub(super) fn decrypt(
    roles: &Roles,
    payloads: &[DecryptPayload],
    assets: &[SplAsset],
) -> Result<OperationResult, Failure> {
    if payloads.is_empty() || payloads.len() as u64 > MAX_DECRYPT_PAYLOADS_PER_BATCH {
        return Err(Failure::Invalid);
    }
    let registry = registry(assets)?;
    let mut results = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        let index = index as u64;
        let utxo = match payload {
            DecryptPayload::Encrypted {
                ciphertext,
                transaction_viewing_public_key,
                salt,
                slot_index,
            } => {
                let key: [u8; 33] = transaction_viewing_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Failure::Invalid)?;
                let key = P256Pubkey::from_bytes(key).map_err(|_| Failure::Invalid)?;
                let salt: Salt = salt.as_slice().try_into().map_err(|_| Failure::Invalid)?;
                let slot = u32::try_from(*slot_index).map_err(|_| Failure::Invalid)?;
                roles
                    .viewing_key
                    .decrypt_utxo(ciphertext, &key, salt, slot)
                    .ok()
                    .and_then(|plaintext| {
                        ConfidentialOutputPlaintext::deserialize(&plaintext)
                            .ok()?
                            .into_utxo(roles.owner, &registry)
                            .ok()
                    })
            }
            DecryptPayload::Plain {
                asset,
                amount,
                blinding,
            } => Some(Utxo {
                owner: roles.owner,
                asset: Address::from_str(asset).map_err(|_| Failure::Invalid)?,
                amount: *amount,
                blinding: *blinding,
                ring_program_id: None,
                data: Data::default(),
            }),
        };
        let opened = utxo.filter(|utxo| utxo.data.is_empty()).and_then(|utxo| {
            let input = SppProofInputUtxo::new(utxo, &roles.nullifier_key);
            let (commitment, nullifier) = (input.hash().ok()?, input.nullifier().ok()?);
            Some(DecryptedPayload::Utxo {
                index,
                asset: input.utxo.asset.to_string(),
                amount: input.utxo.amount,
                blinding: input.utxo.blinding,
                ring_program_id: input.utxo.ring_program_id.map(|id| id.to_string()),
                commitment,
                nullifier,
            })
        });
        results.push(opened.unwrap_or(DecryptedPayload::Unreadable { index }));
    }
    Ok(OperationResult::Decrypt { payloads: results })
}

pub(super) fn registry(assets: &[SplAsset]) -> Result<AssetRegistry, Failure> {
    let entries = assets
        .iter()
        .map(|asset| {
            Address::from_str(&asset.mint)
                .map(|mint| (asset.asset_id, mint))
                .map_err(|_| Failure::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    AssetRegistry::new(entries).map_err(|_| Failure::Invalid)
}
