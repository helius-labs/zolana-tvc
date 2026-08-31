use crate::*;

pub(crate) fn output_json(output: &SppProofOutputUtxo, asset: &AssetJson) -> Result<Value> {
    let recipient = output.owner_address.context("missing output owner")?;
    Ok(json!({
        "recipient": recipient.to_string(),
        "asset": asset,
        "amount": output.amount.to_string(),
        "blinding": encode_hex(&output.blinding),
        "data": encode_hex(output.data.utxo_data().unwrap_or_default()),
        "data_hash": output.data_hash.map(|value| encode_hex(&value)),
        "memo": encode_hex(output.data.memo().unwrap_or_default()),
    }))
}
pub(crate) fn decode_transact(encoded: &str, expected_hash: &[u8; 32]) -> Result<TransactIxData> {
    let transact: TransactIxData = wincode::deserialize_exact(&decode_hex(encoded)?)?;
    if transact.private_tx_hash != *expected_hash {
        bail!("prepared transact private_tx_hash mismatch");
    }
    Ok(transact)
}
pub(crate) fn check_private_tx_binding(data: &[u8], private_tx_hash: &[u8; 32]) -> Result<()> {
    if data
        .windows(private_tx_hash.len())
        .filter(|window| *window == private_tx_hash)
        .count()
        != 1
    {
        bail!("outer instruction has an ambiguous private_tx_hash binding");
    }
    Ok(())
}
pub(crate) fn instruction_json(instruction: solana_instruction::Instruction) -> InstructionJson {
    InstructionJson {
        program_id: instruction.program_id.to_string(),
        accounts: instruction
            .accounts
            .into_iter()
            .map(|account| InstructionAccountJson {
                address: account.pubkey.to_string(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            })
            .collect(),
        data: encode_hex(&instruction.data),
    }
}
pub(crate) fn parse_u64(label: &str, value: &str) -> Result<u64> {
    value.parse().with_context(|| format!("invalid {label}"))
}
pub(crate) fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected {N} bytes"))
}
pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        bail!("invalid hex");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).context("invalid hex"))
        .collect()
}
pub(crate) fn encode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
