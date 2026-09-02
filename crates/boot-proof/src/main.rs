//! Fetches the public Boot Proof of a TVC replica for a relying party that
//! cannot query Turnkey itself.
//!
//! The browser client verifies the Boot Proof against its own pins; this tool
//! only carries the bytes, with a server-side Turnkey API key. It lives in a
//! standalone workspace so the Turnkey client graph stays out of the enclave
//! build.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::Parser;
use serde::Deserialize;
use turnkey_client::generated::services::coordinator::public::v1::GetBootProofRequest;
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};

/// Prints the Boot Proof for one Ephemeral key as JSON.
#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-boot-proof")]
struct Cli {
    #[arg(long)]
    organization_id: String,
    /// The replica's `boot_proof_lookup_key`: 130 bytes of lowercase hex.
    #[arg(long)]
    ephemeral_key: String,
    #[arg(long)]
    api_key_path: PathBuf,
}

#[derive(Deserialize)]
struct StoredApiKey {
    private_key: String,
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        hex::decode(&cli.ephemeral_key)
            .is_ok_and(|decoded| decoded.len() == 130 && hex::encode(decoded) == cli.ephemeral_key),
        "Ephemeral key must be 130-byte lowercase hex"
    );
    let stored: StoredApiKey = serde_json::from_slice(
        &fs::read(&cli.api_key_path)
            .with_context(|| format!("failed to read {}", cli.api_key_path.display()))?,
    )?;
    let api_key = TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key))?;
    let client = TurnkeyClient::builder().api_key(api_key).build()?;
    let response = client
        .get_boot_proof(GetBootProofRequest {
            organization_id: cli.organization_id,
            ephemeral_key: cli.ephemeral_key,
        })
        .await?;
    let boot_proof = response.boot_proof.context("Boot Proof was not found")?;
    println!("{}", serde_json::to_string(&boot_proof)?);
    Ok(())
}
