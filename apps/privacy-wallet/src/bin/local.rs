//! Explicitly unattested local development server.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;
use qos_p256::P256Pair;
use zeroize::Zeroizing;
use zolana_tvc_privacy_wallet::{
    local_testkit_qos_seeds, local_unattested_state, router, LocalServiceConfig,
};

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-privacy-wallet-local")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44020)]
    port: u16,

    /// Disposable Solana keypair JSON used by both the Node test and local custody.
    #[arg(long)]
    wallet_keypair: PathBuf,

    #[arg(long, default_value = "http://127.0.0.1:3001")]
    prover_url: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let encoded = std::fs::read(&cli.wallet_keypair)?;
    let keypair: Vec<u8> = serde_json::from_slice(&encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid keypair JSON"))?;
    if keypair.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the wallet keypair must contain exactly 64 bytes",
        ));
    }
    let mut wallet_secret = Zeroizing::new([0_u8; 32]);
    wallet_secret.copy_from_slice(&keypair[..32]);

    // Stable test-only QOS keys let the SDK pin the local server instead of
    // trusting whatever process happens to answer on the loopback port.
    let (ephemeral_seed, quorum_seed) = local_testkit_qos_seeds();
    let ephemeral = P256Pair::from_master_seed(&Zeroizing::new(ephemeral_seed))
        .map_err(|_| io::Error::other("failed to derive local ephemeral key"))?;
    let quorum = P256Pair::from_master_seed(&Zeroizing::new(quorum_seed))
        .map_err(|_| io::Error::other("failed to derive local quorum key"))?;
    let state = local_unattested_state(
        ephemeral,
        quorum,
        *wallet_secret,
        LocalServiceConfig {
            prover_url: cli.prover_url,
        },
    );
    let address = SocketAddr::new(cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(address).await?;

    eprintln!(
        "LOCAL DEVELOPMENT ONLY: unattested mock custody listening on {address}; do not use funds"
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
