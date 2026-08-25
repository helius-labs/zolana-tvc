//! Explicitly unattested local development server.

use std::io;
use std::net::{IpAddr, SocketAddr};

use clap::Parser;
use qos_p256::P256Pair;
use zolana_tvc_enclave_wallet::{local_unattested_state, router};

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-enclave-wallet-local")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44020)]
    port: u16,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let ephemeral = P256Pair::generate()
        .map_err(|_| io::Error::other("failed to generate local ephemeral key"))?;
    let quorum = P256Pair::generate()
        .map_err(|_| io::Error::other("failed to generate local quorum key"))?;
    let state = local_unattested_state(ephemeral, quorum)?;
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
