use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use clap::Parser;
use zolana_tvc_keyholder_wallet::{load_qos_state, router, DiscoveryConfig};
use zolana_tvc_protocol::encoding::decode_lower_hex_array;

#[derive(Debug, Clone, Copy)]
struct SecurityDomainId([u8; 32]);

impl FromStr for SecurityDomainId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        decode_lower_hex_array(value)
            .map(Self)
            .map_err(|_| "must be exactly 32 bytes of lowercase unprefixed hex".to_owned())
    }
}

fn nonempty(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("must not be empty".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn positive_epoch(value: &str) -> Result<u64, String> {
    let epoch = value
        .parse::<u64>()
        .map_err(|_| "must be a canonical positive u64".to_owned())?;
    if epoch == 0 || epoch.to_string() != value {
        return Err("must be a canonical positive u64".to_owned());
    }
    Ok(epoch)
}

#[derive(Debug, Parser)]
#[command(name = "zolana-tvc-keyholder-wallet")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    #[arg(long, default_value_t = 44020)]
    port: u16,

    #[arg(long)]
    security_domain_id: SecurityDomainId,

    #[arg(long, value_parser = nonempty)]
    release_id: String,

    #[arg(long, value_parser = nonempty)]
    quorum_key_id: String,

    #[arg(long, value_parser = positive_epoch)]
    quorum_key_epoch: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let state = load_qos_state(DiscoveryConfig {
        security_domain_id: cli.security_domain_id.0,
        release_id: cli.release_id,
        quorum_key_id: cli.quorum_key_id,
        quorum_key_epoch: cli.quorum_key_epoch,
    })?;
    let address = SocketAddr::new(cli.host, cli.port);
    let listener = tokio::net::TcpListener::bind(address).await?;

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
