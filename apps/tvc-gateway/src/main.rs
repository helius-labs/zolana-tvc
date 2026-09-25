use std::sync::Arc;

use tracing::info;
use tracing_subscriber::EnvFilter;
use tvc_gateway::app::{self, AppState};
use tvc_gateway::config::{self, Stage};
use tvc_gateway::metrics;

fn config_path() -> String {
    let mut args = std::env::args().skip(1);
    match (args.next(), args.next()) {
        (Some(flag), Some(path)) if flag == "--config" => path,
        (Some(path), None) => path,
        _ => "configs/config.yaml".to_owned(),
    }
}

fn init_tracing(stage: Stage) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match stage {
        Stage::Prod => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        Stage::Dev => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        let _ = interrupt.await;
        return;
    };
    tokio::select! {
        _ = interrupt => {}
        _ = terminate.recv() => {}
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::load(&config_path())?;
    init_tracing(config.stage);
    metrics::init(&config.metrics)?;
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider already installed");
    }
    let state = Arc::new(AppState::new(&config).await?);
    let router = app::router(state, config.enclave.max_body_bytes);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    info!(stage = ?config.stage, listen = %config.listen, "tvc-gateway starting");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    info!("tvc-gateway stopped");
    Ok(())
}
