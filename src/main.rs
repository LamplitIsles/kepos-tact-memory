//! Kepos-published Tact remote memory over local SQLite.
//!
//! The service speaks the Tact remote-memory protocol (routes under `/v1/`) and is meant to
//! sit behind a Kepos publisher's `kind = "http"` service. Kepos strips caller-supplied
//! `Authorization` fields and injects `Authorization: Kepos <subscriber-public-key>`; this
//! server resolves each device to its bound Tact namespace (one person's several devices share
//! one namespace) and applies the configured role. Same-host clients may additionally
//! authenticate with a loopback-only bearer token (`[[auth.credentials]]`); the Kepos header
//! remains the only network identity. Never expose the listener outside the private Kepos
//! publisher ingress — the header can be forged by anything that reaches the target directly.

use std::net::SocketAddr;

use clap::Parser;
use kepos_tact_memory::{
    config::{self, Args},
    router::{ServerState, router},
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let settings = config::Settings::resolve(&args)?;
    let policy = settings.policy()?;
    if !settings.has_devices() && settings.credentials.is_empty() {
        eprintln!(
            "warning: no Kepos devices are bound and no bearer credentials are configured; \
             every request will return 401. Configure --binding or a config file with \
             [[auth.bindings]] (and optionally [[auth.credentials]] for loopback clients)."
        );
    }
    let credentials = settings.credential_table()?;
    info!(
        bind = %settings.bind,
        db = %settings.db.display(),
        devices = settings.bindings.iter().map(|b| b.keys.len()).sum::<usize>(),
        credentials = settings.credentials.len(),
        "starting Kepos Tact memory service"
    );

    let state = ServerState::new(settings.db.clone(), policy, credentials);
    serve(settings.bind, state).await
}

async fn serve(bind: SocketAddr, state: ServerState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutting down");
}
