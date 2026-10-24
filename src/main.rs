mod config;
mod fileops;
mod mcp;
mod runs;
mod ssh;
mod tools;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use config::Config;
use runs::Runs;
use serde_json::json;
use ssh::Pool;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

pub struct AppState {
    pub cfg: Arc<Config>,
    pub pool: Arc<Pool>,
    pub runs: Arc<Runs>,
    pub started: Instant,
}

async fn method_not_allowed() -> impl IntoResponse {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")], "")
}

async fn health(State(app): State<Arc<AppState>>) -> impl IntoResponse {
    let pool: Vec<_> = app
        .pool
        .stats()
        .into_iter()
        .map(|s| json!({"target": s.key, "conns": s.conns, "channels_in_use": s.in_use}))
        .collect();
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": app.started.elapsed().as_secs(),
        "active_runs": app.runs.active_count(),
        "pool": pool,
    }))
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    info!("shutting down");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .init();

    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("SSH_MCP_CONFIG").ok())
        .unwrap_or_else(|| "/etc/ssh-mcp-rs/config.toml".into());
    let cfg = Arc::new(Config::load(path.as_ref())?);
    let pool = Arc::new(Pool::new(cfg.clone())?);
    let runs = Runs::new(pool.clone(), cfg.clone());
    runs.spawn_reaper();

    let app = Arc::new(AppState {
        cfg: cfg.clone(),
        pool,
        runs,
        started: Instant::now(),
    });

    let router = Router::new()
        .route(
            "/mcp",
            post(mcp::handle)
                .get(method_not_allowed)
                .delete(method_not_allowed)
                .route_layer(axum::middleware::from_fn_with_state(app.clone(), mcp::gate)),
        )
        .route("/healthz", get(health))
        .layer(DefaultBodyLimit::max(cfg.limits.max_body_bytes))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    if !addr.ip().is_loopback() && cfg.auth_token.is_none() {
        warn!("listening on non-loopback {addr} WITHOUT an auth token");
    }
    info!(%addr, hosts = cfg.hosts.len(), auth = cfg.auth_token.is_some(), "ssh-mcp-rs listening on /mcp");
    axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
