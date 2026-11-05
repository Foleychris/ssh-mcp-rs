mod config;
mod fileops;
mod mcp;
mod runs;
mod ssh;
mod stdio;
mod tools;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use config::{Config, Mode};
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

pub(crate) async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    info!("shutting down");
}

const USAGE: &str = "usage: ssh-mcp-rs [--stdio] [CONFIG]\n\n\
  (default)  serve MCP over Streamable HTTP on `listen` (POST /mcp)\n\
  --stdio    serve MCP over stdin/stdout for a local client; no network listener\n\n\
CONFIG defaults to $SSH_MCP_CONFIG, then /etc/ssh-mcp-rs/config.toml (HTTP) or\n\
$XDG_CONFIG_HOME/ssh-mcp-rs/config.toml, ~/.config/ssh-mcp-rs/config.toml (stdio).";

/// `[--stdio] [CONFIG]`, in any order. Unknown flags are an error rather than
/// being taken for a config path.
fn parse_args(args: impl Iterator<Item = String>) -> Result<(Mode, Option<String>), String> {
    let mut mode = Mode::Http;
    let mut path = None;
    for a in args {
        match a.as_str() {
            "--stdio" => mode = Mode::Stdio,
            "-h" | "--help" => return Err("ssh-mcp-rs: MCP server for running commands over SSH".into()),
            f if f.starts_with('-') => return Err(format!("unknown option {f:?}")),
            _ if path.is_some() => return Err("more than one config path given".into()),
            _ => path = Some(a),
        }
    }
    Ok((mode, path))
}

fn default_config(mode: Mode) -> String {
    let xdg = std::env::var("XDG_CONFIG_HOME").ok().filter(|v| !v.is_empty());
    let home = std::env::var("HOME").ok().filter(|v| !v.is_empty());
    match (mode, xdg, home) {
        (Mode::Http, _, _) => "/etc/ssh-mcp-rs/config.toml".into(),
        (Mode::Stdio, Some(x), _) => format!("{x}/ssh-mcp-rs/config.toml"),
        (Mode::Stdio, None, Some(h)) => format!("{h}/.config/ssh-mcp-rs/config.toml"),
        (Mode::Stdio, None, None) => "/etc/ssh-mcp-rs/config.toml".into(),
    }
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

    let (mode, path) = match parse_args(std::env::args().skip(1)) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let path = path.or_else(|| std::env::var("SSH_MCP_CONFIG").ok()).unwrap_or_else(|| default_config(mode));
    let cfg = Arc::new(Config::load(path.as_ref(), mode)?);
    let pool = Arc::new(Pool::new(cfg.clone())?);
    let runs = Runs::new(pool.clone(), cfg.clone());
    runs.spawn_reaper();

    let app = Arc::new(AppState {
        cfg: cfg.clone(),
        pool,
        runs,
        started: Instant::now(),
    });

    if mode == Mode::Stdio {
        return stdio::serve(app).await;
    }

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An AppState with a throwaway client key and no reachable hosts, for
    /// protocol tests that never open an SSH connection.
    pub(crate) fn test_app() -> Arc<AppState> {
        use russh::keys::ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ssh-mcp-rs-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let key_file = dir.join("id_ed25519");
        std::fs::write(&key_file, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        let cfg: Config = toml::from_str(&format!(
            "key_file = {:?}\nlearned_hosts_file = {:?}\n[hosts.box]\naddress = \"192.0.2.1\"\n",
            key_file,
            dir.join("learned")
        ))
        .unwrap();
        let cfg = Arc::new(cfg);
        let pool = Arc::new(Pool::new(cfg.clone()).unwrap());
        let runs = Runs::new(pool.clone(), cfg.clone());
        Arc::new(AppState { cfg, pool, runs, started: Instant::now() })
    }

    fn args(v: &[&str]) -> Result<(Mode, Option<String>), String> {
        parse_args(v.iter().map(|s| s.to_string()))
    }

    #[test]
    fn cli_args() {
        assert_eq!(args(&[]), Ok((Mode::Http, None)));
        assert_eq!(args(&["c.toml"]), Ok((Mode::Http, Some("c.toml".into()))));
        assert_eq!(args(&["--stdio"]), Ok((Mode::Stdio, None)));
        assert_eq!(args(&["--stdio", "c.toml"]), Ok((Mode::Stdio, Some("c.toml".into()))));
        assert_eq!(args(&["c.toml", "--stdio"]), Ok((Mode::Stdio, Some("c.toml".into()))));
        assert!(args(&["--stdo"]).is_err());
        assert!(args(&["a", "b"]).is_err());
    }
}
