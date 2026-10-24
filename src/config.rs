//! Configuration (TOML file + a couple of env overrides).

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyPolicy {
    /// Only connect to hosts whose key is already in a known_hosts file.
    Strict,
    /// Trust-on-first-use: unknown hosts are learned into `learned_hosts_file`;
    /// a *changed* key is always refused.
    AcceptNew,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCfg {
    pub address: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Max commands executing at once across all hosts (others queue).
    pub max_concurrent_runs: usize,
    /// SSH channels multiplexed per TCP connection. sshd MaxSessions defaults to 10;
    /// keep headroom because server-side teardown lags the client.
    pub channels_per_conn: usize,
    /// Max pooled SSH connections per (user, host).
    pub max_conns_per_host: usize,
    pub connect_timeout_secs: u64,
    pub keepalive_secs: u64,
    /// How long a synchronous call waits before handing back a run id.
    pub default_wait_secs: u64,
    pub max_wait_secs: u64,
    /// Hard kill after this many seconds (0 = never). Per-call override allowed.
    pub default_timeout_secs: u64,
    /// Bytes of stdout / stderr retained per run (oldest bytes dropped beyond this).
    pub retained_output_bytes: usize,
    /// Bytes of each stream returned inline in a tool result (head+tail beyond this).
    pub inline_output_bytes: usize,
    pub retain_finished_secs: u64,
    pub max_finished_runs: usize,
    /// Total stdout+stderr bytes kept across finished runs; oldest are evicted beyond this.
    pub retained_budget_bytes: usize,
    /// Queued + running runs allowed at once; new runs are refused beyond this.
    pub max_pending_runs: usize,
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrent_runs: 256,
            channels_per_conn: 6,
            max_conns_per_host: 6,
            connect_timeout_secs: 15,
            keepalive_secs: 20,
            default_wait_secs: 90,
            // claude.ai's connector gives up on a tool call at ~230s; stay well under it.
            max_wait_secs: 180,
            default_timeout_secs: 0,
            retained_output_bytes: 8 * 1024 * 1024,
            inline_output_bytes: 48 * 1024,
            retain_finished_secs: 24 * 3600,
            max_finished_runs: 1000,
            retained_budget_bytes: 512 * 1024 * 1024,
            max_pending_runs: 1024,
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "d_listen")]
    pub listen: String,
    /// Optional static bearer token. Also settable via SSH_MCP_TOKEN / SSH_MCP_TOKEN_FILE.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Also accept the secret as `?key=` in the URL (for clients without custom headers).
    #[serde(default)]
    pub allow_query_token: bool,
    /// Permit running with no auth_token on a non-loopback address. Off by default:
    /// the server refuses to start rather than silently serving unauthenticated.
    #[serde(default)]
    pub allow_unauthenticated: bool,
    /// Origins accepted when a browser-style Origin header is present.
    #[serde(default = "d_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "d_user")]
    pub default_user: String,
    #[serde(default = "d_port")]
    pub default_port: u16,
    pub key_file: PathBuf,
    /// Read-only known_hosts files to trust (e.g. ~/.ssh/known_hosts).
    #[serde(default)]
    pub known_hosts_files: Vec<PathBuf>,
    /// Writable file where accept-new learns keys.
    pub learned_hosts_file: PathBuf,
    #[serde(default = "d_policy")]
    pub host_key_policy: HostKeyPolicy,
    /// Allow hostnames that are not listed under [hosts].
    #[serde(default = "d_true")]
    pub allow_unlisted_hosts: bool,
    /// Parity with the old Python server's regex gate (confirm=true required).
    #[serde(default)]
    pub require_confirm_for_destructive: bool,
    #[serde(default)]
    pub hosts: BTreeMap<String, HostCfg>,
    #[serde(default)]
    pub limits: Limits,
}

fn d_listen() -> String {
    "127.0.0.1:8011".into()
}
fn d_origins() -> Vec<String> {
    vec!["https://claude.ai".into(), "https://claude.com".into()]
}
fn d_user() -> String {
    "root".into()
}
fn d_port() -> u16 {
    22
}
fn d_policy() -> HostKeyPolicy {
    HostKeyPolicy::AcceptNew
}
fn d_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if let Ok(t) = std::env::var("SSH_MCP_TOKEN")
            && !t.trim().is_empty() {
                cfg.auth_token = Some(t.trim().to_string());
            }
        if let Ok(p) = std::env::var("SSH_MCP_TOKEN_FILE") {
            let t = std::fs::read_to_string(&p).with_context(|| format!("reading {p}"))?;
            if t.trim().is_empty() {
                bail!("SSH_MCP_TOKEN_FILE {p} is empty — refusing to start without the shared secret");
            }
            cfg.auth_token = Some(t.trim().to_string());
        }
        if let Ok(l) = std::env::var("SSH_MCP_LISTEN") {
            cfg.listen = l;
        }
        if cfg.auth_token.as_deref() == Some("") {
            cfg.auth_token = None;
        }
        if let Some(t) = &cfg.auth_token {
            if t.len() < 32 {
                bail!("auth_token is only {} characters; use at least 32 (e.g. `openssl rand -hex 32`)", t.len());
            }
        }
        let loopback = cfg
            .listen
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        if cfg.auth_token.is_none() && !loopback && !cfg.allow_unauthenticated {
            bail!(
                "no auth_token configured and listen address {} is not loopback — refusing to start \
                 (set SSH_MCP_TOKEN_FILE, or allow_unauthenticated = true if you really mean it)",
                cfg.listen
            );
        }
        for f in &cfg.known_hosts_files {
            std::fs::File::open(f)
                .with_context(|| format!("known_hosts file {} is missing or unreadable", f.display()))?;
        }
        let l = &cfg.limits;
        if l.channels_per_conn == 0 || l.max_conns_per_host == 0 || l.max_concurrent_runs == 0 || l.max_pending_runs == 0 {
            bail!("limits must be non-zero");
        }
        // File tools read whole files (edit_file up to 4 MiB, images up to 5 MiB)
        // through the run output buffer, which drops oldest bytes beyond this.
        if l.retained_output_bytes < 6 * 1024 * 1024 {
            bail!("limits.retained_output_bytes must be at least 6 MiB (file tools read whole files through it)");
        }
        if l.retained_output_bytes < l.inline_output_bytes {
            bail!("limits.retained_output_bytes must be >= limits.inline_output_bytes");
        }
        if l.max_wait_secs > 220 {
            bail!("limits.max_wait_secs must be <= 220 (claude.ai times out tool calls at ~230s)");
        }
        Ok(cfg)
    }
}
