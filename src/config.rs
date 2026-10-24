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
            max_wait_secs: 300,
            default_timeout_secs: 0,
            retained_output_bytes: 8 * 1024 * 1024,
            inline_output_bytes: 48 * 1024,
            retain_finished_secs: 24 * 3600,
            max_finished_runs: 1000,
            max_body_bytes: 32 * 1024 * 1024,
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
            cfg.auth_token = Some(t.trim().to_string());
        }
        if let Ok(l) = std::env::var("SSH_MCP_LISTEN") {
            cfg.listen = l;
        }
        if cfg.auth_token.as_deref() == Some("") {
            cfg.auth_token = None;
        }
        let l = &cfg.limits;
        if l.channels_per_conn == 0 || l.max_conns_per_host == 0 || l.max_concurrent_runs == 0 {
            bail!("limits must be non-zero");
        }
        Ok(cfg)
    }
}
