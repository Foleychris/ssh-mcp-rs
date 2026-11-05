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

/// What a stdio server does with still-active runs when its client goes away.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OnExit {
    /// Kill each run's remote process group, so nothing is orphaned.
    #[default]
    Cancel,
    /// Leave remote processes running (their output is lost with the server).
    Leave,
}

/// Which transport the server runs. Selects which startup checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Http,
    Stdio,
}

/// `max_wait_secs` ceiling. Over HTTP, claude.ai gives up on a tool call at
/// ~230s; a local stdio client has no such proxy in the way.
pub fn max_wait_cap(mode: Mode) -> u64 {
    match mode {
        Mode::Http => 220,
        Mode::Stdio => 600,
    }
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
    /// stdio mode only: what to do with active runs when the client exits.
    #[serde(default)]
    pub stdio_on_exit: OnExit,
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
/// The local login name, as OpenSSH defaults to. Empty if unknown (then
/// `load` asks for an explicit `default_user`).
fn d_user() -> String {
    ["USER", "LOGNAME"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty())
        .unwrap_or_default()
}
fn d_port() -> u16 {
    22
}
fn d_policy() -> HostKeyPolicy {
    HostKeyPolicy::Strict
}

/// Expand a leading `~` or `~/` with `home`. `~user` forms are left alone.
fn expand_tilde(p: &Path, home: Option<&str>) -> PathBuf {
    let Some(home) = home.filter(|h| !h.is_empty()) else {
        return p.to_path_buf();
    };
    match p.to_str() {
        Some("~") => PathBuf::from(home),
        Some(s) if s.starts_with("~/") => Path::new(home).join(&s[2..]),
        _ => p.to_path_buf(),
    }
}
fn d_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path, mode: Mode) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let home = std::env::var("HOME").ok();
        let ex = |p: &Path| expand_tilde(p, home.as_deref());
        cfg.key_file = ex(&cfg.key_file);
        cfg.learned_hosts_file = ex(&cfg.learned_hosts_file);
        cfg.known_hosts_files = cfg.known_hosts_files.iter().map(|p| ex(p)).collect();
        if cfg.default_user.trim().is_empty() {
            bail!(
                "default_user is not set and $USER is empty; set default_user in {}",
                path.display()
            );
        }
        match mode {
            Mode::Http => cfg.http_auth_checks()?,
            // No network listener: listen, the token and allowed_origins don't apply.
            Mode::Stdio => cfg.auth_token = None,
        }
        for f in &cfg.known_hosts_files {
            std::fs::File::open(f).with_context(|| {
                format!("known_hosts file {} is missing or unreadable", f.display())
            })?;
        }
        let l = &cfg.limits;
        if l.channels_per_conn == 0
            || l.max_conns_per_host == 0
            || l.max_concurrent_runs == 0
            || l.max_pending_runs == 0
        {
            bail!("limits must be non-zero");
        }
        // File tools read whole files (edit_file up to 4 MiB, images up to 5 MiB)
        // through the run output buffer, which drops oldest bytes beyond this.
        if l.retained_output_bytes < 6 * 1024 * 1024 {
            bail!(
                "limits.retained_output_bytes must be at least 6 MiB (file tools read whole files through it)"
            );
        }
        if l.retained_output_bytes < l.inline_output_bytes {
            bail!("limits.retained_output_bytes must be >= limits.inline_output_bytes");
        }
        let cap = max_wait_cap(mode);
        if l.max_wait_secs > cap {
            match mode {
                Mode::Http => bail!(
                    "limits.max_wait_secs must be <= {cap} (claude.ai times out tool calls at ~230s)"
                ),
                Mode::Stdio => bail!("limits.max_wait_secs must be <= {cap} in stdio mode"),
            }
        }
        Ok(cfg)
    }

    /// HTTP-mode token handling and startup refusals (env overrides, minimum
    /// token length, no token on a non-loopback address).
    fn http_auth_checks(&mut self) -> Result<()> {
        let cfg = self;
        if let Ok(t) = std::env::var("SSH_MCP_TOKEN")
            && !t.trim().is_empty()
        {
            cfg.auth_token = Some(t.trim().to_string());
        }
        if let Ok(p) = std::env::var("SSH_MCP_TOKEN_FILE") {
            let t = std::fs::read_to_string(&p).with_context(|| format!("reading {p}"))?;
            if t.trim().is_empty() {
                bail!(
                    "SSH_MCP_TOKEN_FILE {p} is empty — refusing to start without the shared secret"
                );
            }
            cfg.auth_token = Some(t.trim().to_string());
        }
        if let Ok(l) = std::env::var("SSH_MCP_LISTEN") {
            cfg.listen = l;
        }
        if cfg.auth_token.as_deref() == Some("") {
            cfg.auth_token = None;
        }
        if let Some(t) = &cfg.auth_token
            && t.len() < 32
        {
            bail!(
                "auth_token is only {} characters; use at least 32 (e.g. `openssl rand -hex 32`)",
                t.len()
            );
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion() {
        let h = Some("/home/me");
        let e = |p: &str| expand_tilde(Path::new(p), h);
        assert_eq!(e("~"), PathBuf::from("/home/me"));
        assert_eq!(
            e("~/.ssh/id_ed25519"),
            PathBuf::from("/home/me/.ssh/id_ed25519")
        );
        assert_eq!(e("/etc/x"), PathBuf::from("/etc/x"));
        assert_eq!(e("~other/x"), PathBuf::from("~other/x"));
        assert_eq!(e("a/~/b"), PathBuf::from("a/~/b"));
        assert_eq!(expand_tilde(Path::new("~/x"), None), PathBuf::from("~/x"));
        assert_eq!(
            expand_tilde(Path::new("~/x"), Some("")),
            PathBuf::from("~/x")
        );
    }

    #[test]
    fn safe_defaults() {
        assert_eq!(d_policy(), HostKeyPolicy::Strict);
        let cfg: Config =
            toml::from_str("default_user = \"u\"\nkey_file = \"k\"\nlearned_hosts_file = \"l\"\n")
                .unwrap();
        assert_eq!(cfg.host_key_policy, HostKeyPolicy::Strict);
        assert_eq!(cfg.stdio_on_exit, OnExit::Cancel);
        assert_eq!(cfg.listen, "127.0.0.1:8011");
        assert!(cfg.auth_token.is_none() && !cfg.allow_query_token && !cfg.allow_unauthenticated);
    }
}
