//! Pooled, multiplexed SSH connections (russh, fully async).
//!
//! One TCP+SSH connection per (user, host) carries up to `channels_per_conn`
//! concurrent exec channels; more connections are opened on demand up to
//! `max_conns_per_host`. Callers beyond that queue on a per-host semaphore.

use crate::config::{AuthMethod, Config, HostKeyPolicy};
use crate::proxy::{ProxyChild, ProxySpec};
use crate::sshauth::{KeyCache, KeyFile};
use crate::sshconfig::{Resolved, SshConfig, Tokens};
use anyhow::{Context, Result, anyhow, bail};
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, client};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

/// sshd's default `MaxAuthTries` is 6; stay under it so a server that has
/// already refused several keys doesn't disconnect us before the last one.
pub const MAX_AUTH_ATTEMPTS: usize = 5;

#[derive(Clone, Debug, Default)]
pub struct Target {
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub user: String,
    /// Name to look host keys up under (ssh_config `HostKeyAlias`); else `address`.
    pub host_key_alias: Option<String>,
    /// Per-host identity files (ssh_config `IdentityFile`), tried before `key_file`.
    pub identity_files: Vec<PathBuf>,
    /// Per-host certificates (ssh_config `CertificateFile`).
    pub cert_files: Vec<PathBuf>,
    /// ssh_config `IdentitiesOnly`: offer only agent keys matching the identity files.
    pub identities_only: bool,
    /// Reach the host through this local command instead of a TCP connect.
    pub proxy: Option<ProxySpec>,
    /// Per-host / per-rule override of `limits.connect_timeout_secs`.
    pub connect_timeout_secs: Option<u64>,
}

impl Target {
    /// Pool key: connections are shared only between identical targets, so
    /// the same address with and without a proxy never shares one.
    pub fn key(&self) -> String {
        let mut k = format!("{}@{}:{}", self.user, self.address, self.port);
        if let Some(a) = &self.host_key_alias {
            k.push_str(&format!("#{a}"));
        }
        if let Some(p) = &self.proxy {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (&p.template, p.shell).hash(&mut h);
            k.push_str(&format!(
                " via {}#{:06x}",
                p.program(),
                h.finish() & 0xff_ffff
            ));
        }
        k
    }

    /// "direct", or "proxy: <program> (<source>)", for list_hosts and test_ssh_connection.
    pub fn transport(&self) -> String {
        match &self.proxy {
            None => "direct".into(),
            Some(p) => format!("proxy: {} ({})", p.program(), p.source),
        }
    }

    /// The name host keys are checked (and learned) under.
    pub fn host_key_name(&self) -> &str {
        self.host_key_alias.as_deref().unwrap_or(&self.address)
    }

    /// The port host keys are recorded with. As in OpenSSH, a `HostKeyAlias`
    /// is looked up bare (no `[name]:port` form), whatever the real port.
    pub fn host_key_port(&self) -> u16 {
        if self.host_key_alias.is_some() {
            22
        } else {
            self.port
        }
    }
}

// ---------------------------------------------------------------- host keys

#[derive(Debug)]
pub enum HandlerError {
    Ssh(russh::Error),
    HostKey(String),
}
impl From<russh::Error> for HandlerError {
    fn from(e: russh::Error) -> Self {
        HandlerError::Ssh(e)
    }
}
impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Ssh(e) => write!(f, "{e}"),
            HandlerError::HostKey(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for HandlerError {}

struct KeyCheck {
    files: Vec<PathBuf>,
    learned: PathBuf,
    policy: HostKeyPolicy,
}

static LEARN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl KeyCheck {
    /// Fail closed: a key is accepted only if it exactly matches a recorded key
    /// for this host. A host with ANY recorded key (of any type) that doesn't
    /// match is refused — russh reports a different-type key as "unknown", not
    /// "changed", so without this an attacker could present e.g. an RSA key to
    /// a host we only know by its ed25519 key and have it learned (downgrade).
    /// Unparseable known_hosts files also refuse rather than fall back to TOFU.
    fn verify(&self, host: &str, port: u16, key: &PublicKey) -> std::result::Result<(), String> {
        let fp = key.fingerprint(HashAlg::Sha256).to_string();
        let mut files: Vec<&PathBuf> = self.files.iter().collect();
        if self.learned.exists() {
            files.push(&self.learned);
        }
        let mut recorded_types: Vec<String> = Vec::new();
        for f in files {
            let entries =
                russh::keys::known_hosts::known_host_keys_path(host, port, f).map_err(|e| {
                    format!(
                        "cannot read known_hosts {} ({e}); refusing to connect to {host}:{port}",
                        f.display()
                    )
                })?;
            for (line, recorded) in entries {
                if recorded == *key {
                    return Ok(());
                }
                if recorded.algorithm() == key.algorithm() {
                    return Err(format!(
                        "HOST KEY MISMATCH for {host}:{port} — server presented {fp}, which differs \
                         from {} line {line}. Refusing to connect.",
                        f.display()
                    ));
                }
                recorded_types.push(format!("{} ({}:{line})", recorded.algorithm(), f.display()));
            }
        }
        if !recorded_types.is_empty() {
            return Err(format!(
                "host {host}:{port} presented a {} key ({fp}) but only other key types are recorded: {}. \
                 Refusing (possible downgrade/MITM). If the host really changed keys, add the new key to known_hosts.",
                key.algorithm(),
                recorded_types.join(", ")
            ));
        }
        match self.policy {
            HostKeyPolicy::Strict => Err(format!(
                "unknown host key for {host}:{port} ({fp}) and host_key_policy is strict. Nothing was \
                 run. Add the host's key to a known_hosts file listed in known_hosts_files (e.g. connect \
                 once with `ssh`, or `ssh-keyscan -p {port} {host}` after checking the fingerprint), or set \
                 host_key_policy = \"accept-new\" to trust it on first use"
            )),
            HostKeyPolicy::AcceptNew => {
                let _g = LEARN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
                // Re-check under the lock so concurrent first connects don't duplicate lines.
                if self.learned.exists()
                    && matches!(
                        russh::keys::check_known_hosts_path(host, port, key, &self.learned),
                        Ok(true)
                    )
                {
                    return Ok(());
                }
                learn_known_hosts_path(host, port, key, &self.learned)
                    .map_err(|e| format!("could not record host key: {e}"))?;
                warn!(%host, port, %fp, "learned new host key (accept-new)");
                Ok(())
            }
        }
    }
}

pub struct Handler {
    host: String,
    port: u16,
    kc: Arc<KeyCheck>,
}

impl client::Handler for Handler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let key = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => {
                return Err(HandlerError::HostKey(
                    "host certificates are not supported".into(),
                ));
            }
        };
        self.kc
            .verify(&self.host, self.port, key)
            .map(|_| true)
            .map_err(HandlerError::HostKey)
    }
}

// ---------------------------------------------------------------- pool

/// Hostnames and usernames come from the caller and can end up in ssh_config
/// `%h`/`%r` tokens (e.g. an `IdentityFile` path) and in error messages, so
/// refuse anything that could act as a path, a token or an option.
fn check_name(what: &str, v: &str) -> Result<()> {
    if v.starts_with('-')
        || v.chars()
            .any(|c| c == '/' || c == '%' || c.is_control() || c.is_whitespace())
    {
        bail!(
            "invalid {what} {v:?}: it may not start with '-' or contain '/', '%', spaces or control characters"
        );
    }
    Ok(())
}

/// Certificates configured for the global key_file: `cert_file` if set
/// (`<key_file>-cert.pub` is always looked for too).
fn global_certs(cfg: &Config) -> Vec<PathBuf> {
    cfg.cert_file.iter().cloned().collect()
}

pub struct Conn {
    pub id: u64,
    handle: client::Handle<Handler>,
    chans: Arc<Semaphore>,
    dead: AtomicBool,
    pub created: Instant,
    /// How this connection authenticated (fingerprints, no key material).
    pub auth: String,
    /// The proxy process carrying this connection; dropped (killed) with it.
    _proxy: Option<std::sync::Mutex<ProxyChild>>,
}

impl Conn {
    fn usable(&self) -> bool {
        !self.dead.load(Ordering::Relaxed) && !self.handle.is_closed()
    }
}

struct HostPool {
    permits: Arc<Semaphore>,
    conns: Mutex<Vec<Arc<Conn>>>,
}

pub struct Lease {
    pub conn: Arc<Conn>,
    pub reused: bool,
    _host: OwnedSemaphorePermit,
    _chan: OwnedSemaphorePermit,
}

pub struct Pool {
    cfg: Arc<Config>,
    keys: KeyCache,
    ssh_config: Option<SshConfig>,
    home: String,
    local_user: String,
    kc: Arc<KeyCheck>,
    ssh_cfg: Arc<client::Config>,
    hosts: std::sync::Mutex<HashMap<String, Arc<HostPool>>>,
    next_id: AtomicU64,
}

pub struct HostStat {
    pub key: String,
    pub conns: usize,
    pub in_use: usize,
}

impl Pool {
    pub fn new(cfg: Arc<Config>) -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_default();
        let local_user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        let keys = KeyCache::default();
        let methods = cfg.auth_methods();
        // Fail fast on a configured key_file that can't be used directly,
        // unless the agent (which may hold it) is also an auth method.
        if methods.contains(&AuthMethod::KeyFile)
            && let Some(k) = &cfg.key_file
            && let KeyFile::Unusable { reason, .. } = keys.get(k, &global_certs(&cfg))
        {
            if methods.contains(&AuthMethod::Agent) {
                warn!(
                    "key_file {}: {reason}; relying on ssh-agent for it",
                    k.display()
                );
            } else {
                bail!("key_file {}: {reason}", k.display());
            }
        }
        if methods.contains(&AuthMethod::Agent) && std::env::var_os("SSH_AUTH_SOCK").is_none() {
            warn!(
                "auth includes \"agent\" but SSH_AUTH_SOCK is not set; agent auth will be skipped"
            );
        }
        let ssh_config =
            match cfg.ssh_config_path(Some(&home).filter(|h| !h.is_empty()).map(String::as_str)) {
                Some(p) => {
                    let c = SshConfig::load(&p, &home)?;
                    info!(file = %p.display(), hosts = c.named_hosts().len(), "loaded ssh config");
                    Some(c)
                }
                None => None,
            };
        info!(auth = ?methods, "ssh client auth");
        let ssh_cfg = client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(cfg.limits.keepalive_secs.max(5))),
            keepalive_max: 3,
            ..Default::default()
        };
        Ok(Self {
            kc: Arc::new(KeyCheck {
                files: cfg.known_hosts_files.clone(),
                learned: cfg.learned_hosts_file.clone(),
                policy: cfg.host_key_policy,
            }),
            keys,
            ssh_config,
            home,
            local_user,
            ssh_cfg: Arc::new(ssh_cfg),
            cfg,
            hosts: Default::default(),
            next_id: AtomicU64::new(1),
        })
    }

    /// Map a user-supplied hostname (alias, address, or anything) to a target.
    /// Explicit `[hosts.*]` entries win; ssh_config (if enabled) fills in what
    /// they leave unset, and describes hosts that aren't listed.
    pub fn resolve(&self, hostname: &str, username: Option<&str>) -> Result<Target> {
        let h = hostname.trim();
        if h.is_empty() {
            bail!("hostname is required");
        }
        let found = self
            .cfg
            .hosts
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(h))
            .or_else(|| self.cfg.hosts.iter().find(|(_, v)| v.address == h));
        check_name("hostname", h)?;
        let user_override = username
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(String::from);
        if let Some(u) = &user_override {
            check_name("username", u)?;
        }
        let sc = |name: &str| -> Result<Resolved> {
            match &self.ssh_config {
                Some(c) => c
                    .resolve(
                        name,
                        &Tokens {
                            home: &self.home,
                            local_user: &self.local_user,
                        },
                    )
                    .with_context(|| format!("in {}", c.source.display())),
                None => Ok(Resolved::default()),
            }
        };
        // Proxy precedence: [hosts] proxy_command, then proxy_rules (unlisted
        // names only), then ssh_config ProxyCommand / ProxyJump.
        let mut proxy: Option<ProxySpec> = None;
        let mut timeout: Option<u64> = None;
        let (alias, address, port, user, r) = match found {
            Some((alias, hc)) => {
                let r = sc(alias)?;
                if let Some(t) = &hc.proxy_command {
                    proxy = Some(ProxySpec {
                        template: t.clone(),
                        shell: hc.proxy_shell,
                        source: format!("hosts.{alias}"),
                    });
                }
                timeout = hc.connect_timeout_secs;
                (
                    alias.clone(),
                    hc.address.clone(),
                    hc.port.or(r.port),
                    hc.user.clone().or(r.user.clone()),
                    r,
                )
            }
            None => {
                let (name, explicit_port) = match h.rsplit_once(':') {
                    Some((a, p)) if !a.contains(':') && p.parse::<u16>().is_ok() => {
                        (a, p.parse().ok())
                    }
                    _ => (h, None),
                };
                let r = sc(name)?;
                if let Some((i, rule)) = self.rule_for(name) {
                    proxy = Some(ProxySpec {
                        template: rule.proxy_command.clone(),
                        shell: rule.proxy_shell,
                        source: format!("proxy_rules[{i}]"),
                    });
                    timeout = rule.connect_timeout_secs;
                }
                // A proxy rule is an explicit opt-in for the names it matches.
                if !self.cfg.allow_unlisted_hosts && !r.named && proxy.is_none() {
                    let mut known: Vec<String> = self.cfg.hosts.keys().cloned().collect();
                    if let Some(c) = &self.ssh_config {
                        known.extend(c.named_hosts());
                    }
                    bail!("unknown host '{h}'. Configured hosts: {}", known.join(", "));
                }
                let address = r.hostname.clone().unwrap_or_else(|| name.to_string());
                (
                    h.to_string(),
                    address,
                    explicit_port.or(r.port),
                    r.user.clone(),
                    r,
                )
            }
        };
        let mut t = Target {
            alias,
            address,
            port: port.unwrap_or(self.cfg.default_port),
            user: user_override
                .or(user)
                .unwrap_or_else(|| self.cfg.default_user.clone()),
            host_key_alias: r.host_key_alias,
            identity_files: r.identity_files,
            cert_files: r.certificate_files,
            identities_only: r.identities_only,
            proxy: match (proxy, &r.proxy) {
                (Some(p), _) => Some(p),
                (None, Some((kind, value))) if kind == "ProxyJump" => {
                    Some(crate::proxy::jump_spec(value, "ssh_config ProxyJump")?)
                }
                (None, Some((_, value))) => Some(ProxySpec {
                    // OpenSSH runs ProxyCommand through a shell; so do we,
                    // with the substituted values quoted.
                    template: value.clone(),
                    shell: true,
                    source: "ssh_config ProxyCommand".into(),
                }),
                (None, None) => None,
            },
            connect_timeout_secs: timeout,
        };
        // As in OpenSSH, identity files are skipped silently when neither the
        // key nor its `.pub` exists (the `.pub` alone still selects agent keys).
        t.identity_files.retain(|p| {
            let mut pubp = p.as_os_str().to_owned();
            pubp.push(".pub");
            p.exists() || std::path::Path::new(&pubp).exists()
        });
        Ok(t)
    }

    /// The first proxy rule whose regex matches `name`.
    fn rule_for(&self, name: &str) -> Option<(usize, &crate::config::ProxyRule)> {
        self.cfg.proxy_rules.iter().enumerate().find(|(_, r)| {
            // Validated at startup; a failure here can't happen, so treat it as no match.
            regex::Regex::new(&r.pattern).is_ok_and(|re| re.is_match(name))
        })
    }

    /// Drop every pooled connection now (which stops their proxy processes).
    pub fn close_all(&self) {
        self.hosts.lock().unwrap().clear();
    }

    /// Hosts named in ssh_config (for list_hosts), excluding ones also in `[hosts]`.
    pub fn ssh_config_hosts(&self) -> Vec<String> {
        let Some(c) = &self.ssh_config else {
            return vec![];
        };
        c.named_hosts()
            .into_iter()
            .filter(|n| !self.cfg.hosts.keys().any(|k| k.eq_ignore_ascii_case(n)))
            .collect()
    }

    /// Key files to try for `t`, each with the certificates that may belong to it.
    fn key_files(&self, t: &Target) -> Vec<(PathBuf, Vec<PathBuf>)> {
        let mut v: Vec<(PathBuf, Vec<PathBuf>)> = t
            .identity_files
            .iter()
            .map(|p| (p.clone(), t.cert_files.clone()))
            .collect();
        if let Some(k) = &self.cfg.key_file
            && !v.iter().any(|(p, _)| p == k)
        {
            let mut c = t.cert_files.clone();
            c.extend(global_certs(&self.cfg));
            v.push((k.clone(), c));
        }
        v
    }

    /// `control` pools are separate so kill/info helpers never queue behind
    /// a host whose channel slots are all held by long-running commands.
    fn host_pool(&self, t: &Target, control: bool) -> Arc<HostPool> {
        let mut m = self.hosts.lock().unwrap();
        let key = if control {
            format!("ctl|{}", t.key())
        } else {
            t.key()
        };
        m.entry(key)
            .or_insert_with(|| {
                let l = &self.cfg.limits;
                Arc::new(HostPool {
                    permits: Arc::new(Semaphore::new(l.channels_per_conn * l.max_conns_per_host)),
                    conns: Mutex::new(Vec::new()),
                })
            })
            .clone()
    }

    async fn connect(&self, t: &Target) -> Result<Arc<Conn>> {
        let handler = Handler {
            host: t.host_key_name().to_string(),
            port: t.host_key_port(),
            kc: self.kc.clone(),
        };
        let timeout = Duration::from_secs(
            t.connect_timeout_secs
                .unwrap_or(self.cfg.limits.connect_timeout_secs),
        );
        let mut proxy_child: Option<ProxyChild> = None;
        let fut = async {
            let mut handle = match &t.proxy {
                None => {
                    client::connect(self.ssh_cfg.clone(), (t.address.as_str(), t.port), handler)
                        .await
                        .map_err(|e| anyhow!("connect {}:{}: {e}", t.address, t.port))?
                }
                Some(spec) => {
                    let argv = crate::proxy::build_argv(spec, &t.address, t.port, &t.user)
                        .with_context(|| format!("{} proxy_command", spec.source))?;
                    let (stream, child) = crate::proxy::spawn(&argv)?;
                    proxy_child = Some(child);
                    client::connect_stream(self.ssh_cfg.clone(), stream, handler)
                        .await
                        .map_err(|e| {
                            anyhow!("SSH handshake through {} failed: {e}", t.transport())
                        })?
                }
            };
            let how = crate::sshauth::authenticate(
                &mut handle,
                t,
                &self.cfg.auth_methods(),
                &self.key_files(t),
                &self.keys,
            )
            .await
            .map_err(|e| anyhow!(e))?;
            Ok::<_, anyhow::Error>((handle, how))
        };
        let res = tokio::time::timeout(timeout, fut).await;
        let (handle, how) = match res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return Err(match proxy_child.as_mut() {
                    Some(c) => e.context(c.diagnose().await),
                    None => e,
                });
            }
            Err(_) => {
                let mut msg = format!("timed out connecting to {} after {timeout:?}", t.alias);
                if let Some(c) = proxy_child.as_mut() {
                    msg.push_str(&format!(
                        " ({}; raise connect_timeout_secs for slow proxies)",
                        c.diagnose().await
                    ));
                }
                bail!(msg);
            }
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        info!(conn = id, target = %t.key(), auth = %how, "ssh connection established");
        Ok(Arc::new(Conn {
            id,
            handle,
            chans: Arc::new(Semaphore::new(self.cfg.limits.channels_per_conn)),
            dead: AtomicBool::new(false),
            created: Instant::now(),
            auth: how,
            _proxy: proxy_child.map(std::sync::Mutex::new),
        }))
    }

    async fn lease(&self, t: &Target, control: bool) -> Result<Lease> {
        let hp = self.host_pool(t, control);
        let host_permit = hp.permits.clone().acquire_owned().await?;
        let mut conns = hp.conns.lock().await;
        conns.retain(|c| c.usable());
        for c in conns.iter() {
            if let Ok(p) = c.chans.clone().try_acquire_owned() {
                return Ok(Lease {
                    conn: c.clone(),
                    reused: true,
                    _host: host_permit,
                    _chan: p,
                });
            }
        }
        let c = self.connect(t).await?;
        let p = c.chans.clone().try_acquire_owned()?;
        conns.push(c.clone());
        Ok(Lease {
            conn: c,
            reused: false,
            _host: host_permit,
            _chan: p,
        })
    }

    /// Open a session channel; retries once on a fresh connection if the
    /// pooled one turned out to be stale.
    pub async fn open_channel(
        &self,
        t: &Target,
        control: bool,
    ) -> Result<(Lease, russh::Channel<client::Msg>)> {
        let mut last_err = None;
        for attempt in 0..4u64 {
            let lease = self.lease(t, control).await?;
            match lease.conn.handle.channel_open_session().await {
                Ok(ch) => return Ok((lease, ch)),
                Err(e) => {
                    if lease.conn.handle.is_closed() {
                        // Stale connection: drop it from the pool and retry on a fresh one.
                        warn!(
                            conn = lease.conn.id,
                            attempt, "channel open failed on closed connection: {e}"
                        );
                        lease.conn.dead.store(true, Ordering::Relaxed);
                    } else {
                        // Live connection refused the channel — typically sshd MaxSessions
                        // momentarily exceeded while closed channels are still being torn down.
                        warn!(
                            conn = lease.conn.id,
                            attempt, "channel open refused (sshd MaxSessions?): {e}"
                        );
                        drop(lease);
                        tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(anyhow!(
            "could not open SSH channel to {}: {}",
            t.alias,
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// Run a short command to completion and collect its output (used for
    /// kill helpers, server info, connection tests).
    pub async fn exec_collect(
        &self,
        t: &Target,
        cmd: &str,
        timeout: Duration,
        control: bool,
    ) -> Result<(Option<u32>, String, String)> {
        let fut = async {
            let (_lease, mut ch) = self.open_channel(t, control).await?;
            ch.exec(true, cmd).await?;
            ch.eof().await?;
            let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
            while let Some(m) = ch.wait().await {
                match m {
                    ChannelMsg::Data { data } => out.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => err.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok::<_, anyhow::Error>((
                code,
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            ))
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| anyhow!("timed out after {timeout:?}"))?
    }

    /// How the pooled connection(s) to `t` authenticated, if any are open.
    pub fn auth_used(&self, t: &Target) -> Option<String> {
        let hp = self.hosts.lock().unwrap().get(&t.key()).cloned()?;
        let conns = hp.conns.try_lock().ok()?;
        conns
            .iter()
            .rev()
            .find(|c| c.usable())
            .map(|c| c.auth.clone())
    }

    pub fn stats(&self) -> Vec<HostStat> {
        let pools: Vec<(String, Arc<HostPool>)> = self
            .hosts
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let l = &self.cfg.limits;
        let total = l.channels_per_conn * l.max_conns_per_host;
        pools
            .into_iter()
            .map(|(key, hp)| HostStat {
                key,
                conns: hp
                    .conns
                    .try_lock()
                    .map(|c| c.iter().filter(|c| c.usable()).count())
                    .unwrap_or(0),
                in_use: total - hp.permits.available_permits(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_names_are_checked() {
        for ok in [
            "build",
            "10.0.0.5",
            "web-01.example.com",
            "fe80::1",
            "DOMAIN\\user",
            "user@realm",
        ] {
            assert!(check_name("x", ok).is_ok(), "{ok}");
        }
        for bad in [
            "../../etc/x",
            "a/b",
            "%d",
            "-oProxyCommand=x",
            "a b",
            "a\nb",
            "a\0b",
        ] {
            assert!(check_name("x", bad).is_err(), "{bad:?}");
        }
    }
}
