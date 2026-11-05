//! Pooled, multiplexed SSH connections (russh, fully async).
//!
//! One TCP+SSH connection per (user, host) carries up to `channels_per_conn`
//! concurrent exec channels; more connections are opened on demand up to
//! `max_conns_per_host`. Callers beyond that queue on a per-host semaphore.

use crate::config::{Config, HostKeyPolicy};
use anyhow::{Context, Result, anyhow, bail};
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, client};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct Target {
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub user: String,
}

impl Target {
    pub fn key(&self) -> String {
        format!("{}@{}:{}", self.user, self.address, self.port)
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
            let entries = russh::keys::known_hosts::known_host_keys_path(host, port, f).map_err(|e| {
                format!("cannot read known_hosts {} ({e}); refusing to connect to {host}:{port}", f.display())
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

pub struct Conn {
    pub id: u64,
    handle: client::Handle<Handler>,
    chans: Arc<Semaphore>,
    dead: AtomicBool,
    pub created: Instant,
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
    key: Arc<PrivateKey>,
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
        let key = russh::keys::load_secret_key(&cfg.key_file, None)
            .with_context(|| format!("loading private key {}", cfg.key_file.display()))?;
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
            key: Arc::new(key),
            ssh_cfg: Arc::new(ssh_cfg),
            cfg,
            hosts: Default::default(),
            next_id: AtomicU64::new(1),
        })
    }

    /// Map a user-supplied hostname (alias, address, or anything) to a target.
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
        let user_override = username.map(str::trim).filter(|u| !u.is_empty());
        match found {
            Some((alias, hc)) => Ok(Target {
                alias: alias.clone(),
                address: hc.address.clone(),
                port: hc.port.unwrap_or(self.cfg.default_port),
                user: user_override
                    .map(String::from)
                    .or_else(|| hc.user.clone())
                    .unwrap_or_else(|| self.cfg.default_user.clone()),
            }),
            None if self.cfg.allow_unlisted_hosts => {
                let (addr, port) = match h.rsplit_once(':') {
                    Some((a, p)) if !a.contains(':') && p.parse::<u16>().is_ok() => {
                        (a.to_string(), p.parse().unwrap())
                    }
                    _ => (h.to_string(), self.cfg.default_port),
                };
                Ok(Target {
                    alias: h.to_string(),
                    address: addr,
                    port,
                    user: user_override
                        .map(String::from)
                        .unwrap_or_else(|| self.cfg.default_user.clone()),
                })
            }
            None => {
                let known: Vec<&str> = self.cfg.hosts.keys().map(String::as_str).collect();
                bail!("unknown host '{h}'. Configured hosts: {}", known.join(", "))
            }
        }
    }

    /// `control` pools are separate so kill/info helpers never queue behind
    /// a host whose channel slots are all held by long-running commands.
    fn host_pool(&self, t: &Target, control: bool) -> Arc<HostPool> {
        let mut m = self.hosts.lock().unwrap();
        let key = if control { format!("ctl|{}", t.key()) } else { t.key() };
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
            host: t.address.clone(),
            port: t.port,
            kc: self.kc.clone(),
        };
        let timeout = Duration::from_secs(self.cfg.limits.connect_timeout_secs);
        let fut = async {
            let mut handle =
                client::connect(self.ssh_cfg.clone(), (t.address.as_str(), t.port), handler)
                    .await
                    .map_err(|e| anyhow!("connect {}:{}: {e}", t.address, t.port))?;
            let hash = handle.best_supported_rsa_hash().await?.flatten();
            let auth = handle
                .authenticate_publickey(
                    t.user.clone(),
                    PrivateKeyWithHashAlg::new(self.key.clone(), hash),
                )
                .await?;
            if !auth.success() {
                bail!(
                    "public-key authentication failed for {}@{} (is the key in authorized_keys?)",
                    t.user,
                    t.alias
                );
            }
            Ok::<_, anyhow::Error>(handle)
        };
        let handle = tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| anyhow!("timed out connecting to {} after {timeout:?}", t.alias))??;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        info!(conn = id, target = %t.key(), "ssh connection established");
        Ok(Arc::new(Conn {
            id,
            handle,
            chans: Arc::new(Semaphore::new(self.cfg.limits.channels_per_conn)),
            dead: AtomicBool::new(false),
            created: Instant::now(),
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
                        warn!(conn = lease.conn.id, attempt, "channel open failed on closed connection: {e}");
                        lease.conn.dead.store(true, Ordering::Relaxed);
                    } else {
                        // Live connection refused the channel — typically sshd MaxSessions
                        // momentarily exceeded while closed channels are still being torn down.
                        warn!(conn = lease.conn.id, attempt, "channel open refused (sshd MaxSessions?): {e}");
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
