//! Client authentication: ssh-agent identities (keys and OpenSSH
//! certificates) and key files (with their certificates), tried in the order
//! `auth` lists, capped at [`MAX_AUTH_ATTEMPTS`] offers per connection.

use crate::config::AuthMethod;
use crate::ssh::{Handler, MAX_AUTH_ATTEMPTS, Target};
use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{Certificate, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::debug;

/// Test-only: skip `session-bind@openssh.com`, to show that
/// destination-constrained agent keys depend on it (tests/auth.rs).
const SKIP_SESSION_BIND_ENV: &str = "SSHMUX_TEST_SKIP_SESSION_BIND";

/// Bind this agent connection to the SSH session being authenticated
/// (`session-bind@openssh.com`, OpenSSH PROTOCOL.agent), as `ssh` does. Agents
/// that enforce destination constraints (`ssh-add -h`) hide or refuse to use a
/// constrained key on an unbound connection. Not fatal: agents without the
/// extension answer with a failure, and only the signature decides. Returns
/// whether the agent accepted it.
async fn bind_agent_session(
    agent: &mut AgentClient<tokio::net::UnixStream>,
    handle: &client::Handle<Handler>,
    t: &Target,
) -> bool {
    if std::env::var_os(SKIP_SESSION_BIND_ENV).is_some() {
        debug!(host = %t.alias, "session-bind skipped ({SKIP_SESSION_BIND_ENV} is set)");
        return false;
    }
    let Some(binding) = handle.agent_session_binding() else {
        debug!(host = %t.alias, "no agent session binding available; not binding the agent");
        return false;
    };
    // forwarding = false: this is direct client auth, not a forwarded socket.
    match agent.bind_session(binding, false).await {
        Ok(()) => {
            debug!(host = %t.alias, "agent bound to the session (session-bind@openssh.com)");
            true
        }
        Err(e) => {
            debug!(host = %t.alias, "agent did not accept session-bind ({e}); continuing unbound");
            false
        }
    }
}

/// A key file, loaded once and cached.
#[derive(Clone)]
pub enum KeyFile {
    Ready {
        key: Arc<PrivateKey>,
        certs: Vec<Certificate>,
    },
    /// Not usable directly; the reason, and its public key if readable (so a
    /// matching agent identity can still be preferred).
    Unusable {
        reason: String,
        public: Option<PublicKey>,
    },
}

impl KeyFile {
    fn public(&self) -> Option<PublicKey> {
        match self {
            KeyFile::Ready { key, .. } => Some(key.public_key().clone()),
            KeyFile::Unusable { public, .. } => public.clone(),
        }
    }
}

/// Load a private key and any certificates for it. Certificates come from
/// `explicit` (config `cert_file` / ssh_config `CertificateFile`) and from
/// `<path>-cert.pub`; only ones whose key matches, and that are currently
/// valid, are kept.
pub fn load_key_file(path: &Path, explicit: &[PathBuf]) -> KeyFile {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return KeyFile::Unusable {
                reason: format!("cannot read it ({e})"),
                public: None,
            };
        }
    };
    let parsed = russh::keys::ssh_key::PrivateKey::from_openssh(&text);
    if let Ok(k) = &parsed
        && k.is_encrypted()
    {
        return KeyFile::Unusable {
            reason: "it is passphrase-protected; load it into ssh-agent and add \"agent\" to auth"
                .into(),
            public: Some(k.public_key().clone()),
        };
    }
    let key = match parsed
        .or_else(|_| russh::keys::decode_secret_key(&text, None).map_err(|e| e.to_string()))
    {
        Ok(k) => k,
        Err(e) => {
            return KeyFile::Unusable {
                reason: format!("cannot parse it ({e})"),
                public: None,
            };
        }
    };
    let mut cert_paths: Vec<PathBuf> = explicit.to_vec();
    let mut default = path.as_os_str().to_owned();
    default.push("-cert.pub");
    cert_paths.push(PathBuf::from(default));
    let mut certs = Vec::new();
    for c in cert_paths {
        if let Ok(cert) = russh::keys::load_openssh_certificate(&c)
            && cert.public_key() == key.public_key().key_data()
            && cert_current(&cert, SystemTime::now())
            && !certs.contains(&cert)
        {
            certs.push(cert);
        }
    }
    KeyFile::Ready {
        key: Arc::new(key),
        certs,
    }
}

/// The certificate's validity window contains `now`.
fn cert_current(cert: &Certificate, now: SystemTime) -> bool {
    let t = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    cert.valid_after() <= t && t < cert.valid_before()
}

/// Key files, loaded on first use.
#[derive(Default)]
pub struct KeyCache {
    m: Mutex<HashMap<PathBuf, KeyFile>>,
}

impl KeyCache {
    pub fn get(&self, path: &Path, certs: &[PathBuf]) -> KeyFile {
        let mut m = self.m.lock().unwrap_or_else(|p| p.into_inner());
        m.entry(path.to_path_buf())
            .or_insert_with(|| load_key_file(path, certs))
            .clone()
    }
}

/// Agent identities in the order to offer them: those matching the host's
/// identity files first (in identity-file order), then the rest, unless
/// `only` (ssh_config `IdentitiesOnly`) drops the rest.
pub fn order_agent_identities(
    ids: Vec<AgentIdentity>,
    preferred: &[PublicKey],
    only: bool,
) -> Vec<AgentIdentity> {
    let key_of = |id: &AgentIdentity| -> PublicKey {
        match id {
            AgentIdentity::PublicKey { key, .. } => key.clone(),
            AgentIdentity::Certificate { certificate, .. } => {
                PublicKey::from(certificate.public_key().clone())
            }
        }
    };
    // Indices into `ids`: matches for each preferred key, in preference order.
    let mut order: Vec<usize> = Vec::new();
    for p in preferred {
        for (i, id) in ids.iter().enumerate() {
            if key_of(id).key_data() == p.key_data() && !order.contains(&i) {
                order.push(i);
            }
        }
    }
    if !only {
        order.extend(
            (0..ids.len())
                .filter(|i| !order.contains(i))
                .collect::<Vec<_>>(),
        );
    }
    let mut slots: Vec<Option<AgentIdentity>> = ids.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

fn fp(k: &PublicKey) -> String {
    format!("{} {}", k.algorithm(), k.fingerprint(HashAlg::Sha256))
}

fn describe(id: &AgentIdentity) -> String {
    match id {
        AgentIdentity::PublicKey { key, .. } => format!("agent key {}", fp(key)),
        AgentIdentity::Certificate { certificate, .. } => format!(
            "agent certificate {} (key id {:?})",
            fp(&PublicKey::from(certificate.public_key().clone())),
            certificate.key_id()
        ),
    }
}

/// Authenticate `handle` as `t.user`. `key_files` pairs each key file with
/// the certificate files that may belong to it, in the order to try them. Returns how it succeeded, or an error
/// listing everything tried (fingerprints only, never key material).
pub async fn authenticate(
    handle: &mut client::Handle<Handler>,
    t: &Target,
    methods: &[AuthMethod],
    key_files: &[(PathBuf, Vec<PathBuf>)],
    cache: &KeyCache,
) -> Result<String, String> {
    let hash = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    let mut tried: Vec<String> = Vec::new();
    let mut attempts = 0usize;
    for m in methods {
        if attempts >= MAX_AUTH_ATTEMPTS {
            break;
        }
        match m {
            AuthMethod::Agent => {
                let mut agent = match AgentClient::connect_env().await {
                    Ok(a) => a,
                    Err(e) => {
                        tried.push(format!(
                            "ssh-agent not available ({e}; is SSH_AUTH_SOCK set?)"
                        ));
                        continue;
                    }
                };
                // Before listing: a constrained key is only visible once bound.
                let bound = bind_agent_session(&mut agent, handle, t).await;
                let ids = match agent.request_identities().await {
                    Ok(ids) => ids,
                    Err(e) => {
                        tried.push(format!("ssh-agent: listing identities failed ({e})"));
                        continue;
                    }
                };
                if ids.is_empty() {
                    tried.push(if bound {
                        "ssh-agent offers no identities for this host (ssh-add -l; keys added with ssh-add -h are limited to their hosts)".into()
                    } else {
                        "ssh-agent holds no identities (ssh-add -l), or only keys limited to other hosts".into()
                    });
                    continue;
                }
                let preferred: Vec<PublicKey> = key_files
                    .iter()
                    .filter_map(|(p, c)| cache.get(p, c).public().or_else(|| read_pub(p)))
                    .collect();
                let ordered = order_agent_identities(ids, &preferred, t.identities_only);
                if ordered.is_empty() {
                    tried.push("ssh-agent: no identity matches the host's IdentityFile (IdentitiesOnly yes)".into());
                }
                for id in ordered {
                    if attempts >= MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    attempts += 1;
                    let what = describe(&id);
                    let r = match &id {
                        AgentIdentity::PublicKey { key, .. } => {
                            let h = if key.algorithm().is_rsa() { hash } else { None };
                            handle
                                .authenticate_publickey_with(&t.user, key.clone(), h, &mut agent)
                                .await
                        }
                        AgentIdentity::Certificate { certificate, .. } => {
                            handle
                                .authenticate_certificate_with(
                                    &t.user,
                                    certificate.clone(),
                                    hash,
                                    &mut agent,
                                )
                                .await
                        }
                    };
                    match r {
                        Ok(a) if a.success() => return Ok(what),
                        Ok(_) => tried.push(format!("{what}: rejected")),
                        Err(e) => {
                            tried.push(format!("{what}: error ({e})"));
                            if handle.is_closed() {
                                return Err(summary(t, &tried, "the server closed the connection"));
                            }
                        }
                    }
                }
            }
            AuthMethod::KeyFile => {
                if key_files.is_empty() {
                    tried.push("key_file: none configured for this host".into());
                }
                for (p, cert_paths) in key_files {
                    if attempts >= MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    let (key, certs) = match cache.get(p, cert_paths) {
                        KeyFile::Ready { key, certs } => (key, certs),
                        KeyFile::Unusable { reason, .. } => {
                            tried.push(format!("key file {}: skipped, {reason}", p.display()));
                            continue;
                        }
                    };
                    let name = format!("key file {} ({})", p.display(), fp(key.public_key()));
                    for cert in certs {
                        if attempts >= MAX_AUTH_ATTEMPTS {
                            break;
                        }
                        attempts += 1;
                        let what = format!("{name} with certificate (key id {:?})", cert.key_id());
                        match handle
                            .authenticate_openssh_cert(&t.user, key.clone(), cert)
                            .await
                        {
                            Ok(a) if a.success() => return Ok(what),
                            Ok(_) => tried.push(format!("{what}: rejected")),
                            Err(e) => tried.push(format!("{what}: error ({e})")),
                        }
                    }
                    if attempts >= MAX_AUTH_ATTEMPTS {
                        break;
                    }
                    attempts += 1;
                    let h = if key.algorithm().is_rsa() { hash } else { None };
                    match handle
                        .authenticate_publickey(&t.user, PrivateKeyWithHashAlg::new(key.clone(), h))
                        .await
                    {
                        Ok(a) if a.success() => return Ok(name),
                        Ok(_) => tried.push(format!("{name}: rejected")),
                        Err(e) => tried.push(format!("{name}: error ({e})")),
                    }
                    if handle.is_closed() {
                        return Err(summary(t, &tried, "the server closed the connection"));
                    }
                }
            }
        }
    }
    let why = if attempts >= MAX_AUTH_ATTEMPTS {
        format!("stopped after {MAX_AUTH_ATTEMPTS} attempts (sshd MaxAuthTries)")
    } else {
        "nothing was accepted".into()
    };
    Err(summary(t, &tried, &why))
}

fn read_pub(p: &Path) -> Option<PublicKey> {
    let mut pubp = p.as_os_str().to_owned();
    pubp.push(".pub");
    russh::keys::load_public_key(PathBuf::from(pubp)).ok()
}

fn summary(t: &Target, tried: &[String], why: &str) -> String {
    format!(
        "authentication failed for {}@{} ({why}). Nothing was run. Tried: {}. Check the user, \
         authorized_keys or the certificate's principals, and the `auth` setting.",
        t.user,
        t.alias,
        if tried.is_empty() {
            "nothing".to_string()
        } else {
            tried.join("; ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::{LineEnding, private::Ed25519Keypair};

    fn kp(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn id(seed: u8) -> AgentIdentity {
        AgentIdentity::PublicKey {
            key: kp(seed).public_key().clone(),
            comment: format!("k{seed}"),
        }
    }

    fn seeds(v: &[AgentIdentity]) -> Vec<String> {
        v.iter()
            .map(|i| match i {
                AgentIdentity::PublicKey { comment, .. } => comment.clone(),
                _ => "cert".into(),
            })
            .collect()
    }

    #[test]
    fn agent_order_prefers_identity_files() {
        let ids = vec![id(1), id(2), id(3)];
        let pref = vec![kp(3).public_key().clone(), kp(9).public_key().clone()];
        assert_eq!(
            seeds(&order_agent_identities(ids.clone(), &pref, false)),
            ["k3", "k1", "k2"]
        );
        assert_eq!(
            seeds(&order_agent_identities(ids.clone(), &pref, true)),
            ["k3"]
        );
        assert_eq!(
            seeds(&order_agent_identities(ids.clone(), &[], false)),
            ["k1", "k2", "k3"]
        );
        assert!(order_agent_identities(ids, &[], true).is_empty());
    }

    #[test]
    fn key_file_loading() {
        let dir = std::env::temp_dir().join(format!("sshauth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain");
        std::fs::write(&plain, kp(1).to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        assert!(
            matches!(load_key_file(&plain, &[]), KeyFile::Ready { ref certs, .. } if certs.is_empty())
        );

        // Passphrase-protected keys are covered by tests/auth.rs (real ssh-keygen output).
        assert!(matches!(
            load_key_file(&dir.join("missing"), &[]),
            KeyFile::Unusable { public: None, .. }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
