//! A small, tested subset of OpenSSH's `ssh_config(5)`.
//!
//! Supported: `Host` blocks (patterns with `*`, `?` and `!negation`),
//! `Include` (with `*`/`?` globs in the last path component), and the
//! directives `HostName`, `User`, `Port`, `IdentityFile`, `CertificateFile`,
//! `IdentitiesOnly`, `ProxyCommand`, `ProxyJump` and `HostKeyAlias`.
//! As in OpenSSH, the first value obtained for a directive wins, except
//! `IdentityFile` and `CertificateFile`, which accumulate.
//!
//! `Match` blocks are skipped with a warning (half-implementing them would
//! silently apply the wrong settings). Other directives are ignored.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// OpenSSH's own limit on nested `Include`s.
const MAX_INCLUDE_DEPTH: usize = 16;
/// Bounds on what we read, so a hostile or runaway config can't eat memory.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FILES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Pos(String),
    Neg(String),
}

#[derive(Debug, Clone)]
struct Block {
    /// `None` for directives before the first `Host` line: they apply to every host.
    patterns: Option<Vec<Pattern>>,
    /// (lowercased keyword, arguments), in file order.
    opts: Vec<(String, Vec<String>)>,
}

impl Block {
    fn matches(&self, host: &str) -> bool {
        let Some(pats) = &self.patterns else {
            return true;
        };
        let host = host.to_ascii_lowercase();
        let mut hit = false;
        for p in pats {
            match p {
                Pattern::Neg(p) if glob(p, &host) => return false,
                Pattern::Pos(p) if glob(p, &host) => hit = true,
                _ => {}
            }
        }
        hit
    }
}

#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    blocks: Vec<Block>,
    /// Where it was read from, for messages.
    pub source: PathBuf,
}

/// The settings `ssh_config` gives one host. Unset fields are `None`/empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_files: Vec<PathBuf>,
    pub certificate_files: Vec<PathBuf>,
    pub identities_only: bool,
    /// `ProxyCommand` or `ProxyJump`, as `(directive, value)`; `none` clears it.
    pub proxy: Option<(String, String)>,
    pub host_key_alias: Option<String>,
    /// A `Host` line names this host without wildcards (so it counts as a
    /// configured host, not one that only matched `Host *`).
    pub named: bool,
}

/// Values for `%` tokens.
pub struct Tokens<'a> {
    pub home: &'a str,
    pub local_user: &'a str,
}

impl SshConfig {
    /// Read `path` and everything it includes.
    pub fn load(path: &Path, home: &str) -> Result<Self> {
        let mut cfg = SshConfig {
            blocks: vec![Block {
                patterns: None,
                opts: vec![],
            }],
            source: path.to_path_buf(),
        };
        let mut files = 0;
        cfg.read_file(path, home, 0, &mut files)
            .with_context(|| format!("reading ssh config {}", path.display()))?;
        Ok(cfg)
    }

    /// Parse config text (no `Include` resolution beyond `home`-relative files).
    #[cfg(test)]
    pub fn parse_str(text: &str, home: &str) -> Result<Self> {
        let mut cfg = SshConfig {
            blocks: vec![Block {
                patterns: None,
                opts: vec![],
            }],
            source: "test".into(),
        };
        let mut files = 0;
        cfg.parse_text(text, Path::new("test"), home, 0, &mut files)?;
        Ok(cfg)
    }

    fn read_file(
        &mut self,
        path: &Path,
        home: &str,
        depth: usize,
        files: &mut usize,
    ) -> Result<()> {
        *files += 1;
        if *files > MAX_FILES {
            bail!("more than {MAX_FILES} files included");
        }
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_FILE_BYTES {
            bail!("{} is larger than {} bytes", path.display(), MAX_FILE_BYTES);
        }
        let text = std::fs::read_to_string(path)?;
        self.parse_text(&text, path, home, depth, files)
    }

    fn parse_text(
        &mut self,
        text: &str,
        path: &Path,
        home: &str,
        depth: usize,
        files: &mut usize,
    ) -> Result<()> {
        let mut in_match = false;
        for (n, line) in text.lines().enumerate() {
            let at = || format!("{} line {}", path.display(), n + 1);
            let Some((kw, args)) = split_line(line).with_context(at)? else {
                continue;
            };
            match kw.as_str() {
                "host" => {
                    in_match = false;
                    if args.is_empty() {
                        bail!("{}: Host needs at least one pattern", at());
                    }
                    let patterns = args
                        .iter()
                        .map(|a| match a.strip_prefix('!') {
                            Some(p) => Pattern::Neg(p.to_ascii_lowercase()),
                            None => Pattern::Pos(a.to_ascii_lowercase()),
                        })
                        .collect();
                    self.blocks.push(Block {
                        patterns: Some(patterns),
                        opts: vec![],
                    });
                }
                "match" => {
                    warn!(
                        "{}: Match blocks are not supported; ignoring this block",
                        at()
                    );
                    in_match = true;
                }
                _ if in_match => {}
                "include" => {
                    if depth >= MAX_INCLUDE_DEPTH {
                        bail!(
                            "{}: Include nested more than {MAX_INCLUDE_DEPTH} deep",
                            at()
                        );
                    }
                    for a in &args {
                        for p in include_paths(a, home)? {
                            self.read_file(&p, home, depth + 1, files)
                                .with_context(|| format!("{}: Include {}", at(), p.display()))?;
                        }
                    }
                }
                _ => self
                    .blocks
                    .last_mut()
                    .expect("always one block")
                    .opts
                    .push((kw, args)),
            }
        }
        Ok(())
    }

    /// Hosts named without wildcards in `Host` lines, in file order.
    pub fn named_hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for b in &self.blocks {
            for p in b.patterns.iter().flatten() {
                if let Pattern::Pos(p) = p
                    && !p.contains(['*', '?'])
                    && !out.contains(p)
                {
                    out.push(p.clone());
                }
            }
        }
        out
    }

    /// Settings for `host` (the name the caller used), first value wins.
    pub fn resolve(&self, host: &str, tok: &Tokens) -> Result<Resolved> {
        let mut r = Resolved::default();
        let mut identities_only = None;
        let mut port: Option<String> = None;
        let (mut idents, mut certs): (Vec<String>, Vec<String>) = (vec![], vec![]);
        let lower = host.to_ascii_lowercase();
        for b in self.blocks.iter().filter(|b| b.matches(host)) {
            if let Some(p) = &b.patterns
                && p.iter()
                    .any(|p| matches!(p, Pattern::Pos(p) if *p == lower))
            {
                r.named = true;
            }
            for (kw, args) in &b.opts {
                let first = args.first().cloned().unwrap_or_default();
                match kw.as_str() {
                    "hostname" => {
                        r.hostname.get_or_insert(first);
                    }
                    "user" => {
                        r.user.get_or_insert(first);
                    }
                    "port" => {
                        port.get_or_insert(first);
                    }
                    "identityfile" => idents.extend(args.iter().cloned()),
                    "certificatefile" => certs.extend(args.iter().cloned()),
                    "identitiesonly" => {
                        identities_only.get_or_insert(first.eq_ignore_ascii_case("yes"));
                    }
                    "proxycommand" | "proxyjump" => {
                        if r.proxy.is_none() {
                            let name = if kw == "proxycommand" {
                                "ProxyCommand"
                            } else {
                                "ProxyJump"
                            };
                            // ProxyCommand's value is the rest of the line.
                            let v = if kw == "proxycommand" {
                                args.join(" ")
                            } else {
                                first
                            };
                            r.proxy = Some((name.to_string(), v));
                        }
                    }
                    "hostkeyalias" => {
                        r.host_key_alias.get_or_insert(first);
                    }
                    other => debug!(
                        directive = other,
                        "ssh config directive not supported; ignored"
                    ),
                }
            }
        }
        if r.proxy
            .as_ref()
            .is_some_and(|(_, v)| v.eq_ignore_ascii_case("none"))
        {
            r.proxy = None;
        }
        r.identities_only = identities_only.unwrap_or(false);
        r.hostname = r.hostname.map(|h| expand(&h, host, None, None, tok));
        if let Some(p) = port {
            r.port = Some(
                p.parse()
                    .with_context(|| format!("Port {p:?} for {host} is not a valid port"))?,
            );
        }
        let remote = r.hostname.clone().unwrap_or_else(|| host.to_string());
        let path = |s: &String| PathBuf::from(expand(s, &remote, r.user.as_deref(), r.port, tok));
        r.identity_files = dedup(
            idents
                .iter()
                .filter(|s| !s.eq_ignore_ascii_case("none"))
                .map(path),
        );
        r.certificate_files = dedup(
            certs
                .iter()
                .filter(|s| !s.eq_ignore_ascii_case("none"))
                .map(path),
        );
        Ok(r)
    }
}

fn dedup(it: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in it {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Split one config line into a lowercased keyword and its arguments.
/// `Keyword value`, `Keyword=value` and `Keyword = value` are all accepted;
/// double quotes group words. Blank lines and `#` comments give `None`.
fn split_line(line: &str) -> Result<Option<(String, Vec<String>)>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let kw = line[..end].to_ascii_lowercase();
    let mut rest = line[end..].trim_start();
    if let Some(r) = rest.strip_prefix('=') {
        rest = r.trim_start();
    }
    let mut args = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut have) = (false, false);
    for c in rest.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                have = true;
            }
            c if c.is_whitespace() && !quoted => {
                if have {
                    args.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            c => {
                cur.push(c);
                have = true;
            }
        }
    }
    if quoted {
        bail!("unterminated quote");
    }
    if have {
        args.push(cur);
    }
    Ok(Some((kw, args)))
}

/// Case-insensitive glob with `*` and `?` (pattern already lowercased).
fn glob(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0, 0, None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Expand `~/` and the tokens `%d` (home), `%h` (remote host), `%r` (remote
/// user), `%u` (local user), `%p` (port) and `%%`. Unknown tokens are kept.
fn expand(s: &str, host: &str, ruser: Option<&str>, port: Option<u16>, tok: &Tokens) -> String {
    let s = match s.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", tok.home),
        None if s == "~" => tok.home.to_string(),
        None => s.to_string(),
    };
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('d') => out.push_str(tok.home),
            Some('h') => out.push_str(host),
            Some('r') => out.push_str(ruser.unwrap_or(tok.local_user)),
            Some('u') => out.push_str(tok.local_user),
            Some('p') => out.push_str(&port.unwrap_or(22).to_string()),
            Some('%') => out.push('%'),
            Some(o) => {
                out.push('%');
                out.push(o);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Paths an `Include` argument names: `~` expanded, relative paths taken
/// from `~/.ssh/`, and `*`/`?` globs in the last component expanded (sorted,
/// like OpenSSH). A glob that matches nothing is not an error.
fn include_paths(arg: &str, home: &str) -> Result<Vec<PathBuf>> {
    let tok = Tokens {
        home,
        local_user: "",
    };
    let p = expand(arg, "", None, None, &tok);
    let p = if Path::new(&p).is_absolute() {
        PathBuf::from(p)
    } else {
        Path::new(home).join(".ssh").join(p)
    };
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return Ok(if p.exists() { vec![p] } else { vec![] });
    }
    let dir = p.parent().unwrap_or(Path::new("/"));
    let mut out: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                glob(
                    &name.to_ascii_lowercase(),
                    &e.file_name().to_string_lossy().to_ascii_lowercase(),
                )
            })
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => vec![],
    };
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOK: Tokens = Tokens {
        home: "/home/me",
        local_user: "me",
    };

    fn cfg(s: &str) -> SshConfig {
        SshConfig::parse_str(s, "/home/me").unwrap()
    }

    fn res(c: &SshConfig, h: &str) -> Resolved {
        c.resolve(h, &TOK).unwrap()
    }

    #[test]
    fn line_splitting() {
        let s = |l: &str| split_line(l).unwrap();
        assert_eq!(s("  # comment"), None);
        assert_eq!(s(""), None);
        assert_eq!(
            s("HostName example.com"),
            Some(("hostname".into(), vec!["example.com".into()]))
        );
        assert_eq!(s("Port=2222"), Some(("port".into(), vec!["2222".into()])));
        assert_eq!(s("Port = 2222"), Some(("port".into(), vec!["2222".into()])));
        assert_eq!(
            s(r#"IdentityFile "~/my keys/id" ~/b"#),
            Some((
                "identityfile".into(),
                vec!["~/my keys/id".into(), "~/b".into()]
            ))
        );
        assert_eq!(s(r#"User """#), Some(("user".into(), vec!["".into()])));
        assert!(split_line(r#"User "x"#).is_err());
    }

    #[test]
    fn globbing() {
        assert!(glob("*", "anything"));
        assert!(glob("*.example.com", "a.example.com"));
        assert!(!glob("*.example.com", "example.com"));
        assert!(glob("web-??", "web-01"));
        assert!(!glob("web-??", "web-1"));
        assert!(glob("a*b*c", "axxbyyc"));
        assert!(!glob("a*b*c", "axxbyy"));
        assert!(glob("", "") && !glob("", "a"));
    }

    #[test]
    fn first_value_wins_and_identities_accumulate() {
        let c = cfg("
            Host build
              HostName build.example.internal
              User deploy
              IdentityFile ~/.ssh/build_key
            Host build *.example.internal
              User other
              Port 2222
              IdentityFile %d/.ssh/id_%r
            Host *
              User fallback
              IdentityFile ~/.ssh/id_ed25519
              IdentitiesOnly yes
        ");
        let r = res(&c, "build");
        assert_eq!(r.hostname.as_deref(), Some("build.example.internal"));
        assert_eq!(r.user.as_deref(), Some("deploy"));
        assert_eq!(r.port, Some(2222));
        assert!(r.identities_only && r.named);
        assert_eq!(
            r.identity_files,
            vec![
                PathBuf::from("/home/me/.ssh/build_key"),
                PathBuf::from("/home/me/.ssh/id_deploy"),
                PathBuf::from("/home/me/.ssh/id_ed25519")
            ]
        );
        let r = res(&c, "unknown");
        assert_eq!(
            (r.hostname, r.user.as_deref(), r.port, r.named),
            (None, Some("fallback"), None, false)
        );
        assert_eq!(c.named_hosts(), vec!["build".to_string()]);
    }

    #[test]
    fn case_insensitive_hosts_and_keywords() {
        let c = cfg("HOST Build\n  hOsTnAmE b.example\n");
        assert_eq!(res(&c, "BUILD").hostname.as_deref(), Some("b.example"));
    }

    #[test]
    fn negation_excludes() {
        let c = cfg("Host *.example.com !secret.example.com\n  User u\n");
        assert_eq!(res(&c, "a.example.com").user.as_deref(), Some("u"));
        assert_eq!(res(&c, "secret.example.com").user, None);
        // A negation alone never matches.
        let c = cfg("Host !foo\n  User u\n");
        assert_eq!(res(&c, "bar").user, None);
    }

    #[test]
    fn global_directives_apply_to_all() {
        let c = cfg("User early\nHost x\n  User late\n");
        assert_eq!(res(&c, "x").user.as_deref(), Some("early"));
    }

    #[test]
    fn hostname_token_and_proxy() {
        let c = cfg("
            Host i-*
              HostName %h.internal
              ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession
            Host jumped
              ProxyJump bastion.example.com
            Host direct
              ProxyCommand none
            Host *
              ProxyJump should-not-apply-to-direct
        ");
        let r = res(&c, "i-0123456789abcdef0");
        assert_eq!(r.hostname.as_deref(), Some("i-0123456789abcdef0.internal"));
        let (kind, v) = r.proxy.unwrap();
        assert_eq!(kind, "ProxyCommand");
        assert!(v.starts_with("aws ssm start-session --target %h"));
        assert_eq!(
            res(&c, "jumped").proxy,
            Some(("ProxyJump".into(), "bastion.example.com".into()))
        );
        assert_eq!(res(&c, "direct").proxy, None);
    }

    #[test]
    fn match_blocks_are_skipped() {
        let c = cfg("
            Match host x exec \"true\"
              User from-match
            Host x
              User from-host
        ");
        assert_eq!(res(&c, "x").user.as_deref(), Some("from-host"));
    }

    #[test]
    fn host_key_alias_and_bad_port() {
        let c = cfg("Host a\n  HostKeyAlias a-key\n  Port nope\n");
        assert!(c.resolve("a", &TOK).is_err());
        let c = cfg("Host a\n  HostKeyAlias a-key\n");
        assert_eq!(res(&c, "a").host_key_alias.as_deref(), Some("a-key"));
    }

    #[test]
    fn host_line_needs_a_pattern() {
        assert!(SshConfig::parse_str("Host\n", "/h").is_err());
    }

    #[test]
    fn includes_globs_and_relative_paths() {
        let home = std::env::temp_dir().join(format!("sshcfg-test-{}", std::process::id()));
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        std::fs::write(ssh.join("config.d/20-b"), "Host b\n  User ub\n").unwrap();
        std::fs::write(ssh.join("config.d/10-a"), "Host a\n  User ua\n").unwrap();
        std::fs::write(ssh.join("config.d/ignored.txt.bak"), "Host z\n").unwrap();
        std::fs::write(
            ssh.join("config"),
            "Include config.d/??-*\nInclude missing/*\nHost c\n  User uc\n",
        )
        .unwrap();
        let home_s = home.to_string_lossy().into_owned();
        let c = SshConfig::load(&ssh.join("config"), &home_s).unwrap();
        assert_eq!(c.named_hosts(), vec!["a", "b", "c"]);
        let tok = Tokens {
            home: &home_s,
            local_user: "me",
        };
        assert_eq!(c.resolve("b", &tok).unwrap().user.as_deref(), Some("ub"));
        // A file including itself hits the depth limit instead of looping.
        std::fs::write(ssh.join("loop"), "Include loop\n").unwrap();
        assert!(SshConfig::load(&ssh.join("loop"), &home_s).is_err());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
