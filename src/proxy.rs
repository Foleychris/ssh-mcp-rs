//! ProxyCommand transport: run a local command whose stdin/stdout carry the
//! SSH stream (AWS SSM `start-session`, `ssh -W` for a jump host,
//! `cloudflared access ssh`, `nc`, …).
//!
//! Templates take `%h` (address), `%p` (port), `%r` (user) and `%%`. By
//! default a template is split into words like a shell would (quotes,
//! escapes) and the values are substituted into each word, so they always
//! stay single argv elements and no shell ever runs. With `shell = true` the
//! template runs under `sh -c` and every substituted value is `sh_quote`d.
//! Substituted values are validated either way.

use crate::runs::sh_quote;
use anyhow::{Context, Result, anyhow, bail};
use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::process::{Child, Command};

/// Bytes of the proxy's stderr kept for error messages.
const STDERR_TAIL: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySpec {
    pub template: String,
    /// Run the template under `sh -c` (values `sh_quote`d) instead of splitting it.
    pub shell: bool,
    /// Where it came from, for messages: `hosts.NAME`, `proxy_rules[N]`, `ssh_config ProxyCommand`, …
    pub source: String,
}

impl ProxySpec {
    /// The program the template runs, for display (`list_hosts`, errors).
    pub fn program(&self) -> String {
        if self.shell {
            return "sh -c".into();
        }
        shell_words::split(&self.template)
            .ok()
            .and_then(|w| w.into_iter().next())
            .unwrap_or_else(|| "?".into())
    }
}

/// Values allowed into `%h`: host names, IPv4/IPv6 addresses, instance IDs.
fn check_host(h: &str) -> Result<()> {
    if h.is_empty()
        || h.starts_with('-')
        || !h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c))
    {
        bail!(
            "address {h:?} can't be used in a proxy command: only letters, digits, '.', '-', '_' and ':' are allowed"
        );
    }
    Ok(())
}

/// Values allowed into `%r`.
fn check_user(u: &str) -> Result<()> {
    if u.is_empty()
        || u.starts_with('-')
        || !u
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
    {
        bail!(
            "user {u:?} can't be used in a proxy command: only letters, digits, '.', '_', '-' and '@' are allowed"
        );
    }
    Ok(())
}

/// Replace `%h %p %r %%` in `s`, passing each value through `q`.
fn substitute(
    s: &str,
    host: &str,
    port: u16,
    user: &str,
    q: &dyn Fn(&str) -> String,
) -> Result<String> {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('h') => out.push_str(&q(host)),
            Some('p') => out.push_str(&q(&port.to_string())),
            Some('r') => out.push_str(&q(user)),
            Some('%') => out.push('%'),
            Some(o) => bail!("unknown token %{o} in proxy command (use %h, %p, %r or %%)"),
            None => bail!("proxy command ends with a lone %"),
        }
    }
    Ok(out)
}

/// Check that a template is usable (at config load time).
pub fn validate(spec: &ProxySpec) -> Result<()> {
    build_argv(spec, "example.com", 22, "user")
        .map(|_| ())
        .with_context(|| format!("{} proxy_command", spec.source))
}

/// The argv to spawn for `spec` with these values.
pub fn build_argv(spec: &ProxySpec, host: &str, port: u16, user: &str) -> Result<Vec<String>> {
    check_host(host)?;
    check_user(user)?;
    if spec.shell {
        let cmd = substitute(&spec.template, host, port, user, &|v| sh_quote(v))?;
        return Ok(vec!["/bin/sh".into(), "-c".into(), cmd]);
    }
    let words = shell_words::split(&spec.template)
        .map_err(|e| anyhow!("can't split proxy command: {e}"))?;
    if words.is_empty() {
        bail!("proxy command is empty");
    }
    words
        .iter()
        .map(|w| substitute(w, host, port, user, &|v| v.to_string()))
        .collect()
}

/// Turn an ssh_config `ProxyJump` value into an `ssh -W` proxy, one hop only
/// (`[user@]host[:port]`), like OpenSSH's own `-J`.
pub fn jump_spec(value: &str, source: &str) -> Result<ProxySpec> {
    if value.contains(',') {
        bail!("ProxyJump {value:?} has more than one hop; only one is supported");
    }
    let rest = value.strip_prefix("ssh://").unwrap_or(value);
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (
            h,
            Some(
                p.parse::<u16>()
                    .with_context(|| format!("ProxyJump port {p:?}"))?,
            ),
        ),
        _ => (hostport, None),
    };
    check_host(host).context("ProxyJump host")?;
    let mut words = vec!["ssh".to_string()];
    if let Some(u) = user {
        check_user(u).context("ProxyJump user")?;
        words.extend(["-l".into(), u.into()]);
    }
    if let Some(p) = port {
        words.extend(["-p".into(), p.to_string()]);
    }
    words.extend(["-W".into(), "%h:%p".into(), "--".into(), host.into()]);
    Ok(ProxySpec {
        template: shell_words::join(&words),
        shell: false,
        source: source.into(),
    })
}

/// A running proxy. Dropping it kills the proxy's whole process group (an
/// SSM session runs `session-manager-plugin` under `aws`).
pub struct ProxyChild {
    child: Child,
    pgid: Option<i32>,
    stderr: Arc<Mutex<VecDeque<u8>>>,
}

impl ProxyChild {
    /// The last lines the proxy wrote to stderr, and its exit status if it
    /// has exited (waits briefly for it).
    pub async fn diagnose(&mut self) -> String {
        let status =
            tokio::time::timeout(std::time::Duration::from_millis(500), self.child.wait()).await;
        let tail = {
            let b = self.stderr.lock().unwrap_or_else(|p| p.into_inner());
            String::from_utf8_lossy(&b.iter().copied().collect::<Vec<u8>>()).into_owned()
        };
        let lines: Vec<&str> = tail.lines().filter(|l| !l.trim().is_empty()).collect();
        let tail = lines[lines.len().saturating_sub(5)..].join(" | ");
        let status = match status {
            Ok(Ok(s)) => format!("proxy exited with {s}"),
            _ => "proxy still running".into(),
        };
        if tail.is_empty() {
            status
        } else {
            format!("{status}; its stderr: {tail}")
        }
    }
}

impl Drop for ProxyChild {
    fn drop(&mut self) {
        if let Some(pg) = self.pgid
            && pg > 1
            && self.child.try_wait().ok().flatten().is_none()
        {
            // SAFETY: plain kill(2) on the process group we created for this child.
            unsafe {
                libc::kill(-pg, libc::SIGTERM);
            }
        }
        let _ = self.child.start_kill();
    }
}

/// Spawn the proxy; returns its stdout+stdin as one stream.
pub fn spawn(
    argv: &[String],
) -> Result<(
    impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    ProxyChild,
)> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("starting proxy {:?}", argv[0]))?;
    let stdout = child.stdout.take().expect("piped");
    let stdin = child.stdin.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let stderr = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
    let tail = stderr.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok(n) = err.read(&mut buf).await {
            if n == 0 {
                break;
            }
            let mut t = tail.lock().unwrap_or_else(|p| p.into_inner());
            t.extend(&buf[..n]);
            let over = t.len().saturating_sub(STDERR_TAIL);
            t.drain(..over);
        }
    });
    let pgid = child.id().map(|p| p as i32);
    Ok((
        tokio::io::join(stdout, stdin),
        ProxyChild {
            child,
            pgid,
            stderr,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(t: &str, shell: bool) -> ProxySpec {
        ProxySpec {
            template: t.into(),
            shell,
            source: "test".into(),
        }
    }

    fn argv(t: &str, host: &str) -> Result<Vec<String>> {
        build_argv(&spec(t, false), host, 2222, "ubuntu")
    }

    #[test]
    fn splits_and_substitutes_per_word() {
        assert_eq!(
            argv("nc %h %p", "example.com").unwrap(),
            ["nc", "example.com", "2222"]
        );
        assert_eq!(
            argv(
                "aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'",
                "i-0123456789abcdef0"
            )
            .unwrap(),
            [
                "aws",
                "ssm",
                "start-session",
                "--target",
                "i-0123456789abcdef0",
                "--document-name",
                "AWS-StartSSHSession",
                "--parameters",
                "portNumber=2222"
            ]
        );
        assert_eq!(
            argv("ssh -W %h:%p -l %r jump", "10.1.2.3").unwrap(),
            ["ssh", "-W", "10.1.2.3:2222", "-l", "ubuntu", "jump"]
        );
        assert_eq!(argv("echo 100%%", "h").unwrap(), ["echo", "100%"]);
        assert_eq!(
            argv("cmd \"two words\" %h", "h").unwrap(),
            ["cmd", "two words", "h"]
        );
    }

    #[test]
    fn injection_attempts_are_rejected_or_contained() {
        for bad in [
            "x; rm -rf /",
            "x$(id)",
            "x`id`",
            "a b",
            "-oProxyCommand=x",
            "x|y",
            "x&y",
            "x\ny",
            "",
            "x'y",
        ] {
            assert!(argv("nc %h %p", bad).is_err(), "{bad:?} accepted");
            assert!(
                build_argv(&spec("nc %h %p", true), bad, 22, "u").is_err(),
                "{bad:?} accepted (shell)"
            );
        }
        assert!(build_argv(&spec("nc %h %p", false), "h", 22, "u; id").is_err());
        // Template metacharacters stay literal without proxy_shell: no shell runs.
        assert_eq!(
            argv("nc %h %p; echo pwned", "h").unwrap(),
            ["nc", "h", "2222;", "echo", "pwned"]
        );
    }

    #[test]
    fn shell_mode_quotes_values() {
        let a = build_argv(
            &spec("nc %h %p 2>/dev/null || echo fail", true),
            "host.example",
            22,
            "u",
        )
        .unwrap();
        assert_eq!(
            a,
            [
                "/bin/sh",
                "-c",
                "nc 'host.example' '22' 2>/dev/null || echo fail"
            ]
        );
    }

    #[test]
    fn bad_templates() {
        assert!(argv("nc %x", "h").is_err());
        assert!(argv("nc %", "h").is_err());
        assert!(argv("nc 'unterminated", "h").is_err());
        assert!(argv("   ", "h").is_err());
        assert!(validate(&spec("nc %h %p", false)).is_ok());
        assert!(validate(&spec("nc %q", false)).is_err());
    }

    #[test]
    fn proxy_jump() {
        let a =
            |v: &str| build_argv(&jump_spec(v, "t").unwrap(), "target.internal", 22, "me").unwrap();
        assert_eq!(
            a("bastion.example.com"),
            [
                "ssh",
                "-W",
                "target.internal:22",
                "--",
                "bastion.example.com"
            ]
        );
        assert_eq!(
            a("ops@bastion.example.com:2200"),
            [
                "ssh",
                "-l",
                "ops",
                "-p",
                "2200",
                "-W",
                "target.internal:22",
                "--",
                "bastion.example.com"
            ]
        );
        assert!(jump_spec("a,b", "t").is_err());
        assert!(jump_spec("-oProxyCommand=x", "t").is_err());
        assert!(jump_spec("bastion:notaport", "t").is_err());
    }

    #[test]
    fn program_names() {
        assert_eq!(
            spec("aws ssm start-session --target %h", false).program(),
            "aws"
        );
        assert_eq!(spec("whatever", true).program(), "sh -c");
    }

    #[tokio::test]
    async fn spawned_proxy_reports_stderr_and_exit() {
        let (_io, mut child) = spawn(&[
            "/bin/sh".into(),
            "-c".into(),
            "echo 'TargetNotConnected: i-0abc' >&2; exit 3".into(),
        ])
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let d = child.diagnose().await;
        assert!(
            d.contains("exit status: 3") && d.contains("TargetNotConnected"),
            "{d}"
        );
    }
}
