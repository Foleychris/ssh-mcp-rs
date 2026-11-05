//! Integration tests for client authentication and ssh_config resolution.
//!
//! Self-contained: each test starts its own sshd and ssh-agent on loopback,
//! with throwaway keys and a throwaway CA, and drives `sshmux-mcp --stdio`.
//! Needs OpenSSH (`sshd`, `ssh-keygen`, `ssh-agent`, `ssh-add`), so it is
//! ignored by default:
//!
//!   cargo test --release --test auth -- --ignored --test-threads=1
//!
//! sshd runs as the current user (no root needed) and only accepts that user.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn user() -> String {
    std::env::var("USER").unwrap_or_else(|_| {
        String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .into()
    })
}

fn sshd_bin() -> PathBuf {
    for p in [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
    ] {
        if Path::new(p).exists() {
            return p.into();
        }
    }
    panic!("sshd not found; install openssh-server");
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn keygen(path: &Path, passphrase: &str) {
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f"])
        .arg(path));
}

/// A throwaway sshd + agent + key material in a temp dir.
struct Lab {
    dir: PathBuf,
    port: u16,
    sshd: Option<Child>,
    agent: Option<Child>,
}

impl Lab {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sshmux-auth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        keygen(&dir.join("host_key"), "");
        keygen(&dir.join("ca"), "");
        std::fs::write(dir.join("authorized_keys"), "").unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let host_pub = std::fs::read_to_string(dir.join("host_key.pub")).unwrap();
        let host_pub: Vec<&str> = host_pub.split_whitespace().take(2).collect();
        std::fs::write(
            dir.join("known_hosts"),
            format!(
                "[127.0.0.1]:{port} {}\nlab-alias {}\n",
                host_pub.join(" "),
                host_pub.join(" ")
            ),
        )
        .unwrap();
        Lab {
            dir,
            port,
            sshd: None,
            agent: None,
        }
    }

    fn p(&self, f: &str) -> PathBuf {
        self.dir.join(f)
    }

    fn authorize(&self, key: &str) {
        let k = std::fs::read_to_string(self.p(&format!("{key}.pub"))).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.p("authorized_keys"))
            .unwrap();
        f.write_all(k.as_bytes()).unwrap();
    }

    /// Sign `key`.pub with the lab CA for the current user.
    fn certify(&self, key: &str) {
        run(Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(self.p("ca"))
            .args(["-I", "lab-cert", "-n", &user(), "-V", "-5m:+1h"])
            .arg(self.p(&format!("{key}.pub"))));
    }

    fn start_sshd(&mut self) {
        let d = self.dir.display();
        let conf = format!(
            "Port {}\nListenAddress 127.0.0.1\nHostKey {d}/host_key\nAuthorizedKeysFile {d}/authorized_keys\n\
             TrustedUserCAKeys {d}/ca.pub\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             PermitRootLogin prohibit-password\nStrictModes no\nUsePAM no\nPidFile {d}/sshd.pid\nMaxAuthTries 6\n",
            self.port
        );
        std::fs::write(self.p("sshd_config"), conf).unwrap();
        let child = Command::new(sshd_bin())
            .args(["-D", "-e", "-f"])
            .arg(self.p("sshd_config"))
            .stderr(std::fs::File::create(self.p("sshd.log")).unwrap())
            .spawn()
            .unwrap();
        self.sshd = Some(child);
        let t0 = Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err() {
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "sshd did not start; see {}",
                self.p("sshd.log").display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn sock(&self) -> PathBuf {
        self.p("agent.sock")
    }

    fn start_agent(&mut self) {
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(self.sock())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        self.agent = Some(child);
        let t0 = Instant::now();
        while !self.sock().exists() {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "ssh-agent did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn agent_add(&self, key: &str) {
        run(Command::new("ssh-add")
            .arg("-q")
            .arg(self.p(key))
            .env("SSH_AUTH_SOCK", self.sock()));
    }

    /// Server config: the given extra TOML, plus a `[hosts.lab]` entry unless `no_host`.
    fn config(&self, extra: &str, no_host: bool) -> PathBuf {
        let d = self.dir.display();
        let mut c = format!(
            "default_user = \"{}\"\nknown_hosts_files = [\"{d}/known_hosts\"]\nlearned_hosts_file = \"{d}/learned\"\n{extra}\n",
            user()
        );
        if !no_host {
            c.push_str(&format!(
                "[hosts.lab]\naddress = \"127.0.0.1\"\nport = {}\n",
                self.port
            ));
        }
        let p = self.p("server.toml");
        std::fs::write(&p, c).unwrap();
        p
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for c in [self.sshd.as_mut(), self.agent.as_mut()]
            .into_iter()
            .flatten()
        {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run the server over stdio, call one tool, return (isError, text). If the
/// server fails to start, returns (true, its stderr).
fn call(lab: &Lab, cfg: &Path, agent: bool, tool: &str, args: Value) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshmux-mcp"));
    cmd.args(["--stdio"])
        .arg(cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env_remove("SSH_AUTH_SOCK").env("RUST_LOG", "warn");
    if agent {
        cmd.env("SSH_AUTH_SOCK", lab.sock());
    }
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let _ = writeln!(stdin, "{req}");
    let mut line = String::new();
    let _ = BufReader::new(child.stdout.take().unwrap()).read_line(&mut line);
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    if line.is_empty() {
        return (true, String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let v: Value = serde_json::from_str(&line).unwrap();
    let r = &v["result"];
    (
        r["isError"] == true,
        r["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

fn test_conn(lab: &Lab, cfg: &Path, agent: bool, host: &str) -> (bool, String) {
    call(
        lab,
        cfg,
        agent,
        "test_ssh_connection",
        json!({"hostname": host}),
    )
}

#[test]
#[ignore]
fn key_file_default_still_works() {
    let mut lab = Lab::new("keyfile");
    keygen(&lab.p("k"), "");
    lab.authorize("k");
    lab.start_sshd();
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(
        !e && t.contains("reachable") && t.contains("key file"),
        "{t}"
    );
}

#[test]
#[ignore]
fn agent_only() {
    let mut lab = Lab::new("agent");
    keygen(&lab.p("k"), "");
    lab.authorize("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("k");
    std::fs::remove_file(lab.p("k")).unwrap(); // only the agent has it now
    let cfg = lab.config("", false); // no key_file -> auth defaults to ["agent"]
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("authenticated with agent key"), "{t}");
    // Without the agent socket, it fails and says why, without running anything.
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(
        e && t.contains("SSH_AUTH_SOCK") && t.contains("Nothing was run"),
        "{t}"
    );
}

#[test]
#[ignore]
fn certificate_only_from_key_file() {
    let mut lab = Lab::new("cert");
    keygen(&lab.p("k"), "");
    lab.certify("k"); // writes k-cert.pub; key is NOT in authorized_keys
    lab.start_sshd();
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(!e && t.contains("with certificate"), "{t}");
}

#[test]
#[ignore]
fn certificate_held_by_agent() {
    let mut lab = Lab::new("agentcert");
    keygen(&lab.p("k"), "");
    lab.certify("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("k"); // ssh-add also loads k-cert.pub
    let cfg = lab.config("auth = [\"agent\"]", false);
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("agent certificate"), "{t}");
}

#[test]
#[ignore]
fn passphrase_key_file() {
    let mut lab = Lab::new("pass");
    keygen(&lab.p("k"), "correct horse");
    lab.authorize("k");
    lab.start_sshd();
    // key_file alone: refuses to start and says how to fix it.
    let cfg = lab.config(&format!("key_file = \"{}\"", lab.p("k").display()), false);
    let (e, t) = test_conn(&lab, &cfg, false, "lab");
    assert!(e && t.contains("passphrase-protected"), "{t}");
    // With the agent holding it, the same key works.
    lab.start_agent();
    std::fs::write(lab.p("askpass"), "#!/bin/sh\necho 'correct horse'\n").unwrap();
    run(Command::new("chmod").arg("755").arg(lab.p("askpass")));
    run(Command::new("ssh-add")
        .arg("-q")
        .arg(lab.p("k"))
        .env("SSH_AUTH_SOCK", lab.sock())
        .env("SSH_ASKPASS", lab.p("askpass"))
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "x")
        .stdin(Stdio::null()));
    let cfg = lab.config(
        &format!(
            "key_file = \"{}\"\nauth = [\"agent\", \"key_file\"]",
            lab.p("k").display()
        ),
        false,
    );
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(!e && t.contains("agent key"), "{t}");
}

#[test]
#[ignore]
fn stops_before_max_auth_tries() {
    let mut lab = Lab::new("many");
    lab.start_sshd();
    lab.start_agent();
    for i in 0..7 {
        keygen(&lab.p(&format!("k{i}")), "");
        lab.agent_add(&format!("k{i}"));
    }
    lab.authorize("k6"); // only the 7th; beyond the cap
    let cfg = lab.config("auth = [\"agent\"]", false);
    let (e, t) = test_conn(&lab, &cfg, true, "lab");
    assert!(e && t.contains("stopped after 5 attempts"), "{t}");
    assert_eq!(t.matches(": rejected").count(), 5, "{t}");
}

#[test]
#[ignore]
fn ssh_config_alias_identityfile_and_hostkeyalias() {
    let mut lab = Lab::new("sshcfg");
    keygen(&lab.p("k"), "");
    keygen(&lab.p("decoy"), "");
    lab.authorize("k");
    lab.start_sshd();
    lab.start_agent();
    lab.agent_add("decoy"); // an agent key that is NOT authorized
    lab.agent_add("k");
    std::fs::write(
        lab.p("ssh_config"),
        format!(
            "Host lab-alias\n  HostName 127.0.0.1\n  Port {}\n  User {}\n  IdentityFile {}\n  IdentitiesOnly yes\n  HostKeyAlias lab-alias\n\
             Host only-decoy\n  HostName 127.0.0.1\n  Port {port}\n  User {u}\n  IdentityFile {decoy}\n  IdentitiesOnly yes\n  HostKeyAlias lab-alias\n\
             Host jumpy\n  HostName 127.0.0.1\n  ProxyJump bastion.example.com\n\
             Host *\n  User nobody-by-default\n",
            lab.port,
            user(),
            lab.p("k").display(),
            port = lab.port,
            u = user(),
            decoy = lab.p("decoy").display(),
        ),
    )
    .unwrap();
    std::fs::remove_file(lab.p("k")).unwrap();
    // k.pub stays: it identifies which agent key IdentitiesOnly allows.
    let cfg = lab.config(
        &format!(
            "ssh_config = \"{}\"\nallow_unlisted_hosts = false\nauth = [\"agent\"]",
            lab.p("ssh_config").display()
        ),
        true,
    );
    // Alias resolves to HostName/Port/User; the host key is checked under
    // HostKeyAlias (known_hosts has "lab-alias", not "[127.0.0.1]:port"...
    // which it also has, so remove that line to prove the alias is used).
    let kh = std::fs::read_to_string(lab.p("known_hosts")).unwrap();
    std::fs::write(
        lab.p("known_hosts"),
        kh.lines()
            .filter(|l| l.starts_with("lab-alias"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let (e, t) = test_conn(&lab, &cfg, true, "lab-alias");
    assert!(
        !e && t.contains("reachable") && t.contains("agent key"),
        "{t}"
    );
    // IdentitiesOnly restricts the agent to the IdentityFile's key: with only
    // the (unauthorized) decoy named, exactly one key is offered and the
    // authorized one is never tried.
    let (e, t) = test_conn(&lab, &cfg, true, "only-decoy");
    assert!(e && t.matches(": rejected").count() == 1, "{t}");
    // A host named only via a wildcard isn't "configured" when unlisted hosts are off.
    let (e, t) = test_conn(&lab, &cfg, true, "somewhere-else");
    assert!(e && t.contains("unknown host"), "{t}");
    // ProxyJump hosts are refused rather than connected to directly.
    let (e, t) = test_conn(&lab, &cfg, true, "jumpy");
    assert!(
        e && t.contains("ProxyJump") && t.contains("Nothing was attempted"),
        "{t}"
    );
    // list_hosts shows the ssh_config hosts.
    let (_, t) = call(&lab, &cfg, true, "list_hosts", json!({}));
    assert!(
        t.contains("lab-alias") && t.contains("jumpy") && t.contains("not supported yet"),
        "{t}"
    );
}
