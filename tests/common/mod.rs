//! Shared harness for the self-contained integration tests: a throwaway
//! sshd and ssh-agent on loopback, and helpers to drive `sshmux-mcp --stdio`.
#![allow(dead_code)] // each test binary uses a different subset

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn user() -> String {
    std::env::var("USER").unwrap_or_else(|_| {
        String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .into()
    })
}

pub fn sshd_bin() -> PathBuf {
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

pub fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn keygen(path: &Path, passphrase: &str) {
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f"])
        .arg(path));
}

/// A throwaway sshd + agent + key material in a temp dir.
pub struct Lab {
    pub dir: PathBuf,
    pub port: u16,
    sshd: Option<Child>,
    agent: Option<Child>,
}

impl Lab {
    pub fn new(name: &str) -> Self {
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

    pub fn p(&self, f: &str) -> PathBuf {
        self.dir.join(f)
    }

    pub fn authorize(&self, key: &str) {
        let k = std::fs::read_to_string(self.p(&format!("{key}.pub"))).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.p("authorized_keys"))
            .unwrap();
        f.write_all(k.as_bytes()).unwrap();
    }

    /// Sign `key`.pub with the lab CA for the current user.
    pub fn certify(&self, key: &str) {
        run(Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(self.p("ca"))
            .args(["-I", "lab-cert", "-n", &user(), "-V", "-5m:+1h"])
            .arg(self.p(&format!("{key}.pub"))));
    }

    pub fn start_sshd(&mut self) {
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

    pub fn sock(&self) -> PathBuf {
        self.p("agent.sock")
    }

    pub fn start_agent(&mut self) {
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

    /// `ssh-add -h`: add `key` to the agent, usable only for a server whose
    /// host key is the one in `host_pub` (OpenSSH destination constraints).
    pub fn agent_add_constrained(&self, key: &str, host_pub: &Path) {
        let k = std::fs::read_to_string(host_pub).unwrap();
        let k: Vec<&str> = k.split_whitespace().take(2).collect();
        let kh = self.p(&format!("{key}.dest_known_hosts"));
        std::fs::write(&kh, format!("dest-host {}\n", k.join(" "))).unwrap();
        run(Command::new("ssh-add")
            .arg("-q")
            .arg("-H")
            .arg(&kh)
            .args(["-h", "dest-host"])
            .arg(self.p(key))
            .env("SSH_AUTH_SOCK", self.sock()));
    }

    pub fn agent_add(&self, key: &str) {
        run(Command::new("ssh-add")
            .arg("-q")
            .arg(self.p(key))
            .env("SSH_AUTH_SOCK", self.sock()));
    }

    /// Server config: the given extra TOML, plus a `[hosts.lab]` entry unless `no_host`.
    pub fn config(&self, extra: &str, no_host: bool) -> PathBuf {
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
pub fn call(lab: &Lab, cfg: &Path, agent: bool, tool: &str, args: Value) -> (bool, String) {
    let sock = lab.sock();
    call_with(cfg, agent.then_some(sock.as_path()), &[], tool, args)
}

/// Like `call`, with an explicit agent socket (or none) and extra environment.
pub fn call_with(
    cfg: &Path,
    agent_sock: Option<&Path>,
    env: &[(&str, &str)],
    tool: &str,
    args: Value,
) -> (bool, String) {
    let (e, t, _) = call_logged(cfg, agent_sock, env, tool, args);
    (e, t)
}

/// `call_with`, also returning the server's stderr (its log) and running it
/// with debug logging for sshmux itself.
pub fn call_logged(
    cfg: &Path,
    agent_sock: Option<&Path>,
    env: &[(&str, &str)],
    tool: &str,
    args: Value,
) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshmux-mcp"));
    cmd.args(["--stdio"])
        .arg(cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env_remove("SSH_AUTH_SOCK")
        .env_remove("SSHMUX_TEST_SKIP_SESSION_BIND")
        .env("RUST_LOG", "warn,sshmux_mcp::sshauth=debug");
    if let Some(sock) = agent_sock {
        cmd.env("SSH_AUTH_SOCK", sock);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let _ = writeln!(stdin, "{req}");
    let mut line = String::new();
    let _ = BufReader::new(child.stdout.take().unwrap()).read_line(&mut line);
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let log = String::from_utf8_lossy(&out.stderr).into_owned();
    if line.is_empty() {
        return (true, log.clone(), log);
    }
    let v: Value = serde_json::from_str(&line).unwrap();
    let r = &v["result"];
    (
        r["isError"] == true,
        r["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        log,
    )
}

pub fn test_conn(lab: &Lab, cfg: &Path, agent: bool, host: &str) -> (bool, String) {
    call(
        lab,
        cfg,
        agent,
        "test_ssh_connection",
        json!({"hostname": host}),
    )
}

/// A long-lived `sshmux-mcp --stdio` for several requests (answers can come
/// back in any order; `wait` collects them by id).
pub struct Session {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<Value>,
}

impl Session {
    pub fn start(lab: &Lab, cfg: &Path, agent: bool) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sshmux-mcp"));
        cmd.args(["--stdio"])
            .arg(cfg)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        cmd.env_remove("SSH_AUTH_SOCK").env("RUST_LOG", "warn");
        if agent {
            cmd.env("SSH_AUTH_SOCK", lab.sock());
        }
        let mut child = cmd.spawn().unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx
                    .send(serde_json::from_str::<Value>(&l).expect("stdout is JSON-RPC"))
                    .is_err()
                {
                    return;
                }
            }
        });
        let stdin = child.stdin.take();
        Session { child, stdin, rx }
    }

    pub fn call(&mut self, id: i64, tool: &str, args: Value) {
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": args}});
        let w = self.stdin.as_mut().unwrap();
        writeln!(w, "{req}").unwrap();
        w.flush().unwrap();
    }

    /// Wait for answers to `ids`; returns id -> (isError, text).
    pub fn wait(&self, ids: &[i64]) -> std::collections::HashMap<i64, (bool, String)> {
        let mut got = std::collections::HashMap::new();
        while got.len() < ids.len() {
            let v = self
                .rx
                .recv_timeout(Duration::from_secs(90))
                .expect("answer within 90 s");
            let r = &v["result"];
            let text = r["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            got.insert(v["id"].as_i64().unwrap(), (r["isError"] == true, text));
        }
        got
    }

    pub fn one(&mut self, id: i64, tool: &str, args: Value) -> (bool, String) {
        self.call(id, tool, args);
        self.wait(&[id]).remove(&id).unwrap()
    }

    /// Close stdin and wait for a clean exit.
    pub fn close(mut self) {
        drop(self.stdin.take());
        let st = self.child.wait().unwrap();
        assert!(st.success(), "server exited with {st}");
    }
}
