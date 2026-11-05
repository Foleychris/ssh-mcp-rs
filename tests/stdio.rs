//! Integration test for `sshmux-mcp --stdio` against a real SSH host.
//!
//! Ignored by default: it needs a config and a reachable host. Never point it
//! at a production host; it starts and kills `sleep` processes there.
//!
//!   SSH_MCP_TEST_CONFIG=/path/to/config.toml SSH_MCP_TEST_HOST=myhost \
//!     cargo test --release --test stdio -- --ignored --test-threads=1
//!
//! The config must not set `stdio_on_exit` (the test sets it). A throwaway
//! sshd on a loopback port works well; see README "Running locally (stdio)".

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: mpsc::Receiver<Value>,
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k} (see the comment at the top of tests/stdio.rs)"))
}

fn host() -> String {
    env("SSH_MCP_TEST_HOST")
}

/// The configured file, optionally with `stdio_on_exit` prepended (top-level
/// keys must come before the first table).
fn config(on_exit: Option<&str>) -> String {
    let path = env("SSH_MCP_TEST_CONFIG");
    let Some(mode) = on_exit else { return path };
    let text = std::fs::read_to_string(&path).unwrap();
    let out = std::env::temp_dir().join(format!("ssh-mcp-stdio-test-{}-{mode}.toml", std::process::id()));
    std::fs::write(&out, format!("stdio_on_exit = \"{mode}\"\n{text}")).unwrap();
    out.to_string_lossy().into_owned()
}

impl Server {
    fn start(cfg: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sshmux-mcp"))
            .args(["--stdio", cfg])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let line = line.unwrap();
                // Every stdout line must be one complete JSON-RPC message.
                let v: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line:?}"));
                assert_eq!(v["jsonrpc"], "2.0", "not JSON-RPC: {line}");
                assert!(v.get("result").is_some() != v.get("error").is_some(), "not a response: {line}");
                if tx.send(v).is_err() {
                    return;
                }
            }
        });
        let stdin = child.stdin.take();
        Server { child, stdin, rx }
    }

    fn send(&mut self, v: Value) {
        let w = self.stdin.as_mut().expect("stdin open");
        writeln!(w, "{v}").unwrap();
        w.flush().unwrap();
    }

    fn request(&mut self, id: i64, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
    }

    fn call(&mut self, id: i64, tool: &str, args: Value) {
        self.request(id, "tools/call", json!({"name": tool, "arguments": args}));
    }

    fn recv(&self, within: Duration) -> Option<Value> {
        self.rx.recv_timeout(within).ok()
    }

    fn expect(&self, id: i64) -> Value {
        let r = self.recv(Duration::from_secs(60)).expect("a response");
        assert_eq!(r["id"], id, "unexpected response {r}");
        r
    }

    /// Run a command synchronously and return its text result.
    fn exec(&mut self, id: i64, cmd: &str) -> String {
        self.call(id, "execute_command", json!({"hostname": host(), "command": cmd}));
        text(&self.expect(id))
    }

    fn handshake(&mut self) {
        self.request(0, "initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "stdio-test", "version": "1"}}));
        let r = self.expect(0);
        assert_eq!(r["result"]["protocolVersion"], "2025-11-25");
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    /// Close stdin and wait for a clean exit.
    fn close(mut self) {
        drop(self.stdin.take());
        let t0 = Instant::now();
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                assert!(st.success(), "server exited with {st}");
                return;
            }
            assert!(t0.elapsed() < Duration::from_secs(40), "server did not exit after stdin EOF");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn text(r: &Value) -> String {
    r["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("no text in {r}")).to_string()
}

/// Number of processes on the host whose command line is exactly `sleep N`.
fn count_sleep(s: &mut Server, id: i64, n: u32) -> u32 {
    let t = s.exec(id, &format!("pgrep -cx -f 'sleep {n}' || true"));
    let out = t.split("--- stdout").nth(1).and_then(|o| o.lines().nth(1)).unwrap_or("0");
    out.trim().parse().unwrap_or_else(|_| panic!("unexpected pgrep output: {t}"))
}

fn wait_for_count(s: &mut Server, id: &mut i64, n: u32, want: u32) {
    let t0 = Instant::now();
    loop {
        *id += 1;
        let c = count_sleep(s, *id, n);
        if c == want {
            return;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "expected {want} × 'sleep {n}', found {c}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore]
fn handshake_list_and_concurrent_calls() {
    let mut s = Server::start(&config(None));
    s.handshake();
    s.request(1, "tools/list", json!({}));
    let r = s.expect(1);
    let names: Vec<_> = r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].clone()).collect();
    assert!(names.contains(&json!("execute_command")) && names.contains(&json!("edit_file")));

    let t0 = Instant::now();
    for i in 100..120 {
        s.call(i, "execute_command", json!({"hostname": host(), "command": format!("sleep 1; echo marker-{i}")}));
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let r = s.recv(Duration::from_secs(60)).expect("20 responses");
        let id = r["id"].as_i64().unwrap();
        assert!((100..120).contains(&id), "unexpected id in {r}");
        assert_eq!(r["result"]["isError"], false, "{r}");
        assert!(text(&r).contains(&format!("marker-{id}")), "response {id} has someone else's output: {r}");
        assert!(seen.insert(id), "duplicate response for {id}");
    }
    // Concurrent: 20 × 1 s finished well under 20 s.
    assert!(t0.elapsed() < Duration::from_secs(10), "calls ran serially? {:?}", t0.elapsed());
    s.close();
}

#[test]
#[ignore]
fn cancelled_notification_stops_the_run() {
    let mut s = Server::start(&config(None));
    s.handshake();
    let mut id = 1;
    wait_for_count(&mut s, &mut id, 301, 0);
    s.call(500, "execute_command", json!({"hostname": host(), "command": "sleep 301", "wait_secs": 120}));
    wait_for_count(&mut s, &mut id, 301, 1);
    s.send(json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                  "params": {"requestId": 500, "reason": "test"}}));
    wait_for_count(&mut s, &mut id, 301, 0);
    // No response for the cancelled request (and nothing else unexpected).
    assert!(s.recv(Duration::from_secs(3)).is_none());
    s.call(501, "list_runs", json!({}));
    let t = text(&s.expect(501));
    assert!(t.contains("cancelled"), "{t}");
    s.close();
}

#[test]
#[ignore]
fn eof_cancels_active_runs_by_default() {
    let mut s = Server::start(&config(Some("cancel")));
    s.handshake();
    let mut id = 1;
    wait_for_count(&mut s, &mut id, 302, 0);
    s.call(600, "execute_command", json!({"hostname": host(), "command": "sleep 302", "background": true}));
    s.expect(600);
    wait_for_count(&mut s, &mut id, 302, 1);
    s.close();

    let mut s = Server::start(&config(None));
    s.handshake();
    wait_for_count(&mut s, &mut id, 302, 0);
    s.close();
}

#[test]
#[ignore]
fn eof_leaves_runs_with_leave() {
    let mut s = Server::start(&config(Some("leave")));
    s.handshake();
    let mut id = 1;
    s.call(701, "execute_command", json!({"hostname": host(), "command": "sleep 304", "background": true}));
    s.expect(701);
    wait_for_count(&mut s, &mut id, 304, 1);
    s.close();

    let mut s = Server::start(&config(None));
    s.handshake();
    // The run the server owned was not cancelled.
    assert_eq!(count_sleep(&mut s, 900, 304), 1, "stdio_on_exit = leave killed the run");
    s.exec(901, "pkill -x -f 'sleep 304'; true");
    s.close();
}
