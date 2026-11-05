//! MCP stdio transport: newline-delimited JSON-RPC on stdin/stdout.
//!
//! * A reader parses each line and dispatches it through the same
//!   transport-neutral layer as HTTP (`mcp::dispatch`). `tools/call` runs on
//!   its own task, so many calls run at once; responses may arrive out of order
//!   and are correlated by id.
//! * One writer task owns stdout. Each response is one `write_all` of
//!   `json + "\n"` and a flush, so messages never interleave. Nothing else may
//!   write to stdout: logs go to stderr (see the test at the bottom).
//! * `notifications/cancelled` cancels the runs the named request started and
//!   suppresses its response.
//! * On stdin EOF or SIGTERM/SIGINT: stop reading, give in-flight requests up
//!   to 5 s, then cancel or leave the still-active runs (`stdio_on_exit`).
//!
//! There is no network listener and no authentication: whoever spawned the
//! process (and so owns its stdin) is the client.

use crate::AppState;
use crate::config::OnExit;
use crate::mcp::{self, CallCtx, Dispatch};
use crate::runs::RunSink;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

/// How long in-flight requests may finish after the client goes away.
const DRAIN: Duration = Duration::from_secs(5);
/// How long cancelled runs get to die on exit (SIGTERM, then SIGKILL after 5 s).
const KILL_WAIT: Duration = Duration::from_secs(12);

const E_PARSE: i64 = -32700;
const E_INVALID_REQUEST: i64 = -32600;

fn rpc_err(id: &Value, code: i64, msg: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg.into()}})
}

pub async fn serve(app: Arc<AppState>) -> anyhow::Result<()> {
    let ppid = std::os::unix::process::parent_id();
    info!(hosts = app.cfg.hosts.len(), ppid,
          "ssh-mcp-rs serving MCP on stdio: no network listener and no network-facing auth \
           (listen, auth_token and allowed_origins are ignored); the parent process is the client");
    info!(target: "audit", client = "stdio", ppid, "stdio session started");
    let input = BufReader::new(tokio::io::stdin());
    run(app, input, tokio::io::stdout(), crate::shutdown_signal()).await;
    // tokio's stdin reader is a blocking thread that can't be interrupted; it
    // would keep the runtime alive after a signal. Everything is flushed now.
    std::process::exit(0);
}

/// One stdio session: read until EOF or `stop`, then drain and clean up.
pub async fn run<R, W>(app: Arc<AppState>, mut input: R, output: W, stop: impl std::future::Future<Output = ()>)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(write_loop(rx, output));
    let s = Session {
        app: app.clone(),
        tx,
        inflight: Arc::new(Mutex::new(HashMap::new())),
        tracker: TaskTracker::new(),
    };
    let max = app.cfg.limits.max_body_bytes;
    let read = async {
        loop {
            match read_line(&mut input, max).await {
                Ok(Line::Msg(l)) => s.on_line(&l).await,
                Ok(Line::TooLong(n)) => {
                    warn!(bytes = n, max, "stdio: discarded an oversized message");
                    s.send(rpc_err(&Value::Null, E_INVALID_REQUEST,
                        format!("message of {n} bytes exceeds the {max}-byte limit (limits.max_body_bytes); it was discarded")))
                        .await;
                }
                Ok(Line::Eof) => return "stdin closed",
                Err(e) => {
                    warn!("stdio: reading stdin failed: {e}");
                    return "stdin error";
                }
            }
        }
    };
    let why = tokio::select! {
        w = read => w,
        _ = stop => "signal",
    };
    info!(reason = why, inflight = s.tracker.len(), "stdio: shutting down");
    s.shutdown().await;
    drop(s);
    // Tasks still holding a sender would keep the writer open; don't wait forever.
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
}

struct Session {
    app: Arc<AppState>,
    tx: mpsc::Sender<String>,
    /// In-flight requests by serialized id (so `1` and `"1"` differ).
    inflight: Arc<Mutex<HashMap<String, RunSink>>>,
    tracker: TaskTracker,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Session {
    async fn send(&self, v: Value) {
        // Err only if the writer died (stdout closed); the client is gone then.
        let _ = self.tx.send(v.to_string()).await;
    }

    async fn on_line(&self, line: &[u8]) {
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let msg: Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => return self.send(rpc_err(&Value::Null, E_PARSE, format!("Parse error: {e}"))).await,
        };
        let method = msg.get("method").and_then(Value::as_str);
        let id = msg.get("id").cloned();
        if method == Some("notifications/cancelled") && id.is_none() {
            return self.cancel(msg.get("params").unwrap_or(&Value::Null));
        }
        let (Some(_), Some(id)) = (method, id) else {
            // Other notifications (notifications/initialized, …), responses to
            // requests we never send, or malformed messages: dispatch decides.
            if let Dispatch::Reply(Some(r)) = mcp::dispatch(self.app.clone(), msg, CallCtx::stdio(None)) {
                self.send(r).await;
            }
            return;
        };

        let key = id.to_string();
        let sink = RunSink::default();
        let refused = {
            let mut m = lock(&self.inflight);
            // Bounded like everything else: a client can't pile up unlimited
            // long-polls. Runs themselves are capped by max_pending_runs too.
            let cap = self.app.cfg.limits.max_pending_runs;
            if m.contains_key(&key) {
                Some(format!("request id {key} is already in use by an in-flight request"))
            } else if m.len() >= cap {
                Some(format!("too many requests in flight ({cap}); wait for some to finish"))
            } else {
                m.insert(key.clone(), sink.clone());
                None
            }
        };
        if let Some(e) = refused {
            return self.send(rpc_err(&id, E_INVALID_REQUEST, e)).await;
        }
        match mcp::dispatch(self.app.clone(), msg, CallCtx::stdio(Some(sink))) {
            Dispatch::Reply(r) => {
                lock(&self.inflight).remove(&key);
                if let Some(r) = r {
                    self.send(r).await;
                }
            }
            Dispatch::Call(fut) => {
                let tx = self.tx.clone();
                let inflight = self.inflight.clone();
                self.tracker.spawn(async move {
                    let r = fut.await;
                    let sink = lock(&inflight).remove(&key);
                    // The spec says not to answer a request the client cancelled.
                    if sink.is_some_and(|s| lock(&s).cancelled) {
                        debug!(request = %key, "response suppressed: request was cancelled");
                        return;
                    }
                    let _ = tx.send(r.to_string()).await;
                });
            }
        }
    }

    /// `notifications/cancelled {requestId, reason?}`: cancel the runs that
    /// request started (same path as cancel_run). Unknown or finished ids are
    /// ignored, as the spec requires.
    fn cancel(&self, params: &Value) {
        let Some(req) = params.get("requestId") else { return };
        let key = req.to_string();
        let reason = params.get("reason").and_then(Value::as_str).map(|r| crate::runs::truncate(r, 200));
        let Some(sink) = lock(&self.inflight).get(&key).cloned() else {
            debug!(request = %key, "cancel for an unknown or finished request; ignored");
            return;
        };
        // Mark first: a run the request starts after this is cancelled at start.
        let ids = {
            let mut s = lock(&sink);
            s.cancelled = true;
            s.ids.clone()
        };
        info!(target: "audit", client = "stdio", request = %key, reason = reason.as_deref().unwrap_or("-"),
              runs = ?ids, "request cancelled by client");
        for id in ids {
            if let Some(run) = self.app.runs.get(&id).filter(|r| !r.is_done()) {
                self.app.runs.cancel(&run);
            }
        }
    }

    async fn shutdown(&self) {
        self.tracker.close();
        if tokio::time::timeout(DRAIN, self.tracker.wait()).await.is_err() {
            info!(pending = self.tracker.len(), "stdio: requests still in flight after {}s", DRAIN.as_secs());
        }
        let active: Vec<_> = self.app.runs.list().into_iter().filter(|r| !r.is_done()).collect();
        match self.app.cfg.stdio_on_exit {
            OnExit::Leave => {
                for r in &active {
                    info!(target: "audit", run = %r.id, host = %r.target.alias,
                          "stdio exit: leaving run active (stdio_on_exit = \"leave\")");
                }
            }
            OnExit::Cancel => {
                for r in &active {
                    info!(target: "audit", run = %r.id, host = %r.target.alias,
                          "stdio exit: cancelling run (stdio_on_exit = \"cancel\")");
                    self.app.runs.cancel(r);
                }
                futures::future::join_all(active.iter().map(|r| r.wait(KILL_WAIT))).await;
                for r in active.iter().filter(|r| !r.is_done()) {
                    warn!(target: "audit", run = %r.id, host = %r.target.alias,
                          "stdio exit: run did not finish after cancel; the remote process may still be running");
                }
            }
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut rx: mpsc::Receiver<String>, mut out: W) {
    while let Some(mut m) = rx.recv().await {
        // serde_json escapes control characters, so `m` holds no raw newline.
        debug_assert!(!m.contains('\n'));
        m.push('\n');
        if let Err(e) = async {
            out.write_all(m.as_bytes()).await?;
            out.flush().await
        }
        .await
        {
            warn!("stdio: writing to stdout failed ({e}); the client is gone");
            return;
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Line {
    Msg(Vec<u8>),
    /// A line longer than the limit, discarded through its newline; its length.
    TooLong(usize),
    Eof,
}

/// Read one `\n`-terminated line of at most `max` bytes (a trailing `\r` is
/// kept; JSON parsing treats it as whitespace). A longer line is discarded
/// through its newline without being buffered. A final unterminated line
/// before EOF still counts.
pub async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let mut seen = 0usize;
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(match (seen, seen > max) {
                (0, _) => Line::Eof,
                (n, true) => Line::TooLong(n),
                _ => Line::Msg(buf),
            });
        }
        let nl = chunk.iter().position(|&b| b == b'\n');
        let part = &chunk[..nl.unwrap_or(chunk.len())];
        seen += part.len();
        if seen <= max {
            buf.extend_from_slice(part);
        } else if !buf.is_empty() {
            buf = Vec::new();
        }
        let used = nl.map_or(chunk.len(), |i| i + 1);
        r.consume(used);
        if nl.is_some() {
            return Ok(if seen > max { Line::TooLong(seen) } else { Line::Msg(buf) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, duplex};

    async fn lines(input: &[u8], max: usize) -> Vec<Line> {
        let mut r = BufReader::with_capacity(4, input);
        let mut v = Vec::new();
        loop {
            let l = read_line(&mut r, max).await.unwrap();
            if l == Line::Eof {
                return v;
            }
            v.push(l);
        }
    }

    #[tokio::test]
    async fn line_framing() {
        let m = |s: &str| Line::Msg(s.as_bytes().to_vec());
        assert_eq!(lines(b"", 10).await, vec![]);
        assert_eq!(lines(b"ab\ncd\n", 10).await, vec![m("ab"), m("cd")]);
        assert_eq!(lines(b"ab\ncd", 10).await, vec![m("ab"), m("cd")]);
        assert_eq!(lines(b"\n\n", 10).await, vec![m(""), m("")]);
        assert_eq!(lines(b"0123456789\n", 10).await, vec![m("0123456789")]);
        // Over the limit: discarded through the newline, then reading continues.
        assert_eq!(lines(b"0123456789X\nok\n", 10).await, vec![Line::TooLong(11), m("ok")]);
        assert_eq!(lines(b"0123456789XYZ", 10).await, vec![Line::TooLong(13)]);
        assert_eq!(lines(b"a\r\n", 10).await, vec![m("a\r")]);
    }

    /// Drive a session over in-memory pipes. Returns (client writer, reader of
    /// server output, session handle).
    fn session(
        app: Arc<AppState>,
    ) -> (tokio::io::DuplexStream, tokio::io::Lines<BufReader<tokio::io::DuplexStream>>, tokio::task::JoinHandle<()>) {
        let (client_w, server_r) = duplex(1 << 16);
        let (server_w, client_r) = duplex(1 << 16);
        let h = tokio::spawn(run(app, BufReader::new(server_r), server_w, std::future::pending()));
        (client_w, BufReader::new(client_r).lines(), h)
    }

    async fn next(out: &mut tokio::io::Lines<BufReader<tokio::io::DuplexStream>>) -> Value {
        let l = tokio::time::timeout(Duration::from_secs(5), out.next_line()).await.unwrap().unwrap().unwrap();
        serde_json::from_str(&l).expect("every stdout line is one complete JSON message")
    }

    #[tokio::test]
    async fn session_handshake_and_errors() {
        let app = crate::tests::test_app();
        let (mut w, mut out, h) = session(app);
        let meta = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}"#;
        let input = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#.to_string(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.into(),
            "".into(),
            r#"{"jsonrpc":"2.0","id":"two","method":"tools/list"}"#.into(),
            "{not json".into(),
            "x".repeat(20 << 20),
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#.into(),
            r#"{"jsonrpc":"2.0","id":4,"method":"nope"}"#.into(),
            format!(r#"{{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{{{meta}}}}}"#),
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}}"#.into(),
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"no_such_tool"}}"#.into(),
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}"#.into(),
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_runs","arguments":{}}}"#.into(),
            r#"[{"jsonrpc":"2.0","id":9,"method":"ping"}]"#.into(),
        ];
        let writer = tokio::spawn(async move {
            for l in input {
                w.write_all(l.as_bytes()).await.unwrap();
                w.write_all(b"\n").await.unwrap();
            }
            w.shutdown().await.unwrap();
        });

        let r = next(&mut out).await;
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        let r = next(&mut out).await;
        assert_eq!(r["id"], "two");
        assert!(r["result"]["tools"].as_array().unwrap().iter().any(|t| t["name"] == "execute_command"));
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (Value::Null, json!(E_PARSE)));
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (Value::Null, json!(E_INVALID_REQUEST)));
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["result"].clone()), (json!(3), json!({})));
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(4), json!(-32601)));
        let r = next(&mut out).await;
        assert_eq!(r["id"], 5);
        assert_eq!(r["result"]["resultType"], "complete");
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(6), json!(-32022)));
        let r = next(&mut out).await;
        assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(7), json!(-32602)));
        // tools/call runs on its own task, so its answer may overtake or trail
        // the synchronous batch rejection; ids correlate them.
        let (a, b) = (next(&mut out).await, next(&mut out).await);
        let (call, batch) = if a["id"] == 8 { (a, b) } else { (b, a) };
        assert_eq!(call["id"], 8);
        assert_eq!(call["result"]["content"][0]["text"], "no runs");
        assert_eq!((batch["id"].clone(), batch["error"]["code"].clone()), (Value::Null, json!(E_INVALID_REQUEST)));

        writer.await.unwrap();
        // EOF ends the session, and nothing else was written.
        tokio::time::timeout(Duration::from_secs(10), h).await.unwrap().unwrap();
        assert!(out.next_line().await.unwrap().is_none());
    }

    /// stdout belongs to the JSON-RPC stream in stdio mode: no source file may
    /// print to it. (The writer above is the only owner of stdout.)
    #[test]
    fn nothing_else_writes_stdout() {
        let srcs = [
            ("main.rs", include_str!("main.rs")),
            ("config.rs", include_str!("config.rs")),
            ("mcp.rs", include_str!("mcp.rs")),
            ("runs.rs", include_str!("runs.rs")),
            ("ssh.rs", include_str!("ssh.rs")),
            ("tools.rs", include_str!("tools.rs")),
            ("fileops.rs", include_str!("fileops.rs")),
            ("stdio.rs", include_str!("stdio.rs")),
        ];
        // The print macros (their e-prefixed stderr twins are fine), the dbg
        // macro (debug leftovers), and any direct std stdout handle.
        let banned = regex::Regex::new(concat!(r"(^|[^e])print(ln)?!|\bdbg!|std::io::std", "out")).unwrap();
        for (name, src) in srcs {
            if let Some(m) = banned.find(src) {
                panic!("{name} contains {:?}: stdout is reserved for JSON-RPC in stdio mode", m.as_str());
            }
        }
        let n = include_str!("stdio.rs").matches(concat!("tokio::io::std", "out()")).count();
        assert_eq!(n, 1, "only stdio::serve may open stdout");
        let main = include_str!("main.rs");
        assert!(main.contains(".with_writer(std::io::stderr)"), "logs must go to stderr");
    }
}
