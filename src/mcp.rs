//! MCP JSON-RPC (both eras) and its Streamable HTTP transport. The stdio
//! transport (src/stdio.rs) reuses [`dispatch`] / [`handle_message`].
//! Serves both eras on one endpoint:
//!  * 2026-07-28 (stateless; per-request `_meta` + mirrored headers, `server/discover`)
//!  * 2024-11-05 … 2025-11-25 (`initialize` handshake), handled statelessly —
//!    no Mcp-Session-Id is minted, so any request can land anywhere.

use crate::{AppState, tools};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::{Value, json};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub const MODERN: &str = "2026-07-28";
pub const LEGACY: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const E_PARSE: i64 = -32700;
const E_INVALID_REQUEST: i64 = -32600;
const E_METHOD: i64 = -32601;
const E_PARAMS: i64 = -32602;
const E_HEADER: i64 = -32020;
const E_VERSION: i64 = -32022;

fn rpc_err(id: &Value, code: i64, msg: impl Into<String>, data: Option<Value>) -> Value {
    let mut e = json!({"code": code, "message": msg.into()});
    if let Some(d) = data {
        e["data"] = d;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": e})
}

fn rpc_ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_resp(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

fn server_info() -> Value {
    json!({"name": "sshmux-mcp", "title": "SSH", "version": env!("CARGO_PKG_VERSION")})
}

fn instructions(app: &AppState) -> String {
    let hosts: Vec<String> = app
        .cfg
        .hosts
        .iter()
        .map(|(k, h)| {
            format!(
                "{k} ({}@{})",
                h.user.as_deref().unwrap_or(&app.cfg.default_user),
                h.address
            )
        })
        .collect();
    format!(
        "Run commands on remote hosts over SSH. Hosts: {}. \
         execute_command is synchronous by default but never kills slow commands: after wait_secs it returns \
         a run_id and the command keeps running. For long jobs pass background=true and poll get_run with \
         wait_secs (long-poll) instead of sleeping. Use write_file (or execute_command's stdin) to write files \
         instead of heredocs. sudo=true runs as root via passwordless sudo.",
        hosts.join(", ")
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn origin_ok(app: &AppState, origin: &str) -> bool {
    if app
        .cfg
        .allowed_origins
        .iter()
        .any(|o| o == origin || o == "*")
    {
        return true;
    }
    let rest = origin.split("://").nth(1).unwrap_or("");
    if rest.starts_with("[::1]") {
        return true;
    }
    let host = rest.split(['/', ':']).next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1")
}

/// Shared-secret check. Accepted carriers, any one of:
///  `Authorization: Bearer <secret>`, `x-api-key: <secret>`, `x-auth-token: <secret>`,
///  and — only when `allow_query_token` is set — `?key=<secret>` on the URL
///  (fallback for clients that cannot send custom headers).
fn authorized(app: &AppState, tok: &str, uri: &axum::http::Uri, headers: &HeaderMap) -> bool {
    let ok = |p: &str| constant_time_eq(p.trim().as_bytes(), tok.as_bytes());
    let hv = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    if let Some(a) = hv("authorization")
        && a.get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("bearer "))
        && ok(&a[7..])
    {
        return true;
    }
    if hv("x-api-key").is_some_and(ok) || hv("x-auth-token").is_some_and(ok) {
        return true;
    }
    if app.cfg.allow_query_token
        && let Some(q) = uri.query()
    {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("key=")
                && ok(v)
            {
                return true;
            }
        }
    }
    false
}

/// Decode the `=?base64?…?=` sentinel form used by Mcp-Name / Mcp-Param-*.
fn decode_header_value(v: &str) -> Option<String> {
    match v
        .strip_prefix("=?base64?")
        .and_then(|r| r.strip_suffix("?="))
    {
        Some(b) => base64::engine::general_purpose::STANDARD
            .decode(b)
            .ok()
            .and_then(|d| String::from_utf8(d).ok()),
        None => Some(v.to_string()),
    }
}

/// Auth + Origin gate, run as middleware so it executes BEFORE the request
/// body is read: unauthenticated callers can't make the server buffer bodies.
pub async fn gate(
    State(app): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let headers = req.headers();
    let uri = req.uri();
    let caller = CallCtx::http(peer, headers);
    if let Some(tok) = &app.cfg.auth_token
        && !authorized(&app, tok, uri, headers)
    {
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");
        warn!(target: "audit", client = %caller.client, peer = %caller.peer, user_agent = %crate::runs::truncate(ua, 120),
              "rejected request: missing or wrong shared secret");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized",
        )
            .into_response();
    }
    if let Some(o) = headers.get(header::ORIGIN) {
        let o = o.to_str().unwrap_or("");
        if !origin_ok(&app, o) {
            warn!(target: "audit", client = %caller.client, peer = %caller.peer, origin = o,
                  "rejected request with disallowed Origin");
            return json_resp(
                StatusCode::FORBIDDEN,
                rpc_err(&Value::Null, E_INVALID_REQUEST, "Origin not allowed", None),
            );
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------- HTTP transport

/// HTTP status for a JSON-RPC reply produced by [`dispatch`]: malformed
/// requests and version errors are 400; an unknown method in the modern era is
/// 404; everything else (including tool and params errors) is 200.
fn http_status(reply: &Value, modern: bool) -> StatusCode {
    match reply.pointer("/error/code").and_then(Value::as_i64) {
        Some(E_PARSE | E_INVALID_REQUEST | E_HEADER | E_VERSION) => StatusCode::BAD_REQUEST,
        Some(E_METHOD) if modern => StatusCode::NOT_FOUND,
        _ => StatusCode::OK,
    }
}

pub async fn handle(
    State(app): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ctx = CallCtx::http(peer, &headers);
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_resp(
                StatusCode::BAD_REQUEST,
                rpc_err(&Value::Null, E_PARSE, format!("Parse error: {e}"), None),
            );
        }
    };
    let version = protocol_version(&msg);
    let modern = version.is_some();
    // The 2026-07-28 header mirror is HTTP-only. A wrong version is reported
    // by dispatch (before any header check), as before the transport split.
    if let (Some(v), Some(obj)) = (version.as_deref(), msg.as_object())
        && v == MODERN
        && let (Some(method), Some(id)) = (obj.get("method").and_then(Value::as_str), obj.get("id"))
    {
        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
        if let Some(r) = header_check(&headers, id, method, &params, v) {
            return r;
        }
    }
    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));

    match dispatch(app, msg, ctx) {
        Dispatch::Reply(None) => StatusCode::ACCEPTED.into_response(),
        Dispatch::Reply(Some(r)) => json_resp(http_status(&r, modern), r),
        Dispatch::Call(fut) if wants_sse => {
            // SSE with keep-alive comments so proxies with idle timeouts
            // (e.g. Cloudflare's ~100s) don't cut long synchronous calls.
            // Dropping the stream (client gone) drops `fut`, not the tool task.
            let stream = async_stream::stream! {
                let body = fut.await;
                yield Ok::<Event, Infallible>(Event::default().event("message").data(body.to_string()));
            };
            let mut resp = Sse::new(stream)
                .keep_alive(
                    KeepAlive::new()
                        .interval(Duration::from_secs(15))
                        .text("keepalive"),
                )
                .into_response();
            resp.headers_mut()
                .insert("x-accel-buffering", HeaderValue::from_static("no"));
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            resp
        }
        Dispatch::Call(fut) => json_resp(StatusCode::OK, fut.await),
    }
}

fn header_check(
    headers: &HeaderMap,
    id: &Value,
    method: &str,
    params: &Value,
    v: &str,
) -> Option<Response> {
    let hv = |n: &str| headers.get(n).and_then(|x| x.to_str().ok());
    let bad = |m: String| {
        Some(json_resp(
            StatusCode::BAD_REQUEST,
            rpc_err(id, E_HEADER, m, None),
        ))
    };
    match hv("mcp-protocol-version") {
        Some(h) if h == v => {}
        Some(h) => {
            return bad(format!(
                "Header mismatch: MCP-Protocol-Version '{h}' does not match body '{v}'"
            ));
        }
        None => return bad("Missing required header: MCP-Protocol-Version".into()),
    }
    match hv("mcp-method") {
        Some(h) if h == method => {}
        Some(h) => {
            return bad(format!(
                "Header mismatch: Mcp-Method '{h}' does not match body '{method}'"
            ));
        }
        None => return bad("Missing required header: Mcp-Method".into()),
    }
    if matches!(method, "tools/call" | "resources/read" | "prompts/get") {
        let body_name = params
            .get("name")
            .or_else(|| params.get("uri"))
            .and_then(Value::as_str);
        match (hv("mcp-name").map(decode_header_value), body_name) {
            (Some(Some(h)), Some(b)) if h == b => {}
            (None, _) => return bad("Missing required header: Mcp-Name".into()),
            (Some(None), _) => return bad("Malformed Mcp-Name header".into()),
            (Some(Some(h)), b) => {
                return bad(format!(
                    "Header mismatch: Mcp-Name '{h}' does not match body '{}'",
                    b.unwrap_or("")
                ));
            }
        }
    }
    None
}

// ---------------------------------------------------------------- transport-neutral JSON-RPC

/// Per-request context shared by every transport: who is calling (for the
/// audit log) and, for stdio, where to record runs the request starts so a
/// `notifications/cancelled` can stop them.
pub struct CallCtx {
    pub client: String,
    pub peer: String,
    pub run_sink: Option<crate::runs::RunSink>,
}

impl CallCtx {
    /// The TCP peer plus, when present, the original client IP that Cloudflare
    /// forwards in `Cf-Connecting-Ip`. (The header is informational only —
    /// anything that can reach the port directly could set it.)
    fn http(peer: std::net::SocketAddr, headers: &HeaderMap) -> Self {
        let client = headers
            .get("cf-connecting-ip")
            .or_else(|| headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "-".into());
        Self {
            peer: peer.ip().to_string(),
            client,
            run_sink: None,
        }
    }

    pub fn stdio(run_sink: Option<crate::runs::RunSink>) -> Self {
        Self {
            client: "stdio".into(),
            peer: "-".into(),
            run_sink,
        }
    }
}

/// `params._meta["io.modelcontextprotocol/protocolVersion"]`, which selects the
/// 2026-07-28 era when present.
fn protocol_version(msg: &Value) -> Option<String> {
    msg.get("params")?
        .get("_meta")?
        .get("io.modelcontextprotocol/protocolVersion")?
        .as_str()
        .map(String::from)
}

pub type CallFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Value> + Send>>;

/// Outcome of dispatching one JSON-RPC message.
pub enum Dispatch {
    /// Answer available now; `None` for notifications and stray responses.
    Reply(Option<Value>),
    /// A validated `tools/call`; the tool already runs on its own task, so
    /// dropping this future never kills the work.
    Call(CallFuture),
}

/// Transport-agnostic JSON-RPC: one parsed message in, one response out
/// (`None` for notifications). Both eras; `_meta` protocolVersion is validated
/// here, HTTP header mirroring is not (that is the HTTP layer's job). The
/// transports call [`dispatch`] directly, since HTTP picks SSE vs JSON for a
/// pending call and stdio tracks in-flight calls for cancellation.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn handle_message(app: Arc<AppState>, msg: Value, ctx: CallCtx) -> Option<Value> {
    match dispatch(app, msg, ctx) {
        Dispatch::Reply(r) => r,
        Dispatch::Call(f) => Some(f.await),
    }
}

pub fn dispatch(app: Arc<AppState>, msg: Value, ctx: CallCtx) -> Dispatch {
    let ready = |v: Value| Dispatch::Reply(Some(v));
    if msg.is_array() {
        return ready(rpc_err(
            &Value::Null,
            E_INVALID_REQUEST,
            "JSON-RPC batches are not supported",
            None,
        ));
    }
    let Some(obj) = msg.as_object() else {
        return ready(rpc_err(
            &Value::Null,
            E_INVALID_REQUEST,
            "expected a JSON-RPC object",
            None,
        ));
    };
    let (Some(method), Some(id)) = (obj.get("method").and_then(Value::as_str), obj.get("id"))
    else {
        // Notification (e.g. notifications/initialized) or a stray response.
        return Dispatch::Reply(None);
    };
    let id = id.clone();
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
    let version = protocol_version(&msg);
    debug!(method, ?version, "request");
    match version {
        Some(v) => modern(app, id, method, params, &v, ctx),
        None => legacy(app, id, method, params, ctx),
    }
}

/// Wrap a result for 2026-07-28: resultType + serverInfo in _meta.
fn complete(mut r: Value) -> Value {
    if let Some(o) = r.as_object_mut() {
        o.insert("resultType".into(), json!("complete"));
        let meta = o.entry("_meta").or_insert_with(|| json!({}));
        meta["io.modelcontextprotocol/serverInfo"] = server_info();
    }
    r
}

fn modern(
    app: Arc<AppState>,
    id: Value,
    method: &str,
    params: Value,
    v: &str,
    ctx: CallCtx,
) -> Dispatch {
    let ready = |v: Value| Dispatch::Reply(Some(v));
    if v != MODERN {
        return ready(rpc_err(
            &id,
            E_VERSION,
            format!("Unsupported protocol version: {v}"),
            Some(json!({"supported": [MODERN], "requested": v})),
        ));
    }
    match method {
        "server/discover" => ready(rpc_ok(
            &id,
            complete(json!({
                "supportedVersions": [MODERN],
                "capabilities": {"tools": {}},
                "serverInfo": server_info(),
                "instructions": instructions(&app),
                "ttlMs": 300_000,
                "cacheScope": "private",
            })),
        )),
        "tools/list" => ready(rpc_ok(
            &id,
            complete(json!({
                "tools": tools::definitions(&app),
                "ttlMs": 300_000,
                "cacheScope": "private",
            })),
        )),
        "tools/call" => tools_call(app, id, params, true, ctx),
        _ => ready(rpc_err(
            &id,
            E_METHOD,
            format!("Method not found: {method}"),
            None,
        )),
    }
}

fn legacy(app: Arc<AppState>, id: Value, method: &str, params: Value, ctx: CallCtx) -> Dispatch {
    let ready = |v: Value| Dispatch::Reply(Some(v));
    match method {
        "initialize" => {
            let req = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let ver = LEGACY
                .iter()
                .find(|v| **v == req)
                .copied()
                .unwrap_or(LEGACY[0]);
            ready(rpc_ok(
                &id,
                json!({
                    "protocolVersion": ver,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": server_info(),
                    "instructions": instructions(&app),
                }),
            ))
        }
        "ping" => ready(rpc_ok(&id, json!({}))),
        "server/discover" => ready(rpc_ok(
            &id,
            complete(json!({
                "supportedVersions": [MODERN],
                "capabilities": {"tools": {}},
                "serverInfo": server_info(),
                "instructions": instructions(&app),
            })),
        )),
        "tools/list" => ready(rpc_ok(&id, json!({"tools": tools::definitions(&app)}))),
        "tools/call" => tools_call(app, id, params, false, ctx),
        _ => ready(rpc_err(
            &id,
            E_METHOD,
            format!("Method not found: {method}"),
            None,
        )),
    }
}

fn tools_call(
    app: Arc<AppState>,
    id: Value,
    params: Value,
    modern: bool,
    ctx: CallCtx,
) -> Dispatch {
    let Some(name) = params.get("name").and_then(Value::as_str).map(String::from) else {
        return Dispatch::Reply(Some(rpc_err(
            &id,
            E_PARAMS,
            "tools/call requires params.name",
            None,
        )));
    };
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    if !tools::definitions(&app)
        .iter()
        .any(|t| t["name"] == name.as_str())
    {
        return Dispatch::Reply(Some(rpc_err(
            &id,
            E_PARAMS,
            format!("Unknown tool: {name}"),
            None,
        )));
    }

    // Audit: one line per tool call. Command text and exit status are logged by
    // the run itself (target "audit" in runs.rs), keyed by run_id.
    let s = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .map(|v| crate::runs::truncate(v, 200))
    };
    info!(target: "audit", tool = %name, client = %ctx.client, peer = %ctx.peer,
          host = s("hostname").as_deref().unwrap_or("-"), path = s("path").as_deref().unwrap_or("-"),
          run_id = s("run_id").as_deref().unwrap_or("-"), "tool call");

    // Run the tool on its own task: if the client disconnects mid-call the
    // work (and any SSH run it started) carries on and stays reachable via list_runs.
    let task = tokio::spawn(async move {
        let t0 = std::time::Instant::now();
        let fut = tools::call(&app, &name, args);
        let out = match ctx.run_sink {
            Some(sink) => crate::runs::RUN_SINK.scope(sink, fut).await,
            None => fut.await,
        };
        debug!(tool = %name, ms = t0.elapsed().as_millis() as u64, "tool done");
        out
    });
    Dispatch::Call(Box::pin(async move {
        match task.await {
            Ok(Some(o)) => {
                let mut content = vec![json!({"type": "text", "text": o.text})];
                if let Some((mime, data)) = o.image {
                    content.push(json!({"type": "image", "mimeType": mime, "data": data}));
                }
                let r = json!({"content": content, "isError": o.is_error});
                rpc_ok(&id, if modern { complete(r) } else { r })
            }
            Ok(None) => rpc_err(&id, E_PARAMS, "Unknown tool", None),
            Err(e) => rpc_err(&id, -32603, format!("internal error: {e}"), None),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const META: &str = "io.modelcontextprotocol/protocolVersion";

    async fn call(msg: Value) -> Option<Value> {
        handle_message(crate::tests::test_app(), msg, CallCtx::stdio(None)).await
    }

    fn req(id: Value, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }

    fn modern_req(id: i64, method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({META: MODERN});
        req(json!(id), method, params)
    }

    fn code(r: &Value) -> i64 {
        r["error"]["code"].as_i64().expect("an error reply")
    }

    #[tokio::test]
    async fn legacy_era() {
        let r = call(req(
            json!(1),
            "initialize",
            json!({"protocolVersion": "2025-06-18"}),
        ))
        .await
        .unwrap();
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(r["result"]["serverInfo"]["name"], "sshmux-mcp");
        assert!(
            r["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("box")
        );
        // An unknown version negotiates down to the newest legacy one.
        let r = call(req(
            json!(1),
            "initialize",
            json!({"protocolVersion": "1.0"}),
        ))
        .await
        .unwrap();
        assert_eq!(r["result"]["protocolVersion"], LEGACY[0]);

        let r = call(req(json!("p"), "ping", json!({}))).await.unwrap();
        assert_eq!(r, json!({"jsonrpc": "2.0", "id": "p", "result": {}}));

        let r = call(req(json!(2), "server/discover", json!({})))
            .await
            .unwrap();
        assert_eq!(r["result"]["supportedVersions"], json!([MODERN]));
        assert_eq!(r["result"]["resultType"], "complete");

        let r = call(req(json!(3), "tools/list", json!({}))).await.unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "execute_command"));
        assert!(r["result"].get("resultType").is_none());

        let r = call(req(json!(4), "tools/call", json!({"name": "list_hosts"})))
            .await
            .unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("192.0.2.1")
        );
        assert!(r["result"].get("resultType").is_none());

        assert_eq!(
            code(
                &call(req(json!(5), "tools/call", json!({"name": "nope"})))
                    .await
                    .unwrap()
            ),
            E_PARAMS
        );
        assert_eq!(
            code(&call(req(json!(6), "tools/call", json!({}))).await.unwrap()),
            E_PARAMS
        );
        assert_eq!(
            code(
                &call(req(json!(7), "resources/list", json!({})))
                    .await
                    .unwrap()
            ),
            E_METHOD
        );
        // Tool-level failures are results with isError, not JSON-RPC errors.
        let r = call(req(
            json!(8),
            "tools/call",
            json!({"name": "get_run", "arguments": {"run_id": "r0"}}),
        ))
        .await
        .unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[tokio::test]
    async fn modern_era() {
        let r = call(modern_req(1, "server/discover", json!({})))
            .await
            .unwrap();
        assert_eq!(r["result"]["supportedVersions"], json!([MODERN]));
        assert_eq!(r["result"]["ttlMs"], 300_000);
        assert_eq!(
            r["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "sshmux-mcp"
        );

        let r = call(modern_req(2, "tools/list", json!({}))).await.unwrap();
        assert_eq!(r["result"]["resultType"], "complete");
        assert_eq!(r["result"]["cacheScope"], "private");

        let r = call(modern_req(3, "tools/call", json!({"name": "list_runs"})))
            .await
            .unwrap();
        assert_eq!(r["result"]["resultType"], "complete");
        assert_eq!(r["result"]["content"][0]["text"], "no runs");

        assert_eq!(
            code(
                &call(modern_req(4, "tools/call", json!({"name": "nope"})))
                    .await
                    .unwrap()
            ),
            E_PARAMS
        );
        // initialize is a legacy-era method.
        assert_eq!(
            code(&call(modern_req(5, "initialize", json!({}))).await.unwrap()),
            E_METHOD
        );

        let mut m = req(json!(6), "tools/list", json!({}));
        m["params"]["_meta"] = json!({META: "2025-06-18"});
        let r = call(m).await.unwrap();
        assert_eq!(code(&r), E_VERSION);
        assert_eq!(r["error"]["data"]["supported"], json!([MODERN]));
    }

    #[tokio::test]
    async fn notifications_and_malformed() {
        assert_eq!(
            call(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await,
            None
        );
        assert_eq!(
            call(json!({"jsonrpc": "2.0", "id": 1, "result": {}})).await,
            None
        );
        assert_eq!(
            code(
                &call(json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]))
                    .await
                    .unwrap()
            ),
            E_INVALID_REQUEST
        );
        assert_eq!(
            code(&call(json!("hello")).await.unwrap()),
            E_INVALID_REQUEST
        );
    }

    #[test]
    fn http_status_mapping() {
        let e = |c: i64| rpc_err(&json!(1), c, "x", None);
        assert_eq!(
            http_status(&rpc_ok(&json!(1), json!({})), true),
            StatusCode::OK
        );
        assert_eq!(http_status(&e(E_VERSION), true), StatusCode::BAD_REQUEST);
        assert_eq!(
            http_status(&e(E_INVALID_REQUEST), false),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(http_status(&e(E_METHOD), true), StatusCode::NOT_FOUND);
        assert_eq!(http_status(&e(E_METHOD), false), StatusCode::OK);
        assert_eq!(http_status(&e(E_PARAMS), true), StatusCode::OK);
    }
}
