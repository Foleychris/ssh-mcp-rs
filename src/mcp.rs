//! MCP over Streamable HTTP. Serves both eras on one endpoint:
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
use tracing::{debug, info};

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
    json!({"name": "ssh-mcp-rs", "title": "SSH", "version": env!("CARGO_PKG_VERSION")})
}

fn instructions(app: &AppState) -> String {
    let hosts: Vec<String> = app
        .cfg
        .hosts
        .iter()
        .map(|(k, h)| format!("{k} ({}@{})", h.user.as_deref().unwrap_or(&app.cfg.default_user), h.address))
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
    if app.cfg.allowed_origins.iter().any(|o| o == origin || o == "*") {
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
    if let Some(a) = hv("authorization") {
        if a.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("bearer ")) && ok(&a[7..]) {
            return true;
        }
    }
    if hv("x-api-key").is_some_and(ok) || hv("x-auth-token").is_some_and(ok) {
        return true;
    }
    if app.cfg.allow_query_token {
        if let Some(q) = uri.query() {
            for pair in q.split('&') {
                if let Some(v) = pair.strip_prefix("key=") {
                    if ok(v) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Decode the `=?base64?…?=` sentinel form used by Mcp-Name / Mcp-Param-*.
fn decode_header_value(v: &str) -> Option<String> {
    match v.strip_prefix("=?base64?").and_then(|r| r.strip_suffix("?=")) {
        Some(b) => base64::engine::general_purpose::STANDARD
            .decode(b)
            .ok()
            .and_then(|d| String::from_utf8(d).ok()),
        None => Some(v.to_string()),
    }
}

pub async fn handle(
    State(app): State<Arc<AppState>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(tok) = &app.cfg.auth_token {
        if !authorized(&app, tok, &uri, &headers) {
            info!("rejected request: missing or wrong shared secret");
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "unauthorized",
            )
                .into_response();
        }
    }
    if let Some(o) = headers.get(header::ORIGIN) {
        let o = o.to_str().unwrap_or("");
        if !origin_ok(&app, o) {
            info!(origin = o, "rejected request with disallowed Origin");
            return json_resp(
                StatusCode::FORBIDDEN,
                rpc_err(&Value::Null, E_INVALID_REQUEST, "Origin not allowed", None),
            );
        }
    }

    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_resp(
                StatusCode::BAD_REQUEST,
                rpc_err(&Value::Null, E_PARSE, format!("Parse error: {e}"), None),
            );
        }
    };
    if msg.is_array() {
        return json_resp(
            StatusCode::BAD_REQUEST,
            rpc_err(&Value::Null, E_INVALID_REQUEST, "JSON-RPC batches are not supported", None),
        );
    }
    let Some(obj) = msg.as_object() else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            rpc_err(&Value::Null, E_INVALID_REQUEST, "expected a JSON-RPC object", None),
        );
    };
    let (Some(method), Some(id)) = (obj.get("method").and_then(Value::as_str), obj.get("id")) else {
        // Notification (e.g. notifications/initialized) or a stray response.
        return StatusCode::ACCEPTED.into_response();
    };
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
    let version = params
        .get("_meta")
        .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(Value::as_str)
        .map(String::from);
    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));

    debug!(method, ?version, "request");
    match version {
        Some(v) => modern(app, &headers, id.clone(), method, params, &v, wants_sse).await,
        None => legacy(app, id.clone(), method, params, wants_sse).await,
    }
}

fn header_check(headers: &HeaderMap, id: &Value, method: &str, params: &Value, v: &str) -> Option<Response> {
    let hv = |n: &str| headers.get(n).and_then(|x| x.to_str().ok());
    let bad = |m: String| Some(json_resp(StatusCode::BAD_REQUEST, rpc_err(id, E_HEADER, m, None)));
    match hv("mcp-protocol-version") {
        Some(h) if h == v => {}
        Some(h) => return bad(format!("Header mismatch: MCP-Protocol-Version '{h}' does not match body '{v}'")),
        None => return bad("Missing required header: MCP-Protocol-Version".into()),
    }
    match hv("mcp-method") {
        Some(h) if h == method => {}
        Some(h) => return bad(format!("Header mismatch: Mcp-Method '{h}' does not match body '{method}'")),
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
                return bad(format!("Header mismatch: Mcp-Name '{h}' does not match body '{}'", b.unwrap_or("")));
            }
        }
    }
    None
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

async fn modern(
    app: Arc<AppState>,
    headers: &HeaderMap,
    id: Value,
    method: &str,
    params: Value,
    v: &str,
    wants_sse: bool,
) -> Response {
    if v != MODERN {
        return json_resp(
            StatusCode::BAD_REQUEST,
            rpc_err(
                &id,
                E_VERSION,
                format!("Unsupported protocol version: {v}"),
                Some(json!({"supported": [MODERN], "requested": v})),
            ),
        );
    }
    if let Some(r) = header_check(headers, &id, method, &params, v) {
        return r;
    }
    match method {
        "server/discover" => json_resp(StatusCode::OK, rpc_ok(&id, complete(json!({
            "supportedVersions": [MODERN],
            "capabilities": {"tools": {}},
            "serverInfo": server_info(),
            "instructions": instructions(&app),
            "ttlMs": 300_000,
            "cacheScope": "private",
        })))),
        "tools/list" => json_resp(StatusCode::OK, rpc_ok(&id, complete(json!({
            "tools": tools::definitions(&app),
            "ttlMs": 300_000,
            "cacheScope": "private",
        })))),
        "tools/call" => tools_call(app, id, params, wants_sse, true).await,
        _ => json_resp(
            StatusCode::NOT_FOUND,
            rpc_err(&id, E_METHOD, format!("Method not found: {method}"), None),
        ),
    }
}

async fn legacy(app: Arc<AppState>, id: Value, method: &str, params: Value, wants_sse: bool) -> Response {
    match method {
        "initialize" => {
            let req = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let ver = LEGACY.iter().find(|v| **v == req).copied().unwrap_or(LEGACY[0]);
            json_resp(StatusCode::OK, rpc_ok(&id, json!({
                "protocolVersion": ver,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": server_info(),
                "instructions": instructions(&app),
            })))
        }
        "ping" => json_resp(StatusCode::OK, rpc_ok(&id, json!({}))),
        "server/discover" => json_resp(StatusCode::OK, rpc_ok(&id, complete(json!({
            "supportedVersions": [MODERN],
            "capabilities": {"tools": {}},
            "serverInfo": server_info(),
            "instructions": instructions(&app),
        })))),
        "tools/list" => json_resp(StatusCode::OK, rpc_ok(&id, json!({"tools": tools::definitions(&app)}))),
        "tools/call" => tools_call(app, id, params, wants_sse, false).await,
        _ => json_resp(StatusCode::OK, rpc_err(&id, E_METHOD, format!("Method not found: {method}"), None)),
    }
}

async fn tools_call(app: Arc<AppState>, id: Value, params: Value, wants_sse: bool, modern: bool) -> Response {
    let Some(name) = params.get("name").and_then(Value::as_str).map(String::from) else {
        return json_resp(StatusCode::OK, rpc_err(&id, E_PARAMS, "tools/call requires params.name", None));
    };
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    if !tools::definitions(&app).iter().any(|t| t["name"] == name.as_str()) {
        return json_resp(StatusCode::OK, rpc_err(&id, E_PARAMS, format!("Unknown tool: {name}"), None));
    }

    // Run the tool on its own task: if the client disconnects mid-call the
    // work (and any SSH run it started) carries on and stays reachable via list_runs.
    let app2 = app.clone();
    let task = tokio::spawn(async move {
        let t0 = std::time::Instant::now();
        let out = tools::call(&app2, &name, args).await;
        debug!(tool = %name, ms = t0.elapsed().as_millis() as u64, "tool done");
        out
    });
    let id2 = id.clone();
    let finish = move |res: Result<Option<tools::ToolOut>, tokio::task::JoinError>| -> Value {
        match res {
            Ok(Some(o)) => {
                let r = json!({"content": [{"type": "text", "text": o.text}], "isError": o.is_error});
                rpc_ok(&id2, if modern { complete(r) } else { r })
            }
            Ok(None) => rpc_err(&id2, E_PARAMS, "Unknown tool", None),
            Err(e) => rpc_err(&id2, -32603, format!("internal error: {e}"), None),
        }
    };

    if wants_sse {
        // SSE with keep-alive comments so proxies with idle timeouts
        // (e.g. Cloudflare's ~100s) don't cut long synchronous calls.
        let stream = async_stream::stream! {
            let body = finish(task.await);
            yield Ok::<Event, Infallible>(Event::default().event("message").data(body.to_string()));
        };
        let mut resp = Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keepalive"))
            .into_response();
        resp.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
        resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        resp
    } else {
        json_resp(StatusCode::OK, finish(task.await))
    }
}
