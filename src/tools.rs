//! MCP tool definitions and handlers.

use crate::AppState;
use crate::runs::{Run, StartOpts, Status, sh_quote, truncate};
use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub struct ToolOut {
    pub text: String,
    pub is_error: bool,
    /// Optional image content block: (mime type, base64 data).
    pub image: Option<(String, String)>,
}

pub fn ok(text: String) -> ToolOut {
    ToolOut { text, is_error: false, image: None }
}
pub fn err(text: impl Into<String>) -> ToolOut {
    ToolOut { text: text.into(), is_error: true, image: None }
}

pub fn definitions(app: &AppState) -> Vec<Value> {
    let hosts: Vec<String> = app
        .cfg
        .hosts
        .iter()
        .map(|(k, v)| match &v.description {
            Some(d) => format!("{k} ({d})"),
            None => k.clone(),
        })
        .collect();
    let host_desc = format!(
        "Target host. Configured: {}.{}",
        hosts.join(", "),
        if app.cfg.allow_unlisted_hosts { " Other hostnames/IPs are also accepted." } else { "" }
    );
    let user_desc = "SSH user (optional; defaults to the host's configured user).";
    let l = &app.cfg.limits;

    let mut exec_props = json!({
        "command": {"type": "string", "description": "Shell command line, run by the user's login shell (non-interactive, no TTY)."},
        "hostname": {"type": "string", "description": host_desc},
        "username": {"type": "string", "description": user_desc},
        "sudo": {"type": "boolean", "description": "Run as root via passwordless `sudo -n`. Default false. (Prefixing the command with `sudo` also works.)"},
        "stdin": {"type": "string", "description": "Data written to the command's stdin, then EOF. stdin is otherwise closed immediately, so commands never hang waiting for input."},
        "background": {"type": "boolean", "description": "Return a run_id immediately instead of waiting (async mode). Poll with get_run."},
        "wait_secs": {"type": "integer", "minimum": 0, "maximum": l.max_wait_secs,
            "description": format!("Sync mode: max seconds to wait (default {}). If the command is still running after this, it keeps running and a run_id is returned for get_run.", l.default_wait_secs)},
        "timeout_secs": {"type": "integer", "minimum": 0,
            "description": format!("Kill the command (TERM, then KILL) after this many seconds. 0 = no limit. Default {}.", l.default_timeout_secs)}
    });
    if app.cfg.require_confirm_for_destructive {
        exec_props["confirm"] = json!({"type": "boolean", "description": "Required (true) for commands that look destructive (rm, mv, redirects, service restarts, …)."});
    }

    vec![
        json!({
            "name": "execute_command",
            "title": "Run shell command",
            "description": format!(
                "Run a shell command on a host over SSH and return exit code, stdout and stderr. \
                 Synchronous by default: waits up to wait_secs (default {}); anything still running then keeps \
                 running in the background and you get a run_id to poll with get_run — nothing is killed. \
                 Use background=true to start long jobs and return immediately; many runs can execute concurrently. \
                 Large outputs are shown head+tail; the full output (up to {} MiB per stream) stays retrievable via get_run offsets.",
                l.default_wait_secs, l.retained_output_bytes / (1024*1024)),
            "inputSchema": {"type": "object", "properties": exec_props, "required": ["command", "hostname"]},
            "annotations": {"destructiveHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "get_run",
            "title": "Get run status/output",
            "description": "Status and output of a run started by execute_command. wait_secs long-polls until the run finishes (or the wait elapses), so prefer one call with wait_secs over rapid polling. Without offsets returns a head+tail view; with stdout_offset/stderr_offset returns raw output from that byte offset (follow next_offset to tail incrementally).",
            "inputSchema": {"type": "object", "properties": {
                "run_id": {"type": "string"},
                "wait_secs": {"type": "integer", "minimum": 0, "maximum": l.max_wait_secs, "description": "Long-poll up to this many seconds for completion. Default 0."},
                "stdout_offset": {"type": "integer", "minimum": 0, "description": "Return stdout starting at this byte offset."},
                "stderr_offset": {"type": "integer", "minimum": 0, "description": "Return stderr starting at this byte offset."},
                "max_bytes": {"type": "integer", "minimum": 1, "description": "Max bytes per stream in offset mode (default 65536)."}
            }, "required": ["run_id"]},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "list_runs",
            "title": "List runs",
            "description": "List recent and active runs (newest first).",
            "inputSchema": {"type": "object", "properties": {
                "active_only": {"type": "boolean", "description": "Only queued/running runs."},
                "hostname": {"type": "string", "description": "Filter by host."},
                "limit": {"type": "integer", "minimum": 1, "description": "Default 20."}
            }},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "cancel_run",
            "title": "Cancel run",
            "description": "Cancel a run: SIGTERM to its whole process group, SIGKILL after 5s if still alive.",
            "inputSchema": {"type": "object", "properties": {"run_id": {"type": "string"}}, "required": ["run_id"]},
            "annotations": {"destructiveHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "write_file",
            "title": "Write file",
            "description": "Write content to a file on a host (streamed over stdin — no heredoc/quoting issues, binary-safe with encoding=base64). Overwrites in place by default (keeps owner/permissions of an existing file). Reports the byte count actually on disk.",
            "inputSchema": {"type": "object", "properties": {
                "hostname": {"type": "string", "description": host_desc},
                "path": {"type": "string", "description": "Absolute path."},
                "content": {"type": "string"},
                "encoding": {"type": "string", "enum": ["utf8", "base64"], "description": "Default utf8."},
                "append": {"type": "boolean"},
                "mkdirs": {"type": "boolean", "description": "Create parent directories."},
                "mode": {"type": "string", "description": "chmod mode, e.g. 0644 or 755."},
                "sudo": {"type": "boolean", "description": "Write as root."},
                "username": {"type": "string", "description": user_desc}
            }, "required": ["hostname", "path", "content"]},
            "annotations": {"destructiveHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "read_file",
            "title": "Read file",
            "description": "Read a file on a host, binary-safe. Returns text when the bytes are valid UTF-8 (no NULs); a whole PNG/JPEG/GIF/WebP image up to 5 MiB is returned as an image you can see; anything else as base64 (force text or base64 with encoding). Reads up to `length` bytes from `offset` (default 256 KiB from 0, max 4 MiB per call); the header gives the file size, mode, owner, mtime and next_offset for paging. Use instead of `cat` for large or binary files.",
            "inputSchema": {"type": "object", "properties": {
                "hostname": {"type": "string", "description": host_desc},
                "path": {"type": "string", "description": "Absolute path."},
                "offset": {"type": "integer", "minimum": 0, "description": "Byte offset to start at (default 0)."},
                "length": {"type": "integer", "minimum": 1, "maximum": 4194304, "description": "Max bytes to return (default 262144)."},
                "encoding": {"type": "string", "enum": ["auto", "utf8", "base64"], "description": "Default auto."},
                "sudo": {"type": "boolean", "description": "Read as root."},
                "username": {"type": "string", "description": user_desc}
            }, "required": ["hostname", "path"]},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "edit_file",
            "title": "Edit file",
            "description": "Edit a text file on a host by exact string replacement. old_string must match exactly once (whitespace and indentation included) unless replace_all=true; zero or multiple matches change nothing and the error says why. Edits in place (keeps inode, owner and permissions — safe for bind-mounted files), and refuses to write if the file changed between read and write. Returns numbered context around each change. Text files up to 4 MiB; use write_file to create or fully replace a file.",
            "inputSchema": {"type": "object", "properties": {
                "hostname": {"type": "string", "description": host_desc},
                "path": {"type": "string", "description": "Absolute path."},
                "old_string": {"type": "string", "description": "Exact text to replace. Include enough surrounding lines to make it unique."},
                "new_string": {"type": "string", "description": "Replacement text (may be empty to delete)."},
                "replace_all": {"type": "boolean", "description": "Replace every occurrence instead of requiring exactly one."},
                "sudo": {"type": "boolean", "description": "Edit as root."},
                "username": {"type": "string", "description": user_desc}
            }, "required": ["hostname", "path", "old_string", "new_string"]},
            "annotations": {"destructiveHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "get_server_info",
            "title": "Server info",
            "description": "OS, uptime/load, CPU, memory, disks and network addresses of a host.",
            "inputSchema": {"type": "object", "properties": {
                "hostname": {"type": "string", "description": host_desc},
                "username": {"type": "string", "description": user_desc}
            }, "required": ["hostname"]},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "test_ssh_connection",
            "title": "Test SSH connection",
            "description": "Check that a host is reachable and authentication works; reports latency.",
            "inputSchema": {"type": "object", "properties": {
                "hostname": {"type": "string", "description": host_desc},
                "username": {"type": "string", "description": user_desc}
            }, "required": ["hostname"]},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": "list_hosts",
            "title": "List hosts",
            "description": "Configured hosts, their default users, and live connection-pool status.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
    ]
}

pub async fn call(app: &Arc<AppState>, name: &str, args: Value) -> Option<ToolOut> {
    let args = if args.is_null() { json!({}) } else { args };
    Some(match name {
        "execute_command" => execute_command(app, args).await,
        "get_run" => get_run(app, args).await,
        "list_runs" => list_runs(app, args),
        "cancel_run" => cancel_run(app, args).await,
        "write_file" => write_file(app, args).await,
        "read_file" => crate::fileops::read_file(app, args).await,
        "edit_file" => crate::fileops::edit_file(app, args).await,
        "get_server_info" => server_info(app, args).await,
        "test_ssh_connection" => test_conn(app, args).await,
        "list_hosts" => list_hosts(app),
        _ => return None,
    })
}

pub fn parse<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, ToolOut> {
    serde_json::from_value(v).map_err(|e| err(format!("invalid arguments: {e}")))
}

// ---------------------------------------------------------------- rendering

pub fn status_line(run: &Run) -> String {
    let s = run.state();
    let mut out = match s.status {
        Status::Queued => "queued (waiting for a free execution slot)".to_string(),
        Status::Running => match s.pid {
            Some(p) => format!("still running (pid {p})"),
            None => "still running".to_string(),
        },
        Status::Exited => match (&s.signal, s.exit_code) {
            (Some(sig), _) => format!("killed by signal {sig}"),
            (None, Some(c)) => format!("exit {c}"),
            _ => "exited".into(),
        },
        Status::Failed => format!("FAILED: {}", s.error.as_deref().unwrap_or("unknown error")),
        Status::Cancelled => "cancelled".into(),
        Status::TimedOut => format!(
            "timed out after {}s",
            run.timeout.map(|t| t.as_secs()).unwrap_or(0)
        ),
    };
    if matches!(s.status, Status::Cancelled | Status::TimedOut) && s.unkillable {
        out.push_str(" — WARNING: could not signal the process (pid unknown); it may still be running");
    }
    if matches!(s.status, Status::Cancelled | Status::TimedOut) {
        if let Some(c) = s.exit_code {
            let _ = write!(out, " (exit {c})");
        } else if let Some(sig) = &s.signal {
            let _ = write!(out, " ({sig})");
        }
    }
    out
}

fn render(app: &AppState, run: &Run, show_cmd: bool) -> String {
    let limit = app.cfg.limits.inline_output_bytes;
    let mut t = format!(
        "[{}] {} · {:.1}s · run_id={}",
        run.target.alias,
        status_line(run),
        run.elapsed().as_secs_f64(),
        run.id
    );
    if show_cmd {
        let _ = write!(t, "\n$ {}", truncate(&run.command, 500));
    }
    let s = run.state();
    if let Some(n) = &s.note {
        let _ = write!(t, "\nnote: {n}");
    }
    if s.stdout.total > 0 {
        let _ = write!(t, "\n--- stdout ({} B) ---\n{}", s.stdout.total, s.stdout.view(limit, "stdout_offset").trim_end_matches('\n'));
    }
    if s.stderr.total > 0 {
        let _ = write!(t, "\n--- stderr ({} B) ---\n{}", s.stderr.total, s.stderr.view(limit, "stderr_offset").trim_end_matches('\n'));
    }
    if s.stdout.total == 0 && s.stderr.total == 0 && s.status.terminal() {
        t.push_str("\n(no output)");
    }
    if !s.status.terminal() {
        let _ = write!(
            t,
            "\n\nStill running. Poll with get_run(run_id=\"{}\", wait_secs=…) or stop it with cancel_run.",
            run.id
        );
    }
    t
}

// ---------------------------------------------------------------- execute

static DESTRUCTIVE: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    [
        r"\b(rm|del|delete|remove|unlink)\b",
        r"\b(mv|move|rename)\b",
        r"\b(cp|copy)\b.*\b(rm|del|delete)\b",
        r"\b(systemctl|service|init\.d)\s+(restart|reload|stop|start|enable|disable)",
        r"\b(reboot|shutdown|halt|poweroff)\b",
        r"\b(dd|mkfs|fdisk|parted)\b",
        r"\b(>|>>)\s+",
        r"\b(sed|awk|grep)\s+.*\b(-i|--in-place)\b",
        r"\b(find|locate)\s+.*\b(-delete|-exec\s+rm)\b",
        r"\b(chmod|chown|chgrp)\b",
        r"\b(umount|mount)\b",
        r"\b(apt|yum|dnf|pacman|zypper)\s+(remove|purge|uninstall)",
        r"\b(pkill|killall|kill)\b",
        r"\b(truncate|>)\s+/dev/",
        r"\b(echo|printf)\s+.*\s+>\s+",
        r"\b(tar|zip|gzip|bzip2)\s+.*\b(--remove-files|-d)\b",
    ]
    .iter()
    .map(|p| regex::Regex::new(&format!("(?i){p}")).unwrap())
    .collect()
});

#[derive(Deserialize)]
struct ExecArgs {
    command: String,
    hostname: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    sudo: Option<bool>,
    /// Legacy name from the Python server.
    #[serde(default)]
    use_sudo: Option<bool>,
    #[serde(default)]
    stdin: Option<String>,
    #[serde(default)]
    background: bool,
    #[serde(default)]
    wait_secs: Option<u64>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    confirm: bool,
}

async fn execute_command(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: ExecArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if a.command.trim().is_empty() {
        return err("command is empty");
    }
    if a.command.contains('\0') || a.username.as_deref().is_some_and(|u| u.contains('\0')) || a.hostname.contains('\0') {
        return err("command, hostname and username must not contain NUL bytes");
    }
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    if app.cfg.require_confirm_for_destructive
        && !a.confirm
        && DESTRUCTIVE.iter().any(|r| r.is_match(&a.command))
    {
        return ok(format!(
            "DESTRUCTIVE OPERATION DETECTED — not executed.\nCommand: {}\nCall execute_command again with confirm=true to proceed.",
            a.command
        ));
    }
    let l = &app.cfg.limits;
    let timeout = match a.timeout_secs.unwrap_or(l.default_timeout_secs) {
        0 => None,
        s => Some(Duration::from_secs(s)),
    };
    let run = app.runs.start(
        target,
        a.command,
        StartOpts {
            sudo: a.sudo.or(a.use_sudo).unwrap_or(false),
            stdin: a.stdin.map(String::into_bytes),
            timeout,
        },
    );
    let run = match run {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if a.background {
        return ok(format!(
            "[{}] started in background · run_id={}\nPoll with get_run(run_id=\"{}\", wait_secs=…).",
            run.target.alias, run.id, run.id
        ));
    }
    let wait = a.wait_secs.unwrap_or(l.default_wait_secs).min(l.max_wait_secs);
    run.wait(Duration::from_secs(wait)).await;
    let failed = matches!(run.state().status, Status::Failed);
    ToolOut { text: render(app, &run, false), is_error: failed, image: None }
}

// ---------------------------------------------------------------- runs

#[derive(Deserialize)]
struct GetRunArgs {
    run_id: String,
    #[serde(default)]
    wait_secs: Option<u64>,
    #[serde(default)]
    stdout_offset: Option<u64>,
    #[serde(default)]
    stderr_offset: Option<u64>,
    #[serde(default)]
    max_bytes: Option<usize>,
}

async fn get_run(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: GetRunArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let Some(run) = app.runs.get(&a.run_id) else {
        return err(format!(
            "unknown run_id '{}' (runs are kept in memory for {}h after finishing and are lost if the server restarts)",
            a.run_id,
            app.cfg.limits.retain_finished_secs / 3600
        ));
    };
    if let Some(w) = a.wait_secs.filter(|w| *w > 0) {
        run.wait(Duration::from_secs(w.min(app.cfg.limits.max_wait_secs))).await;
    }
    if a.stdout_offset.is_none() && a.stderr_offset.is_none() {
        return ok(render(app, &run, true));
    }
    let max = a.max_bytes.unwrap_or(65536).clamp(1, 4 * 1024 * 1024);
    let mut t = format!(
        "[{}] {} · {:.1}s · run_id={}",
        run.target.alias,
        status_line(&run),
        run.elapsed().as_secs_f64(),
        run.id
    );
    let s = run.state();
    for (name, off, buf) in [
        ("stdout", a.stdout_offset, &s.stdout),
        ("stderr", a.stderr_offset, &s.stderr),
    ] {
        let Some(off) = off else { continue };
        let (start, chunk) = buf.read_from(off, max);
        let next = start + chunk.len() as u64;
        let _ = write!(t, "\n--- {name} bytes {start}..{next} of {} (next_offset={next}) ---", buf.total);
        if start > off {
            let _ = write!(t, "\n(note: bytes {off}..{start} were dropped from the retention window)");
        }
        let _ = write!(t, "\n{}", String::from_utf8_lossy(chunk));
    }
    ok(t)
}

#[derive(Deserialize)]
struct ListArgs {
    #[serde(default)]
    active_only: bool,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn list_runs(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: ListArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let limit = a.limit.unwrap_or(20).max(1);
    let host = a.hostname.as_deref().map(|h| {
        app.pool
            .resolve(h, None)
            .map(|t| t.alias)
            .unwrap_or_else(|_| h.to_string())
    });
    let runs: Vec<_> = app
        .runs
        .list()
        .into_iter()
        .filter(|r| !a.active_only || !r.is_done())
        .filter(|r| host.as_deref().is_none_or(|h| r.target.alias.eq_ignore_ascii_case(h)))
        .take(limit)
        .collect();
    if runs.is_empty() {
        return ok("no runs".into());
    }
    let mut t = String::new();
    for r in runs {
        let _ = writeln!(
            t,
            "{}  [{}] {}  {:.1}s  started {}s ago  $ {}",
            r.id,
            r.target.alias,
            status_line(&r),
            r.elapsed().as_secs_f64(),
            r.created.elapsed().as_secs(),
            truncate(&r.command.replace('\n', " ⏎ "), 120)
        );
    }
    ok(t)
}

#[derive(Deserialize)]
struct CancelArgs {
    run_id: String,
}

async fn cancel_run(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: CancelArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let Some(run) = app.runs.get(&a.run_id) else {
        return err(format!("unknown run_id '{}'", a.run_id));
    };
    if run.is_done() {
        return ok(format!("run already finished: {}", status_line(&run)));
    }
    app.runs.cancel(&run);
    run.wait(Duration::from_secs(12)).await;
    ok(render(app, &run, true))
}

// ---------------------------------------------------------------- files

#[derive(Deserialize)]
struct WriteArgs {
    hostname: String,
    path: String,
    content: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    append: bool,
    #[serde(default)]
    mkdirs: bool,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    sudo: bool,
    #[serde(default)]
    username: Option<String>,
}

async fn write_file(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: WriteArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    if let Err(e) = crate::fileops::check_path(&a.path) {
        return e;
    }
    let data = match a.encoding.as_deref().unwrap_or("utf8") {
        "utf8" | "utf-8" | "text" => a.content.into_bytes(),
        "base64" => match base64::engine::general_purpose::STANDARD.decode(a.content.trim()) {
            Ok(d) => d,
            Err(e) => return err(format!("invalid base64: {e}")),
        },
        other => return err(format!("unknown encoding '{other}'")),
    };
    if let Some(m) = &a.mode
        && (m.is_empty() || m.len() > 4 || !m.chars().all(|c| ('0'..='7').contains(&c)))
    {
        return err("mode must be octal digits, e.g. 0644");
    }
    let p = sh_quote(&a.path);
    let expected = data.len();
    // Stage the upload in a temp file and verify it arrived complete before the
    // target is touched, so an interrupted transfer can't truncate it.
    let mut cmd = format!(
        "set -e; tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; n=$(wc -c < \"$tmp\"); \
         [ $((n)) -eq {expected} ] || {{ echo \"incomplete upload ($n of {expected} bytes); target untouched\" >&2; exit 7; }}; "
    );
    if a.mkdirs
        && let Some((dir, _)) = a.path.rsplit_once('/').filter(|(d, _)| !d.is_empty())
    {
        let _ = write!(cmd, "mkdir -p -- {}; ", sh_quote(dir));
    }
    let _ = write!(cmd, "cat \"$tmp\" {} {p}; ", if a.append { ">>" } else { ">" });
    if let Some(m) = &a.mode {
        let _ = write!(cmd, "chmod {m} -- {p}; ");
    }
    let _ = write!(cmd, "wc -c < {p}");
    let (run, out, errs) = match crate::fileops::run_collect(app, target, cmd, a.sudo, Some(data), 64).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !crate::fileops::succeeded(&run) {
        return crate::fileops::failure(&run, "write", &errs);
    }
    let out = String::from_utf8_lossy(&out).trim().to_string();
    let on_disk: Option<usize> = out.parse().ok();
    let verdict = match (a.append, on_disk) {
        (false, Some(n)) if n == expected => "verified".to_string(),
        (false, Some(_)) => format!("SIZE MISMATCH: expected {expected}"),
        (true, Some(_)) => "appended".to_string(),
        (_, None) => format!("could not verify size (wc said {out:?})"),
    };
    ok(format!(
        "[{}] wrote {expected} bytes to {} — file is now {} bytes ({verdict})",
        run.target.alias,
        a.path,
        on_disk.map(|n| n.to_string()).unwrap_or("?".into())
    ))
}

// ---------------------------------------------------------------- host info

#[derive(Deserialize)]
struct HostArgs {
    hostname: String,
    #[serde(default)]
    username: Option<String>,
}

const INFO_SCRIPT: &str = r#"
echo "== OS =="; uname -a; ( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" )
echo; echo "== Uptime / load =="; uptime
echo; echo "== CPU =="; ( lscpu 2>/dev/null | grep -E '^(Model name|CPU\(s\)|Thread|Core|Socket|Architecture)' ) || grep -m1 'model name' /proc/cpuinfo; echo "cores: $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"
echo; echo "== Memory =="; free -h 2>/dev/null || free
echo; echo "== Disks =="; df -h -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null || df -h
echo; echo "== Network =="; ip -br addr 2>/dev/null || ip addr
"#;

async fn server_info(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: HostArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    match app.pool.exec_collect(&target, INFO_SCRIPT, Duration::from_secs(30), false).await {
        Ok((_, out, e)) => ok(format!(
            "System information for {} ({}@{})\n\n{}{}",
            target.alias,
            target.user,
            target.address,
            out.trim_end(),
            if e.trim().is_empty() { String::new() } else { format!("\n\n(stderr)\n{}", e.trim_end()) }
        )),
        Err(e) => err(format!("{e:#}")),
    }
}

async fn test_conn(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: HostArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    let t0 = std::time::Instant::now();
    match app
        .pool
        .exec_collect(&target, "echo ok; whoami; hostname", Duration::from_secs(30), false)
        .await
    {
        Ok((Some(0), out, _)) => {
            let mut l = out.lines().skip(1);
            ok(format!(
                "✅ {} reachable — logged in as {} on {} ({}:{}), round trip {:.0} ms",
                target.alias,
                l.next().unwrap_or("?"),
                l.next().unwrap_or("?"),
                target.address,
                target.port,
                t0.elapsed().as_secs_f64() * 1000.0
            ))
        }
        Ok((code, out, e)) => err(format!("connected but test command failed ({code:?}): {out}{e}")),
        Err(e) => err(format!("❌ {}: {e:#}", target.alias)),
    }
}

fn list_hosts(app: &Arc<AppState>) -> ToolOut {
    let mut t = String::from("Configured hosts:\n");
    for (k, h) in &app.cfg.hosts {
        let _ = writeln!(
            t,
            "  {k:<10} {}@{}:{}{}",
            h.user.as_deref().unwrap_or(&app.cfg.default_user),
            h.address,
            h.port.unwrap_or(app.cfg.default_port),
            h.description.as_deref().map(|d| format!("  — {d}")).unwrap_or_default()
        );
    }
    let stats = app.pool.stats();
    if !stats.is_empty() {
        t.push_str("\nConnection pool:\n");
        for s in stats {
            let _ = writeln!(t, "  {:<40} conns={} channels_in_use={}", s.key, s.conns, s.in_use);
        }
    }
    let _ = write!(t, "\nActive runs: {}", app.runs.active_count());
    ok(t)
}
