//! File tools built on top of runs: read_file (text / binary / image) and
//! edit_file (exact-string replacement, in place, with a change guard).

use crate::AppState;
use crate::runs::{Run, StartOpts, Status, sh_quote};
use crate::tools::{ToolOut, err, ok, parse, status_line};
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

const READ_MAX: u64 = 4 * 1024 * 1024;
const READ_DEFAULT: u64 = 256 * 1024;
const IMAGE_MAX: u64 = 5 * 1024 * 1024;
const EDIT_MAX: u64 = 4 * 1024 * 1024;

/// Run a helper command to completion and return (run, stdout bytes, stderr text).
async fn run_collect(
    app: &Arc<AppState>,
    target: crate::ssh::Target,
    cmd: String,
    sudo: bool,
    stdin: Option<Vec<u8>>,
    max_out: usize,
) -> (Arc<Run>, Vec<u8>, String) {
    let run = app.runs.start(target, cmd, StartOpts { sudo, stdin, timeout: Some(Duration::from_secs(120)) });
    run.wait(Duration::from_secs(130)).await;
    let s = run.state();
    let out = s.stdout.read_from(0, max_out).1.to_vec();
    let errs = String::from_utf8_lossy(s.stderr.read_from(0, 16 * 1024).1).into_owned();
    drop(s);
    (run, out, errs)
}

fn succeeded(run: &Run) -> bool {
    let s = run.state();
    s.status == Status::Exited && s.exit_code == Some(0)
}

fn failure(run: &Run, what: &str, errs: &str) -> ToolOut {
    let why = errs.lines().filter(|l| !l.starts_with("META ")).collect::<Vec<_>>().join(" ");
    err(format!("[{}] {what} failed: {} {}", run.target.alias, status_line(run), why.trim()))
}

/// Common shell preamble: existence / type / permission checks with clear exits.
fn checks(p: &str, need_write: bool) -> String {
    let mut c = format!(
        "[ -e {p} ] || {{ echo 'no such file' >&2; exit 2; }}; \
         [ -d {p} ] && {{ echo 'is a directory' >&2; exit 3; }}; \
         [ -r {p} ] || {{ echo 'permission denied (try sudo=true)' >&2; exit 4; }}; "
    );
    if need_write {
        c.push_str(&format!("[ -w {p} ] || {{ echo 'not writable (try sudo=true)' >&2; exit 4; }}; "));
    }
    c
}

fn image_mime(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

// ---------------------------------------------------------------- read_file

#[derive(Deserialize)]
pub struct ReadArgs {
    hostname: String,
    path: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    sudo: bool,
    #[serde(default)]
    username: Option<String>,
}

pub async fn read_file(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: ReadArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    if a.path.trim().is_empty() {
        return err("path is empty");
    }
    let enc = a.encoding.as_deref().unwrap_or("auto");
    if !matches!(enc, "auto" | "utf8" | "utf-8" | "base64") {
        return err(format!("unknown encoding '{enc}'"));
    }
    let len = a.length.unwrap_or(READ_DEFAULT).clamp(1, READ_MAX);
    // In auto mode a plain read from offset 0 fetches enough to return a whole
    // image; non-image content is still trimmed to `len` below.
    let fetch = if enc == "auto" && a.offset == 0 && a.length.is_none() { IMAGE_MAX } else { len };
    let p = sh_quote(&a.path);
    let cmd = format!(
        "set -e; {}echo \"META $(stat -L -c '%s|%A|%U:%G|%y' -- {p} 2>/dev/null || wc -c < {p})\" >&2; \
         tail -c +{} -- {p} | head -c {fetch}",
        checks(&p, false),
        a.offset + 1
    );
    let (run, mut data, errs) = run_collect(app, target, cmd, a.sudo, None, fetch as usize).await;
    if !succeeded(&run) {
        return failure(&run, "read", &errs);
    }
    let meta = errs.lines().find_map(|l| l.strip_prefix("META ")).unwrap_or("").trim().to_string();
    let mut f = meta.split('|');
    let size: Option<u64> = f.next().and_then(|v| v.trim().parse().ok());
    let rest: Vec<&str> = f.collect();
    let header = |n: u64, eof: bool| {
        let mut t = format!(
            "[{}] {} — bytes {}..{} of {}{}",
            run.target.alias,
            a.path,
            a.offset,
            a.offset + n,
            size.map(|v| v.to_string()).unwrap_or("?".into()),
            if eof { " (EOF)".to_string() } else { format!(" (next_offset={})", a.offset + n) }
        );
        if !rest.is_empty() {
            let _ = write!(t, "\n{}", rest.join("  "));
        }
        t
    };

    // Whole image -> image content block the model can look at.
    let whole = a.offset == 0 && size.is_some_and(|sz| sz == data.len() as u64);
    if enc == "auto" && whole {
        if let Some(mime) = image_mime(&data) {
            let n = data.len() as u64;
            let mut out = ok(format!("{}\n--- image ({mime}, {n} bytes) attached ---", header(n, true)));
            out.image = Some((mime.to_string(), base64::engine::general_purpose::STANDARD.encode(&data)));
            return out;
        }
    }
    let image_note = if enc == "auto" && a.offset == 0 && image_mime(&data).is_some() {
        format!(" — image larger than {} MiB, returned as base64 chunks", IMAGE_MAX / 1024 / 1024)
    } else {
        String::new()
    };
    data.truncate(len as usize);
    let n = data.len() as u64;
    let eof = size.is_none_or(|sz| a.offset + n >= sz);
    let as_text = match enc {
        "base64" => None,
        "utf8" | "utf-8" => Some(String::from_utf8_lossy(&data).into_owned()),
        _ if !image_note.is_empty() => None,
        _ => std::str::from_utf8(&data).ok().filter(|t| !t.contains('\0')).map(str::to_string),
    };
    let mut t = header(n, eof);
    match as_text {
        Some(txt) => {
            let _ = write!(t, "\n--- utf8 ---\n{txt}");
        }
        None => {
            let _ = write!(
                t,
                "\n--- base64 ({n} bytes{}{image_note}) ---\n{}",
                if enc == "auto" && image_note.is_empty() { "; not valid UTF-8 text" } else { "" },
                base64::engine::general_purpose::STANDARD.encode(&data)
            );
        }
    }
    ok(t)
}

// ---------------------------------------------------------------- edit_file

#[derive(Deserialize)]
pub struct EditArgs {
    hostname: String,
    path: String,
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
    #[serde(default)]
    sudo: bool,
    #[serde(default)]
    username: Option<String>,
}

fn line_of(text: &str, byte: usize) -> usize {
    text[..byte].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Numbered context lines around a byte range of `text`.
fn context(text: &str, start: usize, end: usize, around: usize) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let first = line_of(text, start);
    let last = line_of(text, end.max(start));
    let lo = first.saturating_sub(around).max(1);
    let hi = (last + around).min(lines.len());
    let mut out = String::new();
    for ln in lo..=hi {
        let mark = if ln >= first && ln <= last { '>' } else { ' ' };
        let _ = writeln!(out, "{mark}{ln:>5}  {}", lines[ln - 1]);
    }
    out
}

pub async fn edit_file(app: &Arc<AppState>, args: Value) -> ToolOut {
    let a: EditArgs = match parse(args) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let target = match app.pool.resolve(&a.hostname, a.username.as_deref()) {
        Ok(t) => t,
        Err(e) => return err(format!("{e:#}")),
    };
    if a.old_string.is_empty() {
        return err("old_string is empty (use write_file to create or overwrite a file)");
    }
    if a.old_string == a.new_string {
        return err("old_string and new_string are identical; nothing to do");
    }
    let p = sh_quote(&a.path);

    // 1. Read the current content plus a checksum used as a change guard.
    let read_cmd = format!(
        "set -e; {}sz=$(wc -c < {p}); [ \"$sz\" -le {EDIT_MAX} ] || {{ echo \"file is $sz bytes; edit_file limit is {EDIT_MAX}\" >&2; exit 6; }}; \
         echo \"META $(sha256sum < {p} | cut -d' ' -f1)\" >&2; cat -- {p}",
        checks(&p, true)
    );
    let (run, data, errs) = run_collect(app, target.clone(), read_cmd, a.sudo, None, EDIT_MAX as usize + 1).await;
    if !succeeded(&run) {
        return failure(&run, "edit (read)", &errs);
    }
    let Some(sha) = errs.lines().find_map(|l| l.strip_prefix("META ")).map(|s| s.trim().to_string()) else {
        return err("edit: could not checksum the file (sha256sum missing?)");
    };
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(format!("edit: unexpected checksum output {sha:?}"));
    }
    let Ok(text) = String::from_utf8(data) else {
        return err("edit: file is not valid UTF-8 text; edit_file only edits text files");
    };
    if text.contains('\0') {
        return err("edit: file contains NUL bytes (binary); edit_file only edits text files");
    }

    // 2. Locate matches.
    let hits: Vec<usize> = text.match_indices(&a.old_string).map(|(i, _)| i).collect();
    if hits.is_empty() {
        let hint = if text.contains(a.old_string.trim()) {
            " (it does match after trimming leading/trailing whitespace — check indentation and line endings)"
        } else if text.contains("\r\n") && a.old_string.contains('\n') && !a.old_string.contains("\r\n") {
            " (the file uses CRLF line endings)"
        } else {
            ""
        };
        return err(format!("edit: old_string not found in {}{hint}. Nothing was changed.", a.path));
    }
    if hits.len() > 1 && !a.replace_all {
        let lines: Vec<String> = hits.iter().take(10).map(|&i| line_of(&text, i).to_string()).collect();
        return err(format!(
            "edit: old_string matches {} times (lines {}{}). Add surrounding context to make it unique, or pass replace_all=true. Nothing was changed.",
            hits.len(),
            lines.join(", "),
            if hits.len() > 10 { ", …" } else { "" }
        ));
    }

    // 3. Build the new content, remembering where each replacement landed.
    let mut out = String::with_capacity(text.len() + a.new_string.len() * hits.len());
    let mut spans = Vec::new();
    let mut last = 0;
    for &i in &hits {
        out.push_str(&text[last..i]);
        let s = out.len();
        out.push_str(&a.new_string);
        spans.push((s, out.len()));
        last = i + a.old_string.len();
    }
    out.push_str(&text[last..]);
    let expected = out.len();

    // 4. Write back in place (keeps inode, owner, mode) iff unchanged since the read.
    let write_cmd = format!(
        "set -e; cur=$(sha256sum < {p} | cut -d' ' -f1); \
         [ \"$cur\" = \"{sha}\" ] || {{ echo 'file changed since it was read; nothing written — re-run edit_file' >&2; exit 5; }}; \
         cat > {p}; wc -c < {p}"
    );
    let (wrun, wout, werrs) = run_collect(app, target, write_cmd, a.sudo, Some(out.clone().into_bytes()), 64).await;
    if !succeeded(&wrun) {
        return failure(&wrun, "edit (write)", &werrs);
    }
    let on_disk: Option<usize> = String::from_utf8_lossy(&wout).trim().parse().ok();
    let verdict = match on_disk {
        Some(n) if n == expected => "verified".to_string(),
        Some(n) => format!("SIZE MISMATCH: expected {expected}, file has {n}"),
        None => "could not verify size".to_string(),
    };
    let mut t = format!(
        "[{}] {}: replaced {} occurrence{} — file now {} bytes ({verdict})",
        wrun.target.alias,
        a.path,
        hits.len(),
        if hits.len() == 1 { "" } else { "s" },
        on_disk.map(|n| n.to_string()).unwrap_or("?".into())
    );
    for (k, &(s, e)) in spans.iter().take(3).enumerate() {
        let _ = write!(t, "\n--- change {} ---\n{}", k + 1, context(&out, s, e.saturating_sub(1).max(s), 2).trim_end());
    }
    if spans.len() > 3 {
        let _ = write!(t, "\n… and {} more", spans.len() - 3);
    }
    ok(t)
}
