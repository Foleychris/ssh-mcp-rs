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

/// Validate a path argument: absolute, no NUL (sshd rejects NUL in exec strings
/// and would drop the whole shared connection).
pub(crate) fn check_path(path: &str) -> Result<(), ToolOut> {
    if path.contains('\0') {
        return Err(err("path contains a NUL byte"));
    }
    if !path.starts_with('/') {
        return Err(err(format!("path must be absolute (got {path:?})")));
    }
    Ok(())
}

/// Shell step that copies the staged upload (`$tmp`) onto the target `p`
/// (already shell-quoted). `cat tmp > file` keeps the target's inode, owner and
/// mode, but it truncates the target first: if the copy then fails partway
/// (disk full, I/O error) the target may be partial, so the staged copy is
/// kept and the error says where it is.
pub(crate) fn copy_staged(p: &str, append: bool) -> String {
    format!(
        "if ! cat \"$tmp\" {} {p}; then trap - EXIT; \
         echo \"FILE MAY BE PARTIAL: writing the target failed partway; the complete new content is saved at $tmp\" >&2; exit 8; fi; ",
        if append { ">>" } else { ">" }
    )
}

/// Run a helper command to completion and return (run, stdout bytes, stderr text).
/// If it hasn't finished within the wait, it is cancelled — a file operation
/// must never report failure and then quietly happen later.
pub(crate) async fn run_collect(
    app: &Arc<AppState>,
    target: crate::ssh::Target,
    cmd: String,
    sudo: bool,
    stdin: Option<Vec<u8>>,
    max_out: usize,
) -> Result<(Arc<Run>, Vec<u8>, String), ToolOut> {
    let run = app
        .runs
        .start(target, cmd, StartOpts { sudo, stdin, timeout: Some(Duration::from_secs(120)) })
        .map_err(err)?;
    if !run.wait(Duration::from_secs(130)).await {
        app.runs.cancel(&run);
        run.wait(Duration::from_secs(12)).await;
        return Err(err(format!(
            "[{}] file operation did not finish within 130s and was cancelled ({}); it most likely did not run, but if it was cancelled during the final copy the file may be partial — check the file before retrying",
            run.target.alias,
            status_line(&run)
        )));
    }
    let s = run.state();
    if s.stdout.dropped() > 0 {
        drop(s);
        return Err(err("output exceeded the server's retention window; refusing to use a partial read"));
    }
    let out = s.stdout.read_from(0, max_out).1.to_vec();
    let errs = String::from_utf8_lossy(s.stderr.read_from(0, 16 * 1024).1).into_owned();
    drop(s);
    Ok((run, out, errs))
}

pub(crate) fn succeeded(run: &Run) -> bool {
    let s = run.state();
    s.status == Status::Exited && s.exit_code == Some(0)
}

pub(crate) fn failure(run: &Run, what: &str, errs: &str) -> ToolOut {
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
    if let Err(e) = check_path(&a.path) {
        return e;
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
    let (run, mut data, errs) = match run_collect(app, target, cmd, a.sudo, None, fetch as usize).await {
        Ok(v) => v,
        Err(e) => return e,
    };
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
    // A chunk boundary may split a multi-byte character: in auto mode, end the
    // chunk at the last complete character and let next_offset resume there.
    if enc == "auto" && image_note.is_empty() {
        if let Err(e) = std::str::from_utf8(&data) {
            let at_eof = size.is_some_and(|sz| a.offset + data.len() as u64 >= sz);
            if e.error_len().is_none() && !at_eof && e.valid_up_to() > 0 {
                data.truncate(e.valid_up_to());
            }
        }
    }
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

const MAX_EDITS: usize = 200;
/// Cap on the whole change report returned to the caller.
const REPORT_MAX: usize = 16 * 1024;
/// Bytes of a single line shown in the change report.
const LINE_SHOW: usize = 200;
/// Lines shown per change block.
const BLOCK_LINES: usize = 20;

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
}

#[derive(Deserialize)]
pub struct EditArgs {
    hostname: String,
    path: String,
    /// Single-edit form.
    #[serde(default)]
    old_string: Option<String>,
    #[serde(default)]
    new_string: Option<String>,
    #[serde(default)]
    replace_all: bool,
    /// Multi-edit form: applied in order, all-or-nothing.
    #[serde(default)]
    edits: Option<Vec<Edit>>,
    #[serde(default)]
    sudo: bool,
    #[serde(default)]
    username: Option<String>,
}

/// Turn the two argument forms into one edit list, rejecting ambiguous input.
fn select_edits(
    edits: Option<Vec<Edit>>,
    old: Option<String>,
    new: Option<String>,
    replace_all: bool,
) -> Result<Vec<Edit>, String> {
    let list = match (edits, old, new) {
        (Some(_), None, None) if replace_all => {
            return Err("`replace_all` goes on each entry of `edits`, not at the top level".into());
        }
        (Some(list), None, None) => list,
        (None, Some(o), Some(n)) => vec![Edit { old_string: o, new_string: n, replace_all }],
        (Some(_), _, _) => return Err("pass either `edits` or `old_string`/`new_string`, not both".into()),
        _ => return Err("pass `old_string` and `new_string`, or an `edits` list".into()),
    };
    if list.is_empty() {
        return Err("`edits` is empty".into());
    }
    if list.len() > MAX_EDITS {
        return Err(format!("too many edits in one call ({}; max {MAX_EDITS})", list.len()));
    }
    Ok(list)
}

fn line_of(text: &str, byte: usize) -> usize {
    text.as_bytes()[..byte.min(text.len())].iter().filter(|&&b| b == b'\n').count() + 1
}

fn floor_cb(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_cb(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// At most LINE_SHOW bytes of `line`, starting a little before byte `col`.
fn clip(line: &str, col: usize) -> String {
    if line.len() <= LINE_SHOW {
        return line.to_string();
    }
    let a = floor_cb(line, col.saturating_sub(LINE_SHOW / 4));
    let b = ceil_cb(line, a + LINE_SHOW);
    let mut s = String::new();
    if a > 0 {
        let _ = write!(s, "…[{a} bytes] ");
    }
    s.push_str(&line[a..b]);
    if b < line.len() {
        let _ = write!(s, " …[{} more bytes]", line.len() - b);
    }
    s
}

/// Numbered context lines around a byte range of `text`; long lines are
/// clipped and a block shows at most BLOCK_LINES lines.
fn context(text: &str, start: usize, end: usize, around: usize) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let start = start.min(text.len());
    let first = line_of(text, start);
    let last = line_of(text, end.max(start));
    let lo = first.saturating_sub(around).max(1);
    let hi = (last + around).min(lines.len());
    let line_start = text.as_bytes()[..start].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let col = start - line_start;
    let mut out = String::new();
    for (shown, ln) in (lo..=hi).enumerate() {
        if shown == BLOCK_LINES {
            let _ = writeln!(out, "       … ({} more lines)", hi - ln + 1);
            break;
        }
        let mark = if ln >= first && ln <= last { '>' } else { ' ' };
        let _ = writeln!(out, "{mark}{ln:>5}  {}", clip(lines[ln - 1], if ln == first { col } else { 0 }));
    }
    out
}

/// A replaced region in the FINAL text: (start, end, 1-based edit number).
type Span = (usize, usize, usize);

fn merge(a: Vec<Span>, b: Vec<Span>) -> Vec<Span> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] <= b[j] {
            out.push(a[i]);
            i += 1;
        } else {
            out.push(b[j]);
            j += 1;
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// Apply edits in order to `text`. Each edit sees the result of the previous
/// ones. Any failure aborts the whole batch (nothing is written), as does any
/// intermediate result larger than `max` bytes. Returns the new text, the
/// replaced regions in final-text coordinates (sorted), and the total number
/// of replacements. Linear in text size + replacements per edit.
fn apply_edits(text: &str, edits: &[Edit], max: usize) -> Result<(String, Vec<Span>, usize), String> {
    let n = edits.len();
    let label = |k: usize| if n == 1 { String::new() } else { format!("edit {} of {n}: ", k + 1) };
    let mut cur = text.to_string();
    let mut spans: Vec<Span> = Vec::new();
    let mut total = 0;
    for (k, e) in edits.iter().enumerate() {
        if e.old_string.is_empty() {
            return Err(format!("{}old_string is empty (use write_file to create or overwrite a file)", label(k)));
        }
        if e.old_string == e.new_string {
            return Err(format!("{}old_string and new_string are identical", label(k)));
        }
        let hits: Vec<usize> = cur.match_indices(&e.old_string).map(|(i, _)| i).collect();
        if hits.is_empty() {
            let t = e.old_string.trim();
            let hint = if k > 0 && text.contains(&e.old_string) {
                " (it matched the original file, but an earlier edit in this batch changed that text — edits apply in order)"
            } else if !t.is_empty() && t != e.old_string && cur.contains(t) {
                " (it does match after trimming leading/trailing whitespace — check indentation and line endings)"
            } else if cur.contains("\r\n") && e.old_string.contains('\n') && !e.old_string.contains("\r\n") {
                " (the file uses CRLF line endings)"
            } else {
                ""
            };
            return Err(format!("{}old_string not found{hint}", label(k)));
        }
        if hits.len() > 1 && !e.replace_all {
            let lines: Vec<String> = hits.iter().take(10).map(|&i| line_of(&cur, i).to_string()).collect();
            return Err(format!(
                "{}old_string matches {} times (lines {}{}); add surrounding context to make it unique, or set replace_all",
                label(k),
                hits.len(),
                lines.join(", "),
                if hits.len() > 10 { ", …" } else { "" }
            ));
        }
        let (ol, nl) = (e.old_string.len(), e.new_string.len());
        // Hits never overlap each other, so ol * hits <= cur.len().
        let projected = (cur.len() - ol * hits.len()).saturating_add(nl.saturating_mul(hits.len()));
        if projected > max {
            return Err(format!(
                "{}the result would be {projected} bytes, over edit_file's {max}-byte limit",
                label(k)
            ));
        }
        // Earlier spans (sorted): drop any this edit overwrote, shift the rest
        // by the size change of the hits before them. Both lists are sorted, so
        // one forward pass suffices.
        let d = nl as isize - ol as isize;
        let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
        let mut idx = 0;
        for &(s, en, id) in &spans {
            while idx < hits.len() && hits[idx] + ol <= s {
                idx += 1;
            }
            if idx < hits.len() && hits[idx] < en.max(s + 1) {
                continue; // overwritten by this edit
            }
            let sh = d * idx as isize;
            kept.push(((s as isize + sh) as usize, (en as isize + sh) as usize, id));
        }
        let mut next = String::with_capacity(projected);
        let mut fresh: Vec<Span> = Vec::with_capacity(hits.len());
        let mut last = 0;
        for &i in &hits {
            next.push_str(&cur[last..i]);
            let s = next.len();
            next.push_str(&e.new_string);
            fresh.push((s, next.len(), k + 1));
            last = i + ol;
        }
        next.push_str(&cur[last..]);
        total += hits.len();
        spans = merge(kept, fresh);
        cur = next;
    }
    if cur == text {
        return Err("the edits leave the file unchanged".into());
    }
    Ok((cur, spans, total))
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
    if let Err(e) = check_path(&a.path) {
        return e;
    }
    let edits = match select_edits(a.edits, a.old_string, a.new_string, a.replace_all) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let n_edits = edits.len();
    let p = sh_quote(&a.path);

    // 1. Snapshot the file once, then take size, checksum and content from the
    // snapshot so all three describe the same bytes. The checksum is the change
    // guard for the write.
    let read_cmd = format!(
        "set -e; {}sz=$(wc -c < {p}); [ $((sz)) -le {EDIT_MAX} ] || {{ echo \"file is $((sz)) bytes; edit_file limit is {EDIT_MAX}\" >&2; exit 6; }}; \
         snap=$(mktemp); trap 'rm -f \"$snap\"' EXIT; head -c {lim} -- {p} > \"$snap\"; n=$(wc -c < \"$snap\"); \
         [ $((n)) -le {EDIT_MAX} ] || {{ echo \"file grew past edit_file's {EDIT_MAX}-byte limit while being read\" >&2; exit 6; }}; \
         echo \"META $(sha256sum < \"$snap\" | cut -d' ' -f1) $((n))\" >&2; cat \"$snap\"",
        checks(&p, true),
        lim = EDIT_MAX + 1
    );
    let (run, data, errs) = match run_collect(app, target.clone(), read_cmd, a.sudo, None, EDIT_MAX as usize + 1).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !succeeded(&run) {
        return failure(&run, "edit (read)", &errs);
    }
    let meta = errs.lines().find_map(|l| l.strip_prefix("META ")).unwrap_or("").trim().to_string();
    let mut mf = meta.split_whitespace();
    let sha = mf.next().unwrap_or("").to_string();
    let snap_len: Option<usize> = mf.next().and_then(|v| v.parse().ok());
    if sha.is_empty() {
        return err("edit: could not checksum the file (sha256sum missing?)");
    }
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(format!("edit: unexpected checksum output {sha:?}"));
    }
    if snap_len != Some(data.len()) || data.len() as u64 > EDIT_MAX {
        return err(format!(
            "edit: incomplete read ({} of {} bytes); nothing was changed in {}",
            data.len(),
            snap_len.map(|v| v.to_string()).unwrap_or("?".into()),
            a.path
        ));
    }
    let Ok(text) = String::from_utf8(data) else {
        return err("edit: file is not valid UTF-8 text; edit_file only edits text files");
    };
    if text.contains('\0') {
        return err("edit: file contains NUL bytes (binary); edit_file only edits text files");
    }

    // 2. Apply every edit in memory (off the async workers: it is CPU work);
    // any failure means nothing is written.
    let applied = tokio::task::spawn_blocking(move || apply_edits(&text, &edits, EDIT_MAX as usize)).await;
    let (out, spans, total) = match applied {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return err(format!("edit: {e}. Nothing was changed in {}.", a.path)),
        Err(e) => return err(format!("edit: internal error while applying edits ({e}); nothing was changed in {}", a.path)),
    };
    let expected = out.len();

    // 3. Stage the upload in a temp file and check it arrived complete before the
    // target is touched; only then re-check the guard and copy in place.
    let write_cmd = format!(
        "set -e; tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; n=$(wc -c < \"$tmp\"); \
         [ $((n)) -eq {expected} ] || {{ echo \"incomplete upload ($n of {expected} bytes); file untouched\" >&2; exit 7; }}; \
         cur=$(sha256sum < {p} | cut -d' ' -f1); \
         [ \"$cur\" = \"{sha}\" ] || {{ echo 'file changed since it was read; nothing written — re-run edit_file' >&2; exit 5; }}; \
         {copy}wc -c < {p}",
        copy = copy_staged(&p, false)
    );
    let (wrun, wout, werrs) = match run_collect(app, target, write_cmd, a.sudo, Some(out.clone().into_bytes()), 64).await {
        Ok(v) => v,
        Err(e) => return e,
    };
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
        "[{}] {}: {} edit{}, {} replacement{} — file now {} bytes ({verdict})",
        wrun.target.alias,
        a.path,
        n_edits,
        if n_edits == 1 { "" } else { "s" },
        total,
        if total == 1 { "" } else { "s" },
        on_disk.map(|n| n.to_string()).unwrap_or("?".into())
    );
    const SHOW: usize = 5;
    for &(s, e, k) in spans.iter().take(SHOW) {
        let tag = if n_edits == 1 { String::new() } else { format!(" (edit {k})") };
        let _ = write!(t, "\n--- line {}{tag} ---\n{}", line_of(&out, s), context(&out, s, e.saturating_sub(1).max(s), 2).trim_end());
    }
    if spans.len() > SHOW {
        let _ = write!(t, "\n… and {} more change{}", spans.len() - SHOW, if spans.len() - SHOW == 1 { "" } else { "s" });
    }
    if t.len() > REPORT_MAX {
        let cut = floor_cb(&t, REPORT_MAX);
        t.truncate(cut);
        t.push_str("\n… (change report truncated)");
    }
    if on_disk != Some(expected) {
        return err(t);
    }
    ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    const BIG: usize = 1 << 30;
    fn e(o: &str, n: &str) -> Edit {
        Edit { old_string: o.into(), new_string: n.into(), replace_all: false }
    }
    fn ea(o: &str, n: &str) -> Edit {
        Edit { replace_all: true, ..e(o, n) }
    }
    fn ap(text: &str, edits: &[Edit]) -> Result<(String, Vec<Span>, usize), String> {
        apply_edits(text, edits, BIG)
    }

    #[test]
    fn sequential_and_spans_shift() {
        let (out, spans, total) = ap("a\nb\nc\n", &[e("c", "CCC"), e("a", "AAAA")]).unwrap();
        assert_eq!(out, "AAAA\nb\nCCC\n");
        assert_eq!(total, 2);
        // spans are in final coordinates, sorted
        assert_eq!(&out[spans[0].0..spans[0].1], "AAAA");
        assert_eq!(&out[spans[1].0..spans[1].1], "CCC");
    }

    #[test]
    fn later_edit_sees_earlier_result() {
        let (out, _, _) = ap("x=1", &[e("x=1", "x=2"), e("x=2", "x=3")]).unwrap();
        assert_eq!(out, "x=3");
    }

    #[test]
    fn failure_is_all_or_nothing_and_names_the_edit() {
        let r = ap("a b", &[e("a", "A"), e("zzz", "Z")]);
        assert!(r.unwrap_err().starts_with("edit 2 of 2: old_string not found"));
    }

    #[test]
    fn hint_when_earlier_edit_consumed_text() {
        let r = ap("foo bar", &[e("foo bar", "baz"), e("bar", "qux")]).unwrap_err();
        assert!(r.contains("earlier edit in this batch changed that text"), "{r}");
    }

    #[test]
    fn ambiguous_without_replace_all() {
        let r = ap("p=1\np=1\n", &[e("p=1", "p=2")]).unwrap_err();
        assert!(r.contains("matches 2 times (lines 1, 2)"), "{r}");
        assert_eq!(ap("p=1\np=1\n", &[ea("p=1", "p=2")]).unwrap().0, "p=2\np=2\n");
    }

    #[test]
    fn overwritten_span_is_dropped() {
        let (out, spans, _) = ap("abc", &[e("b", "XYZ"), e("aXYZc", "q")]).unwrap();
        assert_eq!(out, "q");
        assert_eq!(spans, vec![(0, 1, 2)]);
    }

    #[test]
    fn multibyte_context_does_not_panic() {
        let (out, spans, _) = ap("t: x\n", &[e("x", "café — 🙂")]).unwrap();
        assert_eq!(out, "t: café — 🙂\n");
        let s = spans[0];
        let c = context(&out, s.0, s.1.saturating_sub(1).max(s.0), 2);
        assert!(c.contains(">    1  t: café — 🙂"), "{c}");
    }

    #[test]
    fn no_op_batch_rejected() {
        assert!(ap("ab", &[e("a", "z"), e("z", "a")]).is_err());
    }

    #[test]
    fn later_edit_between_replace_all_spans() {
        let (out, spans, _) = ap("x\ny\nx\n", &[ea("x", "XX"), e("y", "")]).unwrap();
        assert_eq!(out, "XX\n\nXX\n");
        assert_eq!(spans, vec![(0, 2, 1), (3, 3, 2), (4, 6, 1)]);
    }

    #[test]
    fn replace_all_hits_on_both_sides_of_a_span() {
        let (out, spans, _) = ap("a b a", &[e("b", "BBB"), ea("a", "zz")]).unwrap();
        assert_eq!(out, "zz BBB zz");
        assert!(spans.contains(&(3, 6, 1)), "{spans:?}");
        assert_eq!(spans.len(), 3);
    }

    #[test]
    fn deletion_span_and_context() {
        let (out, spans, _) = ap("abc", &[e("b", "")]).unwrap();
        assert_eq!(out, "ac");
        assert_eq!(spans, vec![(1, 1, 1)]);
        assert!(context(&out, 1, 1, 2).contains(">    1  ac"));
    }

    #[test]
    fn shrinking_edit_shifts_later_span() {
        let (out, spans, _) = ap("aaaa\nX\n", &[e("X", "Y"), e("aaaa", "a")]).unwrap();
        assert_eq!(out, "a\nY\n");
        assert_eq!(spans, vec![(0, 1, 2), (2, 3, 1)]);
    }

    #[test]
    fn error_labels_name_the_right_edit() {
        let r = ap("a b c", &[e("zz", "y"), e("a", "A"), e("b", "B")]).unwrap_err();
        assert!(r.starts_with("edit 1 of 3: old_string not found"), "{r}");
        let r = ap("a b c", &[e("a", "A"), e("b", "B"), e("zz", "y")]).unwrap_err();
        assert!(r.starts_with("edit 3 of 3: old_string not found"), "{r}");
        let r = ap("a b c", &[e("a", "A"), e("", "x")]).unwrap_err();
        assert!(r.starts_with("edit 2 of 2: old_string is empty"), "{r}");
        let r = ap("a b c", &[e("a", "A"), e("c", "c")]).unwrap_err();
        assert!(r.starts_with("edit 2 of 2: old_string and new_string are identical"), "{r}");
        let r = ap("a b c", &[e("zz", "y")]).unwrap_err();
        assert!(r.starts_with("old_string not found"), "{r}");
    }

    #[test]
    fn ambiguity_created_by_earlier_edit() {
        let r = ap("a b", &[e("a", "b"), e("b", "c")]).unwrap_err();
        assert!(r.starts_with("edit 2 of 2: old_string matches 2 times (lines 1, 1)"), "{r}");
    }

    #[test]
    fn crlf_hint() {
        let r = ap("a\r\nb\r\n", &[e("a\nb", "x")]).unwrap_err();
        assert!(r.contains("CRLF"), "{r}");
    }

    #[test]
    fn whitespace_only_old_string_gets_no_trim_hint() {
        let r = ap("a b", &[e("\t", " ")]).unwrap_err();
        assert!(!r.contains("trimming"), "{r}");
    }

    #[test]
    fn multibyte_at_span_edges() {
        let (out, spans, _) = ap("é\n🙂\n", &[e("🙂", "ü"), e("é", "ab")]).unwrap();
        assert_eq!(out, "ab\nü\n");
        let got: Vec<&str> = spans.iter().map(|&(s, en, _)| &out[s..en]).collect();
        assert_eq!(got, vec!["ab", "ü"]);
    }

    #[test]
    fn size_limit_names_the_edit() {
        let text = "a".repeat(1024);
        let edits: Vec<Edit> = (0..13).map(|_| ea("a", "aa")).collect();
        let r = apply_edits(&text, &edits, 1 << 20).unwrap_err();
        assert!(r.starts_with("edit 11 of 13: the result would be 2097152 bytes"), "{r}");
    }

    #[test]
    fn many_spans_stay_fast() {
        let text = "a\n".repeat(200_000);
        let t0 = std::time::Instant::now();
        let (out, spans, total) = ap(&text, &[ea("a", "b"), ea("\n", "\r\n")]).unwrap();
        assert!(t0.elapsed() < std::time::Duration::from_secs(5), "{:?}", t0.elapsed());
        assert_eq!(out.len(), 600_000);
        assert_eq!((spans.len(), total), (400_000, 400_000));
        assert!(spans.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn context_line_numbers() {
        let text = "1\n2\n3\n4\n5\n6\n";
        let c = context(text, 6, 6, 2);
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines.len(), 5, "{c}");
        assert!(lines[0].ends_with("  2") && lines[4].ends_with("  6"), "{c}");
        let marked: Vec<&&str> = lines.iter().filter(|l| l.starts_with('>')).collect();
        assert_eq!(marked, vec![&">    4  4"]);
    }

    #[test]
    fn long_lines_are_clipped_around_the_change() {
        let text = format!("{}NEEDLE{}", "x".repeat(5000), "y".repeat(5000));
        let (out, spans, _) = ap(&text, &[e("NEEDLE", "FOUND")]).unwrap();
        let s = spans[0];
        let c = context(&out, s.0, s.1 - 1, 2);
        assert!(c.contains("FOUND"), "{c}");
        assert!(c.len() < 400, "{}", c.len());
    }

    #[test]
    fn tall_blocks_are_capped() {
        let big: String = (0..100).map(|i| format!("line {i}\n")).collect();
        let (out, spans, _) = ap("x\n", &[e("x\n", &big)]).unwrap();
        let s = spans[0];
        let c = context(&out, s.0, s.1 - 1, 2);
        assert_eq!(c.lines().count(), BLOCK_LINES + 1, "{c}");
        assert!(c.contains("more lines"));
    }

    #[test]
    fn argument_forms() {
        let one = || Some(vec![e("a", "b")]);
        assert!(select_edits(one(), Some("a".into()), Some("b".into()), false).unwrap_err().contains("not both"));
        assert!(select_edits(one(), None, None, true).unwrap_err().contains("top level"));
        assert_eq!(select_edits(Some(vec![]), None, None, false).unwrap_err(), "`edits` is empty");
        let many: Vec<Edit> = (0..201).map(|_| e("a", "b")).collect();
        assert!(select_edits(Some(many), None, None, false).unwrap_err().contains("too many edits"));
        assert!(select_edits(None, Some("a".into()), None, false).is_err());
        let v = select_edits(None, Some("a".into()), Some("b".into()), true).unwrap();
        assert!(v.len() == 1 && v[0].replace_all);
        assert_eq!(select_edits(one(), None, None, false).unwrap().len(), 1);
    }

    #[test]
    fn unknown_edit_fields_rejected() {
        let r = serde_json::from_value::<Edit>(serde_json::json!({"old_string": "a", "new_string": "b", "replaceAll": true}));
        assert!(r.is_err());
    }
}
