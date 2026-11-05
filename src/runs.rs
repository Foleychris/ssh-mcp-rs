//! Command runs: each execution is a `Run` with an id, retained output, and a
//! status that can be awaited (sync), polled (async), or cancelled.

use crate::config::Config;
use crate::ssh::{Pool, Target};
use anyhow::Result;
use russh::ChannelMsg;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Semaphore, watch};
use tokio::time::sleep_until;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const PID_MARKER: &[u8] = b"\x1eSSHMCP_PID=";
/// After exit-status arrives, how long to wait for the channel to close before
/// detaching (a backgrounded child holding stdout open would otherwise hang us).
const EXIT_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    Running,
    Exited,
    Failed,
    Cancelled,
    TimedOut,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Running => "running",
            Status::Exited => "exited",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
            Status::TimedOut => "timed_out",
        }
    }
    pub fn terminal(self) -> bool {
        !matches!(self, Status::Queued | Status::Running)
    }
}

// ---------------------------------------------------------------- output buffer

pub struct OutBuf {
    head: Vec<u8>,
    head_cap: usize,
    /// Absolute offset of data[0].
    base: u64,
    data: Vec<u8>,
    cap: usize,
    pub total: u64,
}

impl OutBuf {
    fn new(cap: usize) -> Self {
        Self {
            head: Vec::new(),
            head_cap: 16 * 1024,
            base: 0,
            data: Vec::new(),
            cap,
            total: 0,
        }
    }

    fn push(&mut self, b: &[u8]) {
        if self.head.len() < self.head_cap {
            let n = (self.head_cap - self.head.len()).min(b.len());
            self.head.extend_from_slice(&b[..n]);
        }
        self.data.extend_from_slice(b);
        self.total += b.len() as u64;
        if self.data.len() > self.cap + self.cap / 4 {
            let drop = self.data.len() - self.cap;
            self.data.drain(..drop);
            self.base += drop as u64;
        }
    }

    /// Release spare capacity once a run has finished.
    fn shrink(&mut self) {
        self.data.shrink_to_fit();
        self.head.shrink_to_fit();
    }

    /// Bytes currently held in memory.
    pub fn held(&self) -> usize {
        self.data.len() + self.head.len()
    }

    /// Bytes dropped from the retained window (oldest output).
    pub fn dropped(&self) -> u64 {
        self.base
    }

    /// Read up to `max` bytes starting at absolute `off`. Returns the actual
    /// start offset (may be later than requested if those bytes were dropped).
    pub fn read_from(&self, off: u64, max: usize) -> (u64, &[u8]) {
        let start = off.max(self.base).min(self.total);
        let i = (start - self.base) as usize;
        let j = (i + max).min(self.data.len());
        (start, &self.data[i..j])
    }

    /// Head + tail view capped at roughly `limit` bytes.
    pub fn view(&self, limit: usize, param: &str) -> String {
        if self.base == 0 && self.data.len() <= limit {
            return String::from_utf8_lossy(&self.data).into_owned();
        }
        let h = (limit / 4).min(self.head.len());
        let t = (limit - h).min(self.data.len());
        let tail_start = self.total - t as u64;
        if tail_start <= h as u64 && self.base == 0 {
            return String::from_utf8_lossy(&self.data).into_owned();
        }
        let omitted = tail_start.saturating_sub(h as u64);
        let mut s = String::from_utf8_lossy(&self.head[..h]).into_owned();
        if self.base > h as u64 {
            s.push_str(&format!(
                "\n…[{omitted} bytes omitted; bytes {h}..{} exceeded the retention window and are gone; \
                 retained output starts at get_run {param}={}]…\n",
                self.base, self.base
            ));
        } else {
            s.push_str(&format!(
                "\n…[{omitted} bytes omitted — read them with get_run {param}={h}]…\n"
            ));
        }
        s.push_str(&String::from_utf8_lossy(&self.data[self.data.len() - t..]));
        s
    }
}

// ---------------------------------------------------------------- run

pub struct RunState {
    pub status: Status,
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub error: Option<String>,
    pub note: Option<String>,
    pub pid: Option<u32>,
    pub started: Option<Instant>,
    pub finished: Option<Instant>,
    pub stdout: OutBuf,
    pub stderr: OutBuf,
    /// A cancel/timeout tried to signal the process but its pid was never captured.
    pub unkillable: bool,
    pid_scan: Option<Vec<u8>>,
}

pub struct Run {
    pub id: String,
    pub target: Target,
    pub command: String,
    pub sudo: bool,
    pub created_at: SystemTime,
    pub created: Instant,
    pub timeout: Option<Duration>,
    st: Mutex<RunState>,
    done_tx: watch::Sender<bool>,
    cancel: CancellationToken,
}

impl Run {
    pub fn state(&self) -> std::sync::MutexGuard<'_, RunState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_done(&self) -> bool {
        *self.done_tx.borrow()
    }

    /// Wait up to `d` for completion. Returns true if finished.
    pub async fn wait(&self, d: Duration) -> bool {
        let mut rx = self.done_tx.subscribe();
        if *rx.borrow() {
            return true;
        }
        matches!(
            tokio::time::timeout(d, rx.wait_for(|v| *v)).await,
            Ok(Ok(_))
        )
    }

    pub fn elapsed(&self) -> Duration {
        let s = self.state();
        match (s.started, s.finished) {
            (Some(a), Some(b)) => b - a,
            (Some(a), None) => a.elapsed(),
            _ => Duration::ZERO,
        }
    }

    fn push_out(&self, b: &[u8]) {
        self.state().stdout.push(b);
    }

    fn push_err(&self, b: &[u8]) {
        let mut s = self.state();
        let Some(mut scan) = s.pid_scan.take() else {
            s.stderr.push(b);
            return;
        };
        scan.extend_from_slice(b);
        // The wrapper prints the marker first, but a login shell may print
        // something (e.g. from ~/.bashrc) before it, so search the first 4 KiB.
        let found = scan
            .windows(PID_MARKER.len())
            .position(|w| w == PID_MARKER)
            .and_then(|i| scan[i..].iter().position(|&c| c == b'\n').map(|nl| (i, i + nl)));
        if let Some((i, nl)) = found {
            s.pid = std::str::from_utf8(&scan[i + PID_MARKER.len()..nl])
                .ok()
                .and_then(|v| v.trim().parse().ok());
            let mut rest = scan[..i].to_vec();
            rest.extend_from_slice(&scan[nl + 1..]);
            s.stderr.push(&rest);
        } else if scan.len() > 4096 {
            s.stderr.push(&scan); // give up: no marker
        } else {
            s.pid_scan = Some(scan);
        }
    }
}

pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Wrap a command so the remote shell reports its pid (= process group, since
/// sshd makes the session child a session leader) and then execs the user's
/// login shell on the real command. This lets us kill the whole group later.
fn wrap(cmd: &str, sudo: bool) -> String {
    let sudo = if sudo { "sudo -n -- " } else { "" };
    format!(
        "printf '\\036SSHMCP_PID=%s\\n' \"$$\" >&2; exec {sudo}\"${{SHELL:-/bin/sh}}\" -c {}",
        sh_quote(cmd)
    )
}

fn new_id(n: u64) -> String {
    let r = std::collections::hash_map::RandomState::new().build_hasher().finish();
    format!("r{n}-{:06x}", r & 0xff_ffff)
}

// ---------------------------------------------------------------- manager

/// Runs started while serving one request. The stdio transport scopes each
/// `tools/call` in [`RUN_SINK`] so `notifications/cancelled` can stop the runs
/// that request started. A tool call starts at most a couple of runs.
#[derive(Default)]
pub struct RequestRuns {
    pub ids: Vec<String>,
    /// The client cancelled the request: runs it starts from now on are
    /// cancelled immediately (they never execute).
    pub cancelled: bool,
}

pub type RunSink = Arc<Mutex<RequestRuns>>;

tokio::task_local! {
    pub static RUN_SINK: RunSink;
}

pub struct Runs {
    pool: Arc<Pool>,
    cfg: Arc<Config>,
    map: Mutex<HashMap<String, Arc<Run>>>,
    sem: Arc<Semaphore>,
    counter: AtomicU64,
}

pub struct StartOpts {
    pub sudo: bool,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

impl Runs {
    pub fn new(pool: Arc<Pool>, cfg: Arc<Config>) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(cfg.limits.max_concurrent_runs)),
            pool,
            cfg,
            map: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(1),
        })
    }

    pub fn start(
        self: &Arc<Self>,
        target: Target,
        command: String,
        o: StartOpts,
    ) -> std::result::Result<Arc<Run>, String> {
        let pending = self.active_count();
        if pending >= self.cfg.limits.max_pending_runs {
            warn!(target: "audit", pending, host = %target.alias, "run refused: too many pending runs");
            return Err(format!(
                "too many queued/running commands ({pending}); wait for some to finish or cancel_run them"
            ));
        }
        let cap = self.cfg.limits.retained_output_bytes;
        let (done_tx, _) = watch::channel(false);
        let run = Arc::new(Run {
            id: new_id(self.counter.fetch_add(1, Ordering::Relaxed)),
            target,
            command,
            sudo: o.sudo,
            created_at: SystemTime::now(),
            created: Instant::now(),
            timeout: o.timeout,
            st: Mutex::new(RunState {
                status: Status::Queued,
                exit_code: None,
                signal: None,
                error: None,
                note: None,
                pid: None,
                started: None,
                finished: None,
                stdout: OutBuf::new(cap),
                stderr: OutBuf::new(cap),
                unkillable: false,
                pid_scan: Some(Vec::new()),
            }),
            done_tx,
            cancel: CancellationToken::new(),
        });
        self.map.lock().unwrap().insert(run.id.clone(), run.clone());
        let cancelled = RUN_SINK
            .try_with(|s| {
                let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
                s.ids.push(run.id.clone());
                s.cancelled
            })
            .unwrap_or(false);
        if cancelled {
            run.cancel.cancel();
        }
        info!(target: "audit", run = %run.id, host = %run.target.alias, user = %run.target.user,
              sudo = run.sudo, cmd = ?truncate(&run.command, 2000), "run started");
        let me = self.clone();
        let r = run.clone();
        tokio::spawn(async move { me.drive(r, o.stdin).await });
        Ok(run)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Run>> {
        self.map.lock().unwrap().get(id.trim()).cloned()
    }

    pub fn list(&self) -> Vec<Arc<Run>> {
        let mut v: Vec<_> = self.map.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|r| std::cmp::Reverse(r.created));
        v
    }

    pub fn cancel(&self, run: &Run) {
        run.cancel.cancel();
    }

    pub fn active_count(&self) -> usize {
        self.map.lock().unwrap().values().filter(|r| !r.is_done()).count()
    }

    pub fn spawn_reaper(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                me.reap();
            }
        });
    }

    fn reap(&self) {
        let keep = Duration::from_secs(self.cfg.limits.retain_finished_secs);
        let mut m = self.map.lock().unwrap();
        m.retain(|_, r| {
            let s = r.state();
            !(r.is_done() && s.finished.is_some_and(|f| f.elapsed() > keep))
        });
        let mut done: Vec<(Instant, String)> = m
            .values()
            .filter(|r| r.is_done())
            .map(|r| (r.created, r.id.clone()))
            .collect();
        done.sort();
        let max = self.cfg.limits.max_finished_runs;
        let mut drop_n = done.len().saturating_sub(max);
        // Memory budget across finished runs: evict oldest until under it.
        let budget = self.cfg.limits.retained_budget_bytes;
        let held = |id: &String| m.get(id).map(|r| { let s = r.state(); s.stdout.held() + s.stderr.held() }).unwrap_or(0);
        let mut total: usize = done.iter().map(|(_, id)| held(id)).sum();
        for (_, id) in done.iter().take(drop_n) {
            total -= held(id);
        }
        while total > budget && drop_n < done.len() {
            total -= held(&done[drop_n].1);
            drop_n += 1;
        }
        if drop_n > 0 {
            info!(evicted = drop_n, retained_bytes = total, "reaped finished runs");
        }
        for (_, id) in done.iter().take(drop_n) {
            m.remove(id);
        }
    }

    /// Run the reaper immediately (used when a large run finishes).
    fn reap_soon(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move { me.reap() });
    }

    async fn drive(self: Arc<Self>, run: Arc<Run>, stdin: Option<Vec<u8>>) {
        // Host channel first, then a global slot: a run waiting on a busy host
        // must not hold a global slot (that would starve runs to other hosts).
        // Both waits honour cancel_run, and the status stays Queued until both
        // are held, so a cancelled queued run never executes.
        let opened = tokio::select! {
            r = self.pool.open_channel(&run.target, false) => Some(r),
            _ = run.cancel.cancelled() => None,
        };
        let (lease, ch) = match opened {
            None => return self.finish(&run, Some(Status::Cancelled), Some("cancelled while queued".into())),
            Some(Err(e)) => return self.finish(&run, Some(Status::Failed), Some(format!("{e:#}"))),
            Some(Ok(v)) => v,
        };
        let permit = tokio::select! {
            p = self.sem.clone().acquire_owned() => p.ok(),
            _ = run.cancel.cancelled() => None,
        };
        if permit.is_none() || run.cancel.is_cancelled() {
            drop(ch);
            drop(lease);
            return self.finish(&run, Some(Status::Cancelled), Some("cancelled while queued".into()));
        }
        {
            let mut s = run.state();
            s.status = Status::Running;
            s.started = Some(Instant::now());
        }
        let res = self.drive_inner(&run, ch, stdin).await;
        drop(lease);
        let (status, err) = match res {
            Ok(st) => (st, None),
            Err(e) => (Some(Status::Failed), Some(format!("{e:#}"))),
        };
        self.finish(&run, status, err);
        drop(permit);
        let big = { let s = run.state(); s.stdout.held() + s.stderr.held() > 16 * 1024 * 1024 };
        if big {
            self.reap_soon();
        }
    }

    fn finish(&self, run: &Run, status: Option<Status>, err: Option<String>) {
        {
            let mut s = run.state();
            // Flush a partially-scanned stderr prefix.
            if let Some(scan) = s.pid_scan.take() {
                s.stderr.push(&scan);
            }
            s.status = match status {
                Some(st) => st,
                None if s.exit_code.is_some() || s.signal.is_some() => Status::Exited,
                None => {
                    s.error.get_or_insert_with(|| "channel closed without exit status".into());
                    Status::Failed
                }
            };
            if let Some(e) = err {
                s.error = Some(e);
            }
            s.finished = Some(Instant::now());
            s.stdout.shrink();
            s.stderr.shrink();
            if s.started.is_none() {
                s.started = s.finished;
            }
            info!(target: "audit", run = %run.id, host = %run.target.alias, status = s.status.as_str(),
                  exit = ?s.exit_code, secs = run.created.elapsed().as_secs(),
                  out = s.stdout.total, err = s.stderr.total, "run finished");
        }
        run.done_tx.send_replace(true);
    }

    fn kill(&self, run: &Run, sig: &'static str) {
        let pid = run.state().pid;
        let Some(pid) = pid else {
            warn!(target: "audit", run = %run.id, sig, "no pid known; cannot signal — remote process may still be running");
            let mut s = run.state();
            s.unkillable = true;
            s.note = Some("could not signal the process (its pid was never captured); it may still be running on the host".into());
            return;
        };
        let sudo = if run.sudo { "sudo -n " } else { "" };
        let cmd = format!(
            "{sudo}kill -s {sig} -- -{pid} 2>/dev/null || {sudo}kill -s {sig} {pid} 2>/dev/null || {sudo}kill -{sig} {pid}"
        );
        let pool = self.pool.clone();
        let t = run.target.clone();
        let id = run.id.clone();
        tokio::spawn(async move {
            match pool.exec_collect(&t, &cmd, Duration::from_secs(15), true).await {
                Ok((code, _, err)) => {
                    info!(run = %id, sig, ?code, err = %err.trim(), "signal sent")
                }
                Err(e) => warn!(run = %id, sig, "kill failed: {e:#}"),
            }
        });
    }

    /// Returns Some(status) to force a terminal status, None to derive it.
    async fn drive_inner(
        &self,
        run: &Run,
        ch: russh::Channel<russh::client::Msg>,
        stdin: Option<Vec<u8>>,
    ) -> Result<Option<Status>> {
        ch.exec(true, wrap(&run.command, run.sudo)).await?;
        let (mut rd, wr) = ch.split();

        let writer = async {
            if let Some(data) = stdin.as_deref() {
                wr.data(data).await?;
            }
            wr.eof().await
        };
        tokio::pin!(writer);
        let mut writer_done = false;

        let deadline = run.timeout.map(|d| tokio::time::Instant::now() + d);
        let mut forced: Option<Status> = None;
        let mut kill_stage = 0u8;
        let mut kill_at: Option<tokio::time::Instant> = None;
        let mut exit_at: Option<tokio::time::Instant> = None;

        loop {
            let timer = [
                if kill_stage == 0 { deadline } else { None },
                kill_at,
                exit_at.map(|t| t + EXIT_GRACE),
            ]
            .into_iter()
            .flatten()
            .min();

            tokio::select! {
                msg = rd.wait() => match msg {
                    None | Some(ChannelMsg::Close) => break,
                    Some(ChannelMsg::Data { data }) => run.push_out(&data),
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        if ext == 1 { run.push_err(&data) } else { run.push_out(&data) }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        run.state().exit_code = Some(exit_status);
                        exit_at.get_or_insert_with(tokio::time::Instant::now);
                    }
                    Some(ChannelMsg::Failure) if exit_at.is_none() && run.state().pid.is_none() => {
                        // sshd refused the exec request (e.g. MaxSessions, ForceCommand).
                        let _ = wr.close().await;
                        anyhow::bail!("the SSH server refused to execute the command");
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, error_message, .. }) => {
                        let mut s = run.state();
                        s.signal = Some(format!("{signal_name:?}"));
                        if !error_message.is_empty() { s.note = Some(error_message); }
                        exit_at.get_or_insert_with(tokio::time::Instant::now);
                    }
                    Some(_) => {}
                },
                r = &mut writer, if !writer_done => {
                    writer_done = true;
                    if let Err(e) = r { warn!(run = %run.id, "stdin write failed: {e}"); }
                }
                _ = run.cancel.cancelled(), if kill_stage == 0 => {
                    forced = Some(Status::Cancelled);
                    kill_stage = 1;
                    self.kill(run, "TERM");
                    kill_at = Some(tokio::time::Instant::now() + KILL_GRACE);
                }
                _ = sleep_until(timer.unwrap_or_else(tokio::time::Instant::now)), if timer.is_some() => {
                    let now = tokio::time::Instant::now();
                    if exit_at.is_some_and(|t| now >= t + EXIT_GRACE) {
                        run.state().note = Some(
                            "process exited but its output pipe was still held open \
                             (likely a backgrounded child); detached".into());
                        let _ = wr.close().await;
                        break;
                    }
                    match kill_stage {
                        0 if deadline.is_some_and(|d| now >= d) => {
                            forced = Some(Status::TimedOut);
                            kill_stage = 1;
                            self.kill(run, "TERM");
                            kill_at = Some(now + KILL_GRACE);
                        }
                        1 if kill_at.is_some_and(|k| now >= k) => {
                            kill_stage = 2;
                            self.kill(run, "KILL");
                            kill_at = Some(now + KILL_GRACE);
                        }
                        2 if kill_at.is_some_and(|k| now >= k) => {
                            run.state().note = Some("process did not die after SIGKILL; channel closed".into());
                            let _ = wr.close().await;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(forced)
    }
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    format!("{}…", &s[..i])
}
