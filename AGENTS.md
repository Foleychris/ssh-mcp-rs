# AGENTS.md — working on ssh-mcp-rs

Read this before changing anything. Then read `README.md` (design, tools, protocol)
and, if you were pointed at one, the proposal under `docs/proposals/`.

## What this is

An MCP server, written in Rust, that runs shell commands and file operations on
remote hosts over SSH. It is a single binary: tokio + axum (HTTP) + russh (SSH
client). MIT licensed, owner Chris Foley.

The owner runs it in production for claude.ai, and the SSH key behind such a
deployment typically has passwordless sudo on the hosts it reaches, so **any
auth bypass, injection or host-key weakness is critical**.

## Layout

| Path | What |
|---|---|
| `src/main.rs` | Startup, axum router, `/healthz`, graceful shutdown |
| `src/config.rs` | TOML config + env overrides, startup validation (token rules, limits) |
| `src/mcp.rs` | MCP Streamable HTTP: auth/Origin gate (middleware), 2026-07-28 stateless + legacy `initialize` eras, SSE for `tools/call`, audit log of calls |
| `src/ssh.rs` | Connection pool (multiplexed channels per connection, per-host semaphores, separate control pool for kills), host resolution (`[hosts]` + ssh_config), host-key verification (fail closed) |
| `src/proxy.rs` | ProxyCommand transport: template splitting and substitution (no shell unless `proxy_shell`), spawning, stderr tail, process-group kill; unit tests |
| `src/sshauth.rs` | Client auth: ssh-agent identities and key files, OpenSSH certificates, capped at 5 offers per connection |
| `src/sshconfig.rs` | `~/.ssh/config` subset parser (Host/Include, HostName/User/Port/IdentityFile/CertificateFile/IdentitiesOnly/ProxyCommand/ProxyJump/HostKeyAlias); unit tests |
| `src/runs.rs` | Run lifecycle: queue → run → finish, output ring buffers, cancel/timeout via remote process-group kill, reaper and memory budget, `sh_quote`, `wrap()` |
| `src/tools.rs` | Tool schemas + handlers (`execute_command`, `get_run`, `list_runs`, `cancel_run`, `write_file`, info tools); `ToolOut` |
| `src/stdio.rs` | stdio transport: newline-delimited JSON-RPC, one stdout writer, `notifications/cancelled`, exit handling (`stdio_on_exit`) |
| `src/fileops.rs` | `read_file`, `edit_file` (multi-edit, all-or-nothing), shared helpers (`run_collect`, `copy_staged`, `check_path`); unit tests |
| `tests/common/` | Shared harness: throwaway sshd + ssh-agent, stdio session helpers |
| `tests/proxy.rs` | Ignored-by-default integration tests through `nc` as a proxy: all tools, proxy_rules, ssh_config ProxyCommand, failures, timeouts, injection |
| `tests/auth.rs` | Ignored-by-default integration tests that start their own sshd + ssh-agent: agent, certificates, passphrase keys, MaxAuthTries cap, ssh_config |
| `tests/stdio.rs` | Ignored-by-default integration test of `--stdio` against a real host (`SSH_MCP_TEST_CONFIG`, `SSH_MCP_TEST_HOST`) |
| `.github/workflows/` | `ci.yml` (fmt, clippy, tests, package, MSRV, integration); `release.yml` (tag-triggered publish, and the Friday Dependabot auto-release via `.github/scripts/dependabot-release.sh`) |
| `Dockerfile` | Multi-stage build; `cargo test --release` gates the image |

## Build and test

```
cargo build --release
cargo test --release          # unit tests; must pass, the Docker build runs them too
cargo clippy --release --all-targets -- -D warnings   # CI fails on any warning
cargo fmt                     # CI and the pre-commit hook reject unformatted code
```

Enable the pre-commit hook once per clone: `git config core.hooksPath .githooks`.
CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests and `cargo package`, and
builds with the MSRV (Rust 1.89).

Run a dev server on a spare loopback port with your own config:

```
SSH_MCP_LISTEN=127.0.0.1:8013 ./target/release/sshmux-mcp /path/to/config.toml
curl -s 127.0.0.1:8013/healthz
```

For integration tests, write your own
config (see `Config` in `src/config.rs`; unknown keys are rejected) and point
the tests at your server. Never point them at a production instance.

## Rules

1. **Never print secrets**: auth tokens, token files, private keys, AWS
   credentials. That covers chat output, logs, test output, commit messages and
   error strings. Build auth headers into a temp file (`curl -H @file`) instead
   of putting the token in argv.
2. **Don't touch a live deployment** (the owner's production instance,
   its host and its proxy) unless the owner explicitly asks. Develop in a
   git worktree or your own clone, and test on a spare port.
3. **Propose before large or risky changes.** If a proposal doc covers the work,
   follow it. If you must deviate (a different design, an extra dependency, a
   behaviour change it doesn't mention), stop and ask, or record the deviation
   and your reasons in the PR or commit description.
4. **No system Python packages**: no `pip install` outside a venv. Rust crates
   via cargo are fine; prefer well-maintained crates and justify each new one.
5. **Commits**: small and focused, with a message that says why. Identity:
   `Chris Foley <Foleychris@users.noreply.github.com>` unless told otherwise. Don't
   commit work- or employer-specific hostnames, instance IDs, account IDs or
   configs. Use placeholders in examples.
6. **Keep the unit tests gating the build.** New logic that can be tested as a
   pure function gets tests in the same module.

## Security invariants (don't regress these)

- Auth and Origin are checked in middleware **before the request body is read**.
  Token comparison is constant-time. Startup refuses an empty token file, a
  token shorter than 32 characters, or no token on a non-loopback address
  (unless `allow_unauthenticated`).
- **Every value interpolated into a remote shell command goes through
  `sh_quote`** or is a validated integer, octal mode or hex digest. Content and
  data travel over stdin, never in the command string. Commands and paths
  containing NUL are rejected (a NUL makes sshd drop the shared connection).
- Proxy commands never run through a shell unless `proxy_shell` (or ssh_config
  `ProxyCommand`, as in OpenSSH) asks for one; then substituted values are
  `sh_quote`d. Substituted values are validated either way. A proxy's whole
  process group dies with its connection.
- Host keys fail closed. A key must exactly match a recorded one; a key of a
  different type than the recorded one is refused (downgrade); an unreadable
  known_hosts file is refused. accept-new only learns hosts that are completely
  unknown.
- File writes stage to a temp file, verify its size, then copy. edit_file is
  all-or-nothing, with a sha256 guard between read and write. A partial final
  copy keeps the staged content and says so (`FILE MAY BE PARTIAL`, exit 8).
  A file operation that times out is cancelled so it can't happen later.
- Everything is bounded: request body, retained output per run, memory across
  finished runs, pending runs, edit result size, report size. New features must
  be bounded too.
- Audit log: one `target: "audit"` line per tool call, run start and finish, and
  rejected request. Command text is logged with Debug formatting so newlines
  can't forge lines.

## Style

- Errors are for the model reading them: say what happened, whether anything
  changed, and what to do next ("Nothing was changed in X", "try sudo=true").
- Tool results are `ToolOut { text, is_error, image }`. Use `ok()` / `err()`.
  Anything that didn't fully succeed is `is_error = true`.
- Don't block the async runtime: CPU-heavy work goes in `spawn_blocking`.
- Logs go to **stderr** only (stdout must stay clean for a stdio transport).
