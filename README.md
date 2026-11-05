# sshmux-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent run commands and edit files
on remote hosts over SSH. One Rust binary (tokio + russh), serving MCP over **stdio** for a local
client or **Streamable HTTP** for a remote one.

- **Pooled, multiplexed SSH.** Connections are reused, with several commands running as channels of
  one connection (6 channels × up to 6 connections per host by default) and queueing beyond that.
  No handshake per call.
- **Long commands don't die.** A call waits up to `wait_secs`, then hands back a `run_id` while the
  command keeps running. `background=true` returns at once; `get_run` long-polls and pages output by
  byte offset. `cancel_run` and `timeout_secs` kill the whole remote process group.
- **File tools without shell quoting.** `write_file` streams content over stdin and verifies the
  size on disk. `read_file` pages text and binary, and returns images as image content. `edit_file`
  does exact-string edits in place, all-or-nothing, with a change guard between read and write.
- **Fails closed on host keys.** A host key must match a recorded one exactly; changed keys and key
  type downgrades are refused.
- **Bounded.** Request size, retained output, memory across finished runs and pending runs all have
  limits. Every tool call, run start and run finish is audit-logged to stderr.

## Install

```
cargo install --locked sshmux-mcp
```

Needs Rust 1.89 or later and a C compiler (the SSH crypto comes from aws-lc). Unix only; tested
on Linux. Windows is not supported.

## Quick start: Claude Code (stdio)

1. Write `~/.config/sshmux-mcp/config.toml`:

   ```toml
   key_file = "~/.ssh/id_ed25519"
   known_hosts_files = ["~/.ssh/known_hosts"]
   learned_hosts_file = "~/.config/sshmux-mcp/known_hosts.learned"
   # default_user defaults to $USER; host_key_policy defaults to "strict"

   [hosts.build]
   address = "build.example.internal"
   user = "ubuntu"
   description = "build box"

   [hosts.db]
   address = "192.0.2.20"
   port = 2222
   ```

   The key must not have a passphrase (ssh-agent support is planned). With the default `strict`
   policy every host must already be in a known_hosts file: connect once with `ssh`, or set
   `host_key_policy = "accept-new"` to trust a host's key the first time and refuse it if it
   ever changes.

2. Register it:

   ```
   claude mcp add ssh -- sshmux-mcp --stdio
   ```

   Use `--scope user` to make it available in every project, and add a config path after
   `--stdio` to use a different file.

3. Ask Claude to run something, e.g. "check disk space on build".

Other MCP clients work the same way: run `sshmux-mcp --stdio [CONFIG]` as a stdio server.

### stdio behaviour

- No network listener and no auth: whoever spawns the process is the client. `listen`, the token
  settings and `allowed_origins` are ignored.
- Requests run concurrently and can be answered out of order (matched by id). In-flight requests
  are capped at `limits.max_pending_runs`. Logs go to stderr; stdout carries only JSON-RPC.
- A malformed line gets a parse error, and a line over `limits.max_body_bytes` gets an error and
  is discarded. Neither ends the session.
- `notifications/cancelled` cancels the runs the request started, and that request gets no response.
- On stdin EOF or SIGTERM/SIGINT the server lets in-flight requests finish for up to 5 s, then
  cancels still-active runs (killing their remote process groups) and exits 0.
  `stdio_on_exit = "leave"` leaves them running instead. Run history lives in memory and is gone
  once the server exits.
- `limits.max_wait_secs` may be up to 600 (220 over HTTP).

## HTTP mode

```
SSH_MCP_TOKEN_FILE=/path/to/token sshmux-mcp /path/to/config.toml
```

Serves `POST /mcp` on `listen` (default `127.0.0.1:8011`) and `GET /healthz`. For a remote client
such as a claude.ai custom connector, put it behind a TLS-terminating proxy or tunnel.

- **Auth:** a shared secret of at least 32 characters (`openssl rand -hex 32`), from
  `SSH_MCP_TOKEN_FILE`, `SSH_MCP_TOKEN` or `auth_token`. Clients send it as
  `Authorization: Bearer …`, `x-api-key` or `x-auth-token`, or as `?key=` only if
  `allow_query_token = true` (for clients that can't set headers). Wrong or missing → 401. The
  check runs before the request body is read.
- **Startup refusals:** no token on a non-loopback address (unless `allow_unauthenticated = true`),
  an empty token file, a short token, or a missing known_hosts file.
- **Origin:** a browser `Origin` header must be in `allowed_origins` (default claude.ai and
  claude.com) or localhost, else 403.
- **Protocol:** both MCP eras on one stateless endpoint. With
  `params._meta["io.modelcontextprotocol/protocolVersion"]` the request is 2026-07-28
  (`server/discover`, `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` header checks); without
  it, 2024-11-05…2025-11-25 with an `initialize` handshake. No `Mcp-Session-Id` is issued.
  `tools/call` answers as SSE with 15 s keep-alives when the client accepts it.
- `SSH_MCP_LISTEN` overrides `listen`.

The repository's `Dockerfile` builds a slim image that runs as UID 1000;
`compose.example.yaml` shows one way to run it.

## Tools

| Tool | What it does |
|---|---|
| `execute_command(command, hostname, username?, sudo?, stdin?, background?, wait_secs?, timeout_secs?, confirm?)` | Run a command via the login shell. stdin is closed unless given. `sudo=true` uses `sudo -n`. |
| `get_run(run_id, wait_secs?, stdout_offset?, stderr_offset?, max_bytes?)` | Status and output of a run; long-polls; pages by byte offset. |
| `list_runs(active_only?, hostname?, limit?)`, `cancel_run(run_id)` | Inspect and stop runs. |
| `write_file(hostname, path, content, encoding?, append?, mkdirs?, mode?, sudo?, username?)` | Write text or base64 via a staged temp file; verifies the size. |
| `read_file(hostname, path, offset?, length?, encoding?, sudo?, username?)` | Text, base64 for binary, images ≤5 MiB as image content; up to 4 MiB per call. |
| `edit_file(hostname, path, old_string, new_string, replace_all?, …)` or `edit_file(…, edits=[…])` | Exact-string replacement, in place (keeps inode, owner and mode), up to 200 edits, all-or-nothing. |
| `get_server_info`, `test_ssh_connection`, `list_hosts` | Host facts, a connectivity check, configured hosts and pool status. |

`hostname` is a configured alias or any host/IP (unless `allow_unlisted_hosts = false`).

## Configuration

TOML; unknown keys are rejected. CONFIG defaults to `$SSH_MCP_CONFIG`, then
`/etc/sshmux-mcp/config.toml` (HTTP) or `$XDG_CONFIG_HOME/sshmux-mcp/config.toml` →
`~/.config/sshmux-mcp/config.toml` (stdio). Paths may start with `~/`.

| Key | Default | |
|---|---|---|
| `key_file` | required | Private key (no passphrase). |
| `learned_hosts_file` | required | Where `accept-new` records keys; read if present. |
| `known_hosts_files` | `[]` | Read-only known_hosts files to trust. Each must exist. |
| `host_key_policy` | `"strict"` | Or `"accept-new"`: learn unknown hosts, refuse changed keys. |
| `default_user` | `$USER` | SSH user when a host has none. |
| `default_port` | `22` | |
| `allow_unlisted_hosts` | `true` | Accept hostnames not under `[hosts]`. |
| `require_confirm_for_destructive` | `false` | Require `confirm=true` for commands matching a destructive-pattern list. |
| `stdio_on_exit` | `"cancel"` | stdio only: `"cancel"` or `"leave"` active runs on exit. |
| `listen` | `"127.0.0.1:8011"` | HTTP only. |
| `auth_token`, `allow_query_token`, `allow_unauthenticated`, `allowed_origins` | none, `false`, `false`, claude.ai + claude.com | HTTP only; see above. |
| `[hosts.NAME]` | | `address` (required), `port`, `user`, `description`. |
| `[limits]` | | See below. |

`[limits]` (defaults): `max_concurrent_runs` 256, `channels_per_conn` 6, `max_conns_per_host` 6,
`connect_timeout_secs` 15, `keepalive_secs` 20, `default_wait_secs` 90, `max_wait_secs` 180,
`default_timeout_secs` 0 (none), `retained_output_bytes` 8 MiB per stream, `inline_output_bytes`
48 KiB, `retain_finished_secs` 86400, `max_finished_runs` 1000, `retained_budget_bytes` 512 MiB,
`max_pending_runs` 1024, `max_body_bytes` 16 MiB.

## Security model

Anyone who can call this server can run anything the SSH key can, including root via `sudo=true`
if the key's user has passwordless sudo. Treat access to it like access to the key.

- Over stdio, the parent process is trusted. Over HTTP, the shared secret is the only gate: keep
  it on loopback or behind a proxy, and never run it unauthenticated on a reachable address.
- Every value put into a remote command line is shell-quoted or validated, and file content goes
  over stdin. Commands and paths containing NUL are rejected.
- Host keys fail closed (see `host_key_policy`). An unreadable known_hosts file refuses the
  connection rather than falling back to trust-on-first-use.
- Audit log: one `target: "audit"` line per tool call, run start (full command, host, user,
  sudo), run finish, and rejected request, on stderr.

## Known limits

- Runs live in memory: restarting the server loses run history, and in-flight commands lose their
  channel. Use `nohup` or `systemd-run` for jobs that must outlive it.
- sshd `MaxSessions` (default 10) caps channels per connection; `channels_per_conn = 6` leaves
  headroom. A refused channel is retried with backoff.
- Key file auth only, for now. ssh-agent, OpenSSH certificates, `~/.ssh/config` and
  ProxyCommand/SSM are planned (`docs/proposals/stdio-and-ssm.md`).

## Development

```
cargo test --release     # unit tests
cargo clippy --release --all-targets -- -D warnings
```

`tests/stdio.rs` is an integration test against a real host (never production):
`SSH_MCP_TEST_CONFIG=… SSH_MCP_TEST_HOST=… cargo test --release --test stdio -- --ignored --test-threads=1`.
Contributor notes are in `AGENTS.md`.

## License

MIT
