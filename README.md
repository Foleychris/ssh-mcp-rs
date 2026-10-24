# ssh-mcp-rs

Rust replacement for the Python `ssh-mcp-server` fork. Async (tokio + axum + russh),
pooled/multiplexed SSH, sync **and** async command execution, Streamable HTTP for both
MCP eras. ~2.2k lines of Rust, one binary; ~42 MB RSS after 1000 concurrent runs.

## Why it's better than the old server

| Old (Python/paramiko) | New |
|---|---|
| New TCP+SSH handshake per call (~100 ms–5 s) | Pooled connections; 6 channels multiplexed per connection, up to 6 connections per host (36 concurrent commands/host), queueing beyond that |
| Blocking: long commands die on the ~120 s timeout | Sync calls wait `wait_secs` (default 90) then hand back a `run_id` — the command keeps running |
| No async | `background=true` → `run_id` immediately; `get_run` long-polls (`wait_secs`) and pages output by byte offset |
| stdin left open (`cat` hangs forever) | stdin closed immediately, or fed from the `stdin` arg |
| `use_sudo` pipes a password → broken with passwordless sudo | `sudo=true` → `sudo -n` (old `use_sudo` name still accepted) |
| No cancel / timeout | `cancel_run` and `timeout_secs`: SIGTERM to the whole remote process group, SIGKILL after 5 s |
| `AutoAddPolicy` (accepts any host key) | Verifies against `~/.ssh/known_hosts`; trust-on-first-use into a separate learned file; **changed keys are refused** |
| `cmd &` hangs the call | Detects exit + held-open pipe, detaches after 2 s with a note |
| Whole output inline | Head+tail view (48 KiB/stream inline); 8 MiB/stream retained for paging |
| Heredoc file writes, quoting pain | `write_file` streams content over stdin, binary-safe (base64), verifies size on disk |
| Stateful-only Streamable HTTP | 2026-07-28 stateless (`server/discover`, header validation) **and** legacy `initialize` clients, both stateless |

## Tools

- `execute_command(command, hostname, username?, sudo?, stdin?, background?, wait_secs?, timeout_secs?, confirm?)`
- `get_run(run_id, wait_secs?, stdout_offset?, stderr_offset?, max_bytes?)`
- `list_runs(active_only?, hostname?, limit?)`, `cancel_run(run_id)`
- `write_file(hostname, path, content, encoding?, append?, mkdirs?, mode?, sudo?, username?)`
- `read_file(hostname, path, offset?, length?, encoding?, sudo?, username?)` — text, base64 for binary, whole PNG/JPEG/GIF/WebP ≤5 MiB as an image content block; paged, max 4 MiB/call
- `edit_file(hostname, path, old_string, new_string, replace_all?, sudo?, username?)` — exact-string replacement; must match once unless replace_all; in place (keeps inode/owner/mode); sha256 change guard between read and write; text ≤4 MiB
- `get_server_info`, `test_ssh_connection`, `list_hosts`

Hosts come from config; unlisted hostnames/IPs
are allowed (`allow_unlisted_hosts`).

## Protocol

One endpoint, `POST /mcp` (`GET`/`DELETE` → 405). Era is chosen per request:
- `params._meta["io.modelcontextprotocol/protocolVersion"]` present → **2026-07-28**: requires
  `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (base64 sentinel supported), mismatch → 400/-32020,
  unknown version → 400/-32022 with `supported`, unknown method → 404/-32601. Results carry
  `resultType`, serverInfo in `_meta`, `ttlMs`/`cacheScope` on lists.
- otherwise → **2024-11-05…2025-11-25**: `initialize` negotiates, no `Mcp-Session-Id` is minted.
- `tools/call` answers as SSE when the client accepts it, with 15 s keep-alive comments (survives
  Cloudflare's ~100 s idle cutoff); otherwise plain JSON.
- `Origin` validated (claude.ai / claude.com / localhost by default) → 403.
- Shared secret (`auth_token` / `SSH_MCP_TOKEN` / `SSH_MCP_TOKEN_FILE`)
  accepted as `Authorization: Bearer`, `x-api-key`, or `x-auth-token`; `?key=` only if
  `allow_query_token = true` (fallback for clients without custom headers). Otherwise 401.

Tasks extension (`io.modelcontextprotocol/tasks`) is **not** implemented: async is exposed as
ordinary tools (run_id handle pattern), which works with every client today.

## Audit log

Every tool call, run start (full command, host, user, sudo) and run finish (status, exit, duration),
and every rejected request (Cf-Connecting-Ip client, peer, user agent) is logged with target `audit`.

## Hardening (2026-10-24 review)

- Refuses to start if `SSH_MCP_TOKEN_FILE` is empty, the token is under 32 chars, there is no token on a
  non-loopback address (unless `allow_unauthenticated = true`), or a configured `known_hosts` file is missing.
- Host keys fail closed: a key must exactly match a recorded key; a host with recorded keys of other types
  only is refused (russh treats a different key type as "unknown", which would otherwise be learned).
- Runs wait for their host channel before taking a global slot; `cancel_run` on a queued run guarantees it
  never executes. Pending runs are capped (`max_pending_runs`); finished-run output has a memory budget
  (`retained_budget_bytes`).
- `write_file` / `edit_file` stage uploads in a temp file and verify the size before touching the target.
  File tools cancel their run if it doesn't finish in time, and refuse partial reads.
- Auth runs as middleware before the body is read; body limit 16 MiB. `wait_secs` max is 180
  (claude.ai times out tool calls at ~230s).
- Audit log escapes control characters in commands.
- Deferred: the per-host connection list lock is held during a new SSH connect (only slow when a host is down).

## Known limits

- Runs live in memory: a server restart loses run history, and in-flight commands lose their SSH
  channel. Use `nohup`/`systemd-run` for jobs that must outlive the server.
- sshd `MaxSessions` (default 10) caps channels per connection; `channels_per_conn` = 6 keeps
  headroom because server-side teardown lags. A refused channel is retried with backoff.

