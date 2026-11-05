# Proposal: stdio transport, work-friendly SSH auth, and SSM

Status: **approved for implementation, phases 0–3.** Phase 4 is design only;
write up findings, don't build it. Phases 0, 1 and 2 are done; phase 3 is next.

Phase 2 as built differs from the text below in these ways:
- Host keys are looked up under `HostName` (or `HostKeyAlias`), not under the
  alias the user typed: that is what OpenSSH does. A `HostKeyAlias` is looked
  up without a port, also as OpenSSH does.
- `Include` is supported (globs in the last path component, depth 16), because
  work configs commonly split hosts into `config.d/`.
- Hosts whose ssh_config sets `ProxyCommand`/`ProxyJump` are refused with an
  explanation until phase 3, rather than connected to directly.
- A passphrase-protected `key_file` stops startup only when `key_file` is the
  sole auth method; with `agent` also listed, the agent is expected to hold it.
- Offers are capped at 5 per connection (one under sshd's default MaxAuthTries).
Owner: Chris Foley. Implementer: read `AGENTS.md` first.

## Why

Today ssh-mcp-rs is an HTTP server built for one deployment: a container behind
a tunnel, one key, a fixed host list. The owner also wants to run it as a
**local stdio MCP server** on a work EC2 instance, so an agent there can reach
other machines for testing. Those machines are reached with a mix of plain SSH
and **AWS Systems Manager (SSM)**. Work SSH setups usually rely on
`ssh-agent`, OpenSSH certificates and `~/.ssh/config` rather than a single key
file.

Goal: one binary that runs either as today's HTTP server (unchanged behaviour)
or as a stdio server, and can reach hosts directly, through any ProxyCommand,
or through SSM, without exposing anything on the network.

## Non-goals

- No change to the HTTP deployment's behaviour, security model or defaults.
- No new network listener in stdio mode.
- No AWS credential handling in-process for phase 3: the `aws` CLI (or whatever
  ProxyCommand is configured) owns credentials.
- No Windows support.

## Phase 0 — make the protocol layer transport-agnostic (refactor, no behaviour change)

`src/mcp.rs` currently builds axum `Response`s (status codes, SSE) while it
dispatches JSON-RPC. Split it:

- `async fn handle_message(app, msg: Value, ctx: &CallCtx) -> Option<Value>`:
  pure JSON-RPC in, a JSON-RPC response out, `None` for notifications. Covers
  both eras: `initialize`, `ping`, `server/discover`, `tools/list`,
  `tools/call` (including the image content block).
- `CallCtx` carries what the audit log and era logic need: era/version, caller
  description (`client`, `peer`, or `"stdio"`), and whether modern
  `complete()` decoration applies.
- The HTTP layer keeps everything HTTP-specific: gate middleware, header
  validation (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`), status-code
  mapping (-32022 → 400, unknown method in the modern era → 404), and SSE with
  keep-alive. It calls `handle_message` and wraps the result.
- Keep `tools_call` spawning the tool on its own task, so a client disconnect
  never kills the work.

Acceptance:
- All `tests/protocol.sh`, `tests/tools.sh` and `tests/smoke.sh` behaviour is
  identical: same status codes, headers and bodies.
- New unit tests call `handle_message` directly for each method in both eras,
  plus notifications, unknown methods and unknown tools.

## Phase 1 — `--stdio` mode

CLI: `ssh-mcp-rs --stdio [config.toml]`. The config path is resolved as today
(argument, then `SSH_MCP_CONFIG`). Suggested default for stdio:
`$XDG_CONFIG_HOME/ssh-mcp-rs/config.toml`, falling back to
`~/.config/ssh-mcp-rs/config.toml`.

Framing, per the MCP stdio transport: newline-delimited JSON-RPC messages on
stdin and stdout, UTF-8, no embedded newlines. Logs go to **stderr only**;
nothing else may write to stdout (there are no `println!` today — keep it that
way, and add a unit test or CI grep).

Concurrency:
- A reader task parses each line and spawns a task per request, so many calls
  run at once, as in HTTP mode.
- A single writer task owns stdout and receives complete serialized responses
  over an mpsc channel. One message is one `write_all` of `json + "\n"`
  followed by a flush, so responses never interleave.
- Responses may be out of order; JSON-RPC ids correlate them.
- A malformed line gets a JSON-RPC parse error (-32700, `id: null`) and the
  server keeps going.
- Cap line length at `limits.max_body_bytes`. Beyond it, reply with an error,
  discard up to the next newline, and keep going.

Lifecycle:
- Support the legacy handshake (`initialize` → response,
  `notifications/initialized` → no response), `ping`, and modern clients
  sending `server/discover` / `_meta` per request. In stdio mode, skip the
  HTTP header checks; validate `_meta` protocolVersion as today.
- Handle `notifications/cancelled` with `requestId`: if that request started a
  run that is still active, cancel it (same path as `cancel_run`). Otherwise
  ignore it.
- On stdin EOF or SIGTERM: stop reading, let in-flight requests finish for up to
  5 s, then handle the remaining runs per the new config key
  `stdio_on_exit = "cancel" | "leave"`. The default is `"cancel"`, which kills
  remote process groups so runs aren't orphaned when the client exits; log
  every one. Then exit 0.

Config and validation in stdio mode:
- No token is required and `listen`, `allowed_origins` and the query-token
  options are ignored. Log once at startup that stdio mode has no
  network-facing auth. Keep every HTTP-mode startup check exactly as it is.
- `max_wait_secs`: the 220 s cap exists because of claude.ai's ~230 s
  tool-call timeout. In stdio mode allow up to 600, document it, and keep the
  default of 90.
- Audit log: `client = "stdio"`, plus the parent PID once at startup.

Acceptance:
- An integration test in `tests/stdio.sh`, or a Rust integration test under
  `tests/`, spawns the binary and runs the legacy handshake, `tools/list`, and
  20 concurrent `execute_command` calls against `localhost` or a test sshd
  container. All 20 answer with correct ids, and no line on stdout is anything
  but a complete JSON-RPC message.
- Interop with the official MCP TypeScript SDK's stdio client
  (`StdioClientTransport`): list tools and call one. Use a throwaway
  `npm install` in a temp dir, not global installs.
- `notifications/cancelled` stops a `sleep 300` run (the remote process is gone).
- EOF with an active run cancels it under the default and leaves it under
  `"leave"`.
- A README section shows how to register it with Claude Code, e.g.
  `claude mcp add ssh -- /path/to/ssh-mcp-rs --stdio`. Check the current
  syntax with `claude mcp add --help`.

## Phase 2 — work-friendly SSH auth and host resolution

1. **ssh-agent.** `key_file` becomes optional. Add
   `auth = ["agent", "key_file"]` (ordered; the default is `["key_file"]` when
   `key_file` is set, else `["agent"]`). Agent auth uses russh 0.64's
   `russh::keys::agent::client::AgentClient::connect_env()` (`SSH_AUTH_SOCK`)
   and `Handle::authenticate_publickey_with`. Try each agent identity in order
   and stop at the first success. Bound the number of attempts: sshd
   `MaxAuthTries` defaults to 6.
2. **OpenSSH certificates.** If `<key_file>-cert.pub` exists (or `cert_file` is
   set), authenticate with `Handle::authenticate_openssh_cert`. Agent-held
   certificates come back from the agent's identity list and should be tried
   too. Verify what russh 0.64 exposes before designing around it.
3. **`~/.ssh/config` subset (opt-in, `ssh_config = true` or a path).** Resolve
   `Host` aliases for `HostName`, `User`, `Port`, `IdentityFile`,
   `ProxyCommand`, `ProxyJump` (one hop only; anything more →
   unsupported-error) and `HostKeyAlias`. Unsupported directives are ignored
   with a debug log. `Match` blocks are skipped with a warning; don't
   half-implement them. Explicit `[hosts.*]` entries in our config win. Prefer
   a small, tested parser in-tree, or a maintained crate if one parses this
   subset correctly, with justification. Unit-test the parser.
4. Host-key verification is unchanged and still fails closed. Look up keys by
   `HostKeyAlias` when set, else the alias the user passed (matching OpenSSH),
   and say so in the error when a key is missing.

Acceptance: unit tests for config resolution and auth ordering. Manual or
integration test against an sshd container configured with (a) agent-only and
(b) cert-only access.

## Phase 3 — ProxyCommand transport (this is how SSM works)

SSM's standard SSH path is a ProxyCommand: `aws ssm start-session --target
<instance-id> --document-name AWS-StartSSHSession --parameters
portNumber=<port>`, which pipes an SSH stream over the SSM channel. Supporting
a generic ProxyCommand therefore covers SSM, ProxyJump-by-command, bastions,
`cloudflared access ssh` and more, while keeping our pooled multiplexed SSH
semantics (stdin, cancel and process-group kill, file tools) unchanged.

Design:
- Per-host `proxy_command = "…"` with `%h` (address), `%p` (port), `%r` (user)
  and `%%` substitutions. Substituted values are validated (hostnames
  `[A-Za-z0-9._:-]`, ports numeric) **and** passed as separate argv elements:
  split the template with a shell-words parser, then substitute into each
  word. Never run it through `sh -c` with substituted text. If a template
  genuinely needs a shell, require an explicit `proxy_shell = true` and quote
  substitutions with `sh_quote`.
- Optional rule for unlisted hosts:
  `[[proxy_rules]] match = "^i-[0-9a-f]{8,17}$"`, `proxy_command = "…"`, so
  `hostname="i-0abc…"` routes through SSM without per-host config.
  `ProxyCommand` from `~/.ssh/config` (phase 2) feeds the same mechanism.
- Spawn the child with `tokio::process::Command` (`kill_on_drop(true)`, stderr
  captured into a small ring buffer for error messages, env inherited so
  `AWS_PROFILE` and `AWS_REGION` work). Join its stdout and stdin into one
  `AsyncRead + AsyncWrite` (`tokio::io::join`) and hand it to
  `russh::client::connect_stream`.
- One child process per pooled connection. When a connection is dropped as
  dead, the child is killed. The pool key includes the proxy, so the same
  address with and without a proxy doesn't share connections.
- `connect_timeout_secs` covers child startup plus the SSH handshake. SSM
  session start can take several seconds; a per-host or per-rule
  `connect_timeout_secs` override is fine.
- If the child exits before the SSH handshake completes, the error includes
  the last few lines of its stderr, e.g. "aws: … TargetNotConnected" or
  "SessionManagerPlugin is not found". That makes misconfiguration obvious.
- Host keys: entries are looked up by the alias or instance ID (OpenSSH users
  set `HostKeyAlias` for SSM hosts); still fail closed. accept-new behaves as
  today.
- `test_ssh_connection` and `list_hosts` show the transport (`direct`,
  `proxy: <program>`).

Acceptance:
- A unit test for template splitting and substitution, including injection
  attempts such as `hostname = "x; rm -rf /"`, which must be rejected or
  passed as a single argv element.
- An integration test with `proxy_command = "nc %h %p"` (or a socat
  equivalent) against a test sshd. Every tool works, including concurrent runs
  across multiplexed channels and `cancel_run`.
- The owner verifies against a real SSM-managed instance. The implementer
  documents the exact config in the README, with placeholder instance IDs
  only.

## Phase 4 — native SSM Run Command backend (design doc only, don't build)

Some instances may have SSM but no sshd or keys. Investigate a backend built on
the AWS SDK for Rust (`aws-sdk-ssm`): `SendCommand` (`AWS-RunShellScript`),
`GetCommandInvocation` polling, and `CancelCommand`. Write
`docs/proposals/ssm-run-command.md` covering:
- Semantic gaps versus SSH: no stdin, no streaming, inline output truncation
  and the S3 output option, latency, cancel semantics (no process-group kill),
  `sudo` (the agent runs as root by default), exit codes.
- How `execute_command`, `get_run`, `cancel_run` and the file tools would map,
  or why some can't. File content would have to go inside the command
  document, which has size limits. **Look up the current AWS limits in the
  docs and cite them; don't guess.**
- The credentials and region model, and IAM permissions needed (least
  privilege).
- A recommendation: build it, or rely on phase 3 (SSH over SSM) plus
  bootstrapping sshd where needed.

## Cross-cutting

- Follow `AGENTS.md`: security invariants, no printed secrets, unit tests gate
  the build, no new clippy warnings in touched code.
- One phase per PR or merge, each releasable alone. The HTTP deployment's
  weekly update builds `master`, so **`master` must always be deployable**.
  Phases must not change HTTP-mode defaults.
- Update `README.md` (new "Running locally (stdio)" and "Proxies and SSM"
  sections) and `compose.example.yaml` only if relevant.
- New dependencies, each justified in the commit message. Likely: none for
  phases 0–1. `shell-words` or equivalent for phase 3. Possibly an ssh_config
  parser for phase 2. `aws-sdk-*` only if phase 4 is ever approved.

## Open questions for the owner (ask, don't assume)

1. Default for `stdio_on_exit`: `cancel` (proposed) or `leave`?
2. Should stdio mode read the HTTP deployment's config format unchanged, or is
   a separate `stdio.toml` example enough?
3. Phase 2.3 (`~/.ssh/config`): is it wanted at work, or are explicit
   `[hosts.*]` plus `proxy_rules` enough?
