# Changelog

All notable changes to sshmux-mcp. Versions follow [semantic versioning](https://semver.org/).

## Unreleased

### Fixed
- `agent` auth now binds the agent connection to the SSH session with
  `session-bind@openssh.com` before listing identities, as OpenSSH's `ssh` does.
  Keys added with `ssh-add -h` (destination constraints), and agents that refuse
  to sign on an unbound connection, now work. Agents without the extension are
  unaffected: a refused bind is logged at debug level and auth carries on.

### Changed
- russh 0.65.1, which includes the client-side fix for GHSA-9264-jvgf-6w2f
  (`kex_done` was called before host-key verification), plus fixes for ECDSA
  signatures with non-canonical padding and short 3DES/EtM packets.

## 0.3.2 (2026-11-06)

### Fixed
- Proxies for connections still being set up are stopped when the server exits,
  instead of being orphaned (`session-manager-plugin` kept running).
- `test_ssh_connection`, `get_server_info` and the kill helper report the
  proxy's own diagnosis when a proxied connection fails, instead of a generic
  30 s timeout.

## 0.3.1 (2026-11-06)

### Changed
- russh 0.65.0: fixes a stack overflow from deeply nested certificates in a
  host key or agent identity, channel window updates that could stall large
  transfers, an agent signing failure that stalled later auth attempts, and
  keepalive re-arming.

## 0.3.0 (2026-11-05)

### Added
- ProxyCommand transport: per-host `proxy_command`, `[[proxy_rules]]` for
  unlisted names, and ssh_config `ProxyCommand` / one-hop `ProxyJump`. Covers
  AWS SSM, bastions and `cloudflared`.

## 0.2.0 (2026-11-05)

### Added
- ssh-agent auth, OpenSSH certificates, an `auth` method list, and an opt-in
  `~/.ssh/config` subset.

## 0.1.0 (2026-11-05)

First release on crates.io: MCP over stdio and Streamable HTTP, pooled and
multiplexed SSH, sync and background runs, and file tools.
