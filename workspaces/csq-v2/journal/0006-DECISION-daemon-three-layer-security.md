---
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T21:45:00Z
author: co-authored
session_id: m8-ipc-detection
session_turn: 80
project: csq-v2
topic: Three defensive layers for daemon Unix-socket IPC
phase: implement
tags: [m8, daemon, security, unix-socket, hardening]
---

# DECISION: Three defensive layers for daemon IPC

## Context

M8.3 added a Unix-socket HTTP server so CLI commands and the future UI
can query the daemon. Unix sockets are the authentication boundary —
there is no application-layer HTTP auth — so we need the socket itself
to be unforgeable from any other UID. Independent security review
surfaced a bind→chmod TOCTOU race that would have made the 0o600
permission ineffective for microseconds after bind.

## Decision: three layers, not one

1. **Umask-before-bind** — `libc::umask(0o077)` before
   `UnixListener::bind` means the socket file is created with 0o600
   from the first syscall. `chmod` after bind remains as
   defense-in-depth. Closes the TOCTOU race on macOS and the
   Linux `/tmp/csq-{uid}.sock` fallback.
2. **SO_PEERCRED / LOCAL_PEERCRED verification** — every accepted
   connection is checked against `geteuid()` before the axum router
   sees the request. Implemented inline per-platform (`struct
ucred` on Linux, `struct xucred` with `SOL_LOCAL/LOCAL_PEERCRED
= 0/1` on macOS). Cross-UID connections dropped silently.
3. **Per-user socket directory** — Linux prefers
   `$XDG_RUNTIME_DIR` (tmpfs, 0o700); macOS uses
   `~/.claude/accounts` (inside HOME). /tmp fallback on Linux
   carries uid in the filename.

## Alternatives considered

- **Native-TLS with OpenSSL**: rejected — pulls OpenSSL attack
  surface for no benefit on a local Unix socket.
- **Deferring SO_PEERCRED to M8.5**: the reviewer said "minimum
  bar before M8.5 credential routes land" — implementing now
  means we don't carry the work forward as a prerequisite.
- **Hand-rolled umask via thread-local**: rejected — the daemon
  serve() is called before any tokio tasks spawn, so process-
  global umask is safe at that call site.

## Consequences

- Any file-permission bug is caught by peer-cred, any peer-cred
  bug is caught by 0o600, any permission bug is caught by the
  per-user directory. Match the hardening baseline sshd and
  systemd use.
- Adds ~100 LOC of platform-specific libc code.
- Hand-rolled HTTP parser in `detect.rs` is scoped to detection
  only — explicit contract that it must NOT be reused for any
  credential-bearing route. Future reviewers should reject PRs
  that try to repurpose it.

## For Discussion

1. macOS `LOCAL_PEERCRED` constants (`SOL_LOCAL = 0`,
   `LOCAL_PEERCRED = 1`) are hardcoded rather than pulled from
   `libc` because the current `libc` crate doesn't expose them.
   If a future `libc` adds them, should we migrate to the crate
   constants for maintainability?
2. The `/tmp/csq-{uid}.sock` Linux fallback exists because
   sun_path has a 108-byte limit that a deep home directory can
   hit. Is the uid-suffix-in-filename enough protection when
   `/tmp` is shared across users? Or should we refuse to start
   without `XDG_RUNTIME_DIR` on Linux?
3. If a future attack emerges against one layer, which layer
   should we double down on — more aggressive umask (full 0o077
   set once at daemon startup for the whole process lifetime),
   stricter peer-cred (also check `pid` and `gid`), or a private
   sub-directory we create + chmod before bind?
