---
name: OAuth callback requires a second, TCP-only listener
description: Why the daemon runs two listeners with different security models and how the boundary between them is enforced
type: DECISION
date: 2026-04-10
created_at: 2026-04-10T00:00:00Z
author: co-authored
session_id: m87b
session_turn: 1
project: csq-v2
topic: M8.7b dual-listener architecture
phase: implement
tags: [daemon, oauth, security, architecture, m8.7, dual-listener]
---

# Dual-Listener Architecture: Unix Socket + TCP Loopback

## Context

M8.3 established the daemon's primary IPC on a **Unix domain socket** protected by the three-layer security model from `0006-DECISION-daemon-three-layer-security.md`:

1. `0o600` socket file permissions (umask 077 before bind)
2. `SO_PEERCRED` / `LOCAL_PEERCRED` per-connection UID check
3. Per-user socket directory (`$XDG_RUNTIME_DIR` / `~/.claude/accounts`)

That is the correct boundary for CLI↔daemon IPC. But M8.7b needs a callback endpoint browsers can reach — and browsers cannot connect to Unix sockets. Anthropic's OAuth flow 302s the user's browser back to `http://127.0.0.1:{port}/oauth/callback?code=X&state=Y`.

## Decision

Run **two listeners** with intentionally different security models:

|                         | Unix socket (M8.3)                                 | OAuth callback (M8.7b)         |
| ----------------------- | -------------------------------------------------- | ------------------------------ |
| Transport               | `UnixListener`                                     | `TcpListener(127.0.0.1, 8420)` |
| Routes                  | `/api/*` (health, accounts, refresh-status, login) | `/oauth/callback` only         |
| Caller authentication   | `SO_PEERCRED` UID check                            | State token (CSRF anchor)      |
| File-system permissions | `0o600` socket file                                | N/A (no socket file)           |
| Directory sandbox       | Per-user socket dir                                | N/A (TCP)                      |
| Attack surface          | One handler per API route                          | Exactly one handler            |

The TCP listener is **deliberately NOT protected by the three-layer model**. It relies on three weaker but sufficient defenses:

1. **127.0.0.1 binding** — hardcoded `IpAddr::V4(Ipv4Addr::LOCALHOST)` in `oauth_callback::serve`. The builder takes a `u16` port, not a `SocketAddr`. There is no code path that can bind to `0.0.0.0` or a non-loopback address. Limits the attacker to same-host code.
2. **State token as CSRF anchor** — every request is authenticated by the `state` query parameter, which must match an entry in the shared `OAuthStateStore`. State tokens are 32 bytes of CSPRNG output, single-use, and TTL-bounded (10 minutes). Without a valid state, the handler returns 400 without touching any other state.
3. **One route only** — `GET /oauth/callback` is the sole registered route. Every other path returns 404, wrong methods return 405. No health endpoint, no accounts endpoint, no login endpoint on the TCP listener.

## Why not unify

Two rejected alternatives:

**Alt A: Run every route on TCP loopback.**
Rejected because the CLI↔daemon IPC benefits from `SO_PEERCRED`. Any other process on the same UID (including sandboxed code that happens to share the UID) could otherwise talk to the daemon. The Unix socket makes the UID boundary load-bearing.

**Alt B: Tunnel the callback through the Unix socket via a helper browser extension.**
Rejected as over-engineered for an alpha. The browser needs to reach the daemon somehow; a 127.0.0.1 TCP listener is the boring, well-understood path that matches v1.x behavior and existing Anthropic OAuth app registration.

## Constraint: port 8420 is fixed

Anthropic's OAuth app registration for the Claude Code `client_id` permits `http://127.0.0.1:8420/oauth/callback` as a valid redirect URI. Using a different port would require Anthropic to register it. The daemon therefore:

- Always tries to bind 8420
- On bind failure (port in use), logs a warning and proceeds with `oauth_store = None` in `RouterState` — the rest of the daemon keeps working, `/api/login/{N}` returns 503 until the port is freed.

We do NOT fall through to an ephemeral port because Anthropic would reject the redirect.

## Consequences

- The attacker model for the TCP listener is "malicious code on the same host that can guess a 32-byte CSPRNG state token." That is computationally infeasible; the practical residual risk is a local attacker pre-consuming a state (see `0012-DISCOVERY-oauth-preconsume-dos-class.md`) — already hardened.
- Graceful shutdown must join three subsystems, not two: server + refresher + OAuth callback. All three share the outer `CancellationToken`; `handle_start` joins each with a 5s deadline.
- Any future route that handles sensitive operations (credential write, keychain access) MUST live on the Unix socket, not the TCP listener. The TCP listener handles exactly one concern: consuming the OAuth callback.
- Integration tests that need TCP access bind the callback listener with `port: 0` so the OS picks an ephemeral port; the listener returns the real port via `CallbackHandle::port`.

## For Discussion

1. **If Anthropic ever rotated the registered redirect URI to a different port, how would users migrate?** The answer is a daemon restart after a constants update — `DEFAULT_REDIRECT_PORT` lives in `csq-core/src/oauth/constants.rs`, matching the single-source-of-truth pattern from `0009-DECISION`. But is there a path where in-flight logins would fail silently during the transition? A rolling deploy would need a grace window where both ports are bound.
2. **The TCP listener has no SO_PEERCRED equivalent.** Could a privileged local process impersonate the browser by sending a forged callback? Yes — but it would also need to know a valid state token, which is only held in the daemon's own memory. The CSRF anchor shifts the boundary from "who can connect" to "who can guess the token." Is that acceptable for the same-UID threat model, or should we add some form of browser-origin assertion (`User-Agent`, `Origin` header check) as defense in depth?
3. **Should the TCP listener refuse connections from non-loopback source addresses as a second check, even though `127.0.0.1` binding already excludes them?** `TcpStream::peer_addr` would return the source; we could reject any non-127.0.0.1 source. Redundant with the bind, but cheap and catches misconfiguration during testing where the listener is intentionally bound to a larger interface for debugging.
