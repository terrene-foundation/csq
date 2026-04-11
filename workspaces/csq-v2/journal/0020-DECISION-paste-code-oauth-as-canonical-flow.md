---
type: DECISION
date: 2026-04-11
created_at: 2026-04-11T19:35:00+08:00
author: co-authored
session_id: session-2026-04-11c
session_turn: 199
project: csq-v2
topic: Adopt paste-code OAuth as the only supported flow; delete the loopback callback listener entirely
phase: implement
tags: [oauth, architecture, breaking, cleanup]
---

# DECISION: Paste-code is the only OAuth flow; delete `oauth_callback.rs`

## Context

After 0019 discovered that Anthropic retired the loopback authorize endpoint for the Claude Code client_id, csq v2 had a choice:

1. **Update the URL constant only**, keep loopback machinery hoping Anthropic accepts it on the new host
2. **Rewrite to paste-code**, deleting the loopback TCP callback listener

Option 1 would have been a two-line fix. Option 2 was ~1500 LOC of changes across 8 files and removed ~1000 LOC of previously-tested infrastructure.

## Why the bigger change was the right call

**The live reference (`claude auth login`) uses paste-code, not loopback.** The csq bash wrapper (`csq` at repo root) shells out to `claude auth login`, which emits:

```
redirect_uri=https://platform.claude.com/oauth/code/callback
code=true
```

`claude auth login` is the canonical Claude Code login flow. If csq reimplements the OAuth flow in Rust and it disagrees with `claude auth login`, csq is wrong by definition — Anthropic can change the rules for this client_id at any time and the reference client is the source of truth. Matching paste-code matches the reference client exactly.

**Loopback might still work, but betting on it is a time bomb.** Anthropic's OAuth app registration for this client_id could have permissive redirect_uri allowlisting that still accepts `http://127.0.0.1:8420/oauth/callback`, but there's no way to know without testing, and even if it works today it could be removed tomorrow without notice. Every new csq release that ships with loopback machinery risks breaking a week later.

**`oauth_callback.rs` was dead weight.** The module was ~1000 LOC (including 15 unit tests) and existed solely to serve one route (`GET /oauth/callback`) that Anthropic would never hit again. Every session that touched OAuth had to reason about _two_ flows: the legacy loopback path and the intended paste-code path. Deleting the dead path removes a whole class of future mistakes.

## What we deleted

| Path                                                         | LOC   | Reason                                            |
| ------------------------------------------------------------ | ----- | ------------------------------------------------- |
| `csq-core/src/daemon/oauth_callback.rs`                      | ~1000 | Loopback TCP callback server + 15 unit tests      |
| `csq-core::oauth::login::start_login_loopback`               | ~50   | Loopback URL builder with deprecated annotation   |
| `csq-core::oauth::constants::redirect_uri(port)`             | ~10   | Loopback URI builder                              |
| `csq-core::oauth::constants::DEFAULT_REDIRECT_PORT`          | ~5    | Was `8420`; unused without loopback               |
| `csq-core::daemon::server::RouterState::oauth_port`          | —     | Port field unused without callback listener       |
| `csq-desktop::forward_oauth_event`, `CallbackState` plumbing | ~60   | Listener startup + event forwarder in `lib.rs`    |
| `tauri-plugin-updater` init + dep                            | ~10   | Was crashing at `did_finish_launching` — see 0021 |

Total removed: ~1150 LOC.

## What we added

| Path                                                  | LOC  | Role                                                        |
| ----------------------------------------------------- | ---- | ----------------------------------------------------------- |
| `csq-core::oauth::constants::PASTE_CODE_REDIRECT_URI` | 1    | Fixed `https://platform.claude.com/oauth/code/callback`     |
| `csq-core::oauth::login::start_login` (rewrite)       | ~80  | Builds paste-code URL with `code=true` + paste redirect_uri |
| `csq-core::daemon::server::oauth_exchange_handler`    | ~140 | New `POST /api/oauth/exchange` route                        |
| `csq-desktop::commands::submit_oauth_code`            | ~80  | New Tauri command: consume state → exchange → save creds    |
| `csq-desktop::AddAccountModal.svelte` paste-code step | ~40  | UI for pasting the code; fallback URL textarea              |
| 7 new unit tests                                      | —    | Covering `/api/oauth/exchange` + scope + constants          |

Total added: ~340 LOC + 7 tests.

**Net**: ~800 LOC deleted, and the one path through the code is now the paste-code path. No more "is this the dead branch or the live branch?".

## The `oauth_store` is the only part we kept from loopback

The `OAuthStateStore` (TTL'd PKCE pending-state map, bounded at `MAX_PENDING`, single-use state tokens) is unchanged. It was originally built to let the loopback callback handler retrieve the verifier, but it's equally valid for paste-code: `start_login` inserts on initiation, `submit_oauth_code` consumes on the user's paste. Same authentication boundary, same CSRF defense, same store implementation.

## Alternatives considered

1. **Keep both flows** — rejected: doubles the cognitive load for every OAuth maintainer. A future session would have to ask "which flow does this touch?" every time it reads OAuth code.
2. **Delegate to `claude auth login` subprocess** — rejected: requires a pseudo-terminal to capture `claude`'s stdin/stdout in a GUI context, significantly more complex than reimplementing paste-code in Rust. Revisit if Anthropic changes the flow again — at that point shelling out may be cheaper than chasing their changes.
3. **Update URL only, leave loopback plumbing** — rejected: betting on an undocumented redirect_uri allowlist that could disappear in any future Anthropic deploy. Option 1 at the top.

## Consequences

**Good:**

- One OAuth flow, matching the reference client byte-for-byte
- Desktop app no longer binds port 8420 → no conflict with `csq daemon`
- `csq daemon start` no longer prints `OAuth: http://127.0.0.1:8420/oauth/callback` in its banner (the line is gone)
- Tests for OAuth drop from 65 → 50 but coverage is arguably better (we test the one real path)

**Bad:**

- The `/api/oauth/exchange` route is **not** covered by an end-to-end test against the live token endpoint. We unit-test the handler shape (empty code, unknown state, 503 when no store) but the actual `exchange_code → credential write → /api/accounts visible` chain is untested in the CI suite. The user declined to run a real login because they have 8 live accounts and didn't want to overwrite credentials. This should be tested the next time someone is genuinely adding an account — a smoke test script that talks to the Unix socket would also help.
- The daemon's Unix-socket `/api/login/{N}` route now requires a follow-up `POST /api/oauth/exchange` call to complete a login. A CLI tool that used the old route expecting the loopback listener to finish the flow automatically will now hang waiting. `csq` bash wrapper doesn't use this route — it shells out to `claude auth login` — so there's no known caller affected.

## For Discussion

1. **Should csq delegate to `claude auth login` subprocess** in the desktop UI instead of reimplementing paste-code? Delegating removes all responsibility for tracking Anthropic's flow changes but requires PTY handling. Revisit if the paste-code flow changes again.
2. **Should v1 `dashboard/oauth.py` be deleted** or updated? It has the dead URL too, and nothing calls it. Leaving it risks someone copy-pasting from it into new code.
3. **Should we probe the live authorize endpoint on `csq daemon start`** and log a warning if it 404s? Cheap early-warning system for the next endpoint migration.

## Cross-references

- 0019-DISCOVERY-anthropic-oauth-endpoint-migration.md — the endpoint move that forced this rewrite
- 0011-DECISION-oauth-dual-listener-security.md — the original security reasoning for having a TCP listener alongside the Unix socket. Still relevant for understanding **why** the dual-listener existed; no longer relevant as architecture.
- 0021-DISCOVERY-tauri-2-10-runtime-gotchas.md — tauri-plugin-updater + homeDir + opener gotchas discovered in the same session
- `csq-core/src/daemon/server.rs` — new paste-code handler lives here
- `csq-desktop/src-tauri/src/commands.rs` — `submit_oauth_code` lives here
