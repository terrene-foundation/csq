---
type: DISCOVERY
date: 2026-04-11
created_at: 2026-04-11T19:25:00+08:00
author: co-authored
session_id: session-2026-04-11c
session_turn: 198
project: csq-v2
topic: Anthropic retired platform.claude.com/v1/oauth/authorize; current endpoint is claude.com/cai/oauth/authorize with paste-code flow
phase: implement
tags: [oauth, anthropic, endpoint, migration, breaking]
---

# DISCOVERY: Anthropic moved the Claude Code OAuth authorize endpoint

## Context

A user running `npm run tauri dev` clicked the new "+ Add Account → Claude" button. The child webview opened, navigated to the authorize URL csq built from `csq-core/src/oauth/constants.rs`, and displayed this response body verbatim:

```json
{
  "type": "error",
  "error": { "type": "not_found_error", "message": "Not Found" },
  "request_id": "req_011CZwsDz58c3z4oJNnBfGB1"
}
```

The shape is the Anthropic API's standard 404 — which meant a real host had served that response. The authorize endpoint we'd been building against was gone.

## Evidence

Direct verification via `WebFetch`:

| URL                                      | Status | Notes                                                                |
| ---------------------------------------- | ------ | -------------------------------------------------------------------- |
| `platform.claude.com/v1/oauth/authorize` | 404    | Returns Anthropic API 404 JSON shape                                 |
| `claude.ai/oauth/authorize`              | 403    | Cloudflare cf-mitigated challenge (real endpoint, just browser-only) |
| `claude.com/cai/oauth/authorize`         | —      | **Current endpoint** — observed live                                 |

Ground-truth URL came from running `csq login 1` in a terminal and reading the printed fallback URL. The bash wrapper (`csq` at repo root) shells out to `claude auth login` (the official Claude Code CLI), which printed:

```
https://claude.com/cai/oauth/authorize
  ?code=true                                               # signals paste-code mode
  &client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e         # UNCHANGED from v1.x
  &response_type=code
  &redirect_uri=https://platform.claude.com/oauth/code/callback  # paste-code, not loopback
  &scope=org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload
  &code_challenge=<PKCE SHA-256>
  &code_challenge_method=S256
  &state=<CSPRNG>
```

## What changed

| Aspect         | v1 csq / csq v2 (pre-migration)          | Claude Code (current)                                        |
| -------------- | ---------------------------------------- | ------------------------------------------------------------ |
| Authorize URL  | `platform.claude.com/v1/oauth/authorize` | `claude.com/cai/oauth/authorize`                             |
| Extra param    | none                                     | `code=true` (mode selector)                                  |
| `redirect_uri` | `http://127.0.0.1:8420/oauth/callback`   | `https://platform.claude.com/oauth/code/callback`            |
| Flow type      | loopback (browser → local TCP server)    | paste-code (browser → code-on-screen → user pastes into app) |
| Scopes         | 5 user scopes                            | 5 user scopes + `org:create_api_key`                         |
| `client_id`    | `9d1c250a-e61b-44d9-88ed-5944d1962f5e`   | same — registration unchanged                                |
| Token URL      | `platform.claude.com/v1/oauth/token`     | same — verified by 15 live refresh cycles                    |

## How long has it been broken

Unknown, but **both** csq v1.x (`dashboard/oauth.py`) and csq v2 (`csq-core/src/oauth/constants.rs`) had stale URLs. Neither had been exercised end-to-end recently because:

1. The v1 Python `dashboard/oauth.py` was never called by `csq login` — the bash wrapper delegates to `claude auth login` directly (see journal/0020-DECISION-paste-code-oauth for why this matters). Dead code can't tell you it's broken.
2. csq v2's OAuth module had unit tests for URL structure but no integration test against the live endpoint.
3. Token refresh paths use the token endpoint (unchanged), so existing accounts kept working even though new logins were silently impossible.

## Blast radius

Anything that hit `OAUTH_AUTHORIZE_URL`:

- `csq-core::oauth::login::start_login` — fixed in same session
- `csq-core::daemon::server::login_handler` (`GET /api/login/{N}`) — fixed in same session
- `csq-desktop::commands::start_claude_login` — works after URL update
- v1 Python `dashboard/oauth.py` — still has the dead URL; unreachable through `csq login`, so low priority

## Implications for future sessions

1. **Don't trust OAuth constants across releases.** Anthropic has moved at least one endpoint for this client_id without notice. An OAuth-reachability smoke test (probe the authorize URL, assert 200 or the expected Cloudflare 403) catches this in under a second.
2. **Unit tests for URL structure are not enough.** All 65 existing tests passed against a dead URL. Only a network probe can tell you the endpoint is alive.
3. **`claude auth login` is the reference implementation.** When in doubt about Claude Code's OAuth behavior, run it and read its output — the wrapper prints the live URL before opening the browser.

## For Discussion

1. **Should `csq daemon start` probe the authorize URL on boot** and log a loud warning if it returns 404? A single HEAD request against `claude.com/cai/oauth/authorize` on startup would have caught this migration the day it happened instead of weeks later when a user first tried to add an account. The cost is one network call per daemon start and a flaky-network failure mode to design around.
2. **Is there a way to subscribe to Anthropic's OAuth app rotation announcements**, or a canonical discovery document (`.well-known/oauth-authorization-server`) we should prefer to hardcoded constants? Hardcoding has worked for two years but we now know the failure is silent and sessions-long. A one-shot fetch of a well-known document at daemon start — with the hardcoded values as a fallback — would self-heal.
3. **Should csq v1.x (`dashboard/oauth.py`) be deleted now** that its constants are provably stale and the `csq` wrapper doesn't call it? Leaving dead code with a working-looking PKCE implementation is a trap for the next contributor who greps for "oauth" and starts reading there.

## Cross-references

- 0020-DECISION-paste-code-oauth-as-canonical-flow.md — why we rewrote the flow instead of just updating the URL
- `csq-core/src/oauth/constants.rs` — current constants
- `csq-core/src/oauth/login.rs` — paste-code builder
