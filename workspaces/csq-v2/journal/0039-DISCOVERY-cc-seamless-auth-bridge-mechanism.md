---
type: DISCOVERY
date: 2026-04-13
created_at: 2026-04-13T22:00:00+08:00
author: co-authored
session_id: 2026-04-13-alpha-5-login-ux
session_turn: 60
project: csq-v2
topic: Claude Code's seamless OAuth uses a local listener bridged by the hosted callback page — loopback is NOT retired the way journal 0020 claimed
phase: redteam
tags: [oauth, cc-compatibility, paste-code, seamless, journal-0020-revision]
---

# CC's seamless auth is still alive — via a hosted-page localhost bridge

## Context

Journal 0020 (2026-04-11) decided to rewrite csq's OAuth flow to paste-code because "Anthropic retired loopback for this client_id." The evidence at the time was that Anthropic's OAuth provider no longer accepts `http://127.0.0.1:<port>/callback` as a registered `redirect_uri` for the Claude Code client_id `9d1c250a-e61b-44d9-88ed-5944d1962f5e`.

That piece is true. What journal 0020 missed: **the reference client (`claude auth login`) still presents a seamless, single-command UX — it just uses a different mechanism to get the code back to the CLI.**

Reproduced this session by running `claude auth login` with `CLAUDE_CONFIG_DIR=/tmp/claude-probe`, then inspecting process state:

```text
$ claude auth login
Opening browser to sign in…
If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&client_id=…&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback&…
Login successful.

$ lsof -p <cc_pid>
  2.1.104 18670 esperie 11u IPv6 0x4512…  TCP localhost:56744 (LISTEN)
```

## The mechanism

1. `claude auth login` starts a local HTTP listener on `[::1]:<random_port>` (IPv6 loopback — doesn't show up in `lsof -i4`, only `-i6`). The listener serves `GET /callback?code=…&state=…`.
2. CC opens the browser to `https://claude.com/cai/oauth/authorize?...&redirect_uri=https://platform.claude.com/oauth/code/callback`.
3. The user signs in at claude.com. Anthropic redirects to the hosted callback page at `platform.claude.com/oauth/code/callback?code=…&state=…`.
4. **The hosted page has client-side JavaScript that POSTs the code + state to `http://[::1]:<cc_port>/callback`.** This is the bridge — no OAuth provider involvement, just a browser-to-localhost fetch issued by Anthropic's own hosted page.
5. CC receives the code on its listener, exchanges it for tokens, and prints `Login successful.`

Probed the listener directly:

```text
$ curl http://[::1]:56744/callback
Authorization code not found
```

The 400-with-message response confirms the path `/callback` is specifically wired — not a stub. Probe on `/` returned 404.

## The port-discovery question (unresolved)

How does the hosted page know WHICH random port CC opened? The authorize URL carries no port parameter. Three hypotheses:

1. **Port scan**: the hosted page tries `[::1]:50000-65535/callback` until one responds. Linear cost ~5s at 50ms/probe — possible but slow.
2. **Deterministic port**: CC might prefer a fixed port (I found `defaultPort = 6499` in the binary strings, but the actual port I observed was random).
3. **Server-side session state**: CC registers the port with Anthropic via a separate API before opening the browser; the hosted page reads the port from its session and uses it.

Not fully reverse-engineered. Future session: inspect the hosted callback page's JavaScript directly OR use `tcpdump` on the loopback interface during an auth flow to see what the page actually connects to.

## Why csq shouldn't reimplement this today

Even if we decoded the port-discovery mechanism, **the bridge is proprietary to Anthropic's hosted page JavaScript and can change without notice**. Any csq listener that tries to piggyback on this would:

- Race CC's own listener if the user has both running
- Break the moment Anthropic changes the bridge (e.g. rotates to a WebSocket, adds a shared-secret handshake, adds origin checks)
- Require a permanent audit-loop chasing upstream changes

The pragmatic path csq adopted in alpha.5: **delegate to `claude auth login` when the `claude` binary is on PATH**. Same seamless UX as running CC directly. csq imports the credentials from the isolated `CLAUDE_CONFIG_DIR=config-N/` after CC exits.

## Consequences

- **Journal 0020's loopback-retired framing is incomplete**. Loopback IS still in use by CC — just via a browser-bridged handshake instead of an OAuth-provider-issued redirect. The "paste-code is the only flow" conclusion was wrong.
- **csq alpha.5 reverses the login priority** (see journal 0040): prefer `handle_direct` (shell out to `claude auth login`) when claude is on PATH; fall back to daemon paste-code with a stdin prompt when it isn't.
- **Paste-code flow is still maintained** as the fallback for environments where Claude Code isn't installed (headless servers, minimal containers).
- **The daemon's `/api/login/{N}` + `/api/oauth/exchange` route pair remains useful** — it's what the fallback consumes.

## For Discussion

1. The port-discovery mechanism is the load-bearing unknown. If it's a port scan, csq could theoretically host its own `/callback` listener alongside CC's and hope Anthropic's page finds one of them. If it's server-side session state, csq cannot piggyback at all without registering its own OAuth client_id. Which hypothesis is worth the ~2 hours to verify, and is the outcome actionable?
2. Journal 0020 deleted ~1500 LOC of csq loopback infrastructure on the "retired" framing. If it turns out csq could reimplement the bridge cheaply, how much of that delete was actually premature?
3. The "delegate to the reference client" principle is broader than just OAuth: any time csq mirrors a Claude Code flow and disagrees with CC's current behavior, csq is wrong by definition (the reference client wins). Should that be codified as a rule (e.g. `rules/reference-client-wins.md`) or left as institutional memory?
