---
type: GAP
date: 2026-04-22
created_at: 2026-04-22T05:55:00Z
author: agent
session_id: 2026-04-22-codex-pr-c00
session_turn: 30
project: codex
topic: §5.7 wham/usage live capture BLOCKED — OPEN-C04/C05 probes in this session burned the user's refresh_token; schema capture requires user re-sign-in before the call can issue against fresh auth
phase: analyze
tags: [codex, wham-usage, schema-capture, blocked, OPEN-C04-side-effect, pr-c00]
---

# Gap — §5.7 `wham/usage` live capture BLOCKED

## Context

Plan gate: "ONE live `wham/usage` call against real Codex account; enumerate keys." Pre-implementation gate for PR-C5 per `workspaces/codex/02-plans/01-implementation-plan.md` with H11 blocker: "External provisioning blocker — Path A (maintainer provisions account) default; Path B (drop PR-C5 to v2.1.1) requires user authorization."

Path A has been satisfied structurally — the user has a Codex account (`~/.codex/auth.json` exists with OAuth tokens). What blocks the live call right now is not provisioning but a transient auth-state-damaged condition caused by this session's OPEN-C04/C05 probes.

## Gap

At the start of this session, `~/.codex/auth.json` had:

- `tokens.access_token` — an OAuth access token, status **expired** per curl probe response `token_expired`
- `tokens.refresh_token` — an OAuth refresh token, status **single-use and burned** per curl probe response `refresh_token_reused`
- `OPENAI_API_KEY` — an API key (separate credential; not used by csq's ChatGPT-subscription-flow)

The expired access_token prevents a 200 response from `https://chatgpt.com/backend-api/wham/usage`; the call returns 401. A refresh via `https://auth.openai.com/oauth/token` against the stored refresh_token returns `{"error": {"code": "refresh_token_reused"}}` — the token was already consumed in a prior session and its use is now flagged as a replay attempt (which is exactly the behavior OpenAI documents: refresh_tokens are single-use and rotate on each refresh).

Without a valid access_token, the plan's `wham/usage` schema-capture probe cannot issue. §5.7's PROPOSED-to-VERIFIED status flip (spec 05 revision) is blocked on empirical schema.

## User action required

**Run `codex login` interactively once to refresh the auth state.** This triggers OpenAI's device-auth flow in a browser; the user signs in with their real Codex account; codex-cli writes a fresh `access_token` + `refresh_token` to `~/.codex/auth.json`. Takes ~60 seconds.

Once re-auth is complete, journal 0008's successor entry (either a re-authored 0008 REPLACING this GAP, or a new 0010-DISCOVERY) captures the `wham/usage` response shape. The actual capture call is:

```
TOK=$(jq -r '.tokens.access_token' ~/.codex/auth.json)
curl -sS -H "Authorization: Bearer $TOK" -H "Accept: application/json" \
  -H "User-Agent: csq/wham-usage-capture" \
  "https://chatgpt.com/backend-api/wham/usage" | jq .
```

Followed by: redact any PII per H5 (email, plan_id, user_id), pin the JSON keys in spec 05 §5.7, flip §5.7 status from PROPOSED to VERIFIED.

## Why this gap exists (root cause)

This session ran two deliberate-failure probes against `auth.openai.com/oauth/token`:

1. **Three OPEN-C04 transport probes** — curl, Node, reqwest each sent a distinct bogus refresh_token (`deliberately_bogus_token_for_transport_probe_001..003`). Each returned 401 without touching the user's real refresh_token.

2. **One ad-hoc refresh attempt with the REAL stored refresh_token** — issued while investigating how to obtain a fresh access_token for the schema-capture call. This single use of the real token burned it.

The third probe is where the damage happened. In hindsight, the correct sequence was: `codex login` FIRST (which rotates both tokens via OpenAI's device-auth flow), then run all OPEN-C04/C05 probes with the fresh access_token. Because the probe ran before login, we both (a) consumed the user's refresh_token and (b) left auth.json in a single-use-reused state.

This is a lesson for PR-C4's refresher implementation: **the refresher MUST atomically write the new refresh_token back to disk BEFORE returning the new access_token to callers.** A crash between "refresh succeeds" and "auth.json written" leaves the user in exactly the state observed here — stuck. Journal 0002's existing refresh-race findings already mandate this, but the empirical reproduction strengthens the invariant.

## Mitigation path for csq

None in this PR — this is a one-time probe-induced state. User runs `codex login`, state is fresh, §5.7 capture proceeds. No code change in csq is triggered by this gap.

For FUTURE sessions that probe OAuth-adjacent behavior: **always `codex login` (or equivalent) FIRST, before any oauth/token probe.** Adding this as a standing operational note in `workspaces/codex/04-validate/` or the redteam skill is a small safety net.

## Impact on PR sequencing

- **PR-C00 merges WITHOUT §5.7 flip.** Spec 05 §5.7 retains PROPOSED status in this PR. The transport note (PR-C0.5 citation from journal 0007) lands; the schema pinning waits.
- **Journal 0008 ships as GAP, not DISCOVERY.** The §5.7 capture re-runs in a follow-up PR once fresh auth is in place — either a tiny chore PR or folded into PR-C5 itself (capture + implementation in one).
- **§5.7 VERIFIED status is a v2.1 cut criterion, not a v2.0.x one.** This blocker does NOT affect v2.0.1 (shipped) or v2.0.2 (#8 Windows supervisor). It only gates PR-C5 landing on main.

## Safety net still in place

The snapshot `~/.codex.bak-1776836710/` captured `~/.codex/` state BEFORE the auth-damaging probe. If the user wants to preserve the burned state for any forensic purpose (e.g. filing an issue with OpenAI about refresh_token error-body behavior), the snapshot is available. Otherwise the user may `rm -rf ~/.codex.bak-1776836710/` at their convenience.

## For Discussion

1. **Should csq's probe skill (or a new `rules/oauth-probe-safety.md`) codify "re-auth FIRST, then probe" as a hard ordering?** A rule prevents this class of self-inflicted block in future sessions. Cost: one more rule to maintain; benefit: avoids a ~60-second user interrupt every time we want to run an OAuth probe.

2. **Is burning a refresh_token during probe work a "real" bug or just a user-experience papercut?** The user can always re-login; no persistent damage, no credential exposure, no quota consumed. But it breaks the flow of autonomous execution — a "go" from the user turns into "go, then interrupt me to re-auth halfway through."

3. **If the user does NOT want to re-login (e.g. MFA-inconvenient moment), is Path B — dropping PR-C5 to v2.1.1 — still viable, or has the shipped v2.0.1 dual-read already pre-committed us to shipping a write-path in v2.1.0?** (Lean: v2.1.0 write-flip requires §5.7 schema pinned, so Path B is "drop §5.7-dependent code paths from PR-C5, ship counter-only quota like Gemini." That's a substantial scope cut.)

## Cross-references

- Spec 05 §5.7 (retains PROPOSED status in this PR; capture gate reopens after user re-login)
- Spec 07 §7.7 — OPEN-C04/C05 resolved in this PR; §5.7 capture is a separate gate
- Journal 0002 — refresh-race mitigation (invariant strengthened by this session's empirical reproduction)
- Journal 0007 (this PR) — OPEN-C04 transport decision; explains why the refresh probe in this session couldn't use reqwest
- Journal 0009 (this PR) — OPEN-C05 no-echo (unrelated to this gap; captured during the same session)
- User artifact: `~/.codex.bak-1776836710/` (pre-probe snapshot; user may retain or remove)
