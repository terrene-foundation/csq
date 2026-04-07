---
type: DECISION
date: 2026-04-01
created_at: 2026-04-01T17:30:00+08:00
author: co-authored
session_id: terrene-squad
session_turn: 80
project: claude-squad
topic: Multi-account rotation architecture for Claude Code
phase: implement
tags: [claude-code, account-rotation, rate-limits, infrastructure]
---

## Decision

Built and published `terrene-foundation/claude-squad` — a multi-account rotation system for Claude Code that pools Claude Max subscriptions with automatic, quota-aware switching.

## Architecture Chosen

**Statusline-driven, keychain-swapping, session_id-coordinated.**

- Statusline command receives `rate_limits` (five_hour + seven_day with `used_percentage` and `resets_at`) from Claude Code on every render — zero-cost quota tracking
- Credentials stored per-account in `~/.claude/accounts/credentials/N.json` with refresh tokens (~1 year lifetime)
- On rotation: engine writes target account's credentials to macOS Keychain and updates `.credentials.json` so Claude Code picks up the new credentials
- Sessions tracked by `session_id` (from statusline JSON), not PIDs (PIDs change per subprocess call)
- flock-based coordination prevents concurrent write conflicts

## Alternatives Considered

1. **`CLAUDE_CONFIG_DIR` per terminal** — Rejected: loses session context, can't auto-rotate mid-session
2. **`/login` mid-session** — Works but requires browser, not automatable
3. **`claude setup-token`** — Generates `sk-ant-oat01-*` tokens but these only work for Agent SDK, not CLI inference
4. **`CLAUDE_CODE_OAUTH_TOKEN` env var** — Only passes access tokens (expire in ~6 hours), not refresh tokens
5. **Direct API polling via curl** — Blocked by Cloudflare on `claude.ai` endpoints

## Key Discovery: Refresh Token is the 1-Year Key

The OAuth refresh token (`sk-ant-ort01-*`, 108 chars) stored in the Keychain's `claudeAiOauth.refreshToken` field is long-lived (~1 year). It can be exchanged for fresh access tokens via the public OAuth refresh endpoint. The `CLAUDE_CODE_OAUTH_REFRESH_TOKEN` env var passes it to sandboxed `claude -p` calls for parallel account polling.

## Priority Algorithm

Use-it-or-lose-it: `urgency = 1000 - (hours_until_weekly_reset * 6)`. Accounts with weekly quota expiring soonest get drained first. 5-hour blocks are temporary parks — engine rotates back when cleared. Load-balancing penalty: `-100 * terminal_count` per account.

## For Discussion

- If Claude Code changes how `rate_limits` are exposed in the statusline JSON, the entire quota tracking breaks — how fragile is this dependency on an undocumented JSON shape?
- If the refresh token rotation behavior changes (currently rotated on each access token refresh), would a dedicated "account vault" service be more robust than file-based credential storage?
- What happens when all accounts are simultaneously rate-limited — should the system queue work or fail loudly?
