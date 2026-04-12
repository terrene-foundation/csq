# 0028 — DECISION: Account/Terminal Separation + Python Elimination

**Date**: 2026-04-12
**Type**: DECISION + DISCOVERY
**Status**: Implemented

## Context

Quota data corruption (5800% on account 2) traced to multiple root causes: terminal-sourced quota attribution via Python `rotation-engine.py`, cross-slot credential contamination, and Anthropic API format misunderstandings.

## Decisions

### 1. Account/Terminal Separation (Authority Spec)

**Rule**: `.claude/rules/account-terminal-separation.md`

- **Accounts** are independent entities that authenticate, auto-refresh, and poll Anthropic for their own usage
- **Terminals** borrow credentials and display data — they NEVER write quota
- Only the daemon's usage poller writes `quota.json`, polling `/api/oauth/usage` per account
- CC's per-terminal `rate_limits` JSON is NOT used for account quota

### 2. Python Elimination

All Python removed from product code:
- `rotation-engine.py` (quota corruptor) — deleted
- `csq` bash wrapper (called Python) — deleted, replaced by Rust binary
- `dashboard/` (legacy web dashboard) — deleted
- `test-*.py` files — deleted
- `statusline-quota.sh` rewritten to call Rust `csq statusline` only

### 3. Login via `claude auth login`

Paste-code OAuth exchange abandoned. Desktop Add Account and `csq login N` both delegate to `claude auth login` which handles the full flow (browser, callback, credentials).

## Discoveries

- **Anthropic `/api/oauth/usage`**: `utilization` is already 0-100 percentage, NOT 0-1 fraction. Our `* 100` produced 5800%.
- **Anthropic token endpoint**: Rejects HTTP/2, requires `no_gzip/no_brotli/no_deflate`, and requires `curl/*` User-Agent string. Non-curl UAs get 400 "Invalid request format".
- **macOS keychain**: GUI apps (Tauri) don't have `$USER` env — use `libc::getpwuid`. CC writes raw JSON to keychain, not hex-encoded. Use `security` CLI (pre-authorized) instead of `security-framework` crate (per-binary keychain prompts on every debug rebuild).
- **3P quota APIs**: Neither MiniMax nor Z.AI exposes programmatic quota endpoints. MiniMax's `coding_plan/remains` is behind Cloudflare (403). Z.AI returns no rate-limit headers.
