# Account/Terminal Separation

Applies to ALL code that reads, writes, or displays account credentials, quota data, or usage information.

## The Two Entities

### Accounts

An Account is an independently authenticated Anthropic identity (email + OAuth tokens). Each account:

- Has its own credentials (`credentials/N.json`)
- Has its own usage quota (polled from Anthropic's `/api/oauth/usage`)
- Auto-refreshes its own tokens (daemon refresher, 5-min cycle)
- Is the SOLE source of truth for its own quota data

Analogy: an Account is like a Chrome profile logged into `claude.ai/settings/usage`. It independently shows its own usage, refreshes its own session, and never asks any terminal what its usage is.

### Terminals (Sessions)

A Terminal is a CC instance (`claude` process) running in a config directory (`config-N/`). Each terminal:

- Borrows an account's credentials (via `.credentials.json` symlink/copy)
- Can swap to any account (`csq swap N`)
- Displays the borrowed account's quota data (read-only)
- NEVER writes quota data
- NEVER determines which account it "belongs to" for quota purposes

Multiple terminals can use the same account simultaneously. The account's quota reflects total usage across ALL terminals using it, as reported by Anthropic.

## MUST Rules

### 1. Only the Daemon Writes Quota Data

Quota data in `quota.json` MUST only be written by the daemon's usage poller (`daemon/usage_poller.rs`), which polls Anthropic's `/api/oauth/usage` endpoint directly with each account's access token.

```
DO:  daemon polls /api/oauth/usage with account 2's token -> writes to quota.json[2]
DO NOT: terminal reads CC's rate_limits JSON -> writes to quota.json[guessed_account]
```

**Why:** Terminal-to-account attribution is unreliable (marker mismatch, credential contamination, orphaned sessions). Polling Anthropic directly with the account's own token is unforgeable — the response IS that account's usage.

### 2. Terminals Read Quota, Never Write It

The statusline command (`csq statusline`) MUST only READ from `quota.json` and display the result. It MUST NOT call `state::update_quota()` or any function that writes quota data.

```
DO:  csq statusline -> read quota.json -> format -> print
DO NOT: csq statusline -> parse CC JSON -> update_quota() -> print
```

**Why:** CC's per-terminal `rate_limits` JSON is a terminal-scoped snapshot, not an account-scoped measurement. Attributing it to an account requires solving the "which account is this terminal running on?" problem, which has 3+ failure modes (contamination, orphaned credentials, marker drift).

### 3. Accounts Auto-Refresh After Login

After a user authenticates an account (Add Account / `csq login N`), the daemon MUST automatically:

1. Start refreshing that account's tokens before they expire
2. Start polling that account's usage from Anthropic
3. Fan out refreshed credentials to all terminals using that account

No manual action beyond the initial login is required.

**Why:** Accounts are independent entities. Once authenticated, they maintain themselves.

### 4. Account Quota Comes from Anthropic, Not CC

The usage poller reads `utilization` (0.0-1.0) from Anthropic's `/api/oauth/usage` endpoint and converts to percentage (0-100). This is the ONLY acceptable source for quota percentages.

```
DO:  Anthropic returns {"utilization": 0.42} -> store used_percentage: 42.0
DO NOT: CC statusline reports {"used_percentage": 2400} -> store used_percentage: 2400.0
```

**Why:** CC's `rate_limits.used_percentage` reflects a single terminal's view and can report values >100% (throttled but not blocked). Anthropic's usage API returns the canonical account-level utilization.

## MUST NOT Rules

### 1. No Terminal-to-Account Attribution for Quota

MUST NOT attempt to determine which account a terminal is running on for the purpose of writing quota data. Functions like `live_credentials_account()` or marker-based attribution MUST NOT be used in quota write paths.

**Why:** This attribution problem has been the root cause of every quota corruption bug: 1200% on account 2 (marker fallback), cross-contamination (shared refresh tokens), orphaned sessions (fanout miss).

### 2. No statusline JSON in Quota Pipeline

CC's statusline JSON (`rate_limits` field) MUST NOT feed into `quota.json`. The statusline JSON is useful for terminal-local display (e.g., showing usage in the terminal itself) but MUST NOT be persisted or attributed to an account.

**Why:** The statusline JSON belongs to the terminal, not the account. Persisting it requires solving attribution, which is the problem that caused 6 contamination issues and 2400% phantom usage.

### 5. Identity Derivation Uses Marker, Not Directory Name

The `.csq-account` marker is the SOLE authority for "which account is this session using." Config directory numbers (`config-8` → `8`) are **slot identifiers** with no semantic meaning after initial setup. Swaps and renames cause slot numbers and account numbers to diverge permanently.

```
DO:  let account = markers::read_csq_account(&config_dir).map(|n| n.get())
DO NOT: let account = extract_account_id_from_dir_name(&config_dir)
```

**Why:** Using directory names for account identity caused two bugs: SessionView showed wrong account after swap (display), and the 3P source check validated against a nonexistent account (security). Both were write-path bugs that silently corrupted user-visible state.

**How to apply:** Any code needing the account number for a config dir MUST read `.csq-account`. Falling back to the dir number is acceptable ONLY when the marker is unreadable, and MUST be logged as a warning.

### 6. Credential Copies Preserve Subscription Metadata

`subscription_type` and `rate_limit_tier` are NOT returned by Anthropic's OAuth token endpoint. CC backfills them into the live `.credentials.json` on first API call. The canonical `credentials/N.json` may have `None` for both fields after a fresh login.

Any code that copies canonical credentials to a live config dir (swap, fanout) MUST check for missing subscription metadata and preserve the existing value from the live `.credentials.json`.

```
DO:  if canonical.subscription_type.is_none() { preserve from existing live }
DO NOT: blindly overwrite live with canonical (strips subscription → CC falls back to Sonnet)
```

**Why:** Overwriting live credentials with `subscription_type: None` causes CC to lose its Max tier and default to Sonnet. The user sees the wrong model with no error message. This contamination bug affected all terminals swapped to account 2 in the 2026-04-12 session.

**Guard locations:** `rotation/swap.rs` (swap_to) and `broker/fanout.rs` (fan_out_credentials) — both must remain in sync.

### 7. Stale Session Detection After Swap

After a swap on a running CC session, the process retains stale in-memory credentials. Detection: compare `.csq-account` marker mtime with process `started_at`. If the marker is newer, the session needs a restart.

```
DO:  show "restart needed" indicator when marker_mtime > process_start_time
DO NOT: assume swap takes effect immediately on running CC processes
```

**Why:** CC caches credentials at startup and does not watch `.credentials.json` for changes. After a swap, the dashboard shows the new account but CC is still using the old account's tokens. Without an indicator, the user believes the swap succeeded when it hasn't.

## External Dependencies

### GrowthBook Feature Flags

CC caches server-side A/B test flags from Anthropic's GrowthBook service in `.claude.json` under `cachedGrowthBookFeatures`. The flag `tengu_auto_mode_config` can override model selection silently, regardless of subscription tier.

**Diagnostic:** When a user reports "wrong model" and credentials/subscription look correct, check `.claude.json` for `cachedGrowthBookFeatures.tengu_auto_mode_config`. If it contains `{"enabled": "opt-in", "model": "claude-sonnet-..."}`, that's the cause — not our code.

**Why this matters for csq:** This failure mode is indistinguishable from subscription contamination at the symptom level. Before checking credentials, diff `.claude.json` GrowthBook caches between a working and broken config dir.

## Cross-References

- `skills/daemon-architecture/SKILL.md` — Daemon subsystem design
- `skills/provider-integration/SKILL.md` — Token endpoint limitations, GrowthBook flags
- `rules/security.md` — Credential handling, atomic writes
- `csq-core/src/daemon/usage_poller.rs` — The ONLY quota writer
- `csq-core/src/daemon/refresher.rs` — Account auto-refresh
- `csq-core/src/rotation/swap.rs` — Subscription guard in swap_to
- `csq-core/src/broker/fanout.rs` — Subscription guard in fan_out_credentials
- `csq-cli/src/commands/statusline.rs` — Terminal display (read-only)
