# 0029 — Identity Derivation, Subscription Contamination, GrowthBook Override

**Date:** 2026-04-12
**Type:** DECISION + DISCOVERY
**Status:** Implemented

## Context

During live debugging of swap/rename behavior across 8 accounts and 10 config dirs, three distinct failure classes were discovered operating simultaneously. The overlap made diagnosis difficult — symptoms from all three looked like "swap shows wrong account / wrong model."

## Finding 1: Slot Number != Account Number (INVARIANT)

**Root cause:** Code used `config-N` directory suffix as account identity. After any swap or rename, slot number and account number diverge permanently.

**Affected code:**
- `commands.rs:292` — `SessionView.account_id` used dir number instead of `.csq-account` marker
- `commands.rs:382` — `swap_session` 3P source check validated against dir number, not marker

**Fix:** All identity derivation now reads `.csq-account` marker. Dir number is fallback-only with warning.

**Invariant codified:** `rules/account-terminal-separation.md` rule 5.

## Finding 2: Subscription Contamination (FAILURE MODE)

**Root cause:** Anthropic's OAuth token endpoint does NOT return `subscriptionType` or `rateLimitTier`. These are set to `None` by `exchange_code` and backfilled by CC at runtime. Any credential copy (swap, fanout) that propagates `None` causes CC to lose Max tier and default to Sonnet.

**Propagation path:** `exchange_code` → `None` in canonical → `merge_refresh` preserves `None` → `swap_to` copies `None` to live → CC reads `None` → Sonnet.

**Fix:** Two-site defensive guard in `rotation/swap.rs` and `broker/fanout.rs` — both check for missing `subscription_type` and preserve the value from existing live credentials.

**Invariant codified:** `rules/account-terminal-separation.md` rule 6.

## Finding 3: GrowthBook Feature Flag Override (EXTERNAL DEPENDENCY)

**Root cause:** Anthropic's server-side A/B testing (GrowthBook) assigned `tengu_auto_mode_config: {"enabled": "opt-in", "model": "claude-sonnet-4-6[1m]"}` to one user ID. This overrides model selection regardless of subscription tier. Cached in `.claude.json` per config dir.

**Diagnostic pattern:** When "wrong model" is reported and credentials look correct, diff `cachedGrowthBookFeatures` between working and broken config dirs BEFORE investigating credentials.

**Fix:** Cleared the cached flag. No code change possible — this is Anthropic's server-side experiment.

**External dependency codified:** `rules/account-terminal-separation.md` External Dependencies section + `skills/provider-integration/SKILL.md`.

## Finding 4: Stale Session Detection (PATTERN)

CC caches credentials in memory at startup. After a swap, the on-disk state changes but the running CC process retains old tokens. Detection heuristic: `.csq-account` marker mtime > process `started_at`.

**Codified:** `commands.rs` `needs_restart` field in `SessionView`, displayed as "restart needed" badge in `SessionList.svelte`.

## Cross-Cutting Observation

Findings 1, 2, and 3 share a root: **physical artifact identity diverges from logical identity after state transitions.** Directory names, token endpoint responses, and GrowthBook caches are all stale after swaps/logins/experiments. The `.csq-account` marker and live credential metadata are authoritative.

## Artifacts Updated

- `rules/account-terminal-separation.md` — rules 5, 6, 7 + External Dependencies section
- `skills/daemon-architecture/SKILL.md` — identity derivation, subscription metadata, stale session detection under Invariant 0
- `skills/provider-integration/SKILL.md` — token endpoint limitation + GrowthBook diagnostic
- `rules/tauri-commands.md` — error mapping rule for named variants
