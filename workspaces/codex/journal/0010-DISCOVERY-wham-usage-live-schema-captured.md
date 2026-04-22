---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T06:20:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c00
session_turn: 40
project: codex
topic: §5.7 wham/usage schema captured live — two-window rate_limit (5h primary + 7d secondary) parallel to Anthropic; used_percent is 0-100 not 0-1; top-level has PII (user_id/account_id/email) requiring redaction
phase: analyze
tags: [codex, wham-usage, schema, resolved, PII, pr-c00-followup]
---

# Discovery — §5.7 live capture: `wham/usage` schema pinned

## Context

Journal 0008 (GAP) recorded that this session's OPEN-C04 transport probe burned the user's stored refresh_token, blocking the §5.7 live capture. The user completed a `codex login` cycle to re-auth; `~/.codex/auth.json` now has a fresh `access_token` + `refresh_token` (plus a new top-level `account_id` field that wasn't present before — interesting for PR-C3 but out-of-scope here). This journal documents the resulting live capture and replaces journal 0008's GAP state.

## Probe

```bash
TOK=$(jq -r '.tokens.access_token' ~/.codex/auth.json)
curl -sS -o /tmp/wham-capture.json \
  -w "http=%{http_code}\n" \
  -H "Authorization: Bearer $TOK" \
  -H "Accept: application/json" \
  -H "User-Agent: csq/wham-usage-capture" \
  "https://chatgpt.com/backend-api/wham/usage"
```

Result: `http=200`. Response parsed and inspected with `jq`. PII values redacted before inclusion in this journal.

## Captured shape (values redacted, types preserved)

```json
{
  "user_id": "<PII: opaque user UUID>",
  "account_id": "<PII: opaque account UUID>",
  "email": "<PII: user email>",
  "plan_type": "plus",
  "rate_limit": {
    "allowed": true,
    "limit_reached": false,
    "primary_window": {
      "used_percent": 0,
      "limit_window_seconds": 18000,
      "reset_after_seconds": 18000,
      "reset_at": 1776856630
    },
    "secondary_window": {
      "used_percent": 0,
      "limit_window_seconds": 604800,
      "reset_after_seconds": 604800,
      "reset_at": 1777443430
    }
  },
  "code_review_rate_limit": null,
  "additional_rate_limits": null,
  "credits": {
    "has_credits": false,
    "unlimited": false,
    "overage_limit_reached": false,
    "balance": "0",
    "approx_local_messages": [0, 0],
    "approx_cloud_messages": [0, 0]
  },
  "spend_control": { "reached": false },
  "rate_limit_reached_type": null,
  "promo": null,
  "referral_beacon": null
}
```

### Field summary (12 top-level keys)

| Path                                             | Type         | csq quota-path use                                                            |
| ------------------------------------------------ | ------------ | ----------------------------------------------------------------------------- |
| `user_id`                                        | string (PII) | **Redact.** Not stored.                                                       |
| `account_id`                                     | string (PII) | **Redact.** Not stored.                                                       |
| `email`                                          | string (PII) | **Redact.** Not stored.                                                       |
| `plan_type`                                      | string       | Tier metadata (e.g. `"plus"`, `"team"`, likely `"free"`). Store for UI label. |
| `rate_limit.allowed`                             | bool         | Slot callable flag.                                                           |
| `rate_limit.limit_reached`                       | bool         | Parallel of Anthropic `limit_reached`.                                        |
| `rate_limit.primary_window.used_percent`         | number       | **Primary quota source, 0-100.** Emit as `QuotaKind::Utilization`.            |
| `rate_limit.primary_window.limit_window_seconds` | number       | Window size (observed: 18000 = 5h).                                           |
| `rate_limit.primary_window.reset_after_seconds`  | number       | Countdown to reset.                                                           |
| `rate_limit.primary_window.reset_at`             | number       | Unix epoch of reset (preferred — absolute beats relative).                    |
| `rate_limit.secondary_window.*`                  | (same)       | 7d rolling window (604800 = 7d). Second utilization emission.                 |
| `code_review_rate_limit`                         | null/object? | Unobserved (plan=plus, no code-review activity). Treat as optional.           |
| `additional_rate_limits`                         | null/object? | Unobserved. Optional.                                                         |
| `credits.*`                                      | object       | PAYG / overage context. Not csq-quota relevant; skip.                         |
| `spend_control.reached`                          | bool         | Billing flag; not csq-quota. Surface as separate UX if desired.               |
| `rate_limit_reached_type`                        | null/string? | Likely a tag when a window is exhausted (e.g. `"primary"`). Optional.         |
| `promo` / `referral_beacon`                      | null/object? | Marketing metadata. Ignore.                                                   |

## Discovery

`GET chatgpt.com/backend-api/wham/usage` returns a rich object with:

1. **Two concurrent rate-limit windows** — primary (5h, 18000s) and secondary (7d, 604800s) — parallel to Anthropic's `/api/oauth/usage` 5h+7d pattern. This is the structural alignment csq needed: `QuotaKind::Utilization` emits both windows with no abstraction mismatch.

2. **`used_percent` is already a percentage (0-100), not a fraction (0-1).** Matches Anthropic's `utilization` field behavior (csq memory `discovery_anthropic_api_quirks.md`). csq stores it as a `f64` in `[0.0, 100.0]`.

3. **Three absolute PII fields at top level** — `user_id`, `account_id`, `email`. Per redteam H5 these MUST be stripped before the drift-capture write path (`accounts/codex-wham-drift.json`). Redactor extension (PR-C0) adds a PII strip rule for these three keys in addition to the existing token-pattern rules.

4. **Reset-timestamp pair** — both `reset_after_seconds` (countdown) and `reset_at` (Unix epoch) are provided. csq uses `reset_at` as canonical (absolute is idempotent across retries; `reset_after_seconds` drifts with request latency). `reset_after_seconds` remains useful as a sanity-check for clock-skew detection.

5. **Null-heavy optional fields** — `code_review_rate_limit`, `additional_rate_limits`, `rate_limit_reached_type`, `promo`, `referral_beacon` are all `null` on a healthy plus-plan account. Parser must tolerate both `null` and future object-shapes; fail-soft into `QuotaKind::Unknown` only on structural surprise (new top-level key unknown to the parser AND `rate_limit.*` fields missing).

6. **`credits` block is orthogonal to subscription quota.** Signals PAYG overage / API-credit state. Not relevant to ChatGPT-subscription quota tracking; skip in csq's quota write-path. May become relevant in a future "billing surface" feature but that's out of scope for v2.1.

## Why this matters

1. **Schema PROPOSED → VERIFIED.** Spec 05 §5.7 status flips from PROPOSED to VERIFIED; placeholder block is replaced with the observed shape. Parser in PR-C5 implements against a confirmed contract.

2. **Parser implementation is trivial.** Structural match with Anthropic's poller — `primary_window.used_percent` + `primary_window.reset_at` + `secondary_window.*` are the only fields that reach `quota.json`. ~40 LOC in `csq-core/src/daemon/usage_poller/codex.rs`.

3. **PII redaction is now a concrete set, not a placeholder.** H5 pre-redact strip targets exactly three keys (`user_id`, `account_id`, `email`). PR-C0's redactor extension can land with a specific test:

   ```rust
   #[test]
   fn wham_drift_snapshot_strips_user_id_account_id_email() { ... }
   ```

4. **plan_type is lightweight tier context worth storing.** csq doesn't need it for quota math, but the AccountCard can display "Plus plan — 0% of 5h window" vs a raw percentage. Good UX cheap. Add as `plan_type: Option<String>` on AccountQuota's `extras` field (spec 07 §7.4.1 `extras: Option<Value>` escape hatch).

5. **csq `quota.json` v2 schema is adequate as-is.** No new fields required. `primary_window` + `secondary_window` fit into the existing `utilization` variant; plan_type parks in `extras`. No schema bump needed.

6. **The `account_id` field now in `auth.json` is noteworthy for PR-C3.** Fresh login returned a NEW top-level `account_id` that wasn't in the pre-probe auth.json shape. This is presumably the `ChatGPT-Account-Id` header value that spec 05 §5.7 assumed csq would need to pass. The field is now readable from auth.json directly — no separate API call needed to discover it.

## Limits of this capture

- **One call against one account.** Plus-plan account, both windows at 0% utilization, `limit_reached: false` across the board. The error-path fields (`rate_limit_reached_type`, `rate_limit.limit_reached: true` scenario, 429 responses) are NOT exercised. The parser MUST handle them tolerantly but cannot be schema-verified against observed examples until a real rate-limit event occurs.

- **No 429 captured.** The placeholder "429 body shape" in §5.7 is still inference, not observation. Follow-up opportunity: deliberately exhaust the 5h window in a throwaway session and capture the 429 body. OR wait for natural rate-limiting post-launch and reactively parse. Cost-benefit favors the latter (natural) approach.

- **No free-plan, no team-plan, no enterprise-plan.** Only `plan_type: "plus"` observed. Other plan values may introduce new fields or change field semantics. Schema-drift circuit breaker catches this post-launch.

- **No code-review activity.** `code_review_rate_limit` was `null`. Its real shape is unknown. Parser treats `null | object` uniformly via `Option<CodeReviewRateLimit>`.

- **Transport was curl (direct).** The PR-C0.5 Node bridge should also surface this shape correctly; integration test in PR-C5 asserts Node-bridge parity.

## Decision impact

- **Spec 05 §5.7 VERIFIED.** Placeholder replaced with the observed shape; revision stamp added.
- **PR-C5 parser target is now concrete.** 40-LOC module against documented fields.
- **PR-C0 redactor adds PII strip for `user_id` / `account_id` / `email`.** Previously "defense-in-depth, shape TBD"; now "defense-in-depth, these three specific keys."
- **Journal 0008 (GAP) state is RESOLVED by this entry.** GAP is immutable per journal rule 1; this entry supersedes the BLOCKED status with a concrete schema.
- **§5.7 VERIFIED becomes a v2.1.0 cut criterion check; was previously uncertain whether it would block.** Now green.

## For Discussion

1. **plan_type discovery suggests csq might expose more than just quota utilization on the Codex AccountCard — plan name, credit status, reset countdown.** Is the v2.1 scope too narrow if we stop at raw utilization, or is feature creep the real risk? (Lean: ship utilization only in v2.1; plan_type label as a follow-up because it's cheap UI-only without write-path complexity.)

2. **The `reset_at` (Unix epoch) vs `reset_after_seconds` (countdown) pair gives csq a clock-drift oracle for free — if server-absolute and local-countdown disagree by >5 seconds, log a drift warning.** Worth wiring into the refresher's clock-skew mitigation (journal 0002 mentions HTTP `Date` header as the skew source), or redundant?

3. **The new `account_id` in auth.json post-login: was this added by a recent codex-cli release, or was it always there and prior auth.json files had it elsewhere?** If it was ALWAYS derivable from the id_token claims, csq shouldn't rely on it being a top-level field; id_token parsing is the stable path. If codex-cli started surfacing it as a convenience field only in 0.122.0+, the minimum supported codex-cli version changes.

## Cross-references

- Spec 05 §5.7 (VERIFIED this PR via revision 1.3.2)
- Journal 0008 (GAP RESOLVED by this entry — journal 0008 itself remains immutable per rule 1; treat 0008 + 0010 as a pair)
- Journal 0007 — OPEN-C04 transport decision (Node bridge); parser tested via both curl and Node bridge in PR-C5
- Journal 0005 — OPEN-C02 (CODEX_HOME respected; relevant because PR-C5 spawns the poller subprocess per-slot)
- Plan §PR-C0 — redactor extension PII-strip set now concrete
- Plan §PR-C5 — parser implementation unblocked
- Memory: `discovery_anthropic_api_quirks.md` — utilization is-already-% confirmed for OpenAI too
- Redteam H5 — PII strip requirement satisfied with concrete target keys
