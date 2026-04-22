# 05 Quota Polling Contracts

Spec version: 1.1.0 | Status: VERIFIED | Governs: Anthropic and third-party usage polling

---

## 5.0 Scope

This spec defines the daemon's contract with Anthropic's OAuth usage endpoint and third-party providers (MiniMax, Z.AI). It specifies the request shape, parse rules, and write invariants for `quota.json`.

**Status note:** sections 5.3 (MiniMax) and 5.4 (Z.AI) have been VERIFIED via live API testing (journal 0032). Section 5.2 (claude.ai dashboard endpoint) remains observational — csq uses the OAuth usage endpoint (5.1) instead.

## 5.1 Anthropic `/api/oauth/usage`

**Request:**

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <access_token>
Anthropic-Beta: oauth-2025-04-20
Accept: application/json
User-Agent: curl/<csq-version>     (required — non-curl UAs get 400)
```

Transport constraints (journal 0028 Discovery, load-bearing):

- HTTP/1.1 only. HTTP/2 fails.
- No compression (`no_gzip/no_brotli/no_deflate`).
- `User-Agent` MUST start with `curl/`. This is a server-side allowlist; non-curl UAs return 400 "Invalid request format".

**Response shape:**

```json
{
  "five_hour": { "utilization": 42.0, "resets_at": "2026-04-12T20:00:00Z" },
  "seven_day": { "utilization": 15.0, "resets_at": "2026-04-18T00:00:00Z" }
}
```

**Parse rule (load-bearing):** `utilization` is a percentage in `[0, 100]`, NOT a fraction in `[0, 1]`. Multiplying by 100 produced the 5800% bug that spawned the entire journal 0028 cleanup. The current code in `parse_usage_response` correctly stores the value directly. The header comment on `daemon::usage_poller` is stale (still says "0.0-1.0") and MUST be corrected to avoid re-introducing the bug.

**Resolved (2026-04-12 Playwright investigation):** the 85% vs 100% discrepancy was NOT an endpoint difference. Both endpoints return the same `utilization` field on the same 0-100 scale. The stale reading was caused by the daemon poller dying at 12:17 UTC (see section 5.6). Fix the poller hang and the display matches the web.

## 5.2 claude.ai web dashboard (RESOLVED)

**Investigated 2026-04-12 via Playwright MCP.** The web dashboard at `claude.ai/settings/usage` calls a DIFFERENT endpoint from what csq uses, but the core data is equivalent.

**Endpoint:** `GET https://claude.ai/api/organizations/<org-uuid>/usage`
**Auth:** session cookie (NOT bearer token — csq cannot use this endpoint directly)
**Response:**

```json
{
  "five_hour": {
    "utilization": 8,
    "resets_at": "2026-04-12T16:00:01.287405+00:00"
  },
  "seven_day": {
    "utilization": 4,
    "resets_at": "2026-04-18T11:00:00.287430+00:00"
  },
  "seven_day_oauth_apps": null,
  "seven_day_opus": null,
  "seven_day_sonnet": { "utilization": 0, "resets_at": null },
  "seven_day_cowork": null,
  "iguana_necktie": null,
  "extra_usage": {
    "is_enabled": false,
    "monthly_limit": null,
    "used_credits": null,
    "utilization": null
  }
}
```

**Key findings:**

1. Same core fields as `/api/oauth/usage`: `five_hour.utilization`, `seven_day.utilization`, same 0-100 percentage scale.
2. Additional fields not in the bearer endpoint: per-model 7-day breakdowns (`seven_day_opus`, `seven_day_sonnet`), `seven_day_oauth_apps` (CC-specific usage), `seven_day_cowork`, `extra_usage` (overage billing).
3. Auth is session-cookie-only — csq cannot replay this without maintaining a browser session.
4. Bootstrap call (`GET /api/bootstrap/<org-uuid>/app_start`) returns `rate_limit_tier: "default_claude_max_20x"` confirming subscription tier.

**Decision:** csq stays on `/api/oauth/usage` (bearer-authenticated). The data is equivalent for the fields csq needs. The web endpoint gives richer breakdown data that csq could expose later if cookie auth becomes viable.

## 5.3 MiniMax (RESOLVED — fixed in PR #79)

**Investigated 2026-04-12 via Playwright MCP, corrected 2026-04-12 via direct API testing (journal 0032).**

**Working endpoint:**

```
GET https://platform.minimax.io/v1/api/openplatform/coding_plan/remains
Authorization: Bearer <API_KEY>
Accept: application/json
```

**Notes:**

- **Host:** `platform.minimax.io` (NOT `www.minimax.io` which returns 403 via Cloudflare, and NOT `api.minimax.chat` which is for message traffic only).
- **GroupId:** Optional. The `?GroupId=<group-id>` parameter was initially believed required per browser capture, but direct API testing (journal 0032 Finding 2) confirmed the endpoint works without it, returning all models.

**Response shape:**

```json
{
  "model_remains": [
    {
      "model_name": "MiniMax-M*",
      "current_interval_total_count": 30000,
      "current_interval_usage_count": 29957,
      "current_weekly_total_count": 300000,
      "current_weekly_usage_count": 289423,
      "start_time": 1775988000000,
      "end_time": 1776006000000,
      "remains_time": 281019
    }
  ]
}
```

**CRITICAL — `usage_count` is REMAINING, not consumed.** The endpoint name is `/coding_plan/remains`. `current_interval_usage_count` = remaining usable count. To compute consumed: `used = total - usage_count`. Example: `total=30000, usage_count=29957` → 43 consumed, 0.14% used (journal 0032 Finding 3).

**Parser:** Iterate `model_remains[]`, find entry matching configured model (or `MiniMax-M*` for coding plan), compute 5h percentage as `(total - usage_count) / total * 100`, 7d from `current_weekly_*` fields with same formula.

**Status:** Fixed in PR #79 — correct host, correct parser, correct remaining-vs-consumed semantics.

## 5.4 Z.AI (RESOLVED — API key works, fixed in PR #80)

**Investigated 2026-04-12 via Playwright MCP, corrected 2026-04-12 via direct API testing (journal 0032).**

**Working endpoint:**

```
GET https://api.z.ai/api/monitor/usage/quota/limit
Authorization: Bearer <API_KEY>
Accept: application/json
```

**CRITICAL correction:** The spec originally claimed a JWT session token was required and the API key was insufficient. Journal 0032 Finding 1 proved this wrong — the same API key stored in per-slot `settings.json` (`ANTHROPIC_AUTH_TOKEN`) works for the quota endpoint. The browser captured both cookies AND the Authorization header; the spec attributed auth to the JWT cookie, but the header alone is sufficient.

**Response:**

```json
{
  "code": 200,
  "data": {
    "limits": [
      {
        "type": "TOKENS_LIMIT",
        "unit": 3,
        "number": 5,
        "percentage": 6,
        "nextResetTime": 1776007017081
      },
      {
        "type": "TOKENS_LIMIT",
        "unit": 6,
        "number": 1,
        "percentage": 11,
        "nextResetTime": 1776389633997
      }
    ],
    "level": "max"
  }
}
```

**Unit mapping:** `unit: 3` = 5-hour window, `unit: 6` = 7-day window. `percentage` is already 0-100 (no multiplication needed). Filter by `type: "TOKENS_LIMIT"` to get the coding quota entries.

**Status:** Fixed in PR #80 — daemon polls both 5h and 7d windows with API key auth. The JWT OAuth flow (options 1-3 from the original spec) is no longer needed.

## 5.5 Write invariants

Regardless of source (Anthropic or 3P), the daemon usage poller writes to `quota.json`:

- **One writer**: the usage poller task only. Enforced by rule 1 of `account-terminal-separation.md`.
- **Atomic**: temp file + rename with `0o600` permissions.
- **Per-account keyed**: `quota.json.accounts.<N>` structure preserved. See `csq-core/src/quota/state.rs`.
- **`updated_at` timestamp**: every write stamps the current UNIX time as a float seconds since epoch. Freshness checks (e.g. the dashboard staleness badge — future work) read this field.
- **Rate limits data**: for 3P slots that produce `anthropic-ratelimit-*` headers, the poller ALSO stores `rate_limits` on the account record. Anthropic accounts do not populate this field.

## 5.6 Cooldown and backoff (CRITICAL BUG FIX)

On 2026-04-12 the daemon's usage poller stopped firing after the 12:17 UTC tick. Log evidence showed it successfully completed the 4th Anthropic tick and the `tick_3p` call, then went silent. No panic log, no error. The root cause is almost certainly a blocking HTTP call in `tick_3p` that exceeded the 10-second `reqwest` client timeout (or hung on a TLS handshake under certain conditions) and blocked the `await` on `spawn_blocking` indefinitely.

**Mandatory fixes for the refresh + poller supervisor:**

1. **Per-call timeout**: wrap every `tokio::task::spawn_blocking(|| poll_anthropic_usage(...))` and `spawn_blocking(|| poll_3p_usage(...))` result in `tokio::time::timeout(30s, join_handle)`. On timeout, abort the join handle, log `warn!`, and treat as transient failure (enter cooldown).
2. **Supervised main loop**: `run_loop` MUST be spawned under a supervisor that respawns on panic with exponential backoff, logging the panic payload. Currently the task is `tokio::spawn`ed and its panic dies silently.
3. **Health heartbeat**: the main loop emits a DEBUG log every tick ("usage poller tick complete"). The supervisor checks this heartbeat every 60s; if absent for >3× the expected interval, force-restart the poller subsystem.

These fixes live in the implementation scope of the upgrade that lands specs 01-04. They do not require architecture changes, only hardening.

## 5.7 Codex `/backend-api/wham/usage` (PROPOSED — schema pending live capture)

**Status:** PROPOSED. Endpoint is undocumented; response schema must be captured on first live call in a Codex-provisioned environment. This section locks down what we know; the schema block below is placeholder until verified.

**Request:**

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <codex_access_token>
ChatGPT-Account-Id: <account_id>
Accept: application/json
User-Agent: <csq/version>   (User-Agent gating not confirmed; start with a csq UA + fall back to curl UA on 4xx)
```

Transport considerations:

- TLS-fingerprint behavior (Cloudflare/Akamai) for `chatgpt.com/backend-api/*` is unverified. OPEN-C04 in spec 07 §7.7.4 gates this — if reqwest is blocked, Codex polling reuses the JS-runtime subprocess transport (same pattern as Anthropic per journal 0056). Otherwise native typed HTTP.
- Per-call timeout: 30s (inherits §5.6).

**Response shape (placeholder, TO BE VERIFIED):**

```json
{
  "five_hour": { "utilization": 42.0, "resets_at": "2026-04-22T20:00:00Z" },
  "seven_day": { "utilization": 15.0, "resets_at": "2026-04-28T00:00:00Z" }
}
```

The real shape may differ — confirmed via openai/codex issue #15281 that the field set is richer than what `codex /status` surfaces. First live capture becomes the authority.

**Parse contract:**

- Versioned parser emits `QuotaKind::Utilization` with value in `[0, 100]` on known schema.
- Unknown shape → `QuotaKind::Unknown`; raw body persisted to `accounts/codex-wham-drift.json` (cap 64 KB; redactor runs before write) for bug-report attachment.
- Status codes MUST be enumerated from observation (OPEN-C05, new gap): what does wham/usage return for over-quota, suspended, or throttled accounts? Defer until observed; dispatch mapping documented as errors land.

**Write invariants (inherits §5.5):**

- Daemon is sole writer. Stamp `surface: "codex"`, `kind: "utilization"`, `schema_version: 2` per spec 07 §7.4.
- `updated_at` timestamp; freshness follows standard cadence.

**Poll cadence:** 5 minutes per active Codex account. Matches Anthropic §5.1 per spec 04 INV-06.

**Circuit breaker:**

- 5 consecutive drift detections (`QuotaKind::Unknown`) → 15-minute cooldown, doubling with cap 80 minutes (standard §5.6 backoff).
- 5 consecutive 4xx/5xx failures → same backoff; last-known-good `quota.json` value preserved.

**Refresh coupling:**

- wham/usage polling MUST use the per-account access_token provided by the daemon's refresher (spec 07 INV-P01). Never a separate token.
- If refresh fails (account LOGIN-NEEDED), polling pauses for that slot.

**Implementation site:** `csq-core/src/daemon/usage_poller/codex.rs` (new).

## 5.8 Gemini counter + 429 parse (PROPOSED — event-driven, no public quota endpoint)

**Status:** PROPOSED. Google exposes no public quota endpoint for AI Studio API keys. This section defines the event-driven counter + 429-body parser that stands in for polling.

**Context:** unlike Anthropic / Codex / MiniMax / Z.AI, there is no `GET /usage` shape for Gemini API keys. Quota signal is best-effort: increment a client-side counter on every spawn, parse `RESOURCE_EXHAUSTED` response bodies on 429 for rate-limit reset, capture effective-model from the response payload for silent-downgrade detection.

**Inputs (event-driven, not polled):**

1. **Spawn event** — csq-cli emits `gemini_counter_increment { slot, ts }` via daemon IPC at the moment `gemini` is successfully spawned.
2. **429 event** — csq-cli wraps `gemini` stderr, detects `RESOURCE_EXHAUSTED` response bodies, parses `quotaMetric` + `retryDelay`, emits `gemini_rate_limited { slot, retry_delay_s, quota_metric }`.
3. **Effective-model event** — csq-cli parses `modelVersion` (location pinned by OPEN-G02 in workspaces/gemini/01-analysis/01-research/04-risk-analysis.md §4 GG3) from response, emits `gemini_effective_model_observed { slot, selected, effective }` on every response (debounced on the receive side).
4. **ToS-guard event** — csq-cli response-body sentinel detects OAuth-flow markers (`"Opening browser"`, `oauth2.googleapis.com`, `cloudcode-pa.googleapis.com`) on AI-Studio-provisioned slots; emits `gemini_tos_guard_tripped { slot, trigger }`; csq-cli kills the child.

**429 response shape (placeholder, TO BE VERIFIED):**

```json
{
  "error": {
    "code": 429,
    "status": "RESOURCE_EXHAUSTED",
    "message": "...",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
        "violations": [
          {
            "quotaMetric": "generativelanguage.googleapis.com/generate_content_free_tier_requests",
            "quotaId": "..."
          }
        ]
      },
      {
        "@type": "type.googleapis.com/google.rpc.RetryInfo",
        "retryDelay": "3600s"
      }
    ]
  }
}
```

OPEN-G03 (new gap): exact field positions in 2026-04 need live verification. Parser versioned; drift → `gemini_quota_schema_drift` error tag + raw body to `accounts/gemini-429-drift.json` (cap 64 KB, redacted).

**Counter state in `quota.json`:**

Field definitions and authoritative shape are owned by spec 07 §7.4.1. This section shows the Gemini-specific instantiation; spec 07 is the contract. The `schema_version: 2` top-level field lives at the root of `quota.json`, not per-account.

```json
{
  "schema_version": 2,
  "accounts": {
    "5": {
      "surface": "gemini",
      "kind": "counter",
      "updated_at": 1745332320,
      "counter": {
        "requests_today": 237,
        "resets_at_tz": "America/Los_Angeles",
        "last_reset": "2026-04-22T00:00:00-07:00"
      },
      "rate_limit": {
        "active": false,
        "reset_at": null,
        "last_retry_delay_s": null,
        "last_quota_metric": null,
        "cap": null
      },
      "selected_model": "gemini-3-pro-preview",
      "effective_model": "gemini-2.5-pro",
      "effective_model_first_seen_at": "2026-04-22T14:12:00Z",
      "mismatch_count_today": 3,
      "is_downgrade": true
    }
  }
}
```

Note the `cap` field inside `rate_limit` (populated from `RESOURCE_EXHAUSTED` body `quotaValue`) — reconciled with spec 07 §7.4.1 per VP-final red-team R1 (2026-04-22). Prior revisions of §5.8 flattened `cap` to a top-level `rate_limit: u64` which conflicted with the nested retry-state shape documented here.

**Write invariants (inherits §5.5):**

- Daemon is sole writer. csq-cli emits events, daemon writes.
- **When daemon is down**, csq-cli does NOT attempt to write quota.json directly. Events are dropped; UI reads stale data with honest freshness indicator.
- Effective-model debounce: latch `is_downgrade = true` only after 3 mismatches in 5 minutes (ADR-G06).
- Counter reset: scheduled daemon task runs at midnight America/Los_Angeles (pinned TZ for DST-correctness per ADR-G05).

**UI invariants:**

- When counter present: `AccountCard` shows "N requests today".
- When 429 active: `AccountCard` shows rate-limit countdown.
- When counter absent AND no 429: `AccountCard` shows "quota: n/a". **NEVER synthesize a percentage** (rules/account-terminal-separation.md rule 4; ADR-G05).
- When `is_downgrade`: `AccountCard` shows downgrade badge with `selected → effective`.

**Circuit breaker:**

- 5 consecutive 429-body-parse failures → flip to `QuotaKind::Unknown` state; preserve last-known-good.
- No poll to circuit-break on the main path (Gemini is event-driven); circuit breaker only applies to the parser.

**No refresh coupling** — Gemini API keys are flat; no refresh subsystem interacts.

**Implementation site:** `csq-core/src/daemon/usage_poller/gemini.rs` (new, event consumer only; no poll loop).

## 5.9 Cross-references

- `specs/04-csq-daemon-architecture.md` section 4.2.2 — usage poller subsystem.
- `specs/07-provider-surface-dispatch.md` §7.4 — surface → quota-kind dispatch table; §7.7.1 resolution of Codex refresh semantics.
- `rules/account-terminal-separation.md` rules 1, 2, 4 — quota writer and source-of-truth invariants.
- `csq-core/src/daemon/usage_poller.rs` — implementation site (splits into Anthropic/MiniMax/Z.AI/Codex/Gemini modules per spec 07).
- Journal `0028-DECISION-account-terminal-separation-python-elimination.md` — utilization-as-percentage discovery.
- Journal `0025-DISCOVERY-per-slot-third-party-provider-bindings.md` — per-slot 3P binding model.
- workspaces/codex/journal/0004 — Codex pre-expiry refresh strategy (load-bearing for §5.7 coupling).
- workspaces/gemini/journal/0002 — silent-downgrade detection design (load-bearing for §5.8 `effective_model` field).

## Revisions

- 2026-04-12 — 1.0.0 — Initial draft. Sections 5.2-5.4 pending Playwright investigation. Section 5.6 documents the 2026-04-12 poller hang and mandates supervisor + per-call timeout fixes.
- 2026-04-13 — 1.1.0 — Sections 5.3 and 5.4 corrected per journal 0032: MiniMax GroupId is optional, Z.AI API key works (JWT not required), MiniMax usage_count = remaining not consumed. Both fixes shipped in PRs #79 and #80.
- 2026-04-22 — 1.2.0 — Added §5.7 (Codex `/backend-api/wham/usage`, PROPOSED — schema pending live capture) and §5.8 (Gemini counter + 429 parse, event-driven). Former §5.7 "Cross-references" renumbered to §5.9. Both new sections ship as PROPOSED status until live response capture verifies schema; escalation to VERIFIED follows the spec-05 pattern set by MiniMax (§5.3) and Z.AI (§5.4) via journal 0032 — never commit to a verbatim response shape without observation. Journaled in workspaces/codex/journal/0004 and workspaces/gemini/journal/0002.
- 2026-04-22 — 1.2.1 — PR-VP-final red-team R1 reconciliation. §5.8 counter-state example reconciled with spec 07 §7.4.1: added `cap` field inside `rate_limit` struct so the 429 `quotaValue` has a home; added cross-reference note that field definitions are owned by spec 07 §7.4.1 to prevent future drift. No behaviour change; shape-compatible with the updated spec 07 1.1.1 frozen schema. Journal 0067 R1.
