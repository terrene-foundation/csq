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

## 5.7 Cross-references

- `specs/04-csq-daemon-architecture.md` section 4.2.2 — usage poller subsystem.
- `rules/account-terminal-separation.md` rules 1, 2, 4 — quota writer and source-of-truth invariants.
- `csq-core/src/daemon/usage_poller.rs` — implementation site.
- Journal `0028-DECISION-account-terminal-separation-python-elimination.md` — utilization-as-percentage discovery.
- Journal `0025-DISCOVERY-per-slot-third-party-provider-bindings.md` — per-slot 3P binding model.

## Revisions

- 2026-04-12 — 1.0.0 — Initial draft. Sections 5.2-5.4 pending Playwright investigation. Section 5.6 documents the 2026-04-12 poller hang and mandates supervisor + per-call timeout fixes.
- 2026-04-13 — 1.1.0 — Sections 5.3 and 5.4 corrected per journal 0032: MiniMax GroupId is optional, Z.AI API key works (JWT not required), MiniMax usage_count = remaining not consumed. Both fixes shipped in PRs #79 and #80.
