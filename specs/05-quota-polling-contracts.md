# 05 Quota Polling Contracts

Spec version: 1.4.3 | Governs: Anthropic and third-party usage polling

---

## 5.0 Scope

This spec defines the daemon's contract with Anthropic's OAuth usage endpoint and third-party providers (MiniMax, Z.AI, DeepSeek), plus the Codex and Gemini usage surfaces. It specifies the request shape, parse rules, and write invariants for `quota.json`.

Sections 5.3 (MiniMax) and 5.4 (Z.AI) have been verified via live API testing. Section 5.2 (claude.ai dashboard endpoint) remains observational — csq uses the OAuth usage endpoint (5.1) instead.

## 5.1 Anthropic `/api/oauth/usage`

**Request:**

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <access_token>
Anthropic-Beta: oauth-2025-04-20
Accept: application/json
User-Agent: curl/<csq-version>     (required — non-curl UAs get 400)
```

Transport constraints (load-bearing):

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

**Parse rule (load-bearing):** `utilization` is a percentage in `[0, 100]`, NOT a fraction in `[0, 1]`. Multiplying by 100 is a bug — it produces phantom utilization values in the thousands of percent. The code in `parse_usage_response` stores the value directly. Any header comment on `daemon::usage_poller` describing the scale as "0.0-1.0" is stale and MUST be corrected to avoid re-introducing the bug.

**Zero-usage `resets_at`:** when `utilization: 0.0` on a window, Anthropic returns `resets_at: null` (no consumption → no reset scheduled). Probes and parsers MUST treat `resets_at: null` as "no reset data" (acceptable when `utilization == 0`), not as a contract violation. The web endpoint (§5.2) shows this same pattern on zero-usage `seven_day_sonnet`. The bearer endpoint also emits additional sibling keys observed in §5.2 (`seven_day_oauth_apps`, `seven_day_opus`, `seven_day_sonnet`, `seven_day_cowork`) — parsers MUST tolerate these.

**Endpoint equivalence:** the bearer endpoint and the web dashboard (§5.2) return the same `utilization` field on the same 0-100 scale. An apparent discrepancy between csq's displayed value and the web dashboard is a poller-liveness symptom (see §5.6), not an endpoint difference — fix the poller hang and the display matches the web.

## 5.2 claude.ai web dashboard (observational)

The web dashboard at `claude.ai/settings/usage` calls a DIFFERENT endpoint from what csq uses, but the core data is equivalent.

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

## 5.3 MiniMax

**Working endpoint:**

```
GET https://platform.minimax.io/v1/api/openplatform/coding_plan/remains
Authorization: Bearer <API_KEY>
Accept: application/json
```

**Notes:**

- **Host:** `platform.minimax.io` (NOT `www.minimax.io` which returns 403 via Cloudflare, and NOT `api.minimax.chat` which is for message traffic only).
- **GroupId:** Optional. The `?GroupId=<group-id>` parameter was initially believed required per browser capture, but direct API testing confirmed the endpoint works without it, returning all models.

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

**CRITICAL — `usage_count` is REMAINING, not consumed.** The endpoint name is `/coding_plan/remains`. `current_interval_usage_count` = remaining usable count. To compute consumed: `used = total - usage_count`. Example: `total=30000, usage_count=29957` → 43 consumed, 0.14% used.

**Parser:** Iterate `model_remains[]`, find entry matching configured model (or `MiniMax-M*` for coding plan), compute 5h percentage as `(total - usage_count) / total * 100`, 7d from `current_weekly_*` fields with the same formula.

## 5.4 Z.AI

**Working endpoint:**

```
GET https://api.z.ai/api/monitor/usage/quota/limit
Authorization: Bearer <API_KEY>
Accept: application/json
```

**Auth:** The API key alone is sufficient. The same API key stored in per-slot `settings.json` (`ANTHROPIC_AUTH_TOKEN`) works for the quota endpoint — no JWT session cookie is required. A browser capture shows both cookies AND the Authorization header, but the header alone authenticates the request.

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

**TIME_LIMIT entries and null reset:** Z.AI's response can also emit `type: "TIME_LIMIT"` entries (e.g. `unit: 5` for monthly time quotas) interleaved with TOKENS_LIMIT entries. The probe and the daemon poller MUST filter by `type == "TOKENS_LIMIT"` before inspecting fields. Additionally, **`nextResetTime` is null on a TOKENS_LIMIT window with zero usage** (no consumption means no reset is scheduled). The daemon's `usage_poller::zai` handles this by silently skipping the window (treats it as "no data available"); the probe's contract assertion accepts null and fails only on a present-but-non-positive `nextResetTime`.

## 5.4a DeepSeek (Anthropic-bridge with no rate-limit headers)

**Endpoint:** `https://api.deepseek.com/anthropic/v1/messages` (Anthropic-API-compatible bridge).

**Auth:** Bearer token via `ANTHROPIC_AUTH_TOKEN`. Same env-var contract as MiniMax / Z.AI ClaudeCode-surface 3P providers.

**Quota signal: NONE on the bridge.** Live verification: `POST /v1/messages` with `max_tokens=1` against the bridge returns HTTP 200 + a normal Anthropic-shape response body, but **emits no `anthropic-ratelimit-*` response headers**. The generic 3P probe path (`POST /v1/messages` → `extract_rate_limit_headers`) consequently produces zero data for DeepSeek slots. Catalog `quota_kind = QuotaKind::Unknown`; the daemon's 3P usage poller skips DeepSeek entries (the `Skip QuotaKind::Unknown` branch in `csq-core/src/daemon/usage_poller/third_party.rs`).

**Per-plan billing-mode caveat:** DeepSeek, along with MiniMax and Z.AI, ships BOTH subscription tiers AND pay-per-token modes. The API key authenticates either. csq today cannot empirically classify a slot's mode at provisioning time — that lives in the user's plan with the provider, not in the catalog. A planned per-slot usage ledger derived from CC's per-turn cost log will let csq render token + cost numbers regardless of mode.

**Asymmetric tier defaults:** DeepSeek's published Claude Code integration guidance recommends `ANTHROPIC_DEFAULT_HAIKU_MODEL = deepseek-v4-flash`, `CLAUDE_CODE_SUBAGENT_MODEL = deepseek-v4-flash`, `CLAUDE_CODE_EFFORT_LEVEL = max`. csq's `Provider.extra_env` field seeds these on bind so users get DeepSeek's published-optimal config out of the box. Other providers carry empty `extra_env`.

**Cross-references:**

- DeepSeek catalog entry: `csq-core/src/providers/catalog.rs::PROVIDERS` (`id: "deepseek"`).
- Generic 3P probe: `csq-core/src/daemon/usage_poller/third_party.rs::poll_3p_usage`.

## 5.5 Write invariants

Regardless of source (Anthropic or 3P), the daemon usage poller writes to `quota.json`:

- **One writer**: the usage poller task only. The slot id for every write is sourced from authoritative metadata (the per-slot poller's own state, a validated IPC event payload, or a slot-lifecycle operation parameter) — never derived from terminal-scoped state.
- **Atomic**: temp file + rename with `0o600` permissions.
- **Per-account keyed**: `quota.json.accounts.<N>` structure preserved. See `csq-core/src/quota/state.rs`.
- **`updated_at` timestamp**: every write stamps the current UNIX time as a float seconds since epoch. Freshness checks (e.g. a dashboard staleness badge) read this field.
- **Rate limits data**: for 3P slots that produce `anthropic-ratelimit-*` headers, the poller ALSO stores `rate_limits` on the account record. Anthropic accounts do not populate this field.

## 5.6 Cooldown and backoff

The daemon's usage poller is a long-running background task. A blocking HTTP call (timeout overrun, or a hung TLS handshake) that blocks an `await` indefinitely can silently stall the poller with no panic and no error log. The poller supervisor MUST be hardened against this:

1. **Per-call timeout**: wrap every `tokio::task::spawn_blocking(|| poll_anthropic_usage(...))` and `spawn_blocking(|| poll_3p_usage(...))` result in `tokio::time::timeout(30s, join_handle)`. On timeout, abort the join handle, log `warn!`, and treat as a transient failure (enter cooldown).
2. **Supervised main loop**: `run_loop` MUST be spawned under a supervisor that respawns on panic with exponential backoff, logging the panic payload. A bare `tokio::spawn` whose panic dies silently is insufficient.
3. **Health heartbeat**: the main loop emits a DEBUG log every tick ("usage poller tick complete"). The supervisor checks this heartbeat every 60s; if absent for >3× the expected interval, force-restart the poller subsystem.

Standard backoff parameters for transient failures: 15-minute cooldown, doubling with a cap of 80 minutes.

## 5.7 Codex `/backend-api/wham/usage`

Verified against a live Codex plus-plan account. The schema block below is the observed shape with PII values redacted.

**Request:**

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <codex_access_token>
ChatGPT-Account-Id: <account_id>
Accept: application/json
User-Agent: <csq/version>   (User-Agent gating not confirmed; start with a csq UA + fall back to curl UA on 4xx)
```

Transport considerations:

- **Node subprocess transport REQUIRED.** reqwest/rustls is body-stripped by Cloudflare on both `chatgpt.com/backend-api/*` and `auth.openai.com/oauth/token`: status 401 + `cf-ray` header present, but response body reduced to `{"error": {}, "status": 401}` instead of the full `{"error": {"message": "...", "code": "token_expired"}}` that curl and Node return. Same failure class as the Anthropic transport. Codex polling uses the Node bridge at `csq-core/src/http/codex.rs` — same runtime as the Anthropic bridge; no new dependency.
- Per-call timeout: 30s (inherits §5.6).

**Credential source:**

The `<codex_access_token>` in the Authorization header is read from per-identity creds — `identities/<UUID>/credentials-codex.json` resolved via `crate::accounts::profiles::resolve_slot_to_uuid(base_dir, slot)` → `crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)`. When `resolve_slot_to_uuid` returns `None` (legacy installs, or slots whose UUID mapping was never minted), the fallback path is `csq-core/src/providers/codex/provisioning::binding_path(base_dir, slot)` (= `<base>/credentials/codex-<N>.json`).

The same channel is used by:

- The daemon usage poller (`csq-core/src/daemon/usage_poller/codex.rs`).
- The daemon refresher (`csq-core/src/daemon/refresher.rs`).
- The broker check (`csq-core/src/refresh/check.rs`).
- The handle-dir spawn (`csq-core/src/session/handle_dir.rs`).
- The `csq probe` codex-oauth cell (`csq-core/src/probe/codex_oauth.rs`).

The probe does NOT read `~/.codex/auth.json` — that path is codex-cli's standalone state, csq-unmanaged. Reading it would violate the diagnostic-surface invariant that diagnostics read from the same credential channel as daemon production paths (see spec 02 — csq Handle-Dir Model).

**Response shape (PII redacted):**

```json
{
  "user_id": "<PII: opaque UUID — redact>",
  "account_id": "<PII: opaque UUID — redact>",
  "email": "<PII: user email — redact>",
  "plan_type": "plus",
  "rate_limit": {
    "allowed": true,
    "limit_reached": false,
    "primary_window": {
      "used_percent": 0.0,
      "limit_window_seconds": 18000,
      "reset_after_seconds": 18000,
      "reset_at": 1776856630
    },
    "secondary_window": {
      "used_percent": 0.0,
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

**Field-to-quota mapping:**

| Source field                                                                                                  | quota.json destination               | Notes                                                             |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ----------------------------------------------------------------- |
| `rate_limit.primary_window.used_percent`                                                                      | `utilization_5h` (f64 in [0,100])    | 5h window (18000s observed). **Already a %, not 0-1.**            |
| `rate_limit.primary_window.reset_at`                                                                          | `resets_at_5h` (Unix epoch)          | Preferred — absolute beats relative.                              |
| `rate_limit.secondary_window.used_percent`                                                                    | `utilization_7d` (f64 in [0,100])    | 7d window (604800s observed).                                     |
| `rate_limit.secondary_window.reset_at`                                                                        | `resets_at_7d` (Unix epoch)          |                                                                   |
| `plan_type`                                                                                                   | `extras.plan_type` (Option<String>)  | UI label only; not used in quota math.                            |
| `rate_limit.allowed` / `.limit_reached`                                                                       | derived fields / LOGIN-NEEDED signal | Drives UX messaging, not utilization.                             |
| `user_id` / `account_id` / `email`                                                                            | **REDACTED — never persisted**       | The PII redactor targets exactly these 3 keys.                    |
| `credits.*` / `spend_control.*`                                                                               | (ignored)                            | PAYG / billing metadata; out of scope for quota.                  |
| `code_review_rate_limit` / `additional_rate_limits` / `rate_limit_reached_type` / `promo` / `referral_beacon` | (optional, parsed tolerantly)        | Null on healthy plus-plan account; parser accepts null-or-object. |

**Parse contract:**

- Versioned parser emits TWO `QuotaKind::Utilization` values per poll — one per window — with values in `[0.0, 100.0]`.
- `reset_after_seconds` vs `reset_at` clock-skew sanity check: if absolute(reset_at - now - reset_after_seconds) > 5s, log `clock_skew_warning` (informational; does not fail the poll).
- Unknown shape → `QuotaKind::Unknown`; raw body persisted to `accounts/codex-wham-drift.json` (cap 64 KB; **PII redactor MUST run before write** — strip `user_id`, `account_id`, `email` keys regardless of drift) for bug-report attachment.
- Status codes: 200 = schema parsed. 401 `token_expired` → refresher retry. 429 body shape is uncaptured (no natural 429 has been observed); parser treats unknown status-5xx/4xx bodies as `QuotaKind::Unknown`.

**Write invariants (inherits §5.5):**

- Daemon is sole writer. Stamp `surface: "codex"`, `kind: "utilization"`, `schema_version: 2` per spec 07 (Provider Surface Dispatch) §7.4.
- `updated_at` timestamp; freshness follows standard cadence.

**Poll cadence:** 5 minutes per active Codex account. Matches Anthropic §5.1 per spec 04 (csq Daemon Architecture) INV-06.

**Circuit breaker:**

- 5 consecutive drift detections (`QuotaKind::Unknown`) → 15-minute cooldown, doubling with cap 80 minutes (standard §5.6 backoff).
- 5 consecutive 4xx/5xx failures → same backoff; last-known-good `quota.json` value preserved.

**Refresh coupling:**

- wham/usage polling MUST use the per-account access_token provided by the daemon's refresher (spec 07 — Provider Surface Dispatch — INV-P01). Never a separate token.
- If refresh fails (account LOGIN-NEEDED), polling pauses for that slot.

**Implementation site:** `csq-core/src/daemon/usage_poller/codex.rs`.

## 5.8 Gemini counter + 429 parse (event-driven, no public quota endpoint)

Google exposes no public quota endpoint for AI Studio API keys. This section defines the event-driven counter + 429-body parser that stands in for polling.

**Context:** unlike Anthropic / Codex / MiniMax / Z.AI, there is no `GET /usage` shape for Gemini API keys. Quota signal is best-effort: increment a client-side counter on every spawn, parse `RESOURCE_EXHAUSTED` response bodies on 429 for rate-limit reset, capture effective-model from the response payload for silent-downgrade detection.

**Inputs (event-driven, not polled):**

1. **Spawn event** — csq-cli emits `gemini_counter_increment { slot, ts }` via daemon IPC at the moment `gemini` is successfully spawned.
2. **429 event** — csq-cli wraps `gemini` stderr, detects `RESOURCE_EXHAUSTED` response bodies, parses `quotaMetric` + `retryDelay`, emits `gemini_rate_limited { slot, retry_delay_s, quota_metric }`.
3. **Effective-model event** — csq-cli parses `modelVersion` from the response, emits `gemini_effective_model_observed { slot, selected, effective }` on every response (debounced on the receive side).

> **Note on subprocess wrapping.** csq spawns the official `gemini` binary as a subprocess — structurally identical to running it under a shell alias or a terminal multiplexer. csq does not reimplement or bypass the official CLI.

### 5.8.2 Code Assist OAuth

OAuth-mode Gemini slots (`AuthMode::CodeAssistOAuth`) take a Utilization-shape poll path distinct from §5.8.1's event-driven Counter for ApiKey/VertexSa. Implementation lives in `csq-core/src/daemon/usage_poller/gemini_oauth.rs` + `csq-core/src/providers/gemini/code_assist_quota.rs`.

**Endpoints (verified from gemini-cli's published source):**

- `POST https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist` — discovers the user's GCP project. Request body carries `metadata.{ideType, platform, pluginType, pluginVersion}` for telemetry; csq sends `pluginType=CSQ`. Response field `cloudaicompanionProject` carries the project resource name.
- `POST https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota` — returns per-model `BucketInfo[]`. Request body: `{project, userAgent}`. Response: `{buckets: [{modelId, tokenType, remainingFraction, remainingAmount, resetTime}]}`.

**Auth posture:** csq is read-only on `~/.gemini/oauth_creds.json` (Google Credentials shape: `access_token`, `refresh_token?`, `expiry_date?`, `token_type?`, `scope?`). gemini-cli + google-auth-library own refresh; csq reads the current `access_token` on every poll and presents it as `Authorization: Bearer …`. If the token has expired and gemini-cli has not refreshed (e.g., gemini-cli not running and no recent user invocation), the poll returns 401 and csq waits for gemini-cli to refresh on the user's next session.

**Aggregation:** `BucketInfo` is per-model + per-tokenType. `code_assist_quota::aggregate_to_usage_window` picks the LIMITING bucket — the row with the lowest `remainingFraction` across all rows — and projects it to a single (`used_percentage`, `resets_at`) pair. The limiting `modelId` and `tokenType` are stored in `accounts.<N>.extras.code_assist_limiting_{model,token_type}` for diagnostic UI rendering.

**Quota row shape:**

```json
{
  "schema_version": 2,
  "accounts": {
    "5": {
      "surface": "gemini",
      "kind": "utilization",
      "five_hour": null,
      "seven_day": { "used_percentage": 80.0, "resets_at": 4102444800 },
      "extras": {
        "code_assist_limiting_model": "gemini-2.5-flash",
        "code_assist_limiting_token_type": "REQUESTS"
      },
      "updated_at": 1714000000.0
    }
  }
}
```

The Code Assist daily reset is mapped into `seven_day` (the longer-window slot); `five_hour` is set to null because Code Assist has no equivalent short window. The 5h window is Anthropic-Max-specific.

**Tick cadence:** runs every Anthropic-tick interval (default 5 min). Two HTTP calls per OAuth-mode slot per cycle — `loadCodeAssist` then `retrieveUserQuota`. The current implementation does not cache the project; a future refinement caches per-account and re-discovers only on 401/403.

**Failure handling:** any non-200 from either endpoint logs at `warn` level and skips that slot for the tick. No cooldown/backoff on this path yet — subsequent ticks try again immediately. A future refinement integrates with the shared cooldowns/backoffs maps.

**Verification posture:** the endpoint contract was extracted from gemini-cli's published source but has not been exercised against a live Code Assist subscription from csq's transport. Manual smoke is the gate before tagging — provision an OAuth-mode Gemini slot, run the daemon, observe `quota.json` populates correctly within one tick.

**429 response shape (to be verified against a live capture):**

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

Exact field positions need live verification. The parser is versioned; drift → `gemini_quota_schema_drift` error tag + raw body to `accounts/gemini-429-drift.json` (cap 64 KB, redacted).

**Counter state in `quota.json`:**

Field definitions and authoritative shape are owned by spec 07 (Provider Surface Dispatch) §7.4.1. This section shows the Gemini-specific instantiation; spec 07 is the contract. The `schema_version: 2` top-level field lives at the root of `quota.json`, not per-account.

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

The `cap` field inside `rate_limit` is populated from the `RESOURCE_EXHAUSTED` body `quotaValue`. It lives nested inside the retry-state shape (not as a top-level `rate_limit: u64`), consistent with spec 07 §7.4.1.

**Write invariants (inherits §5.5):**

- Daemon is sole writer to `quota.json`. csq-cli emits events, daemon writes.
- **When daemon is down, events are NOT dropped.** csq-cli writes every event to the CLI-durable NDJSON log (§5.8.1 below) before returning; the log outlives the daemon-down window and is drained on daemon startup.
- Effective-model debounce: latch `is_downgrade = true` only after 3 mismatches in 5 minutes.
- Counter reset: scheduled daemon task runs at midnight America/Los_Angeles (pinned TZ for DST-correctness).

### 5.8.1 CLI-durable NDJSON event log

The event-delivery durability contract sits under the IPC event-delivery contract in spec 07 (Provider Surface Dispatch) §7.2.3.1 — §7.2.3.1 governs IPC; this subsection governs durability.

**File layout (one file per slot, per surface):**

```
~/.claude/accounts/gemini-events-<slot>.ndjson    (mode 0600)
```

Slot-scoped so per-slot drain locks never contend across slots, and so a slot rename / account deletion can remove a single file without affecting siblings. Path resolution follows the same discipline as `csq.sock` (spec 04 — csq Daemon Architecture — §4.2.5 layer 3); the path helper `providers::gemini::capture::ndjson_path(base_dir, slot)` is the sole source of truth — emitters and drainers MUST NOT construct the path inline (the daemon drainer's `ndjson_log_path` / `ndjson_lock_path` wrappers delegate to it).

**Encoding — one event per line, JSON-encoded:**

```json
{"v":2,"id":"01HG…26-char-uuidv7","ts":"2026-04-22T14:12:00Z","slot":5,"surface":"gemini","kind":"counter_increment","payload":{}}
{"v":2,"id":"01HG…26-char-uuidv7","ts":"2026-04-22T14:12:03Z","slot":5,"surface":"gemini","kind":"rate_limited","payload":{"retry_delay_s":3600,"quota_metric":"generativelanguage.googleapis.com/generate_content_free_tier_requests","cap":250}}
{"v":2,"id":"01HG…26-char-uuidv7","ts":"2026-04-22T14:12:05Z","slot":5,"surface":"gemini","kind":"effective_model_observed","payload":{"selected":"gemini-3-pro-preview","effective":"gemini-2.5-pro"}}
```

| Field     | Type   | Required | Notes                                                                                                                    |
| --------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| `v`       | u8     | yes      | Event schema version. v2 = current shape. Drainer drops envelopes with unknown `kind` silently rather than quarantining. |
| `id`      | string | yes      | UUIDv7 (26-char base32). Deduplication key — daemon applies each `id` at most once.                                      |
| `ts`      | string | yes      | RFC 3339 in UTC with `Z` suffix. Not used for ordering (file order wins); used for TTL + audit.                          |
| `slot`    | u16    | yes      | Must equal the slot encoded in the filename; mismatch → drainer rejects and moves to `.corrupt`.                         |
| `surface` | string | yes      | `"gemini"` in v2. Reserved for future surfaces that adopt the NDJSON durability pattern.                                 |
| `kind`    | string | yes      | One of `counter_increment`, `rate_limited`, `effective_model_observed`.                                                  |
| `payload` | object | yes      | Kind-specific shape. MUST NOT contain secrets. The token redactor runs over the serialised line.                         |

**Write discipline (emitter side):**

1. Serialise the event to a single line (`serde_json::to_string` + `\n`). No pretty-printing — one line per event, end-of-line delimiter is `\n`.
2. `OpenOptions::new().create(true).append(true).mode(0o600).open(path)` — `O_APPEND` guarantees concurrent emitters see atomic writes (POSIX append atomicity for writes ≤ `PIPE_BUF` = 4 KiB; all event kinds are well under that bound).
3. `write_all(line.as_bytes())` — single syscall, no partial writes on POSIX `O_APPEND`.
4. `sync_data(&file)` — forces the kernel to flush the append to the underlying block device. This adds latency and is required for the "survives daemon crash mid-event" durability guarantee.
5. Close the file. Emitters open-append-close per event — no long-lived handle.

If any step fails, the emitter logs `error_kind = "gemini_event_ndjson_write_failed"` with fixed-vocabulary fields and returns `Ok(())` to the spawn path (matching §7.2.3.1's drop-on-unavailable philosophy: event loss is preferable to spawn failure). NDJSON write failure is the durability-floor failure; there is no further fallback.

**Drain discipline (daemon side):**

On daemon startup and on every reconnect (post-restart, post-unix-socket-rebind):

1. For each slot N with an extant account, resolve `~/.claude/accounts/gemini-events-<N>.ndjson`.
2. Acquire per-slot advisory file lock (`fcntl(F_SETLK, F_WRLCK)`). If contended, skip and retry on next tick — never block.
3. Open `O_RDWR`. Read to EOF, parse each line as `Event { v, id, ts, slot, surface, kind, payload }`.
4. For each event with current `v` and `id` NOT in the in-memory applied-event set, apply to `quota.json` (via the standard atomic-replace path) and insert `id` into the applied-event set. Applied-event set is bounded (LRU 16 k entries) because UUIDv7 ordering makes dedup a sliding window, not a growing set.
5. On successful apply of ALL lines in the file, `ftruncate` to 0 and `fsync`. On ANY parse error, move the file to `gemini-events-<slot>.corrupt.<ts>` (for operator inspection) and start a fresh log.
6. Release lock.

Drain runs under the daemon's per-slot mutex (same mutex that guards `quota.json` writes for that slot) — single-writer-to-quota.json invariant preserved across the IPC path AND the NDJSON drain path because both terminate at the same mutex.

**Durability guarantees:**

- **Daemon-down event loss:** zero events lost for events successfully `sync_data`-ed to the log. Emitter-crash-before-sync may lose the in-flight event (acceptable; the emitter is a short-lived spawn with a single event in flight).
- **Daemon-crash mid-drain event loss:** zero events lost. Drain is not atomic, but the `id` dedup set means partial drain followed by full re-drain at restart reapplies exactly once.
- **Log file corruption (power loss mid-append):** bounded — POSIX `O_APPEND` + `sync_data` limits corruption to at most the final line. The `.corrupt` quarantine + fresh start rule handles the corner case; operator inspects; next slot interaction writes fresh events.

**Retention + size bound:**

- Each event is ~180 bytes. A saturated slot emitting one event per second produces ~15 MiB/day uncompressed; drain cadence is sub-minute under a healthy daemon so steady-state file size is bytes, not megabytes.
- Hard cap: emitter refuses to write if the log exceeds 10 MiB (logged as `error_kind = "gemini_event_ndjson_log_full"`; operator action needed — drain stalled). The circuit-breaker threshold is chosen so a pathological runaway never fills the disk.

**Security invariants:**

- Mode 0600 enforced at open (umask + explicit). Owner = current user. File lives under `~/.claude/accounts/` which is already 0700.
- Payload MUST NOT contain tokens, API keys, or OAuth fragments. The token redactor runs over every serialised line before write — defence in depth for accidental inclusion.
- Gitignore MUST cover `gemini-events-*.ndjson` (no repository leak).
- File path MUST be validated against the slot-N bound — prevents writes outside `accounts/`.

**Test fixtures:**

- `ndjson_event_survives_daemon_restart` (write with daemon down, start daemon, drain, quota.json reflects event)
- `ndjson_log_truncated_after_successful_drain`
- `concurrent_emitters_produce_well_formed_lines` (O_APPEND atomicity regression)
- `drainer_rejects_v0_or_vN>1_events`
- `drainer_quarantines_corrupt_line_and_continues`
- `dedup_via_uuidv7_id_prevents_double_apply`
- `log_fsync_before_emitter_returns` (durability regression)
- `emitter_hits_10mib_cap_cleanly` (circuit-breaker regression)

**UI invariants:**

- When counter present: `AccountCard` shows "N requests today".
- When 429 active: `AccountCard` shows rate-limit countdown.
- When counter absent AND no 429: `AccountCard` shows "quota: n/a". **NEVER synthesize a percentage.**
- When `is_downgrade`: `AccountCard` shows downgrade badge with `selected → effective`.

**Circuit breaker:**

- 5 consecutive 429-body-parse failures → flip to `QuotaKind::Unknown` state; preserve last-known-good.
- No poll to circuit-break on the main path (Gemini is event-driven); the circuit breaker only applies to the parser.

**No refresh coupling** — Gemini API keys are flat; no refresh subsystem interacts.

**Implementation site:** `csq-core/src/daemon/usage_poller/gemini.rs` (event consumer only; no poll loop).

## 5.9 Cross-references

- `specs/04-csq-daemon-architecture.md` §4.2.2 — usage poller subsystem.
- `specs/07-provider-surface-dispatch.md` §7.4 — surface → quota-kind dispatch table; §7.7.1 resolution of Codex refresh semantics.
- `csq-core/src/daemon/usage_poller.rs` — implementation site (splits into Anthropic/MiniMax/Z.AI/Codex/Gemini modules per spec 07).
- For the quota-writer and source-of-truth invariants (one daemon writer, slot id from authoritative metadata, terminals read-only), see spec 02 (csq Handle-Dir Model).
