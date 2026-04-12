# Provider Integration — csq v2.0

Quick reference for how csq discovers, authenticates, and polls third-party providers alongside Anthropic accounts.

## Provider Catalog

Source: `csq-core/src/providers/catalog.rs`

| ID       | Name    | Auth   | Base URL                     | Settings File          | Synthetic ID |
| -------- | ------- | ------ | ---------------------------- | ---------------------- | ------------ |
| `claude` | Claude  | OAuth  | `api.anthropic.com`          | `settings.json`        | 1-999        |
| `mm`     | MiniMax | Bearer | `api.minimax.chat/anthropic` | `settings-mm.json`     | 902          |
| `zai`    | Z.AI    | Bearer | `api.z.ai/api/anthropic`     | `settings-zai.json`    | 901          |
| `ollama` | Ollama  | None   | `localhost:11434`            | `settings-ollama.json` | —            |

## Anthropic OAuth Endpoints (2026-04-11)

Anthropic migrated the Claude Code OAuth authorize endpoint **without notice**. csq v1.x `dashboard/oauth.py` and csq v2 `csq-core/src/oauth/constants.rs` both had stale URLs until this session. Refresh paths kept working because the token endpoint is unchanged. See `workspaces/csq-v2/journal/0019-DISCOVERY-anthropic-oauth-endpoint-migration.md`.

| Purpose             | URL                                               | Status      |
| ------------------- | ------------------------------------------------- | ----------- |
| Authorize           | `https://claude.com/cai/oauth/authorize`          | **Current** |
| ~~Authorize (v1)~~  | ~~`platform.claude.com/v1/oauth/authorize`~~      | 404 (dead)  |
| Paste-code redirect | `https://platform.claude.com/oauth/code/callback` | Current     |
| Token exchange      | `https://platform.claude.com/v1/oauth/token`      | Unchanged   |
| `client_id`         | `9d1c250a-e61b-44d9-88ed-5944d1962f5e`            | Unchanged   |

### Claude Code OAuth flow is paste-code, not loopback

Anthropic no longer accepts `http://127.0.0.1:8420/oauth/callback` as a `redirect_uri` for this client_id. The current flow:

1. Caller generates PKCE verifier + state, builds URL with `code=true` + `redirect_uri=https://platform.claude.com/oauth/code/callback`
2. User authorizes in a browser (system browser or webview — `claude auth login` uses system browser)
3. Anthropic shows an authorization code on its callback page
4. User copies the code, pastes it back into the calling app
5. App looks up the verifier by state token, exchanges at the token endpoint with the **same** paste-code redirect URI

The `csq` bash wrapper shells out to `claude auth login` for this flow — it does not drive the OAuth handshake itself. csq-core's `oauth::start_login` + `oauth::exchange_code` reimplement the same flow for the desktop app and daemon HTTP API.

### Required scopes

```
org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload
```

`org:create_api_key` is **new** vs. v1.x csq — Claude Code added it. If you see "unauthorized" errors after a fresh login, check this scope first.

### Token endpoint does NOT return subscription metadata

The token endpoint (`/v1/oauth/token`) returns `access_token`, `refresh_token`, `expires_in`, and optionally `scope`. It does NOT return `subscriptionType` or `rateLimitTier`. CC populates these fields in `.credentials.json` on first API call at runtime.

**Consequence:** After `exchange_code` (login), the canonical `credentials/N.json` has `subscription_type: None`. Any swap or fanout that copies this to a live config dir before CC has backfilled will cause CC to lose its Max tier and default to Sonnet.

**Guard:** `rotation/swap.rs` and `broker/fanout.rs` both check for missing `subscription_type` and preserve the value from existing live credentials. See `rules/account-terminal-separation.md` rule 6.

### GrowthBook feature flags (external, diagnostic only)

CC caches server-side A/B test flags from Anthropic's GrowthBook service in each config dir's `.claude.json` under `cachedGrowthBookFeatures`. These flags are assigned per-user-ID and can silently override CC behavior.

**Known model-override flag:** `tengu_auto_mode_config` — when set to `{"enabled": "opt-in", "model": "claude-sonnet-4-6[1m]"}`, CC uses Sonnet regardless of subscription. csq has no control over this.

**Diagnostic:** When investigating "wrong model" reports, diff `cachedGrowthBookFeatures` between a working and broken config dir BEFORE diving into credential/subscription debugging. This saves hours.

### Don't try to "fix" loopback

Both csq v1.x and csq v2 had loopback OAuth flows. Both are now dead. Don't reintroduce a loopback callback listener — Anthropic's client_id registration rejects it. Delegate to `claude auth login` or use paste-code.

## Settings File Structure

3P settings files have two key locations (both must be checked):

```json
{
  "ANTHROPIC_AUTH_TOKEN": "key",
  "ANTHROPIC_BASE_URL": "https://api.example.com",
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "key",
    "ANTHROPIC_BASE_URL": "https://api.example.com"
  }
}
```

- **Discovery** (`accounts/discovery.rs`) checks top-level AND `env.` subobject
- **Runtime** (`providers/settings.rs`) reads from `env.` subobject via `ProviderSettings::get_api_key()`
- **Lesson learned** (journal 0014): checking only one location causes phantom accounts that are discovered but never polled

## Polling Strategy

| Provider type      | Method                                   | Interval | Data source                                            |
| ------------------ | ---------------------------------------- | -------- | ------------------------------------------------------ |
| Anthropic          | `GET /api/oauth/usage` with Bearer token | 5 min    | Response body: `{five_hour: {utilization, resets_at}}` |
| 3P (Z.AI, MiniMax) | `POST /v1/messages` with `max_tokens=1`  | 15 min   | Response headers: `anthropic-ratelimit-*`              |

### 3P Rate-Limit Headers

Extracted by `extract_rate_limit_headers()` in `daemon/usage_poller.rs`:

| Header                                    | Field                 |
| ----------------------------------------- | --------------------- |
| `anthropic-ratelimit-requests-limit`      | `requests_limit`      |
| `anthropic-ratelimit-requests-remaining`  | `requests_remaining`  |
| `anthropic-ratelimit-tokens-limit`        | `tokens_limit`        |
| `anthropic-ratelimit-tokens-remaining`    | `tokens_remaining`    |
| `anthropic-ratelimit-input-tokens-limit`  | `input_tokens_limit`  |
| `anthropic-ratelimit-output-tokens-limit` | `output_tokens_limit` |

Headers are extracted even on 4xx responses (3P providers often include them on errors).

### Probe Body

Built dynamically from the provider's `default_model`:

```rust
build_probe_body(provider.default_model)
// → {"model":"MiniMax-M2","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}
```

## Synthetic ID Collision

3P accounts use synthetic IDs (901 Z.AI, 902 MiniMax) that overlap with the valid `AccountNum` range (1..999). The poller uses **separate cooldown/backoff maps** for 3P (`cooldowns_3p`, `backoffs_3p`) to prevent an Anthropic account 901 from colliding with Z.AI's cooldown state.

Future fix: reserve 900+ in `AccountNum` at the type level.

## Quota Storage

Both Anthropic and 3P write to the same `quota.json` via `QuotaFile`:

```rust
AccountQuota {
    five_hour: Option<UsageWindow>,      // Anthropic: from utilization. 3P: from token_usage_pct()
    seven_day: Option<UsageWindow>,      // Anthropic only
    rate_limits: Option<RateLimitData>,  // 3P only (raw header values)
    updated_at: f64,
}
```

3P accounts set `resets_at = 4_102_444_800` (2100-01-01) to prevent `clear_expired()` from removing data that has no natural reset time.

## Token Redaction

`error::redact_tokens()` covers:

- `sk-ant-oat01-*` and `sk-ant-ort01-*` (Anthropic OAuth tokens) — unconditional
- `sk-*` with 20+ char body (Anthropic API keys) — generic
- 32+ hex digit runs (3P raw API keys)

3P API keys in `PollError` inner strings are currently safe (never logged), but the redaction is defense-in-depth.
