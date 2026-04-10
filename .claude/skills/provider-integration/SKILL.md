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
