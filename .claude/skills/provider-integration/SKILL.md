# Provider Integration — csq v2.3

Quick reference for how csq discovers, authenticates, and polls Anthropic + Codex + Gemini + third-party providers across the surface-dispatch architecture.

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

### OAuth refresh body shape

CC sends `scope` in the refresh body (`services/oauth/client.ts:159-162`). Our code currently omits it (safe per RFC 6749 §6 — omitted scope retains the original grant). Both work.

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "sk-ant-ort01-...",
  "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
}
```

### Cloudflare TLS fingerprinting — Node.js transport required (journal 0056)

Anthropic endpoints (`platform.claude.com`, `api.anthropic.com`) are behind Cloudflare which performs JA3/JA4 TLS fingerprinting. **reqwest with rustls is blocked** — every request returns `429 rate_limit_error` regardless of volume. `curl` is also blocked. Only Node.js's OpenSSL TLS stack produces an accepted fingerprint.

```
DO:  http::post_json_node(url, body)   — shells out to `node`, pipes body via stdin
DO:  http::get_bearer_node(url, token) — shells out to `node`, pipes token via stdin
DO NOT: http::post_json(url, body)     — reqwest/rustls, blocked by Cloudflare
DO NOT: http::get_bearer(url, token)   — reqwest/rustls, blocked by Cloudflare
```

**Why:** Proven empirically: same endpoint, same body, same headers — `node` succeeds, `reqwest`/`curl` get 429. The TLS handshake fingerprint is the only difference. CC itself uses Bun (OpenSSL-based) for the same reason.

**No fallback.** If `node`/`bun` is not found on PATH, `post_json_node` returns `Err` immediately. Falling back to reqwest would just hit the Cloudflare wall and trigger cooldowns.

**Scope of the node transport:** Only Anthropic endpoints. 3P endpoints (MiniMax, Z.AI, GitHub Releases) use reqwest — they don't have Cloudflare's aggressive fingerprinting.

**Journal 0052 correction:** Journal 0052 attributed mass refresh failure to the `scope` field in the refresh body. That was a misdiagnosis — the root cause was the TLS fingerprint. See journal 0056.

### Runbook: "all accounts asking to re-auth"

```bash
# 1. Check the daemon is alive.
curl --unix-socket ~/.claude/accounts/csq.sock http://localhost/api/health

# 2. Inspect token expiries directly (bypasses daemon cache).
for n in $(seq 1 7); do
  f=~/.claude/accounts/credentials/$n.json
  [ -f "$f" ] && python3 -c "
import json, time
d = json.load(open('$f'))
e = d['claudeAiOauth']['expiresAt'] / 1000
diff = e - time.time()
status = f'{diff/3600:.1f}h left' if diff > 0 else f'EXPIRED {-diff/3600:.1f}h ago'
print(f'account $n: {status}')
"
done

# 3. Query the refresher cache.
curl --unix-socket ~/.claude/accounts/csq.sock http://localhost/api/refresh-status

# 4. If rate_limited on multiple accounts, test via node (NOT curl/reqwest):
RT=$(python3 -c "import json; print(json.load(open('$HOME/.claude/accounts/credentials/1.json'))['claudeAiOauth']['refreshToken'])")
node -e "
const https = require('https');
const body = JSON.stringify({grant_type:'refresh_token',refresh_token:'$RT',client_id:'9d1c250a-e61b-44d9-88ed-5944d1962f5e'});
const req = https.request('https://platform.claude.com/v1/oauth/token',{method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)},timeout:15000},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>console.log(d));});
req.write(body);req.end();
"
# If node succeeds but daemon fails → check that post_json_node is wired (not post_json)
```

**A successful refresh rotates the RT server-side.** If you run the manual replay above, you MUST write the new tokens back into both `credentials/N.json` and `config-N/.credentials.json` immediately, or the old RT will show up dead on the next daemon tick.

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

## Codex Surface (v2.1, journals 0001-0010, 0023)

csq v2.1 added Codex (OpenAI's CLI) as a first-class second surface alongside ClaudeCode. The two surfaces are dispatched via `Surface::ClaudeCode` and `Surface::Codex` enums in `csq-core/src/providers/catalog.rs`. Surface classification is the input to every routing decision (`auto_rotate::find_target`, `csq swap` dispatcher, `daemon::refresher::tick`, `usage_poller::dispatch`). v2.1 auto-rotate is **ClaudeCode-only by design** — `find_target` short-circuits on non-ClaudeCode current account.

### Auth flow: device-auth, not paste-code

Codex uses OAuth device-auth via codex-cli (`codex login --device-auth`), not the Anthropic paste-code flow. csq spawns codex-cli as a subprocess, parses the device code from the scrubbed-line stdout (`is_device_code_shape` matches exactly `XXXX-XXXX`), surfaces it in the desktop UI, and waits for codex-cli to complete. Subprocess hardening (PR-C9a finding 2-7): bounded BufReader (64 KiB), `mpsc::sync_channel(4)`, `child.wait()` BEFORE `.join()` on reader threads, `cancel_codex_login` Tauri command, re-entrancy guard.

### Canonical credential layout

| File                                                         | Purpose                                                               | Mode     |
| ------------------------------------------------------------ | --------------------------------------------------------------------- | -------- |
| `credentials/codex-<N>.json`                                 | Canonical credential file (refresh tokens, access token, account_id)  | 0o400 \* |
| `config-<N>/config.toml`                                     | Codex configuration; MUST contain `cli_auth_credentials_store="file"` | 0o600    |
| `config-<N>/codex-sessions/`                                 | Per-account persistent session state                                  | 0o700    |
| `config-<N>/codex-history.jsonl`                             | Per-account command history                                           | 0o600    |
| `term-<pid>/auth.json` (symlink)                             | Resolves canonical-direct to `credentials/codex-<N>.json`             | symlink  |
| `term-<pid>/{config.toml,sessions,history.jsonl}` (symlinks) | Resolve to `config-<N>/...`                                           | symlinks |

\* `0o400` between refresh windows (INV-P08); the daemon refresher flips to `0o600` for the write then back to `0o400` under per-account mutex. The startup reconciler's `pass1_codex_credential_mode` repairs any drift from a SIGKILL mid-flip.

`auth.json` symlinks **canonical-direct** (NOT through `config-<N>`) per spec 07 §7.2.2. The other items symlink through `config-<N>`. This asymmetry matters for `csq swap` Codex→Codex: the rename loop in `repoint_handle_dir_codex` MUST rewrite `auth.json` BEFORE `.csq-account` so a mid-loop failure cannot leave the marker pointing at slot N+1 while the credential still resolves to slot N (M-CDX-1, journal 0024).

### Same-surface Codex swap is in-flight (M10, journal 0023)

`csq swap` Codex→Codex routes through `same_surface_codex` → `repoint_handle_dir_codex`, mirroring the ClaudeCode in-flight repoint. UNIX open-after-rename keeps in-flight session fds valid until close; codex-cli re-stats `auth.json` before each API call so the next request authenticates as the new slot. Pre-PR-C9a behavior was to take the cross-surface `exec`-replace path, silently dropping the conversation — that's the M10 bug fixed in v2.1.0.

The dispatcher routing matrix is unit-tested via the extracted `route(src, tgt) -> RouteKind` helper (`csq-cli/src/commands/swap.rs`, L-CDX-3). Any future refactor that re-routes `(Codex, Codex)` through `cross_surface_exec` fails `route_codex_to_codex_is_same_surface_codex` at `cargo test` time.

### Usage polling: `wham/usage`, not `/api/oauth/usage`

Codex usage lives at `https://chatgpt.com/backend-api/wham/usage` (NOT Anthropic's `/api/oauth/usage`). Live schema captured in journal 0010: two-window rate-limit (5h primary + 7d secondary, parallel to Anthropic's structure); `used_percent` is `0-100`, NOT `0-1` (same gotcha as Anthropic). PII at the top level (`user_id`, `account_id`, `email`) requires redaction before any logging or fixture capture.

`usage_poller/codex.rs` writes raw bodies to `accounts/codex-wham-raw.json` (0o600, redactor-first) for forensic drift detection. Circuit breaker: 5 consecutive failures → 15min initial backoff → 80min cap.

### Transport: Node.js subprocess (journal 0007)

Same Cloudflare TLS-fingerprint issue as Anthropic — reqwest/rustls is JA3/JA4-blocked. Codex endpoints route through the existing Node.js subprocess transport pattern from journal 0056. Reuses `csq-core/src/http/` handlers with Codex-specific endpoint URLs.

### Cross-surface swap

`csq swap` between ClaudeCode ↔ Codex slots takes the `cross_surface_exec` path: INV-P05 confirm prompt (`--yes` bypasses) → INV-P10 atomic rename of source handle dir to `.sweep-tombstone-swap-<pid>-<nanos>` (preserves open fds for the running surface; daemon sweep reaps the tombstone on next tick) → `exec` the target binary. Conversation does not transfer.

Windows: `cross_surface_exec` is `#[cfg(unix)]` (uses `std::os::unix::process::CommandExt`). Cross-surface swap on Windows is not supported in v2.1.

## Gemini Surface (v2.3, journals 0001-0013)

csq v2.3 added Gemini (Google's CLI) as a first-class third surface alongside ClaudeCode and Codex. Surface dispatch extends to `Surface::Gemini`; everything else (auto_rotate, swap, refresher, usage_poller) routes via `discovery::discover_all`. Two key inversions vs. Codex:

- **API-key only, no OAuth** (ADR-G09). OAuth subscription rerouting is rejected per Google ToS — the 7-layer guard below actively prevents it. There is no disable knob (C-CR1).
- **No daemon required for `csq run`** (INV-P02 inverted). Quota is event-driven via NDJSON, not polled. See `daemon-architecture` SKILL.md "Gemini NDJSON Event Log Consumer".

### Auth: API-key paste or Vertex SA JSON

`csq setkey gemini --slot N --from-stdin` and the desktop AddAccountModal both run a stdin-only provisioning flow. The API key never appears in argv, never lands in any structured log, and is redacted by `error::redact_tokens` (the redactor learns `AIza*` in v2.3 alongside the existing `sk-ant-*` and long-hex coverage).

Two auth modes: **AI Studio API key** (validated to start with `AIza`; csq-cli `provision_api_key` rejects non-`AIza` paste mistakes BEFORE writing the vault) and **Vertex SA JSON path** (`provisioning::validate_vertex_sa_path` requires a regular file, ≤ 64 KiB, not a symlink). Canonical secret lands in `platform::secret` at namespace `gemini/<slot>`.

### `csq-core` orchestration helpers (single-source for csq-cli + csq-desktop)

| Helper                                      | What it does                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `provisioning::provision_api_key_via_vault` | atomic `vault.set` + `write_binding` with rollback on marker-write failure                           |
| `provisioning::set_model_name`              | reads binding, mutates model field, atomic write                                                     |
| `provisioning::is_known_gemini_model`       | static catalog check (4 entries: 2.5-pro, 2.5-flash, 2.0-flash-exp, 1.5-pro)                         |
| `provisioning::delete_api_key_from_vault`   | reads binding to determine auth mode; `vault.delete` for ApiKey, no-op for VertexSa or absent marker |
| `spawn::spawn_gemini`                       | EP2/EP3 pre-spawn guards + env scrub + exec                                                          |

csq-cli (`commands/setkey.rs`, `commands/models.rs`) calls these helpers directly; csq-desktop's six Tauri commands (`gemini_provision_api_key`, `gemini_provision_vertex_sa`, `gemini_switch_model`, `gemini_probe_tos_residue`, `is_gemini_tos_acknowledged`, `acknowledge_gemini_tos`) wrap the same helpers. The desktop "remove account" path (`remove_account` Tauri command) calls `delete_api_key_from_vault` BEFORE touching the marker — closes the orphan-key risk that v2.3.1 (#203) patched after v2.3.0 shipped.

### Canonical layout

| Path                                           | Purpose                                                                              | Mode    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------ | ------- |
| `credentials/gemini-<N>.json`                  | Binding marker (auth mode + selected model). NOT a credential — vault holds the key. | 0o600   |
| `accounts/.gemini-tos-acknowledged-<slot>`     | Per-slot ToS acknowledgement marker (mirrors `codex/tos.rs` shape)                   | 0o600   |
| `accounts/gemini-events-<N>.ndjson`            | Per-slot CLI event log (drained by daemon — see daemon-architecture SKILL.md)        | 0o600   |
| `accounts/gemini-events-<N>.corrupt.<unix_ms>` | Rotated event log on parse failure (forensic retention)                              | 0o600   |
| `platform::secret` namespace `gemini/<slot>`   | At-rest secret (Keychain / Secret Service / Credential Manager / file)               | (vault) |

### 7-layer Terms-of-Service defense (EP1–EP7)

Active enforcement of Google's API-key-only requirement. C-CR1 mandates: no disable knob, no "EP4 is advisory" reclassification. Each layer is independent and all are mandatory.

| Layer | Where it fires                          | What it checks                                                                                                                              |
| ----- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| EP1   | `setkey gemini` / `gemini_provision_*`  | Refuses provisioning if `~/.gemini/oauth_creds.json` is present                                                                             |
| EP2   | `spawn::spawn_gemini` pre-exec          | `reassert_api_key_selected_type(handle_dir)` — refuses if user-level `selectedType=oauth-personal` would override                           |
| EP3   | `spawn::spawn_gemini` env build         | `Command::env_remove` drops `GOOGLE_APPLICATION_CREDENTIALS`, `GEMINI_API_KEY`, …                                                           |
| EP4   | `tos_guard.rs` runtime stderr sentinel  | Substring scan of gemini-cli stderr for documented OAuth-rerouting markers, pinned to `gemini-cli 0.38.x` (whitelist regression test green) |
| EP5   | `capture.rs` response-shape detector    | `modelVersion` mismatch flag against slot's selected model (REST + SSE)                                                                     |
| EP6   | `spawn::spawn_gemini` `.env` scan       | Pre-spawn hard refusal on `$CWD/.env` containing `GEMINI_API_KEY=` / `GOOGLE_API_KEY=`                                                      |
| EP7   | `csq logout` + desktop `remove_account` | `vault.delete(gemini/<slot>)` so secret never outlives slot                                                                                 |

**Whitelist-pinning convention.** When gemini-cli ships a new minor that changes the EP4 marker strings, the regression test `whitelist_matches_pinned_minor_version` fails before any user can bypass the sentinel. Bump = updated whitelist OR refusal dialog (PR-G3); never silent fall-through.

### `platform::secret` primitive (v2.3, generalized)

Five backends behind one `SecretStore` trait, selectable via `CSQ_SECRET_BACKEND`:

| Backend     | File                  | Used when                                                                                                |
| ----------- | --------------------- | -------------------------------------------------------------------------------------------------------- |
| `macos`     | `secret/macos.rs`     | macOS, default — `security-framework` Keychain                                                           |
| `linux`     | `secret/linux.rs`     | Linux, default — Secret Service via D-Bus                                                                |
| `file`      | `secret/file.rs`      | Linux opt-in / WSL-no-keyring fallback — AES-GCM-on-disk + Argon2id KDF + `CSQ_SECRET_PASSPHRASE[_FILE]` |
| `windows`   | `secret/windows.rs`   | Windows, default — DPAPI + Credential Manager                                                            |
| `in-memory` | `secret/in_memory.rs` | Tests only — gated `cfg!(any(test, feature = "secret-in-memory"))`                                       |

**`secret-in-memory` feature flag is dev-deps-only** for downstream test builds (csq-desktop). `cfg!(test)` only fires when csq-core is itself compiled with `--test`; downstream test binaries load csq-core as a normal dep where `cfg!(test)` is false. csq-desktop's `[dev-dependencies]` therefore lists `csq-core = { path = "...", features = ["secret-in-memory"] }`. Cargo unifies features across `[dependencies]` and `[dev-dependencies]` of the same crate, so the in-memory backend is reachable in `cargo test` builds and stays absent from `cargo build --release` (PR #203 + v2.3.1 fix).

`audit.rs` carries the security-reviewer sign-off ledger. Every backend implements: `set(SlotKey, &SecretString)`, `get(SlotKey) -> SecretString`, `delete(SlotKey)`, `list_keys() -> Vec<SlotKey>`. Errors map via `SecretError` (BackendUnavailable / Locked / AuthorizationRequired / NotFound / Timeout / Io / EncryptionFailed / DecryptionFailed / InvalidKey / PermissionDenied) — every variant has actionable UI text per `tauri-commands.md` §6.

**Drop-vault-on-unbind invariant (D7, journal 0013):** any code path that removes a Gemini slot's binding marker MUST also call `vault.delete(SlotKey { surface: SURFACE_GEMINI, account: N })`. CLI `csq logout` does it via `delete_api_key_from_vault`; desktop `remove_account` does it via the same helper since v2.3.1.

### Gemini cross-surface swap

Same shape as Codex: same-surface Gemini→Gemini repoint atomically; cross-surface follows v2.1.0 INV-P05 confirm + INV-P10 rename-source-to-tombstone + `exec`. The dispatcher routing matrix (`csq-cli/src/commands/swap.rs::route`) extends to handle the Gemini RouteKind variant.

### Static model catalog (no `/models` endpoint)

`csq models switch <slot> <model>` for Gemini routes to a static 4-entry catalog. gemini-cli does not expose a `/models` endpoint analogous to claude-cli's, so new entries land in csq-core releases — `is_known_gemini_model` is the single source of truth.

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
