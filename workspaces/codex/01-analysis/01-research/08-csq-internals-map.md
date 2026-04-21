# 08 — csq Internals Map for Codex Integration

Phase: /analyze | Agent: Explore | Date: 2026-04-21

Call-site inventory for every subsystem the Codex surface integration must touch. File:line citations against csq HEAD at time of analysis. This drives implementation sequencing.

## 1. Provider Catalog & Dispatch

**File: `csq-core/src/providers/catalog.rs:48-111`**

Current structure:

- `const PROVIDERS: &[Provider]` — 4 entries: claude (OAuth), mm (Bearer), zai (Bearer), ollama (None)
- `pub fn get_provider(id: &str)` — lookup by id string
- `Provider` struct fields: `id`, `name`, `auth_type`, `key_env_var`, `base_url_env_var`, `default_base_url`, `default_model`, `validation_endpoint`, `settings_filename`, `system_primer`, `timeout_secs`, `default_auth_token`

**For Codex (spec 07):**

- Add `surface: Surface` enum (ClaudeCode | Codex | Gemini)
- Add `spawn_command: &'static str` ("codex")
- Add `home_env_var: &'static str` ("CODEX_HOME")
- Add `home_subdir: Option<&'static str>` (None)
- Add `model_config: ModelConfigTarget` (TomlModelKey)
- Add `quota_kind: QuotaKind` (Utilization)
- Append Codex entry to PROVIDERS with id="codex", auth_type=OAuth
- Update all `get_provider()` callsites that dispatch on provider id

## 2. Provider Settings Load/Save

**File: `csq-core/src/providers/settings.rs:162-246`**

- `load_settings(base_dir, provider_id)` — reads `{settings_filename}`, defaults if missing
- `save_settings(base_dir, settings)` — atomic write with 0o600 perms via `secure_file()` + `atomic_replace()`
- `ProviderSettings` struct: raw JSON Value + provider_id
- Methods: `get_api_key()`, `set_api_key()`, `get_model()`, `set_model()`, `get_group_id()` (MiniMax)

**For Codex:** Codex auth is NOT in settings.json — it's in `credentials/codex-<N>.json` (spec 07.2.2). Model config is in `config-<N>/config.toml` (TomlModelKey). `settings.rs` unchanged; Codex dispatch happens in session setup.

## 3. Handle-Dir Lifecycle

**File: `csq-core/src/session/handle_dir.rs:43-150`**

- `create_handle_dir(base_dir, claude_home, account, pid)` — creates `term-<pid>/` with symlinks
- `const ACCOUNT_BOUND_ITEMS: &[&str]` = `.credentials.json`, `.csq-account`, `.current-account`, `.quota-cursor` (line 37-41)
- Shared items via `ensure_shared_target()` (line 148)
- `.claude.json` and `settings.json` are intentionally NOT symlinked (line 29-35 comments)
- `repoint_handle_dir()` — swap symlink targets atomically
- `sweep_dead_handles()` — daemon cleanup

**For Codex:**

- Handle dir IS `CODEX_HOME` (not wrapper around config-<N>)
- Codex symlink set: `codex-auth.json`, `config.toml`, `codex-sessions/`, `codex-history.jsonl` (spec 07.2.2)
- Codex `home_subdir = None` → handle-dir root = CODEX_HOME root
- Dispatch on `surface` to pick symlink set

**Changes:**

- `ACCOUNT_BOUND_ITEMS` → surface-aware table indexed by Surface
- `create_handle_dir()` gains `surface: Surface` parameter
- Branch on surface to populate correct symlink set
- `materialize_handle_settings()` branches on surface

## 4. Isolation & Shared Items

**File: `csq-core/src/session/isolation.rs`**

- `const SHARED_ITEMS: &[SharedItem]` — files/dirs symlinked from `~/.claude`
- `ensure_shared_target()` — creates target if absent
- Examples: `keybindings.json`, `history.jsonl`, `__store.db`, `plugins/`, `.mcp.json`

**For Codex:** Codex has its own shared-item set (if any). Make SHARED_ITEMS surface-aware with Codex/Gemini tables.

## 5. Swap Semantics

**File: `csq-cli/src/commands/swap.rs:13-66`**

- Reads `CLAUDE_CONFIG_DIR` env var
- If dir starts with `term-` (handle-dir model): `handle_dir::repoint_handle_dir()` + notify daemon cache invalidation
- If `config-` (legacy): `rotation::swap_to()` with deprecation warning
- Otherwise: error

**For Codex:**

- Read surface from marker or provider catalog
- Detect both current and target surfaces
- If surfaces differ → cross-surface warning + `exec` flow (ADR-C06)
- Same-surface uses existing `repoint_handle_dir()`

## 6. Login Flow

**File: `csq-cli/src/commands/login.rs:49-89`**

Current (Anthropic OAuth):

- Priority 1: shell out to `claude auth login` with isolated `CLAUDE_CONFIG_DIR=config-{N}/`
- Priority 2: daemon paste-code flow via `/api/login/{N}` + `/api/oauth/exchange`
- Finalize: update `profiles.json`, write `.csq-account` marker, clear `broker_failed` sentinel

Current (3P API key):

- `setkey` command → writes `config-<N>/settings.json` under `env.ANTHROPIC_AUTH_TOKEN`

**For Codex:**

- Device-code flow (spec 07.3.3):
  1. Write `config-<N>/config.toml` (cli_auth_credentials_store = "file" + model) BEFORE login
  2. Shell out: `CODEX_HOME=config-<N> codex login --device-auth`
  3. Codex writes `config-<N>/auth.json` on success
  4. Daemon renames to `credentials/codex-<N>.json`, symlinks back as `config-<N>/codex-auth.json`
  5. 0400 mode outside refresh windows
  6. Keychain probe (ADR-C11)

**New:**

- `csq-core/src/providers/codex/mod.rs` — orchestration module
- Extend `login.rs` with surface detection + device-code dispatch
- `find_codex_binary()` — PATH lookup (parallel to `find_claude_binary()`)

## 7. Daemon Refresher

**File: `csq-core/src/daemon/refresher.rs:65-395` (key gates at 283, 304-307)**

- Anthropic-only today: `discover_anthropic(base_dir)` + filter `info.source != AccountSource::Anthropic`
- `broker_check()` POST refresh_token → new access token
- Cache update + `credentials/<N>.json` write
- Cooldowns + exponential backoff (10min × 2^n, cap 80min) per account

**For Codex:**

- Must dispatch by surface — Codex accounts route to `broker_codex_check()` hitting `auth.openai.com`
- Not a separate refresher subsystem — a surface-parameterized path inside `tick()`

**Changes:**

- Rename `discover_anthropic()` → `discover_refreshable()` returning `(AccountNum, Surface)` tuples
- Surface-dispatch `broker_check()` → `broker_anthropic_check()` vs `broker_codex_check()`
- Update cooldowns map key to `(Surface, AccountNum)` (prevents Anthropic-slot-9 vs Codex-slot-9 sharing cooldown)

## 8. Usage Poller

**File: `csq-core/src/daemon/usage_poller/mod.rs:56-150` + `third_party.rs:40-112`**

- `tick()` — Anthropic `/api/oauth/usage`
- `tick_3p()` — MiniMax, Z.AI via probe + rate-limit headers
- Both write `quota.json` keyed by account ID
- Cooldowns + backoff for 429/401/errors

**For Codex:**

- New sibling module `daemon/usage_poller/codex.rs`
- Hits `chatgpt.com/backend-api/wham/usage`
- Quota-kind = Utilization (same shape as Anthropic)

**Changes:**

- `mod.rs` dispatch table adds `Surface::Codex → codex::tick`
- Account discovery path becomes surface-aware
- Cooldowns keyed by (Surface, AccountNum)

## 9. Credential Storage

**File: `csq-core/src/credentials/` (file.rs:114, mod.rs:27, file.rs:135)**

- `canonical_path(base_dir, account)` → `credentials/<N>.json` (Anthropic)
- `live_path()` → `config-<N>/.credentials.json` — HARDCODED
- `CredentialFile::claude_ai_oauth: OAuthPayload` — struct field name (mod.rs:27)
- `rate_limit_tier: Some("default_claude_max_20x"...)` fixture — relies on `claude_ai_oauth` shape

**For Codex:**

- Canonical path: `credentials/codex-<N>.json` (spec 07.2.2)
- Symlink: `config-<N>/codex-auth.json` → `../credentials/codex-<N>.json`
- Needs different struct (device-code response shape, no subscription_type/rate_limit_tier in Anthropic's sense)

**Changes:**

- Fork `CredentialFile` into tagged enum: `CredentialFile::Anthropic { claude_ai_oauth }` | `CredentialFile::Codex { tokens }`
- Parameterize `canonical_path()` and `live_path()` by `Surface`
- One-shot migration on daemon startup to re-shape existing `credentials/<N>.json` into tagged form (or keep legacy filename and add parallel codex-<N>.json files)
- 0400↔0600 mode-flip helper (ADR-C13)

## 10. Quota State

**File: `csq-core/src/quota/state.rs:19-82`**

Current `quota.json`:

- `{ accounts: { "1": { five_hour, seven_day, rate_limits, updated_at } } }`
- `AccountQuota` struct: `five_hour: Option<UsageWindow>`, `seven_day: Option<UsageWindow>`, `rate_limits`, `updated_at`
- `UsageWindow`: `used_percentage: f64`, `resets_at: u64`

**For Codex:** same 5h/7d shape; schema change is adding `surface` + `kind` tags + `schema_version: 2` (spec 07 §7.6.2).

**Changes:**

- Bump schema version + one-shot migration
- Desktop UI must tolerate missing `surface` (default `"claude-code"`) during migration window (G7)

## 11. Desktop Commands (Tauri)

**File: `csq-desktop/src-tauri/src/commands.rs:67-180`**

Current:

- `get_accounts(base_dir)` → Vec<AccountView> (id, label, source, has_credentials, quota, token_status, provider_id)
- Dispatches on `AccountSource::Anthropic` vs `AccountSource::ThirdParty { provider }`

**For Codex:**

- Either add `AccountSource::Codex` variant OR reuse ThirdParty with provider="codex"
- New commands:
  - `start_codex_login(account: u16)` → device_code + user_code
  - `complete_codex_login(account: u16, device_code: string)` — polls until success
  - `swap_to_account(account: u16)` → `/api/invalidate-cache` + frontend refresh
  - `change_model_for_account(account: u16, model: string)` — dispatches to config.toml for Codex, settings.json for others
- `get_accounts()` reads AccountSource + surface for each account

## 12. Svelte Frontend Components

**Files: `csq-desktop/src/lib/components/{AddAccountModal,ChangeModelModal,AccountList}.svelte`**

**AddAccountModal state machine:**

- Steps: picker, running-claude, paste-code, bearer-form, keyless-confirm, success, error
- `ProviderView`: id, name, auth_type ('oauth' | 'bearer' | 'none'), default_base_url, default_model

**For Codex:**

- Add `device-code` step: display user_code + QR, poll completion
- Extend ProviderView with `surface` field
- Step transitions:
  - Codex: picker → ToS disclosure → codex-binary check → device-code → exchanging → success
  - Claude: existing paths
  - MM/ZAI: existing bearer-form
- New Tauri invokes: `start_codex_login` + poll `complete_codex_login`

**Changes:**

- Fetch ProviderView list from Tauri (`list_providers()`) instead of hardcoded
- AccountList.svelte: surface badge
- ChangeModelModal: live fetch + cache + staleness badge

## 13. Run Command & Session Setup

**File: `csq-cli/src/commands/run.rs:12-96` + `:98-135` (3P) + `:139-200` (Anthropic)**

Current:

- Resolve account, detect 3P via `discover_per_slot_third_party()`
- Dispatch to `launch_third_party()` or `launch_anthropic()`
- Both: create handle dir, set CLAUDE_CONFIG_DIR, exec `claude`

**For Codex:** new `launch_codex()`:

1. Verify daemon is running (INV-P02)
2. Verify `config-<N>/config.toml` exists
3. Create handle dir (surface=Codex symlink set)
4. Set CODEX_HOME = handle_dir_abs
5. Strip `OPENAI_*` env vars
6. Exec `codex`

**Changes:**

- Surface detection in `resolve_account()` or run dispatch
- `launch_codex()` function
- Correct env var per surface

## 14. Error Handling & Token Redaction

**File: `csq-core/src/error.rs:44, 76-105, 260`**

- `redact_tokens()` matches `sk-ant-oat01-`, `sk-ant-ort01-`, generic `sk-*`, long hex
- `sanitize_body()` (line 55) for HTTP error responses
- `extract_oauth_error_type()` (line 44) — &static str allowlist to prevent injection
- `error_kind_tag` (line 260) — closed enum of Anthropic-flavored tags

**For Codex:**

- Add `sess-[A-Za-z0-9_-]{20,}` pattern + JWT shape to KNOWN_TOKEN_PREFIXES
- Extend `error_kind_tag` enum with OpenAI-flavored tags (`rate_limit_exceeded`, `insufficient_quota`, `account_suspended`, `codex_schema_drift`)
- Unit test: sample Codex error body round-trips to correct tag (lesson from journal 0052)
- Extend `OAUTH_ERROR_TYPES` allowlist with device-code flow errors

## 15. Models & Provider Catalog Extension

**File: `csq-core/src/providers/models.rs:22-82`**

Current: 3 Claude + 1 MiniMax + 1 Z.AI. Ollama is dynamic (via `ollama list`).

**For Codex:** Codex list is dynamic (via `chatgpt.com/backend-api/codex/models`). Pattern matches Ollama more than Claude. Add `discover_codex_models()` alongside `ollama.rs`. Bundle a cold-start minimal list (`gpt-5-codex`, `gpt-5.1-codex`) so the modal is never empty (resolves F6').

## 16. Tests & Integration

**Inferred structure:**

- Unit tests inline per module (providers/catalog.rs:124-193)
- Integration tests in `tests/` directory
- 3P fixtures: mock HTTP responses, fake credentials

**For Codex — new test files:**

- `tests/integration_codex_login.rs` — device-code flow with mock
- `tests/integration_codex_swap.rs` — cross-surface swap
- `tests/integration_codex_sweep.rs` — sweep of Codex handle dir preserves symlink targets (R3)
- `tests/fixtures/codex-auth.json` — canonical credential shape sample
- Extend handle-dir tests to include Surface parameter
- Extend refresher tests to verify surface-dispatched filter (regression for PR1)
- Golden-file test on `wham/usage` parser (F5)

## 17. Dispatch Patterns & Missing Abstractions

**Key pattern: Surface-aware dispatch**

Today dispatches on:

- `provider.id` string — catalog.rs
- `AccountSource` enum (Anthropic vs ThirdParty { provider }) — discovery.rs, commands.rs

**For Codex — dispatch points that become surface-aware:**

1. `handle_dir.rs` — ACCOUNT_BOUND_ITEMS, symlink materialization
2. `run.rs` — session launch
3. `swap.rs` — same-surface vs cross-surface (ADR-C06)
4. `refresher.rs` — discovery filter + refresh endpoint
5. `usage_poller/mod.rs` — discovery + poll endpoint
6. `credentials/` — canonical path + struct shape
7. `login.rs` — OAuth vs device-code
8. Desktop commands — AccountSource + UI dispatch
9. `error.rs` — token patterns + error_kind_tag enum
10. `auto_rotate.rs` (daemon) — refuse cross-surface candidates (G13)

## Summary: Implementation Sequencing

| Phase | What                                                                   | Touches                             | Regression Risk                                                |
| ----- | ---------------------------------------------------------------------- | ----------------------------------- | -------------------------------------------------------------- |
| PR1   | `Surface` enum + refactor catalog + surface-dispatch existing filters  | 10 files                            | **High** — Anthropic refresh filter must explicitly skip Codex |
| PR2   | `providers::codex` module (login, config.toml seed, keychain probe)    | 3-4 new files                       | Low (isolated)                                                 |
| PR3   | `daemon::refresher` Codex extension                                    | refresher.rs, credentials/, broker/ | **High** — endpoint + payload differences                      |
| PR4   | `daemon::usage_poller::codex`                                          | new module in usage_poller/         | Medium                                                         |
| PR5   | Desktop UI (AddAccountModal, ChangeModelModal, AccountCard, ToS modal) | ~6 Svelte + 2-3 Tauri commands      | Low                                                            |
| PR6   | `quota.json` v1→v2 migration                                           | quota/state.rs + daemon startup     | Medium                                                         |
| PR7   | `csq run` dispatch + `csq swap` cross-surface `exec`                   | run.rs, swap.rs                     | Medium                                                         |

**Total touch: ~25 key files across 5 subsystems (catalog, credentials, session, daemon, UI).**
