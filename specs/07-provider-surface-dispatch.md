# 07 Provider Surface Dispatch

Spec version: 1.0.0 | Status: DRAFT | Governs: per-surface on-disk layout, spawn command, login flow, quota dispatch, model-config key, cross-surface operations

---

## 7.0 Scope

csq originally launched only the `claude` binary. Third-party providers (MiniMax, Z.AI, Ollama) were bolted on by pointing `claude` at an alternative `ANTHROPIC_BASE_URL`. This spec adds a **surface abstraction** so csq can launch first-class native CLIs (`codex`, `gemini`) alongside `claude`, without a translation proxy and without regressing any existing provider.

A **surface** is the CLI binary csq spawns for a slot and the on-disk shape that binary expects. Three surfaces are in scope:

| Surface      | Binary   | Home env var        | Config-dir shape                                  |
| ------------ | -------- | ------------------- | ------------------------------------------------- |
| `ClaudeCode` | `claude` | `CLAUDE_CONFIG_DIR` | handle dir contains symlinks into `config-<N>`    |
| `Codex`      | `codex`  | `CODEX_HOME`        | handle dir IS the `CODEX_HOME`; symlinks for auth |
| `Gemini`     | `gemini` | `GEMINI_CLI_HOME`   | `handle-dir/.gemini/` is the effective state dir  |

This spec is additive on top of specs 01–05. It does not replace them. Spec 02 remains the base handle-dir model; this spec describes the per-surface specializations the `Surface` enum dispatches into.

## 7.1 The Surface abstraction

### 7.1.1 Type

The `Provider` struct (`csq-core/src/providers/catalog.rs`) gains:

```rust
pub enum Surface {
    ClaudeCode,
    Codex,
    Gemini,
}

pub struct Provider {
    // existing fields (id, name, auth_type, key_env_var, base_url_env_var, ...)
    pub surface: Surface,
    pub spawn_command: &'static str,
    pub home_env_var: &'static str,
    pub home_subdir: Option<&'static str>,     // Some(".gemini") for Gemini; None otherwise
    pub model_config: ModelConfigTarget,
    pub quota_kind: QuotaKind,                 // Utilization | Counter | Unknown
}

pub enum ModelConfigTarget {
    EnvInSettingsJson,      // ClaudeCode (Anthropic/MM/Z.AI): env.ANTHROPIC_MODEL in settings.json
    TomlModelKey,           // Codex: top-level `model = "..."` in config.toml
    SettingsModelName,      // Gemini: model.name in .gemini/settings.json
}
```

### 7.1.2 Dispatch tables

The following tables are the authority for per-surface behavior. Any code that switches on surface MUST read from these (or from constants derived from them), never hardcode a binary name or env var.

| Surface      | spawn_command | home_env_var        | home_subdir     | quota_kind  | model_config      |
| ------------ | ------------- | ------------------- | --------------- | ----------- | ----------------- |
| `ClaudeCode` | `claude`      | `CLAUDE_CONFIG_DIR` | None            | Utilization | EnvInSettingsJson |
| `Codex`      | `codex`       | `CODEX_HOME`        | None            | Utilization | TomlModelKey      |
| `Gemini`     | `gemini`      | `GEMINI_CLI_HOME`   | Some(".gemini") | Counter     | SettingsModelName |

## 7.2 Per-surface on-disk layouts

Base layout (spec 02 §2.1) is unchanged. The following amendments describe what each surface adds INSIDE its per-account `config-<N>/` and per-terminal `term-<pid>/`.

### 7.2.1 `Surface::ClaudeCode`

Unchanged from spec 02. `config-<N>` holds `.credentials.json`, `.csq-account`, `settings.json`, `.claude.json`. Handle dir holds symlinks + materialized `settings.json`.

### 7.2.2 `Surface::Codex`

```
config-<N>/                              (permanent, per-account)
├── .csq-account                         "N"
├── codex-auth.json          → ../credentials/codex-<N>.json   (symlink)
├── config.toml                          (daemon-writable; contains model + auth-store mode)
├── codex-sessions/                      (per-account, persistent)
├── codex-history.jsonl                  (per-account, persistent)
└── [shared symlinks — same set as ClaudeCode]

credentials/codex-<N>.json               (canonical, daemon-owned, mode 0400 outside refresh windows)

term-<pid>/                              (ephemeral; this IS CODEX_HOME)
├── .csq-account             → ../config-<N>/.csq-account       (symlink)
├── auth.json                → ../credentials/codex-<N>.json    (symlink)
├── config.toml              → ../config-<N>/config.toml        (symlink)
├── sessions                 → ../config-<N>/codex-sessions     (symlink)
├── history.jsonl            → ../config-<N>/codex-history.jsonl(symlink)
├── log/                                 (ephemeral, per-terminal)
└── .live-pid
```

**Why auth.json lives at `credentials/codex-<N>.json`, not inside `config-<N>`:** separation of concerns. The daemon's refresher owns tokens for every account regardless of surface; putting all canonical credentials in a single directory simplifies fanout reasoning and keeps config-<N> focused on user-editable state.

**Why `codex-sessions/` and `codex-history.jsonl` are persistent:** spec 02 INV-02 makes handle dirs ephemeral. Codex stores `sessions/` and `history.jsonl` inside `CODEX_HOME` by default; if we honored that literally, daemon sweep would delete user transcripts. The symlink relocates them to per-account persistent storage, analogous to how `Surface::ClaudeCode` symlinks `history/`, `sessions/`, etc. back to `~/.claude`.

### 7.2.3 `Surface::Gemini`

```
config-<N>/                              (permanent, per-account)
├── .csq-account                         "N"
├── .gemini/
│   ├── settings.json                    (pre-seeded; security.auth.selectedType = "gemini-api-key")
│   └── [sub-state symlinks into gemini-state]
├── gemini-state/                        (per-account, persistent)
│   ├── shell_history
│   └── tmp/
├── gemini-key.enc                       (API key, 0600; read by daemon only on spawn)
└── [shared symlinks]

term-<pid>/.gemini/                      (effective state dir under GEMINI_CLI_HOME)
├── settings.json            → ../../config-<N>/.gemini/settings.json (symlink)
├── .csq-account             → ../../config-<N>/.csq-account          (symlink)
├── shell_history            → ../../config-<N>/gemini-state/shell_history (symlink)
└── tmp                      → ../../config-<N>/gemini-state/tmp      (symlink)
```

**Why `home_subdir = Some(".gemini")`:** gemini-cli prepends `.gemini/` to whatever `GEMINI_CLI_HOME` points at. Setting `GEMINI_CLI_HOME=term-<pid>` causes gemini-cli to read/write `term-<pid>/.gemini/*`. The handle dir itself therefore needs a `.gemini/` subdir.

**Why the API key is never in `.env`:** `google-gemini/gemini-cli#21744` shows that if ANY `.env` exists in the `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME` discovery chain, the first file found short-circuits the lookup. csq injects `GEMINI_API_KEY` directly into the spawned child process environment. No `.env` files are written or relied upon by csq.

#### 7.2.3.1 Event-delivery contract (FROZEN — PR-G0)

Gemini is the first surface where the CLI (csq-cli) emits runtime events to the daemon without requiring the daemon to be running in order to spawn the child (INV-P02 inverted — ADR-G09). This subsection pins the socket-path resolution, connect-timeout, drop-on-unavailable, and NDJSON fallback-durability rules that every emitter MUST follow. Locked by PR-G0 so PR-G2a (capture module) and PR-G3 (daemon consumer) implement against a stable contract.

**Socket path resolution (same discipline as spec 04 §4.2.5 layer 3):**

```
if $XDG_RUNTIME_DIR is set and is a directory:
    socket = $XDG_RUNTIME_DIR/csq.sock
else:
    socket = ~/.claude/accounts/csq.sock
```

Resolution is identical to the daemon's `bind()` path. If the daemon binds the first path, csq-cli connects to the first path; if the daemon fell back to the second, csq-cli falls back to the second. A platform-path helper (`platform::paths::daemon_socket()`) is the single source of truth — emitter call sites MUST NOT hard-code either path.

**Non-blocking connect, 50 ms ceiling:**

Emitter issues `UnixStream::connect(path)` wrapped in `tokio::time::timeout(Duration::from_millis(50), ...)`. On timeout OR `ConnectionRefused` OR `NotFound`, the emitter does NOT retry, does NOT backoff, and does NOT block the spawn. The 50 ms bound is a hard ceiling: spawn latency is user-visible and Gemini's design tenet is "daemon absence MUST NOT degrade spawn-time UX."

**Drop-on-unavailable semantics:**

When IPC is unavailable, the emitter:

1. Writes the event to `gemini-events-<slot>.ndjson` (durability floor — see spec 05 §5.8).
2. Emits one structured log record at `warn` with fixed-vocabulary fields:
   ```
   error_kind = "gemini_event_ipc_unavailable"
   slot       = <u16>
   event_type = "counter_increment" | "rate_limited" | "effective_model_observed" | "tos_guard_tripped"
   reason     = "connect_timeout" | "connection_refused" | "socket_missing"
   ```
   No event payload in the log (payload contains no secrets per spec 05 §5.8, but the log stays lean for signal-to-noise).
3. Returns `Ok(())`. The emitter MUST NOT return an error to the spawn path — a failed emit is a successful drop, not a spawn failure.

**NDJSON is the durability floor, not a fallback:**

The NDJSON log is written on EVERY event, regardless of IPC success (C-CR2 design tenet: "single-writer-to-quota.json preserved via CLI-durable event log"). IPC is the same-session latency path; the log is the durability path. The daemon drains NDJSON on startup and reconnect (spec 05 §5.8); duplicate delivery is prevented by per-event UUIDs reconciled against the daemon's in-memory applied-event set.

**Emitter MUST NOT block on:**

- Filesystem growth of `gemini-events-<slot>.ndjson` (bounded by spec 05 §5.8 drain cadence, daemon responsibility).
- Daemon restart (log survives daemon-down windows by design).
- Peer-credential rejection (daemon's `SO_PEERCRED` layer — if rejected, same handling as timeout: drop + log + NDJSON).

**Test fixtures (PR-G0 docs-only; implementation tests in PR-G2a/PR-G3):**

- `socket_path_prefers_xdg_runtime_dir_when_set`
- `socket_path_falls_back_to_accounts_dir_when_xdg_unset`
- `connect_timeout_respects_50ms_ceiling_wall_clock` (guard against sleep-loop regressions)
- `emit_returns_ok_when_daemon_down` (NDJSON write verified, no error propagated)
- `emit_writes_ndjson_even_when_ipc_succeeds` (durability floor invariant)

**Cross-references:**

- spec 05 §5.8 — NDJSON durability contract (file layout, O_APPEND + fsync, drain semantics).
- spec 04 §4.2.5 — daemon socket layers 1–3 (the emitter assumes layer 3 path resolution).
- rules/security.md rule 7 — daemon IPC three-layer security (emitter inherits).
- journal 0067 H7 — origin of this subsection (event-delivery contract pinning).

## 7.3 Per-surface login and setup

### 7.3.1 `Surface::ClaudeCode` (Anthropic)

Unchanged: delegate to `claude auth login` inside `config-<N>/`. See spec 03.

### 7.3.2 `Surface::ClaudeCode` (MM / Z.AI)

Unchanged: API-key capture into `config-<N>/settings.json` under `env.ANTHROPIC_AUTH_TOKEN` + `env.ANTHROPIC_BASE_URL`. See journal 0025.

### 7.3.3 `Surface::Codex`

Ordered sequence (any deviation is a spec violation):

1. `mkdir -p config-<N>/` and `mkdir -p config-<N>/codex-sessions/`.
2. Write `config-<N>/config.toml` with:
   ```toml
   cli_auth_credentials_store = "file"
   model = "<default-model>"
   ```
   This MUST happen BEFORE step 3. Rationale: without this file, `codex login` uses the keychain default and writes a credential entry under `com.openai.codex` keychain service; a later csq rewrite of `config.toml` does not retroactively move the token to a file.
3. Shell out: `CODEX_HOME=config-<N> codex login --device-auth`. User completes device code in browser.
4. On success, codex writes `config-<N>/auth.json`. Daemon moves it to `credentials/codex-<N>.json` (atomic rename), then replaces `config-<N>/auth.json` with `codex-auth.json → ../credentials/codex-<N>.json` symlink.
5. Flip `credentials/codex-<N>.json` mode to `0400` outside refresh windows.
6. On first Codex login on the machine, probe for pre-existing keychain entry via `security find-generic-password -s com.openai.codex` (macOS). If present, offer purge via modal before proceeding.
7. Register account N with daemon refresher + usage poller.

### 7.3.4 `Surface::Gemini`

1. `mkdir -p config-<N>/.gemini/` and `mkdir -p config-<N>/gemini-state/tmp/`.
2. Write `config-<N>/.gemini/settings.json` pre-seeded:
   ```json
   {
     "security": { "auth": { "selectedType": "gemini-api-key" } },
     "model": { "name": "auto" }
   }
   ```
   This MUST happen BEFORE the first `gemini` spawn so the TUI does not interactively prompt for auth type.
3. Capture API key (AI Studio or Vertex service-account JSON path) via desktop modal or `csq setkey gemini --slot N`.
4. Encrypt at rest in `config-<N>/gemini-key.enc` using the platform-native secret layer. Never plaintext.
5. Probe: `GEMINI_CLI_HOME=config-<N> GEMINI_API_KEY=<key> gemini -p "ping" -m gemini-2.5-flash-lite --output-format json`. Exit 0 → valid.
6. Register account with daemon usage poller (counter mode).

## 7.4 Per-surface quota dispatch

Amends spec 05 — new sections are added there (§5.7 Codex, §5.8 Gemini), this spec fixes the dispatch table.

| Surface      | QuotaKind   | Endpoint                                                  | Refresh invariant                            |
| ------------ | ----------- | --------------------------------------------------------- | -------------------------------------------- |
| `ClaudeCode` | Utilization | `https://api.anthropic.com/api/oauth/usage` (or 3P probe) | Daemon-owned, spec 05 §5.1–5.4               |
| `Codex`      | Utilization | `https://chatgpt.com/backend-api/wham/usage`              | Daemon-owned, versioned parser, spec 05 §5.7 |
| `Gemini`     | Counter     | Client-side counter + 429 `RESOURCE_EXHAUSTED` parse      | Daemon-owned, spec 05 §5.8                   |

### 7.4.1 `quota.json` schema v2 (FROZEN — PR-C1.5)

This subsection is the authoritative contract for the quota.json v2 shape. PR-B8 (v2.0.1 dual-read), PR-C6 (v2.1 write-path flip), and PR-G3 (v2.2 Gemini event-driven consumer) all implement against this schema. Changes after freeze require a new section with a superseding revision stamp — no silent drift.

**Frozen 2026-04-22 by PR-C1.5** (journal 0067 H1: quota schema is a design-once cross-stream collision; freeze before either Codex or Gemini code is implemented, land the reader in v2.0.1 as shakedown).

#### Top-level

| Field            | Type                        | Required in v2 | Notes                                                               |
| ---------------- | --------------------------- | -------------- | ------------------------------------------------------------------- |
| `schema_version` | `u32`                       | Yes (= `2`)    | Absent → v1. Unknown value → reader errors with actionable message. |
| `accounts`       | `map<string, AccountQuota>` | Yes            | Keyed by account number as decimal string (unchanged from v1).      |

#### `AccountQuota` — mandatory fields

| Field        | Type     | Default on missing     | Applies to   | Notes                                                                                                    |
| ------------ | -------- | ---------------------- | ------------ | -------------------------------------------------------------------------------------------------------- |
| `surface`    | `string` | `"claude-code"`        | all surfaces | Allowed: `"claude-code"` / `"codex"` / `"gemini"`.                                                       |
| `kind`       | `string` | `"utilization"`        | all surfaces | Allowed: `"utilization"` / `"counter"` / `"unknown"`. `"unknown"` is the schema-drift degradation state. |
| `updated_at` | `f64`    | (required, no default) | all surfaces | Unchanged from v1 (Unix epoch seconds, fractional).                                                      |

#### `AccountQuota` — utilization fields (existing v1 shape, retained)

Used by `Surface::ClaudeCode` and `Surface::Codex`. Unchanged from v1:

| Field         | Type             | Default on missing | Notes                                                   |
| ------------- | ---------------- | ------------------ | ------------------------------------------------------- |
| `five_hour`   | `UsageWindow?`   | `null`             | `{ used_percentage: f64, resets_at: u64 }`.             |
| `seven_day`   | `UsageWindow?`   | `null`             | Same shape as `five_hour`.                              |
| `rate_limits` | `RateLimitData?` | `null`             | 3P response-header data (MM / Z.AI). Unchanged from v1. |

#### `AccountQuota` — counter fields (NEW, reserved for `Surface::Gemini`)

Shape reconciled with spec 05 §5.8 per VP-final red-team R1 (CRITICAL — nested spec shapes were inconsistent). All fields optional at the `AccountQuota` level; inner struct fields have their own required-ness. Serialization on Option parents: `#[serde(default, skip_serializing_if = "Option::is_none")]`. Readers that encounter these fields on a non-Gemini account MUST NOT error — they simply ignore them.

Two nested structs (`CounterState`, `RateLimitState`) carry Gemini-specific retry and reset bookkeeping. Inline scalar fields carry cross-response model state.

**`CounterState`** (reserved for `Surface::Gemini`):

| Field            | Type      | Default    | Semantics                                                                |
| ---------------- | --------- | ---------- | ------------------------------------------------------------------------ |
| `requests_today` | `u64`     | `0`        | CLI-sent request count since last reset.                                 |
| `resets_at_tz`   | `string`  | (required) | IANA TZ (always `"America/Los_Angeles"` for Gemini).                     |
| `last_reset`     | `string?` | `null`     | ISO-8601 timestamp of last midnight-TZ reset; `null` before first reset. |

**`RateLimitState`** (reserved for `Surface::Gemini`, but shape generic enough to describe any 429-driven retry state):

| Field                | Type      | Default | Semantics                                                                              |
| -------------------- | --------- | ------- | -------------------------------------------------------------------------------------- |
| `active`             | `bool`    | `false` | `true` during the 429 retry window.                                                    |
| `reset_at`           | `string?` | `null`  | ISO-8601 timestamp when the 429 retry window ends; `null` if unknown.                  |
| `last_retry_delay_s` | `u64?`    | `null`  | Most recent `retryDelay` from `RESOURCE_EXHAUSTED` body (diagnostic).                  |
| `last_quota_metric`  | `string?` | `null`  | Most recent `quotaMetric` from `RESOURCE_EXHAUSTED` body (diagnostic).                 |
| `cap`                | `u64?`    | `null`  | Daily cap (`quotaValue`) if known. Alias for what prior text called `rate_limit: u64`. |

**Inline Gemini fields on `AccountQuota`** (all optional):

| Field                           | Type              | Default | Semantics                                                                                 |
| ------------------------------- | ----------------- | ------- | ----------------------------------------------------------------------------------------- |
| `counter`                       | `CounterState?`   | `null`  | Per-day request counter state (nested).                                                   |
| `rate_limit`                    | `RateLimitState?` | `null`  | 429 retry state (nested).                                                                 |
| `selected_model`                | `string?`         | `null`  | Model the user requested (settings.json `model.name`).                                    |
| `effective_model`               | `string?`         | `null`  | Model Gemini actually used (per-response `modelVersion`, spec 05 §5.8).                   |
| `effective_model_first_seen_at` | `string?`         | `null`  | ISO-8601 first observation of current `effective_model` (drives `is_downgrade` debounce). |
| `mismatch_count_today`          | `u32?`            | `null`  | Count of responses where `effective_model != selected_model`. Reset at midnight LA.       |
| `is_downgrade`                  | `bool?`           | `null`  | Derived: `true` when `mismatch_count_today >= DOWNGRADE_DEBOUNCE` (default 3).            |

#### `AccountQuota` — escape-hatch field for unreserved data

Added per VP-final red-team R2 (HIGH — Codex `wham/usage` unknown shape). Reserved for surface-specific payload fragments that don't fit the above reserved fields. Never emitted by csq v2.0.1's v1 writer; added so PR-C5 (Codex wham parser) can stash unmigrated fields without forcing schema v3:

| Field    | Type                 | Default | Semantics                                                                                              |
| -------- | -------------------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `extras` | `serde_json::Value?` | `null`  | Surface-specific data outside the reserved schema. Consumers MUST tolerate unknown keys inside extras. |

Serialization: `#[serde(default, skip_serializing_if = "Option::is_none")]`. Does not contribute to semantic identity — round-trip preservation only.

#### `QuotaKind::Unknown` degradation

When a surface parser hits schema drift (new field it doesn't recognise in an upstream response, or a circuit-breaker-exceeded sequence of 5xx responses), the record's `kind` becomes `"unknown"` and utilization/counter fields stay at their last-known values. Statusline consumers render `quota: unknown` rather than a stale number. Recovery: next successful poll with recognised schema flips kind back to `"utilization"` or `"counter"`.

#### Example v2 file (mixed surfaces)

```json
{
  "schema_version": 2,
  "accounts": {
    "1": {
      "surface": "claude-code",
      "kind": "utilization",
      "five_hour": { "used_percentage": 42.0, "resets_at": 1775726400 },
      "seven_day": { "used_percentage": 8.0, "resets_at": 1776196800 },
      "rate_limits": null,
      "updated_at": 1775722800.0
    },
    "2": {
      "surface": "codex",
      "kind": "utilization",
      "five_hour": { "used_percentage": 18.0, "resets_at": 1775726400 },
      "seven_day": null,
      "rate_limits": null,
      "updated_at": 1775722800.0
    },
    "3": {
      "surface": "gemini",
      "kind": "counter",
      "updated_at": 1775722800.0,
      "counter": {
        "requests_today": 42,
        "resets_at_tz": "America/Los_Angeles",
        "last_reset": "2026-04-22T00:00:00-07:00"
      },
      "rate_limit": {
        "active": false,
        "reset_at": null,
        "last_retry_delay_s": null,
        "last_quota_metric": null,
        "cap": 1000
      },
      "selected_model": "gemini-2.5-pro",
      "effective_model": "gemini-2.5-pro",
      "effective_model_first_seen_at": "2026-04-22T14:12:00Z",
      "mismatch_count_today": 0,
      "is_downgrade": false
    }
  }
}
```

#### Compatibility matrix

| Writer \ Reader    | v1 reader (pre-B8)                                                                                                       | v2.0.1 dual-read (B8+)                                                                                                                                                                                                               | v2 writer (C6+)                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| v1 file (legacy)   | OK                                                                                                                       | OK (defaults applied)                                                                                                                                                                                                                | N/A                                                |
| v2 file (C6+)      | errors on `deny_unknown_fields`; otherwise OK via `#[serde(default)]` (v2.0.0 verified not to set `deny_unknown_fields`) | OK                                                                                                                                                                                                                                   | OK                                                 |
| schema_version > 2 | errors                                                                                                                   | **degrades** to `QuotaFile::empty()` with `WARN error_kind="schema_version_newer"` and `degraded=true` flag; statusline renders "quota: unknown (upgrade csq)" rather than hard-fail. Per VP-final red-team R3 (HIGH — rollback UX). | errors — refuses writing over incompatible version |

PR-B8 (v2.0.1) is the shakedown ship. It adds v2 READ with all fields optional-tolerant and continues to WRITE v1 schema_version — explicitly forced at the serialization boundary so a v2.0.1 daemon that somehow constructs `schema_version: 2` in memory still writes `schema_version: 1` to disk. v2.1 PR-C6 flips the write path.

### 7.4.2 Cross-stream consumer tests (PR-C1.5 gate)

The following regression tests are the contract that PR-B8 (v2.0.1), PR-C6 (v2.1), PR-G3 (v2.2) all satisfy against this frozen schema:

1. **Parse v1 file unchanged** — legacy file reads exactly as before this spec revision.
2. **Parse v2 file with Claude-only accounts** — migrated v1 with `schema_version=2` and `surface="claude-code"` fields explicit.
3. **Parse v2 file with mixed surfaces** — the §7.4.1 example above parses cleanly.
4. **Parse v2 file missing optional Gemini fields** — null-defaults applied without panic.
5. **Parse v2 file with schema_version=3 degrades not errors** — per R3 the reader returns an empty `QuotaFile` + WARN, does not propagate an error to callers. Statusline-facing use case.
6. **Round-trip v2 in-memory → save → load preserves Gemini fields** — v2.0.1 writer forces `schema_version: 1` on serialization, but nested Gemini fields (`counter`/`rate_limit`/etc.) survive the round-trip via serde defaults. Per R6, the round-trip is NOT byte-identical at the schema_version level — the test asserts semantic equality of accounts, with the writer's `schema_version=1` forcing documented.
7. **Reject non-numeric account keys** — per R5, `load_state` must error on `accounts[key]` where `key.parse::<u16>()` fails.
8. **`extras` field survives round-trip** — per R2, a v2 file with an `extras` object containing arbitrary shapes parses, round-trips, and the unknown fragment is preserved byte-for-byte.

These test names are canonical; PR-B8 / PR-C6 / PR-G3 implementations use the same names for traceability. The VP-final red-team expansion added tests 5' (degradation semantics), 7 (key validation), and 8 (extras round-trip).

### 7.4.3 Migration semantics (summarises §7.6.2 below)

On the v2.1 release that flips write path, daemon startup: (a) reads quota.json, (b) if `schema_version` is absent or `1`, stamps every account with `surface="claude-code"`, `kind="utilization"`, sets top-level `schema_version=2`, (c) atomically replaces the file. Idempotent, crash-safe (atomic rename). v2.0.1's PR-B8 dual-read means a v2.1 daemon starting against a v1 file never encounters a parse error — it simply migrates.

## 7.5 Invariants

**INV-P01: Daemon is the _scheduled pre-expiry_ refresher across refreshable surfaces.**

- For `Surface::Codex`, daemon refresh writes `credentials/codex-<N>.json` under `tokio::sync::Mutex` AT LEAST 2 HOURS before JWT expiry. Handle dirs NEVER hold a copy — only a symlink. Rationale: `openai/codex#10332` (refresh-token single-use race), `#15502` (copies of auth.json break refresh).
- **Why pre-expiry specifically:** codex's in-process refresh path (`codex-rs/login/src/auth/manager.rs:1863-1883` `is_stale_for_proactive_refresh`) fires only when the access-token `exp` claim is `<= Utc::now()`. There is NO pre-expiry leeway window in codex's own logic. The `cli_auth_credentials_store = "file"` flag does NOT disable in-process refresh; it only selects a write destination (verified OPEN-C01 resolution, 2026-04-22). The daemon prevents the in-process path from firing by always keeping tokens fresh enough that codex's threshold is never reached.
- For `Surface::ClaudeCode`, INV-06 (spec 02 / 04) still applies unchanged (2h pre-expiry window).
- For `Surface::Gemini` (API-key only), there is no refresh — API keys are flat and long-lived.
- **Clock-skew risk:** if local clock drifts > 2h ahead of server, the daemon will miss its refresh window and codex will fire its own refresh. Daemon emits `clock_skew_detected` warning when local time differs from HTTP `Date` header by > 5 min. See workspaces/codex/journal/0004.
- **Contingency:** if codex ever tightens its refresh threshold to pre-expiry (making the scheduled-refresh mitigation unreliable), csq interposes via `CODEX_REFRESH_TOKEN_URL_OVERRIDE` pointing at a daemon-local OAuth token-grant endpoint. Not shipped in PR1; captured as a follow-up track.

**INV-P02: Daemon is a hard prerequisite for refreshable surfaces.**

- `csq run N` for a slot bound to `Surface::Codex` MUST refuse to spawn if the daemon is not running, with an actionable error message. Rationale: INV-P01 depends on the daemon firing pre-expiry; without it, codex WILL hit its on-expiry threshold and refresh in-process, burning the refresh token via openai/codex#10332.
- `Surface::ClaudeCode` with Anthropic OAuth gets the same treatment (existing behavior from spec 04).
- `Surface::ClaudeCode` with MM/Z.AI and `Surface::Gemini` (API-key only) do NOT require the daemon — flat keys, no refresh.

**INV-P03: Configuration pre-seed is ordered.**

- For `Surface::Codex`, `config-<N>/config.toml` is written BEFORE `codex login` is invoked. Integration test asserts the ordering.
- For `Surface::Gemini`, `config-<N>/.gemini/settings.json` is written BEFORE the first `gemini` spawn. Integration test asserts the ordering.

**INV-P04: Handle dir persistence carveouts are surface-dispatched.**

- `Surface::ClaudeCode`: no per-terminal persistent state; `history/`, `sessions/` etc. symlink to `~/.claude` (spec 02 §2.1.3).
- `Surface::Codex`: `sessions/` and `history.jsonl` symlink to `config-<N>/codex-sessions/` and `config-<N>/codex-history.jsonl`. Daemon sweep of handle dir MUST NOT dereference these symlinks.
- `Surface::Gemini`: `shell_history` and `tmp/` symlink to `config-<N>/gemini-state/`. Same sweep guarantee.

**INV-P05: Cross-surface `csq swap` warns and exec-replaces.**

- If the target slot's surface differs from the current terminal's surface, `csq swap` prints a warning: `conversation will not transfer across surfaces`, prompts for confirmation (`--yes` bypasses), and then `exec`s the new surface's binary in place with the appropriate home env var and handle dir.
- Same-surface swap retains the existing in-flight symlink-repoint behavior (spec 02 INV-04).

**INV-P06: Model selection is dispatched by `ModelConfigTarget`.**

- `EnvInSettingsJson`: write `env.ANTHROPIC_MODEL` in `config-<N>/settings.json`.
- `TomlModelKey`: write top-level `model = "..."` in `config-<N>/config.toml`.
- `SettingsModelName`: write `model.name` in `config-<N>/.gemini/settings.json`.
- Native in-session `/model` slash commands (CC's, codex's, gemini's) are unaffected. csq seeds the default; the user overrides per-session.

**INV-P07: Token redaction covers all surface token formats before first log line.**

- `error::redact_tokens` MUST match: Anthropic `sk-ant-*`, Codex `sess-*` + JWT pattern, Gemini `AIza*`. Extension lands with the Codex PR and is verified by unit tests on the redactor.

**INV-P08: Credential mode-flip is mutex-coordinated.**

- `credentials/codex-<N>.json` (and any other canonical credential file that implements the 0400-outside-refresh pattern) MUST only be mode-flipped under the per-account `tokio::sync::Mutex` also held by the refresher.
- All writers (daemon refresh, `csq login N --provider codex`, re-login after `invalid_grant`) acquire the mutex, flip to `0600`, write (atomic rename), flip back to `0400`, release.
- Daemon startup runs a reconciler that flips any `0600` canonical credential file back to `0400` if no refresh is in progress. Derived from workspaces/codex/01-analysis/01-research/04-risk-analysis.md §2 R7 + ADR-C13.

**INV-P09: Per-account refresh mutex lifecycle is tied to slot provisioning.**

- Per-account `tokio::sync::Mutex` instances live in `DashMap<(Surface, AccountNum), Arc<Mutex<()>>>`.
- `csq login N --provider <surface>` allocates the mutex on first provisioning.
- `csq logout N` MUST acquire the mutex (serializing any in-progress refresh), delete the credential file, then remove the mutex entry from the DashMap.
- Memory is not leaked across logout/login cycles. Keyed on `(Surface, AccountNum)` prevents slot-9-Codex and slot-9-Anthropic from sharing a lock. Derived from ADR-C14.

**INV-P10: Cross-surface swap cleans up the source handle dir before exec.**

- When `csq swap M` crosses surfaces, csq MUST remove the current (source-surface) handle dir BEFORE `exec`ing the target binary on the new (target-surface) handle dir.
- If removal fails, swap aborts with non-zero exit; the `exec` is not attempted.
- If removal succeeds but `exec` fails (binary not on PATH, permission denied), csq exits non-zero with an actionable error; the user must re-run `csq run M`. The source terminal is already gone; this is deliberate — swap is destructive by its cross-surface nature. Derived from workspaces/codex/01-analysis/01-research/04-risk-analysis.md §4 G6.

**INV-P11: Auto-rotation refuses cross-surface candidates.**

- The daemon's auto-rotation subsystem (`daemon::auto_rotate`) MUST filter rotation candidates to the same `Surface` as the currently-active terminal.
- When no same-surface candidate is available, auto-rotation surfaces a user-visible notification rather than silently rotating across surfaces (which would require `exec` in place, an action reserved for explicit user `csq swap`).
- Derived from workspaces/codex/01-analysis/01-research/04-risk-analysis.md §4 G13.

## 7.6 Migration

### 7.6.1 Refactor existing providers to `Surface::ClaudeCode`

Current `catalog.rs` entries (claude, mm, zai, ollama) gain `surface: Surface::ClaudeCode`. Their `spawn_command` becomes `"claude"`, `home_env_var` becomes `"CLAUDE_CONFIG_DIR"`, `home_subdir` becomes `None`. Their `model_config` becomes `EnvInSettingsJson`. All existing tests must pass unchanged after the refactor.

### 7.6.2 `quota.json` v1→v2

On daemon startup, if `quota.json.schema_version < 2`, rewrite atomically: stamp all records with `surface: "claude-code"`, `kind: "utilization"`, bump schema to 2. Non-destructive — old value + timestamp preserved.

### 7.6.3 Existing handle dirs on upgrade

Pre-upgrade handle dirs have no `surface` marker. Daemon sweep treats them as `ClaudeCode`; they continue to work until the user exits their terminal. No forced migration.

## 7.7 Open preconditions

These are items that MUST be resolved (verified or decided) before the first Codex implementation PR lands. They are spec preconditions, not spec content per se — the spec's invariants above assume each of them resolves as expected.

### 7.7.1 OPEN-C01 — Verify `cli_auth_credentials_store = "file"` semantics re: in-process refresh

**Status:** RESOLVED 2026-04-22. Finding: the flag does NOT disable in-process refresh; it only selects a storage backend.

**Resolution summary** (full source citations in workspaces/codex/journal/0004-DECISION-daemon-pre-expiry-refresh-strategy.md):

- `codex-rs/login/src/auth/storage.rs:319-332` — `cli_auth_credentials_store` enum only chooses between `FileAuthStorage`, `KeyringAuthStorage`, `AutoAuthStorage`, `EphemeralAuthStorage`. No refresh gating.
- `codex-rs/login/src/auth/manager.rs:1376-1389` — `AuthManager::auth()` unconditionally invokes `refresh_token()` when `is_stale_for_proactive_refresh` returns true. Called from every codex HTTP path.
- `codex-rs/login/src/auth/manager.rs:1863-1883` — `is_stale_for_proactive_refresh` returns true when JWT `exp <= Utc::now()` OR `auth_dot_json.last_refresh > 8 days`. **No pre-expiry leeway**; codex refreshes ON expiry, not before.
- `codex-rs/login/src/auth/manager.rs:1745-1750` — in-process refresh is serialized by `refresh_lock` SCOPED TO ONE `AuthManager` (one codex process). Two sibling codex processes have no cross-process coordination → exactly the openai/codex#10332 failure mode.
- Grep of `codex-rs/` for `DISABLE_REFRESH|READONLY|NO_REFRESH|skip_refresh`: zero hits. No escape-hatch env var exists.

**Adopted mitigation:** daemon pre-expiry scheduled refresh with 2h safety margin (INV-P01 re-framed). Codex's on-expiry threshold is never reached because the daemon refreshes first. Contingency on failure: interpose via `CODEX_REFRESH_TOKEN_URL_OVERRIDE` (seen at `manager.rs:99`) to point codex's refresh endpoint at a daemon-local proxy. Upstream feature request for `CODEX_SKIP_INPROCESS_REFRESH=1` filed as a separate long-lead track.

**Confidence:** HIGH (direct source read, multi-branch grep, shallow clone of codex main 2026-04-22).

**Reference:** workspaces/codex/journal/0004; ADR-C15 (resolved); 04-risk-analysis.md §4 G1 (resolved).

### 7.7.2 OPEN-C02 — Verify `codex` honors `CODEX_HOME` for sessions/ and history.jsonl

**Status:** RESOLVED 2026-04-22 POSITIVE. Finding: `codex-cli` 0.122.0 respects `CODEX_HOME` fully for sessions/rollouts, shell snapshots, logs_2.sqlite, installation_id, and plugin tree. Probe: `CODEX_HOME=/tmp/codex-probe codex exec 'say only: hi'` wrote session rollout + shell snapshot + logs exclusively to `/tmp/codex-probe/`; `~/.codex/` received zero files with session_id matching the probe. C-CR3 kill-switch does NOT fire. Spec 07 §7.2.2 stands without modification.

**Reference:** workspaces/codex/journal/0005 (PR-C00).

### 7.7.3 OPEN-C03 — Verify `remove_dir_all` symlink-safety

**Status:** RESOLVED 2026-04-22 POSITIVE. Finding: `std::fs::remove_dir_all` on modern Rust (post-CVE-2022-21658 fix, Rust 1.58+) unlinks symlinks without traversing them. Empirical probe on macOS 25.3.0 (APFS) confirmed: `fs::remove_dir_all(handle_dir)` with `handle_dir/sessions → sensitive_dir/` symlink leaves `sensitive_dir/sentinel` intact. csq-core's existing `sweep_handles_image_cache_symlink` regression test (`csq-core/src/session/handle_dir.rs` line 2180) already covers this invariant for Claude Code's image-cache symlink; the Codex `sessions/` symlink inherits the same guarantee. PR-C0's `tests/integration_codex_sweep.rs` scoped to Codex-specific edge cases (broken symlink, symlink-to-symlink) rather than re-proving the base case.

**Reference:** workspaces/codex/journal/0006 (PR-C00); CVE-2022-21658.

### 7.7.4 OPEN-C04 — Verify HTTP transport for Codex endpoints

**Status:** RESOLVED 2026-04-22 — Node transport required. Finding: reqwest/rustls reaches OpenAI's Cloudflare-fronted endpoints without hard-block (all three transports returned 401 with `cf-ray` + `server: cloudflare`) BUT response bodies are stripped for reqwest — `{"error": {}, "status": 401}` instead of curl's full `{"error": {"message": "...", "code": "token_expired", ...}}`. Node fetch preserves the body with minor wording variance vs curl. Csq adopts the Node subprocess pattern (reused from Anthropic journal csq-v2/0056) for both `/oauth/token` refresh and `chatgpt.com/backend-api/wham/usage` polling. **PR-C0.5 fires** per plan.

**Reference:** workspaces/codex/journal/0007 (PR-C00); memory/discovery_cloudflare_tls_fingerprint.md.

### 7.7.5 OPEN-C05 — `/oauth/token` error-body token echo

**Status:** RESOLVED 2026-04-22 NEGATIVELY — no echo observed. Finding: four deliberately-bad refresh-token probes against `auth.openai.com/oauth/token` (three bogus tokens via curl/Node/reqwest + one real-but-burned token) produced error bodies that describe the failure without echoing submitted refresh_token values. Contrast with Anthropic's `/v1/oauth/token` which echoed refresh_token fragments (journal csq-v2/0007). Structural defense (SecretString module-wide in refresher) downgraded from emergency to "best-practice-when-touching-module"; PR-C0's redactor extension proceeds as planned as defense-in-depth for other Codex error surfaces (wham/usage 429s, WebSocket upgrades, SSO callbacks).

**Reference:** workspaces/codex/journal/0009 (PR-C00); redteam H6.

## 7.8 What this spec does NOT cover

- The exact `wham/usage` response schema — that lives in spec 05 §5.7 (to be captured on first live observation).
- The exact `RESOURCE_EXHAUSTED` error-body schema for Gemini 429s — spec 05 §5.8.
- CLI argument surfaces (`csq run`, `csq swap`, `csq login`, `csq models switch`) — spec 03.
- Desktop UI component design — workspaces/codex/05-frontend-design/, workspaces/gemini/05-frontend-design/.

## 7.8 Cross-references

- Spec 01 — CC credential architecture. Still authoritative for `Surface::ClaudeCode`.
- Spec 02 — Handle-dir model. Base invariants hold; §7.2 adds per-surface overlays.
- Spec 04 — Daemon architecture. §7.5 INV-P01, P02 extend the refresh invariants.
- Spec 05 — Quota polling contracts. §7.4 defines the dispatch; §5.7 / §5.8 (to be added) hold the per-endpoint contracts.
- `.claude/rules/account-terminal-separation.md` — rule 4 (account quota from provider endpoint, not CC) applies surface-generically.
- Workspaces: `workspaces/codex/`, `workspaces/gemini/` — per-surface analysis, plans, validation, journals.

## Revisions

- 2026-04-21 — 1.0.0 — Initial draft, introduced for Codex + Gemini integration. Derived from research + red team findings in this session (see workspaces/codex/04-validate/, workspaces/gemini/04-validate/ when populated). References openai/codex#10332, #15502; google-gemini/gemini-cli#21744.
- 2026-04-21 — 1.0.1 — /analyze phase for Codex surface completed (workspaces/codex/01-analysis/). Added INV-P08 (credential mode-flip mutex coordination), INV-P09 (per-account mutex lifecycle), INV-P10 (cross-surface swap cleanup), INV-P11 (auto-rotation refuses cross-surface). Added §7.7 Open preconditions OPEN-C01..C04 as PR-gating verifications. Spec ordering numbering shift: former §7.7 "What this spec does NOT cover" becomes §7.8; former §7.8 "Cross-references" becomes §7.9. Journaled in workspaces/codex/journal/0001.
- 2026-04-22 — 1.0.2 — OPEN-C01 RESOLVED via direct openai/codex source read. Finding: `cli_auth_credentials_store = "file"` does NOT disable in-process refresh; codex refreshes on-expiry regardless. INV-P01 re-framed to "scheduled pre-expiry refresher" with 2h safety margin (matches spec 04 INV-06 Anthropic pattern). INV-P02 rationale refined accordingly. Clock-skew mitigation added. Gemini /analyze phase completed (workspaces/gemini/01-analysis/) — no spec 07 changes required; Gemini inherits the abstraction unchanged. Journaled in workspaces/codex/journal/0004 and workspaces/gemini/journal/0001.
- 2026-04-22 — 1.1.0 — PR-C1.5: §7.4 expanded with frozen quota.json v2 schema subsection 7.4.1 (mandatory + optional fields, example mixed-surface file, compatibility matrix), §7.4.2 cross-stream consumer test names, §7.4.3 migration semantics summary. Minor bump because schema is a cross-stream contract; adding it is additive to existing text but promotes the shape from prose to specification. Consumed by PR-B8 (v2.0.1 dual-read), PR-C6 (v2.1 write flip), PR-G3 (v2.2 Gemini counter). Journal 0067 H1.
- 2026-04-22 — 1.1.1 — PR-VP-final red-team reconciliation. Shape of §7.4.1 Gemini counter fields reconciled with spec 05 §5.8 — `counter` and `rate_limit` promoted from flat scalars to nested structs (`CounterState` / `RateLimitState`) to preserve Gemini retry-state fields (`reset_at`, `last_retry_delay_s`, `last_quota_metric`) that the flat shape discarded. `effective_model_first_seen_at` added at AccountQuota level. `extras: Option<Value>` escape-hatch field added so surfaces (notably Codex `wham/usage`) can stash unmigrated payload fragments without forcing schema v3. `schema_version > 2` handling changed from hard-error to degrade-to-empty + WARN for rollback UX. §7.4.2 test list expanded from 6 to 8 canonical tests (5' degradation, 7 key validation, 8 extras round-trip). Consumed by PR-VP-Group1-code (PR-B8 schema revision). Journal 0067 R1/R2/R3/R5/R6.
- 2026-04-22 — 1.2.0 — PR-G0: §7.2.3.1 "Event-delivery contract" added. Pins socket-path resolution (shared with spec 04 §4.2.5 layer 3 via `platform::paths::daemon_socket()`), 50 ms non-blocking connect ceiling, drop-on-unavailable semantics with fixed-vocabulary structured log, NDJSON-as-durability-floor invariant, and the emitter-MUST-NOT-block rules. Consumed by PR-G2a (capture.rs emitter) and PR-G3 (daemon drain). Journal 0067 H7.
- 2026-04-22 — 1.2.1 — PR-C00: §7.7.2 OPEN-C02, §7.7.3 OPEN-C03 flipped to RESOLVED POSITIVE with citations to journals 0005, 0006. §7.7.4 OPEN-C04 flipped to RESOLVED (Node transport required) citing journal 0007 — PR-C0.5 fires. New §7.7.5 OPEN-C05 RESOLVED NEGATIVELY citing journal 0009. C-CR3 kill-switch does NOT fire (OPEN-C02 positive). Unblocks PR-C3 (handle-dir layout), PR-C4 (refresher via Node bridge), PR-C0 (redactor extension as defense-in-depth). Remaining gate: §5.7 schema capture (journal 0008 GAP — pending fresh Codex auth after this session's probe-induced refresh_token burn).
