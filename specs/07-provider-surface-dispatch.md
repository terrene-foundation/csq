# 07 Provider Surface Dispatch

Spec version: 1.6.0 | Status: DRAFT | Governs: per-surface on-disk layout, spawn command, login flow, quota dispatch, model-config key, cross-surface operations

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

identities/<UUID>/credentials-codex.json (identity-keyed canonical, daemon-owned, mode 0600)
credentials/codex-<N>.json               (legacy canonical, daemon-owned, mode 0400 outside refresh windows; retires release N+1)

term-<pid>/                              (ephemeral; this IS CODEX_HOME)
├── .csq-account             → ../config-<N>/.csq-account       (symlink)
├── auth.json                → ../credentials/codex-<N>.json    (symlink — retargeted to identities/<UUID>/credentials-codex.json)
├── config.toml              → ../config-<N>/config.toml        (symlink)
├── sessions                 → ../config-<N>/codex-sessions     (symlink)
├── history.jsonl            → ../config-<N>/codex-history.jsonl(symlink)
├── log/                                 (ephemeral, per-terminal)
└── .live-pid
```

**Why auth.json lives at `credentials/codex-<N>.json`, not inside `config-<N>`:** separation of concerns. The daemon's refresher owns tokens for every account regardless of surface; putting all canonical credentials in a single directory simplifies fanout reasoning and keeps config-<N> focused on user-editable state.

**Identity-keyed canonical write (parity with the Anthropic surface).** Every call to `csq_core::credentials::file::save_canonical_for` for a `Surface::Codex` variant writes `identities/<UUID>/credentials-codex.json` as the **canonical write site**, BEFORE writing to `credentials/codex-<N>.json` (legacy canonical). The chokepoint is `save_codex_canonical_for_uuid` in `csq-core/src/credentials/file.rs`, parallel to `save_uuid_credentials` for the Anthropic surface. Path shape resolved via `credentials_codex_path_for(base, uuid)` in `csq-core/src/accounts/identity_store.rs`.

Write-order invariants (parity with the Anthropic canonical write):

1. **Resolve UUID once.** `resolve_uuid_for_account(base, slot)` is called once at the top of the mutex-held section in `save_canonical_for`; the UUID is held through both writes (resolve-once constraint).
2. **Identity FIRST.** `identities/<UUID>/credentials-codex.json` is written before `credentials/codex-<N>.json`. A crash between write 1 and write 2 leaves the identity dir with the new tokens but the legacy dir stale — readers falling back to the legacy path see the old token until the next refresh tick, which is safe.
3. **Fail-closed.** If the identity write fails, the legacy write is NOT attempted; `save_canonical_for` propagates the `CredentialError` immediately.
4. **Graceful skip.** If no UUID mapping exists for the slot (legacy layout or daemon Pass 0 not yet run), the identity write is silently skipped and only `credentials/codex-<N>.json` is written. The legacy canonical retains its 0o400 mode-flip; the identity-keyed file is 0o600 (Codex JWTs are equally sensitive but the 0o400 mode is reserved for the legacy canonical per INV-P08 to preserve the existing refresh-window dance).
5. **Subscription-metadata guard call site.** `save_codex_canonical_for_uuid` invokes `preserve_subscription_metadata` at the same shape as `save_uuid_credentials`. The helper currently no-ops on Codex variants (Codex has no `subscription_type` / `rate_limit_tier`), but the call site retains structural parity so any future Codex-shape preservation (e.g. `last_refresh`) is automatic.
6. **Partial-failure cleanup compliance.** `save_codex_canonical_for_uuid` uses the injectable `save_codex_canonical_for_uuid_inner<W,S,R>` shape with `let _ = std::fs::remove_file(&tmp)` on every failure branch (write / secure_file / atomic_replace).
7. **Per-account mutex.** The chokepoint sits inside the per-`(Surface::Codex, AccountNum)` write mutex held by `save_canonical_for` via `AccountMutexTable::global().get_or_insert(...)`; serialises concurrent writers within one process.

The legacy `credentials/codex-<N>.json` canonical is **retained through release N** for downgrade safety; it retires in release N+1 once the downgrade window closes (per the 4-release-cycle migration policy).

**FM-6 — Codex `by_slot_identity` label is non-stable across re-login.** The `by_slot_identity` channel (spec 02 §2.2) writes `format!("codex-{}/{}", slot, account_id_prefix)` into `profiles.json::by_slot_identity[N]` on every successful `csq login --codex`. The `account_id_prefix` is the first dash-block of `tokens.account_id`, which is REGENERATED by ChatGPT's OAuth backend on every device-auth flow. Re-running `csq login --codex` against the same Codex account (same ChatGPT identity) produces a fresh `account_id`, hence a fresh label, hence the `by_slot_identity[N]` value changes between login attempts. This is intentional: csq has no stable per-account identifier from Codex's OAuth response (no email claim, no immutable subject) — `account_id` is the best available approximation, and the write captures whatever the upstream produced.

Operational consequences:

- `get_email(N)` for a Codex slot returns the most-recent post-login label. A `csq logout 12; csq login 12 --codex` sequence against the same Codex account changes the label between identical user actions.
- The `by_slot_identity` channel is identity-CLASS-stable (always `"codex-N/..."` shape) but not identity-VALUE-stable. Consumers needing value stability (e.g. cross-session reporting) MUST anchor on the slot number itself or on `accounts[N].email` (legacy, deprecated).
- The `id_token` JWT inside `credentials-codex.json` is NOT decoded by csq (`format_label` at `csq-core/src/providers/codex/login.rs` takes `account_id_hint`, never the JWT) — id_token stays opaque per the §7.3.3 banner. Future versions COULD anchor on a Codex-issued stable `sub` claim if Codex adds one, but the spec authority for the current shape is this paragraph.
- Backfill does NOT re-derive the label from `credentials-codex.json` for Codex slots — it only copies `accounts[N].email` verbatim when the prefix matches `"codex-"`. An upgraded host whose `accounts[N].email` was set by an older build carries that historical label forward; a future re-login overwrites it.

**Why `codex-sessions/` and `codex-history.jsonl` are persistent:** spec 02 INV-02 makes handle dirs ephemeral. Codex stores `sessions/` and `history.jsonl` inside `CODEX_HOME` by default; if we honored that literally, daemon sweep would delete user transcripts. The symlink relocates them to per-account persistent storage, analogous to how `Surface::ClaudeCode` symlinks `history/`, `sessions/`, etc. back to `~/.claude`.

### 7.2.3 `Surface::Gemini`

> **ToS clarification.** Earlier revisions of this spec described an EP1–EP7 "ToS guard" stack actively pinning `security.auth.selectedType = "gemini-api-key"` and killing gemini-cli processes that hit OAuth markers in stderr. That framing rested on a misreading of gemini-cli's published ToS guidance (the cited prohibition targets reimplementations that bypass the official CLI; csq spawns the official `gemini` binary as a subprocess, structurally identical to running it under tmux or a shell alias). The runtime enforcement has been removed and the architectural narrative below has been rewritten. csq treats Gemini the same way it treats Claude and Codex: the user authenticates the official CLI, csq spawns it, and the auth state in the user's `~/.gemini/` (OAuth credentials for Code Assist) or csq-managed `gemini-key.enc` (AI Studio API key, Vertex SA) drives the chosen mode.

```
config-<N>/                              (permanent, per-account)
├── .csq-account                         "N"
├── .gemini/
│   ├── settings.json                    (csq-managed model.name; auth.selectedType written ONLY when slot is bound to an API-key — not when the user authenticates via Code Assist OAuth)
│   └── [sub-state symlinks into gemini-state]
├── gemini-state/                        (per-account, persistent)
│   ├── shell_history
│   └── tmp/
├── gemini-key.enc                       (API key, 0600; present ONLY for API-key slots — absent for OAuth Code Assist slots)
└── [shared symlinks]

term-<pid>/.gemini/                      (effective state dir under GEMINI_CLI_HOME)
├── settings.json            → ../../config-<N>/.gemini/settings.json (symlink)
├── .csq-account             → ../../config-<N>/.csq-account          (symlink)
├── shell_history            → ../../config-<N>/gemini-state/shell_history (symlink)
└── tmp                      → ../../config-<N>/gemini-state/tmp      (symlink)
```

**Why `home_subdir = Some(".gemini")`:** gemini-cli prepends `.gemini/` to whatever `GEMINI_CLI_HOME` points at. Setting `GEMINI_CLI_HOME=term-<pid>` causes gemini-cli to read/write `term-<pid>/.gemini/*`. The handle dir itself therefore needs a `.gemini/` subdir.

**Why the API key is never in `.env`:** gemini-cli's `.env` discovery walks the `$CWD → ancestors → $GEMINI_CLI_HOME → $HOME` chain, and the first file found short-circuits the lookup. csq injects `GEMINI_API_KEY` directly into the spawned child process environment. No `.env` files are written or relied upon by csq.

**FM — Gemini `by_slot_identity` label stability.** The `by_slot_identity[N]` channel (spec 02 §2.2) carries `format!("gemini-{}/{}", slot, mode_class)` for Gemini-bound slots, where `mode_class ∈ {apikey, vertex, codeassist}` is a pure function of the `AuthMode` in the csq-owned `credentials/gemini-<N>.json` binding marker. Produced by the single shared `gemini_identity_label`, written synchronously by all 3 `provision_*` paths (marker-FIRST/identity-LAST) and by the daemon backfill Gemini arm. **Stability contract — the inverse of Codex §7.2.2 FM-6:** the Gemini label is identity-CLASS-stable always (`gemini-N/...` shape), and identity-VALUE-stable WITHIN a mode (re-provisioning slot N in the same mode yields the byte-identical literal — Gemini's mode does not regenerate across re-auth, unlike Codex's `tokens.account_id`). The value changes ONLY on a deliberate operator mode re-provision (`csq setkey gemini` over a slot previously in a different mode → `gemini-N/apikey` becomes e.g. `gemini-N/codeassist`). Therefore a `by_slot_identity[N]` value change for a Gemini slot is a LEGITIMATE operator action signal (mode switch), NOT the slot-hijack/re-auth ambiguity Codex FM-6 warns about. Consumers needing cross-mode value stability MUST anchor on the slot number, not the literal. **Forward-compat:** a future `BINDING_SCHEMA_VERSION` bump makes `read_binding` reject old-shape markers, which would make the backfill skip that slot (no identity written) — so binding-marker schema bumps MUST coordinate the `by_slot_identity` backfill. The distinct `gemini_provision_malformed` log tag surfaces this; it is never silently swallowed. Why mode-class and not a per-account id: the Vertex SA email lives in the operator's SA JSON and the Code Assist account-id in gemini-cli's `~/.gemini/oauth_creds.json` — reading either is the forbidden class (external/fragile/daemon-refreshed). The auth mode is the only per-slot identity fact csq owns in a file it atomically writes.

#### 7.2.3.1 Event-delivery contract (FROZEN)

Gemini is the first surface where the CLI (csq-cli) emits runtime events to the daemon without requiring the daemon to be running in order to spawn the child (INV-P02 inverted). This subsection pins the socket-path resolution, connect-timeout, drop-on-unavailable, and NDJSON fallback-durability rules that every emitter MUST follow.

**Socket path resolution (same discipline as spec 04 §4.2.5 layer 3):**

```
if $XDG_RUNTIME_DIR is set and is a directory:
    socket = $XDG_RUNTIME_DIR/csq.sock
else:
    socket = ~/.claude/accounts/csq.sock
```

Resolution is identical to the daemon's `bind()` path. If the daemon binds the first path, csq-cli connects to the first path; if the daemon fell back to the second, csq-cli falls back to the second. The daemon-path helper (`csq_core::daemon::paths::socket_path(base_dir)`, `csq-core/src/daemon/paths.rs`) is the single source of truth — emitter call sites MUST NOT hard-code either path.

**Non-blocking connect, 50 ms ceiling:**

Emitter issues `UnixStream::connect(path)` wrapped in `tokio::time::timeout(Duration::from_millis(50), ...)`. On timeout OR `ConnectionRefused` OR `NotFound`, the emitter does NOT retry, does NOT backoff, and does NOT block the spawn. The 50 ms bound is a hard ceiling: spawn latency is user-visible and Gemini's design tenet is "daemon absence MUST NOT degrade spawn-time UX."

**Drop-on-unavailable semantics:**

When IPC is unavailable, the emitter:

1. Writes the event to `gemini-events-<slot>.ndjson` (durability floor — see spec 05 §5.8).
2. Emits one structured log record at `warn` with fixed-vocabulary fields:
   ```
   error_kind = "gemini_event_ipc_unavailable"
   slot       = <u16>
   event_type = "counter_increment" | "rate_limited" | "effective_model_observed"
   reason     = "connect_timeout" | "connection_refused" | "socket_missing"
   ```
   No event payload in the log (payload contains no secrets per spec 05 §5.8, but the log stays lean for signal-to-noise).
3. Returns `Ok(())`. The emitter MUST NOT return an error to the spawn path — a failed emit is a successful drop, not a spawn failure.

**NDJSON is the durability floor, not a fallback:**

The NDJSON log is written on EVERY event, regardless of IPC success (single-writer-to-quota.json preserved via CLI-durable event log). IPC is the same-session latency path; the log is the durability path. The daemon drains NDJSON on startup and reconnect (spec 05 §5.8); duplicate delivery is prevented by per-event UUIDs reconciled against the daemon's in-memory applied-event set.

**Emitter MUST NOT block on:**

- Filesystem growth of `gemini-events-<slot>.ndjson` (bounded by spec 05 §5.8 drain cadence, daemon responsibility).
- Daemon restart (log survives daemon-down windows by design).
- Peer-credential rejection (daemon's `SO_PEERCRED` layer — if rejected, same handling as timeout: drop + log + NDJSON).

**Test fixtures:**

- `socket_path_prefers_xdg_runtime_dir_when_set`
- `socket_path_falls_back_to_accounts_dir_when_xdg_unset`
- `connect_timeout_respects_50ms_ceiling_wall_clock` (guard against sleep-loop regressions)
- `emit_returns_ok_when_daemon_down` (NDJSON write verified, no error propagated)
- `emit_writes_ndjson_even_when_ipc_succeeds` (durability floor invariant)

**Cross-references:**

- spec 05 §5.8 — NDJSON durability contract (file layout, O_APPEND + fsync, drain semantics).
- spec 04 §4.2.5 — daemon socket layers 1–3 (the emitter assumes layer 3 path resolution).

#### 7.2.3.2 Capability-layer with-layer deviation

When `csq run --capability-layer` engages on a Gemini slot AND the pre-spawn pipeline returns `LayerControl::WithLayer` (`.coc/` resolved + non-empty), `term-<pid>/.gemini/settings.json` is **materialized via JSON-merge** rather than the full-template re-emit shown in §7.2.3 above. The merge preserves any user-authored top-level keys csq does not manage (e.g. `mcpServers`, `ui.theme`). The Inherit path (capability layer off / `.coc/` fallback) goes through the same JSON-merge writer with `system_instruction = None` (preserved from any existing value), so layer-OFF spawns are still byte-equivalent to the pre-layer shape when the file starts empty.

**csq-managed fields:** `model.name` (slot-bound model) and `system_instruction` (capability-layer scaffold). For API-key / Vertex SA slots, csq additionally writes `security.auth.selectedType = "gemini-api-key"` so gemini-cli does not interactively prompt for auth type at first spawn. For Code Assist OAuth slots, csq writes `security.auth.selectedType = "oauth-personal"` (gemini-cli v0.41.2+ does NOT auto-discover `~/.gemini/oauth_creds.json` when the field is unset; it prompts for first-run auth method on every project entry until pinned). The binding-mode dispatch lives in `csq-core/src/providers/gemini/probe.rs::pin_selected_type_for`. The selected-type pin is a UX shortcut, NOT a ToS-driven defense. All other top-level keys are preserved verbatim by the JSON-merge writer.

**`system_instruction` ownership semantics.** csq owns the field ONLY when the capability layer is active for a spawn. The layer-OFF (Inherit) path through `csq_core::providers::gemini::probe::reassert_api_key_selected_type` PRESERVES any existing `system_instruction` value verbatim — whether user-authored OR written by a prior layer-on spawn. This avoids silent user-content loss (the same failure mode the codex `instructions` merge guards against).

**Operator-visible tradeoff.** A workstation that ran `csq run N --capability-layer` once leaves layer-era scaffold text in `.gemini/settings.json::system_instruction` until the next layer-on spawn or `csq login` re-seed. Bare-CLI spawns after a layer-on spawn inherit the scaffold; the alternative (silent strip on layer-off) was rejected as strictly worse (silent user-content loss). The text is informational system-prompt content with no enforced behavior — operators who need the pre-layer byte-equivalent shape can `csq login N` to re-seed cleanly.

**AlreadyCorrect gate.** All THREE csq-managed fields (`selectedType`, `model.name`, `system_instruction`) must match the requested values for `DriftOutcome::AlreadyCorrect` to fire. An earlier implementation gated only on `selectedType`, which silently dropped per-spawn directive injection on every post-first spawn (the `system_instruction` would be left at whatever the first spawn wrote, regardless of the new spawn's class verdict).

**Pre-spawn order preserved.** `build_spawn_plan_with_system_instruction` in `csq_core::providers::gemini::spawn` reuses the `build_spawn_plan` pipeline order: (1) `.env` shadow-auth scan FIRST so a refusal aborts before settings mutation (clean rollback) — purpose is preventing accidental cross-account credential leak (a generic safety guard), not a ToS defense; (2) read binding marker; (3) settings drift reassertion (handles `model.name` + `system_instruction` ownership; only writes `security.auth.selectedType` for API-key-bound slots); (4) resolve secret (skipped for OAuth slots); (5) build allowlisted env. The §7.5 INV-P02 inversion (Gemini does NOT require the daemon) is unchanged — gemini's spawn does not depend on token refresh.

**Post-rename re-stat (TOCTOU close).** Immediately before `Command::spawn` (via `execute_plan_as_child`), `csq/src/cli/commands/run.rs::verify_gemini_handle_settings_is_regular_file` re-stats `term-<pid>/.gemini/settings.json` and refuses to spawn if it became a symlink between materialization and spawn. Closes the same-user-attacker TOCTOU window where an unlink + symlink-replace would otherwise inject attacker-controlled `system_instruction` into gemini-cli. Mirrors the codex variant at §7.2.2.1.

**Bench-reset path.** `csq login <N> --reset-handle-dir` JSON-merge-removes `system_instruction` from `config-<N>/.gemini/settings.json` via `csq/src/cli/commands/login.rs::reset_handle_dir_gemini` (the removal is inline in the login command; `providers/gemini/settings.rs` exposes only the writer/merge helpers). The bench harness invokes this before every trial; ownership semantics still hold (csq owns `system_instruction` only when the layer is active for a spawn) — the reset is a bench-only contract, NOT a routine layer-off path. Without per-trial reset, the layer-off ratio collapses toward 1.0× because gemini-cli reads the prior layer-on `system_instruction` on its layer-off invocation.

**Cross-references.**

- `csq-core/src/providers/gemini/settings.rs::merge_managed_into_existing` — pure JSON-merge writer.
- `csq/src/cli/commands/login.rs::reset_handle_dir_gemini` — bench-reset removal (inline JSON-merge removal of `system_instruction`).
- `csq-core/src/providers/gemini/probe.rs::reassert_api_key_selected_type` (layer-OFF) + `reassert_api_key_selected_type_with_system_instruction` (layer-ON).
- `csq-core/src/providers/gemini/spawn.rs::build_spawn_plan_with_system_instruction` + `execute_plan_as_child`.
- `csq/src/cli/commands/run.rs::launch_gemini` (with-layer arm) — orchestration.

#### 7.2.3.3 Host-isolation warning surfacing

When the capability layer engages on a Gemini slot AND the parent env carries production-shaped secrets (per `csq_core::env::looks_like_production_secret`), csq surfaces an informational warning to three sinks:

1. **stderr** — single line emitted by `csq/src/cli/commands/run.rs::emit_host_isolation_warning_if_needed` BEFORE the gemini-cli spawn. Carries the count + first-detected-name exemplar (NOT the full names list — disclosure-minimization). Format: `warning: gemini host-isolation — N production-shaped env-var name(s) detected (e.g. <FIRST>); model running gemini reads $HOME unfiltered.`

2. **structured log** via `tracing::warn!` with fixed-vocabulary fields: `error_kind="gemini_host_isolation_warning" surface="gemini" account=<N> detected_count=<N> first_name=<NAME>`.

3. **`csq doctor`** — `host_isolation` field in the JSON output. Gate: `status: "warning"` requires BOTH `gemini_slots_present == true` AND `detected_count > 0`. Operators who provision only cc/codex slots see `status: "ok"` regardless of env shape (no false-positive WARN). Default mode emits count + first_name; verbose mode adds the full `detected_var_names` array.

**Exemplar selection.** `first_name` uses `csq_core::env::first_exemplar` which prefers the EXACT-priority list (`ANTHROPIC_API_KEY` > `OPENAI_API_KEY` > ... > `GITHUB_TOKEN`) over lex-first. Operators with both a known-real and a benign-suffix-pattern detection see the known-real name as the exemplar.

**Heuristic scope.** `looks_like_production_secret` matches via SUFFIX (`_API_KEY`, `_SECRET_KEY`, `_ACCESS_KEY`, `_PASSWORD`, `_CREDENTIALS`, `_TOKEN`) plus an EXACT-match list of known SaaS shapes. Bare `_KEY` / `_PASS` / `_SECRET` were dropped from SUFFIXES (over-broad — `XKB_DEFAULT_LAYOUT_KEY`, `MY_DOG_NAME_PASS`, `SUPER_SECRET` false positives).

**Informational, not enforcement.** The warning does NOT abort the spawn. Operator-side mitigation (run gemini suites on a clean VM / dedicated eval host) stays load-bearing. csq's surfacing makes the risk visible at decision time but does not prevent the operator from accepting it on hardened workstations.

**Cross-references.**

- `csq_core::env::looks_like_production_secret` + `first_exemplar` — heuristic.
- `csq/src/cli/commands/run.rs::detect_host_context` + `emit_host_isolation_warning_if_needed` — per-spawn detection + emission.
- `csq/src/cli/commands/doctor.rs::HostIsolationStatus` + `check_host_isolation_with_env` — doctor surface (testable variant takes env-name iterator to avoid `std::env` mutation in tests).

#### 7.2.2.1 Capability-layer with-layer deviation (Codex)

When `csq run --capability-layer` engages on a Codex slot AND the pre-spawn pipeline returns `LayerControl::WithLayer` (`.coc/` resolved + non-empty), `term-<pid>/config.toml` is **materialized as a regular file** (rather than the symlink to `config-<N>/config.toml` shown in the §7.2.2 layout above) for that single spawn. The regular file contains the canonical content + a per-spawn `instructions = "..."` block built by the capability layer's scaffold stage. The Inherit path (capability layer off OR `.coc/` resolves to `CocSource::Empty`) preserves the symlink layout — byte-equivalent to the pre-layer shape.

**Merge mechanism.** `csq/src/cli/commands/run.rs::materialize_handle_config_toml_with_instructions` reads the canonical, calls `csq_core::coc::translate::codex_merge::merge_instructions_via_toml_value` (`toml::Value` round-trip — NOT string concatenation), atomic-writes to `term-<pid>/config.toml`. The merge function:

- Parses canonical via `toml::from_str` (sanitized error on parse failure — discards the parser's body to avoid echoing fragmented credential bytes per spec 07 INV-P07).
- When the canonical already has a non-empty `instructions = "..."` value, the user's text is preserved; the layer scaffold is appended under sentinel fences `[csq:layer-scaffold-begin]` / `[csq:layer-scaffold-end]` for unambiguous audit grep.
- Refuses with actionable error if the canonical `instructions` already contains either fence marker (indicates a prior csq write was hand-edited or the literal was pre-seeded — recovery via `csq login N --provider codex` re-seed).
- `config_toml_overlay` keys (today always empty; reserved for MCP filter parameters) are parsed via `toml::from_str` as single TOML scalar expressions to preserve scalar type (an overlay value `"42"` becomes integer 42, not the string `"42"`). Multi-line raw values + trailing comments are rejected.
- Round-trip parses the serialized output and asserts byte-equality on the `instructions` field — catches serializer bugs.

**Safety rationale (NO cross-process lock).** The merge does NOT acquire any cross-process or intra-process lock. Safety relies on:

1. **Canonical-writer atomicity:** all writers to `config-<N>/config.toml` (`csq login --provider codex` and `daemon::startup_reconciler::pass2_codex_config_toml`) use `csq_core::platform::fs::atomic_replace` (`rename(2)` Unix / retry-loop `MoveFileExW` Windows). Readers see EITHER full-old OR full-new content, never a partial state.
2. **Writer rarity:** both writers are interactive (`csq login`) or once-per-daemon-start (reconciler). Concurrent racing of either with a `csq run --capability-layer` spawn is a same-user-self-race the operator triggered.
3. **Round-trip parse defense-in-depth:** if `config-<N>/config.toml` is corrupt for ANY reason (bit rot, manual edit producing invalid TOML, future writer that fails to use atomic_replace), `toml::from_str` returns Err and the helper aborts cleanly. No silent corruption reaches the merged tmp.

A future PR introducing a writer that does NOT use `atomic_replace` MUST add a CI grep test asserting all writers use `atomic_replace` — partial-valid-TOML (e.g., truncated mid-comment) could otherwise yield wrong-content corruption rather than parse-error abort. A CI gate enforces this contract on every commit.

**Post-rename re-stat (TOCTOU close).** Immediately before `Command::spawn`, `csq/src/cli/commands/run.rs::verify_codex_handle_config_toml_is_regular_file` re-stats `term-<pid>/config.toml` and refuses to spawn if it became a symlink between materialization and spawn. Closes the same-user-attacker TOCTOU window where an unlink + symlink-replace would otherwise inject attacker-controlled `instructions` into codex.

On Unix, the re-stat window is **microseconds** (post `rename(2)`). On Windows, the window is **up to 500 ms** because `atomic_replace_windows` retries `MoveFileExW` up to 5 times with 100 ms delay between attempts. The fail-closed abort posture preserves safety on both platforms; operators on Windows seeing intermittent "config.toml became a symlink" errors should investigate concurrent process modification.

**Bench-reset path.** `csq login <N> --reset-handle-dir [--non-interactive]` re-symlinks `term-<pid>/config.toml` → `config-<N>/config.toml`, restoring the canonical pre-layer-on shape. The bench harness invokes this before every trial so layer-off measurements are not contaminated by prior layer-on residue.

**Cross-references.**

- `csq-core/src/coc/translate/codex_merge.rs` — pure data merge.
- `csq/src/cli/commands/run.rs::materialize_handle_config_toml_with_instructions` + `verify_codex_handle_config_toml_is_regular_file` — orchestration.

## 7.3 Per-surface login and setup

### 7.3.1 `Surface::ClaudeCode` (Anthropic)

Unchanged: delegate to `claude auth login` inside `config-<N>/`. See spec 03.

### 7.3.2 `Surface::ClaudeCode` (MM / Z.AI)

Unchanged: API-key capture into `config-<N>/settings.json` under `env.ANTHROPIC_AUTH_TOKEN` + `env.ANTHROPIC_BASE_URL`.

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

Three valid auth paths, each with distinct provisioning. The user picks one when binding the slot:

**Path A — AI Studio API key (today's default):**

1. `mkdir -p config-<N>/.gemini/` and `mkdir -p config-<N>/gemini-state/tmp/`.
2. Write `config-<N>/.gemini/settings.json` pre-seeded:
   ```json
   {
     "security": { "auth": { "selectedType": "gemini-api-key" } },
     "model": { "name": "auto" }
   }
   ```
   The `selectedType` pre-seed is a UX shortcut so gemini-cli's TUI does not interactively prompt for auth choice on first spawn — NOT a ToS-driven defense.
3. Capture API key (AI Studio) via desktop modal or `csq setkey gemini --slot N`.
4. Encrypt at rest in `config-<N>/gemini-key.enc` using the platform-native secret layer. Never plaintext.
5. Probe: `GEMINI_CLI_HOME=config-<N> GEMINI_API_KEY=<key> gemini -p "ping" -m gemini-2.5-flash-lite --output-format json`. Exit 0 → valid.
6. Register account with daemon usage poller (counter mode).

**Path B — Vertex SA (service-account JSON):**

Same as Path A, except the captured artifact is the path to a Vertex AI service-account JSON file. csq sets `GOOGLE_APPLICATION_CREDENTIALS=<sa-json-path>` and `GOOGLE_GENAI_USE_VERTEXAI=true` in the spawn environment. The API key path is not used.

**Path C — Code Assist OAuth subscription:**

PRECONDITION: gemini-cli v0.41.2+ has NO non-interactive auth surface. The `gemini auth login` subcommand was removed; positional args default to interactive mode (`gemini auth login` is parsed as a prompt to the model, not a subcommand). The user MUST therefore run `gemini` once interactively BEFORE provisioning a Code Assist OAuth slot in csq:

```
$ gemini      # opens first-run picker; select "1. Sign in with Google";
              # complete browser flow; quit gemini-cli
```

After this prerequisite, `~/.gemini/oauth_creds.json` exists with shape `{access_token, refresh_token, expiry_date, ...}`. csq's role becomes verify-and-record:

1. Verify `~/.gemini/oauth_creds.json` exists, parses, and has a non-expired `access_token`. csq does NOT extract or copy the tokens — only checks shape + freshness. Implementation: `csq_core::providers::gemini::oauth_login::verify_oauth_creds`.
2. Write the binding marker `credentials/gemini-<N>.json` with `{"v":1,"auth":{"mode":"code_assist_oauth"},"model_name":"auto",...}`. The marker carries no payload — its presence is the signal.
3. `config-<N>/.gemini/settings.json` is created lazily on first `csq run` with `security.auth.selectedType = "oauth-personal"` pinned. gemini-cli sees the pin and uses the existing OAuth creds without showing the first-run picker. The pinning happens in `csq-core/src/providers/gemini/probe.rs::reassert_settings_drift` via `pin_selected_type_for(&AuthMode::CodeAssistOAuth) → Some("oauth-personal")`.
4. No API key is captured. No `gemini-key.enc` is written for Code Assist slots; the vault is not touched. csq never refreshes the OAuth token — gemini-cli + google-auth-library own refresh; on stale `expiry_date`, csq surfaces `GeminiOauthCredsStale` and the user runs `gemini` interactively to refresh.
5. No HTTP probe at provisioning time. The first user-initiated session against the slot is the first auth check; the daemon's first OAuth poll tick (spec 05 §5.8.2 — `cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota`) is the first quota check.
6. Daemon usage poller branch: ApiKey/VertexSa slots stay on the event-driven Counter shape (spec 05 §5.8.1); Code Assist OAuth slots take the Utilization-shape `cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota` poll (implemented per spec 05 §5.8.2).

**Two provisioning entry points for Path C** (both verify-only):

- **Desktop AddAccount modal** — "Code Assist (Sign in with Google)" tab invokes the `gemini_provision_oauth(slot)` Tauri command, which calls `oauth_login::perform` to verify `~/.gemini/oauth_creds.json` + write the binding marker. The modal SHOULD render a banner BEFORE invoking the command instructing the user to run `gemini` interactively first if they have not already done so. Synchronous and fast (no subprocess; no browser wait).
- **CLI** — `csq login N --provider gemini`. Same `oauth_login::perform` path. On `GeminiOauthCredsNotFound`, the error message tells the user exactly what to do: "run `gemini` once interactively, then re-run `csq login N --provider gemini`."

(Every Path C user is "manual" in the sense that they run `gemini` interactively outside csq. The desktop and CLI commands above are the binding-recording verbs.)

**Convention:** `csq login` is the verb for all OAuth (browser-driven) provisioning — Claude Max OAuth (`csq login N`, default), Codex device-auth (`csq login N --provider codex`), and Gemini Code Assist (`csq login N --provider gemini`). `csq setkey` is for non-OAuth credential paths — paste-a-key (Claude direct API, AI Studio, MiniMax/Z.AI/DeepSeek Bearer) or pick-a-file (Vertex SA), plus keyless (Ollama). API-key + Vertex SA Gemini paths stay on `setkey`; OAuth Gemini moves to `login`.

## 7.4 Per-surface quota dispatch

Amends spec 05 — new sections are added there (§5.7 Codex, §5.8 Gemini), this spec fixes the dispatch table.

| Surface      | QuotaKind   | Endpoint                                                  | Refresh invariant                            |
| ------------ | ----------- | --------------------------------------------------------- | -------------------------------------------- |
| `ClaudeCode` | Utilization | `https://api.anthropic.com/api/oauth/usage` (or 3P probe) | Daemon-owned, spec 05 §5.1–5.4 + §5.4a       |
| `Codex`      | Utilization | `https://chatgpt.com/backend-api/wham/usage`              | Daemon-owned, versioned parser, spec 05 §5.7 |
| `Gemini`     | Counter\*   | Client-side counter + 429 `RESOURCE_EXHAUSTED` parse      | Daemon-owned, spec 05 §5.8                   |

\* The catalog `quota_kind` field is `Counter` for ALL Gemini slots, but the actual dispatch is per-binding: ApiKey / VertexSa slots run the event-driven Counter path (spec 05 §5.8.1); Code Assist OAuth slots (Path C in §7.3.4) run the Utilization-shape poller (spec 05 §5.8.2) against `cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota` with per-model `BucketInfo` aggregation. The catalog tag is provisional; the binding's `AuthMode` is the load-bearing dispatcher.

### 7.4.1 `quota.json` schema v2 (FROZEN)

This subsection is the authoritative contract for the quota.json v2 shape. The v2.0.1 dual-read, the v2.1 write-path flip, and the v2.2 Gemini event-driven consumer all implement against this schema. Changes after freeze require a new section with a superseding revision stamp — no silent drift.

The quota schema is a design-once cross-stream contract; it was frozen before either Codex or Gemini code was implemented, and the reader landed in v2.0.1 as shakedown.

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

Shape reconciled with spec 05 §5.8. All fields optional at the `AccountQuota` level; inner struct fields have their own required-ness. Serialization on Option parents: `#[serde(default, skip_serializing_if = "Option::is_none")]`. Readers that encounter these fields on a non-Gemini account MUST NOT error — they simply ignore them.

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

Reserved for surface-specific payload fragments that don't fit the above reserved fields. Never emitted by csq v2.0.1's v1 writer; added so the Codex `wham/usage` parser can stash unmigrated fields without forcing schema v3:

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

| Writer \ Reader    | v1 reader (pre-dual-read)                                                                                                | v2.0.1 dual-read                                                                                                                                                                      | v2 writer                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| v1 file (legacy)   | OK                                                                                                                       | OK (defaults applied)                                                                                                                                                                 | N/A                                                |
| v2 file            | errors on `deny_unknown_fields`; otherwise OK via `#[serde(default)]` (v2.0.0 verified not to set `deny_unknown_fields`) | OK                                                                                                                                                                                    | OK                                                 |
| schema_version > 2 | errors                                                                                                                   | **degrades** to `QuotaFile::empty()` with `WARN error_kind="schema_version_newer"` and `degraded=true` flag; statusline renders "quota: unknown (upgrade csq)" rather than hard-fail. | errors — refuses writing over incompatible version |

The v2.0.1 release is the shakedown ship. It adds v2 READ with all fields optional-tolerant and continues to WRITE v1 schema_version — explicitly forced at the serialization boundary so a v2.0.1 daemon that somehow constructs `schema_version: 2` in memory still writes `schema_version: 1` to disk. The v2.1 release flips the write path.

### 7.4.2 Cross-stream consumer tests

The following regression tests are the contract that the v2.0.1 reader, the v2.1 write flip, and the v2.2 Gemini event-driven consumer all satisfy against this frozen schema:

1. **Parse v1 file unchanged** — legacy file reads exactly as before this spec revision.
2. **Parse v2 file with Claude-only accounts** — migrated v1 with `schema_version=2` and `surface="claude-code"` fields explicit.
3. **Parse v2 file with mixed surfaces** — the §7.4.1 example above parses cleanly.
4. **Parse v2 file missing optional Gemini fields** — null-defaults applied without panic.
5. **Parse v2 file with schema_version=3 degrades not errors** — the reader returns an empty `QuotaFile` + WARN, does not propagate an error to callers. Statusline-facing use case.
6. **Round-trip v2 in-memory → save → load preserves Gemini fields** — the v2.0.1 writer forces `schema_version: 1` on serialization, but nested Gemini fields (`counter`/`rate_limit`/etc.) survive the round-trip via serde defaults. The round-trip is NOT byte-identical at the schema_version level — the test asserts semantic equality of accounts, with the writer's `schema_version=1` forcing documented.
7. **Reject non-numeric account keys** — `load_state` must error on `accounts[key]` where `key.parse::<u16>()` fails.
8. **`extras` field survives round-trip** — a v2 file with an `extras` object containing arbitrary shapes parses, round-trips, and the unknown fragment is preserved byte-for-byte.

These test names are canonical; the v2.0.1 / v2.1 / v2.2 implementations use the same names for traceability.

### 7.4.3 Migration semantics (summarises §7.6.2 below)

On the v2.1 release that flips write path, daemon startup: (a) reads quota.json, (b) if `schema_version` is absent or `1`, stamps every account with `surface="claude-code"`, `kind="utilization"`, sets top-level `schema_version=2`, (c) atomically replaces the file. Idempotent, crash-safe (atomic rename). The v2.0.1 dual-read means a v2.1 daemon starting against a v1 file never encounters a parse error — it simply migrates.

## 7.5 Invariants

**INV-P01: Daemon is the _scheduled pre-expiry_ refresher across refreshable surfaces.**

- For `Surface::Codex`, daemon refresh writes `credentials/codex-<N>.json` under `tokio::sync::Mutex` AT LEAST 2 HOURS before JWT expiry. Handle dirs NEVER hold a copy — only a symlink. Rationale: codex's refresh-token single-use race; copies of auth.json break refresh.
- **Why pre-expiry specifically:** codex's in-process refresh path fires only when the access-token `exp` claim is `<= now()`. There is NO pre-expiry leeway window in codex's own logic. The `cli_auth_credentials_store = "file"` flag does NOT disable in-process refresh; it only selects a write destination. The daemon prevents the in-process path from firing by always keeping tokens fresh enough that codex's threshold is never reached.
- For `Surface::ClaudeCode`, INV-06 (spec 02 / 04) still applies unchanged (2h pre-expiry window).
- For `Surface::Gemini` API-key + Vertex SA paths, there is no refresh — keys are flat and long-lived. For Code Assist OAuth slots, gemini-cli refreshes its own OAuth tokens internally; csq does not interpose.
- **Clock-skew risk:** if local clock drifts > 2h ahead of server, the daemon will miss its refresh window and codex will fire its own refresh. Daemon emits `clock_skew_detected` warning when local time differs from HTTP `Date` header by > 5 min.
- **Contingency:** if codex ever tightens its refresh threshold to pre-expiry (making the scheduled-refresh mitigation unreliable), the recorded response is to interpose via `CODEX_REFRESH_TOKEN_URL_OVERRIDE` pointing at a daemon-local OAuth token-grant endpoint.

**INV-P02: Daemon is a hard prerequisite for refreshable surfaces.**

- `csq run N` for a slot bound to `Surface::Codex` MUST refuse to spawn if the daemon is not running, with an actionable error message. Rationale: INV-P01 depends on the daemon firing pre-expiry; without it, codex WILL hit its on-expiry threshold and refresh in-process, burning the refresh token.
- `Surface::ClaudeCode` with Anthropic OAuth gets the same treatment (existing behavior from spec 04).
- `Surface::ClaudeCode` with MM/Z.AI and `Surface::Gemini` (API-key, Vertex SA, OR Code Assist OAuth) do NOT require the daemon for spawn — flat keys + gemini-cli's own internal OAuth refresh. (For Code Assist OAuth, the daemon DOES poll Google's `cloudcode-pa.googleapis.com/.../retrieveUserQuota` endpoint for quota visibility per spec 05 §5.8.2 — but spawn itself is daemon-independent.)

**INV-P03: Configuration pre-seed is ordered.**

- For `Surface::Codex`, `config-<N>/config.toml` is written BEFORE `codex login` is invoked. Integration test asserts the ordering.
- For `Surface::Gemini` API-key + Vertex SA paths, `config-<N>/.gemini/settings.json` is written BEFORE the first `gemini` spawn so gemini-cli does not interactively prompt for auth choice. For Code Assist OAuth slots, only `model.name` is pre-seeded; `security.auth.selectedType` is pinned to `oauth-personal` on first `csq run`. Integration test asserts the ordering for the API-key + Vertex SA paths.

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

- `error::redact_tokens` MUST match: Anthropic `sk-ant-*`, Codex `sess-*` + JWT pattern, Gemini `AIza*`. Verified by unit tests on the redactor.

**INV-P08: Credential mode-flip is mutex-coordinated.**

- `credentials/codex-<N>.json` (and any other canonical credential file that implements the 0400-outside-refresh pattern) MUST only be mode-flipped under the per-account `tokio::sync::Mutex` also held by the refresher.
- All writers (daemon refresh, `csq login N --provider codex`, re-login after `invalid_grant`) acquire the mutex, flip to `0600`, write (atomic rename), flip back to `0400`, release.
- Daemon startup runs a reconciler that flips any `0600` canonical credential file back to `0400` if no refresh is in progress.

**INV-P09: Per-account refresh mutex lifecycle is tied to slot provisioning.**

- Per-account mutex instances live in `Mutex<HashMap<(Surface, AccountNum), Arc<Mutex<()>>>>` — exposed via `crate::credentials::mutex::AccountMutexTable`.
- `csq login N --provider <surface>` allocates the mutex on first provisioning (via `AccountMutexTable::get_or_insert`).
- `csq logout N` MUST acquire the mutex (serializing any in-progress refresh), delete the credential file, then remove the mutex entry from the table (via `AccountMutexTable::remove`).
- Memory is not leaked across logout/login cycles. Keyed on `(Surface, AccountNum)` prevents slot-9-Codex and slot-9-Anthropic from sharing a lock.
- **Implementation note** — the table ships `std::sync::Mutex` rather than `tokio::sync::Mutex`, and a `Mutex<HashMap<...>>` rather than `DashMap<...>`. Every current consumer (`credentials::file::save_canonical_for`) is synchronous and holds the guard across a bounded atomic rename, not across an `await`. A sync mutex is sufficient and keeps the write path sync; the outer `Mutex<HashMap>` avoids a `dashmap` crate dependency for a map of O(slots × surfaces) ≈ O(20) entries. A future daemon Codex refresher may add an async-safe variant if refresher critical sections grow `.await` points.

**INV-P10: Cross-surface swap cleans up the source handle dir before exec.**

- When `csq swap M` crosses surfaces, csq MUST remove the current (source-surface) handle dir BEFORE `exec`ing the target binary on the new (target-surface) handle dir.
- If removal fails, swap aborts with non-zero exit; the `exec` is not attempted.
- If removal succeeds but `exec` fails (binary not on PATH, permission denied), csq exits non-zero with an actionable error; the user must re-run `csq run M`. The source terminal is already gone; this is deliberate — swap is destructive by its cross-surface nature.

**INV-P11: Auto-rotation refuses cross-surface candidates.**

- The daemon's auto-rotation subsystem (`daemon::auto_rotate`) MUST filter rotation candidates to the same `Surface` as the currently-active terminal.
- When no same-surface candidate is available, auto-rotation surfaces a user-visible notification rather than silently rotating across surfaces (which would require `exec` in place, an action reserved for explicit user `csq swap`).

## 7.6 Migration

### 7.6.1 Refactor existing providers to `Surface::ClaudeCode`

Current `catalog.rs` entries (claude, mm, zai, ollama) gain `surface: Surface::ClaudeCode`. Their `spawn_command` becomes `"claude"`, `home_env_var` becomes `"CLAUDE_CONFIG_DIR"`, `home_subdir` becomes `None`. Their `model_config` becomes `EnvInSettingsJson`. All existing tests must pass unchanged after the refactor.

### 7.6.2 `quota.json` v1→v2

On daemon startup, if `quota.json.schema_version < 2`, rewrite atomically: stamp all records with `surface: "claude-code"`, `kind: "utilization"`, bump schema to 2. Non-destructive — old value + timestamp preserved.

### 7.6.3 Existing handle dirs on upgrade

Pre-upgrade handle dirs have no `surface` marker. Daemon sweep treats them as `ClaudeCode`; they continue to work until the user exits their terminal. No forced migration.

## 7.7 Open preconditions

These are items that MUST be resolved (verified or decided) before the first Codex implementation work lands. They are spec preconditions, not spec content per se — the spec's invariants above assume each of them resolves as expected.

### 7.7.1 OPEN-C01 — Verify `cli_auth_credentials_store = "file"` semantics re: in-process refresh

**Status:** RESOLVED. Finding: the flag does NOT disable in-process refresh; it only selects a storage backend.

**Resolution summary:**

- The `cli_auth_credentials_store` enum only chooses between file, keyring, auto, and ephemeral auth storage. No refresh gating.
- codex's `AuthManager::auth()` unconditionally invokes `refresh_token()` when its proactive-refresh staleness check returns true. Called from every codex HTTP path.
- That staleness check returns true when the JWT `exp <= now()` OR the last refresh is older than 8 days. **No pre-expiry leeway**; codex refreshes ON expiry, not before.
- in-process refresh is serialized by a refresh lock SCOPED TO ONE auth manager (one codex process). Two sibling codex processes have no cross-process coordination → exactly the refresh-token single-use failure mode.
- No `DISABLE_REFRESH` / `NO_REFRESH` / `skip_refresh` escape-hatch env var exists in codex.

**Adopted mitigation:** daemon pre-expiry scheduled refresh with 2h safety margin (INV-P01). Codex's on-expiry threshold is never reached because the daemon refreshes first. Contingency on failure: interpose via `CODEX_REFRESH_TOKEN_URL_OVERRIDE` to point codex's refresh endpoint at a daemon-local proxy.

**Confidence:** HIGH (direct review of Claude Code / codex published behavior).

### 7.7.2 OPEN-C02 — Verify `codex` honors `CODEX_HOME` for sessions/ and history.jsonl

**Status:** RESOLVED POSITIVE. Finding: codex-cli 0.122.0 respects `CODEX_HOME` fully for sessions/rollouts, shell snapshots, logs, installation_id, and plugin tree. Probe: `CODEX_HOME=/tmp/codex-probe codex exec 'say only: hi'` wrote session rollout + shell snapshot + logs exclusively to `/tmp/codex-probe/`; `~/.codex/` received zero files with session_id matching the probe. The kill-switch does NOT fire. §7.2.2 stands without modification.

### 7.7.3 OPEN-C03 — Verify `remove_dir_all` symlink-safety

**Status:** RESOLVED POSITIVE. Finding: `std::fs::remove_dir_all` on modern Rust (post-CVE-2022-21658 fix, Rust 1.58+) unlinks symlinks without traversing them. Empirical probe on macOS 25.3.0 (APFS) confirmed: `fs::remove_dir_all(handle_dir)` with `handle_dir/sessions → sensitive_dir/` symlink leaves `sensitive_dir/sentinel` intact. csq-core's existing `sweep_handles_image_cache_symlink` regression test (`csq-core/src/session/handle_dir.rs`) already covers this invariant for Claude Code's image-cache symlink; the Codex `sessions/` symlink inherits the same guarantee. Codex sweep integration tests are scoped to Codex-specific edge cases (broken symlink, symlink-to-symlink) rather than re-proving the base case.

### 7.7.4 OPEN-C04 — Verify HTTP transport for Codex endpoints

**Status:** RESOLVED — Node transport required. Finding: reqwest/rustls reaches OpenAI's Cloudflare-fronted endpoints without hard-block (all three transports returned 401 with `cf-ray` + `server: cloudflare`) BUT response bodies are stripped for reqwest — `{"error": {}, "status": 401}` instead of curl's full `{"error": {"message": "...", "code": "token_expired", ...}}`. Node fetch preserves the body with minor wording variance vs curl. csq adopts the Node subprocess pattern (same as for Anthropic) for both `/oauth/token` refresh and `chatgpt.com/backend-api/wham/usage` polling.

### 7.7.5 OPEN-C05 — `/oauth/token` error-body token echo

**Status:** RESOLVED NEGATIVELY — no echo observed. Finding: four deliberately-bad refresh-token probes against `auth.openai.com/oauth/token` (three bogus tokens via curl/Node/reqwest + one real-but-burned token) produced error bodies that describe the failure without echoing submitted refresh_token values. Contrast with Anthropic's `/v1/oauth/token` which echoed refresh_token fragments. Structural defense (SecretString module-wide in refresher) downgraded from emergency to best-practice-when-touching-module; the redactor extension proceeds as defense-in-depth for other Codex error surfaces (wham/usage 429s, WebSocket upgrades, SSO callbacks).

## 7.8 What this spec does NOT cover

- The exact `wham/usage` response schema — that lives in spec 05 §5.7 (to be captured on first live observation).
- The exact `RESOURCE_EXHAUSTED` error-body schema for Gemini 429s — spec 05 §5.8.
- CLI argument surfaces (`csq run`, `csq swap`, `csq login`, `csq models switch`) — spec 03.
- Desktop UI component design.

## 7.9 Cross-references

- Spec 01 — CC credential architecture. Still authoritative for `Surface::ClaudeCode`.
- Spec 02 — Handle-dir model. Base invariants hold; §7.2 adds per-surface overlays.
- Spec 04 — Daemon architecture. §7.5 INV-P01, P02 extend the refresh invariants.
- Spec 05 — Quota polling contracts. §7.4 defines the dispatch; §5.7 / §5.8 hold the per-endpoint contracts.
- Spec 09 — Third-party provider polling.

## Revisions

- 1.0.0 — Initial draft, introduced for Codex + Gemini integration. References codex's refresh-token single-use race and gemini-cli's `.env` discovery short-circuit.
- 1.0.1 — Codex surface analysis completed. Added INV-P08 (credential mode-flip mutex coordination), INV-P09 (per-account mutex lifecycle), INV-P10 (cross-surface swap cleanup), INV-P11 (auto-rotation refuses cross-surface). Added §7.7 Open preconditions OPEN-C01..C04 as gating verifications.
- 1.0.2 — OPEN-C01 RESOLVED. Finding: `cli_auth_credentials_store = "file"` does NOT disable in-process refresh; codex refreshes on-expiry regardless. INV-P01 re-framed to "scheduled pre-expiry refresher" with 2h safety margin. Clock-skew mitigation added. Gemini analysis completed — no spec 07 changes required; Gemini inherits the abstraction unchanged.
- 1.1.0 — §7.4 expanded with frozen quota.json v2 schema subsection 7.4.1 (mandatory + optional fields, example mixed-surface file, compatibility matrix), §7.4.2 cross-stream consumer test names, §7.4.3 migration semantics summary. Minor bump because schema is a cross-stream contract.
- 1.1.1 — Schema reconciliation. Shape of §7.4.1 Gemini counter fields reconciled with spec 05 §5.8 — `counter` and `rate_limit` promoted from flat scalars to nested structs (`CounterState` / `RateLimitState`). `effective_model_first_seen_at` added at AccountQuota level. `extras: Option<Value>` escape-hatch field added. `schema_version > 2` handling changed from hard-error to degrade-to-empty + WARN for rollback UX. §7.4.2 test list expanded from 6 to 8 canonical tests.
- 1.2.0 — §7.2.3.1 "Event-delivery contract" added. Pins socket-path resolution, 50 ms non-blocking connect ceiling, drop-on-unavailable semantics with fixed-vocabulary structured log, NDJSON-as-durability-floor invariant, and the emitter-MUST-NOT-block rules.
- 1.2.1 — §7.7.2 OPEN-C02, §7.7.3 OPEN-C03 flipped to RESOLVED POSITIVE. §7.7.4 OPEN-C04 flipped to RESOLVED (Node transport required). New §7.7.5 OPEN-C05 RESOLVED NEGATIVELY. Kill-switch does NOT fire (OPEN-C02 positive).
- 1.3.0 — gemini-cli v0.41.2 auth-subcommand regression. §7.2.3.2 Code Assist OAuth slots now PIN `selectedType=oauth-personal` (was: leave unset). §7.3.4 Path C rewritten — csq no longer shells out to `gemini auth login` (subcommand removed in v0.41.2); operator runs `gemini` interactively first, csq verifies `~/.gemini/oauth_creds.json` shape + freshness and writes the binding marker. Three-entry-points block collapsed to two (Desktop + CLI). Added `GeminiOauthCredsUnreadable` variant to distinguish I/O permission errors from JSON malformation.
- 1.4.0 — Gemini `by_slot_identity` writer. §7.2.3 gains the "FM — Gemini `by_slot_identity` label stability" note: the channel now carries `gemini-<N>/{apikey,vertex,codeassist}` (mode-class derived from the binding marker's `AuthMode` via the shared `gemini_identity_label`), written synchronously by all 3 `provision_*` paths (marker-FIRST/identity-LAST) + the daemon backfill arm. Stability contract is the INVERSE of §7.2.2 FM-6 (Codex): Gemini is class-stable AND value-stable-within-a-mode; a value change signals a legitimate operator mode re-provision, not re-auth ambiguity. Forward-compat: binding-schema bumps must coordinate the `by_slot_identity` backfill.
- 1.5.0 — Spec-accuracy wave: §7.2.3.1 socket-path helper citation corrected to `csq_core::daemon::paths::socket_path(base_dir)` (daemon/paths.rs). §7.2.3.2 bench-reset citation corrected to the shipped inline removal at `csq/src/cli/commands/login.rs::reset_handle_dir_gemini`. All `csq-cli/src/commands/` paths migrated to `csq/src/cli/commands/` (crate merge). No contract change.
- 1.5.1 — Split-state purge: INV-P01 contingency bullet rewritten present-state — the interposition design is recorded as a conditional contingency, not a tracked follow-up. No shipped behavior changed.
