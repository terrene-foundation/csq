# 08 — csq Internals Map for Gemini Integration (Diff vs Codex)

Phase: /analyze | Date: 2026-04-22

Gemini lands AFTER Codex and inherits the surface-dispatch infrastructure Codex introduces. This document is a **delta** against `workspaces/codex/01-analysis/01-research/08-csq-internals-map.md` — read that first, then this one.

## What Gemini reuses from Codex's surface plumbing (no additional touch)

- `Surface` enum (Codex PR1 adds `Gemini` as the third variant alongside `ClaudeCode` and `Codex`).
- `Provider` struct extensions (`spawn_command`, `home_env_var`, `home_subdir`, `model_config`, `quota_kind`).
- Handle-dir surface-dispatched create/sweep path.
- Cross-surface `csq swap` exec-in-place (INV-P05).
- `quota.json` v2 schema with `surface` + `kind` tags + migration.
- Token redaction pattern extension.
- Error kind tag enum extension.
- Surface dispatch in discovery, refresher filter, usage poller, auto-rotate.
- Daemon-as-sole-writer for quota.json — reused for Gemini's counter.

## What Gemini adds (new touch points)

### 1. New module: `csq-core/src/providers/gemini/`

- `mod.rs` — surface catalog entry, spawn helper
- `keyfile.rs` — `GeminiKeyFile { enc_blob: Vec<u8>, kind: AIStudio | Vertex { path: PathBuf } }` + encrypt/decrypt via `platform::secret`
- `settings.rs` — pre-seed + drift-detector (reassert `security.auth.selectedType = "gemini-api-key"` on every spawn)
- `probe.rs` — `gemini -p "ping" -m gemini-2.5-flash-lite --output-format json` validation probe

### 2. New module: `csq-core/src/platform/secret/`

Abstraction over platform-native secret storage used for Gemini `gemini-key.enc`:

- `macos.rs` — Keychain via security-framework
- `linux.rs` — libsecret
- `windows.rs` — DPAPI (stubbed; Windows deferred per ADR-G11)

Codex may benefit from this same abstraction for `com.openai.codex` keychain probe (ADR-C11). Recommend landing `platform::secret` in Codex PR2 and Gemini reuses.

### 3. New module: `csq-core/src/daemon/usage_poller/gemini.rs`

Event-driven, not polling. Listens on IPC for:

- `gemini_counter_increment { slot, ts }` — writes `quota.json[N].counter += 1`
- `gemini_rate_limited { slot, retry_delay_s, quota_metric }` — writes `quota.json[N].rate_limit_reset_at`
- `gemini_effective_model_observed { slot, selected, effective, is_downgrade }` — writes `quota.json[N].effective_model` + badge state

Resets counter at midnight America/Los_Angeles daily via a scheduled task (tokio `sleep_until`).

### 4. New CLI command: `csq setkey gemini --slot <N>`

Extends `csq-cli/src/commands/setkey.rs` (currently handles MiniMax/Z.AI bearer keys) with a Gemini branch:

- Detect key shape (`AIza...` → AI Studio; JSON with `type: "service_account"` → Vertex; else refuse)
- Call `providers::gemini::seed_settings_json(N)` BEFORE any spawn
- Call `providers::gemini::encrypt_and_store(N, key)` via `platform::secret`
- Call `providers::gemini::probe(N)` for validation
- Register with daemon via IPC

### 5. New desktop UI components

- AddAccountModal.svelte — Gemini card with AI Studio / Vertex tabs, ToS disclosure modal
- ChangeModelModal.svelte — Gemini static model list + preview warning
- AccountCard — downgrade badge, "quota: n/a" rendering rules

Codex established the pattern; Gemini extends without new infrastructure.

### 6. New spawn helper: `csq-core/src/providers/gemini/spawn.rs`

`spawn_gemini(handle_dir: &Path, key: &str) -> Result<Child>` — the ONLY call site that instantiates `Command::new("gemini")`. Enforces:

- `env_clear()`
- Allowlist: `PATH`, `HOME`, `USER`, `LANG`, `TERM`, `GEMINI_CLI_HOME`, `GEMINI_API_KEY`, `HTTPS_PROXY`
- Drift detector invocation before exec
- Response-body sentinel via stderr wrapper

CI-enforced grep: `Command::new("gemini")` anywhere else is a build error.

### 7. New IPC message types

- `Request::GeminiCounterIncrement { slot: AccountNum, ts: u64 }`
- `Request::GeminiRateLimited { slot: AccountNum, retry_delay_s: u32, quota_metric: String }`
- `Request::GeminiEffectiveModel { slot: AccountNum, selected: String, effective: String }`
- `Request::GeminiSettingsDrift { slot: AccountNum, old: String, new: String }`
- `Request::GeminiTosGuardTripped { slot: AccountNum, trigger: String }`

Daemon handler writes to `quota.json` under per-slot mutex. csq-cli emits these during/after each gemini spawn.

## What Gemini does NOT touch (but Codex does)

- `credentials/` canonical credential dir — Gemini has no OAuth, no refresh. `gemini-key.enc` lives in `config-<N>/`, not in `credentials/`.
- Daemon refresher — Gemini accounts are skipped entirely (load-bearing regression test).
- 0400/0600 mode-flip reconciler (INV-P08) — does NOT apply to `gemini-key.enc`; must explicitly exclude.
- Per-account refresh mutex DashMap — Gemini does not allocate entries.
- `credentials/file.rs` `live_path` parameterization — Gemini has its own path helper, not this one.

## Regression risk specific to Gemini

Codex's PR1 makes every surface-dispatched site handle Codex. Gemini's PR-G1 must verify each site ALSO correctly handles `Surface::Gemini`:

- **refresher.rs:305 filter** — skip Gemini accounts (no refresh).
- **auto_rotate.rs:331** — Gemini candidates are ONLY paired with other Gemini (INV-P11).
- **error_kind_tag enum** — extend with Gemini variants; no catch-all that swallows.
- **redact_tokens** — AIza* + Vertex PEM patterns live alongside sess-* and sk-ant-\*.
- **handle_dir.rs ACCOUNT_BOUND_ITEMS** — Gemini set is distinct.
- **quota.json schema reader** — tolerate Gemini-specific fields as absent on mixed installs.

## Implementation sequencing (Gemini-specific)

| Phase | What                                                                                           | Touches                      | Depends on       |
| ----- | ---------------------------------------------------------------------------------------------- | ---------------------------- | ---------------- |
| PR-G1 | `Surface::Gemini` variant + catalog entry + all surface-dispatched sites extended              | ~5 files                     | Codex PR1 landed |
| PR-G2 | `platform::secret` abstraction + `providers::gemini` keyfile + settings + probe + spawn helper | ~6 new files                 | PR-G1            |
| PR-G3 | `daemon::usage_poller::gemini` event-driven writer + IPC messages                              | 2-3 files                    | PR-G2            |
| PR-G4 | csq-cli `setkey gemini` + drift detector + stderr sentinel                                     | 2 files                      | PR-G3            |
| PR-G5 | Desktop UI (AddAccountModal + ChangeModelModal + AccountCard)                                  | ~4 Svelte + 3 Tauri commands | PR-G3            |

Total: 5 PRs. ~12–15 new files, ~6–8 modifications to existing Codex-refactored code.

## Summary

Gemini is significantly lighter than Codex because:

- No OAuth → no refresh subsystem extension
- No token race → no mutex dance
- No wham/usage schema uncertainty → no parser versioning drama
- No keychain escalation class (the keychain is the INTENDED defense, not a hazard)

Gemini's novelty is event-driven quota (counter + 429 + effective-model) and the ToS-guard defense layer (drift detector + response-body sentinel). Both are bounded additions on top of Codex's infrastructure.
