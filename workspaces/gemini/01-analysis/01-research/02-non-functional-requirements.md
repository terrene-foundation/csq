# 02 — Gemini Surface: Non-Functional Requirements

Phase: /analyze | Date: 2026-04-22

Performance, reliability, security, compatibility, observability, and maintainability constraints for the Gemini surface. Partners with 01-functional-requirements.md.

## NFR-G01 — Cold-start performance

- `csq run <gemini-slot>` from invocation to `gemini` prompt MUST be < 600ms on M-series macOS (p99). Gemini is lighter than Codex (no daemon prerequisite check, no config.toml materialize); budget is tighter.
- Hard budget breakdown:
  - Handle-dir create + symlink set: < 50ms
  - Settings drift reassert (read + optional rewrite): < 20ms
  - Key decrypt (platform-secret roundtrip): < 100ms (cold) / near-zero (cached in-process during that spawn)
  - Gemini binary `exec`: < 100ms
- **Prohibited on this path:** network calls, live-fetch model list, billing API probe.
- Test: integration bench that spawns a Gemini handle dir 100× and asserts p99.

## NFR-G02 — No refresh cadence (surface distinction)

- Gemini uses flat API keys; no refresh cadence applies. Daemon does NOT poll Gemini for token rotation.
- If a user revokes the AI Studio key in Google's console, csq's only signal is spawn failure (F1). NFR: first failed spawn after revocation MUST emit `error_kind = "gemini_api_key_invalid"` within 2 seconds.

## NFR-G03 — Quota cadence

- Counter mode: no poll cadence; increments on spawn. Daemon IPC receives `gemini_counter_increment { slot, ts }` from csq-cli on each spawn; writes to `quota.json` under per-slot lock.
- 429 parser: daemon consumes stderr-forwarded `gemini_429` events from csq-cli; writes `rate_limit_reset_at` + `last_retryDelay_seconds`.
- Effective-model capture: same channel; first response's `modelVersion` recorded; debounced flapping (3 mismatches in 5 min → latch).
- Schema-drift circuit breaker: 5 consecutive `gemini_quota_schema_drift` events → UI flips to "quota: unknown" + persists raw body to `accounts/gemini-429-drift.json` (cap 64 KB, redacted).

## NFR-G04 — Security

- **No plaintext API key on disk.** `config-<N>/gemini-key.enc` is encrypted via platform secret (Keychain / libsecret / DPAPI). Mode `0o600`.
- **No API key in IPC events.** Event payloads to renderer carry derived fields only (counter, reset_at, effective_model).
- **No API key in process env of anything except `gemini`'s direct child.** `Command::env` explicitly sets `GEMINI_API_KEY`; child cannot re-export. Subprocess env allowlist: `PATH`, `HOME`, `USER`, `LANG`, `TERM`, `GEMINI_CLI_HOME`, `GEMINI_API_KEY`, `HTTPS_PROXY`. Everything else stripped via `Command::env_clear()` + explicit allowlist.
- **No API key in logs.** `error::redact_tokens` extended with `AIza[0-9A-Za-z_-]{35}` pattern + Vertex PEM block + `client_email` conditional. Unit test: a sample Gemini error body with `AIza…` is redacted before any `tracing::warn!` call.
- **ToS guard enforcement at every spawn** — EP1 (drift detector) + EP3 (env sanitation) + EP6 (refuse if `oauth_creds.json` in chain) run before every `exec gemini`. Adds ~10-15ms to spawn budget; accounted for in NFR-G01.
- **Response-body sentinel** — csq-cli wraps gemini's stderr and scans for OAuth-flow markers (`Opening browser`, `oauth2.googleapis.com`). Match → kill child + `error_kind = "gemini_tos_guard_tripped"`.

## NFR-G05 — Reliability

- **Single-writer for counter + effective-model:** daemon IPC is the only quota.json writer. When daemon is down, csq-cli emits a toast "quota not tracked (start daemon for live counter)" but proceeds with spawn. No fake data.
- **Settings drift self-healing:** every spawn re-asserts `security.auth.selectedType = "gemini-api-key"`; any drift is corrected + logged. No cumulative drift risk.
- **Key-decrypt failure recovery:** if `gemini-key.enc` fails to decrypt (platform secret unavailable, file corruption), csq refuses to spawn + surfaces `csq setkey gemini --slot N --re-enter` guidance.
- **429 graceful degradation:** parser failure → raw body logged + UI shows "quota signal degraded (see ~/.claude/accounts/gemini-429-drift.json)".

## NFR-G06 — Observability

- Structured events via tracing subscriber:
  - `gemini_setkey_captured`, `gemini_setkey_validated`, `gemini_setkey_failed { error_kind }`
  - `gemini_spawn_attempted`, `gemini_spawn_succeeded`, `gemini_spawn_failed { error_kind }`
  - `gemini_counter_increment { slot, ts }`
  - `gemini_effective_model_observed { selected, effective, is_downgrade }`
  - `gemini_rate_limited { slot, retry_delay_s, quota_metric }`
  - `gemini_settings_drift { slot, old_auth_type, new_auth_type }` — fires when drift detector corrects
  - `gemini_tos_guard_tripped { slot, trigger }` — fires when response-body sentinel kills child
- `error_kind_tag` enum extended with Gemini-specific values: `api_key_invalid`, `vertex_sa_path_missing`, `gemini_quota_schema_drift`, `gemini_preview_downgrade`, `gemini_settings_drift`, `gemini_tos_guard_tripped`.

## NFR-G07 — Compatibility

- **gemini-cli minimum version:** pinned in `providers/gemini/mod.rs`; refused below. Probed at `csq setkey` time.
- **Platform:** macOS + Linux at ship. Windows deferred (ADR-G11).
- **Gemini model list:** static per-release; bumped via csq release cadence (ADR-G08).
- **quota.json v2:** shared schema with Codex and Anthropic; Gemini-specific fields (`counter`, `reset_at`, `selected_model`, `effective_model`) tolerated as absent on mixed-install reads.

## NFR-G08 — Maintainability

- **`Command::new("gemini")` ban:** only `providers::gemini::spawn_gemini(handle_dir, key)` instantiates the child. Grep-based CI check enforces single call site.
- **Surface exhaustiveness:** all `match Surface { ClaudeCode => ..., Codex => ..., Gemini => ... }` handle every variant.
- **Test floor:** PR-G1 through PR-G5 each add ≥1 integration test from the 7-test load-bearing list in 04-risk-analysis §3.
- **Spec 07 is source of truth** — any deviation during implementation updates spec 07 in the same commit.

## NFR-G09 — Error recovery

- **Invalid key mid-session:** spawn fails fast; UI surfaces `re-enter key` action that opens `csq setkey` flow.
- **Vertex path missing:** spawn probes `GOOGLE_APPLICATION_CREDENTIALS` before exec; if absent/unreadable, refuse with `vertex_sa_path_missing` + actionable message.
- **gemini-cli version too old:** refuse with pinned-version message at `csq setkey`.
- **OAuth residue detected post-install** (user flipped settings or added oauth_creds.json later): drift detector rewrites settings.json; oauth_creds.json is not touched but spawn proceeds. Next `csq run` re-asserts.

## NFR-G10 — Observational budget

- No steady-state polling for Gemini (no quota endpoint). Only event-driven writes from csq-cli → daemon on spawn + 429 + model observation.
- Typical: 10 Gemini accounts × 3 spawns/day average = 30 events/day. Negligible.

## NFR-G11 — Documentation

- User-facing: release notes cover API-key-only design, ToS posture (NO OAuth rerouting), the drift detector, and downgrade surfacing.
- In-product: first-run Gemini modal shows Google ToS language verbatim.
- Developer-facing: spec 07 + workspaces/gemini/01-analysis artifacts.

## Cross-references

- FR: `01-functional-requirements.md`
- ADRs: `03-architecture-decision-records.md`
- Risk: `04-risk-analysis.md`
- Security: `07-security-analysis.md`
- Spec 07
