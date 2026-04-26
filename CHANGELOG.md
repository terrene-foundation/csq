# Changelog

All notable changes to csq are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbering follows [Semantic Versioning](https://semver.org/).

## [2.3.0] — 2026-04-26

Gemini as a first-class third surface alongside ClaudeCode and Codex: API-key provisioning (AI Studio paste or Vertex SA JSON path) under `platform::secret` encryption-at-rest, in-flight `csq swap` between Gemini slots, cross-surface swap with the existing v2.1.0 confirm + tombstone path, `csq run` that does not require a running daemon (a deliberate inversion of v2.1.0's INV-P02 for Codex), event-driven quota via a CLI-durable NDJSON event log, a 7-layer Terms-of-Service defense (EP1–EP7) pinned to gemini-cli 0.38.x, and a desktop UI mirroring the ClaudeCode and Codex flows. No schema migration; quota.json stays at v2.

See `docs/releases/v2.3.0.md` for the full release notes.

### Added

- `Surface::Gemini` variant + dispatch wiring across `discovery`, `auto_rotate`, `rotation::swap_to`, `daemon::refresher`, `usage_poller`. Surface dispatch architecture from v2.1.0 extends to a third variant.
- `csq_core::platform::secret` — encryption-at-rest primitive with five backends: `macos.rs` (Keychain via `security-framework`), `linux.rs` (Secret Service with AES-GCM file fallback), `windows.rs` (DPAPI + Credential Manager), `file.rs` (AES-GCM-only fallback for headless / CI / WSL-no-keyring environments), `in_memory.rs` (test-only). All five implement the same `SecretStore` trait; `audit.rs` carries the security-reviewer sign-off ledger.
- `csq_core::providers::gemini` — full Gemini surface module: `provisioning.rs` (vault wiring + model orchestration), `spawn.rs` (`spawn_gemini` with EP2/EP3 pre-spawn guards), `tos_guard.rs` (EP4 stderr sentinel pinned to gemini-cli 0.38.x), `tos.rs` (per-slot ToS marker mirror of `codex/tos.rs`), `capture.rs` (NDJSON emitter with `O_APPEND` + `fsync`), `event_id.rs` (envelope ID minting), `keyfile.rs` (canonical path for at-rest secret artifacts).
- `csq setkey gemini <slot> --from-stdin` — CLI provisioning. API key piped on stdin; never reaches argv; redacted by `error::redact_tokens` (now learns `AIza*` prefix).
- `csq run` — Gemini surface dispatch via `discovery::discover_all`. Does not require a running daemon for Gemini slots (ADR-G09, INV-P02 inverted).
- `csq swap` — cross-surface routing for Gemini slots; same-surface Gemini→Gemini repoints atomically; cross-surface follows v2.1.0 INV-P05 confirm + INV-P10 rename-source-to-tombstone + `exec`.
- `csq models switch` — Gemini dispatch via `discover_all`; static catalog with 4 entries (`gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash-exp`, `gemini-1.5-pro`).
- `accounts/gemini-events-<N>.ndjson` — per-slot event log, 0o600, gitignored, drained by daemon. Spec 07 §7.2.3.1 freezes the event-delivery contract: 50 ms non-blocking connect ceiling, drop-on-unavailable semantics, NDJSON-as-durability-floor invariant.
- Daemon NDJSON consumer + live IPC route — drains every `gemini-events-<N>.ndjson` on startup and on each tick; advances `quota.json`; rotates corrupt logs to `gemini-events-<N>.corrupt.<unix_ms>` and starts fresh.
- Desktop UI (PR-G5): AddAccountModal Gemini tab with two sub-tabs (AI Studio key paste / Vertex SA JSON file picker), ToS disclosure modal, inline OAuth-residue warning panel; ChangeModelModal static Gemini list with preview-tier downgrade warning; AccountCard surface badge + downgrade chip + "quota: n/a" rendering.
- Six new Tauri commands: `is_gemini_tos_acknowledged`, `acknowledge_gemini_tos`, `gemini_probe_tos_residue`, `gemini_provision_api_key`, `gemini_provision_vertex_sa`, `gemini_switch_model`.

### Changed

- `error::redact_tokens` learns the `AIza*` prefix (Google API keys) alongside the existing `sk-ant-*` and long-hex coverage. Applied at every Gemini-adjacent error format site.
- `dialog:allow-open` permission grant added to `csq-desktop/src-tauri/capabilities/default.json` (narrow, replaces no `:default` 3P plugin grants — capability audit per `rules/tauri-commands.md`).

### Deferred

- **D7 — vault-delete-on-unbind from desktop** (journal 0011 §FD #1, restated in 0013). CLI `csq logout` calls `vault.delete`; desktop "remove Gemini account" flow does not yet. Follow-up PR.
- **csq-cli orchestration cleanup** (journal 0013). `setkey.rs::handle_gemini` and `models.rs::write_gemini_model_to_binding` carry ~30 LOC of contained duplication that collapses to single-source via `csq-core` helpers.
- **`launch_gemini` / `exec_gemini` factoring** (journal 0012 §D4). 2 callers today; threshold is 3. Re-evaluate at v2.4 if a third caller appears.

---

## [2.2.0] — 2026-04-25

Minor release on v2.1.1. Two backwards-compatible onboarding improvements reported against fresh WSL installs: `csq status` now shows every configured surface (was Anthropic-only), and `csq install` + `csq run` pre-emptively detect the two failure modes behind `SessionStart:startup hook error` / `node:internal/modules/cjs/loader:1143`.

See `docs/releases/v2.2.0.md` for the full release notes.

### Added

- `csq_core::platform::env_check` — hook-environment preflight module. `run_preflight(claude_home, cwd)` parses both global and project `settings.json` hook blocks, resolves every hook command's script path (with `$CLAUDE_PROJECT_DIR` / `~` expansion), verifies existence, and for `.js` scripts also resolves every `require("./relative")` target against node's standard extension set (`.js`, `.cjs`, `.mjs`, `.json`, `index.js`). Emits `EnvIssue::NodeMissingForHooks`, `::HookScriptMissing`, or `::HookRelativeRequireMissing` with full path context. `detect_linux_flavor()` classifies WSL / Debian / RedHat / Arch / Other from `/proc/version` + `/etc/os-release`; `node_install_hint()` returns the right package-manager one-liner per platform.
- `csq install` runs the preflight after settings patching. On Linux flavors where csq knows the install command, prompts `[y/N]` before running `sudo apt` / `dnf` / `pacman`. macOS / Windows / unknown flavors print the hint only.
- `csq run` runs the same preflight at the top of `handle()`, stderr-only and non-blocking — mid-session launches are never stranded.
- `AccountStatus` gains `source: AccountSource` and `surface: Surface` fields (both with `#[serde(default)]`) so third-party and Codex rows carry enough context for surface-aware rendering.
- README Troubleshooting entry for the `loader:1143` error string with per-platform fix commands.

### Changed

- `csq-core::quota::status::show_status` now calls `discovery::discover_all` instead of `discover_anthropic`. The daemon's `GET /api/accounts` (via `cached_discovery` in `daemon::server`) makes the same switch, so the daemon-delegated path and the direct path both enumerate every configured surface. Previously both were Anthropic-only.
- `AccountStatus::format_line` renders a surface tag after the label — `[codex]` for Codex OAuth rows, `[<provider>]` for third-party rows (e.g. `[minimax]`, `[zai]`, `[ollama]`), `[manual]` for manually configured rows. Anthropic OAuth rows render an empty tag so existing `csq status` output is byte-identical for Anthropic-only setups.
- `AccountStatus::format_line` skips the `5h:— / 7d:—` quota suffix for surfaces csq does not poll (third-party + manual) and renders `(api-key)` instead, so "no polling" is distinguishable from "no data yet".

---

## [2.1.1] — 2026-04-24

Patch release on v2.1.0 closing two on-disk-artifact migration gaps reported the day after the v2.1.0 cut. No new features, no schema changes, no behavior change for fresh installs.

See `docs/releases/v2.1.1.md` for the full release notes.

### Fixed

- **#184** — daemon-startup migration to strip legacy `apiKeyHelper` from 3P settings written by pre-alpha.8 csq. The field was the provider's `system_primer` string serialized into a key CC interprets as a shell command; affected slots emitted `apiKeyHelper failed: exited 127` plus an auth-conflict warning on every CC launch. The write paths were hardened in alpha.8 but on-disk artifacts on upgraded machines were never cleaned up. New `pass4` in the daemon's startup reconciler walks `<base_dir>/config-<N>/settings.json` and `<base_dir>/settings-*.json` and strips `apiKeyHelper` only when both `apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN` are present (the unambiguous legacy-bug signature; user-authored helper scripts alone are preserved). Atomic + 0o600 + idempotent + mtime-preserving on no-op.
- **#185** — `csq install` now walks per-terminal handle dirs at `~/.claude/accounts/term-*/settings.json` alongside the existing `config-<N>/settings.json` walk. Pre-install terminals carrying the stale `bash ~/.claude/accounts/statusline-quota.sh` wrapper no longer silently lose their statusline when `cleanup_v1_artifacts` renames the wrapper to `.bak`. Install summary line now reports both per-slot and per-handle migrations on separate lines.

### Changed

- `ReconcileSummary` gains two counter fields (`api_key_helper_files_seen`, `api_key_helper_files_migrated`) for telemetry / `csq doctor`.
- `csq install` extracts the per-file statusline-strip work into a shared `strip_legacy_statusline_from_file` helper used by both `migrate_per_slot_statuslines` and the new `migrate_handle_dir_statuslines`.

---

## [2.1.0] — 2026-04-23

Codex as a first-class second surface alongside ClaudeCode: device-auth login, central token refresh, live `wham/usage` polling, in-flight `csq swap` between Codex slots, cross-surface swap with confirm-prompt + clean handover, and a desktop UI with Terms-of-Service disclosure. Quota schema writer flips v1 → v2; v2.0.1 dual-read keeps downgrade compatible.

See `docs/releases/v2.1.0.md` for the full release notes including the surface dispatch architecture, two redteam convergence rounds, the M10 same-surface Codex repoint decision, the M-CDX-1 ordering invariant, the Windows caveat carry-over, and migration & compatibility notes.

### Added

- Codex surface across `discovery`, `auto_rotate`, `rotation::swap_to`, `daemon::refresher`, and `usage_poller`. `Surface::ClaudeCode` and `Surface::Codex` enums replace the prior implicit Anthropic-only assumption.
- `csq login N --provider codex` CLI flow + desktop AddAccountModal Codex panels (codex-tos, codex-keychain-prompt, codex-running, codex-picker in ChangeModelModal). Five new Tauri commands: `start_codex_login`, `complete_codex_login`, `list_codex_models`, `acknowledge_codex_tos`, `set_codex_slot_model`. Plus `cancel_codex_login` from the round-1 hardening.
- Daemon Codex refresher (`broker_codex_check` + `HttpPostFnCodex`), surface-dispatched `tick`, startup reconciler (INV-P08 mode flip + INV-P03 config.toml drift), Windows H2 gate (`require_daemon_healthy` cross-platform + named-pipe surface-dispatch integration test).
- `usage_poller/codex.rs` parses live `wham/usage` per journal 0010 schema (5h primary + 7d secondary rate-limit windows; `used_percent` is 0–100). Circuit breaker 5-fail → 15min → 80min cap. Raw-body capture to `accounts/codex-wham-raw.json` (0600, redactor-first). STABLE per journal 0010 capture.
- `quota.json` schema_version 2 writer (PR-C6). Nested `CounterState` / `RateLimitState` per spec 07 §7.4.1 + `extras: Option<serde_json::Value>` escape hatch. Idempotent v1 → v2 migration on first daemon tick.
- `csq swap` cross-surface dispatch (PR-C7). INV-P05 confirm prompt (`--yes` bypasses), INV-P10 rename-source-to-tombstone, then `exec` the target binary. Same-surface Codex routes to the new in-flight `repoint_handle_dir_codex` (M10).
- `csq models switch <slot> <model>` Codex dispatch — Codex slots route to a `TomlModelKey` writer that updates `config.toml`.
- New `csq-core/src/platform/test_env.rs` shared cross-module mutex for env-var-mutating tests.
- Surface badge in AccountList per slot.
- `repoint_handle_dir_codex` for in-flight same-surface Codex swap (M10 / journal 0023). codex-cli re-stats `auth.json` before each API call so the next request authenticates as the new slot; UNIX open-after-rename keeps in-flight session fds valid until close.
- `RouteKind` + `route()` pure dispatcher helper in `csq-cli/src/commands/swap.rs` with three-way matrix unit tests (L-CDX-3, journal 0024).

### Changed

- Auto-rotate is **ClaudeCode-only by design** in v2.1 (CRITICAL fix in journal 0021). `find_target` short-circuits when the current account's surface is not ClaudeCode; `repoint_handle_dir` adds a belt-and-suspenders refusal for Codex-shape handle dirs.
- IPC payload audit flipped from blacklist to per-struct **whitelist** via `assert_ipc_keys_whitelisted` helper (round 1).
- `app.emit` for `codex-device-code` narrowed to `app.emit_to("main", ...)` so the device code does not broadcast to every window.
- `csq swap` cross-surface path uses atomic `rename` to a `.sweep-tombstone-swap-<pid>-<nanos>` sibling instead of `remove_dir_all`, closing the Ctrl-C signal-window race and preserving open fds for the running surface process.
- `repoint_handle_dir_codex` `codex_links` slice rewrites credential (`auth.json`) BEFORE marker (`.csq-account`) so a mid-loop rename failure cannot leave the marker pointing at slot N+1 while the credential still resolves to slot N (M-CDX-1 / journal 0024).

### Fixed

- `is_device_code_shape` narrowed to exactly `XXXX-XXXX` (8 alphanumerics + mandatory middle dash); regression tests pin acceptance and rejection patterns.
- `acknowledgeCodexTos` recursion guard via `tosRetry` parameter — second `tos_required` returns a user-facing error instead of looping.
- `complete_codex_login` outer `.map_err` re-redacts via `redact_tokens` so the full anyhow chain is sanitized at the IPC boundary.
- Keychain purge errors wrapped in `redact_tokens` before formatting.
- Raw-auth-json wipe uses a fixed 64 KiB zero buffer + `O_WRONLY|O_TRUNC` + `sync_all`; retries `remove_file` after zero-write.
- `/api/invalidate-cache` HTTP POST wrapped in 500ms `recv_timeout` so a hung daemon cannot block the calling `spawn_blocking` thread indefinitely.
- `mpsc::channel(unbounded)` in the codex device-auth piped reader converted to `sync_channel(4)` with `try_send` so banner repetition cannot fill memory; forwarder drains all codes but only fires `on_code` for the first.
- `tos::is_acknowledged` distinguishes `NotFound` (silent) from other `io::Error` kinds (logged at WARN with named error_kind tags).
- `complete_login_scrubs_written_auth_json_when_canonical_save_fails` regression — extracted `scrub_and_remove_written` helper called from BOTH success cleanup AND `save_canonical_for` error branch.
- `set_codex_slot_model` consults `discover_all` and refuses non-Codex slots with a named error.
- Codex surface guard in `repoint_handle_dir_codex` requires BOTH `auth.json` AND `config.toml` AND each must be a symlink (L-CDX-1 / journal 0024).
- `csq swap` Codex→Codex no longer silently `exec`-replaces the running codex process (M10 / journal 0023). Prior behaviour dropped the user's conversation with no warning.

### Platform notes

- **Windows.** Codex on Windows is **not supported** in v2.1 — Codex slots require a running daemon (INV-P02), and the daemon supervisor still short-circuits per v2.0.1's PR-VP-C1a (the `windows-daemon` Cargo feature is default-off pending PR-VP-C1b). Same-surface Codex swap on Windows is also untested per L-CDX-2 (the `repoint_handle_dir_codex` regression tests are all `#[cfg(unix)]`, matching the existing ClaudeCode `repoint_handle_dir` path's status). Both repoint paths will be audited together when the Windows port workstream lands.
- **macOS / Linux.** Full Codex support; carries over the v2.0.1 macOS ad-hoc signature and Linux daemon socket layout.

### Deferred to v2.1.x or v2.2

- PR-VP-C1b — Windows daemon flag flip.
- L-CDX-2 — same-surface Codex swap on Windows behaviour audit (paired with the Windows port).
- `RepointStrategy` trait extraction — re-evaluate at N=3 surfaces.
- IPC whitelist proc-macro — re-evaluate if a second IPC slip materializes past the unit-test harness.

---

## [2.0.1] — 2026-04-22

Safety patch on v2.0.0. One CRITICAL credential-handling risk fixed (auto-rotation routing Anthropic OAuth tokens through 3P endpoints under a narrow but reachable mix of OAuth + 3P bindings on the same slot), four HIGH correctness bugs, nine MED/LOW hardening items. Adds READ tolerance for the v2 quota.json schema that v2.1 writes (dual-read; v2.0.1 continues to write v1).

See `docs/releases/v2.0.1.md` for the full red-team finding inventory (journal 0067), structural rotation fix (PR-A1 / journal 0064), credential-sync guards (PR-B7 / journal 0068), and quota schema shakedown (PR-C1.5 / VP-final).

## [2.0.0] — 2026-04-22

First stable release of the Rust rewrite. Retires the v1.x bash + Python stack.

See `docs/releases/v2.0.0.md` for the full release notes with install instructions, migration guide, and known limitations.

### Added

- Full Rust CLI: `csq run`, `csq swap`, `csq status`, `csq login`, `csq setkey`, `csq install`, `csq doctor`, `csq update check`, `csq statusline`, `csq models switch`.
- Tauri desktop app with Svelte 5 frontend — system tray, OAuth flow, quota dashboard, in-app update detection, Ollama model switcher.
- Handle-dir session model (spec 02) — each terminal has an ephemeral `term-<pid>/` with symlinks, enabling in-flight `csq swap` without terminal restart.
- Third-party provider support: MiniMax, Z.AI, Ollama. Per-slot bindings, per-provider quota polling.
- Central token refresher with per-account exponential backoff (10min × 2^n, cap 80min).
- Daemon IPC hardened with umask 0o077 + chmod 0o600 + peer-credential check (`SO_PEERCRED` / `LOCAL_PEERCRED`) + per-user socket directory.
- Recurring in-app update check with exponential-backoff retry and tray menu trigger.
- Paste-code OAuth flow (replaces the legacy loopback TCP listener).
- Square TF app-icon family (full 16→1024 `.icns`, no Retina pixelation).
- Subscription-metadata preservation guard across every credential write site (`rotation::swap_to`, `broker::fanout::fan_out_credentials`, `broker::sync::backsync`, `credentials::refresh::merge_refresh`).
- Token redaction (`error::redact_tokens`) at every OAuth body error-format surface.
- `csq install` migrates legacy per-slot `statusLine` (v1.x `statusline-quota.sh` references) to `csq statusline` on upgrade.
- `csq models switch` CLI for in-place 3P model retarget; `--pull-if-missing` auto-pulls Ollama models before binding.
- Ollama integration via HTTP API (`http://localhost:11434/api/tags`) + `find_ollama_bin()` resolver (searches `$OLLAMA_BIN`, `/usr/local/bin`, `/opt/homebrew/bin`, PATH).

### Fixed

- Auto-rotation no longer corrupts `config-N/.credentials.json` under the handle-dir model — refuses to run when any `term-*/` dir is present (journal 0064, P0-1).
- `download_and_apply` updater path guards against placeholder signing key at the core entry, not just the CLI wrapper (journal 0063 H1).
- `broker::sync::backsync` preserves canonical's `subscription_type` when live carries `None` (journal 0063 P1-1) — prevents silent Max→Sonnet downgrade after re-login.
- `bind_provider_to_slot` preserves user-edited `permissions`, `plugins`, `effortLevel`, and user-custom env keys when rebinding a 3P provider (journal 0063 P1-2).
- `providers::settings::save_settings` propagates `secure_file` chmod errors — 3P API-token files can no longer silently publish at umask default.
- `ChangeModelModal` loads installed Ollama models on every open edge (journal 0061) — alpha.21 had a `$effect` guard that skipped the first open entirely.
- `cancel_login` IPC command uses fixed-vocabulary error tags (journal 0063 M1) — future OAuthError widening cannot leak token material.
- Tauri capabilities narrowed to per-command allowlists (`opener:allow-open-url`, `autostart:allow-*`, `process:allow-restart/exit`) (journal 0063 M2).
- Resurrection-log JSONL uses `serde_json::to_string` (journal 0063 M3) — paths with backslash or control characters no longer corrupt the forensic trail.
- Desktop header shows the bundled `tauri.conf.json` version via `getVersion()` instead of a hardcoded literal (journal 0063 P1-5).

### Platform notes

- Windows desktop supervisor short-circuits on `#[cfg(not(unix))]` — the non-unix `run_daemon` was a stub; the supervisor no longer fake-claims daemon ownership and no longer blocks token refresh expectations. Full Windows named-pipe daemon wiring ships in a post-2.0 release. See L4 in the release notes.

### Deferred to 2.0.1

- Handle-dir-native auto-rotator (structural fix to P0-1).
- Shared `csq-core` helper for `set_slot_model_write` / `write_slot_model` atomic write (red-team R6).
- Throttled `ollama-pull-progress` emit rate (red-team R11).
- Defense-in-depth canonicalization guard on all `base_dir: String` Tauri commands (security audit L7).
- Security audit M-level cleanups: L1 (make `OAuthError::Http.body` private), L2–L6 (log-line cleanups), L7 (base_dir canonicalization).

---

## [1.1.0] — 2026-04-10

Z.AI GLM-5.1 provider support + coding-orchestration benchmark harness. Last v1.x release before the Rust rewrite.

## [1.0.0] — 2026-04-09

Initial multi-provider session manager for Claude Code. Bash + Python implementation with rotation engine, token refresh daemon, quota statusline, and paste-code OAuth.

---

[2.0.0]: https://github.com/terrene-foundation/csq/releases/tag/v2.0.0
[1.1.0]: https://github.com/terrene-foundation/csq/releases/tag/v1.1.0
[1.0.0]: https://github.com/terrene-foundation/csq/releases/tag/v1.0.0
[2.0.1]: https://github.com/terrene-foundation/csq/releases/tag/v2.0.1
[2.1.0]: https://github.com/terrene-foundation/csq/releases/tag/v2.1.0
[2.1.1]: https://github.com/terrene-foundation/csq/releases/tag/v2.1.1
