# Changelog

All notable changes to csq are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbering follows [Semantic Versioning](https://semver.org/).

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
