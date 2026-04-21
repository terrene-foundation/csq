# csq v2.0.0 Stable — Risk Analysis

**Author:** deep-analyst agent (read-only)
**Date:** 2026-04-21
**Related:** `workspaces/csq-v2/briefs/03-v2-stable-readiness.md`
**Method:** Static code walk across csq-core, csq-cli, csq-desktop. Seven risk dimensions (error-path, upgrade paths, credential safety, daemon lifecycle, concurrency, platform gaps, test coverage).

## Executive summary

1. **One P0 identity-corruption bug is live in the auto-rotator.** `auto_rotate::tick` writes account M's credentials into `config-N/.credentials.json` via `rotation::swap_to`, directly violating INV-01 of spec 02 (config-N is permanent). Auto-rotate is opt-in (default `enabled: false`), so only users who set `rotation.json` trigger the bug — but if they do, their canonical identity graph corrupts silently.
2. **Three P1 credential-drift paths survive.** `sync::backsync` strips `subscription_type` when live lacks it; `third_party::bind_provider_to_slot` wipes user-customised per-slot settings on `csq setkey --slot N`; `providers::settings::save_settings` silent-swallows chmod failures on files that hold 3P API tokens.
3. **Windows ships a fake-healthy daemon.** `daemon_supervisor::run_daemon` on non-unix is a cancellation await with no subsystems — but the PidFile is still acquired and `detect_daemon` reports healthy.
4. **One hardcoded version string will embarrass day-1.** `csq-desktop/src/lib/components/Header.svelte:69` renders `v2.0.0-alpha.21` literally.
5. **Test/reality gap risk is not confined to `ChangeModelModal`.** `AddAccountModal.test.ts` mounts with `isOpen: true` and never exercises the closed→open rerender.

## Findings by severity

### P0

#### P0-1 — Auto-rotator corrupts `config-N/.credentials.json` under the handle-dir model

- **Evidence:** `csq-core/src/daemon/auto_rotate.rs:223` calls `swap_to(base_dir, &config_dir, target)` where `config_dir = config-<N>` (line 138-148 filters to `config-*`). `rotation::swap_to` (`csq-core/src/rotation/swap.rs:87-88`) writes `target`'s credentials into `config_dir/.credentials.json`. Spec 02 INV-01 explicitly forbids any non-login/non-refresher write into `config-<N>/.credentials.json`.
- **Failure mode:** When auto-rotate is enabled, the daemon rotates config-1's credentials file from account 1's creds to account 3's creds. Next refresh tick: daemon loads `credentials/1.json` (account 1's canonical), compares to live config-1/.credentials.json (now account 3's). Identity graph drifts silently. Subsequent `csq run 1` launches CC with a handle dir symlinking to config-1's now-corrupted credentials. CC logs in as account 3 while the user thinks they're on account 1.
- **Blast radius:** Every config dir touched by auto-rotation. Once contaminated, the handle-dir symlinks resolve to the wrong identity. User-facing symptom: "wrong model," "wrong quota," "my account 1 is showing account 3's usage."
- **Mitigating factor:** Auto-rotate default is `enabled: false`. No one hits it unless they opt in. That also means there's no regression-test pressure catching it.
- **Suggested fix:** Option A (structural): auto-rotator walks `term-*` handle dirs and calls `handle_dir::repoint_handle_dir`. Option B (stable-safe): gate auto-rotate OFF in handle-dir mode with an explicit guard + WARN log. Option C: ship B in 2.0.0, ship A in 2.0.1.

### P1

#### P1-1 — `sync::backsync` strips `subscription_type` when live lacks it

- **Evidence:** `csq-core/src/broker/sync.rs:67` (`credentials::save(&canonical_path, &live_creds)?;`) writes live straight into canonical. Unlike `broker::fanout::fan_out_credentials` (`csq-core/src/broker/fanout.rs:72-86`) and `rotation::swap_to` (`csq-core/src/rotation/swap.rs:64-85`), backsync has no preservation guard.
- **Failure mode:** User re-logs in via `claude auth login` inside an already-running csq session. CC writes fresh `.credentials.json` with `subscription_type: None`. Statusline runs `backsync` on the next render. Backsync writes the None-subscription live into canonical. User's Max tier vanishes until next refresh backfills — typically 5 hours.
- **Suggested fix:** Mirror the preservation guard into `backsync`. Regression test: `backsync_preserves_subscription_type_when_live_has_none`.

#### P1-2 — `bind_provider_to_slot` destroys user-edited per-slot settings.json

- **Evidence:** `csq-core/src/accounts/third_party.rs:161-204` builds a minimal settings object from scratch (`Map::new()` at line 161, 174) and writes it atomically. No read-modify-write. Asymmetric with `unbind_provider_from_slot` which DOES preserve unrelated fields.
- **Failure mode:** User runs `csq setkey mm --slot 3 --key ...` on a slot where they previously edited `config-3/settings.json` to add `permissions`, `plugins`, or custom `env` keys. Bind silently overwrites the entire file with only the 3P env block.
- **Suggested fix:** Read existing settings; merge the 3P env keys into its `env` object; preserve every other field. Mirror the shape of `unbind_provider_from_slot`. Regression test: `bind_preserves_user_customisations_in_settings_json`.

#### P1-3 — Windows: daemon supervisor reports healthy but runs no subsystems

- **Evidence:** `csq-desktop/src-tauri/src/daemon_supervisor.rs:376-384` (`#[cfg(not(unix))]` `run_daemon`) is a stub that awaits cancellation and returns `Ok(())`. No refresher, no usage poller, no auto-rotator. But the supervisor still acquires the PidFile.
- **Failure mode:** Windows user installs csq v2.0.0. Tray shows "Daemon running." Tokens never refresh. Quota never polls.
- **Blast radius:** 100% of Windows users, if we ship Windows builds claiming daemon functionality.
- **Suggested fix:** Either implement full daemon on Windows (named-pipe IPC is already there per security-reviewer agent) before stable, OR gate Windows supervisor to NOT acquire the PidFile + label Windows "preview" in release notes.

#### P1-4 — `providers::settings::save_settings` silent-swallows chmod on 3P API-key files

- **Evidence:** `csq-core/src/providers/settings.rs:228` — `secure_file(&tmp).ok();`. The file this writes holds `env.ANTHROPIC_AUTH_TOKEN` (MiniMax / Z.AI API keys). Inconsistent with OAuth credential save (`credentials/file.rs:67-70`) and handle-dir materialization (`session/handle_dir.rs:234-237`) which both PROPAGATE secure_file errors.
- **Failure mode:** On an exotic filesystem (network mount, tmpfs with restrictive ACLs), chmod fails silently. 3P API token file lands at world-readable default permissions.
- **Suggested fix:** Propagate the error. Same for `quota/state.rs:74`, `accounts/profiles.rs:97`, `accounts/markers.rs:114` (defense-in-depth consistency fixes; non-secret but pattern divergence creates review fatigue).

#### P1-5 — Hardcoded `v2.0.0-alpha.21` version string in desktop header

- **Evidence:** `csq-desktop/src/lib/components/Header.svelte:69` — `<span class="version">v2.0.0-alpha.21</span>`. No template binding, no variable.
- **Failure mode:** When v2.0.0 stable is tagged, the in-app version string still says alpha.21.
- **Suggested fix:** Bind to `@tauri-apps/api/app`'s `getVersion()` or expose `CARGO_PKG_VERSION` as a Tauri command. Regression test: assert rendered version string equals crate version at build time.

#### P1-6 — `AddAccountModal.test.ts` has the same test/reality gap that hid the ChangeModelModal bug

- **Evidence:** `csq-desktop/src/lib/components/AddAccountModal.test.ts:83` — all tests call `renderModal()` with `isOpen: true`. No closed-mount then rerender test. `AddAccountModal` has a `$effect` at line 163 guarded by `if (isOpen)` that could suffer the exact same initial-edge failure as ChangeModelModal did; currently does NOT have the bug, but nothing tests the closed→open boundary.
- **Failure mode:** Latent — a future refactor that adds another reactive read could introduce the same bug class.
- **Suggested fix:** Copy the closed→open rerender test from `ChangeModelModal.test.ts` into `AddAccountModal.test.ts`.

### P2

- **P2-1** — `get_ollama_models` silently returns `vec![]` on every error (5 failure modes collapsed). `csq-core/src/providers/ollama.rs:39-83`. User can't distinguish "Ollama not installed" from "no models pulled yet."
- **P2-2** — Daemon force-quit leaves no cooldown journal. `csq-desktop/src-tauri/src/lib.rs:1117-1126` catches `RunEvent::Exit` but not kill -9. In-memory cooldowns lost on forced restart. Low blast radius — 5-min tick provides natural spacing.
- **P2-3** — `state_store.rs` uses `.expect("state store lock poisoned")` on the inner mutex. Panic propagation is handler-scoped; low probability of poisoning because critical sections are trivial. Defense in depth fix: `parking_lot::Mutex` or `.lock().unwrap_or_else(|e| e.into_inner())`.

## What a red-teamer would hit first — ranked

1. **Turn on auto-rotation** (`rotation.json: { enabled: true, threshold_percent: 50 }`) and watch config-N/.credentials.json drift to the wrong account within 5 minutes. P0-1.
2. **Re-login mid-session to strip Max tier.** P1-1. Recovers within 5 hours but the user thinks csq broke their account.
3. **Launch on Windows.** Tray says "Daemon running." Tokens never refresh. P1-3.
4. **Edit `config-N/settings.json` to add permissions, then `csq setkey mm --slot N`.** Permissions gone. P1-2.
5. **Screenshot the about-box.** P1-5 — version string says alpha.21 on a stable release.

## Test-coverage gaps by priority

| Prio | Code                                                       | Why it matters                                                                                                             |
| ---- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| P0   | `auto_rotate::tick` + handle-dir model                     | Zero handle-dir tests. No test reads `term-*` to prove rotation doesn't corrupt config-N.                                  |
| P1   | `sync::backsync` + subscription_type                       | 7 existing tests, all with `subscription_type: None`. No test where canonical starts with `Some(max)` and live has `None`. |
| P1   | `third_party::bind_provider_to_slot` preserves user fields | Unbind has preservation test (line 675). Bind has none.                                                                    |
| P1   | Desktop `Header.svelte` version rendering                  | No test asserts rendered version matches `CARGO_PKG_VERSION`.                                                              |
| P1   | `AddAccountModal.test.ts` closed→open rerender             | `ChangeModelModal.test.ts` has the rerender test now; `AddAccountModal.test.ts` does not.                                  |
| P2   | `csq run` (CLI)                                            | `commands/run.rs` has 1 test. No end-to-end test of the handle-dir creation path.                                          |
| P2   | `csq logout`, `csq status`, `csq swap` (CLI)               | Zero `#[cfg(test)]` modules.                                                                                               |
| P2   | Windows daemon_supervisor                                  | No test asserts Windows supervisor does NOT acquire PidFile or claims health when subsystems aren't running.               |

## Appendix: places where `secure_file(&tmp).ok()` silently swallows chmod

| File:line                                | File type                           | Contains secrets?       |
| ---------------------------------------- | ----------------------------------- | ----------------------- |
| `csq-core/src/providers/settings.rs:228` | `settings-<provider>.json` (global) | **Yes — 3P API tokens** |
| `csq-core/src/accounts/profiles.rs:97`   | `profiles.json`                     | No (emails, but PII)    |
| `csq-core/src/accounts/markers.rs:114`   | `.csq-account`, `.current-account`  | No                      |
| `csq-core/src/quota/state.rs:74`         | `quota.json`                        | No (usage data)         |
| `csq-core/src/accounts/discovery.rs:457` | `.resurrection-log.jsonl`           | No                      |
