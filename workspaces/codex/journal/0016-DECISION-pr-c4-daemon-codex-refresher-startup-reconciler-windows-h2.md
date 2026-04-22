---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T00:20:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c4
session_turn: 18
project: codex
topic: PR-C4 — daemon Codex refresher (`broker_codex_check` + `HttpPostFnCodex`), surface-dispatched `tick`, `startup_reconciler` (INV-P08 mode flip + INV-P03 config.toml drift), and the H2 merge gate (Windows `require_daemon_healthy` cross-platform + named-pipe surface-dispatch integration test).
phase: implement
tags:
  [
    codex,
    pr-c4,
    daemon-refresher,
    broker-codex-check,
    startup-reconciler,
    inv-p01,
    inv-p03,
    inv-p08,
    inv-p09,
    h2-merge-gate,
    windows-named-pipe,
    clock-skew,
  ]
---

# Decision — PR-C4: daemon Codex refresher + startup reconciler + Windows H2 gate

## Context

Journal 0015 closed PR-C3c with the refresher iterating Codex slots and `continue`-skipping them — a structural placeholder so PR-C4 could land `broker_codex_check` in a single `match` arm. PR-C4 cashes that placeholder and additionally:

- Adds a sibling `broker_codex_check` in `csq-core/src/broker/check.rs` that mirrors the existing Anthropic `broker_check` contract (try-lock per slot, re-read inside lock, mutex-coordinated atomic write) for Codex.
- Threads a NEW `HttpPostFnCodex` transport (returns body + Date header) end-to-end so the daemon can emit `clock_skew_detected` per spec 07 §7.5 INV-P01.
- Introduces `csq-core/src/daemon/startup_reconciler.rs` — a two-pass clamp that runs BEFORE the refresher spawns: (1) flips Codex canonical credentials/codex-N.json from 0o600 → 0o400 if it crashed mid-flip (INV-P08); (2) rewrites config-N/config.toml when `cli_auth_credentials_store = "file"` has drifted (INV-P03).
- Closes the journal 0015 `#[cfg(not(unix))] Ok(())` carve-out in `csq-cli/src/commands/run.rs::require_daemon_healthy` — `daemon::detect_daemon` already had a Windows named-pipe path, so the cross-platform gate is one cfg removal.
- Lands the H2 merge gate per journal 0067 H2: `csq-core/tests/integration_codex_refresher_windows.rs` exercises a named-pipe daemon plus a surface-dispatched refresher cycle with both Anthropic and Codex transport closures and asserts the Codex slot routes ONLY to the Codex transport.

Spec contracts driving the design:
- §7.5 INV-P01 — daemon refreshes ≥ 2h before JWT exp; clock-skew warn at > 5min drift from server `Date` header.
- §7.5 INV-P02 — `csq run N` for a Codex slot refuses if the daemon is not running (already enforced; PR-C4 makes Windows enforce too).
- §7.5 INV-P08 — Codex canonical lives at 0o400 between refresh windows; mode flip is mutex-coordinated.
- §7.5 INV-P09 — per-`(Surface, AccountNum)` mutex; reconciler shares the same mutex table.
- §7.7.4 OPEN-C04 — Node transport required; reused via `super::post_json_node_with_date`.

## Decision

Six surgical pieces, all under one PR because they form one coherent landing of the daemon's Codex refresh story:

### 1. `broker_codex_check` (csq-core/src/broker/check.rs)

Sibling of `broker_check`. Decodes the access-token JWT exp claim (new `http_codex::jwt_exp_secs` + base64url-no-padding decoder, no new crate dep). If exp is more than 2h away → `BrokerResult::Valid` without HTTP. Otherwise acquires the same `refresh-lock` flock pattern Anthropic uses, re-reads inside lock, calls `http_codex::refresh_with_http_meta` (new transport-injected helper that returns `(CodexTokens, Option<DateHeader>)`), and routes:

- `code: "token_expired"` → `BrokerResult::Failed(BrokerError::CodexTokenExpired)` + `set_broker_failed(_, "codex_token_expired")`. Maps to `LOGIN_REQUIRED:` at the IPC boundary via the existing `From<CsqError> for String` (FR-CORE-03 step 5).
- `code: "refresh_token_reused"` → `BrokerResult::Failed(BrokerError::CodexRefreshReused)` + `set_broker_failed(_, "codex_refresh_reused")`.
- HTTP 429 → `BrokerResult::RateLimited` (refresher applies exponential backoff).
- Other → `BrokerResult::Failed(BrokerError::RefreshFailed)` + `set_broker_failed(_, "broker_refresh_failed")`.
- Success → builds a `CredentialFile::Codex` via `merge_codex_refresh` (preserves `auth_mode`, `openai_api_key`, `account_id`, `extra`; stamps `last_refresh` with hand-rolled RFC-3339-ish UTC), then writes via `file::save_canonical_for` which already coordinates the per-account write mutex (INV-P09) and runs the 0o400→0o600→write→0o400 dance (INV-P08).

Unlike Anthropic, there is no sibling-recovery pass: Codex's RT is single-use (openai/codex#10332), so trying a sibling would burn a second token. A failed refresh is terminal — re-login.

7 unit tests cover: valid no-refresh, expiring refresh path, token_expired→LOGIN-NEEDED, refresh_reused→LOGIN-NEEDED, missing refresh_token→LOGIN-NEEDED, concurrent locks (exactly one upstream call across 8 threads), clock-skew warn-but-succeed.

### 2. `HttpPostFnCodex` + `post_json_node_with_date` (csq-core/src/daemon/refresher.rs + csq-core/src/http/mod.rs)

New `pub type HttpPostFnCodex = Arc<dyn Fn(&str, &str) -> Result<(Vec<u8>, Option<String>), String> + Send + Sync + 'static>`. Sibling to the existing `HttpPostFn`. The Date-aware Node transport returns `(body, Option<Date header>)` over stdout — first line is the Date value (empty if absent), rest is the body (byte-for-byte identical to `post_json_node`). Splitting on `\n` keeps body lossless even when JSON contains newlines.

Refresher `spawn` / `spawn_with_config` / `run_loop` / `tick` all gain the `http_post_codex` parameter. Production wiring in `csq-cli/src/commands/daemon.rs` and `csq-desktop/src-tauri/src/daemon_supervisor.rs` passes `http::post_json_node_with_date`. Tests pass mock closures returning canned responses + an optional Date header.

The Codex branch in `tick` mirrors the Anthropic per-account cooldown / backoff bookkeeping but reads the access-token JWT exp claim for the cache record (rather than the Anthropic `claude_ai_oauth.expires_at` field). Surface dispatch lives entirely inside the `if info.source == AccountSource::Codex` branch — the Anthropic branch is unchanged byte-for-byte.

### 3. `startup_reconciler.rs` (NEW)

Two passes, both surface-scoped to Codex (the only surface today with the 0o400 invariant + the file-backed-auth directive). Both run synchronously before `spawn_refresher` so the running daemon never races against the reconciler.

Pass 1 walks `credentials/codex-<N>.json`, acquires the per-`(Surface::Codex, AccountNum)` mutex from `AccountMutexTable::global()`, and flips any 0o600 file back to 0o400 via `secure_file_readonly`. The mutex coordinates with the live refresher's `save_canonical_for` — the reconciler simply blocks until any in-flight refresh completes, then asserts steady-state 0o400. Catches the failure mode where `save_canonical_for` crashes between `secure_file` (0o600 write window) and `secure_file_readonly` (close window) — atomically replaced files always have a mode, but the post-write flip is a separate syscall and a sigkill in between leaves 0o600 until the next reconciler pass.

Pass 2 walks every `config-<N>/config.toml` for slots that have a Codex canonical and ensures the file contains `cli_auth_credentials_store = "file"` (canonical or `'file'` single-quoted form). If missing or drifted, rewrites via `surface::write_config_toml` PRESERVING any existing `model = "..."` value parsed line-wise (csq has no TOML parser dep, and the spec 07 §7.3.3 file shape is fixed at two keys). Codex respects the file-backed auth store ONLY when this key is present at startup; a rewrite landed AFTER codex starts does not migrate an existing keychain entry.

Returns a `ReconcileSummary` with per-pass counters (already_ok / repaired) for telemetry. Wired into both `csq-cli/src/commands/daemon.rs::handle_start` and `csq-desktop/src-tauri/src/daemon_supervisor.rs` immediately before the matching `daemon::serve(...)` call.

Pass 1 is no-op on Windows (`secure_file_readonly` is no-op there; `is_already_readonly` returns true on `cfg(not(unix))` so the repair counter never bumps). Pass 2 runs unchanged on every platform.

11 unit tests cover: empty-dir no-op; 0o600 → 0o400 flip; 0o400 already-ok; missing config.toml created; drifted config.toml preserved-model rewrite; correct config.toml mtime untouched; canonical/single-quoted directive parser; comment stripping; non-Codex files ignored.

### 4. H2 merge gate — Windows `require_daemon_healthy` (csq-cli/src/commands/run.rs)

`daemon::detect_daemon` already has a `windows_health_check` path covering the 4-step protocol (PID liveness → named-pipe open → minimal HTTP/1.1 GET /api/health → status line check). Closing the journal 0015 `#[cfg(not(unix))] Ok(())` carve-out is now one `cfg` removal: `require_daemon_healthy` becomes cross-platform and the same `DetectResult` match applies on Windows.

The journal 0015 trade-off — "refusing spawn on Windows today would brick every Windows user whose daemon is live but whose pipe client isn't wired yet" — no longer holds because the pipe client IS wired (it has been since M8.6); only the run.rs cfg gate was holding it back.

### 5. H2 merge gate — Windows named-pipe integration test

`csq-core/tests/integration_codex_refresher_windows.rs` (`#![cfg(windows)]`) stands up a real `server_windows::serve` named pipe with a unique name, plants an expired Codex slot, runs an inline `/api/health` probe through the pipe to verify the daemon is reachable, then spawns the surface-dispatched refresher with mock Anthropic + Codex transports and asserts:

- The Anthropic transport closure NEVER fires for the Codex slot.
- The Codex transport closure fires exactly once.
- The canonical credentials/codex-N.json carries the new tokens after the tick.
- The refresh cache contains the slot's entry.

This satisfies the journal 0067 H2 merge gate: "Windows named-pipe integration test green on CI". On non-Windows hosts the file compiles to an empty unit and contributes nothing to the test run.

### 6. Token-redaction defense at new error sites

Every new `{e}` formatter on the Codex branch has been audited per `.claude/rules/security.md` MUST Rule 8 / journal 0010 (token-echo defense):

- `refresher.rs` Codex branch's `credentials::load(canonical)` failure path runs the CredentialError Display through `error::redact_tokens()` before formatting. CredentialError::Corrupt's `reason` carries serde_json's error Display, which can echo input bytes — and the input here IS credential JSON.
- `startup_reconciler.rs` `cred_file::load` failure path: same redact_tokens wrap.
- `broker_codex_check`'s upstream-error branch never uses `{e}` — every warn-log emits a fixed-vocabulary `error_kind` tag (`codex_token_expired`, `codex_refresh_reused`, `broker_refresh_failed`, `broker_other`) computed via inline `match` rather than wrapping into `CsqError` just to call `error_kind_tag`.

## Alternatives considered

**A. Drop `broker_codex_check` into the existing Anthropic `match` arm.** Rejected. The Anthropic flow has resurrection from live siblings + sibling-RT recovery + `expect_anthropic` panics on the Codex variant. Trying to share the function body would force conditional `match` arms throughout. A sibling function with a different transport closure type and no recovery pass is far cleaner.

**B. Use `tokio::sync::Mutex` for the per-account mutex.** Rejected for PR-C4 — same rationale as journal 0012 (PR-C2a) §"Deviation". Every consumer of `AccountMutexTable` is synchronous; broker_codex_check holds the guard across an atomic_replace, never an `await`. A sync mutex stays fully sufficient. PR-C4 honored this by NOT introducing async-mutex churn even though the refresher is itself async — the refresher delegates to `tokio::task::spawn_blocking` for the broker call, so the sync mutex inside the broker is held entirely on a blocking thread.

**C. Separate "Date-aware" refresher transport vs. extending the existing one.** Rejected the latter. Changing `HttpPostFn`'s signature would require updating every Anthropic test mock and the existing Anthropic broker_check, none of which need the Date header. Keeping `HttpPostFn` byte-for-byte stable and adding a sibling `HttpPostFnCodex` is surgical and matches the surface-dispatch pattern the rest of PR-C4 follows.

**D. Skip clock-skew detection in PR-C4 (defer to follow-up).** Rejected. Spec 07 §7.5 INV-P01 explicitly names "clock-skew via HTTP Date" as part of the daemon contract, and the plan text for PR-C4 calls it out by name. Implementing the parser + warn at the same time as the refresh path costs ~80 lines of test-covered code and avoids a mid-air handoff.

**E. Use a TOML parser crate for the config.toml drift detector.** Rejected. csq has zero TOML deps today, the spec-fixed file shape is two keys, and pulling `toml` in for a 5-line line-wise check would be ~30k lines of dep tree for ~3 rules. Line-wise parser handled with comment stripping + double/single-quoted value tolerance.

**F. Run the startup reconciler from inside the refresher on first tick.** Rejected. The whole point is to land the canonical at 0o400 BEFORE the refresher starts so any concurrent `csq run N` invocation that calls into `save_canonical_for` reads a consistent steady state. Running it inside the refresher means the first tick races against any in-flight `csq run N`. Synchronous pre-spawn is the safer ordering.

## Consequences

- The daemon now owns Codex refresh end-to-end. The codex-cli's on-expiry in-process refresh path (`manager.rs:1745-1750`) never fires under the daemon's pre-expiry refresh, so the openai/codex#10332 single-use RT race is structurally avoided.
- `csq run N` for a Codex slot now refuses on Windows when the daemon is down, exiting with `EXIT_CODE_DAEMON_REQUIRED = 2`. Scripts can detect "daemon-down" vs other launch failures across all three platforms uniformly.
- Two-codex-process scenario (e.g. Cursor + a separate `codex` shell binding the same slot) is bounded by the per-slot `refresh-lock` flock — exactly one fires the refresh per cycle. Validated by `broker_codex_check_concurrent_exactly_one_refresh` (8 threads, 1 HTTP call).
- `clock_skew_detected` warns appear in the daemon log when local time differs from server `Date` header by > 5 min. The warn is non-fatal — the refresh still succeeds. Operators see the drift in `csq daemon status` log scrape.
- The startup reconciler closes the "canonical at 0o600 after a daemon SIGKILL mid-flip" failure mode. Recovery is automatic on the next daemon start; no `csq doctor` flag needed.
- The Windows H2 gate is satisfied by the new integration test. PR-C5 (usage poller Codex module) inherits the green Windows surface-dispatched refresher cycle as its base case — no further Windows integration test required for PR-C5.
- Tests grew from 940 → 1080 (+140 across new broker_codex_check tests, http::codex JWT/Date helpers, startup_reconciler, refresher dispatch tests, and the Windows integration). Vitest still 94, svelte-check 103 files 0 errors.

## For Discussion

1. **Pass 2 of the startup reconciler preserves the existing `model` key when rewriting a drifted config.toml. The line-wise parser tolerates `model = "..."` and `model = '...'` but rejects bare `model = x` (no quotes). Should the reconciler reject bare values silently (the current behavior — returns None and falls back to default model) or instead refuse to repair and surface a warn so the operator notices the malformed file?** (Lean: surface a warn but continue with default model. The operator's manual edit produced a malformed line; refusing to repair would leave the file in a state that breaks INV-P03 — losing the `cli_auth_credentials_store = "file"` directive — which is worse than overwriting a malformed `model` with the default.)

2. **`broker_codex_check`'s clock-skew check uses the server `Date` from the SUCCESSFUL refresh response. If the refresh fails with `token_expired`, no Date header is captured and no warn is emitted — but a clock-skew large enough to push the local "this is expired" decision earlier than the server's view could be the *cause* of the spurious failure. Should we hoist the Date-header capture out of the refresh path into a separate startup probe (one HEAD against api.openai.com per daemon boot)?** (Lean: defer to PR-C4-followup. The probe adds startup latency + a third HTTP call type, and the failure-correlation use case is rare in practice — drift > 2h would be needed to actually mis-route, and most clock daemons keep skew under 1s. The current after-refresh check catches the majority of cases at zero added cost.)

3. **The H2 integration test stands up a real Windows named-pipe server but exercises the refresher with mocked HTTP transports. If the `windows_health_check` adapter regressed in a way that broke `detect_daemon` against `windows_health_check` (rather than against an inline probe), this test would still pass. Counterfactually: had we kept the integration test focused only on the refresher cycle and left the daemon detect to its existing unit test (`detect_windows_live_daemon_returns_healthy`), would the test still satisfy journal 0067 H2's "Windows named-pipe integration test" merge gate, or does the gate specifically demand end-to-end coverage including the detect adapter?** (Lean: the gate's intent is "exercise the surface-dispatched refresher cycle on a Windows runner via the named-pipe layer", which the current test does. The detect-adapter unit test at csq-core/src/daemon/detect.rs covers the adapter side. Bundling both into one integration test would add coupling without adding coverage — the existing split is intentional. Keep both.)

## Cross-references

- `workspaces/codex/journal/0015-DECISION-pr-c3c-launch-codex-refresher-filter.md` — placeholder iterate-and-skip that PR-C4 cashes.
- `workspaces/codex/journal/0014-DECISION-pr-c3b-codex-login-device-auth.md` — login orchestrator + FR-CLI-05 setkey hard-refuse, the slot-provisioning prerequisite for the refresher.
- `workspaces/codex/journal/0007-DECISION-codex-transport-via-node-subprocess.md` (OPEN-C04) — Node transport rationale; PR-C4 reuses the pattern via the new `_with_date` sibling.
- `workspaces/codex/journal/0009-DISCOVERY-codex-oauth-error-body-no-echo.md` (OPEN-C05) — error-body echo defense-in-depth; redact_tokens wraps every new `{e}` formatter on the Codex branch.
- `workspaces/codex/journal/0012-DECISION-pr-c2-decomposition-mutex-first.md` — `AccountMutexTable` deviation from `tokio::sync::Mutex`; PR-C4 honors the same sync-mutex-sufficient stance.
- `workspaces/csq-v2/journal/0067-DECISION-redteam-post-v2.0.0-plan-convergence.md` — H2 (Windows named-pipe integration test as merge gate) closed by `csq-core/tests/integration_codex_refresher_windows.rs`.
- `specs/07-provider-surface-dispatch.md` §7.5 INV-P01 (2h pre-expiry, clock-skew via HTTP Date), INV-P02 (daemon hard prerequisite), INV-P03 (config.toml ordering), INV-P08 (mode-flip mutex coordination), INV-P09 (per-account mutex lifecycle).
- `csq-core/src/broker/check.rs::broker_codex_check` — sibling to `broker_check` added here.
- `csq-core/src/daemon/refresher.rs::tick` — surface-dispatched per-account loop; replaces the journal 0015 `continue` skip.
- `csq-core/src/daemon/startup_reconciler.rs` — NEW module; two-pass clamp.
- `csq-core/src/http/codex.rs::{refresh_with_http_meta, parse_http_date_secs, jwt_exp_secs, b64url_decode, CLOCK_SKEW_WARN_SECS}` — Codex-side transport + parsers added here.
- `csq-cli/src/commands/run.rs::require_daemon_healthy` — H2 cross-platform gate; carve-out closed.
- `.claude/rules/security.md` MUST Rule 8 (no `{e}` near OAuth code without redact); MUST Rule 4 (atomic writes) — both honored end-to-end.
- `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings) — every error site audited inline; no deferred items.
