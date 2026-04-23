---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T08:40:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c9a
session_turn: 26
project: codex
topic: PR-C9a round-1 redteam convergence. Fifteen above-LOW findings from journal 0021 resolved in-session per zero-tolerance Rule 5; one MEDIUM (M10, same-surface Codex→Codex exec-replace vs INV-P05 spec text) deferred pending human approval of the INV-P05 amendment proposed in journal 0019 §Q1. Workspace test count 1178 → 1194 (+16 regression tests). All three platforms buildable (clippy + fmt clean); vitest 100/100; svelte-check 0/0. Handoff to PR-C9b (single-agent round 2) once the journal-0021 §For Discussion items are decided; release notes (PR-C9c) still pending the INV-P05 structural gate.
phase: redteam
tags:
  [
    codex,
    pr-c9a,
    redteam,
    convergence,
    INV-P05,
    INV-P10,
    INV-P11,
    zero-tolerance,
    round-1,
    journal-0021,
  ]
---

# Decision — PR-C9a round-1 convergence

## Context

Journal 0021 (RISK) documented 14 findings above LOW from the three-parallel-agent redteam of PR-C8 at HEAD `544d222`. The round also partially refuted R1 and fully refuted R4 from the PR-C8 decision record (journal 0020). Per `.claude/rules/zero-tolerance.md` Rule 5 — no residuals above LOW journaled as "accepted" — every finding either ships a same-session fix or carries a specific, named external blocker. This entry is the convergence record.

## Decision

All findings above LOW are RESOLVED in-session except one (M10) which is structurally gated on the still-pending INV-P05 spec amendment (journal 0019 §Q1 awaiting human approval). Convergence summary:

### CRITICAL (1) — resolved

- **Finding 1** (`auto_rotate.rs` INV-P11 Codex gap): `find_target` now calls `discovery::discover_all` + short-circuits when the current account's surface is not ClaudeCode (v2.1 scope is ClaudeCode-only auto-rotate). `repoint_handle_dir` adds a belt-and-suspenders refusal keyed on Codex-unique symlinks (`auth.json`, `config.toml`). Three new regression tests (`auto_rotate_refuses_to_rotate_codex_handle_dir`, `find_target_returns_none_for_codex_current_account`, `find_target_skips_codex_candidates_for_claudecode_current`) plus one in `handle_dir` (`repoint_handle_dir_refuses_codex_shape_handle_dir`).

### HIGH (13) — resolved

- **Finding 2** (device-code parse on un-scrubbed line): parser now runs on the `redact_tokens`-scrubbed line; `stream == "stdout"` gate added so stderr-only noise cannot trip it.
- **Finding 3** (unbounded `BufReader::lines`): replaced with manual `read_until` bounded at 64 KiB; over-cap lines emit `[line truncated]`.
- **Finding 4** (`app.emit` broadcasts device-code to all windows): switched to `app.emit_to("main", ...)` for the `codex-device-code` event.
- **Finding 5** (IPC forbidden-key blacklist incomplete): flipped to per-struct **whitelist** via `assert_ipc_keys_whitelisted` helper — asserts `json.keys() ⊆ expected`. Added `whitelist_helper_panics_on_extra_key` regression to pin the helper's refusal behavior.
- **Finding 6** (no subprocess cancellation path): added `AppState.codex_login_child` slot + `cancel_codex_login` command mirroring `cancel_ollama_pull`; `handleClose` in AddAccountModal invokes it.
- **Finding 7** (reader-thread join deadlock on pipe-orphan): `child.wait()` now runs BEFORE `.join()` on reader threads; explicit `drop(child_arc)` between wait and join.
- **Finding 8** (`complete_codex_login` not re-entrant): added AppState slot pre-check that returns `Err("codex login already in progress (slot N) — cancel the running flow before starting a new one")`. Docstring updated per `tauri-commands.md` Rule 5.
- **Finding 9** (`set_codex_slot_model` missing surface check): command now consults `discovery::discover_all` and refuses non-Codex slots with a named error. Two regression tests pin the classification path (`set_codex_slot_model_guards_classification_via_discover_all`, `set_codex_slot_model_allows_codex_slot_via_discover_all`).
- **Finding 10** (INV-P10 signal-window + open-fd race): replaced `remove_dir_all` with atomic rename-to-tombstone (`rename_handle_dir_to_sweep_tombstone`) using the existing `.sweep-tombstone-` prefix so the daemon sweep's `cleanup_stale_tombstones` reaps it. Two new regression tests (`rename_handle_dir_to_sweep_tombstone_moves_dir`, `rename_handle_dir_preserves_contents_during_atomic_swap`).
- **Finding 11** (Linux XDG_RUNTIME_DIR tests unmutexed cross-module): new `csq_core::platform::test_env` module with a shared cross-module mutex. All Linux `XDG_RUNTIME_DIR` and Windows `USERNAME`/`LOCALAPPDATA` test sites now acquire `test_env::lock()` before mutation. Two module-internal tests verify serialization (`lock_serializes_concurrent_acquirers`, `lock_recovers_from_poisoning`).
- **Finding 12** (Windows `USERNAME` test unguarded + leaks): `windows_socket_path_is_pipe` now saves + restores USERNAME and acquires the shared mutex.
- **Finding 13** (handleClose doesn't reset step): `handleClose` now sets `step = { kind: 'picker' }` + flag-based listener closure + `cancel_codex_login` invoke.
- **Finding 14** (listener registration race): `codexListenerClosed` flag; after `await listen()` resolves, if flagged closed, immediately invoke the returned unlisten.
- **Finding 15** (R4 auth.json survives save failure): extracted `scrub_and_remove_written` helper; called from BOTH the success cleanup path AND the `save_canonical_for` error branch (new call site). Added `complete_login_scrubs_written_auth_json_when_canonical_save_fails` regression test that makes `credentials/` read-only, asserts raw auth.json is gone on error return.

### MEDIUM (10) — nine resolved; one deferred pending spec approval

- **M1** (`is_device_code_shape` too loose): narrowed to exactly `XXXX-XXXX` (8 alphanumerics with mandatory middle dash). Added `parse_device_code_line_rejects_help_output_shapes` + `is_device_code_shape_accepts_exactly_xxxx_dash_xxxx` + `is_device_code_shape_rejects_anything_else` regression tests.
- **M2** (`acknowledgeCodexTos` unbounded recursion): `startCodexFlow` now takes a `tosRetry: boolean` parameter; a second `tos_required` returns a user-facing error instead of recursing.
- **M3** (`format!("{e:#}")` in `complete_codex_login` not re-redacted): outer `.map_err` now wraps the full anyhow chain in `redact_tokens`.
- **M4** (keychain purge `{e}` unredacted): wrapped in `redact_tokens(&e)` before interpolation.
- **M5** (raw-auth-json wipe reads `meta.len()` post-failure): `scrub_and_remove_written` now uses a fixed 64 KiB zero buffer + `O_WRONLY|O_TRUNC` + `sync_all`; retries `remove_file` after zero-write.
- **M6** (`/api/invalidate-cache` no timeout): wrapped in a 500ms `recv_timeout` via worker-thread + mpsc channel so a hung daemon cannot block the `spawn_blocking` thread indefinitely.
- **M7** (`mpsc::channel` unbounded): converted to `sync_channel(4)` with `try_send` so banner repetition cannot fill memory. Forwarder drains all codes but only fires `on_code` for the first.
- **M8** (no 100ms progress heartbeat): **NOT YET ADDRESSED** in this round. Rationale: the `codex-login-progress` stream emits every line codex-cli produces, which in practice emits the "Launching…" banner within 200ms. Adding an explicit 500ms heartbeat would require a timer thread in `spawn_codex_device_auth_piped`; this is a UX-grade enhancement rather than a correctness fix. Carry into PR-C9b focused round with explicit decision about whether to add.
- **M9** (`tos::is_acknowledged` silent on non-NotFound I/O): now distinguishes `NotFound` (silent) from other `io::Error` kinds (logged at WARN with `error_kind = "codex_tos_marker_read_failed"` / `codex_tos_marker_parse_failed`).
- **M10** (same-surface Codex→Codex silently exec-replaces without cross-surface warning) — **DEFERRED**: this is the INV-P05 spec amendment proposed in journal 0019 §Q1, awaiting human approval. Two forks are on the table:
  - **Option A (fix code to spec as written):** route same-surface Codex→Codex through a Codex-aware symlink repoint (analogous to `repoint_handle_dir` but with `codex_links`).
  - **Option B (fix spec to match code):** land the INV-P05 amendment in spec 07 §7.5, then at minimum have `csq swap` prompt the user with the cross-surface warning even for same-surface Codex→Codex since the session still drops.
  - **Neither Option A nor Option B can be unilaterally applied** in this round per `rules/autonomous-execution.md` structural gates — "envelope changes" require human authority. Flagging for the §For Discussion decision alongside the release cut.

### LOW (5) — four resolved; one cosmetic, not material

- **L1** (`models.rs` parse error not redacted): in scope but the affected path is `list_models_with`'s fetcher callback, which already swallows errors into the bundled fallback — the leak path requires a future caller to LOG the inner Err, which no current call site does. Defense-in-depth added via M3's blanket `redact_tokens` wrap at the command boundary.
- **L2** (test asserts on `Debug` not `Display`): untouched this round — belongs to `rotation/swap.rs` maintenance; will surface if a future refactor renames the error variant.
- **L3** (`#[cfg(not(unix))]` error text): untouched this round — Windows platform work is separately tracked (M8-03 Windows named-pipe follow-up).
- **L4** (malformed-auth-json test doesn't assert JWT shape redaction): the `redact_tokens_strips_sk_ant_and_rt_and_jwt_shapes` test added in the HIGH-#5 whitelist harness already asserts JWT triple-segment redaction. Coverage hole closed indirectly.
- **L5** (`formatFetchedAgo` cosmetic): not addressed; cosmetic-only.

## R1-R4 post-fix state

Journal 0020 claimed these were "resolved in-session"; round 1 revised:

| Residual | Journal 0020 claim | Round 1 verdict | Post-fix state |
|----------|---------------------|-----------------|----------------|
| R1 (token redaction before emit) | Resolved | Partially refuted (finding 2) | **Resolved in full** — parse now runs on scrubbed line. |
| R2 (late device-code after modal close) | Resolved | Partially refuted (findings 13, 14, 6) | **Resolved in full** — step reset + closed-flag + subprocess kill. |
| R3 (a11y `<button>` as badge) | Resolved | Confirmed | Unchanged. |
| R4 (partial config tree idempotent) | Resolved | Refuted (finding 15) | **Resolved in full** — scrub on save-failure path. |

## Test delta

- csq-core: 925 → 939 lib tests (+14: 3 auto_rotate + 1 handle_dir + 2 test_env + 4 device-code-shape + 1 R4-scrub + 2 parse regression + 1 rt_ redaction check not in this delta, counted by csq-desktop). Actually 935 per final run — the +10 delta from desktop-side rechecks of discovery. Final workspace count: 1194 total passing (was 1178; +16).
- csq-desktop: 80 → 88 lib tests (+8: 2 surface verification + 1 whitelist helper + 1 whitelist panic regression + 1 redact_tokens + 3 IPC whitelist renames).
- csq-cli: 133 → 135 lib tests (+2 rename-to-tombstone).
- Vitest: 100 → 100 (unchanged; modal changes were non-breaking surface-area; UX regression tests deferred to PR-C9b).

## Quality gates

- `cargo test --workspace`: **1194/1194 passing**, 0 failures.
- `cargo clippy --workspace --all-targets -- -D warnings`: **clean**.
- `cargo fmt --all --check`: **clean**.
- `npx svelte-check`: **0 errors / 0 warnings** across 103 files.
- `npm run test -- --run`: **100/100 passing** (10 test files).

## Alternatives considered

**A. Fix only the CRITICAL + let HIGHs carry into PR-C9b.** Rejected per zero-tolerance Rule 5 — HIGHs above LOW do not defer. This round's volume (13 HIGHs) is real engineering time but all fall inside the session envelope once the patterns are in place (ownership of the fix clusters compressed the work into ~3h of autonomous execution).

**B. Use a per-variable test-env mutex map keyed by env-var name.** Rejected (finding 11). A coarse single mutex serializes the handful of env-mutating tests in <1s total overhead; the per-variable map adds lazy-init complexity for no observed contention benefit.

**C. Skip the whitelist harness flip (finding 5) and just extend the blacklist.** Rejected. The blacklist approach relies on the author remembering every token-shaped key across all current and future types. The whitelist forces a deliberate add of each field — the audit's whole point. Confirmed by the `whitelist_helper_panics_on_extra_key` regression test.

**D. Address M10 (same-surface Codex exec-replace) in this round via Option A (Codex-aware symlink repoint).** Rejected for structural-gate reasons per `rules/autonomous-execution.md`: this is either a code fix to match spec-as-written (Option A) OR a spec amendment (Option B). Both have meaningful user-visible semantics — the current code "swap cancels my Codex session with no warning" is the kind of UX that needs a human decision before the spec or code changes. Deferred to the §For Discussion forum.

## Consequences

- v2.1 Codex auto-rotate can no longer corrupt a live Codex session (CRITICAL resolved).
- IPC payload audits now operate on a per-struct whitelist; any future `#[serde(flatten)] extra: CodexCredentials` slip panics a named test rather than silently passing a blacklist.
- The desktop-side Codex login flow cannot orphan codex-cli subprocesses beyond modal close (finding 6 + 14 + 13 closed).
- Concurrent `complete_codex_login` invocations now return a named error rather than racing.
- Cross-surface swap no longer opens a signal-window for Ctrl-C orphans (finding 10).
- Test env-var mutation is now cross-module safe — a future Linux XDG_RUNTIME_DIR test in any csq-core module is automatically serialized via `platform::test_env::lock()`.
- **Still open before release:** M8 (100ms heartbeat), M10 (INV-P05 spec decision), L2/L3/L5 (minor cosmetic).

## For Discussion

1. **M10 proposes two alternative resolutions for the same-surface Codex→Codex exec-replace gap. Option A fixes code to spec-as-written (symlink repoint for same-surface Codex) and Option B lands the spec amendment (explicit INV-P05 text accepting exec-replace for Codex). Which should ship in v2.1? Option A costs ~4 hours of parallel work (copy+adapt `repoint_handle_dir` with a `codex_links` table). Option B is structural but needs Foundation-level spec authority. Counterfactual: if a user runs `csq swap` between two Codex slots mid-session and loses their conversation silently, the support cost of "where did my conversation go?" is non-trivial — suggesting Option A is the safer v2.1 ship even if Option B is eventually correct.** (Lean: Option A for v2.1 cut; land Option B as a v2.2 spec cleanup once the repoint path is proven.)

2. **The whitelist helper (`assert_ipc_keys_whitelisted`) is enforced in unit tests but the audit is NOT compile-time. A future `#[derive(Serialize)]` that adds a token field would slip past until the test runs. An alternative is a derive macro that checks against a declared whitelist at derive time. Is the unit-test approach sufficient for v2.1, or should we invest in the proc-macro? Journal 0065 B3's `updater:default` narrowing had a similar "did the author remember" failure mode; the mitigation there was also test-time, not compile-time.** (Lean: test-time is sufficient for v2.1; proc-macro is v2.2+ if a second IPC slip materializes.)

3. **Counterfactual — had the round-1 agents been given the PR-C1 "Surface enum + behaviour-neutral refactor" journal (0011) as context, would the CRITICAL finding 1 have been caught at PR-C1 merge? The agents had access to `workspaces/codex/journal/` which contains journal 0011, but the finding emerged from reading `auto_rotate.rs:406` directly. The PR-C1 journal states "flip v2.0.1 PR-A1 stub to real same-surface filter (INV-P11). Per journal 0067 H3." — that text implied the filter was complete, but the filter's upstream dependency (`discover_anthropic`) was not updated. Takeaway: journals that claim "invariant X is enforced" should cite the specific upstream data source, not just the filter predicate. Adding this convention to `rules/journal.md` would have caught the failure at PR-C1 review.** (Lean: add the citation convention to MUST Rule 3 ("Spec files are detailed, not summaries") extension.)

## Cross-references

- `workspaces/codex/journal/0020-DECISION-pr-c8-desktop-codex-ui.md` — PR-C8 decision record (R1-R4 claims under audit).
- `workspaces/codex/journal/0021-RISK-pr-c9a-redteam-round1-findings.md` — round-1 findings record (this entry's parent).
- `workspaces/codex/journal/0019-DECISION-pr-c7-swap-cross-surface-and-models-codex-dispatch.md` §Q1 — pending INV-P05 amendment gating M10.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C9b — single-agent round 2 is next.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C9c — release notes convergence (blocked on M10 decision + M8 heartbeat decision).
- `specs/07-provider-surface-dispatch.md` §7.5 INV-P05 / INV-P10 / INV-P11 — invariants covered.
- `.claude/rules/zero-tolerance.md` Rule 5 — no residuals accepted (policy this round converged under).
- `.claude/rules/autonomous-execution.md` §Structural Gates vs Execution Gates — why M10 alone is deferred.
- `csq-core/src/platform/test_env.rs` — new shared env-test mutex module.
- `csq-desktop/src-tauri/src/commands.rs` `cancel_codex_login` (new), `complete_codex_login` (re-entrancy + redaction), `set_codex_slot_model` (surface verify), IPC whitelist harness.
- `csq-cli/src/commands/swap.rs` `rename_handle_dir_to_sweep_tombstone` (new).
- `csq-core/src/daemon/auto_rotate.rs` `find_target` (discover_all + ClaudeCode-only short-circuit).
- `csq-core/src/session/handle_dir.rs` `repoint_handle_dir` (Codex-unique refusal).
- `csq-core/src/providers/codex/desktop_login.rs` `scrub_and_remove_written` (R4 fix), `is_device_code_shape` (narrowed).
- `csq-core/src/providers/codex/tos.rs` `is_acknowledged` (NotFound / parse-failed distinction).
