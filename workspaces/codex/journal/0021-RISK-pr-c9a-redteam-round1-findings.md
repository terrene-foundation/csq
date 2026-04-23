---
type: RISK
date: 2026-04-23
created_at: 2026-04-23T05:45:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c9a
session_turn: 5
project: codex
topic: PR-C9a round-1 redteam findings. Three parallel agents (security-reviewer, intermediate-reviewer, deep-analyst) attacked non-overlapping slices of PR-C8 (desktop Codex UI) at HEAD 544d222. Fourteen findings above LOW. One CRITICAL (auto_rotate INV-P11 structurally broken for Codex). Thirteen HIGH. R2 (late device-code event) partially refuted; R4 (partial config tree idempotent) refuted. All above LOW queued for same-session fix per zero-tolerance Rule 5. One MEDIUM gates on the still-pending INV-P05 spec amendment (journal 0019 §Q1) and is flagged for human sign-off before fix.
phase: redteam
tags:
  [
    codex,
    pr-c9a,
    redteam,
    round-1,
    INV-P05,
    INV-P10,
    INV-P11,
    zero-tolerance,
    findings,
    R2-refuted,
    R4-refuted,
  ]
---

# Round-1 Redteam Findings — PR-C8 (desktop Codex UI)

## Context

PR-C8 shipped 2026-04-23 at HEAD `544d222` (journal 0020). Decision record claimed four residuals (R1-R4) "resolved in-session" per zero-tolerance Rule 5. Round-1 redteam spawned three parallel agents per `feedback_redteam_efficiency` against three non-overlapping slices of the PR-C8 surface area:

- **Agent 1 (security-reviewer)** — Codex credential handling, event-stream PII, IPC payload secret-audit, error-body token echo on OAuth-adjacent paths.
- **Agent 2 (intermediate-reviewer)** — Cross-surface swap invariants (INV-P05/P10/P11), Windows named-pipe detect race fix, handle-dir lifecycle under cross-surface exec-replace, concurrent-call correctness for new Tauri commands.
- **Agent 3 (deep-analyst)** — Device-auth subprocess race conditions, DI seam abuse, late-event modal cleanup (R2), tokio spawn_blocking contract, Svelte `$effect` correctness per `rules/svelte-patterns.md` MUST Rules 5 + 6, plan-vs-implementation drift.

Baseline: `cargo test --workspace` 1178 green, exit 0.

## Findings

Each finding is `SEV FILE:LINE — problem — fix`. Resolution state in the §Resolution tracker below — this entry is immutable per `rules/journal.md` MUST NOT Rule 1; a companion journal 0022 will record the post-fix convergence.

### CRITICAL

1. **`csq-core/src/daemon/auto_rotate.rs:406,429-433,465`** — `find_target` calls `discover_anthropic(base_dir)` which only scans `credentials/<N>.json` (stem must parse as `u16`), excluding every `credentials/codex-<N>.json`. When a `term-*` dir binds to a Codex-only slot, `accounts.iter().find(|a| a.id == current.get())` returns `None`, `active_surface` falls back to `Surface::ClaudeCode`, and the same-surface filter admits ClaudeCode candidates. The rotator then calls `repoint_handle_dir` on the Codex handle dir, which only rewrites `ACCOUNT_BOUND_ITEMS = [".credentials.json", ".csq-account", ".current-account", ".quota-cursor"]` — corrupting the Codex session mid-flight (live `codex` process suddenly reads a ClaudeCode marker; orphan `auth.json`/`config.toml`/`sessions` symlinks point at the old `config-N`). Exact INV-P11 failure mode the spec prohibits.
   **Fix:** replace `discover_anthropic` with `discover_all` in `find_target`; short-circuit the entire tick when `current_account.surface != ClaudeCode` OR the surface-filtered candidate set is empty. Belt-and-suspenders: teach `repoint_handle_dir` to refuse when source handle dir contains `auth.json`/`config.toml` (Codex shape).

### HIGH

2. **`csq-desktop/src-tauri/src/commands.rs:1625-1629`** — `parse_device_code_line(&line)` runs on the **raw** pre-redaction `line`, not the scrubbed variant. If a malicious `codex` binary (process substitution is possible in the same-user threat model) prints `Visit https://evil/ enter ABCD-EFGH\n...sk-ant-oat01-<real-token>` on one line, the scrubbed copy is emitted safely via `codex-login-progress` but the un-scrubbed line's device-code gets forwarded as truthful to `on_code`.
   **Fix:** call `parse_device_code_line(&scrubbed)` so any parse decision uses the redacted copy; gate parser on `stream == "stdout"` so stderr-only noise cannot trip it.

3. **`csq-desktop/src-tauri/src/commands.rs:1619`** — `BufReader::lines()` is unbounded. A codex-cli that writes >default-buffer (8 KB) worth of secret-containing data between newlines (or never flushes a final `\n`) grows the per-line allocation unboundedly with un-redacted content; `redact_tokens` allocates a `Vec<char>` of the full width, so a ~2 MB single-line log triggers OOM inside `redact_tokens` and the reader thread dies with stdout unread.
   **Fix:** manual `read_until(b'\n', ...)` with a 64 KB cap; emit `{"stream":tag,"line":"[line truncated]"}` on cap hit.

4. **`csq-desktop/src-tauri/src/commands.rs:1538`** — `app.emit("codex-device-code", &info)` broadcasts to every window, including any future secondary window (tray menu, settings) not authorized to see the `user_code`. The device code is a one-time secret; pairing it with the verification URL click confers possession of the OAuth session.
   **Fix:** `app.emit_to("main", "codex-device-code", &info)` per `tauri-commands.md` multi-window rule.

5. **`csq-desktop/src-tauri/src/commands.rs:2133-2234`** — IPC-audit harness is a token-prefix **blacklist** (only `access_token / refresh_token / id_token / api_key / openai_api_key`). Missing: `sess-*`, `rt_*`, `sk-ant-*`, `OPENAI_API_KEY` (matches CodexCredentials field exactly), `account_id`, `last_refresh`, `auth_mode`, `tokens`. A future `StartLoginView` that accidentally gains `#[serde(flatten)] extra: CodexCredentials` slips the 5-key harness entirely.
   **Fix:** flip to a per-struct **whitelist** — assert `json.as_object().keys() ⊆ expected_keys`. Covers the siblings-R1-missed gap.

6. **`csq-desktop/src-tauri/src/commands.rs:1571-1668`** — `spawn_codex_device_auth_piped` has no cancellation path. `AppState` lacks a `codex_login_child` slot (contrast with `ollama_pull_child` at `lib.rs:129`). Closing the modal unmounts UI but the subprocess keeps running in `spawn_blocking` until codex-cli's internal device-auth timeout (~15 min) fires, burning a blocking tokio thread and leaving an orphan process visible to the user.
   **Fix:** mirror `ollama_pull_child` pattern — `Arc<Mutex<Option<Arc<Mutex<Child>>>>>` in `AppState`; add `cancel_codex_login` command; Svelte calls from `handleClose` / modal unmount.

7. **`csq-desktop/src-tauri/src/commands.rs:1660-1666`** — reader-thread lifecycle: `while let Ok(info) = rx.recv()` at L1653 blocks until both reader threads drop their `tx` clone AND channel drains. Reader threads exit when stdout/stderr pipes close, which requires child exit. If the child is killed externally (e.g. new `cancel_codex_login` command fires) but the OS does not close the pipe (observed on macOS with buffered stdio), the stdout reader may remain blocked on `read_line`; `.join()` at L1661-1666 then hangs forever.
   **Fix:** `child.wait()` first, explicitly drop `child.stdout` / `child.stderr` before joining threads.

8. **`csq-desktop/src-tauri/src/commands.rs:1520-1558`** — `complete_codex_login` is not re-entrant. Two concurrent Tauri invocations with the same `account` both spawn `codex login --device-auth` with the same `CODEX_HOME=config-<N>/`, race on `auth.json` writing, then both call `save_canonical_for` + `remove_file(&written)`. `AccountMutexTable` protects only the single atomic write inside `save_canonical_for`, not the surrounding spawn/wait/relocate sequence. Second caller typically sees `"could not parse {} after codex login"` once the first caller unlinks `written`.
   **Fix:** acquire `AccountMutexTable::global().get_or_insert(Surface::Codex, account)` for the entire `complete_login` body (or maintain a desktop-side per-(surface,account) in-flight set that returns `Err("login already in progress for slot N")`). Add idempotency docstring per `tauri-commands.md` Rule 5.

9. **`csq-desktop/src-tauri/src/commands.rs:1757-1779`** — `set_codex_slot_model` does not verify `slot` is a Codex surface. A renderer (or any caller) passing a ClaudeCode slot number writes `cli_auth_credentials_store = "file"\nmodel = "..."` into `config-<N>/config.toml` of an Anthropic slot. That file is otherwise absent in Anthropic layout → surface-marker drift → poisoned subsequent surface classification.
   **Fix:** before writing, call `discovery::discover_all` (or single-slot surface lookup) and return `Err("slot N is not a Codex slot")` if `surface != Codex`. Add defense-in-depth: same check inside `providers::codex::surface::write_config_toml`.

10. **`csq-cli/src/commands/swap.rs:208-216`** — INV-P10 signal-window regression. `remove_dir_all` runs AFTER user confirms BEFORE `exec`. If the user Ctrl-C's between `remove_dir_all` returning and `cmd.exec()` issuing the syscall, the source terminal has no handle dir and the target never spawned — dead csq process, no running CLI, zombie cooldown entry in the daemon rotator map. Also `remove_dir_all` on a directory containing active `codex` process state deletes files under open fds.
    **Fix:** rename-to-tombstone the source handle dir (`term-<pid>` → `term-<pid>.swapping-<target>`), then `exec`; daemon sweep reaps the tombstone. Preserves INV-P10 semantics (source unreachable) while keeping directory alive for in-flight fds.

11. **`csq-core/src/daemon/paths.rs:194-212, 247-263`** — Linux tests `linux_prefers_xdg_runtime_dir` and `linux_falls_back_without_xdg_runtime_dir` mutate `XDG_RUNTIME_DIR` with `std::env::set_var` and are NOT guarded by `SOCKET_TEST_MUTEX` in `detect.rs` (different module, different mutex). `detect_missing_pid_file_is_not_running` in `detect.rs:364` ALSO mutates `XDG_RUNTIME_DIR` on Linux. Three tests race across modules — same env var, no shared mutex. Same failure class as commit `2818595` fixed for Windows `LOCALAPPDATA`, unfixed on Linux.
    **Fix:** hoist env-test mutex to a crate-private module (e.g. `csq-core/src/platform/test_env.rs`) keyed by env-var name; all sites acquire + save/restore. `with_var(name, value, || ...)` helper. Clippy `disallowed_methods` lint for `std::env::set_var` outside the helper module prevents regression.

12. **`csq-core/src/daemon/paths.rs:238`** — Windows test `windows_socket_path_is_pipe` mutates `USERNAME` without acquiring the Windows mutex from `detect.rs` (different env var, but unmutex'd). Also leaks: `USERNAME` is never restored.
    **Fix:** add save/restore pair analogous to `linux_prefers_xdg_runtime_dir`, guard with the shared env-test mutex from finding 11.

13. **`csq-desktop/src/lib/components/AddAccountModal.svelte:516-525`** — `handleClose` drops the `codexDeviceCodeUnlisten` handle but does NOT reset `step`. The listener closure at L478-490 guards on `step.kind === 'codex-running' && step.account === account`. After close, state persists on AccountList parent; if Tauri's event bus has a pending delivery, the guard passes and `openUrl()` fires on a closed modal. R2 resolution claim partially refuted.
    **Fix:** `step = { kind: 'picker' }` inside `handleClose`, OR guard the listener on `isOpen` as a belt-and-suspenders check.

14. **`csq-desktop/src/lib/components/AddAccountModal.svelte:476-491`** — listener registration race: if user closes the modal while `await listen()` is in-flight, `codexDeviceCodeUnlisten` is still `null` in `handleClose` so nothing unregisters. When `listen()` resolves later, the handler goes live on a closed modal.
    **Fix:** track a `closed` flag; after `await listen()` resolves, if closed, immediately invoke the returned unlisten function.

15. **`csq-core/src/providers/codex/desktop_login.rs:185-220`** — when `credentials::load(&written)` succeeds but `save_canonical_for` FAILS, the raw `auth.json` at `config-<N>/auth.json` is NOT cleaned up (the cleanup at L223-235 runs only on `save_canonical_for` success). Tokens sit on disk at whatever mode codex-cli wrote (typically 0o644 or 0o600) until the next retry overwrites. R4 "partial tree idempotent" claim refuted for this branch — `write_config_toml` atomicity holds, but `auth.json` leaks live access+refresh tokens world-readable-on-Linux between attempts.
    **Fix:** wrap `save_canonical_for` call path to unlink + zero-overwrite `written` on failure before returning. In the fallback cleanup (:223-235) call `secure_file(&written)` (0o600) BEFORE zero-write; retry `remove_file` after zero.

### MEDIUM (10)

- **M1** `csq-core/src/providers/codex/desktop_login.rs:287-298` — `is_device_code_shape` accepts 6-16 uppercase/digit runs. Matches common ALL-CAPS help output (`NOTICE`, `WARNING`, `FATAL7`, `ID-ABCDE`). Fix: require exactly `XXXX-XXXX` (8 alphanumerics with mandatory middle dash).
- **M2** `csq-desktop/src/lib/components/AddAccountModal.svelte:448-457` — `acknowledgeCodexTos` → `startCodexFlow` recursion has no depth guard. Stale backend read → infinite async recursion. Fix: recursion depth counter, max 1 re-entry.
- **M3** `csq-desktop/src-tauri/src/commands.rs:1541` — `format!("{e:#}")` re-serializes the full anyhow chain. Upstream `.context()` additions could leak through pre-existing redaction layer. Fix: `redact_tokens(&format!("{e:#}"))` for defense-in-depth.
- **M4** `csq-core/src/providers/codex/desktop_login.rs:159-163` — keychain purge failure message interpolates `{e}` unredacted. Fix: `redact_tokens(&e)` or fixed-vocabulary `error_kind = "codex_keychain_purge_failed"`.
- **M5** `csq-core/src/providers/codex/desktop_login.rs:225-228` — remove-failed fallback reads `meta.len()` post-failure; if file raced and grew, zero-fill is short. Fix: `O_WRONLY|O_TRUNC` + fixed 64 KB zero + fsync + retry remove.
- **M6** `csq-desktop/src-tauri/src/commands.rs:1551` — `/api/invalidate-cache` call inside `complete_codex_login` has no timeout; a hung daemon blocks the `spawn_blocking` thread indefinitely. Fix: `tokio::time::timeout` wrap, or skip if non-responsive.
- **M7** `csq-desktop/src-tauri/src/commands.rs:1604` — `mpsc::channel` unbounded. Pathological codex-cli banner repetition fills memory. Fix: `sync_channel(4)` + early-exit after first device-code.
- **M8** `csq-desktop/src-tauri/src/commands.rs:1530-1557` — no 100ms progress heartbeat during pre-device-code window (`tauri-commands.md` Rule 4). Silent "Launching…" spinner if codex-cli buffers stdout. Fix: emit a tick from the forwarder loop every 500ms even with no line.
- **M9** `csq-core/src/providers/codex/tos.rs:60-69` — `is_acknowledged` treats all parse errors as "not accepted" including I/O errors (0o000 permissions, disk full). Attacker-flipped unreadable marker forces re-prompt loop. Fix: distinguish `NotFound` (expected) from other `io::Error` kinds; log `error_kind = "codex_tos_marker_read_failed"` on the latter.
- **M10** `csq-cli/src/commands/swap.rs:69-78, module docstring §3` — same-surface Codex→Codex routes through `_ => cross_surface_exec(...)` which exec-replaces silently WITHOUT cross-surface confirmation (the `if is_cross_surface && !yes` path is skipped). Per the CURRENT text of spec 07 INV-P05, same-surface swaps must symlink-repoint, not exec-replace. Journal 0019 §Q1 proposed an INV-P05 amendment rationalizing Codex→Codex exec-replace, but the amendment is still **pending human approval**. **BLOCKED PENDING SPEC DECISION** — two options:
  - **Option A (fix code to spec):** route same-surface Codex→Codex through a Codex-aware symlink repoint (analogous to `repoint_handle_dir` but with `codex_links`). Honors spec-as-written.
  - **Option B (fix spec to code):** land the INV-P05 amendment (human sign-off), then adjust swap.rs to at minimum emit the cross-surface confirmation prompt even for same-surface Codex→Codex (user must know the session drops).

### LOW (5)

- **L1** `csq-core/src/providers/codex/models.rs:174` — `format!("parse models: {e}")` where `e` is `serde_json::Error`; future callers logging the `Err(…)` would leak. Fix: `Err(redact_tokens(&format!("parse models: {e}")))`.
- **L2** `csq-core/src/rotation/swap.rs:63-70` — test asserts on `Debug`, not `Display`. Future variant refactor silently breaks user-facing message. Fix: assert on `Display`.
- **L3** `csq-cli/src/commands/swap.rs:287-301` — `#[cfg(not(unix))]` error text does not distinguish same-surface vs cross-surface Windows paths. Fix: tighten message, link forthcoming Windows codex doc.
- **L4** `csq-desktop/src-tauri/src/commands.rs` (test) `complete_login_redacts_malformed_auth_json_tokens` — asserts `rt_AAAA` not echoed; does not assert `eyJ…` JWT shape redacted. Coverage gap.
- **L5** `csq-desktop/src/lib/components/ChangeModelModal.svelte:99` — `formatFetchedAgo` uses `Date.now()` without mock seam; cosmetic only.

## R1-R4 verification summary

| Residual                                | Claim (journal 0020) | Verdict               | Evidence                                                                                                                                                                                                             |
| --------------------------------------- | -------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 (token redaction before emit)        | Resolved             | **PARTIALLY REFUTED** | Emit side correctly redacts (safe). Parser side consumes the un-scrubbed `line` (HIGH finding 2). Emit is closed; parse trust-boundary is open.                                                                      |
| R2 (late device-code after modal close) | Resolved             | **PARTIALLY REFUTED** | Unlisten IS called in both handleClose and finally. But step state persists (finding 13) and listener-registration race leaves a null-unlisten window (finding 14). Subprocess also not killed on close (finding 6). |
| R3 (a11y `<button>` as badge)           | Resolved             | **CONFIRMED**         | Native `<button>` element; vitest `tagName === 'button'` passes.                                                                                                                                                     |
| R4 (partial config-N tree idempotent)   | Resolved             | **REFUTED**           | `write_config_toml` IS atomic+idempotent (the claim covered). `auth.json` on `save_canonical_for` failure is NOT cleaned (finding 15 — leaks live tokens between retries).                                           |

## Plan-vs-implementation drift

**Shipped as extras (not in plan §PR-C8):**

- `set_codex_slot_model` — a FIFTH command (plan listed 4). Journal 0020 acknowledged; plan not updated.
- `codex-keychain-prompt` — plan says "ToS disclosure" but does not enumerate keychain prompt as a separate modal step. Justified by spec 07 §7.3.3 step 2.
- `codex-login-progress` event stream — not in plan. Debug affordance.

**Shipped short of plan:**

- **PR-C1 capability manifest audit** — plan said "one-line check that new IPC commands added by subsequent Codex PRs are accounted for in `src-tauri/capabilities/main.json` narrowing". `default.json` was NOT updated with per-command allow-list entries for the 5 new Codex commands. May be intentional (Tauri 2 `core:default` grants invoke for all registered commands) but the per-command narrowing promise is unmet. Same class of concern as journal 0065 B3 (`updater:default` narrowing gap).

## Resolution tracker

Per `.claude/rules/zero-tolerance.md` Rule 5, all above LOW resolved in-session unless gated on a structural decision. Fixes land as same-PR commits or a follow-up PR-C9a.1; handoff to PR-C9b (round 2, single focused agent) only after these are green.

| #     | SEV      | Status              | Notes                                                        |
| ----- | -------- | ------------------- | ------------------------------------------------------------ |
| 1     | CRITICAL | PENDING             | auto_rotate discover_all + surface filter                    |
| 2     | HIGH     | PENDING             | scrubbed-line parsing                                        |
| 3     | HIGH     | PENDING             | bounded line reader                                          |
| 4     | HIGH     | PENDING             | emit_to("main")                                              |
| 5     | HIGH     | PENDING             | forbidden-key whitelist flip                                 |
| 6     | HIGH     | PENDING             | subprocess cancel path                                       |
| 7     | HIGH     | PENDING             | wait-before-join                                             |
| 8     | HIGH     | PENDING             | complete_codex_login re-entrancy                             |
| 9     | HIGH     | PENDING             | set_codex_slot_model surface check                           |
| 10    | HIGH     | PENDING             | INV-P10 rename-to-tombstone                                  |
| 11    | HIGH     | PENDING             | env-test mutex generalization                                |
| 12    | HIGH     | PENDING             | Windows USERNAME guard                                       |
| 13    | HIGH     | PENDING             | handleClose step reset                                       |
| 14    | HIGH     | PENDING             | listener registration race                                   |
| 15    | HIGH     | PENDING             | R4 auth.json cleanup                                         |
| M1-M9 | MEDIUM   | PENDING             | batch pass                                                   |
| M10   | MEDIUM   | **BLOCKED ON SPEC** | INV-P05 amendment (journal 0019 §Q1) requires human sign-off |
| L1-L5 | LOW      | PENDING             | batch pass                                                   |

Convergence (tests green, fixes merged, residuals converted to LOW or below) recorded in journal 0022.

## For Discussion

1. **Finding 1 (CRITICAL, auto_rotate INV-P11) cites `accounts::discovery::discover_anthropic` as the root cause, but `discovery::discover_all` has existed since PR-C1. Why did PR-C1's "behaviour-neutral refactor" (journal 0011) leave `auto_rotate` on the legacy narrower discovery function instead of the surface-aware one — was it an intentional scope deferral or an oversight? The PR-C1 test delta named 5 regressions from risk analysis §3; none of them covered rotator-on-Codex-slot.** (Counterfactual: had the PR-C1 regressions included a Codex-bound handle dir under auto-rotate pressure, this CRITICAL would have been caught at the spine PR and wouldn't have required a round-1 redteam.)

2. **Findings 13+14 (HIGH, AddAccountModal close races) invalidate the journal 0020 R2 claim that `codexDeviceCodeUnlisten` is "dropped synchronously in handleClose and in the finally block". The unlisten IS dropped — the claim isn't a lie — but the guard it protects (`step.kind === 'codex-running'`) persists through close. Is the fix (reset `step` in `handleClose`) sufficient, or does the Svelte store need a more general "modal-closed-cancel-everything" primitive so this class of bug can't recur? The ChangeModelModal has a similar shape; should the PR-C9a fix pass audit it for the same pattern?** (The alpha.21 spinner-hang regression in journal 0061 was also a modal state-machine bug; this is the third in the family.)

3. **Finding 10 (HIGH, INV-P10 signal-window) proposes rename-to-tombstone as the fix. An alternative is to install a signal handler that restores the source handle dir if Ctrl-C fires between `remove_dir_all` and `exec`. The tombstone approach is simpler but loses one tick of responsiveness (the source is briefly unreachable before exec). Is the tombstone acceptable for v2.1, or should a more nuanced "soft-unreachable → hard-delete after exec acks" pattern be considered? The current commit sweep already handles stale handle dirs; using tombstone names piggybacks on existing infrastructure at no extra cost.**

## Cross-references

- `workspaces/codex/journal/0020-DECISION-pr-c8-desktop-codex-ui.md` — PR-C8 decision record; R1-R4 claims under audit here.
- `workspaces/codex/journal/0019-DECISION-pr-c7-swap-cross-surface-and-models-codex-dispatch.md` §For Discussion Q1 — INV-P05 spec amendment proposal (blocks M10).
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C9a — this round's plan; §PR-C9b — round 2; §PR-C9c — release notes.
- `specs/07-provider-surface-dispatch.md` §7.5 INV-P01 through INV-P11.
- `specs/02-csq-handle-dir-model.md` — handle-dir lifecycle, sweep semantics.
- `.claude/rules/zero-tolerance.md` Rule 5 — no "residuals accepted".
- `.claude/rules/svelte-patterns.md` MUST Rules 5 + 6 — $effect untrack, async-nullable $state.
- `.claude/rules/tauri-commands.md` MUST Rules 1, 3, 4, 5 — Result return, no secrets in IPC, 100ms progress, idempotency doc.
- commit `2818595` (Windows `LOCALAPPDATA` mutex) — precedent for finding 11's generalization.
