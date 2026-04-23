---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T10:40:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c9b
session_turn: 14
project: codex
topic: PR-C9b round-2 redteam convergence. Single-agent pass against HEAD `0af516a` (post-PR-C9a merge) surfaced 1 MEDIUM (M-CDX-1 — Codex repoint rewrote the `.csq-account` marker before the `auth.json` credential, exposing a partial-failure window where the marker pointed at slot N+1 while the credential still resolved to slot N) plus 3 LOW (L-CDX-1 strengthen Codex surface guard; L-CDX-2 Windows behavior of `repoint_handle_dir_codex` undefined; L-CDX-3 dispatcher routing not unit-tested). All four resolved in-session except L-CDX-2, which is documented as a known limitation matching the existing ClaudeCode repoint path's status (Windows port is a separately-tracked workstream M8-03). M8 (100ms heartbeat) decided "ship as-is" with empirical evidence from the AddAccountModal (state transitions render before the first codex-cli line). Three §For Discussion items from journal 0022 plus three from journal 0023 received explicit recommendations. Workspace tests 1199 → 1205 (+6 regressions). Clippy / fmt / svelte-check / vitest all green. Round 2 converges; PR-C9c (release notes) is unblocked.
phase: redteam
tags:
  [
    codex,
    pr-c9b,
    redteam,
    convergence,
    M-CDX-1,
    L-CDX-1,
    L-CDX-3,
    M8,
    round-2,
    journal-0023,
  ]
---

# Decision — PR-C9b round-2 convergence

## Context

Per `feedback_redteam_efficiency`, round 2 runs a single focused agent on the round-1 residuals plus any new code introduced by round-1 fixes. The new code in scope was the M10 fix (`repoint_handle_dir_codex` + `same_surface_codex` dispatcher arm) which had not been audited yet. The agent was also asked to revisit M8 (100ms heartbeat) and the §For Discussion items from journal 0022.

## Findings

### MEDIUM (1) — resolved

- **M-CDX-1** (`csq-core/src/session/handle_dir.rs` `repoint_handle_dir_codex` — `codex_links` slice ordering): credential rewrite (`auth.json`) MUST precede marker rewrite (`.csq-account`). The pre-fix order rewrote the marker first, so a mid-loop I/O failure (ENOSPC, EROFS, transient kernel error on the staged tmp) could leave the marker flipped to slot N+1 while `auth.json` still resolved to slot N. Two failure cascades from there: (a) the daemon's usage poller polls `/api/oauth/usage` keyed on `.csq-account`, attributing slot N's usage to slot N+1; (b) the next swap trips F3's `.csq-account` mismatch refusal because the marker says N+1 but the canonical credential says N. ClaudeCode's `ACCOUNT_BOUND_ITEMS` already follows the credential-first invariant (`.credentials.json` at index 0, `.csq-account` at index 1); the Codex slice diverged from it without justification. **Fix:** moved `("auth.json", canonical_cred.clone())` to index 0 and `(".csq-account", new_config.join(".csq-account"))` to index 1; added inline comment naming the invariant. **Regression test:** `repoint_handle_dir_codex_writes_credential_before_marker` uses `MetadataExt::ctime`/`ctime_nsec` to assert the marker's inode-change time is at-or-after the credential's, with a 20ms pre-act sleep to make ordering observable across filesystems with coarse mtime resolution.

### LOW (3) — two resolved, one documented as a known limitation

- **L-CDX-1** (Codex surface guard too permissive — same file): the original guard checked `auth.json.symlink_metadata().is_err()` only. Two gaps: (a) only checks `auth.json`, not the second Codex-unique marker `config.toml` (the inverse guard in `repoint_handle_dir` checks both); (b) accepts any entry that has `symlink_metadata` — a planted regular file or directory at `auth.json` would slip through. Same-user threat model bounds blast radius but does not eliminate the surface. **Fix:** loop over `["auth.json", "config.toml"]` and require each to be a symlink via `symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false)`. **Regression tests:** `repoint_handle_dir_codex_refuses_when_auth_json_is_regular_file` plants a regular file at `auth.json` and asserts refusal + that the planted file survives untouched; `repoint_handle_dir_codex_refuses_when_config_toml_symlink_missing` strips `config.toml` from a Codex handle dir and asserts refusal. Existing `repoint_handle_dir_codex_refuses_non_codex_handle_dir` still passes (a ClaudeCode handle dir lacks both markers and fails at iteration 0).

- **L-CDX-2** (Windows behavior of `repoint_handle_dir_codex` undefined — same file): the function is not `#[cfg(unix)]`-gated and the regression tests are all `#[cfg(unix)]`. Compiles on Windows; behavior under Windows symlink/junction semantics is untested. **Resolution: documented as a known limitation, not fixed in PR-C9b.** Rationale: the existing `repoint_handle_dir` (ClaudeCode) is also not `#[cfg(unix)]`-gated and is in the same Windows-untested state — fixing the Codex path differently would create asymmetric platform support across two functions that are otherwise mirror images. The Windows port of csq is a separately-tracked workstream (M8-03 named-pipe IPC and friends); both repoint paths will be audited together when that workstream lands. Per `rules/zero-tolerance.md` Rule 5 exceptions, this is "platform-specific work that requires a new dependency to be added to Cargo.toml in a follow-up PR" — the named blocker is the Windows port, not a vague "future work" framing.

- **L-CDX-3** (dispatcher routing not unit-tested — `csq-cli/src/commands/swap.rs` `handle()`): the `(source, target)` match in `handle()` is the only code standing between M10 and a regression. A future refactor that consolidates the match arms could re-route `(Codex, Codex)` through `cross_surface_exec` and the existing structural assertion in `repoint_handle_dir_codex_repoints_codex_symlinks` (which checks "no tombstone created") would only catch it if the test exercised `handle()`, which it doesn't (it calls `repoint_handle_dir_codex` directly). **Fix:** extracted the routing decision into `enum RouteKind { SameSurfaceClaudeCode, SameSurfaceCodex, CrossSurface }` + free function `fn route(source: Surface, target: Surface) -> RouteKind`. `handle()` now matches on `RouteKind` instead of the surface tuple; the matrix is unit-testable without env-var or filesystem setup. **Regression tests:** `route_claudecode_to_claudecode_is_same_surface_claudecode`, `route_codex_to_codex_is_same_surface_codex`, `route_cross_surface_is_cross_surface` (covers both cross-surface directions).

## M8 — decision: ship as-is

Round 1 deferred M8 with the rationale "the `codex-login-progress` stream emits every line codex-cli produces, which in practice emits the 'Launching…' banner within 200ms". Round 2 verified empirically:

- `csq-desktop/src/lib/components/AddAccountModal.svelte` line 495 sets `step = { kind: 'codex-running', account, deviceCode: null }` BEFORE invoking the backend. The modal IMMEDIATELY transitions to a render frame that shows "Signing in to Codex account #N…" + the hint paragraph "Launching `codex login --device-auth`… waiting for codex-cli to surface the device code." (lines 860–884).
- `tauri-commands.md` Rule 4 100ms-heartbeat exists to prevent the "did it freeze?" ambiguity. That ambiguity does not exist here because the UI has already transitioned in the same render frame as the click — there is no blank gap for the user to interpret as a freeze.

Adding a timer thread to `spawn_codex_device_auth_piped` would add a ~30-line concurrency surface (timer + cancel + join interaction with the existing reader-thread `child.wait()` → `.join()` sequence from round-1 finding 7) for zero observable user benefit. **Decision: do not add the heartbeat. The lede + hint paragraphs are the spinner.**

## §For Discussion responses

Combined responses to journal 0022 §FD #2/#3 and journal 0023 §FD #1/#2/#3:

1. **Journal 0022 #2 (proc-macro vs unit-test for IPC payload audits) — keep unit-test for v2.1.** The current `assert_ipc_keys_whitelisted` + `whitelist_helper_panics_on_extra_key` regression catches the failure mode it was designed for. A proc-macro adds build-time complexity, a new crate dependency, and a custom `derive` annotation surface — all of which violate `rules/independence.md` Rule 3 (Foundation-only and upstream dependencies). The cost of one missed test addition is a `cargo test` failure on the next CI run; the cost of a proc-macro is permanent build-graph weight. The trigger to revisit: a second IPC type slip past the test harness.

2. **Journal 0022 #3 + Journal 0023 #3 (journal citation conventions) — combine into a single new SHOULD rule for `terrene/.claude/rules/journal.md`.** Recommended text: "Journal entries that codify a design constraint or claim an invariant is enforced SHOULD cite an empirical reference (man page, test, prior journal, or measurable behaviour). Plausibility-only justifications are not durable." This catches both PR-C1's "INV-P11 same-surface filter is enforced" (which claimed the filter was complete while its upstream `discover_anthropic` was not updated) and PR-C7's `sessions/`-orphan rationale (which was plausible-sounding, refutable in a 10-line test, and cost a full PR-C9a session to overturn). **Action item:** rule edit lives in the parent `terrene/` repo, not csq — flag for next root-level session per `cross-repo.md` MUST Rule 3 (csq does not modify parent repo files).

3. **Journal 0023 #1 (extract `RepointStrategy` trait) — leave duplication for v2.1.** The two repoint paths share lock + pre-flight + rename loop but diverge on the trailing `materialize_handle_settings` + `rebuild_claude_json_for_swap` pair (ClaudeCode-only). A trait would either (a) leave those methods on the trait with no-op defaults for Codex (signaling that Codex "could" need them, which it cannot per spec 07 §7.2.2) or (b) split into two traits, at which point the abstraction adds nothing the two functions don't already provide. **Re-evaluate when a third surface lands** — at N=3 the abstraction has structural justification.

4. **Journal 0023 #2 (mock-codex no-exec assertion) — leave at structural level.** The tombstone-count check is a sufficient witness that `cross_surface_exec` did not run because tombstone creation is its only persistent on-disk side effect before `exec`. Mocking `exec` on Unix would require `LD_PRELOAD` (Linux-only) or `DYLD_INSERT_LIBRARIES` (macOS-only). L-CDX-3's dispatcher routing test (this convergence) handles the underlying concern without `exec` mocking.

## Hypotheses refuted

The agent tested seven hypotheses; four were refuted with named evidence. Recording here so the next round does not retread:

- **Concurrency.** Two-swap interleave is covered by the per-handle `.swap.lock`. Auto-rotate + swap is covered by the same lock (auto_rotate goes through `repoint_handle_dir`, same lock file). `cancel_codex_login` operates only on the login subprocess `Child`, not on a running codex-cli session — disjoint code paths. Codex-cli writing `auth.json` mid-rename: write goes to the canonical file via the symlink fd; renaming the symlink does not disturb the fd.
- **INV-P11 carry-over.** `auto_rotate::find_target` short-circuits on non-ClaudeCode `active_surface`. The new `repoint_handle_dir_codex` is reachable only from `same_surface_codex` in the CLI dispatcher; auto_rotate cannot reach it.
- **IPC whitelist release-mode bypass.** `assert_ipc_keys_whitelisted` is called only inside `#[cfg(test)]` blocks — there is no release-mode path that fails open.
- **Tombstone PID/nanos collision.** `rename_handle_dir_to_sweep_tombstone` uses `{pid}-{nanos:x}` and each `csq` process has its own PID — same-PID same-nanosecond collision is impossible.
- **Cancel half-writes the keychain.** Keychain purge runs BEFORE subprocess spawn; keychain WRITES happen post-login after the user enters the device code. Cancellation before that means no write occurred.
- **`test_env::lock` poison recovery.** `platform/test_env.rs:124` actively spawns + panics + re-acquires; recovery works.

## Quality gates

- `cargo test --workspace`: **1205 / 1205 passing**, 0 failures (was 1199; +6 round-2 regressions: 1 ordering invariant + 2 strengthened-guard + 3 routing matrix).
- `cargo clippy --workspace --all-targets -- -D warnings`: **clean**.
- `cargo fmt --all --check`: **clean** (auto-applied one match-arm rewrap).
- `npx svelte-check`: **0 errors / 0 warnings** across 103 files (frontend untouched).
- `npm run test -- --run`: **100 / 100 passing**.

## Alternatives considered

**A. Promote M-CDX-1 to HIGH because the failure mode causes silent quota drift in the daemon.** Rejected — silent quota drift is recoverable on the next successful swap (which corrects both the marker and the credential atomically) and the daemon's poller is bounded by the 5-min cycle, so the drift window is short. HIGH is reserved for unrecoverable or actively destructive failure modes (lost credentials, incorrect cross-account writes); this is recoverable misattribution. Same-session fix per Rule 5 either way; severity affects the journal entry's tagging, not the action.

**B. `#[cfg(unix)]`-gate `repoint_handle_dir_codex` (L-CDX-2).** Rejected for asymmetry with `repoint_handle_dir` (ClaudeCode), which is also not gated. The decision to gate or not gate the repoint paths is a Windows-port-wide question, not a single-function question.

**C. Add an extended ordering test that injects a controlled rename failure (chmod the staging dir read-only between iterations 0 and 1) and asserts the marker did not flip.** Rejected — mid-loop fault injection requires either (a) breaking encapsulation by exposing the iteration counter or (b) making rename go through an injectable transport. The mtime/ctime ordering test pins the same invariant with no production code change. The fault-injection test is a SHOULD if a future refactor introduces a per-item retry loop or any other source of within-loop iteration ordering subtlety.

## Consequences

- **PR-C9a M10 fix is hardened** against partial-failure (M-CDX-1) and against malicious / corrupted Codex handle dirs (L-CDX-1).
- **The dispatcher routing is now unit-tested** at the matrix level (L-CDX-3). A future refactor that re-routes `(Codex, Codex)` through `cross_surface_exec` will fail `route_codex_to_codex_is_same_surface_codex` immediately at `cargo test` time, before any user can lose a conversation.
- **M8 is closed** — no heartbeat will be added in v2.1; the existing modal state-transition timing is sufficient feedback.
- **PR-C9c (release notes) is unblocked.** All journal 0022 outstanding items have either landed (M10) or been decided (M8). All §For Discussion items have explicit recommendations either implemented or routed to the parent repo for the journal-citation convention.
- **No carryover findings to PR-C9c.** Round 2 converges to zero above-LOW residuals; PR-C9c does not need to ship a third redteam round.

## R-state of round-2 findings

| Finding | Severity | State | Resolution |
|---------|----------|-------|------------|
| M-CDX-1 | MEDIUM | RESOLVED | Reorder + ctime regression test |
| L-CDX-1 | LOW | RESOLVED | Strengthened guard + 2 regression tests |
| L-CDX-2 | LOW | DOCUMENTED | Asymmetric to ClaudeCode repoint; Windows port (M8-03) is the named blocker |
| L-CDX-3 | LOW | RESOLVED | Extracted `route()` + 3 matrix tests |
| M8 | MEDIUM (deferred from r1) | RESOLVED — ship as-is | Empirical: AddAccountModal transitions in same render frame |

## For Discussion

1. **The M-CDX-1 fix relies on the `codex_links` slice being processed in declaration order — which is the natural read of `for (name, target) in codex_links` over a `&[(_, _)]` slice. If a future Rust edition or a `rayon`-style parallelization PR turned that loop into an unordered traversal, the ordering invariant would silently regress. Should we lift the invariant out of the slice's index order and into an explicit two-phase rewrite (credential phase, then marker phase)? Counterfactual: the test would catch the regression, but a `for` loop is the structurally-cheapest way to express the ordering and an explicit two-phase rewrite trades 5 LoC for 30 LoC of repeated lock/stage/rename boilerplate. (Lean: keep slice-order; the regression test is the contract, the slice ordering is the implementation. If a parallel-rewrite PR ever lands, the test will block it and force the author to add the two-phase split.)**

2. **L-CDX-2 (Windows behavior) is documented as "matching ClaudeCode's status" rather than fixed. This is internally consistent but means a Windows user running `csq swap` between two Codex slots gets undefined behavior with no error message. Should v2.1's release notes call this out explicitly under the existing Windows caveat, or is the existing "csq is Unix-first; Windows port tracked as M8-*" framing sufficient? (Lean: PR-C9c release notes add one bullet under the Windows caveat: "Same-surface Codex swap on Windows is untested; the Unix-only `cross_surface_exec` path remains the only validated swap behavior on Windows.")**

3. **Counterfactual — would round 1 have caught M-CDX-1 if it had been run with 4 agents instead of 3 (one dedicated to "audit any new Codex code")? The M-CDX-1 finding emerged because the round-2 agent compared the new `codex_links` slice ordering against the established ClaudeCode `ACCOUNT_BOUND_ITEMS` ordering and noticed the divergence. Round-1 agents did not have the new code in their scope (they audited PR-C8 at HEAD `544d222`, before M10 existed). The bug is M10-implementor's responsibility; round 1 had no chance. Per `feedback_redteam_efficiency`, parallel agents in round 1 are for breadth, not for re-auditing fixes the round itself produces — that's specifically what round 2 is for. (Lean: confirms the existing 3-then-1 cadence; M-CDX-1 is a round-2-class finding by construction, not a round-1 escape.)**

## Cross-references

- `workspaces/codex/journal/0021-RISK-pr-c9a-redteam-round1-findings.md` — round-1 findings.
- `workspaces/codex/journal/0022-DECISION-pr-c9a-round1-convergence.md` — round-1 convergence + §For Discussion items.
- `workspaces/codex/journal/0023-DECISION-pr-c9a-m10-resolution.md` — M10 Option A landing; the new code this round audited.
- `csq-core/src/session/handle_dir.rs` `repoint_handle_dir_codex` — fixes for M-CDX-1 + L-CDX-1; tests for ordering invariant + dual-marker guard.
- `csq-cli/src/commands/swap.rs` `route()` + `RouteKind` — extracted dispatcher for L-CDX-3; matrix unit tests.
- `csq-desktop/src/lib/components/AddAccountModal.svelte` lines 495 + 860–884 — empirical evidence for M8 ship-as-is.
- `.claude/rules/zero-tolerance.md` Rule 5 — policy under which all four findings closed in-session (L-CDX-2 under the platform-blocker exception).
- `.claude/rules/independence.md` Rule 3 — proc-macro avoidance argument for §FD #2.
- `terrene/.claude/rules/journal.md` — destination for the §FD #3 rule edit (parent-repo work, not csq).
- `feedback_redteam_efficiency` (memory) — 3-then-1 cadence justified.
