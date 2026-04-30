---
type: RISK
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h10-codex
session_turn: 2
project: coc-harness-unification
topic: H10 round-1 security review (single agent) — 7 findings, all above-LOW resolved
phase: redteam
tags: [coc-eval, h10, security-review, round1, single-agent, zero-tolerance]
---

# H10 round-1 single-agent review — 7 findings converged

Per `feedback_redteam_efficiency` ("3 parallel agents in round 1 only;
switch to 1 focused agent by round 3"), H10 ran a single focused
agent because the H10 surface is a thin layer mirroring the H3-era
`cc_launcher`. The 6 above-LOW findings resolve in this PR per
`rules/zero-tolerance.md` Rule 5; the 1 LOW is accepted with rationale.

## Findings summary

| Severity  | Count | Resolved | Accepted |
| --------- | ----- | -------- | -------- |
| CRIT      | 1     | 1        | 0        |
| HIGH      | 3     | 3        | 0        |
| MED       | 2     | 2        | 0        |
| LOW       | 1     | 0        | 1        |
| **Total** | **7** | **6**    | **1**    |

## Findings

- **CRIT-1** _(resolved)_ — `_build_codex_args` returned `(exec, --sandbox, read-only, prompt)` with no argv terminator. A prompt starting with `--` (SF4-shaped indirect-injection content, future templated user content) would be parsed as a flag. **Fix:** insert `--` before the prompt: `(exec, --sandbox, read-only, --, prompt)`. Tests: `test_codex_args_inserts_double_dash_before_prompt`, `test_codex_args_safe_with_normal_prompt`, `test_codex_args_safe_with_dash_starting_real_world_prompt`.
- **HIGH-1** _(resolved)_ — `build_stub_home` codex extension symlinked to `src_path.resolve()` (the resolved file inode), so an atomic rotation of `~/.codex/auth.json` (rename → new inode) would orphan the stub_home symlink. **Fix:** symlink to `src_path` itself; symlink-to-symlink chains survive rotation. Test: `test_build_stub_home_codex_symlink_uses_source_path`.
- **HIGH-2** _(resolved)_ — `_AUTH_ERROR_PATTERNS` extended with bare substrings `"unauthorized"` / `"Token expired"` would false-positive on legitimate model output discussing auth. **Fix:** anchored each codex pattern to HTTP-status / error-prefix context (`"401 Unauthorized"`, `"Error: Token expired"`, `"Please sign in to ChatGPT"`, `"codex login required"`). Tests: `test_is_auth_error_line_does_not_false_positive_on_unauthorized_word`, `test_is_auth_error_line_does_not_match_prose_token_expired`, `test_is_auth_error_line_codex_specific_shapes`.
- **HIGH-3** _(resolved empirically)_ — `CODEX_HOME=stub_home` was unverified against codex 0.122. **Resolution:** the live codex gate (capability 3/4 + compliance 9/9 + safety 5/5) authenticated successfully, proving codex honors `CODEX_HOME`. Had it ignored the env var, codex would have fallen through to the empty `<stub_root>/.codex` (placeholder dir) and probe-failed with `skipped_cli_auth` on every cell. The 17/18 pass rate is the empirical proof. Documented in journal 0024 + spec 08.
- **MED-1** _(resolved)_ — codex `exec ping` 10s probe timeout was tight for a network round-trip through ChatGPT API. **Fix:** new constant `_CODEX_PROBE_TIMEOUT_SEC = 20.0` for codex specifically; cc stays at 10s. Test: `test_codex_probe_timeout_higher_than_cc`.
- **MED-2** _(resolved already-covered)_ — codex tokens (sk-proj-_, sess-_) feared to escape `redact_tokens`. **Resolution:** the existing `TOKEN_PREFIXES_WITH_BODY` patterns `("sk-", 20)` and `("sess-", 20)` already match `sk-proj-...` and `sess-...` because Pattern 2 only requires the prefix. Added regression tests `test_redact_tokens_handles_sk_proj_prefix` + `test_redact_tokens_handles_sess_prefix`.
- **LOW-1** _(accepted)_ — `register_cli` allows re-registration of an existing `cli_id`. **Rationale:** Phase 1 SUITE modules are first-party only; the test infrastructure relies on `monkeypatch.setitem(CLI_REGISTRY, ...)` for mocking. Adding a `replace=True` flag would be cosmetic for the current threat model. Tracked as a future Phase 2 hardening when third-party suite contributions land.

## H7 audit-hook follow-up fix

While testing the H10 changes against the full pytest suite, an interaction with the H7 `credential_audit` module surfaced: `sys.addaudithook` cannot be unregistered, so the hook fired on H10 tests' setup paths that legitimately wrote to `.credentials.json`-shaped fixtures. **Fix:** added an early-return on `_installed` in `credential_audit._hook` so `disarm_for_tests()` actually disarms the hook within a single Python process. This is a cross-test-isolation improvement, not a new finding — it was a latent bug in H7 that only surfaced with H10's broader test landscape.

## Lib pytest delta

`548 → 559 passed, 2 skipped` (+11 round-1 regression tests on top of the 17 H10 base tests, plus 1 fix to the audit-hook installed-flag check).

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H10
- Ship journal: `journal/0024-DECISION-h10-codex-activation-shipped.md`
- Spec: `specs/08-coc-eval-harness.md` (new "Codex activation (H10)" section)
- Live cc gate run id: `2026-04-30T10-32-36Z-67761-0000-859D29Lb` (recorded in PR comment)

## For Discussion

- **Q1 (challenge assumption):** HIGH-2 anchored codex patterns to HTTP-status / error-prefix context. If a future codex version emits auth errors in a different vocabulary (e.g. "Forbidden" or "session_expired"), the cache wouldn't flush. Should `_AUTH_ERROR_PATTERNS` carry a fallback "any line with `error:` AND any auth-keyword"? Or do we accept the targeted patterns as the contract?
- **Q2 (counterfactual):** HIGH-3 was resolved empirically rather than via an integration test. If the next session's live cc gate degrades and codex auth starts failing, an integration test asserting `codex --help | grep CODEX_HOME` would have surfaced the regression earlier. Worth the install dependency on the codex binary in CI?
- **Q3 (extend):** The audit-hook `_installed` early-return is a behavior change. Pre-fix, the hook was a permanent tripwire across the Python process; post-fix, it's gate-able via `disarm_for_tests`. Operators running `coc-eval/run.py` outside pytest are unaffected (`arm_for_implementation_run` is called once and the flag stays True), but is there a less ergonomically-loaded shape (e.g. a context manager) that makes the test isolation explicit?
