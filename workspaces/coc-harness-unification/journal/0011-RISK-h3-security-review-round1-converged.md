---
type: RISK
date: 2026-04-29
created_at: 2026-04-29T12:10:00+08:00
author: agent
session_id: term-35747
session_turn: 240
project: coc-harness-unification
topic: H3 round-1 security review — 1 HIGH + 3 MEDIUM + 2 LOW findings, all resolved in-session
phase: implement
tags:
  [
    h3,
    security,
    redteam,
    convergence,
    redaction,
    symlink,
    toctou,
    sandbox,
    zero-tolerance,
  ]
---

# RISK — H3 round-1 security-reviewer findings + same-session resolution

`security-reviewer` audited the H3 cc-launcher + auth-probe + canary surface before commit. Verdict: 1 HIGH, 3 MEDIUM, 2 LOW. Per `rules/zero-tolerance.md` Rule 5 ("No residual risks journaled as accepted") and the auto-memory `feedback_zero_residual_risk`, every above-LOW finding was resolved in this same /implement cycle BEFORE the PR opened. LOW findings (L1, L2) were also addressed because the fixes were trivial. No "documented and deferred" residuals.

## Findings + resolutions

### HIGH

**H1 — Auth probe stderr can leak echoed token material into the failure card.**
`coc-eval/lib/auth.py:172-181` (pre-fix) captured the first 500 bytes of cc's stderr verbatim into `AuthProbeResult.reason` with the comment "the redactor runs at JSONL persistence." OAuth error bodies have been observed echoing refresh-token prefixes inside `invalid_grant` responses (csq journals 0007, 0010 — different repo). The "redact later" contract is fragile because (a) any stray `print(result.reason)` or pytest `--tb=long` traceback bypasses it, and (b) the H3 PR does not yet contain the runner that would apply `redact_tokens` downstream. Until H4 lands the JSONL writer with redaction, an `ok=False, reason="…sk-ant-oat01-XXXX…"` could surface in pytest output, journal entries, or debug logs.

**Resolution:** redact at the source. `_probe_cc` now imports `redact_tokens` from `coc-eval/lib/redact.py` and applies it to the truncated stderr snippet before storing in `reason`. New regression test `TestProbeTimeout::test_stderr_token_redacted_in_reason` injects a synthetic `sk-ant-oat01-…` token via a fake claude script and asserts the token is absent from the result while a non-token diagnostic substring (`invalid_grant`) survives.

### MEDIUM

**M1 — `_find_user_credentials` follows symlinks without verifying the target lives inside the user's HOME.**
`launcher.py:266-305` (pre-fix) walked `~/.claude/accounts/config-*/.credentials.json` and accepted a symlink without resolving + asserting `Path.home()` containment. A `config-N/.credentials.json -> /tmp/attacker-creds.json` would have been silently chained into `_stub_home/`. Same-user threat model bounds this, but the symlink-target trust assumption is exactly what `_assert_credentials_symlink_intact` tries to enforce — the inode-parity check confirms "not swapped between readlink and stat" but does NOT confirm "target lives where we expect."

**Resolution:** new helper `_is_within(child, parent)` resolves both sides and uses `Path.relative_to` to test containment. Both the direct path (`~/.claude/.credentials.json`) and the per-account path (`~/.claude/accounts/config-N/.credentials.json`) now require their `.resolve()` to land inside `~/.claude/`. Three new regression tests in `TestCredentialSymlinkContainment` exercise the rejection path, the legitimate csq-shape (link-inside-claude-root), and the per-config-N rejection.

**M2 — Canary fixture has a TOCTOU window between exists-check and write.**
`tests/integration/test_stub_home_canary.py:57-66` (pre-fix) did `if CANARY_PATH.exists(): pytest.skip()` then `CANARY_PATH.write_text(...)`. Between those two calls an operator could land a real `_test_canary.md` and the test would clobber it. The `try/finally` cleanup is correct against in-test crashes but does not address the entry race.

**Resolution:** `CANARY_PATH.open("x", encoding="utf-8")` collapses the existence check and the write into a single `O_CREAT|O_EXCL` syscall. `FileExistsError` is caught and translated to `pytest.skip(...)` with the same operator-actionable message.

**M3 — `_resolve_sandbox_wrapper` interpolates `Path.home()` into bwrap argv unsanitized.**
`launcher.py:487-510` (pre-fix) interpolated `str(Path.home())` directly into the bwrap argv. argv-list invocation makes shell injection structurally impossible, BUT a HOME containing `..` (e.g. via a malicious `HOME=/tmp/x/../etc`) would produce confusing tmpfs mount paths. Defense in depth, not exploitable today.

**Resolution:** `Path.home().resolve()` is computed first; if the result fails `is_absolute()` the wrapper raises a typed RuntimeError. The macOS path is unaffected (sandbox-exec doesn't interpolate HOME).

### LOW

**L1 — Auth probe runs `claude --version` with a different env shape than the actual probe.**
`auth.py:117-118` (pre-fix) ran `subprocess.run([binary, "--version"], …)` without passing `env=`, inheriting the full process env, while the real probe ran with the caller-provided minimal env. Distinguishing inheritance behavior by call site is a contract footgun.

**Resolution:** the `probe_env` resolution moved BEFORE the version capture. Both subprocess calls now run under the same env shape — either the caller-provided minimal env (with PATH backfilled) or the inherited parent env if the caller passes `env=None`.

**L2 — `_build_cc_env` does not include `LOGNAME`/`USER` and the omission is undocumented.**
CC currently doesn't read these but some token-display paths might surface them in the future; harmless today, worth a code comment naming the deliberate omission.

**Resolution:** docstring comment added at the env-build site naming the deliberate omission and the future-trigger condition (some CC version observed depending on these vars).

## Verification

- `pytest coc-eval/tests/lib/`: **186 passed** (was 182; +4 new regression tests for H1, M1).
- `pytest coc-eval/tests/integration/test_stub_home_canary.py`: **GREEN** (M2 fix did not regress isolation behavior; 27s wall).
- `cargo check --workspace`: clean.
- `cargo fmt --all --check`: clean.
- Stub scan + `shell=True` + `os.system` greps: clean.

## Why fixes landed in-session, not in a follow-up

`rules/zero-tolerance.md` Rule 5 is unambiguous: "No residual risks journaled as 'accepted'". `feedback_zero_residual_risk` (auto-memory) reinforces this with a specific anti-pattern: "user rejects 'documented and deferred'; resolve redteam findings, don't journal them as accepted." Each of H1, M1, M2, M3 took 5-15 minutes to fix; deferring would have cost more in re-review than the fixes did to land.

The zero-tolerance principle's underlying argument: every "bounded by same-user threat model" or "narrow window in practice" or "cold path" framing is the same argument every redteamer hears for every finding — accepting them once trains the next session to accept them too.

## For Discussion

1. **Redact-at-source vs redact-at-persistence.** H1 was fixed by redacting at the auth probe source rather than relying on a downstream JSONL writer (H4) to apply `redact_tokens`. Compare: the source-redact approach is defense-in-depth (catches stray prints, traceback echoes) but adds a stable redaction overhead to every probe call (~microseconds per call, negligible). The persistence-redact approach centralizes redaction in one place but is fragile to forgotten-call paths. Should H4 still apply `redact_tokens` to JSONL records, or is the source-side redaction sufficient and the JSONL writer can trust its inputs are already clean?

2. **Symlink containment check scope.** M1 added containment for credential symlinks. The same trust assumption exists for `_assert_credentials_symlink_intact` in `spawn_cli`'s pre-spawn revalidation — that helper checks inode parity but NOT containment. Counterfactual: if an attacker swapped `_stub_home/.credentials.json` to point outside `~/.claude/` AFTER `build_stub_home` finished but BEFORE `spawn_cli` revalidated, would the inode-parity check catch it? Yes (the inodes would mismatch), but a containment check there too would close the more obvious "creds resolve outside expected root" failure mode that an inode mismatch surfaces less legibly. Worth adding to spawn_cli's revalidator?

3. **TOCTOU as a class.** M2 fixed one TOCTOU. `build_stub_home` itself has a similar pattern — `creds_link.unlink()` then `creds_link.symlink_to(src.resolve())`. Between those two calls, another process could create a file at the same path. Same-user threat model bounds this, but consistency suggests using `os.symlink(target, creds_link)` with `EXIST`-style retry, or `tempfile`-style atomic-replace via `os.rename`. Should H4+ codify a "no exists+write pairs" rule across the harness, with `O_EXCL` or atomic-rename as the only allowed shapes?

## References

- Journal 0010 — H3 ship report (initial DECISION; this RISK entry adds the security-review convergence layer).
- `rules/zero-tolerance.md` Rule 5 — "no residual risks accepted".
- `feedback_zero_residual_risk` (auto-memory) — user-stated rejection of "documented and deferred" framing.
- `coc-eval/lib/auth.py:_probe_cc` — H1 fix site.
- `coc-eval/lib/launcher.py:_find_user_credentials` + `_is_within` — M1 fix site.
- `coc-eval/lib/launcher.py:_resolve_sandbox_wrapper` — M3 fix site.
- `coc-eval/tests/integration/test_stub_home_canary.py:canary_rule_file` — M2 fix site.
- `coc-eval/tests/lib/test_auth_probe.py:test_stderr_token_redacted_in_reason` — H1 regression test.
- `coc-eval/tests/lib/test_cc_launcher.py:TestCredentialSymlinkContainment` — M1 regression tests.
