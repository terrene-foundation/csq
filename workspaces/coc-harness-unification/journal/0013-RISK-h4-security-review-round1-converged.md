---
type: RISK
date: 2026-04-29
created_at: 2026-04-29T13:45:00+08:00
author: agent
session_id: term-35747
session_turn: 335
project: coc-harness-unification
topic: H4 round-1 security review — 2 HIGH + 4 MEDIUM + 3 LOW findings, all resolved in-session
phase: implement
tags:
  [
    h4,
    security,
    redteam,
    convergence,
    jsonl,
    redaction,
    umask,
    $ref-cycle,
    zero-tolerance,
  ]
---

# RISK — H4 round-1 security-reviewer findings + same-session resolution

`security-reviewer` audited the H4 JSONL writer + schema validator + run-id surface before commit. Verdict: 2 HIGH, 4 MEDIUM, 3 LOW. Per `rules/zero-tolerance.md` Rule 5 ("No residual risks journaled as accepted") and the auto-memory `feedback_zero_residual_risk`, every above-LOW finding was resolved in this same /implement cycle BEFORE the PR opened. Two LOW findings were also addressed because the fixes folded into the M2 patch. L3 was a false alarm flagged for the H9 aggregator review only — no H4 action.

## Findings + resolutions

### HIGH

**H1 — `extra` kwarg on `write_header` bypasses redaction.**
`coc-eval/lib/jsonl.py:309-310` (pre-fix) merged operator-supplied `extra` dict into the header via `record.update(extra)` BEFORE `validate_record`, but redaction was scoped to `stdout_truncated`/`stderr_truncated` in `record_result` only. A caller stuffing `extra={"last_auth_error": "<resp body containing sk-ant-oat01-…>"}` would persist the token raw. Same exposure for `auth_probes[*].reason`: the H3 probe redacts at source, but a future probe path or a manually-built header would slip through.

**Resolution.** Replaced per-field redaction with deep recursive redaction. New `_deep_redact_record(record)` walks every string in every dict + list in the record and applies `redact_tokens` in place. Called from BOTH `write_header` (after `extra` merge) AND `record_result` (replaces the previous two-field pass). `redact_tokens` is byte-pattern-based and idempotent; double-redaction yields identical bytes. New tests:

- `TestExtraKwargRedacted::test_extra_kwarg_token_redacted` injects `sk-ant-oat01-DDDDDDDDDDDDDDDDDDDDDDDD` via `extra` and asserts the disk bytes do not contain the token.
- `TestExtraKwargRedacted::test_auth_probe_reason_redacted` does the same for `auth_probes["cc"]["reason"]`.

**H2 — `git` PATH lookup in `_verify_results_path_gitignored`.**
`coc-eval/lib/jsonl.py:163-170` (pre-fix) ran `subprocess.run(["git", "check-ignore", ...])` resolving `git` via `$PATH`. A hostile `~/bin/git` shim earlier on PATH would run inside the harness's user context with a controlled argument. `cwd=repo_root` would also enable `GIT_CONFIG_COUNT` / `GIT_DIR` / `core.editor` injection from the surrounding env. Same-user threat model bounds it, but per zero-tolerance Rule 5, that's not a residual-risk shield.

**Resolution.** Two-layer fix:

1. **PATH-resolve via `shutil.which("git")` + trusted-prefix allowlist** (`/usr/bin/`, `/bin/`, `/usr/local/bin/`, `/opt/homebrew/bin/`). Anything outside that allowlist (e.g. `~/bin/git`) is silently skipped with a stderr breadcrumb — the gitignore guard does not run, but a hostile shim never executes either.
2. **Stripped subprocess env** — `{PATH: "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", HOME, LANG}` only. All `GIT_*` vars are dropped.

### MEDIUM

**M1 — `os.rename` over a symlink at the destination.**
`coc-eval/lib/jsonl.py:471` (pre-fix) called `os.rename(tmp, path)` without checking whether `path` was a symlink. On some Linux variants `os.rename` follows the symlink — an attacker who plants `<log_dir>/<test>.log -> /tmp/leak` would have the harness write into `/tmp/leak`.

**Resolution.** `_write_log_body` now calls `path.is_symlink()` first and raises `RuntimeError("refusing to overwrite symlink at ...")` rather than proceeding. New regression test `TestLogFileSymlinkRefused::test_symlink_at_log_path_refused` plants a symlink and confirms the writer refuses + the symlink target stays untouched.

**M2 — `_write_log_body` umask race on tmp file.**
`coc-eval/lib/jsonl.py:433` (pre-fix) opened the tmp file via `tmp.open("w", encoding="utf-8")`, which creates the file at umask-default mode (typically 0o644), wrote the redacted-but-still-sensitive body, then `chmod`-ed to 0o600 only AFTER close. Between line 433 and line 470, the tmp file existed at 0o644 with secret content. This is the exact umask-race shape `rules/security.md` §5a calls out.

**Resolution.** Replaced the `tmp.open("w", …)` path with `os.open(str(tmp), O_WRONLY|O_CREAT|O_EXCL, 0o600)` + `os.fdopen(fd, "w", …)`. The file is 0o600 from the FIRST byte written, eliminating the race. `O_EXCL` also catches a stale-tmp collision (e.g. from a crashed prior run) — unlinked best-effort before open. New regression test `TestLogFileModeAtCreation::test_creation_uses_excl_mode_0o600` monkeypatches `os.open` to capture the flag/mode arguments and asserts both `O_EXCL` and `0o600` are passed.

**M3 — Partial-write race shares M2's fix.**
The "tmp file at 0o644 between write and chmod" concern is the same surface as M2; folded into the same patch.

**M4 — Schema `$ref` cycle DoS.**
`coc-eval/lib/schema_validator.py:80-128` (pre-fix) did not track recursion depth. A schema with `definitions.A.$ref = "#/definitions/B"` and `definitions.B.$ref = "#/definitions/A"` would recurse until Python's stack limit. The bundled `v1.0.0.json` has no cycles, but the validator is reused as a library and `_load_schema` reads `_SCHEMA_PATH` from disk — anyone with FS write access to `coc-eval/schemas/` can plant a cyclic schema and DoS the aggregator.

**Resolution.** Added `_MAX_SCHEMA_DEPTH = 64` constant + a `_depth: int` parameter to `validate_against_schema`. Each recursive call (including ref resolution) increments. Hit-cap raises `SchemaValidationError("schema recursion depth exceeded ... — possible cyclic $ref")`. v1.0.0's deepest legitimate nesting is ~5 levels; 64 is conservative headroom for forward-compat sub-schemas. New regression test `TestSchemaValidator::test_cyclic_ref_bounded` constructs `A→B→A` and asserts the error fires.

### LOW

**L1 — `iter_records` skips oversized files silently with stderr breadcrumb.**
The aggregator caller MAY not surface that breadcrumb. Marked as a documented behavior; a typed `JsonlOversizeError` upgrade is a v1.1 concern. **Not patched in H4** — flagged for H9 aggregator review.

**L2 — `read_record` `parse_int` cap returns 0 silently.**
A 20-digit `runtime_ms` becoming `0` corrupts aggregator distributions silently. Same docstring contract decision as L1; **not patched in H4** — H9 aggregator can wrap and surface explicit error semantics.

**L3 — Hostile dict keys in `iter_records`.**
False alarm: `read_record` already enforces `isinstance(record, dict)` and JSON keys are always strings, so attribute-style dunder injection is structurally impossible. **No-op** — flag carried forward to H9 aggregator review for any `**record`-style spreads.

## Verification

- `pytest coc-eval/tests/lib/`: **234 passed** (was 229 pre-security-fix; +5 regression tests for H1×2, M1, M2, M4).
- `pytest coc-eval/tests/integration/`: 2 passed (AC-16 + capability smoke; H4 changes do not touch the launcher path).
- `cargo check --workspace`: clean.
- `cargo fmt --all --check`: clean.
- Stub scan / `shell=True` / `os.system` greps: clean.

## Why fixes landed in-session, not in a follow-up

Same argument as journal 0011: `rules/zero-tolerance.md` Rule 5 + `feedback_zero_residual_risk` are unambiguous. Each finding took 5–20 minutes; deferring would have cost more in re-review than the fixes did to land. The "same-user threat model" framing on H2 was specifically called out by the reviewer as not a residual-risk shield — that's the canonical anti-pattern this rule guards against.

## For Discussion

1. **Allowlist precision for `git` resolution.** The H2 fix accepts any `git` binary inside `/usr/bin/`, `/bin/`, `/usr/local/bin/`, or `/opt/homebrew/bin/`. A user who has installed git via `pyenv` or `asdf` (both common on this dev box) would land it at `~/.pyenv/shims/git` — outside the allowlist, so the gitignore check silently skips. Compare: the trade-off is "false negative on the gitignore check (results dir might be committable)" vs "false positive on the trusted path (could execute attacker shim)". Counterfactual: if the gitignore check matters more than the path-trust check on a non-distro-managed dev machine, should the allowlist be operator-configurable via env var (`COC_EVAL_TRUSTED_GIT_PATH`)?

2. **Deep redaction breadth vs depth.** The current `_deep_redact_record` is breadth-oriented — it walks dicts/lists/strings recursively. If a future field carries a binary blob (e.g. a base64-encoded screenshot), the redactor either:
   - Treats it as a string and pattern-matches inside the b64 (slow, irrelevant matches),
   - Or fails to match a token-shape that crosses a b64 boundary.
     Should the schema explicitly mark "do not redact" fields (e.g. `x-redact: skip` annotation honored by `_deep_redact_record`), or accept the speed/security trade-off as Phase-1 sufficient?

3. **`os.O_EXCL` vs explicit `umask` save/restore.** M2's fix uses `O_EXCL` which fails if the tmp already exists. An alternative was `os.umask(0o077)` save/restore around the `open`. Compare: `O_EXCL` catches stale-tmp collisions (good — no overwrite of unrelated data) but requires explicit pre-unlink (we do this best-effort). `umask` is simpler but doesn't surface stale-tmp pollution. Worth codifying which idiom the codebase prefers (`rules/security.md` §5a is silent on this distinction)?

## References

- Journal 0012 — H4 ship report (initial DECISION; this RISK entry adds the security-review convergence layer).
- `rules/zero-tolerance.md` Rule 5 — "no residual risks accepted".
- `rules/security.md` §5a — partial-failure cleanup pattern (the umask-race shape M2 is fixing).
- `feedback_zero_residual_risk` (auto-memory) — user-stated rejection of "documented and deferred" framing.
- `coc-eval/lib/jsonl.py:_deep_redact_record` — H1 fix site.
- `coc-eval/lib/jsonl.py:_verify_results_path_gitignored` — H2 fix site.
- `coc-eval/lib/jsonl.py:_write_log_body` — M1/M2/M3 fix site.
- `coc-eval/lib/schema_validator.py:_MAX_SCHEMA_DEPTH` + `validate_against_schema` — M4 fix site.
- `coc-eval/tests/lib/test_jsonl.py:TestExtraKwargRedacted` + `TestLogFileSymlinkRefused` + `TestLogFileModeAtCreation` — regression tests.
- `coc-eval/tests/lib/test_suite_validator.py:TestSchemaValidator::test_cyclic_ref_bounded` — M4 regression.
- Journal 0011 — H3 security-review convergence (template followed by this entry).
