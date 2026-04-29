---
type: RISK
date: 2026-04-29
created_at: 2026-04-29T22:15:00+08:00
author: agent
session_id: 69c9c519-6759-4e17-a84d-d9156f2cab95
session_turn: 14
project: coc-harness-unification
topic: H5 security review rounds — 5 HIGH + 10 MEDIUM + 17 LOW resolved in-PR (rounds 1 + 2)
phase: implement
tags:
  [
    h5,
    security,
    redteam,
    convergence,
    runner,
    argparse,
    sigint,
    cwdsubdir,
    subprocess-env,
    zero-tolerance,
  ]
---

# RISK — H5 security review rounds (parallel + focused) + same-session resolution

`security-reviewer` audited the H5 capability suite + runner + run.py + tests + CI workflow before commit. Round 1 spawned three parallel agents (per `feedback_redteam_efficiency`): one on the runner orchestrator, one on argparse + suite loader, one on tests + CI + the H5 jsonl gitignore-probe change. Round 2 ran a single focused agent over the convergence patches. Per `rules/zero-tolerance.md` Rule 5 every above-LOW finding was resolved in this same /implement cycle BEFORE the PR opened; LOW items were also fixed when trivial.

## Findings + resolutions (round 1)

**Verdict:** 0 CRITICAL, 5 HIGH, 10 MEDIUM, 16 LOW across 3 agents.

### HIGH (5)

- **H5-R-1** — `_run_one_attempt` `cwdSubdir` resolved path was not re-anchored to the fixture root after `Path.resolve()` followed the symlink. Same-user attacker planting `<fixture>/<sub>` as a symlink to `/etc` would redirect cc's cwd. **Fix:** `target_cwd.relative_to(fixture_root_resolved)` after `.resolve()`.
- **H5-T-1** — integration tests parsed `run_id=` from cc stdout and passed it directly to `shutil.rmtree`. Empty / `..` / garbage tokens would have wiped sibling run dirs. **Fix:** `validate_run_id(run_id)` (RUN_ID_RE) before any filesystem use.
- **H5-T-2** — integration tests inherited `**os.environ`, passing `ANTHROPIC_LOG`/`CLAUDE_TRACE`/`CLAUDE_DEBUG`/API keys to cc. **Fix:** explicit allowlist (`PATH`, `HOME`, `LANG`, `LC_*`, optional `CLAUDE_CONFIG_DIR`).
- **H5-T-3** — integration tests wrote to `coc-eval/results/` on the developer tree; concurrent test invocations could collide. **Fix:** added `--results-root` flag to `run.py`; tests pass `tmp_path / "results"`.
- **H5-T-4** — CI grep guards omitted `coc-eval/tests/`. A test introducing `subprocess.run(..., shell=True)` would not be caught. **Fix:** extended every guard (`shell=True`, fixture-substitution, scaffold-injection) to cover tests.

### MEDIUM (10)

- **H5-A-1** — `list_profiles` printed unsanitized `name` and `model` (control-char / ANSI smuggling via attacker-influenced `~/.claude/settings-*.json`). **Fix:** `validate_name(raw_name)` + `_PROFILE_MODEL_RE.fullmatch(m)`; invalid values become `<invalid-profile-name>` / `<invalid>` literals.
- **H5-A-2** — `list_profiles` followed symlinks under `~/.claude/settings-*.json`. **Fix:** `entry.is_symlink()` short-circuits with stderr warning before `read_text()`.
- **H5-A-3** — `_resolve_format`'s `sys.stdout.isatty()` raises `ValueError`/`OSError` on closed-or-detached stdout (sandbox / nohup patterns). **Fix:** try/except returns "jsonl" on failure.
- **H5-R-2** — `parse_resume` used unvalidated `in_flight_suite` from INTERRUPTED.json as a glob component. **Fix:** `validate_suite_name` before `run_dir.glob`.
- **H5-R-3** — `_write_interrupted` did not check whether `path.parent` was a symlink. **Fix:** `parent.exists() and parent.is_symlink()` short-circuit before `mkdir`.
- **H5-T-5** — `test_cli_registry` mutated global `CLI_REGISTRY` with try/finally restoration; assertion-fail or interrupt could leave the registry mocked. **Fix:** `monkeypatch.setitem` (auto-restore on raise).
- **H5-T-6** — autouse `reset_auth_cache` lived in one test file; sibling integration tests' `_AUTH_CACHE` could be poisoned by an earlier probe. **Fix:** moved to `tests/integration/conftest.py`.
- **H5-T-7** — CI did not pin `PYTEST_DISABLE_PLUGIN_AUTOLOAD`. **Fix:** set `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` on every pytest step.
- **H5-T-8** — `.gitignore` had a redundant bare `coc-eval/results` line that could match a file by that name. **Fix:** dropped; only `coc-eval/results/` (trailing slash) remains. Combined with the gitignore-probe fix in `lib/jsonl.py`.
- **H5-T-9** — no unit test for `_verify_results_path_gitignored`. **Fix:** new `tests/lib/test_jsonl_gitignore_probe.py` exercises ignored / unignored / no-repo / trusted-prefix-skip shapes against a controlled tmp git repo.

### LOW (16)

- **H5-R-4** — `_accumulate_tokens` could crash on malformed `tokens` field. **Fix:** isinstance guard + try/except.
- **H5-R-5** — `read_interrupted` did unbounded read + followed symlinks. **Fix:** 64 KiB cap + `is_symlink()` reject.
- **H5-R-6** — `parse_resume` did not refuse a symlinked run dir. **Fix:** explicit `is_symlink()` check.
- **H5-R-7** — stderr auth-error scan had no line cap. **Fix:** capped at 200 lines.
- **H5-A-4** — confirmed argparse `e.code` handling. Added `test_unknown_flag_maps_to_64`.
- **H5-A-5** — `_split_csv` defense-in-depth — tokens now go through `validate_name` before closed-set lookup.
- **H5-A-6** — `_print_zero_auth_banner` redacts strings via `_redact_for_terminal` (control-char strip + 400-byte cap).
- H5-A-7 through H5-A-11 — confirmed-no-action (ToCToU on `--resume`, closed-set traversal, ReDoS, ASCII-only prompts, banner-write paths).
- **H5-T-10** — `shutil.rmtree(..., ignore_errors=True)` masked failures. **Fix:** `onexc=` callback that surfaces failures via stderr.
- **H5-T-11** — first integration test had no try/finally around rmtree. **Fix:** wrap both tests in try/finally.
- H5-T-12 — bubblewrap install deferral; left as-is for future workflows.
- **H5-T-13** — dangling comment at end of `test_argparse.py`. **Fix:** replaced with `test_unknown_flag_maps_to_64`.

## Findings + resolutions (round 2)

Round 2 verified all round-1 fixes sound (file-by-file), and surfaced one new LOW:

- **H5-R2-1** — `_redact_for_terminal` regex preserved `\n` (line-forging vector for future probe authors). **Fix:** widened to `[\x00-\x1f\x7f]` (full C0 + DEL).

R2-2/R2-3/R2-4/R2-5 were noted as bounded-by-same-user-threat-model or non-security UX — no action.

## Convergence verdict

All above-LOW findings resolved in-PR. Five rounds total of harness-pattern proof: H3 had 1 HIGH + 3 MEDIUM, H4 had 2 HIGH + 4 MEDIUM, H5 had 5 HIGH + 10 MEDIUM. The HIGH/MEDIUM count grew with surface area (orchestrator + argparse + tests + CI) but the convergence policy held — every PR ships clean.

Lib pytest 234 → 287; cc integration tests green; cargo + clippy + fmt + svelte-check + vitest + stub scan + pyright all clean. PR #220 merged at commit `4ca8461`.

## For Discussion

1. The 3-parallel-then-1-focused review pattern is paying for itself: the test/CI agent in round 1 found 4 HIGH that the runner-orchestrator agent could not have surfaced (different scope). For PRs with substantial test code, parallelism in round 1 is the right default. Should we codify "parallel rounds 1, focused rounds 2+" as a rule in `agents.md` for future security reviews, or keep it as an emergent pattern?

2. Counterfactual: if H5 had landed without the `--results-root` flag (T-3), the integration test would have written to the developer's `coc-eval/results/` and concurrent runs would have collided. The fix added an operator-facing flag. Is the trust boundary right (operator owns the path, including system paths like `/etc`), or should we restrict acceptable values to a tmp-or-default-only allowlist?

3. The pattern of writing both 00NN-DECISION (ship) and 00NN+1-RISK (security findings) per PR (H3 → 0010+0011, H4 → 0012+0013, H5 → 0014+0015) makes the journal trail dense but very searchable. Should the H6+ entries follow the same pattern, or fold the security review section into the DECISION entry once a finding count drops below a threshold?
