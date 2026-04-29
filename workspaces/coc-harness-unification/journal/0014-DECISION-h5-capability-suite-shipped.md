---
type: DECISION
date: 2026-04-29
created_at: 2026-04-29T14:00:00Z
author: agent
session_id: 69c9c519-6759-4e17-a84d-d9156f2cab95
session_turn: 12
project: coc-harness-unification
topic: H5 capability suite + runner orchestrator + run.py argparse shipped
phase: implement
tags: [h5, capability, runner, argparse, sigint, resume, ci-workflow]
---

# H5 — Capability suite shipped (cc end-to-end)

The harness contract is now end-to-end on cc: launcher + auth probe +
JSONL writer + capability SUITE dict + retry-once + token-budget +
SIGINT/INTERRUPTED.json + resume + argparse + CI workflow. The H5 gate
("`coc-eval/run.py capability --cli cc` produces 4 JSONL records;
C1-C4 all pass") is live.

## What landed

**Code:**

- `coc-eval/suites/capability.py` — SUITE dict v1.0.0 with C1-C4 ported
  from loom `suites/capability.mjs`. Per-CLI fixture mapping for C1/C2;
  shared fixture for C3/C4. Phase 1: cc only runs; codex/gemini cells
  populated structurally so H10/H11 don't refactor.
- `coc-eval/suites/__init__.py` — `SUITE_REGISTRY` static dict (NOT
  glob — CRIT-03 fix).
- `coc-eval/lib/runner.py` — top-level orchestrator. `score_regex`,
  `RunSelection`, `RunContext`, `ProgressEmitter` (pretty/jsonl/json),
  `run_test_with_retry` (INV-DET-1), `_check_token_budget` (INV-RUN-7),
  `install_sigint_handler` + `_write_interrupted` (R3-CRIT-02),
  `parse_resume` + `read_interrupted` (FR-13), `list_profiles` (FR-19),
  `_print_zero_auth_banner` (AC-32 / exit 78).
- `coc-eval/run.py` — argparse entry. Positional suite, `--cli`,
  `--test`, `--skip-cli`, `--skip-suite`, `--validate`, `--tag`,
  `--format`, `--resume`, `--list-profiles`, `--token-budget-{input,output}`,
  `--results-root`. UX-13 cases A-E. AC-45 first/last stdout `run_id=`.
- `coc-eval/lib/jsonl.py` — `_verify_results_path_gitignored` now passes
  a `<results>/.gitignore-probe` sub-path to `git check-ignore` instead
  of the directory itself. Pre-existing pattern bug surfaced when the
  harness first tried to write under `coc-eval/results/`; fixed in-PR
  per zero-tolerance Rule 1.

**Tests (48 new, total 287):**

- `tests/lib/test_runner_score.py` — `score_regex` + selection resolution.
- `tests/lib/test_runner_progress.py` — pretty/jsonl format, monotonic
  ETA (AC-34).
- `tests/lib/test_runner_resume.py` — INTERRUPTED.json round-trip +
  parse_resume semantics.
- `tests/lib/test_runner_token_budget.py` — INV-RUN-7 boundary cases.
- `tests/lib/test_argparse.py` — UX-13 cases A-E + `--validate` paths +
  H5-A-4 unknown-flag pinning.
- `tests/lib/test_cli_registry.py` — AC-42 noop_cli registration via
  `monkeypatch.setitem` (H5-T-5).
- `tests/lib/test_init_overhead.py` — AC-25 ≤5s init overhead.
- `tests/lib/test_jsonl_gitignore_probe.py` — H5-T-9 covers the jsonl.py
  probe-path change against a controlled tmp git repo.
- `tests/integration/test_capability_cc.py` — H5 gate against real cc.
  Bounded env, `--results-root tmp_path`, `validate_run_id` on parsed
  stdout, try/finally + onexc cleanup.
- `tests/integration/test_zero_auth_first_run.py` — AC-32 banner exit 78.
- `tests/integration/test_resume_smoke.py` — INTERRUPTED.json on-disk shape.
- `tests/integration/test_flake_discrimination.py` — AC-18 5/5 deterministic.
- `tests/integration/conftest.py` — autouse `auth.reset_cache` for every
  integration test (H5-T-6).

**CI:**

- `.github/workflows/coc-harness.yml` — PR-triggered on
  `coc-eval/`, `csq-core/`, `coc-env/`, `.claude/rules/`. Runs lib pytest +
  non-cc integration tests + grep guards (`SUITE_MANIFEST` authority,
  no-glob, `shell=True`, fixture-substitution stub, scaffold-injection
  stub, no-bare-print) + pyright. `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`
  (H5-T-7).

## Security review — round 1 (3 parallel agents) + round 2 (1 focused)

**Round 1** spawned three parallel `security-reviewer` agents per the
H3/H4 precedent + memory `feedback_redteam_efficiency`. Findings:

| Agent               | CRITICAL | HIGH  | MEDIUM | LOW    |
| ------------------- | -------- | ----- | ------ | ------ |
| Runner orchestrator | 0        | 1     | 2      | 4      |
| Argparse + run.py   | 0        | 0     | 3      | 8      |
| Tests + CI + jsonl  | 0        | 4     | 5      | 4      |
| **Total**           | **0**    | **5** | **10** | **16** |

**Convergence policy** (zero-tolerance Rule 5): every finding above LOW
fixed in-PR; LOW items fixed when trivial. All 31 findings resolved.

Highlights:

- **H5-R-1 (HIGH)** — `cwdSubdir` resolved path was not re-anchored to
  the fixture root after `Path.resolve()` followed the symlink. A
  same-user attacker planting `<fixture>/<sub>` as a symlink to `/etc`
  redirected cc's cwd. Fix: `target_cwd.relative_to(fixture_root_resolved)`.
- **H5-T-1 (HIGH)** — integration tests parsed `run_id=` from cc stdout
  and passed it directly to `shutil.rmtree`. Garbage / empty / `..`
  tokens would have wiped sibling run dirs. Fix: `validate_run_id`
  before any filesystem use.
- **H5-T-2 (HIGH)** — integration tests inherited `**os.environ`,
  passing `ANTHROPIC_LOG`/`CLAUDE_TRACE`/`CLAUDE_DEBUG`/API keys to cc.
  Fix: explicit allowlist (PATH/HOME/LANG + optional CLAUDE_CONFIG_DIR).
- **H5-T-3 (HIGH)** — integration tests wrote to `coc-eval/results/`
  on the developer tree. Fix: added `--results-root` flag; tests pass
  `tmp_path / "results"`. Concurrent test invocations no longer collide.
- **H5-T-4 (HIGH)** — CI grep guards omitted `coc-eval/tests/`. A test
  introducing `subprocess.run(..., shell=True)` would not be caught.
  Fix: extended every guard (shell=True, fixture-substitution,
  scaffold-injection) to cover tests.

**Round 2** spawned one focused `security-reviewer` (per
`feedback_redteam_efficiency`: switch to single agent by round 3).
Verified all round-1 fixes sound. One new LOW: `_redact_for_terminal`
preserved `\n` (line-forging vector for future probe authors). Fixed
in-PR by widening regex to `[\x00-\x1f\x7f]`.

## Key invariants validated

- **INV-DET-1 (retry-once)**: C3-pathscoped-canary observed flake-prone
  on cc (model-version dependent — H5 todo's risk section). Live test
  run captured `pass_after_retry` → confirms the retry path fires and
  records correctly. C1, C2, C4 are deterministic.
- **INV-PERM-1 (permission-mode authority)**: every spawn passes through
  `assert_permission_mode_valid`; mismatches hard-panic at spawn time.
- **INV-AUTH-3 (re-probe on stderr)**: the runner scans stderr for
  `auth_error` patterns and clears the cache (capped at 200 lines —
  H5-R-7).
- **INV-RUN-3 (process group kill)**: `start_new_session=True` +
  `os.killpg(SIGTERM)` → grace → `SIGKILL`. Verified via timeout path.
- **INV-RUN-7 (token budget)**: `_check_token_budget` short-circuits
  before each test; `_accumulate_tokens` is defensive (H5-R-4).
- **INV-ISO-5 (fresh fixture per attempt)**: every retry calls
  `prepare_fixture` fresh; `verify_fresh` rejects stale dirs.
- **INV-ISO-6 (credential symlink integrity)**: every spawn revalidates
  the credential symlink before exec (`launcher.spawn_cli`).
- **MED-04 (results dir gitignore)**: `_verify_results_path_gitignored`
  now uses a probe sub-path so the directory pattern (`<dir>/`) matches
  correctly. New unit test covers both ignored and unignored shapes.

## H5 gate — verified live

```
$ python coc-eval/run.py capability --cli cc
run_id=2026-04-29T13-46-45Z-11043-0000-nhEkm7lt
{"kind":"progress","event":"running",...}
{"kind":"progress","event":"terminal","test":"C1-baseline-root","state":"pass","runtime_ms":5856}
{"kind":"progress","event":"terminal","test":"C2-baseline-subdir","state":"pass","runtime_ms":6057}
{"kind":"progress","event":"terminal","test":"C3-pathscoped-canary","state":"pass_after_retry","runtime_ms":24191}
{"kind":"progress","event":"terminal","test":"C4-native-subagent","state":"pass","runtime_ms":28683}
run_id=2026-04-29T13-46-45Z-11043-0000-nhEkm7lt
```

5 records on disk (1 header + 4 tests), schema v1.0.0 valid,
`cli_versions = {"cc": "2.1.123 (Claude Code)"}`. AC-45 first/last
stdout lines both contain `run_id=`.

## Test counts

- Lib pytest: 234 (H4 baseline) → **287** (+53 H5)
- Integration (non-cc-spawning): 4 (H4 baseline) → **8** (+4 H5)
- Integration (cc-spawning): 2 → **2** (H3 smoke + H5 capability gate;
  same H5 file replaces no prior tests)

## What's next (H6)

H5 unblocks H6 (compliance suite). Compliance reuses the same orchestrator
(`run_suite`, `run_test_with_retry`, `score_regex`) and the same SUITE
schema. Per the implementation plan, H6 ports CM1-CM9 from
loom `suites/compliance.mjs` and adds compliance-specific rubric
extensions (declarative-rule citation scoring).

H10/H11 (codex/gemini launcher registration) become the next "register
a new CLI" exercise — AC-42 stub `noop_cli` already proves the
mechanism works without launcher-table edits.

## Cross-references

- todo: `workspaces/coc-harness-unification/todos/active/H5-capability-suite.md`
- plan: `workspaces/coc-harness-unification/02-plans/01-implementation-plan.md` §H5
- launcher contract: `workspaces/coc-harness-unification/01-analysis/05-launcher-table-contract.md`
- schema: `coc-eval/schemas/v1.0.0.json` + `suite-v1.json`
- prior: 0010 (H3), 0011 (H3 review), 0012 (H4), 0013 (H4 review)

## For Discussion

1. The C3-pathscoped-canary test is informational on cc per the H5
   todo's risk section — but the integration test now strictly enforces
   pass on C1/C2/C4 and treats C3 as informational (only the score
   shape is checked). When H10/H11 land codex/gemini, C3 becomes a
   genuine failure for those CLIs (canary should be ABSENT). Should we
   revisit and require a positive C3 result on at least one CLI for
   future PRs, or is "informational on every CLI" the right phase-1
   stance?

2. Counterfactual: if we had skipped the round-1 parallel review and
   gone straight to round-2 single agent, the 4 HIGH findings in tests
   (T-1 through T-4) would have surfaced eventually but probably not
   before merge — the runner-orchestrator agent saw only `lib/runner.py`
   in its scope and the test agent's findings were specific to the
   cc-spawning subprocess invocation. The 3-parallel pattern remains
   the right round-1 strategy for any PR with substantial test code.

3. The `--results-root` flag was added to enable test isolation (H5-T-3).
   That flag is now operator-facing too — operators can redirect
   results anywhere. Should we restrict its acceptable values (e.g.,
   reject system paths like `/etc`, `/var`, `/usr`) or accept the
   current "operator owns the path" trust boundary? Production usage
   is overwhelmingly `coc-eval/results/` (default); the flag is a
   tests-and-CI affordance.
