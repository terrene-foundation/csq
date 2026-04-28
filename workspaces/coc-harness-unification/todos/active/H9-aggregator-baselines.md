# H9 — Aggregator + run-id scoping + baselines + hardening

**Goal.** Run-scoped Markdown matrix with baseline-gating, partial-coverage banner, JSON-bomb defenses, markdown-injection escape.

**Depends on:** H1, H4 (JSONL schema + readers), H5-H8 (suites producing JSONL).

**Blocks:** H10, H11 (CI gate uses aggregate baseline).

## Tasks

### Build — aggregator core

- [ ] Create `coc-eval/aggregate.py`:
  - Reads `results/<run_id>/*.jsonl` (default: latest run).
  - `--since 7d` for cross-run aggregation (parses ISO durations).
  - `--validate` runs schema validation against the HEADER's stated `schema_version` (forward-compat per UX-17 / AC-46).
  - `--full` flag refuses partial runs unless `--allow-partial` (UX-19 / AC-48).
  - Markdown output: `(test × cli × runs)` matrix with pass-rate, p50 runtime, state distribution.
  - Footer: `Total: N records, M failures, K quarantined; rerun with --failed-only for short list.`

### Build — JSON-bomb defenses

- [ ] Per-file size cap (10MB → skip with warning).
- [ ] Per-record byte cap (100KB hard reject).
- [ ] Bounded int parsing: `json.loads(line, parse_int=lambda s: int(s) if len(s) < 20 else 0)`.
- [ ] Use `json.JSONDecoder.raw_decode` with byte-budget for files >1MB.
- [ ] Explicit handling: `try/except RecursionError, MemoryError, OverflowError`.

### Build — Markdown-injection escape

- [ ] Use `escape_md(s)` from H4 jsonl.py on EVERY string field consumed for Markdown emission (test name, fixture name, error reason, prompt excerpt).
- [ ] Drop `cmd` field rendering — operators read `cmd_template_id` and look up the launcher table; or read the `.log` file.

### Build — baselines.json mechanism

- [ ] Create `coc-eval/baselines.json` (committed):
  ```json
  {
    "(implementation, cc, opus-4-7)": {
      "min_tests_passing": 35,
      "min_total_score": 35,
      "max_total_score": 50
    },
    "(compliance, codex, default)": { "min_tests_passing": 7, "max_tests": 9 },
    "(compliance, gemini, default)": { "min_tests_passing": 6, "max_tests": 9 }
  }
  ```
- [ ] `--gate baseline` flag: aggregate exits non-zero if any cell falls below baseline (AC-40).
- [ ] SUMMARY.md "Baseline status" section per (suite, cli) showing PASS / at-floor / regression.

### Build — partial-coverage banner

- [ ] If "latest run" was scoped (subset of suites or CLIs), print:
  ```
  WARN: latest run (run_id=X) covered only suite=compliance, cli=cc.
        Reporting on that subset. For full matrix:
          aggregate.py --since 7d --full
  ```
- [ ] `--full` flag asserts every (suite, cli) pair in the manifest has at least one record; fails otherwise.

### Build — flaky/quarantine support

- [ ] `quarantined: true` test attribute: aggregator counts these in a separate "Quarantine" section; default skip; `--include-quarantined` runs them (UX-10 / AC-41).
- [ ] State `skipped_quarantined` rendered with distinct symbol (per state legend in user-flows).

### Build — additional flags (UX-05)

- [ ] `--top N` (default 50): cap rows by recency.
- [ ] `--regressions-only`: rows where pass-rate dropped vs prior 7d window.
- [ ] `--failed-only`: rows with at least one `state ∈ {fail, error_*}`.
- [ ] `--format pretty | json | csv | md` (default md).

### Build — auto-quarantine cron workflow (FR-14, R3-MED-03)

- [ ] Create `.github/workflows/auto-quarantine.yml`:
  - `cron: '0 3 * * 1'` — Monday 03:00 UTC weekly.
  - Steps: run each test 5× via `coc-eval/run.py <suite> --cli all --test <id>`; compute pass-rate per test.
  - For tests with pass-rate <80%: open a PR flipping `quarantined: true` for that test in its suite definition.
  - Includes rationale + 5-trial result in PR description (per FR-14 / journal-entry attached to exit-quarantine flow).
- [ ] `coc-eval/scripts/quarantine-flip.py` helper invoked by the workflow.

### Build — schema fwd-compat test (AC-46)

- [ ] Commit a v1.0.0 sample fixture at `coc-eval/tests/fixtures/sample-v1.0.0.jsonl`.
- [ ] `coc-eval/tests/integration/test_schema_compat.py`: invokes `aggregate.py` reading the fixture; asserts clean Markdown matrix without warnings or errors.

### Test

- [ ] `coc-eval/tests/lib/test_aggregate.py`:
  - `test_md_injection_canary`: input record with `test_name = '|<a href=javascript:alert(1)>x</a>|'` → escaped output (AC-8a).
  - `test_jsonbomb_size`: 10.1MB JSONL file → skipped with warning (AC-8b).
  - `test_jsonbomb_int`: line with 25-digit int → bounded parse (AC-8b).
  - `test_baseline_gate_below`: synthetic record with score below baseline; `--gate baseline` exits non-zero (AC-40).
  - `test_partial_coverage_banner`: single-suite run produces WARN banner (AC-48).
  - `test_regressions_only`: 14d × 5 tests × 1 CLI returns ≤20 rows on stable codebase (AC-37).

## Gate

- AC-8 markdown matrix produced from clean run.
- AC-6 schema validation passes on last 100 records.
- AC-8a injection canary green.
- AC-8b JSON-bomb tolerance green.
- AC-46 schema fwd-compat green.
- AC-40 baseline gate exits non-zero on synthetic regression.

## Acceptance criteria

- AC-6, AC-8, AC-8a, AC-8b
- AC-37 (regressions-only ≤20 rows)
- AC-39 (every new test has baseline row in same PR — process check; tracked via PR description template)
- AC-40 (aggregate exit code reflects baseline parity)
- AC-46 (schema fwd-compat)
- AC-48 (partial-coverage banner)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H9 <summary>`
- [ ] Branch name `feat/coc-harness-h9-aggregator`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

The baseline-gating mechanism is operationally important but easy to get wrong. A bad baseline (set too lenient) lets regressions through; a bad baseline (set too strict) creates false-positive CI red. Initial baselines should encode current passing scores, not aspirational ones; bumps require explicit PR + journal entry.
