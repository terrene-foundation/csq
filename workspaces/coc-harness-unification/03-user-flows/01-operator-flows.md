# Operator Flows

User = an operator (human or CI) running the consolidated harness from `csq/coc-eval/`. All flows assume Phase 1 ship (PRs H1–H13 merged).

## Flow A — Run everything before a release cut

**Trigger:** `/release` skill checklist requires "harness green" before tag push.

**Actor:** Foundation maintainer or release-bot.

```
$ cd ~/repos/terrene/contrib/csq
$ coc-eval/run.py all
```

**What happens:**

1. Run-id allocated: `2026-04-28T19-34-21Z-9k2f3`. `results/<run_id>/` created.
2. Auth probes run for all three CLIs. JSONL header records `auth_probes`. If any CLI fails probe, that CLI's tests record `skipped_cli_auth`; harness continues.
3. Suites run in fixed order: compliance → safety → capability → implementation. (Suite-ordering rule: non-write suites first, write suite last to prevent residue contamination — HIGH-03.)
4. Per suite × per CLI: tests stream to stdout as JSONL; full logs persist under `results/<run_id>/`.
5. Implementation × {codex, gemini} cells emit `state: skipped_artifact_shape` (Phase 1 cc-only per ADR-B).
6. On completion: `aggregate.py` (auto-invoked unless `--no-aggregate`) emits `results/<run_id>/SUMMARY.md` with the parity matrix.
7. Exit code: 0 if all non-skipped pass; 1 if any non-skipped fails; 2 if harness errored.

**Operator reads:** `results/<run_id>/SUMMARY.md`. Looks for: pass-rates per suite per CLI, any `error_*` states (harness bugs), any unexpected `skipped_*` (CLI/auth issues to triage before release).

**Failure modes & recovery:**

- Auth probe fails for a CLI → run `claude login N` / `codex login` / `gemini auth login` and retry.
- Score regression on implementation suite → diff against last clean run (`aggregate.py --since 7d`); investigate before tagging.
- Quota exhaustion mid-run → harness records `skipped_quota`; rerun the affected suite later.

## Flow B — Iterating on a single suite during development

**Trigger:** Editing a fixture or adding a test in `compliance` suite.

**Actor:** developer.

```
$ coc-eval/run.py compliance --cli cc
```

**What happens:**

1. Only compliance suite runs; only on cc.
2. ~9 tests; ~7-10 minutes wall-clock; one JSONL + one .log per test.
3. Aggregate auto-invoked, scoped to this run.

**Operator reads:** stdout for live progress + `results/<run_id>/SUMMARY.md`. The pass-rate and per-test failure reasons surface immediately.

**Common variation:** `--cli all` after the cc baseline is green, to verify no codex/gemini regression.

## Flow C — Debugging one flaky test

**Trigger:** A test reads `pass_after_retry` consistently in CI.

**Actor:** developer.

```
$ coc-eval/run.py compliance --cli gemini --test CM7-outcomes-not-implementation
```

**What happens:**

1. Single test runs once.
2. Full prompt, cmd, env, stub_home path written to JSONL + .log.
3. Operator inspects `results/<run_id>/gemini-compliance-CM7-outcomes-not-implementation.log` — full stdout/stderr (token-redacted), exact cmd, runtime breakdown.

**Operator reads:** the .log file. Diffs against a previous run's log to identify model drift vs prompt issue vs scoring criterion mismatch.

**Common variation:** repeat 5× with `--test` to measure flake rate (INV-DET-3 quarantine threshold = ≥80% pass rate).

## Flow D — Running implementation eval against a non-default model

**Trigger:** Foundation publication needs MiniMax M2.7 score against COC implementation suite.

**Actor:** Foundation evaluator.

```
$ coc-eval/run.py implementation --profile mm --cli cc --label "MiniMax M2.7"
```

**What happens:**

1. `--profile mm` overlays `~/.claude/settings-mm.json` onto base settings (CRIT-02 path-traversal blocked at argparse).
2. `ANTHROPIC_*` env scrub ensures profile settings.json is sole router.
3. Implementation suite runs on cc with MiniMax routing. Capability/compliance/safety suites refuse `--profile` (ADR-C: profiles are CC-implementation-only).
4. Exit-1 if `coc-eval/run.py compliance --profile mm` (rejects with: "profiles are CC-implementation-only; codex/gemini models are selected via their own configs").
5. Output: standard JSONL + ablation-aware aggregate showing COC-vs-bare delta.

**Operator reads:** `aggregate.py --run <run_id>` Markdown matrix; the `delta` column is the value-add measurement.

**Common variation:** `--mode ablation --ablation-group no-rules` to measure the rules layer's specific contribution.

## Flow E — Skipping a CLI temporarily

**Trigger:** Gemini quota exhausted; operator wants to ship the cc/codex slice anyway.

**Actor:** developer or release-bot.

```
$ coc-eval/run.py all --skip-cli gemini
```

**What happens:**

1. Gemini-specific records record `state: skipped_user_request`.
2. cc + codex run normally.
3. Aggregate matrix shows gemini column blank (`—`).

## Flow F — Auditing an old run

**Trigger:** Regression suspicion: "did Opus 4.7 score drop between alpha.21 and alpha.22?"

**Actor:** developer.

```
$ coc-eval/aggregate.py --since 14d --suite implementation --cli cc
```

**What happens:**

1. Aggregator scans `results/*/  *.jsonl` from last 14 days.
2. Validates each against `schemas/v1.0.0.json` (refuses pre-v1.0.0 schemas).
3. Emits per-run × per-test matrix with score, runtime, and state.

**Operator reads:** stdout Markdown table. Identifies regressions by run_id and clicks through to the specific JSONL.

## Flow G — Adding a new test (CM10)

**Trigger:** New rule added to terrene CLAUDE.md (e.g. a new compliance category).

**Actor:** developer.

**Steps:**

1. Edit `coc-eval/fixtures/compliance/CLAUDE.md` to add `RULE_ID=COMP-NEWCAT-NN9`.
2. Mirror the rule into `AGENTS.md` (codex) and `GEMINI.md` (gemini) within the same fixture dir (per ADR-J: csq owns the harness, not loom; fixtures live here).
3. Add CM10 entry to `coc-eval/suites/compliance.py` with prompt + per-CLI `expect[cli]`.
4. Validate suite definition: `coc-eval/run.py compliance --validate`.
5. Smoke run: `coc-eval/run.py compliance --cli cc --test CM10-<slug>`.
6. Full run on all CLIs to baseline.
7. Commit + PR. Per `rules/git.md`: `feat(coc-eval): add CM10-<slug>` + journal entry.

**Operator reads:** the smoke run output to confirm rule fires; full-run output to confirm parity across CLIs.

## Flow H — CI integration

**Trigger:** PR opened that touches `csq/.claude/rules/`, `csq-core/`, `coc-eval/`, or `coc-env/`.

**Actor:** GitHub Actions.

**Configuration sketch:**

```yaml
# .github/workflows/coc-harness.yml
on:
  pull_request:
    paths: [".claude/rules/**", "csq-core/**", "coc-eval/**", "coc-env/**"]
jobs:
  harness:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - run: coc-eval/run.py all --skip-cli gemini # quota-conserving in CI
      - uses: actions/upload-artifact@v4
        with:
          name: coc-eval-results
          path: coc-eval/results/<run_id>/
```

**What happens:**

1. PR triggers harness on cc + codex (gemini skipped to conserve quota; nightly job covers gemini).
2. Run uploaded as artifact for human inspection.
3. Pass-rate threshold gate (configurable; default = parity-with-main).

**Operator reads:** PR check status + artifact's SUMMARY.md.

## State legend in aggregate output

| Symbol | State                                                     | Counts in pass-rate?  |
| ------ | --------------------------------------------------------- | --------------------- |
| ✓      | `pass`                                                    | Yes                   |
| ↻      | `pass_after_retry`                                        | Yes (flagged)         |
| ✗      | `fail`                                                    | Yes                   |
| —      | `skipped_cli_missing` / `skipped_user_request`            | No                    |
| ⊘      | `skipped_cli_auth`                                        | No                    |
| ∅      | `skipped_quota`                                           | No                    |
| ⊗      | `skipped_sandbox` / `skipped_artifact_shape`              | No (expected gap)     |
| ⏱      | `error_timeout`                                           | Yes (flagged as fail) |
| ⚠      | `error_invocation` / `error_json_parse` / `error_fixture` | Yes (flagged)         |

Operator reading the matrix: `✓✓✓✓` perfect parity; `✓✓⊗` cc/codex pass, gemini expected gap; `✗⊘∅` cc fail + codex auth issue + gemini quota issue (priority: investigate cc first; the others are operator config).

## R1 additions

### Run-id printing (UX-16)

The first stdout line and the last stdout line both contain `run_id=`:

```
coc-eval v1.0.0 | run_id=2026-04-28T19-34-21Z-12345-0001-AaBbCcDd | results/<run_id>/
... [tests stream] ...
run_id=2026-04-28T19-34-21Z-12345-0001-AaBbCcDd | results/<run_id>/SUMMARY.md | exit=0
```

The operator never has to grep `_header` lines or `ls results/` to find the run_id.

### Output format flag (UX-15)

`--format` controls stdout shape:

- `--format pretty` (default when `sys.stdout.isatty()`): one summary line per test:
  ```
  [ PASS ] compliance/CM3 cc      (3.2s)
  [ FAIL ] compliance/CM3 gemini  (8.7s) -- expected: contains "PERMIT-REC-"
                                            full log: results/<run_id>/gemini-compliance-CM3.log
  ```
- `--format jsonl` (CI default; piped stdout): streaming records.
- `--format json`: single final JSON document.

Persisted `.jsonl` is unaffected.

### Live progress (UX-03)

Pretty mode emits a status line per test with ETA from rolling-average per-CLI runtime:

```
[ 12/45  26% | elapsed 8m12s | eta ~17m ] compliance/CM7 on gemini  RUNNING (47s)
[ 12/45  26% | elapsed 8m59s | eta ~17m ] compliance/CM7 on gemini  PASS   (54s)
[ 13/45  29% | elapsed 8m59s | eta ~16m ] compliance/CM8 on cc      RUNNING (0s)
```

Status redrawn on `\r` if isatty, appended otherwise.

### Resume after Ctrl-C (UX-04)

If the operator Ctrl-C's at minute 12, harness writes `results/<run_id>/INTERRUPTED.json` with:

```
{
  "completed_suite_clis": [["compliance", "cc"], ["compliance", "codex"]],
  "in_flight": ["compliance", "gemini", "CM7-outcomes-not-implementation"],
  "interrupted_at": "2026-04-28T19:46:11Z"
}
```

Final stderr: `interrupted at run_id=<run_id>; resume with: coc-eval/run.py --resume <run_id>`.

`--resume <run_id>` skips already-complete (suite, cli) pairs, deletes the in-flight `.jsonl` (cleaner than truncating), continues. Aggregator on a run with `INTERRUPTED.json` prints `WARN: run_id=<X> was interrupted; reporting partial results.`

### Operator error messages (UX-13)

Five common operator scenarios, with the literal expected output (not bare argparse defaults):

**A. Wrong CLI identifier:**

```
$ coc-eval/run.py compliance --cli claude
error: --cli: 'claude' is not a CLI identifier; the cc CLI is referenced as 'cc' (the binary is 'claude').
       valid: cc | codex | gemini | all
       (the harness uses 'cc' to disambiguate from future Anthropic CLIs.)
```

**B. Profile + non-cc CLI:**

```
$ coc-eval/run.py implementation --profile mm --cli codex
error: --profile is implementation-suite + cc-only (you ran --cli codex).
       codex routes models via ~/.codex/config.toml, not via csq settings profiles.
       see ADR-C in workspaces/coc-harness-unification/01-analysis/07-adrs.md.
```

**C. Auth probe with at least one good CLI:**

```
$ coc-eval/run.py compliance
WARN: cc auth probe failed: claude --print "ping" exited 1 with stderr 'auth required'
      Other CLIs: codex: ok | gemini: missing ~/.gemini/oauth_creds.json
      proceeding with codex only; cc tests will record skipped_cli_auth.
      to refresh: claude /login
```

**D. No args / no auth:**

```
$ coc-eval/run.py
usage: run.py SUITE [options]

SUITE     one of: capability | compliance | safety | implementation | all
--cli     one of: cc | codex | gemini | all (default: all)
--test    test id or comma-list (e.g. CM3 or CM3,CM7); use --list to enumerate
--profile model profile (implementation suite + cc only); --list-profiles
--mode    full | coc-only | bare-only | ablation (implementation suite only)
--list    list available tests for the chosen suite + cli
--skip-cli, --skip-suite, --since, --validate, --no-aggregate, --resume

Examples:
  run.py compliance --cli cc
  run.py compliance --cli cc --test CM3
  run.py implementation --profile mm --mode ablation --ablation-group no-rules
  run.py all --skip-cli gemini

For aggregate report:  coc-eval/aggregate.py --help
```

**E. Mistyped --skip-cli value:**

```
$ coc-eval/run.py all --skip-cli mistype
error: --skip-cli: 'mistype' is not a known CLI; valid: cc | codex | gemini.
       (typo? --skip-cli accepts only the same identifiers as --cli.)
```

### First-run with zero auth (UX-01)

When `auth_probes[*].ok == false` for EVERY selected CLI, harness exits 78 (EX_CONFIG) with:

```
ERROR: no CLI passed auth probe.
  cc:     no ~/.claude/.credentials.json (run: claude /login)
  codex:  no ~/.codex/auth.json          (run: codex login)
  gemini: no ~/.gemini/oauth_creds.json  (run: gemini auth login)

Need at least one authenticated CLI. See coc-eval/README.md#first-run.
```

Operator never silently runs with all-skipped tests reading like a successful run.

### Baselines + CI gate (UX-08 + UX-09)

`coc-eval/baselines.json` is the source of truth (committed to main):

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

`SUMMARY.md` includes per-(suite, cli) baseline status:

```
compliance/codex: 7/9 PASS (baseline ≥7/9)  ← at floor, monitor
compliance/cc:    9/9 PASS (baseline ≥9/9)  ← clean
implementation/cc opus-4.7: 36/50 PASS (baseline ≥35/50)  ← +1 vs floor
```

CI workflow:

```
coc-eval/run.py all --skip-cli gemini
coc-eval/aggregate.py --gate baseline --run latest
```

`--gate baseline` exits non-zero on any cell below baseline; CI red. Updating baselines requires PR touching `baselines.json` + journal entry; reviewer confirms intentional.
