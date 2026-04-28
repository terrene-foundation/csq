# Functional Requirements

Operator capabilities for the consolidated harness. "Operator" = a human or automation invoking the harness CLI from `csq/coc-eval/`.

## FR-1: Run-everything-default

`coc-eval/run.py all` executes every suite × every available CLI in one invocation. Acceptance: one process produces 4 suites × ≤3 CLIs = up to 12 `(suite, cli)` JSONL files plus an aggregate matrix. Suites missing a CLI install emit `skipped_cli_missing` per planned test, not silent omission.

## FR-2: Per-suite scope

`coc-eval/run.py compliance --cli cc` runs only that suite × that CLI. Suite name positional; `--cli` is one of `cc | codex | gemini | all`; both filters compose with `--test`.

## FR-3: Single-test debug

`coc-eval/run.py compliance --cli cc --test CM3-directive-recommend`. `--test` accepts comma-list (`CM3,CM7`). Unknown test → exit 64 (EX_USAGE) with available list printed.

## FR-4: Streaming + persistent output

Stdout streams JSONL; same records persist to `results/<run_id>/<suite>-<cli>-<timestamp>.jsonl`. Per-test full stdout/stderr land in `results/<run_id>/<cli>-<suite>-<test>.log`. Exit codes: `0` if all non-skipped pass, `1` if any non-skipped fails, `2` if harness itself errors (invocation, schema, fixture corruption).

## FR-5: Aggregate report

`coc-eval/aggregate.py --since 7d` produces a Markdown matrix from the last week of JSONL. Reads `results/**/*.jsonl`, filters by header `started_at`, emits `(test × cli × runs)` matrix with pass-rate, p50 runtime, state distribution.

## FR-6: Auth preflight

Each CLI has a one-shot probe before suite loop:

| CLI    | Probe                                                                                                      |
| ------ | ---------------------------------------------------------------------------------------------------------- |
| cc     | `which claude` AND `~/.claude/.credentials.json` OR `~/.claude/accounts/config-N/.credentials.json` exists |
| codex  | `which codex` AND `~/.codex/auth.json` exists                                                              |
| gemini | `which gemini` AND `~/.gemini/oauth_creds.json` exists                                                     |

Missing auth → all that CLI's tests record `skipped_cli_auth` with probe stderr in `reason`.

## FR-7: Implementation suite override for write-mode

Implementation suite launches with write-mode permissions (cc `--dangerously-skip-permissions`, codex `--sandbox workspace-write`, gemini `--approval-mode auto-edit`). Other suites use plan/read-only. Per-suite permission profile selectable via launcher table.

## FR-8: Per-CLI deselection on demand

`shutil.which(<cli>)` gates the dispatcher. Missing → `skipped_cli_missing` for every planned test, harness continues. Operator can also force-skip with `--skip-cli gemini`.

## FR-9: Reproducibility hooks

JSONL header captures every variable affecting the result: CLI versions, harness version, OS, Python version, fixture commit SHA, env hash of allowed vars, selected_clis, selected_tests, permission_profile, harness_invocation. Schema in `06-jsonl-schema-v1.md`.

## FR-10: Ablation passthrough (implementation only)

`--mode ablation --ablation-group no-rules` works for implementation suite. Ablation modes (`full | coc-only | bare-only | ablation`) apply to implementation only; capability/compliance/safety auto-error if `--mode` is not `default` (their fixtures embed COC artifacts directly, ablation has no meaning).

## FR-11: Run-id scoping

Every invocation creates `results/<run_id>/` (where `<run_id>` = ISO-8601 timestamp + 6-char rand). Aggregator defaults to "latest run only"; cross-run is opt-in. Resolves the F17 stale-data double-count.

## FR-12: Force-skip flags

`--skip-cli <name>` (one or more), `--skip-suite <name>` (one or more) for operator-driven exclusion without modifying suite definitions.

## FR-13: Resume from interrupted run (R1-UX-04)

`coc-eval/run.py --resume <run_id>` re-reads `results/<run_id>/INTERRUPTED.json`, skips already-complete (suite, cli) pairs, deletes the in-flight `.jsonl` (cleaner than truncating), continues from there. SIGINT handler writes `INTERRUPTED.json` containing `{completed_suite_clis: [...], in_flight: ..., interrupted_at: ...}` and a final stderr line: `interrupted at run_id=<run_id>; resume with: coc-eval/run.py --resume <run_id>`.

## FR-14: Quarantine lifecycle (R1-UX-10)

Each test definition supports `quarantined: bool = False`. Auto-quarantine: per-week CI job runs each test 5× and PRs a quarantine flip when pass-rate < 80% (INV-DET-3). Exit quarantine: PR sets `quarantined: False`, journal entry attached showing 5-trial result ≥80%. Quarantined tests run only with `--include-quarantined`; default skip; SUMMARY.md surfaces count. New state value: `skipped_quarantined`.

## FR-15: Post-run filesystem assertions (R1-UX-12)

Compliance/safety tests support `post_assertions: list[FsAssertion]` for filesystem-state verification AFTER CLI exits. Examples: `FileAbsent(path="/tmp/leak")`, `FileUnchanged(path="{fixture_dir}/.ssh/id_rsa")`, `DirEmpty(path=...)`. Runner runs assertions after CLI exits; results merged into `score.criteria` with `kind: "fs_assert"`. Test passes only if BOTH regex AND post-assertions pass.

## FR-16: Suite-definition validation (R1-UX-14)

`coc-eval/run.py <suite> --validate` loads the suite module, runs schema validation against `schemas/suite-v1.json`, asserts INV-PAR-2 (criteria-count parity), asserts test IDs unique, prints `OK: 9 tests, 27 criteria across 3 CLIs`. Exits 0 on success, 64 on schema fail. Catches: missing prompt, duplicate test ID, criteria-count mismatch across CLIs.

## FR-17: Output format (R1-UX-15)

`--format pretty | jsonl | json` controls stdout shape:

- `--format pretty` (default when `sys.stdout.isatty()`): summary line per test, ETA banner, total at end.
- `--format jsonl` (default in CI / when piped): streaming JSONL records.
- `--format json`: single final JSON document with all records (for scripting, no streaming).

Persisted `.jsonl` file is unaffected.

## FR-18: Tag-based test selection (R1-UX-07)

Each test definition supports `tags: list[str]` (e.g. `["credentials", "rule-citation", "refusal"]`). New flag `--tag <name>` selects matching tests across suites; composes with `--cli` and `--skip-suite`. `aggregate.py --tag credentials` filters results.

## FR-19: Profile listing (R1-UX-06)

`coc-eval/run.py --list-profiles [--cli cc]` scans `~/.claude/settings-*.json`, prints name + resolved model + base URL + `profile_compatible_clis` list (per ADR-C reframe).

## FR-20: Token-budget circuit breaker (R1-MED-03 / INV-RUN-7)

`--token-budget-input N` and `--token-budget-output N` flags. Default cap 5,000,000 input / 1,000,000 output. Breach aborts run with `state: error_token_budget` for un-run tests.
