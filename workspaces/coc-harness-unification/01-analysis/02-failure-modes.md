# Failure Modes — Loom→csq Harness Consolidation

Severity legend: **CRIT** = blocks Phase 1 ship; **HIGH** = ship-blocking unless explicit acceptance; **MED** = ship with mitigation noted; **LOW** = v1.1 follow-up acceptable.

## F00 — Runtime/dependency split decision (META)

**Severity: CRIT.** Loom is Node.js (`*.mjs`); csq runner is Python stdlib. `independence.md` §3 forbids Node.js as a runtime dep on csq. Two options:

- **(A) Port to Python.** ~380 LOC port. Aligns with §3.
- **(B) Carve out Node.js as permitted runtime.** Rule edit + install probe. Opens the npm-deps door.

**Recommendation: (A).** csq users already have Node via `claude`/`codex`/`gemini` itself, but csq's own install footprint stays stdlib. Per ADR-A in `07-adrs.md`.

## F01 — Cross-suite contamination via real `~/.claude` (CRIT)

`runner.py:308-314` symlinks REAL `~/.claude/{agents,skills,rules,memory}` into the temp config dir. Loom's `harness.mjs:97-101` doesn't override `CLAUDE_CONFIG_DIR` because OAuth lives at real HOME. Both punt on isolation.

When compliance/CM1-refuse-stub asks the model to cite `RULE_ID=COMP-ZT-STUB-4M8`, the user's own `~/.claude/rules/zero-tolerance.md` and `rules/no-stubs.md` ALSO instruct refusal — without that RULE_ID. Model refuses on user's rule grounds, never cites fixture's RULE_ID. Test reads "fail" but the failure is contamination.

**Mitigation:** Per-suite `home_mode`: implementation = `shared`; other three = `stub` with credential-only symlink. Stub HOME contains only `.credentials.json` (symlink) + `hasCompletedOnboarding: true`; user's global rules are invisible. JSONL header records `home_mode` for audit.

## F02 — Implementation suite is fundamentally cc-only under current launchers (CRIT)

EVAL-A006 and EVAL-P003 require code edits → file writes. Loom launchers: cc plan-mode (no writes), codex `--sandbox read-only` (no writes), gemini plan-mode (no writes). Combined runner without per-suite override → all implementation tests score zero on artifact tier.

**Mitigation:**

1. Per-suite × per-CLI launcher table (see `05-launcher-table-contract.md`).
2. Per-test `requires_writes: bool` flag. Test skipped for any (cli, suite) whose launcher cannot satisfy `requires_writes` → `state: skipped_sandbox`.
3. Implementation suite Phase 1 = cc-only; codex/gemini under that suite get `state: skipped_artifact_shape` until Phase 2.

## F03 — Permission-mode drift between suites (HIGH)

Loom uses `--permission-mode plan` for cc; csq uses `--dangerously-skip-permissions`. Combined: which mode wins per suite per CLI? Picking globally breaks one or the other.

**Mitigation:** Per-suite default + per-test override. Implementation = `--dangerously-skip-permissions`; capability/compliance/safety = `--permission-mode plan`. JSONL records `permission_mode` per record so a "fail" can be diagnosed as plan-mode-blocked vs rule-blocked.

## F04 — Settings profile vs scrubbed env conflict (HIGH)

csq strips `ANTHROPIC_*` env vars (`runner.py:450-453`); loom doesn't. Combined runner inconsistently routes the model across suites.

**Mitigation:** Always scrub `ANTHROPIC_*`. Profile selection is mandatory; resolved model identity stamped in JSONL header. Stub-HOME suites strip `commands/`/`hooks/` symlinks (not COC-input-of-record for capability/compliance/safety).

## F05 — Fixture preparation race (HIGH)

Loom = per-test tmpdir. csq = shared `coc-env/` with `git clean -fd` reset. A future parallelization corrupts the shared tree. Mid-test crash without `try/finally` reset poisons the next test.

**Mitigation:**

1. Per-test tmpdir for capability/compliance/safety (loom-style).
2. Implementation suite keeps `coc-env/` reset path but wraps in `try/finally`.
3. Phase 1 enforces `concurrency: 1` in code; v1.1 considers parallel.
4. Pre-flight check: refuse to run if parent `coc-env/` has uncommitted changes outside scaffold paths.

## F06 — Scoring-engine schema reconciliation (HIGH)

Loom `score`: `{pass: bool, criteria: [{label, kind, pattern, pass}]}`. csq `score_test`: `{total, max_total, tiers: [{name, points, max_points, reason}]}`. Aggregator can't read both.

**Mitigation:** Unified record schema (see `06-jsonl-schema-v1.md`). Pre-existing dead code: `scoring.py:248-249` references `result["coc_bonus"]` that `score_test` never produces — fix in same session per zero-tolerance Rule 1.

## F07 — User's own rules contaminate compliance citations (HIGH)

`_symlink_shared_dirs` includes `memory/`. Memory content can instruct model to cite real terrene/csq rule IDs, not fixture RULE_IDs. capability/C3 path-scoped canary can be triggered by user's own `paths:`-frontmatter rules overlapping `/tmp` paths.

**Mitigation:**

1. F01 mitigation handles compliance/safety/capability.
2. Implementation suite: drop `memory/` from `_symlink_shared_dirs`. Memory is per-project autobiographical, not COC artifact.
3. Pre-flight scan: warn if any user `~/.claude/rules/**/*.md` has `paths:` frontmatter referencing `/tmp` or `/private/tmp`.

## F08 — Codex/Gemini fixture parity (CRIT for implementation; HIGH for others)

Implementation suite scaffolds assume cc-shaped artifacts (CC reads `.claude/`). Codex/Gemini use `AGENTS.md`/`GEMINI.md` shapes — won't see the COC artifact tree the same way.

**Mitigation:**

1. Phase 1 implementation suite = cc-only. JSONL records `state: skipped_artifact_shape` for codex/gemini × implementation cells.
2. v1.1 follow-up: per-CLI artifact mirrors (this is the Phase 2a unified-`.coc/` problem; out of scope here).
3. Drop COC-awareness-bonus tier or scope conditional on `cli == "cc"`.

## F09 — Compounding retry policy (MED)

Loom gemini-only quota retry. csq empty-response retry. Stacked: gemini quota → loom retry → still empty → csq retry. Two distinct symptoms conflate into one "pass."

**Mitigation:** Single retry policy in unified runner with category-specific delays. JSONL `attempts: [{outcome, runtimeMs, stderr_excerpt}, ...]` and `final_state`. Cap total wall-clock at `2 × test_timeout`. Generalize quota detection across all three CLIs.

## F10 — CLI-skip-on-missing semantics (HIGH)

`spawnSync("codex")` ENOENT becomes a model-fail in the JSONL. Auditor sees "codex 0/13" and concludes non-compliance when codex is just absent.

**Mitigation:**

1. Pre-flight: probe each CLI with `--version` AND a smoke prompt. JSONL header records `availability: {installed, authed, smoke_passed}`.
2. ENOENT → `state: error_invocation` with `error_kind: "cli_missing"`. Auth-fail stderr → `state: skipped_cli_auth`. Quota → `state: skipped_quota`.
3. Aggregator renders skipped cells distinctly from real fails.

## F11 — Output cap and log explosion (LOW)

Loom 32k stdout cap; csq 500-3000 char preview. Mixed schemas mean some tests are reproducible from JSONL alone, others aren't.

**Mitigation:** Unified cap = 32k stdout / 8k stderr in JSONL, full to companion `.log`. Run-id-scoped subdirectory under `results/` (see F17).

## F12 — Failure-mode taxonomy (HIGH)

Closed enum required:

| state                    | meaning                                  | aggregator  |
| ------------------------ | ---------------------------------------- | ----------- |
| `pass`                   | All criteria satisfied                   | ✓           |
| `pass_after_retry`       | Failed once, passed retry                | ✓ flagged   |
| `fail`                   | Criteria not met, real response          | ✗           |
| `skipped_cli_missing`    | CLI binary absent                        | —           |
| `skipped_cli_auth`       | CLI present, auth lapsed                 | ⊘           |
| `skipped_quota`          | Quota exhausted post-retry               | ∅           |
| `skipped_sandbox`        | Test needs writes; CLI in plan/read-only | ⊗           |
| `skipped_artifact_shape` | Implementation × non-cc                  | ⊗           |
| `error_timeout`          | Wall-clock exceeded                      | ✗ flagged   |
| `error_invocation`       | Spawn/subprocess error                   | ✗ flagged   |
| `error_json_parse`       | CC `--output-format json` unparseable    | ✗ flagged   |
| `error_fixture`          | Fixture preparation failed               | harness bug |

**Mitigation:** Single source via Python `Enum`; aggregator treats unknown values as `error_unknown`, never silently maps to `fail`.

## F13 — Empty-response retry deletes diagnostics (MED, csq pre-existing)

`runner.py:579-583` retries on `not ok AND empty result AND zero output_tokens`. Catches JSON-parse errors with non-empty stdout but `result=""` — diagnostic stderr discarded.

**Mitigation:** Tighten predicate to retry only on `state ∈ {error_timeout, skipped_quota}`. Don't retry on `error_json_parse`.

## F14 — Loom busy-wait blocks process during quota retry (MED, loom pre-existing)

`harness.mjs:184-187` tight while-loop pegs CPU 10s. CI throttling can DELAY the retry past intended window.

**Mitigation:** Python port uses `time.sleep`. One line.

## F15 — Quota retry can collide with test_timeout (LOW)

Gemini 180s + 10s wait + 180s = 370s. Subsumed by F09 mitigation #2 (cap at `2 × test_timeout`).

## F16 — Credential-loss risk via stubHome regression (MED)

Future change to `CLI_COMMANDS.cc` that engages stubHome would break csq's account-rotation invariants — CC writes credentials into temp dir, daemon never refreshes them.

**Mitigation:**

1. Stubbed HOME MUST symlink credentials, never copy.
2. Runner guard: refuse to launch if `<stub_home>/.credentials.json` exists and is not a symlink.
3. Cross-ref `account-terminal-separation.md` invariants in the harness spec.

## F17 — Aggregator double-counts on rerun (HIGH, loom pre-existing)

`aggregate.mjs:24-42` reads ALL `*.jsonl` indiscriminately. Stale data folds into every report.

**Mitigation:** Run-id scoping. Each invocation creates `results/<run_id>/` directory. Aggregator defaults to "latest run only"; cross-run is opt-in via `--since` flag.

## F18 — Test ordering matters with shared coc-env (MED, csq pre-existing)

Subsumed by F05 mitigation #1 (per-test tmpdir for non-implementation suites; broaden `git clean -fdx` for implementation).

## F19 — Per-CLI × per-suite timeout matrix (MED)

Loom: cc/codex 60s, gemini 180s. csq: per-test 600s default. Combined: implementation needs per-test budget; others need per-CLI defaults.

**Mitigation:** `timeout_ms[suite][cli]` 2D table. Implementation uses `test_def["timeout"]` directly. Capability/compliance/safety use loom's defaults.

## F20 — Synthetic markers transmitted to third parties (LOW, context)

Fixture markers (`MARKER_CC_BASE=...`) reach Anthropic/OpenAI/Google. Synthetic, but verify runner doesn't accidentally embed real `~/.claude/` content in prompts.

**Mitigation:** Runner-level pre-send scan: refuse prompt containing `sk-ant-`, `sk-`, `ssh-rsa AAAA`, `BEGIN PRIVATE KEY`. Defense in depth.

## F21 — Fixture-name validation insufficient (LOW)

`/^[a-zA-Z0-9._-]+$/` permits `..`. Path traversal possible.

**Mitigation:** Reject names containing `..` or starting with `.`. `^[a-zA-Z0-9_-][a-zA-Z0-9._-]*$` AND `!includes('..')`.

## F22 — Empty `--cli` arg silent crash (LOW)

`--cli` without value → `cliArg = undefined` → `CLI_COMMANDS[undefined]` TypeError.

**Mitigation:** Validate `cliArg ∈ {cc, codex, gemini, all}` at parse.

## F23 — `--output-format json` × loom regex (LOW)

csq uses JSON output mode. Wrapping inflates 32k cap with JSON overhead.

**Mitigation:** `--output-format json` only for implementation suite. Other suites use plain stdout.

## F24 — Codex sandbox-mode wording in compliance prompts (MED)

Subsumed by F01 (stub HOME eliminates user's `independence.md` from competing with fixture's `COMP-IND-COMM-5K8`).

## F25 — Missing dimension: rubric_type vs CLI-mode (MED)

csq has `rubric_type ∈ {coc, bare, ablation-*}`. Loom has none. Unification needs both axes.

**Mitigation:** Three-axis matrix `(suite, test, cli, rubric)`. Non-implementation suites use `rubric = "default"` (one row). Implementation: rubric varies per ablation. Header records the set of rubrics actually run.

## F26 — Phase 1 ship readiness summary

**Blocking (must resolve before ship):** F00, F01, F02, F04, F05, F06, F08(item 1), F10, F12, F17, F25. Plus security CRIT-01, CRIT-02, HIGH-01..06 from `09-security-review.md`.

**Recommended fixes during port:** F03, F07, F09, F13, F14, F19, F23, F24.

**v1.1 deferred:** F11, F15, F16, F20, F21, F22.

## Vector cross-reference

| Vector (from brief)                | Findings      |
| ---------------------------------- | ------------- |
| 1 (cross-suite contamination)      | F01, F07, F18 |
| 2 (CLI-skip-on-missing)            | F10, F12      |
| 3 (permission-mode drift)          | F02, F03      |
| 4 (settings vs env)                | F04           |
| 5 (fixture prep race)              | F05           |
| 6 (scoring schema)                 | F06, F25      |
| 7 (CC hierarchy contamination)     | F01, F07, F24 |
| 8 (codex/gemini fixture parity)    | F02, F08      |
| 9 (quota retry stutter)            | F09, F14, F15 |
| 10 (output cap)                    | F11, F17      |
| 11 (impl suite under codex/gemini) | F02, F08      |
| 12 (failure mode taxonomy)         | F10, F12      |

## Findings beyond the original 12 vectors

F00 (runtime split — META), F13 (csq retry-eats-diagnostics), F16 (credential-loss via stubHome regression), F17 (aggregator stale-data double-count), F19 (timeout matrix), F21 (fixture-name traversal), F22 (empty `--cli` crash), F23 (`--output-format json` × loom regex), F25 (rubric_type dimension).
