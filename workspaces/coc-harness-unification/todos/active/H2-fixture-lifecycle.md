# H2 — Per-test tmpdir fixture lifecycle

**Goal.** Land the loom-style fixture preparation as a Python module. Port loom fixtures into csq.

**Depends on:** H1 (validators).

**Blocks:** H5 (capability suite needs fixtures), H6 (compliance), H7 (implementation), H8 (safety).

## Tasks

### Build — fixture library

- [ ] Create `coc-eval/lib/fixtures.py`:
  - `prepare_fixture(name: str) -> Path`: validates name via `validators.validate_name`; copies from `coc-eval/fixtures/<name>/` to `$TMPDIR/coc-harness-<name>-<rand>/` via `shutil.copytree`; runs `git init -q` + `git add -A` + `git commit -q -m init` via `subprocess.run([list], shell=False)`.
  - `cleanup_fixtures(older_than_hours: int = 24)`: scans `$TMPDIR` for `coc-harness-*` dirs older than threshold; removes via `shutil.rmtree(..., ignore_errors=True)`.
  - `cleanup_eval_tempdirs(run_started: float)`: removes every `/tmp/csq-eval-*` older than the current run's start time (`mkdtemp` directories with credential symlinks MUST NOT survive process exit, HIGH-03 #3).
  - `verify_fresh(path: Path) -> None` (INV-ISO-5): asserts mtime ≤ 5s, dir non-empty, `.git` not symlinked outside `$TMPDIR`. Raises FixtureError otherwise.

### Build — fixture content port

- [ ] Port fixture directories from `~/repos/loom/.claude/test-harness/fixtures/` to `coc-eval/fixtures/`:
  - `baseline-cc/` (only `CLAUDE.md` + `sub/`)
  - `baseline-codex/` (only `AGENTS.md` + `sub/`)
  - `baseline-gemini/` (only `GEMINI.md` + `sub/`)
  - `pathscoped/` (`.claude/rules/` with `paths:` + canary phrase)
  - `compliance/` (9 rules with unique RULE_IDs) — content adaptation for H6's product-name substitution flagged but performed in H6.
  - `safety/` (CRIT rules + permit-token contract)
  - `subagent/` (`.gemini/agents/test-agent.md` + parallels)
- [ ] Add `coc-eval/fixtures/.gitignore` for any generated state.
- [ ] Each fixture root gets a header comment (in `CLAUDE.md` / `AGENTS.md` / `GEMINI.md` as appropriate): "Adapted from loom/.claude/test-harness/fixtures/<name>/ on 2026-04-28."

### Test

- [ ] Create `coc-eval/tests/lib/test_fixtures.py`:
  - `test_prepare_distinct_dirs`: two consecutive `prepare_fixture("baseline-cc")` calls return distinct paths; both contain `CLAUDE.md`.
  - `test_prepare_invalid_name`: `prepare_fixture("..")` raises ValueError; `prepare_fixture("/etc/passwd")` raises ValueError.
  - `test_cleanup_zero_age`: create 3 `coc-harness-*` dirs; `cleanup_fixtures(older_than_hours=0)` removes all 3.
  - `test_verify_fresh`: prepare a fixture, `verify_fresh()` returns; mutate `.git` to symlink outside `$TMPDIR`, `verify_fresh()` raises.
  - `test_eval_tempdir_cleanup`: create `/tmp/csq-eval-test-AAAA/` with mtime in the past; `cleanup_eval_tempdirs(now)` removes it.

## Gate

- `pytest coc-eval/tests/lib/test_fixtures.py` green.
- `coc-eval/fixtures/baseline-cc/CLAUDE.md` contains `MARKER_CC_BASE=cc-base-loaded-CC9A1` (loom marker preserved).
- All 7 fixture dirs present and structurally correct (per loom layout).

## Acceptance criteria

- AC-15 (fresh fixture per test, distinct paths)
- AC-17 (cross-run cleanup; 24h threshold; no `csq-eval-*` mkdtemp survival)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H2 <summary>`
- [ ] Branch name `feat/coc-harness-h2-fixture-lifecycle`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

Loom's fixtures contain Kailash/DataFlow product names in compliance/CM5 + CM6 prompts. H2 ports byte-for-byte; H6 substitutes (R2-MED-03). DO NOT substitute in H2 — H6 owns the substitution layer.
