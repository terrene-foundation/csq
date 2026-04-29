# H6 — Compliance suite (cc only) + full CM port

**Goal.** Full CM1-CM9 port. Stub-HOME isolation already validated by H3; H6 trusts that.

**Depends on:** H1, H2, H3, H4, H5 (orchestrator).

**Blocks:** H10 (codex compliance), H11 (gemini compliance).

## Tasks

### Build — compliance suite definition

- [x] Create `coc-eval/suites/compliance.py`:
  - `SUITE` dict: `name="compliance"`, `version="1.0.0"`, `permission_profile="plan"`, `fixture_strategy="per-cli-isolated"` (single shared `compliance` fixture per cli though, distinct from baseline-cc/codex/gemini).
  - 9 tests ported from `~/repos/loom/.claude/test-harness/suites/compliance.mjs`:
    - CM1-refuse-stub
    - CM2-refuse-hardcoded-secret
    - CM3-directive-recommend
    - CM4-delegation-needs-specs
    - CM5-refuse-commercial-reference
    - CM6-refuse-wrong-foundation-name
    - CM7-outcomes-not-implementation
    - CM8-no-cc-artifact-in-codex-or-gemini
    - CM9-proposal-append-not-overwrite
  - Each test scores via `kind: contains` for RULE_ID citation pattern (e.g. `RULE_ID[\s=:]+COMP-ZT-STUB-4M8`).
  - `scoring_backend = "regex"` per test.

### Build — fixture content adaptation

- [x] Adapt `coc-eval/fixtures/compliance/CLAUDE.md` (and AGENTS.md, GEMINI.md) per R1-AD-12 + R2-MED-03:
  - Replace `Kailash Python SDK` with a csq-domain-appropriate fictional commercial product name (TBD during implementation; pick something obviously fictional, e.g. `FoobarCorp Database Builder`).
  - Replace `DataFlow Inc` with a fictional commercial entity name.
  - Replace `Terrene Labs`/`Kailash Corporation`/`Kailash 3.0` with paired fictional incorrect names + correct `Terrene Foundation` (the test is "model corrects wrong foundation name"; the WRONG name can stay loom-style, but no Kailash references).
  - Per-fixture header comment: "Adapted from `loom/.claude/test-harness/fixtures/compliance/CLAUDE.md` on 2026-04-28; product names substituted to remove commercial references per `csq/.claude/rules/independence.md`."
- [x] Update CM5 + CM6 prompts in `compliance.py` to match adapted fixture names.

### Build — post_assertions / FsAssertion infrastructure (R3-CRIT-03)

- [x] Create `coc-eval/lib/fs_assertions.py`:
  - `FsAssertion` dataclass (frozen).
  - `FileAbsent(path)` — asserts path does not exist after CLI exits.
  - `FileUnchanged(path)` — pre-test snapshots SHA-256 of path; post-test asserts unchanged.
  - `DirEmpty(path)` — asserts directory has no entries.
  - `FilePresent(path)` — asserts path exists.
  - `evaluate(assertion: FsAssertion, fixture_dir: Path) -> AssertionResult` returning `{matched: bool, label: str, kind: "fs_assert", points: int, max_points: int}`.
- [x] Wire into `coc-eval/lib/runner.py`: after CLI exits and before scoring, run `evaluate()` on each `test.post_assertions`; merge results into `score.criteria` with `kind: "fs_assert"`. Test passes only if BOTH regex AND post-assertions pass.
- [x] Test: `coc-eval/tests/lib/test_fs_assertions.py` covering each kind (FileAbsent passes when file truly absent; FileUnchanged catches mtime changes; etc.).

### Build — pre-commit fixture-substitution audit (R2-MED-03)

- [x] Add CI check: `grep -ri 'kailash\|dataflow' coc-eval/fixtures/` MUST return zero matches. Add as a step in `.github/workflows/coc-harness.yml` (created in H5 or H9; if not yet present, scaffold here).
- [x] Local script `coc-eval/scripts/check-fixture-substitution.sh` for developer pre-commit hook.

### Test

- [x] `coc-eval/tests/integration/test_compliance_cc.py`:
  - Run `coc-eval/run.py compliance --cli cc`; assert 9 records emit; assert all 9 PASS on cc.
  - Asserts the substitution audit passes (`subprocess.run(["grep", "-ri", "kailash\\|dataflow", "coc-eval/fixtures/"]).returncode == 1` — grep returns 1 on no match).

## Gate

- CM1-CM9 PASS on cc with stub HOME.
- Fixture-substitution audit returns zero matches.
- AC-3 (cc subset) green.

## Acceptance criteria

- AC-3 (compliance ≥9/9 on cc)
- (AC-14 ownership moved to H8 per R3-HIGH-03 — H8 owns the multi-suite mtime integration test)
- FR-15 post_assertions infrastructure (R3-CRIT-03 build side)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [x] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H6 <summary>`
- [x] Branch name `feat/coc-harness-h6-compliance-suite`
- [x] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

Fixture-substitution can introduce subtle bugs: if the new fictional product name happens to overlap with a real csq-domain term, future readers get confused. Pick names that are obviously fictional and document them in the per-fixture header. CM5 and CM6 prompts have to track the substitution exactly — a regex matching "Terrene Labs" and the prompt saying "Terrene Inc" causes silent test failures.
