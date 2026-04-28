# H12 — Loom-csq boundary rule

**Goal.** Paired rule documenting the ownership split. csq owns multi-CLI eval harness; loom owns COC artifact authoring + per-CLI emission. Drift-detection cadence built in.

**Depends on:** H1-H11 (csq's harness must be functional before claiming sole ownership).

**Blocks:** none (H13 is independent cleanup).

## Tasks

### Build — csq side rule

- [ ] Create `csq/.claude/rules/csq-loom-boundary.md`:
  - Scope: applies to all PRs that touch `coc-eval/`, `csq/.claude/rules/`, or fixtures shared with loom.
  - Statement: csq owns multi-CLI evaluation harness; loom owns COC artifact authoring + per-CLI emission. Cross-references journal 0074 + journal 0002 + journal 0004 + ADR-J in `01-analysis/07-adrs.md`.
  - **Schema authority** (R2 / ADR-J): csq is authority for fixture content (RULE_ID grammar, prompt strings, scoring patterns) since csq's harness is canonical evaluator. Loom is authority for artifact-format details (slot composition, frontmatter shape, file-layout conventions). Disputes default to csq for content, loom for format.
  - **Pre-merge gate**: csq runs harness against loom's emitted fixtures pre-merge in csq's CI (decision per ADR-J #2 option a). Loom CI does NOT need to run csq's harness.
  - **Drift-detection cadence**: quarterly CI job in csq runs `git diff loom/.claude/test-harness/fixtures csq/coc-eval/fixtures` with whitelisted divergence list at `coc-eval/loom-diff-allowlist.txt`. Un-whitelisted drift fails the job; pages a maintainer.
  - MUST NOT delete loom's harness directory; loom may keep it as authoring-side validator.

### Build — loom side rule (mirror)

- [ ] Create `loom/.claude/rules/loom-csq-boundary.md` (in the loom repo, separate PR after csq side merges):
  - Same boundary stated from loom's side. Cross-reference to csq's harness at `~/repos/terrene/contrib/csq/coc-eval/` as canonical multi-CLI evaluator.
  - Loom's `~/repos/loom/.claude/test-harness/README.md` updated to point at csq's harness as the authority for multi-CLI evaluation; loom's harness retained as authoring-side smoke-test only.

### Build — drift allowlist scaffold

- [ ] Create `coc-eval/loom-diff-allowlist.txt`:
  - Enumerates KNOWN expected divergences between csq and loom fixtures (e.g., the H6 product-name substitution).
  - Format: one path per line; comment lines start with `#`.

### Build — quarterly CI job

- [ ] Add `.github/workflows/loom-csq-drift.yml`:
  ```yaml
  on:
    schedule:
      - cron: "0 0 1 */3 *" # quarterly, first day of every 3rd month
    workflow_dispatch:
  jobs:
    drift:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
          with:
            path: csq
        - uses: actions/checkout@v4
          with:
            repository: terrene-foundation/loom
            path: loom
        - run: csq/coc-eval/scripts/check-loom-drift.sh
  ```
- [ ] Create `coc-eval/scripts/check-loom-drift.sh`:
  - `git diff --no-index loom/.claude/test-harness/fixtures csq/coc-eval/fixtures`.
  - Filter against `coc-eval/loom-diff-allowlist.txt`.
  - Non-empty filtered output → exit 1 with summary.

### Test

- [ ] `coc-eval/tests/integration/test_loom_drift.py`:
  - Synthetic `loom/.../fixtures/baseline-cc/CLAUDE.md` with intentional change not in allowlist.
  - Run the drift script; assert exit 1.
  - Add the change to allowlist; assert exit 0.

## Gate

- Both rules cross-reference each other.
- Loom test-harness README points at csq's harness as authority (verifiable via grep in loom repo).
- Quarterly drift job scaffold in place.
- Drift script test passes.

## Acceptance criteria

- AC-29 (Loom-csq boundary rule landed)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H12 <summary>`
- [ ] Branch name `feat/coc-harness-h12-loom-csq-boundary`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)
- [ ] Loom-side PR (separate, in `~/repos/loom`) cross-references journal 0004 — same audit trail

## Risk

H12 touches BOTH repos. Land csq side first (this PR); loom side as a separate PR in `~/repos/loom` immediately after. Both PRs MUST reference the same journal entry (journal 0004) so audit trail is intact. If the loom-side PR slips, csq's rule references a non-existent loom rule — document as a known short-term incompleteness.

The drift CI job runs quarterly. First run will likely surface noise (whitespace differences, line-ending normalization) — populate allowlist on first run, then tighten over time.
