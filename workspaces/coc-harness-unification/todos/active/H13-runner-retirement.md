# H13 — csq runner.py retirement

**Goal.** Final cleanup. `coc-eval/run.py` is the only entry point. Old `runner.py:main` becomes a deprecation shim.

**Depends on:** H1-H11 (full harness functional). H12 independent.

**Blocks:** none (terminal PR of Phase 1).

## Tasks

### Build — runner.py shim

- [ ] Modify `coc-eval/runner.py`:
  - `runner.py:main()` → thin shim emitting `DeprecationWarning("runner.py is deprecated; use coc-eval/run.py")`.
  - Dispatches to `coc-eval/run.py` with translated args (best-effort: `runner.py default opus --mode full --tests EVAL-A004` → `run.py implementation --profile default --mode full --test EVAL-A004`).
  - Keeps deprecation alive for 1 release; remove in v1.1.

### Build — old aggregate format fallback

- [ ] Old `eval-<profile>-<mode>.json` aggregate output is kept as a fallback for one release (so existing downstream tooling that reads it doesn't break).
- [ ] New canonical format is JSONL via `coc-eval/run.py`. Aggregator reads JSONL.
- [ ] Document in `coc-eval/README.md` that JSON aggregate is deprecated and will be removed in v1.1.

### Update — coc-eval/README.md

- [ ] H1 created the README. H13 updates it with:
  - Final operator commands reflecting all merged PRs.
  - Pointer to `specs/08-coc-eval-harness.md` as durable spec.
  - Migration note: `runner.py` users move to `run.py` over the next release.
  - All 10 ADRs (A through J) recorded with status `ACCEPTED` or `REJECTED` in the spec (AC-28).

### Test

- [ ] `test_runner_shim.py`:
  - Invoking `coc-eval/runner.py default opus --mode full` emits DeprecationWarning AND produces equivalent output to `coc-eval/run.py implementation --profile default --mode full`.
- [ ] Manual eval-pass for both ablation modes (no-rules, rules-only) still produces the expected COC-vs-bare delta — score parity check end-to-end.

## Gate

- Manual ablation eval-pass for `no-rules` and `rules-only` produces expected COC-vs-bare delta on Opus 4.7.
- README final-state operator commands work end-to-end.
- All ADRs recorded with status in spec (AC-28).

## Acceptance criteria

- AC-27 (README final state)
- AC-28 (ADRs recorded with status)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H13 <summary>`
- [ ] Branch name `feat/coc-harness-h13-runner-retirement`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

`runner.py` shim must translate args correctly. Most existing scripts invoke `runner.py default opus --mode full` or similar; the translation is well-defined. Edge cases (e.g., `--ablation-group rules-only`) need explicit testing. Document any non-translatable args (none expected, but verify).
