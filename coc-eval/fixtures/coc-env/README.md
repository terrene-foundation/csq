# coc-env — implementation suite base fixture

Empty COC base used as the per-test fixture root for every implementation
test (EVAL-A004/A006/B001/P003/P010). Per-test scaffold files (under
`coc-eval/scaffolds/<eval-id>/`) are layered on top by the runner before
`git init` so the fixture's first commit captures both the base and the
scaffold byte-identically across attempts (INV-ISO-5 / INV-PAR-1).

The implementation prompts are self-contained — they do not reference
project rules — so this base is intentionally minimal. The only point
of having a `coc-env` fixture (rather than using the scaffold dir
directly) is to keep the per-test prepare path uniform across all four
suites: the runner always prepares a fixture, then optionally injects
scaffold files, then `git init`s.

Per `coc-eval/lib/runner.py`, the `_build_scaffold_setup_fn` helper
inspects each implementation test's `scaffold` field and injects the
corresponding scaffold tree into this base before commit.

DO NOT add files here that reference proprietary product names — the
CI gate `coc-eval/scripts/check-fixture-substitution.sh` enforces this.
