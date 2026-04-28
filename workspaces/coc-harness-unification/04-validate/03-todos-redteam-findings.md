# Todo-list Red-Team — Findings + Resolutions

Single deep-analyst pass over the 13 PR todos. Found **4 CRIT + 5 HIGH + 3 MED**. All resolved in same session per `rules/zero-tolerance.md` Rule 5. Post-fix: zero CRIT + zero HIGH net. Todos ready for `/implement` gate.

## Findings

| ID      | Severity | Issue                                                                                                        | Resolution                                                                                               |
| ------- | -------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------ |
| CRIT-01 | CRIT     | AC-1 / AC-44 / FR-16 — `schemas/suite-v1.json` referenced but no todo creates it                             | Added to H1: schema file + `lib/suite_validator.py`. Added to H5: `run.py --validate`                    |
| CRIT-02 | CRIT     | FR-13 / AC-35 / AC-36 — SIGINT handler + `--resume` had no owning todo                                       | Added to H5: SIGINT handler, `INTERRUPTED.json` writer, `--resume` flag, integration test                |
| CRIT-03 | CRIT     | FR-15 — `post_assertions` / `FsAssertion` infrastructure missing entirely                                    | Added `lib/fs_assertions.py` + runner integration to H6 (build) + H8 (wire)                              |
| CRIT-04 | CRIT     | AC-13 — `shell=True` grep guard had no owning gate                                                           | Added to H1: grep guard CI step                                                                          |
| HIGH-01 | HIGH     | `.github/workflows/coc-harness.yml` referenced by H6/H8/H10/H11 but never created                            | Pinned ownership to H5 (first PR needing CI green); subsequent PRs ADD steps via diff                    |
| HIGH-02 | HIGH     | FR-20 / AC-24a — `--token-budget-input/output` flags + circuit breaker test missing                          | Added to H7: argparse flags, runner tracking, `state: error_token_budget` test                           |
| HIGH-03 | HIGH     | AC-14 (no real `~/.claude` writes) was a hope, not a test                                                    | Moved ownership to H8 with explicit mtime-snapshot integration test                                      |
| HIGH-04 | HIGH     | FR-17 / AC-34 — runtime `--format pretty                                                                     | jsonl                                                                                                    | json` + monotonic ETA missing | Added to H5: `--format` flag, pretty formatter, monotonic ETA test |
| HIGH-05 | HIGH     | H10/H11 over-stated dependency on H1-H9                                                                      | Loosened to H1, H2, H3, H4, H5; H6-H9 are soft recommends, not hard blockers                             |
| MED-01  | MED      | H7's "depends on H6" is style not load-bearing                                                               | H7 dep loosened to H1, H2, H3, H4, H5; H6 is soft recommend                                              |
| MED-02  | MED      | Per-PR cross-cutting (journal, /validate, mutation testing, PR title) not in any checklist                   | Added uniform "Cross-cutting" closing checkblock to all 13 todos                                         |
| MED-03  | MED      | 8 scattered R1/UX ACs unowned (AC-10, AC-18, AC-25, AC-32, AC-42, AC-47, AC-49 + FR-14 cron + FR-18 `--tag`) | Distributed: AC-10/AC-32/AC-47 → H11; AC-18/AC-25/AC-42/FR-18 → H5; FR-14 cron → H9; AC-49 deletion → H4 |

## Verdict

After applying fixes:

- **Zero CRIT, zero HIGH.**
- All 49 ACs + lettered ACs have owning tasks.
- All 20 FRs have owning tasks.
- All abstractions in launcher contract + JSONL schema are surfaced as todos.
- Cross-cutting per-PR concerns (journal, /validate, mutation, PR title) are explicit checkboxes everywhere.

**Todos ready for `/implement` approval gate.**

## Cross-cutting checklist added to every todo

```
### Cross-cutting (per implementation-plan §Cross-cutting)
- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H<N> <summary>`
- [ ] Branch name `feat/coc-harness-h<N>-<slug>`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)
```
