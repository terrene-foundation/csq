---
type: DECISION
date: 2026-04-28
created_at: 2026-04-28T23:30:00+08:00
author: co-authored
session_id: term-4164
session_turn: 75
project: coc-harness-unification
topic: Redteam round 2 converged after applying 8 fixes; analyze phase ready for /todos
phase: redteam
tags: [redteam, convergence, round-2, analyze-phase-close]
---

# DECISION — Redteam round 2 converged; analyze phase complete

## Decision

Redteam round 2 (single focused deep-analyst agent per `feedback_redteam_efficiency`) found **2 HIGH + 4 MED + 2 LOW**. All 8 above-LOW findings were resolved in the same session per `rules/zero-tolerance.md` Rule 5. Round-2 net after fixes: **zero CRIT + zero HIGH**. Convergence achieved.

The analyze phase is closed. The next step is `/todos` to break the implementation plan (PRs H1-H13 with H7↔H8 swap) into tracked work items.

## What round 2 found and fixed

| Finding    | Severity | What was wrong                                                                                                                                                                                                                                                                  | Fix applied                                                                                                                                                                                                                      |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R2-HIGH-01 | HIGH     | INV-RUN-7 vs INV-RUN-8 cross-file mismatch (`09-security-review.md` HIGH-03 said "INV-RUN-7" for ordering after R1 renumbered ordering to INV-RUN-8)                                                                                                                            | Updated reference; added clarifying header to `04-nfr-and-invariants.md`                                                                                                                                                         |
| R2-HIGH-02 | HIGH     | `sys.addaudithook` mitigation framed as equivalent to sandbox; in fact the audit hook only catches harness-process opens, NOT subprocess-child syscalls. Plus: synthetic credential canary lived in H8 but defenses ship in H7, so H7 gate had no fixture proving sandbox works | Rewrote HIGH-07 mitigation + ADR-F mitigation #3 with audit-hook scope caveat (defense-in-depth tripwire vs sandbox = primary defense). Moved synthetic credential canary from H8 to H7; H7 gate now validates sandbox pre-merge |
| R2-MED-01  | MED      | State precedence ladder included mutually-exclusive pairs (`pass > fail`) and conflated within-test predicates with across-test invariants                                                                                                                                      | Split into two ladders: within-test (single record resolution) and across-test (run-loop boundaries)                                                                                                                             |
| R2-MED-02  | MED      | INV-PAR-2 silent on `skipped_artifact_shape` exemption; would block H7 trying to satisfy criteria-count parity for cells that aren't running                                                                                                                                    | Added carve-out: invariant exempts cells resolving to `skipped_artifact_shape`                                                                                                                                                   |
| R2-MED-03  | MED      | H6 fixture-substitution audit missing; loom fixture content with "Kailash"/"DataFlow Inc" could leak via paths or non-prose channels regex doesn't cover                                                                                                                        | Added pre-commit grep audit to H6 gate: `grep -ri 'kailash\|dataflow' coc-eval/fixtures/` returns zero                                                                                                                           |
| R2-MED-04  | MED      | AC-24 still said "≤35 min" (pre-R1 figure) but security review HIGH-10 referenced 90min; AC-25 didn't account for INV-AUTH-3 per-suite probe overhead                                                                                                                           | AC-24 updated to 90min full / 50min cc-only / 35min CI-default; AC-25 amended with probe-overhead amortization note                                                                                                              |
| R2-LOW-01  | LOW      | Sandbox tooling Phase-1 install prerequisites understated (Linux `bwrap` is third-party install, not preinstalled)                                                                                                                                                              | H1 README scope: documents `bubblewrap` install for Linux; macOS `sandbox-exec` preinstalled (with deprecation note); Windows gated out                                                                                          |
| R2-LOW-02  | LOW      | `LaunchInputs.suite: Literal[...]` closed vs `CliId = str` open; asymmetry not justified                                                                                                                                                                                        | Added comment to launcher contract: suites map to COC methodology layers (CO 5-layer architecture); CLIs ship continuously                                                                                                       |

## Why round 2 was a single agent

Per `feedback_redteam_efficiency` memory: "3 parallel agents in round 1 only; switch to 1 focused agent by round 3." Round 2 used 1 agent because round 1's 3-agent cohort produced 50 findings — most were genuinely orthogonal, and the round-2 task was validation of fix coherence (not new lens-additive scrutiny). A single agent reading the full R1-revised package and probing for fix-induced contradictions hit the right depth.

The 8 round-2 findings are all FIX-INDUCED issues, not new threats:

- 2 HIGH = round-1 fixes that were either label-collisions or scope-confused (not enough; not what they claimed).
- 4 MED + 2 LOW = round-1 fixes that needed tightening at the edges.

This is the expected shape of round-2 findings on a converged round 1. Three more round-1 agents would have produced more orthogonal redundancy, not the fix-coherence audit that round 2 actually delivered.

## Convergence criterion

Round-2 exit criterion was zero CRIT + zero HIGH net. After applying the 8 fixes, the analysis package contains:

- **Zero CRIT findings** (was 7 across rounds 0+1; all fixed).
- **Zero HIGH findings** (was 22 across rounds 0+1; all fixed).
- **Open MED/LOW findings:** 0 unresolved (all 22+3 resolved in fix passes).

The package is ready for /todos. Implementation may begin against the durable spec at `specs/08-coc-eval-harness.md` once it is written in PR H1.

## Files updated by round-2 fixes

- `01-analysis/04-nfr-and-invariants.md` — invariant-label note, ladder split, INV-PAR-2 carve-out
- `01-analysis/05-launcher-table-contract.md` — Literal-vs-str asymmetry justification
- `01-analysis/06-jsonl-schema-v1.md` — ladder split mirrored from invariants
- `01-analysis/07-adrs.md` — ADR-F mitigation #3 audit-hook scope caveat
- `01-analysis/08-acceptance-criteria.md` — AC-24 budget revision, AC-25 probe-overhead note
- `01-analysis/09-security-review.md` — INV-RUN-8 reference fix, HIGH-07 audit-hook caveat + canary move
- `02-plans/01-implementation-plan.md` — H6 fixture-substitution gate, H7 canary scope (moved from H8), H8 scope reduced, H1 README sandbox prereqs
- `04-validate/02-redteam-round2-findings.md` — round-2 findings + resolutions

## For Discussion

1. Round-2 surfaced two HIGH cross-fix contradictions that round 1 missed (INV number collision; audit-hook semantics). These are the expected failure mode of multi-agent round 1 — agents do not see each other's fixes. Should there be a STANDARD round-2 cohort that re-reads after every multi-agent round, or is "single focused agent" enough? The `feedback_redteam_efficiency` memory says single, and this round confirms it — but the failure mode is real.

2. The audit-hook scope confusion (R2-HIGH-02) was a genuine technical error introduced in round-1 fix HIGH-07. The Python `sys.addaudithook` API is well-documented as in-process only. Round-1 security agent didn't catch it because the focus was "find more findings," not "verify mitigation correctness against documented APIs." Should round-1 mitigations include a "verify against authoritative docs" step in the agent prompt?

3. Counterfactual — if round 2 had found a CRIT (a fix that introduced a new vulnerability), the analyze phase would have rolled to round 3 and Phase 1 ship would slip. The round-2 exit was reasonably likely to find SOMETHING but not necessarily HIGH-severity. What's the empirical probability of round-2 finding a HIGH after a robust round 1? This data point (2/50 ≈ 4% rate) suggests round-2 is high-value (catches real issues) but doesn't gate phase progression unduly.

## References

- `04-validate/01-redteam-round1-findings.md` — round-1 input
- `04-validate/02-redteam-round2-findings.md` — round-2 findings + resolutions
- Memory `feedback_redteam_efficiency` — single-agent rationale for round 2+
- `rules/zero-tolerance.md` Rule 5 — same-session fix mandate
