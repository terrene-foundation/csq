# Red-Team Round 2 — Findings + Resolutions

Single-agent focused review of round-1 fixes. Found **2 HIGH + 4 MED + 2 LOW**. Per `rules/zero-tolerance.md` Rule 5, all above-LOW fixes applied in same session.

## HIGH (resolved)

### R2-HIGH-01 — INV-RUN-7 vs INV-RUN-8 number collision

**Where:** `09-security-review.md` HIGH-03 mitigation #2 referenced "INV-RUN-7" for ordering, but R1's renumbering moved ordering to INV-RUN-8 (INV-RUN-7 became token-budget). Cross-file inconsistency.

**Fix applied:** Updated `09-security-review.md` to reference INV-RUN-8 for ordering. Added clarifying note at top of `04-nfr-and-invariants.md` distinguishing the two.

### R2-HIGH-02 — Audit hook (`sys.addaudithook`) doesn't catch subprocess-child credential reads

**Where:** `09-security-review.md` HIGH-07 + ADR-F mitigation #3 frame the audit hook as equivalent to sandbox ("audit OR sandbox"). It is NOT — `sys.addaudithook` fires on Python-process events only. Subprocess child opens (the documented threat) are not caught. Plus: synthetic credential canary lands in H8 but defenses ship in H7, so H7 gate has no fixture exercising the sandbox.

**Fix applied:**

1. Rewrote HIGH-07 mitigation in `09-security-review.md` to caveat audit-hook scope explicitly: hook is harness-internal tripwire only; primary defense is sandbox.
2. Updated ADR-F mitigation #3 with same caveat.
3. Updated AC-23a to specify what the audit hook actually catches.
4. Moved synthetic credential canary from H8 to H7 in plan; H7 gate now includes "canary triggers CRIT under sandbox profile."

## MEDIUM (resolved)

### R2-MED-01 — State precedence ladder includes mutually-exclusive pairs and conflates within-test with across-test

**Fix applied:** Split ladder into within-test (single-record predicate resolution) and across-test (run-loop boundaries: token_budget, quarantined). Removed `pass > fail` (mutually exclusive at attempt boundary).

### R2-MED-02 — INV-PAR-2 silent on `skipped_artifact_shape` exemption

**Fix applied:** Appended carve-out to INV-PAR-2: invariant exempts cells resolving to `skipped_artifact_shape`. Implementation × {codex, gemini} cells in Phase 1 don't trip parity check.

### R2-MED-03 — H6 fixture-substitution audit missing

**Fix applied:** Added to H6 gate: `grep -ri 'kailash\|dataflow' coc-eval/fixtures/` returns zero matches. Per-fixture header lists original loom file + substitution.

### R2-MED-04 — AC-24 budget vs INV-AUTH-3 probe overhead unreconciled

**Fix applied:** AC-24 updated to 90min full / 50min cc-only matching round-1 derivation; AC-25 amended with per-suite probe overhead note.

## LOW (resolved)

### R2-LOW-01 — Sandbox tooling Phase-1 install prerequisites

**Fix applied:** README scope (H1) now mentions `bubblewrap` install for Linux + `sandbox-exec` preinstalled on macOS + Windows gated out.

### R2-LOW-02 — `LaunchInputs.suite: Literal[...]` vs `CliId = str` asymmetry

**Fix applied:** Added justification note to `05-launcher-table-contract.md` — suites map to COC methodology layers, CLIs ship continuously.

## Round-2 verdict

After applying the above fixes: **zero CRIT + zero HIGH net.** Convergence achieved. Recommend proceeding to `/todos` to break the implementation plan into tracked work items.

## Files updated by round-2 fixes

- `01-analysis/04-nfr-and-invariants.md` — INV labels clarified, ladder split, INV-PAR-2 carve-out
- `01-analysis/05-launcher-table-contract.md` — suite-Literal justification
- `01-analysis/06-jsonl-schema-v1.md` — ladder split mirrored
- `01-analysis/07-adrs.md` — ADR-F mitigation #3 audit-hook caveat
- `01-analysis/08-acceptance-criteria.md` — AC-24 budget revision, AC-25 probe-overhead note
- `01-analysis/09-security-review.md` — INV-RUN-8 reference fix, HIGH-07 audit-hook caveat
- `02-plans/01-implementation-plan.md` — H6 fixture-substitution gate, H7 canary scope, H1 README install prereqs
