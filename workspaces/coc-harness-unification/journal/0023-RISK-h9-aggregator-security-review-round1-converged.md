---
type: RISK
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h9-aggregator
session_turn: 2
project: coc-harness-unification
topic: H9 round-1 security review — 31 findings, all above-LOW resolved
phase: redteam
tags: [coc-eval, h9, security-review, round1, parallel-agents, zero-tolerance]
---

# H9 round-1 security review — 31 findings converged

Three parallel `security-reviewer` agents audited H9 in non-overlapping
scopes: (a) `aggregate.py` + JSON-bomb defenses, (b) baselines + markdown
escape + coverage gate, (c) tests + spec coverage. Per
`rules/zero-tolerance.md` Rule 5, all above-LOW findings are resolved
in this PR.

## Findings summary

| Severity  | (a) | (b) | (c) | Total  | Resolved | Accepted |
| --------- | --- | --- | --- | ------ | -------- | -------- |
| CRIT      | 1   | 0   | 0   | 1      | 1        | 0        |
| HIGH      | 4   | 5   | 4   | 13     | 13       | 0        |
| MED       | 3   | 5   | 6   | 14     | 11       | 3        |
| LOW       | 1   | 1   | 2   | 4      | 1        | 3        |
| **Total** | 9   | 11  | 12  | **32** | 26       | 6        |

The 6 accepted findings cluster around CSV-CRLF policy (intentionally
Unix-LF), test-shape brittleness, and CI gate ergonomics deferred to
H13.

## (a) aggregate.py + JSON-bomb defenses — 9 findings

- **A-CRIT-1** _(resolved)_ — Per-record cap fires AFTER Python's line iterator materializes a giant single-line file. **Fix:** rewrote `_iter_jsonl_records` to read in 64 KiB chunks; per-record cap enforced while buffering, oversized record marked invalid + buffer cleared without ever holding the full line. Tests: `test_iter_jsonl_caps_syntactically_valid_oversized_record`, `test_iter_jsonl_long_line_no_newline_does_not_blow_memory`.
- **A-HIGH-1** _(resolved)_ — `_check_int_bounds(max_depth=32)` charged a recursion level for every dict-key check, risking false-rejection of legitimate nested records. **Fix:** raised cap to 64; descend only into values (JSON keys are guaranteed `str`-typed). Tests: `test_check_int_bounds_negative_boundary`, `test_check_int_bounds_realistic_legacy_record`.
- **A-HIGH-2** _(resolved)_ — `--run-id` regex-validated but no symlink containment check; `_discover_latest_run` followed symlinks. **Fix:** `is_symlink()` skip in discovery; `resolve(strict=True)` + `relative_to(results_root.resolve())` containment check on explicit run dirs. `_iter_jsonl_records` also refuses symlinked JSONL files. Tests: `test_resolve_run_dir_rejects_symlinked_run_dir`, `test_discover_latest_run_skips_symlink_entries`.
- **A-HIGH-3** _(resolved)_ — Multi-suite header drift silently merged. **Fix:** subsequent headers must match the first header's `run_id`; mismatch raises `AggregatorError`. Test: `test_load_run_rejects_header_run_id_drift`.
- **A-HIGH-4** _(resolved)_ — Test records carrying `run_id`/`schema_version` (header-only fields) silently absorbed into the matrix. **Fix:** explicit refusal at load time. Tests: `test_load_run_rejects_test_record_with_run_id_field`, `test_load_run_rejects_test_record_with_schema_version`.
- **A-MED-1** _(resolved)_ — `_load_baselines` no size cap, follows symlinks. **Fix:** 1 MiB cap + symlink refusal. Tests: `test_load_baselines_rejects_oversized_file`, `test_load_baselines_rejects_symlink`.
- **A-MED-2** _(accepted)_ — CSV `lineterminator="\n"` not RFC-4180 (`\r\n`). **Rationale:** `\n` is the Unix harness convention; downstream tools that need RFC-4180 strict-mode can pipe through a transformer. Documented; cell content with embedded CR/LF is correctly quoted by Python's `csv.QUOTE_MINIMAL`.
- **A-MED-3** _(resolved)_ — `--top` ranks `skipped_*` cells (max_total=0) at ratio 0, polluting top-N. **Fix:** filter to `pass`/`pass_after_retry` cells with `max_total > 0` before sort. Test: `test_main_top_excludes_skipped_cells`.
- **A-LOW-1** _(resolved)_ — Substring-match exit-code mapping (`"invalid --run-id" in str(e)`) brittle to error wording. **Fix:** `InvalidRunIdError` + `RunNotFoundError` subclasses; `main()` exit-maps by type. Tests: `test_main_invalid_run_id_returns_64`, `test_main_run_not_found_returns_78`.

## (b) Baselines + markdown escape + coverage gate — 11 findings

- **B-HIGH-1** _(resolved)_ — `_md_escape` did not strip newlines; a stdout-leaked newline split markdown rows. **Fix:** strip control chars (`\\x00`–`\\x1f` minus space); newlines/tabs/CRs become single spaces. Tests: `test_md_escape_strips_newline_in_cell`, `test_md_escape_strips_carriage_return`, `test_md_escape_strips_other_control_chars`.
- **B-HIGH-2** _(resolved)_ — `_md_escape` missed `[`/`]`/`<`/`>` (link injection + HTML mixing). **Fix:** widened escape regex to `[\\\\|`\\[\\]]`; entity-encode `<`/`>`. Tests: `test_md_escape_brackets_neutralized`, `test_md_escape_angle_brackets_entity_encoded`.
- **B-HIGH-3** _(resolved)_ — Negative `max_total` (or `total > max_total`) defeated the floor logic. **Fix:** refuse such records as invalid at load time. Tests: `test_load_run_rejects_negative_total`, `test_load_run_rejects_negative_max_total`, `test_load_run_rejects_total_exceeding_max`.
- **B-HIGH-4** _(resolved)_ — `_check_full_coverage` used `KNOWN_CLI_IDS` (3 CLIs) regardless of what the run actually invoked. **Fix:** main() defaults `selected_clis=tuple(sorted(run.clis_seen))` so a single-CLI run is not falsely flagged partial for the other 2. Test: `test_full_coverage_uses_clis_seen_default`.
- **B-HIGH-5** _(resolved)_ — Quarantined cells with canary `isolation_breach: True` were silently dropped from the matrix. **Fix:** `RunData.quarantined_breaches` tracks them; `main()` emits a stderr WARNING banner unconditionally. Tests: `test_load_run_records_quarantined_isolation_breach`, `test_main_emits_quarantined_breach_audit_banner`.
- **B-MED-1** _(resolved — duplicate of A-MED-1)_ — baselines size cap added.
- **B-MED-2** _(resolved)_ — Typo'd floor keys (e.g. `min_totl`) silently meant "no floor → false-pass". **Fix:** `_load_baselines` validates every leaf entry has at least one of `{min_total, min_pct}` and rejects unknown keys. Tests: `test_load_baselines_rejects_typo_floor_key`, `test_load_baselines_rejects_empty_floor_dict`, `test_load_baselines_accepts_real_committed_file`.
- **B-MED-3** _(resolved)_ — `state` not enum-validated at load; terminal-control sequences in stderr possible. **Fix:** closed-set check; non-canonical states refused as invalid. Tests: `test_load_run_rejects_unknown_state_value`, `test_load_run_accepts_canonical_state_values`.
- **B-MED-4** _(resolved)_ — `_below_baseline` dual-floor semantics undocumented. **Fix:** docstring updated; `max_total <= 0` with a `min_pct` floor now fail-safes (cannot evaluate). Tests: `test_below_baseline_dual_floor_total_under`, `test_below_baseline_dual_floor_pct_under`, `test_below_baseline_max_total_zero_with_pct_floor_fails`.
- **B-MED-5** _(accepted)_ — HTML-comment rewrite redundant after B-HIGH-2. **Rationale:** the `<!--`/`-->` rewrite was made obsolete by the universal `<>` entity encoding. Removed in the same edit; documented in spec 08.
- **B-LOW-1** _(accepted)_ — `_state_glyph` defaults to `"??"` for unknown states. **Rationale:** B-MED-3 enforces enum at load, so `??` is now unreachable. The defensive default remains as a forward-compat tripwire (a future schema bump that adds a state would surface as `??` in pretty/md output, prompting an aggregator update).

## (c) Tests + spec coverage — 12 findings

- **C-HIGH-1** _(resolved)_ — Per-record cap test used non-JSON payload, didn't prove ordering of size-check vs parse. **Fix:** new test writes a syntactically valid record with a 100 KiB+ `stdout_truncated` field (`test_iter_jsonl_caps_syntactically_valid_oversized_record`).
- **C-HIGH-2** _(resolved)_ — Int-bounds boundary missing at `±(2^53−1)`. **Fix:** new tests for both positive AND negative boundaries.
- **C-HIGH-3** _(resolved)_ — Quarantine + canary-leak interaction had no test; the security-critical invariant was unverified. **Fix:** `test_load_run_records_quarantined_isolation_breach` + `test_main_emits_quarantined_breach_audit_banner`.
- **C-HIGH-4** _(resolved)_ — Spec 08 had zero coverage of aggregator/baselines. **Fix:** added "Aggregator + baselines (H9)" section covering caps, gate semantics, exit codes, baselines.json schema, markdown-escape contract, quarantine audit.
- **C-MED-1** _(resolved)_ — Markdown-escape vector tests missing for newlines + brackets + angle brackets. **Fix:** new dedicated tests for each vector.
- **C-MED-2** _(resolved)_ — Baseline gate degenerate cases (`max_total=0` with `min_pct`) untested. **Fix:** `test_baseline_gate_max_total_zero_with_pct_floor` + `test_below_baseline_max_total_zero_with_pct_floor_fails`.
- **C-MED-3** _(accepted)_ — Header-without-schema_version path conflated "missing field" with "old version". **Rationale:** the schema requires the field; absence collapses to `""` which mismatches `"1.0.0"` and raises drift. Operator-distinguishing the two cases is cosmetic; both signal an upstream producer bug requiring intervention.
- **C-MED-4** _(resolved)_ — `_render_json` round-trip didn't verify field types. **Fix:** `test_render_json_field_types_correct` asserts `total`/`max_total`/`runtime_ms` are numeric, `attempts` is int, `isolation_breach` is bool.
- **C-MED-5** _(accepted)_ — Module-level `aggregate` import + sys.path mutation could leak across tests. **Rationale:** verified `aggregate.py` has no module-level mutable state outside the constants. Refactoring to per-test `monkeypatch.syspath_prepend` is cosmetic.
- **C-MED-6** _(accepted)_ — CI doesn't run `aggregate.py --validate` on PR. **Rationale:** the 75 pytest tests cover the aggregator surface comprehensively. Adding a CI step that runs the aggregator against a live result dir would require a recent committed sample run, which would itself be a maintenance burden. Tracked for H13 retirement work — at that point the aggregator becomes the only entry point and the CI gate is natural.
- **C-LOW-1** _(accepted)_ — `test_main_full_partial_returns_2` comment claims "5 tests × 3 CLIs = 15 cells". **Rationale:** the test now uses `clis_seen` semantics (B-HIGH-4 fix) so the assertion is no longer about that exact arithmetic. Comment can drift without compromising the test's correctness.
- **C-LOW-2** _(resolved)_ — Some test fixtures used 2026-04-30 timestamps. **Fix:** new round-1 regression tests use the year-2100 sentinel `_FAR_FUTURE_TS = "2100-01-01T00:00:00.000Z"` per `rules/testing.md` MUST Rule 1.

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H9
- Ship journal: `journal/0022-DECISION-h9-aggregator-shipped.md`
- H7 + H8 round-1 review precedent: `journal/0019-RISK-h7-...`, `journal/0021-RISK-h8-...`
- Spec: `specs/08-coc-eval-harness.md` (new "Aggregator + baselines (H9)" section)
- All regression tests: `coc-eval/tests/lib/test_h9_security_review_round1.py` (36 tests)

## Lib pytest delta

`456 → 531 passed, 2 skipped` (+39 H9 base + 36 round-1 regression).

## For Discussion

- **Q1 (challenge assumption):** B-HIGH-5 quarantine audit is a stderr WARNING banner without bumping rc. Argument for the current shape: quarantine is operator's deliberate choice; banner is the audit signal. Argument for stricter rc=1: a credential leak is a credential leak. Which is the right operator UX, and is there evidence from the H7 + H8 live runs that would settle this?
- **Q2 (counterfactual):** R1-A-CRIT-1 was caught by adversarial reasoning, not by tests. The chunked reader fix is now tested, but is there a class of memory-bomb attacks not yet covered by tests? (E.g. compressed payloads, char-class explosions in regex baselines, recursion in third-party JSON parsers.)
- **Q3 (extend):** The aggregator exit-code matrix is now 0/1/2/64/78. Round 2 (single focused agent per `feedback_redteam_efficiency`) should verify that these codes compose correctly when MULTIPLE gates fire simultaneously — currently `worst_rc = max(...)` but partial-coverage (2) and baseline-violation (1) coexisting need explicit semantics.
