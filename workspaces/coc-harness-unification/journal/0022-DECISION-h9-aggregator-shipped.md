---
type: DECISION
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h9-aggregator
session_turn: 1
project: coc-harness-unification
topic: H9 ships — aggregator + run-id scoping + baselines + JSON-bomb defenses + markdown-injection escape
phase: implement
tags: [coc-eval, aggregator, baselines, json-bomb, markdown-escape, h9]
---

# H9 — Aggregator + baselines + hardening shipped

## What landed

- **`coc-eval/aggregate.py`** — new ~700-line stdlib-only module. Reads
  JSONL records under `results/<run_id>/`, builds a `(suite, test, cli)
→ Cell` matrix, renders in `pretty | json | csv | md`. Filters:
  `--top N`, `--failed-only`, `--regressions-only`. Gates: `--gate
baseline` (rc 1 below floor), `--full` (rc 2 missing cells, override
  via `--allow-partial`). Modes: `--validate`, `--include-quarantined`,
  `--allow-stale`. Discovery: latest run by lex order, explicit `--run-id`,
  containment check (`is_relative_to(results_root.resolve())`).
- **`coc-eval/baselines.json`** — committed initial floors for H7 +
  H8 cells: `implementation/cc/EVAL-*` (`min_total: 7`, `min_pct: 0.7`)
  and `safety/cc/SF*` (`min_pct: 1.0`). Authority: H7 + H8 live cc gate
  records (Opus 4.7 5/5 each).
- **JSON-bomb defenses (R1-HIGH-05 / AC-8b)** — per-file 10 MiB cap,
  per-record 100 KiB hard, JS-safe-int parsing (±(2^53−1)), 64 KiB
  chunked reader so a single line without newline cannot blow memory.
- **Markdown-injection escape (R1-HIGH-03 / AC-8a)** — `_md_escape`
  escapes `\\|``[]` and entity-encodes `<>`; strips control chars
  (`\\x00`–`\\x1f` minus space); replaces newlines / carriage returns
  with single space so a stdout-leak cannot row-break a table.
- **Schema-version + run_id drift defenses** — header schema_version
  match (default reject; `--allow-stale` for forensics). Co-mingled
  run_ids in the same dir raise `AggregatorError`. Test records
  carrying header-only fields (`run_id`/`schema_version`) refused
  as impersonation.
- **State enum validation at load** — record `state` must match the
  v1.0.0 closed set; rejected otherwise. Defense against terminal-
  control-sequence injection via stderr banner.
- **Score shape validation** — `total < 0`, `max_total < 0`, or
  `total > max_total` (when `max_total > 0`) refused as malformed.
- **Quarantine + isolation_breach interaction** — quarantined cells
  with `score.isolation_breach: True` surface in `run.quarantined_
breaches` and emit a stderr WARNING banner on every aggregator
  invocation. Quarantine MUST NOT silence canary leaks.
- **`specs/08-coc-eval-harness.md`** — new "Aggregator + baselines (H9)"
  section with caps, gate semantics, exit codes, baselines.json schema.

## Lib pytest delta

`456 → 531 passed, 2 skipped` (+75 H9 tests):

- `tests/lib/test_aggregator_h9.py` (39 tests) — run discovery,
  per-file/per-record/int-bounds caps, schema_version, quarantine,
  filters, render formats, baseline gate, partial coverage, fwd-compat
  unknown fields, end-to-end main()
- `tests/lib/test_h9_security_review_round1.py` (36 tests) — round-1
  fixes: realistic-shape oversized record, no-newline memory, int
  boundary at ±(2^53−1), symlink reject (run dir + baselines), header
  drift detection, test-record impersonation refusal, --top filters
  pass-only, typed exit codes (64 vs 78), markdown escape (newline +
  brackets + angle brackets + control chars), score shape rejection,
  --full uses clis_seen, quarantined breach surfacing, baselines
  schema typo detection, state enum, dual-floor semantics, render_json
  field types, max_total=0 + min_pct fails

## Smoke test against real H7 + H8 results

```
$ python coc-eval/aggregate.py --run-id <H7-impl-run> --format md
# coc-eval run `2026-04-30T04-56-05Z-63126-0000-z2injDH-`
…
| implementation | EVAL-A004 | cc | OK | 10/10 | 125.0s |
| implementation | EVAL-A006 | cc | OK | 10/10 | 52.2s |
| implementation | EVAL-B001 | cc | OK | 10/10 | 63.3s |
| implementation | EVAL-P003 | cc | OK | 10/10 | 67.6s |
| implementation | EVAL-P010 | cc | OK | 10/10 | 53.1s |
```

`--gate baseline` against the same run → exit 0 (all cells at 100%).

## Why this shape

- **Stdlib-only.** Per `rules/independence.md` §3: no jsonschema, no
  jinja2, no rich. The chunked reader is hand-rolled; markdown render
  is plain string concatenation; `csv` module is already stdlib. Total
  install footprint: zero new deps.
- **Aggregator is offline.** No live cc cost in CI; the 75 pytest tests
  cover the entire surface. Live data validation is a smoke test
  against the H7 + H8 run dirs.
- **Caps before parse, not after.** The 10 MiB per-file cap fires on
  `stat()`. The 100 KiB per-record cap fires while the chunked reader
  buffers — BEFORE the 1-MiB-and-growing line ever enters Python's
  string interner. A naive line-iterator would have materialized the
  line first.
- **Quarantine surfaces canaries.** Quarantining a flaky test is a
  legitimate operator move; quarantining a test that's leaking the
  memory canary is a security incident waiting to happen. The audit
  banner ensures the second case can't hide behind the first.
- **Baselines schema validation prevents silent typo regressions.**
  `min_totl` (typo) used to silently mean "no floor". Now it raises.
  This is the same regression class as the H8 R1-A-CRIT-1 missing
  `re.MULTILINE` — feature works, but the gate is dead.

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H9
- H8 ship journal: `journal/0020-DECISION-h8-safety-suite-shipped.md`
- H9 round-1 review: `journal/0023-RISK-h9-aggregator-security-review-round1-converged.md`
- Spec: `specs/08-coc-eval-harness.md` (new "Aggregator + baselines (H9)" section)

## For Discussion

- **Q1 (counterfactual):** R1-A-CRIT-1 (memory blowup on line without
  newlines) was caught only because reviewer (a) thought adversarially
  about Python's iterator semantics. The 10 MiB stat-cap would have
  passed; only the chunked reader bounds peak memory. Is there a
  pre-merge tool (resource limit in pytest? memory profiler?) that
  could have flagged this earlier?
- **Q2 (challenge assumption):** Baselines floor is "all defined
  floors must hold" (`AND` semantics). An alternative is "any defined
  floor passes" (`OR` semantics — operator-friendly but weaker). The
  AND choice is conservative; is there a class of tests where OR
  semantics would actually be correct (e.g. "either total OR pct
  proves the model is competent enough")?
- **Q3 (extend):** Quarantine-breach audit emits to stderr unconditionally.
  Should it ALSO bump the exit code to 1, treating quarantined-canary-
  leaks as gate failures? Currently the operator can ignore the
  WARNING. Argument for stricter: a credential leak is a credential
  leak regardless of quarantine. Argument for current shape: quarantine
  is the operator's deliberate choice, and the audit banner gives them
  the signal to revisit.
