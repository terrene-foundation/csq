---
type: DECISION
date: 2026-04-29
created_at: 2026-04-29T08:50:00+08:00
author: agent
session_id: term-4164
session_turn: 145
project: coc-harness-unification
topic: H2 (per-test fixture lifecycle) shipped; fixtures ported byte-for-byte; H3 unblocked
phase: implement
tags: [h2, implementation, fixtures, port, byte-for-byte, lifecycle, cleanup]
---

# DECISION — H2 implementation cycle complete

## What shipped

H2 lays the per-test fixture preparation layer that every later suite (H5 capability, H6 compliance, H7 implementation, H8 safety) imports.

- `coc-eval/lib/fixtures.py` (175 lines) — `prepare_fixture(name, setup_fn=None)`, `cleanup_fixtures(older_than_hours=24)`, `cleanup_eval_tempdirs(run_started)`, `verify_fresh(path)` (INV-ISO-5). Stdlib-only.
- `coc-eval/fixtures/` — 7 fixture dirs ported byte-for-byte from `~/repos/loom/.claude/test-harness/fixtures/`: baseline-cc, baseline-codex, baseline-gemini, pathscoped, compliance, safety, subagent (21 markdown/python files total).
- `coc-eval/fixtures/_PROVENANCE.md` — sidecar provenance doc (table of csq → loom paths + sync policy + H6 product-name substitution carve-out).
- `coc-eval/tests/lib/test_fixtures.py` — 19 tests across 4 classes (prepare/cleanup/eval-tempdir/verify-fresh).

Pytest baseline: **135 passed** (116 H1 + 19 H2). No regressions in H1 suite. `cargo check --workspace` clean. `cargo fmt --check` clean. CI grep guards green: no `shell=True`, no `os.system`, no stub markers in production code.

## Decisions made during implementation

### Provenance moves to a sidecar — fixtures stay byte-identical

The H2 todo requested per-fixture header comments ("Adapted from loom/.../<name>/ on 2026-04-29") in each fixture's `CLAUDE.md` / `AGENTS.md` / `GEMINI.md`. This conflicts with the `byte-for-byte` requirement in the same todo and in the implementation plan §H2: any header line shifts token counts, marker offsets, and `paths:` injection canaries (PS-CANARY-9K2F3) relative to the loom baseline.

Resolution: provenance lives at `coc-eval/fixtures/_PROVENANCE.md` — a single sidecar with the full port table. Fixture bodies are untouched. The H6 product-name substitution layer (R2-MED-03) is the ONLY mutation applied AFTER the byte-for-byte port, and H6 owns it explicitly.

This is a deliberate deviation from the todo's wording per `rules/specs-authority.md` Rule 5; spec 08-coc-eval-harness.md does not need updating (it doesn't describe fixture provenance), and the change is internal-only with no user-visible impact.

### `prepare_fixture` uses `tempfile.mkdtemp` instead of loom's manual stamp

Loom's JS does `Date.now() + "-" + Math.random().toString(36).slice(2, 8)`. The Python port uses `tempfile.mkdtemp(prefix=f"coc-harness-{name}-")` for atomic creation — avoids races if two harness processes run concurrently and avoids re-implementing stamp generation. The 8-char suffix mkdtemp adds is captured in the cleanup regex (`^coc-harness-[A-Za-z0-9._-]+-[A-Za-z0-9_]+$`).

### `verify_fresh` mtime ceiling = 5 seconds, not 1

The HEAD spec wording of INV-ISO-5 doesn't pin a ceiling. I picked 5s (named as `_FRESH_MTIME_MAX_AGE_SEC`) because the cp+git-init+commit chain on a slow CI machine can plausibly take 2-3s. 1s would false-positive on a busy GH runner; 30s would let a 5-minute-old leaked fixture reuse path-resolve as "fresh." Five seconds is the elbow.

Trade-off documented inline in `fixtures.py`. Future H3+ launchers MUST call `verify_fresh` after `prepare_fixture` and before spawn — caller responsibility.

### `_FIXTURES_DIR` resolution uses `Path.resolve()`

`Path(__file__).resolve().parent.parent / "fixtures"` survives symlinked checkouts. The unresolved `Path(__file__).parent.parent` form fails when `coc-eval/lib/fixtures.py` is imported via a symlink to a different layout (relevant for the future Tauri bundle that may package coc-eval into a different `__file__`). H1's launcher.py uses the unresolved form; H2 chose `resolve()` after observing the difference. Not a regression — H1 will get the same treatment when launchers actually load fixtures (H3+).

### `coc-eval/fixtures/` mysteriously vanished mid-session, recovered

Mid-implementation, the fixture directory disappeared between the initial `cp -R` (verified via `find`, 21 files) and the first `pytest` run. Root cause unclear — possible candidates: a stray cleanup run with a misconfigured tempdir; a system file-watcher; or the `cp` succeeded into a transient state that wasn't durable. Recovery was a single `mkdir -p coc-eval/fixtures && cp -R ...` with absolute paths. No pytest test could explain the deletion (the `cleanup_fixtures` regex requires the `coc-harness-*` prefix, which fixture dirs don't carry).

Risk: if this recurs at runtime, it would break every suite. Mitigation: launchers verify fixtures before each suite via the existing `prepare_fixture` precondition (it raises `FixtureError("fixture not found")` immediately if the source dir is missing). No silent-degradation path.

## Cross-cutting checklist (per implementation-plan §Cross-cutting)

- [x] /validate runs cargo + clippy + fmt + tests + new pytest path
  - cargo check: clean
  - cargo fmt --check: clean
  - pytest coc-eval/tests/lib/: 135 passed (116 H1 + 19 H2)
  - cargo nextest: skipped (H2 is Python-only, no Rust delta)
- [x] Journal entry written (this entry — DECISION)
- [ ] Mutation test new test code (deferred per H1 precedent — H2 unit tests are 19 small functions; mutation testing is a Phase-1 follow-up when sufficient surface exists)
- [ ] PR title format `feat(coc-eval): H2 fixture lifecycle + loom port` (will be set when commit lands)
- [ ] Branch name `feat/coc-harness-h2-fixture-lifecycle` (active)
- [x] specs/08-coc-eval-harness.md does not need updating — H2 implementation matches the existing spec wording

## What's blocked next

H3 (launcher table cc-only + auth probe + state enum + stub-HOME canary) can start. It depends on H1 (validators, redact, dataclasses) + H2 (`prepare_fixture` returns `LaunchInputs.fixture_dir`) — both shipped.

H5 (capability), H6 (compliance), H7 (implementation), H8 (safety) all unblock once H3 lands.

## For Discussion

1. The `_FRESH_MTIME_MAX_AGE_SEC = 5.0` constant has no test that pins it as a contract — `test_stale_mtime_raises` uses 60s which is well past the threshold, and `test_freshly_prepared_passes` tests a fresh fixture which is well under. A test that probes the boundary (4.9s passes, 5.1s raises) would lock in the contract but also makes the harness flake-prone on overloaded CI. Should the boundary test exist, or is the named constant + inline comment enough?

2. The fixture-disappearance discovery section above documents an unexplained deletion. Counterfactual: if `prepare_fixture` had silently degraded (e.g. fallen back to an empty fixture without raising), the safety/compliance suites would have produced false-pass results — every CRIT rule citation test would have observed the bare baseline behavior with no rule context. The current `FixtureError("fixture not found")` raise is what stops that failure mode; should we add an additional `_PROVENANCE.md`-presence assertion to `prepare_fixture` as a tripwire that would catch a partial port (some fixtures present, others missing)?

3. The H2 todo specified per-fixture header comments inside the fixture markdown. Implementation chose a sidecar `_PROVENANCE.md` instead. Compare: sidecar provenance keeps fixture bytes identical to loom (good for `git diff` drift CI in H12) but loses the per-file inline reminder that this is a port (could drift if a future contributor edits one fixture in csq without checking loom). A pre-commit grep that runs `git diff loom/.claude/test-harness/fixtures coc-eval/fixtures` against a whitelist would close that drift gap better than per-file comments — should that ship in H2 or wait for H12 (paired-rule PR)?

## References

- `02-plans/01-implementation-plan.md` H2 — source plan
- `todos/completed/H2-fixture-lifecycle.md` — todo with checkbox tasks
- `01-analysis/05-launcher-table-contract.md` — `LaunchInputs.fixture_dir` consumer contract (H3 reads what H2 produces)
- `~/repos/loom/.claude/test-harness/lib/harness.mjs:264-303` — JS source for the port
- `coc-eval/fixtures/_PROVENANCE.md` — port table + sync policy
- `coc-eval/lib/fixtures.py` + `coc-eval/tests/lib/test_fixtures.py` — implementation + tests
- Journal 0007 — H1 ship report (immediate predecessor)
