---
type: DECISION
date: 2026-04-28
created_at: 2026-04-29T00:30:00+08:00
author: agent
session_id: term-4164
session_turn: 110
project: coc-harness-unification
topic: H1 (spec + scaffolding + validators) shipped; foundation laid for H2-H13
phase: implement
tags: [h1, implementation, foundation, redact-port, validators, suite-schema]
---

# DECISION — H1 implementation cycle complete

## What shipped

H1 is the foundational PR — every subsequent PR (H2-H13) imports from `coc-eval/lib/`. Surface area:

- `specs/08-coc-eval-harness.md` (165 lines) — durable spec per `rules/specs-authority.md`.
- `coc-eval/README.md` — operator quick-start with sandbox prerequisites + UX-13 error catalogue.
- `coc-eval/lib/__init__.py` — package marker.
- `coc-eval/lib/validators.py` (107 lines) — `FIXTURE_NAME_RE`, `validate_name`, `SUITE_MANIFEST`, per-suite test manifests, `validate_cli_id`.
- `coc-eval/lib/redact.py` (175 lines) — Python port of `csq-core::error::redact_tokens` with word-boundary parity (R1-HIGH-01).
- `coc-eval/lib/states.py` (113 lines) — `class State(str, Enum)` with within-test + across-test precedence ladders (R2-MED-01).
- `coc-eval/lib/launcher.py` (172 lines) — `LaunchInputs`/`LaunchSpec`/`AuthProbeResult`/`CliEntry` dataclasses, `PERMISSION_MODE_MAP`, `SANDBOX_PROFILE_MAP`, `CLI_TIMEOUT_MS`, `CLI_REGISTRY`, `assert_permission_mode_valid` (INV-PERM-1 R2-MED-01).
- `coc-eval/lib/suite_validator.py` (165 lines) — `validate_suite` against `schemas/suite-v1.json` with INV-PAR-2 carve-out for `skipped_artifact_shape` (R2-MED-02 + R3-CRIT-01).
- `coc-eval/schemas/suite-v1.json` — JSON Schema for SUITE dicts.
- `coc-eval/conftest.py` — sys.path setup so tests can `import lib.X`.
- `pyrightconfig.json` (workspace root) — extraPaths for coc-eval/.
- `coc-eval/tests/lib/` — 116 tests across 5 modules.

All 116 pass. Cargo workspace 1614+ tests still pass. Three CI grep guards green: no `shell=True`, no `os.system`, no glob discovery.

## Decisions made during implementation

### `cd` between bash invocations is unreliable

Sequential `cd coc-eval && ...` calls accumulated working-directory state across tool invocations, leading to a `coc-eval/coc-eval` cwd on the second invocation. Switched to absolute paths via `cd /abs/path && ...` for every bash call. Future H2-H13 implementation agents should follow the same convention.

### `coc-eval` hyphenated dir requires `conftest.py` shim

`coc-eval` is not a valid Python package name (hyphen). Tests import `from lib.X` rather than `from coc_eval.lib.X`. The `conftest.py` at `coc-eval/` adds itself to `sys.path` so pytest auto-discovery works. Pyright at workspace root needs `pyrightconfig.json` with `"extraPaths": ["coc-eval"]` to resolve the imports statically.

### `validate_name` uses `type(s) is not str` not `isinstance(s, str)`

Pyright complained the `isinstance` branch was unreachable given the type annotation. The runtime check is necessary because callers from CLI argparse may pass non-str values the type checker can't see. Using `type(s) is not str` (exact-type check) keeps Pyright happy AND preserves the runtime guard. Trade-off: rejects str subclasses; acceptable because no production caller passes a subclass.

### `scoring_backend` enum check moved to schema, not duplicated in code

Initial implementation had both schema-level enum (`["regex", "tiered_artifact"]`) AND a code-level guard. Round-1 redteam taught that schema authority is the single source of truth. Removed the code-level guard; schema validation catches it first. Test regex updated to match the schema error message.

### `validate_name` errors wrapped in `SuiteValidationError`

A test name with a space (`"C1 baseline root"`) raises `ValueError` from `validate_name`. The suite-validator caller now catches and re-raises as `SuiteValidationError` so callers get a uniform exception type from the suite-validation surface.

## Cross-cutting checklist (per implementation-plan §Cross-cutting)

- [x] /validate runs cargo + clippy + fmt + tests + new pytest path (cargo: 1614+ pass; pytest: 116 pass)
- [x] Journal entry written (this entry — DECISION)
- [ ] Mutation test new test code (deferred per "PR #214 precedent applies once a sufficiently broad test surface exists; H1 is unit-only")
- [ ] PR title format `feat(coc-eval): H1 spec + scaffolding + validators` (will be set when commit lands)
- [ ] Branch name `feat/coc-harness-h1-spec-scaffolding` (will be set when branched)
- [x] specs/08-coc-eval-harness.md created (Rule 4: spec landed at first instance)

## What's blocked next

H2 (per-test tmpdir fixture lifecycle) can start. It depends on H1 (validators, redact, dataclasses) — all shipped. H3 also unblocked (depends on H1+H2; can start once H2 ships).

## For Discussion

1. The redact word-boundary semantics use `(?<![A-Za-z0-9_-])sk-...` lookbehind syntax in the spec — but the actual Python implementation uses a custom char-iteration loop (mirroring Rust's `is_key_char`), NOT a regex. Both produce identical behavior on the fixtures, but the spec describes a regex form that doesn't exist in code. Should the spec be updated to describe the char-iteration approach, or is the lookbehind regex an acceptable pseudo-code abstraction?

2. The 25-fixture parity test (AC-20a) covers ALL pattern CLASSES (known prefix, prefix-with-body, hex, JWT, PEM, word-boundary, edge cases) but does not enumerate 25 specific Rust fixtures byte-for-byte. The full 25 may need adding when H4 wires the redactor into the JSONL writer. Acceptable to defer the strict 25-fixture-byte-for-byte parity to H4, or should it land in H1?

3. Counterfactual — if `coc-eval` had been named `coc_eval` from the start (Python-package-friendly), the conftest.py shim and pyrightconfig.json would be unnecessary. Should we rename the directory in a separate cleanup PR (touches every import + every git history reference) or keep the hyphen for compatibility with the existing csq runner.py and absorb the conftest cost? Going with the latter for now.

## References

- `02-plans/01-implementation-plan.md` H1 — source plan
- `todos/active/H1-spec-scaffolding.md` — todo with checkbox tasks
- `04-validate/03-todos-redteam-findings.md` — R3-CRIT-01 (suite-v1 schema), R3-CRIT-04 (no-shell=True grep)
- `04-validate/02-redteam-round2-findings.md` — R2-MED-01 (state ladder split), R2-MED-02 (INV-PAR-2 carve-out)
- `04-validate/01-redteam-round1-findings.md` — R1-CRIT-02 ($HOME override), R1-CRIT-03 (suite glob ACE), R1-HIGH-01 (redact word-boundary)
- `csq-core/src/error.rs:161 redact_tokens` — Rust source for the Python port
- `coc-eval/.test-results` — test counts + regression check
