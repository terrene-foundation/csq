---
type: DECISION
date: 2026-04-29
created_at: 2026-04-29T13:30:00+08:00
author: agent
session_id: term-35747
session_turn: 320
project: coc-harness-unification
topic: H4 (JSONL writer + schema v1.0.0 + run-id + aggregator hardening primitives) shipped; H5-H8 unblocked
phase: implement
tags:
  [
    h4,
    implementation,
    jsonl,
    schema,
    redaction,
    run-id,
    forward-compat,
    aggregator-hardening,
  ]
---

# DECISION — H4 implementation cycle complete

## What shipped

H4 lays the persistence layer that every later suite (H5 capability, H6 compliance, H7 implementation, H8 safety) writes through, plus the aggregator-hardening primitives (H9 reads via these). Stdlib-only, no PyPI deps.

- `coc-eval/lib/schema_validator.py` (NEW, 175 LOC) — extracted from H1's `suite_validator.py` and extended to support `pattern` (regex), multi-type arrays (e.g. `["string", "null"]`), `null` type, `number` type, and intra-document `$ref` resolution against `#/definitions/...`. Bounded recursion at depth 64 (M4).
- `coc-eval/lib/run_id.py` (NEW, 60 LOC) — `generate_run_id()` returns `<iso8601-second>-<pid>-<counter>-<rand>`. CSPRNG suffix via `secrets.token_urlsafe(6)`. `validate_run_id()` enforces `RUN_ID_RE.fullmatch` BEFORE any FS op.
- `coc-eval/lib/jsonl.py` (NEW, ~480 LOC) — `JsonlWriter` (open + write_header + record_result + write_log + close), `validate_record`, `escape_md`, `read_record`, `iter_records`, `now_iso8601_ms`. Token redaction applied recursively to every string in every record before serialization (defense-in-depth, H4 review H1). Per-line cap 100 KB hard; per-file cap 10 MB; bounded `parse_int` at 19 digits.
- `coc-eval/schemas/v1.0.0.json` (NEW) — full JSON Schema draft-07 document with `definitions` for `iso8601_ts`, `run_id`, `suite_name`, `state`, `criteria_kind`, `auth_probe`, `criterion`, `tier`, `score`, `header_record`, `test_record`. Forward-compat: every `additionalProperties` defaults to `true`.
- `coc-eval/lib/suite_validator.py` — refactored to import from the shared `schema_validator`; `SchemaValidationError` → `SuiteValidationError` mapped at the boundary so callers see the same surface as before.
- `coc-eval/lib/__init__.py` — module list updated.
- Tests: `tests/lib/test_run_id.py` (13), `tests/lib/test_jsonl.py` (24, incl. 5 security regressions), `tests/lib/test_aggregator_hardening.py` (12), plus a cyclic-$ref guard test added to `test_suite_validator.py`. **+48 lib tests vs 186 H3 baseline → 234 passed.**
- `tests/lib/test_process_group.py` — `test_spawn_returns_running_proc` timeout bumped from 5 s to 15 s after a flake under multiprocessing-test contention. Pre-existing issue surfaced under H4's heavier suite; fixed in-session per zero-tolerance Rule 1.
- Integration: existing AC-16 canary + capability smoke STILL GREEN on real cc (account 8) with the H4 writer in scope of imports.

`cargo check`/`cargo fmt`/stub-scan/`shell=True` greps: clean. The H4 suite is stdlib-only.

## Decisions made during implementation

### `_filter_settings_overlay` → `filter_settings_overlay` … reused decision shape

H3 dropped the leading-underscore on the public allowlist filter for the same reason: Pyright complains about unused private functions, and the function IS the public contract. H4 follows the same convention: `validate_record`, `escape_md`, `read_record`, `iter_records`, `now_iso8601_ms` are public surface. `_deep_redact_record` and `_resolve_ref` stay private.

### Deep redaction beats per-field redaction

The H3 `record_result` redacted only `stdout_truncated` and `stderr_truncated`. The security review (H1 finding) flagged the `extra` kwarg on `write_header` as a redaction-bypass sink. Two options surfaced:

1. **Per-field redaction**: redact known token sinks; document operator responsibility for everything else.
2. **Deep redaction**: walk the entire record recursively and pass every string through `redact_tokens`.

Option 2 wins on durability — adding a new field in `06-jsonl-schema-v1.md` doesn't require a redaction-list update. `redact_tokens` is byte-pattern-based and idempotent; double-redacting `stdout_truncated` (which the producer might already have redacted) yields identical bytes. Cost is dominated by the existing stdout/stderr fields, so the wider walk adds negligible CPU.

### Schema validator extraction beats inline extension

H1 had a private `_validate_against_schema` baked into `suite_validator.py`. H4 needed `pattern`, multi-type arrays, `null`, and `$ref` — extending in-place would have left the validator inseparable from suite-specific logic, blocking JSONL reuse. Extraction to `schema_validator.py` with a public `validate_against_schema` and `SchemaValidationError` keeps both consumers (suite + jsonl) honest. The `SuiteValidationError` is preserved at the boundary for backward compat.

### `additionalProperties: true` (default) at every scope

The JSONL contract (06-jsonl-schema-v1.md §"Schema versioning rules") mandates forward-compat: future minor versions add fields; tooling consumes only known fields. The schema document leans on the validator's default-true behavior — no scope sets `additionalProperties: false`. A forward-compat test (`test_unknown_field_validates`) pins this contract.

### Optional-field omission instead of nullable

The schema declares `harness_invocation`, `model_id`, `token_budget`, etc. as `type: string` (not nullable). Initial `write_header` emitted `null` for unset values, breaking validation. Fix: omit unset optional fields entirely from the record. Cleaner contract — null vs missing-key vs empty-string is a forever-confusing trichotomy, and the JSONL spec doesn't differentiate.

### `mp.get_context("spawn").Pool(5)` for run-id collision test

`spawn` (vs `fork`) gives each worker a fresh interpreter — strongest test of cross-process uniqueness (independent counters, independent `os.getpid()`, independent CSPRNG state). The cost is +0.5s startup but worth it for AC-11a's stated rigor.

### Trusted-prefix allowlist for `git` instead of full env scrub

The security review (H2 finding) flagged `subprocess.run(["git", ...])` as PATH-resolvable to a hostile shim. Two options:

1. **Resolve via `shutil.which` and validate against an OS-managed prefix allowlist** (`/usr/bin/`, `/bin/`, `/usr/local/bin/`, `/opt/homebrew/bin/`). User-installed shims at `~/bin/git` are untrusted → skip the check.
2. **Always-skip the check** if `git` isn't at a known-safe absolute path.

Option 1 keeps the gitignore guard active for legitimate users while neutralizing PATH-hijack attacks. Combined with a stripped subprocess env (`{PATH, HOME, LANG}` only), GIT\_\* env-var injection is also closed.

## Cross-cutting checklist (per implementation-plan §Cross-cutting)

- [x] `cargo check`: clean
- [x] `cargo fmt --check`: clean
- [x] `pytest coc-eval/tests/lib/`: 234 passed (was 186 H3 baseline; +48)
- [x] `pytest coc-eval/tests/integration/`: 2 passed (AC-16 + capability smoke)
- [x] Stub scan / `shell=True` / `os.system` greps: clean
- [x] Journal entry written (this — DECISION 0012); security-review convergence in 0013
- [ ] Mutation testing (deferred per H1/H2/H3 precedent — H4 unit tests are 48 small functions; not enough surface area)
- [ ] PR title format `feat(coc-eval): H4 JSONL writer + schema v1.0.0` (set when PR opens)
- [ ] Branch name `feat/coc-harness-h4-jsonl-schema` (active)
- [x] specs/08-coc-eval-harness.md unchanged — H4 matches the existing JSONL spec wording (parallel-arrays, closed state taxonomy, stdlib-only, per-line cap, redaction at persistence)

## Acceptance criteria — H4 gate

- **AC-6** (schema validation last 100 records): `validate_record` runs at every write; `iter_records` round-trips through schema OK in tests.
- **AC-7** (closed state taxonomy): `test_invented_state_rejected` confirms unknown enum values fail.
- **AC-11a** (run-id collision resistance): `TestRunIdCollisionResistance::test_five_parallel_generators` passes with `mp.get_context("spawn").Pool(5)`.
- **AC-20** (redaction canary): `TestRedactionCanary::test_token_in_stderr_redacted_on_disk` + `test_token_in_stdout_redacted` + `TestExtraKwargRedacted::*` confirm `sk-ant-oat01-` substrings never reach disk.
- **AC-21** (path-traversal blocked): `TestPathTraversalBlocked::*` verifies malformed run_id + unknown suite both abort BEFORE creating any FS path.

## What's blocked next

- **H5 (capability suite):** unblocked. Will write through `JsonlWriter`, score via `score.criteria` (regex backend).
- **H6 (compliance):** unblocked. Same writer, same backend.
- **H7 (implementation):** unblocked. Tiered_artifact backend writes `score.tiers`.
- **H8 (safety + cross-suite ordering):** unblocked.
- **H9 (aggregator + run-id scoping + baselines):** the writer + reader + escape_md + caps are all in place; H9 wires them into the Markdown emitter.

## For Discussion

1. **Deep redaction performance ceiling.** The current `_deep_redact_record` walks every string in every record on every write. For a 100-record-per-suite typical run, that's ~700 string traversals (header has ~7 sub-fields with cli_versions/auth_probes; record has ~30). Counterfactual: if a future suite emits 10000-line records (e.g. an EVAL implementation suite that captures every model turn), the redactor cost dominates. Should H4 introduce a "redaction depth" cap (e.g. don't recurse into `artifacts.git_diff` because it's already redacted by the producer), or trust that record sizes stay bounded by the 100 KB per-line cap (which forces operators to truncate before write)?

2. **`run_id` PID component vs container parity.** PID disambiguation works on a single host but two containers running on the same kernel image MAY have overlapping PID namespaces (especially with PID-rewriting init shims). The CSPRNG suffix still ensures uniqueness, so PID is structural disambiguation — not strict. Should the run_id format add a hostname component for cross-host collation, or accept that aggregation across hosts is a v1.1 concern?

3. **Optional-field omission vs null-typed schema.** H4 omits unset optional fields rather than emitting `null`. Compare: emitting `null` keeps the record shape stable across runs (every header has the same key set), making downstream aggregator joins simpler. Omission is cleaner JSON but creates `KeyError` traps in naive consumers. Should the spec be amended to require `null` for unset optionals + the schema be updated to make every optional `["type", "null"]`, or stay with omission (current) and document the contract?

## References

- `02-plans/01-implementation-plan.md` §H4 — source plan.
- `01-analysis/06-jsonl-schema-v1.md` — JSONL contract (header shape, run-id format, parallel-arrays score, state taxonomy).
- `todos/active/H4-jsonl-writer-schema.md` — todo with checkbox tasks.
- `coc-eval/schemas/v1.0.0.json` — the schema artifact.
- `coc-eval/lib/{jsonl,run_id,schema_validator}.py` — the H4 implementation.
- `coc-eval/tests/lib/{test_jsonl,test_run_id,test_aggregator_hardening}.py` — H4 tests.
- Journal 0010 — H3 ship report (immediate predecessor).
- Journal 0011 — H3 security-review convergence (template for journal 0013).
- Journal 0013 — H4 security-review convergence (companion to this entry).
