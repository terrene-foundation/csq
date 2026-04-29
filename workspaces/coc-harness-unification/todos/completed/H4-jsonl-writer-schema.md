# H4 — JSONL writer + schema v1.0.0

**Goal.** Persistence layer with redaction inline. Schema versioned and forward-compatible.

**Depends on:** H1 (redact, states), H2 (fixture lifecycle), H3 (launcher fields like `home_mode`, `sandbox_profile`).

**Blocks:** H5 (capability writes JSONL), H6, H7, H8, H9 (aggregator reads JSONL).

## Tasks

### Build — JSONL writer

- [ ] Create `coc-eval/lib/jsonl.py`:
  - `set_results_file(run_id: str, suite: str) -> Path`: creates `coc-eval/results/<run_id>/<suite>-<timestamp>.jsonl`; writes empty file. Asserts `git check-ignore coc-eval/results/` succeeds (MED-04 startup assertion); refuses write if path not gitignored.
  - `write_header(suite, started_at, host, cli_versions, auth_probes, fixtures_commit, ...) -> None`: serializes the `_header: true` record per `06-jsonl-schema-v1.md` §Header.
  - `record_result(record: dict) -> None`: applies `redact_tokens` to `stdout_truncated` AND `stderr_truncated` BEFORE serialization; writes one line; appends to companion `.log` file (also redacted).
  - `read_record(line: str) -> dataclass`: returns dataclass with defaults for any optional v1.x field (forward-compat per UX-17 / AC-46).

### Build — run-id format

- [ ] Implement `generate_run_id() -> str` in `coc-eval/lib/runner.py` (or `lib/run_id.py`):
  - Format: `<iso8601-second>-<pid>-<counter>-<rand>` per `06-jsonl-schema-v1.md` (R1-HIGH-04).
  - `<iso8601-second>`: UTC, format `YYYY-MM-DDThh-mm-ssZ`.
  - `<pid>`: `os.getpid()` decimal.
  - `<counter>`: 4-digit zero-padded `itertools.count()` (process-local).
  - `<rand>`: `secrets.token_urlsafe(6)` (8 chars after b64).
- [ ] Setup `results/<run_id>/` directory at run start.

### Build — JSON schema v1.0.0

- [ ] Create `coc-eval/schemas/v1.0.0.json` JSON Schema document. Validates:
  - Header record fields (schema_version, harness_version, run_id format, suite enum, ISO-8601 timestamps, host, cli_versions, auth_probes, etc.).
  - Per-test record (regex backend): `state` enum, `score.criteria` array shape, `kind` values (`contains | absent | fs_assert | tier`), required fields.
  - Per-test record (tiered_artifact backend): `score.tiers` array, `artifacts` shape.
  - Parallel arrays per R1-AD-05: `score.criteria` and `score.tiers` are independent optionals; record may have one, the other, or both.

### Build — companion .log writer

- [ ] `record_result` writes a sibling `<run_id>/<cli>-<suite>-<test>.log` file:
  - Full (untruncated) stdout + stderr, BUT redacted via `redact_tokens`.
  - Header lines: cli + version, test, cmd_template_id, cwd, stub_home, exit code, signal, runtime, timed_out flag, score JSON.
  - File mode 0o600.
- [ ] For tests marked `evidence_required: true` (UX-20 / AC-49), write a sibling `<test>.evidence.log` with mode 0o600, banner header `EVIDENCE LOG — DO NOT COMMIT — DELETE AFTER REVIEW`. **Auto-deleted on next run + records deletion timestamp** in JSONL `evidence_log_deleted_at` field (R3-MED-03).

### Build — aggregator hardening primitives

- [ ] In `coc-eval/lib/jsonl.py`, expose helpers used by `aggregate.py`:
  - Per-file size cap (10MB → skip with warning) (R1-HIGH-05).
  - Per-record byte cap (100KB hard) (R1-HIGH-05).
  - Bounded int parsing: `json.loads(line, parse_int=lambda s: int(s) if len(s) < 20 else 0)`.
  - Markdown escape function: `escape_md(s) -> str` mapping `|→\|`, `<→&lt;`, `>→&gt;`, backticks wrapped, newlines stripped (R1-HIGH-03 / AC-8a).

### Test

- [ ] `coc-eval/tests/lib/test_jsonl.py`:
  - `test_round_trip`: write_header + record_result + read; validate against v1.0.0 schema; deserialize round-trips field-for-field.
  - `test_redaction_canary`: result with `stderr = "auth failed: sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAA"`; persisted JSONL grep for `sk-ant-oat01-AAAA` → zero matches (AC-20).
  - `test_run_id_collision`: spawn 5 generators in parallel, all 5 produce distinct run_ids (AC-11a).
  - `test_schema_validate_unknown_field`: record with extra unknown field `future_v2_thing: "foo"` validates OK against v1.0.0 (forward-compat).
  - `test_schema_reject_invalid_state`: record with `state: "invented"` fails validation.
- [ ] `coc-eval/tests/lib/test_aggregator_hardening.py`:
  - `test_md_injection_canary`: record with `test_name: '|<a href=javascript:alert(1)>x</a>|'` → escaped output without unescaped angle brackets (AC-8a).
  - `test_jsonbomb_size`: 10.1MB JSONL file → skip with warning, no parse (AC-8b).
  - `test_jsonbomb_int`: line with `{"runtime_ms": 9999...20-digits}` → bounded int 0 (AC-8b).

## Gate

- `pytest coc-eval/tests/lib/test_jsonl.py` + `test_aggregator_hardening.py` green.
- `coc-eval/schemas/v1.0.0.json` validates against `jsonschema` library (use vendored validator or stdlib `jsonschema`-equivalent).
- Negative-control redaction: `sk-ant-oat01-AAAA` in stderr produces zero matches in persisted JSONL.

## Acceptance criteria

- AC-6 schema validation (last 100 records)
- AC-7 closed state taxonomy
- AC-11a run-id collision
- AC-20 redaction canary
- AC-21 profile-name path traversal blocked (validators imported)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H4 <summary>`
- [ ] Branch name `feat/coc-harness-h4-jsonl-schema`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

Forward-compat semantics mean the schema validator MUST be lenient on unknown fields (`additionalProperties: true` at the right scope) but strict on type/enum violations. Easy to flip the wrong way — test both cases.

## Verification

Closed 2026-04-29 — `/implement` cycle complete. See `journal/0012-DECISION-h4-jsonl-writer-shipped.md` + `journal/0013-RISK-h4-security-review-round1-converged.md`.

**Plan reference:** `02-plans/01-implementation-plan.md` §H4 + `01-analysis/06-jsonl-schema-v1.md`. Every checklist item below maps to a plan paragraph or schema section.

**Build — JSONL writer**

- `coc-eval/lib/jsonl.py::JsonlWriter` — `open(run_id, suite, base_dir, skip_gitignore_check)` + `write_header(...)` + `record_result(record)` + `write_log(...)` + `close()`. MED-04 startup assertion lives in `_verify_results_path_gitignored` (PATH-resolved git via trusted-prefix allowlist after H4 review H2).
- `read_record(line)` returns dict (forward-compat). `iter_records(path)` enforces 10MB per-file + 100KB per-line + bounded int parsing.

**Build — run-id format**

- `coc-eval/lib/run_id.py::generate_run_id` — `<iso8601-second>-<pid>-<counter>-<rand>` per spec. `validate_run_id` enforces `RUN_ID_RE.fullmatch` BEFORE any FS op (AC-21).

**Build — JSON schema v1.0.0**

- `coc-eval/schemas/v1.0.0.json` — header + test record definitions, regex + tiered_artifact backends, parallel arrays per AD-05, closed `state` enum per AC-7.

**Build — companion .log writer**

- `JsonlWriter.write_log` writes `<run_id>/logs/<cli>-<suite>-<test>.log` at mode 0o600 from creation (M2 fix using `os.open` + `O_EXCL`). Banner + headers + redacted bodies. Evidence-required tests get a sibling `.evidence.log`.

**Build — aggregator hardening primitives**

- `escape_md(s)` — `|`, `<`, `>`, backticks, newlines (AC-8a markdown injection).
- `iter_records(path)` — per-file 10MB cap, per-line 100KB cap, bounded `parse_int` (AC-8b).

**Test files**

- `tests/lib/test_run_id.py` — 13 tests: regex match, components, sub-second distinct, 5-process collision via `mp.Pool(spawn)`, `validate_run_id` rejects malformed/non-string.
- `tests/lib/test_jsonl.py` — 24 tests: round-trip header + record, redaction canary on stdout AND stderr, forward-compat (unknown field validates), schema strictness (state enum rejected), path-traversal blocked (run_id + suite), per-line cap, companion log mode 0o600 + redaction + evidence sibling, plus 5 security regressions: extra-kwarg redaction, auth_probe.reason redaction, log symlink refusal, file mode at creation.
- `tests/lib/test_aggregator_hardening.py` — 12 tests: escape_md (pipe/HTML/anchor/backtick/newlines/non-string), per-line byte cap, bounded int, per-file size cap.
- `tests/lib/test_suite_validator.py` — extracted schema-validator tests pinned to new public API + cyclic `$ref` guard test (M4).

**Gate**

- `pytest coc-eval/tests/lib/`: 234 passed (was 186 H3 baseline; +48).
- `pytest coc-eval/tests/integration/`: 2 passed (AC-16 canary + capability smoke; H4 changes do not touch launcher).
- `cargo check --workspace`: clean.
- `cargo fmt --check`: clean.
- Stub scan + `shell=True` + `os.system` greps: clean.

**Acceptance criteria**

- AC-6 schema validation — `validate_record` runs at every write.
- AC-7 closed state taxonomy — `test_invented_state_rejected` GREEN.
- AC-11a run-id collision — `test_five_parallel_generators` GREEN.
- AC-20 redaction canary — `test_token_in_stderr_redacted_on_disk` + `test_token_in_stdout_redacted` + `TestExtraKwargRedacted` (2) GREEN.
- AC-21 path-traversal blocked — `TestPathTraversalBlocked::*` GREEN.

**Cross-cutting**

- specs/08-coc-eval-harness.md unchanged — H4 matches the existing JSONL spec wording (parallel-arrays, closed state taxonomy, stdlib-only, per-line cap, redaction at persistence).
- Journals 0012 (ship) + 0013 (security-review convergence) written. 6 above-LOW security findings (2 HIGH + 4 MEDIUM) all resolved in-session per zero-tolerance Rule 5.
