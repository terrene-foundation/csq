# H1 — Spec + scaffolding + validators

**Goal.** Lay the foundation: durable spec, validators centralized, redaction port, launcher dataclasses. No suites running yet.

**Depends on:** none (first PR).

**Blocks:** H2, H3, H4 (all subsequent PRs import from `coc-eval/lib/`).

## Tasks

### Build — durable spec

- [ ] Write `specs/08-coc-eval-harness.md` codifying §03–§07 of analysis. Cover: closed `state` enum + within-test/across-test precedence ladder split (R2-MED-01); JSONL header shape; ADR-A through ADR-J decisions verbatim; sandbox-exec/bwrap profiles; settings-key positive allowlist; fixture-name validator regex; tempdir cleanup invariant; Windows credential rule; `redact_tokens` patterns + word-boundary parity contract. Per `rules/specs-authority.md` Rule 4. Spec MUST be ≤300 lines per Rule 7; split if exceeded.

### Build — operator README

- [ ] Write `coc-eval/README.md`. Quick-start operator commands (`run.py compliance --cli cc`, `run.py all`, `aggregate.py --since 7d`), link to spec, common error catalogue (the 5 messages in `03-user-flows/01-operator-flows.md` UX-13). **Sandbox prerequisites (R2-LOW-01):** Linux operators install `bubblewrap` (`apt install bubblewrap` / `dnf install bubblewrap`); macOS has `sandbox-exec` preinstalled (deprecated by Apple as of 10.10 but functional in Phase 1; v1.1 follow-up to migrate to `sandbox` framework via Rust shim); Windows is gated out at argparse.

### Build — validators

- [ ] Create `coc-eval/lib/validators.py`:
  - `FIXTURE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-][a-zA-Z0-9._-]*$")`
  - `validate_name(s: str, max_len: int = 64) -> None` (raises ValueError on `..`, leading dot, regex mismatch, length > max_len). Used for fixture/suite/CLI/profile names. Centralizes CRIT-02 fix.
  - `SUITE_MANIFEST = ["capability", "compliance", "safety", "implementation"]` (CRIT-03 fix).
  - Per-suite test manifest dicts (e.g. `IMPLEMENTATION_TEST_MANIFEST = ["EVAL-A004", "EVAL-A006", ...]`).
  - **No glob discovery** — explicit lists only.

### Build — redaction port

- [ ] Create `coc-eval/lib/redact.py`. Python port of `csq-core/src/error.rs:161 redact_tokens`:
  - Patterns: `sk-ant-oat01-`, `sk-ant-ort01-`, `sk-* + 20`, `sess-* + 20`, `rt_* + 20`, `AIza* + 30`, 32+ hex run, 3-segment JWT, PEM blocks.
  - **Word-boundary parity** (R1-HIGH-01): use lookbehind/lookahead char-class (`(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])`). Naive `\b` regex is INCORRECT.
  - Byte-pattern-based, NOT field-name-based — do NOT redact JSON `error_description` field by name.

### Build — launcher dataclasses + state enum

- [ ] Create `coc-eval/lib/launcher.py`:
  - `CliId = str` TypeAlias (NOT closed Literal — UX-11). Comment: suites are closed Literal because they map to COC methodology layers; CLIs are open because new model-CLIs ship continuously.
  - `LaunchInputs` dataclass with fields: `cli`, `suite` (Literal of 4), `fixture_dir`, `prompt`, `permission_mode`, `timeout_ms`, `stub_home`, `home_root` (R1-CRIT-02), `extra_env`, `sandbox_profile`.
  - `LaunchSpec` dataclass with fields: `cmd`, `args`, `cwd`, `env`, `sandbox_wrapper` (R1-CRIT-01), `expected_state_on_missing`.
  - Empty `CLI_REGISTRY: dict[CliId, CliEntry] = {}` (populated in H3/H10/H11).
  - `CLI_TIMEOUT_MS[(suite, cli)]` table (initial values from `05-launcher-table-contract.md`).
  - INV-PERM-1 runtime check stub: `_assert_permission_mode_valid(spec, inputs)` raises RuntimeError on mismatch.

- [ ] Create `coc-eval/lib/states.py`. `class State(Enum)` with closed taxonomy. Two precedence functions:
  - `classify_within_test(signals: dict) -> State` ladder: `error_fixture > error_invocation > error_json_parse > error_timeout > skipped_sandbox > skipped_artifact_shape > pass_after_retry > pass > fail`.
  - `classify_across_test(loop_state: dict) -> State | None` boundary states: `skipped_cli_missing`, `skipped_cli_auth`, `skipped_quota`, `skipped_quarantined`, `error_token_budget`.

### Build — suite-v1 schema + validator (R3-CRIT-01)

- [ ] Create `coc-eval/schemas/suite-v1.json` JSON Schema covering the SUITE dict shape: `name`, `version`, `permission_profile`, `fixture_strategy ∈ {per-cli-isolated, coc-env}`, `tests` array, per-test required fields (`name`, `prompt`, `expect`, optional `permission_mode_override`, `requires_write_justification`, `tags`, `quarantined`, `post_assertions`, `scoring_backend`).
- [ ] Create `coc-eval/lib/suite_validator.py`:
  - `validate_suite(suite_module) -> None` raising on schema mismatch, duplicate test ID, INV-PAR-2 criteria-count mismatch across CLIs (with `skipped_artifact_shape` carve-out).
  - Used by `run.py --validate` (FR-16, lands in H5).

### Build — security grep guards (R3-CRIT-04)

- [ ] CI grep guard: `grep -rn 'shell=True' coc-eval/` MUST return zero matches (AC-13).
- [ ] CI grep guard: `grep -rn 'os.system\|os.popen' coc-eval/` MUST return zero matches.
- [ ] Both guards lifted into `.github/workflows/coc-harness.yml` (created in H5 per R3-HIGH-01).

### Test

- [ ] Create `coc-eval/tests/lib/test_validators.py`: regex matches (`good_name`, `another-fixture_v2`, `1abc`); rejections (`..`, `.hidden`, `foo/bar`, `foo bar`, 65-char string).
- [ ] Create `coc-eval/tests/lib/test_suite_validator.py`: synthetic SUITE with missing `prompt` raises; duplicate test ID raises; criteria-count mismatch across CLIs raises (unless `skipped_artifact_shape`).
- [ ] Create `coc-eval/tests/lib/test_redact.py`: port ALL 25 fixtures from `csq-core/src/error.rs:686-1013` byte-for-byte. Mandatory parity test: `redact_tokens("module_sk-1234567890123456789012345")` returns input unchanged. Mandatory canary: `redact_tokens("foo sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAA bar")` redacts.
- [ ] Create `coc-eval/tests/lib/test_launcher.py`: dataclass round-trip (construct, serialize via `dataclasses.asdict`, reconstruct); INV-PERM-1 stub raises on mismatched `(suite, cli, permission_mode)`.
- [ ] Create `coc-eval/tests/lib/test_states.py`: `classify_within_test` returns deterministic state for each signal combination; `pass_after_retry` wins over `pass` when `attempts > 1`.
- [ ] CI grep guard: `grep -rn 'glob.*suites\|glob.*tests' coc-eval/lib/` MUST be empty.

## Gate

- `pytest coc-eval/tests/lib/` green.
- Redact-canary `sk-ant-oat01-AAAA...` → `sk-ant-oat01-***` end-to-end.
- Word-boundary parity test passes.
- SUITE_MANIFEST grep guard passes.
- `find coc-eval -name '*.py' | xargs grep '^import\|^from'` shows only stdlib imports (AC-12).

## Acceptance criteria

- AC-1 (suite-v1 schema exists, validator works) — R3-CRIT-01
- AC-12 stdlib check
- AC-13 no-`shell=True` grep guard — R3-CRIT-04
- AC-20 redaction canary
- AC-20a 25-fixture parity
- AC-26 spec exists
- AC-27 README exists
- AC-32-bis no-glob check

## Cross-cutting (per implementation-plan §Cross-cutting)

- [x] /validate runs cargo + clippy + fmt + tests + new pytest path (cargo: 1614+ pass; pytest: 116 pass)
- [x] Journal entry written: `journal/0007-DECISION-h1-foundation-shipped.md`
- [ ] Mutation test new test code — deferred (H1 is unit-only; mutation testing applies once a sufficiently broad surface lands per PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H1 spec + scaffolding + validators` (set when commit lands)
- [ ] Branch name `feat/coc-harness-h1-spec-scaffolding` (set when branched)
- [x] specs/08-coc-eval-harness.md created (Rule 4)

## Risk

The redact word-boundary semantics are subtle. A naive Python `\b` regex matches differently than Rust's `is_key_char` predicate. Verify by running Rust + Python redactor on the same 25 fixtures — outputs must be byte-identical.

## Verification

**Plan reference:** `02-plans/01-implementation-plan.md` H1 — every scope item below is checked against the plan paragraph, line by line.

**Files shipped + spec mapping:**

| Plan item                                                                            | Implementation                                                                   | AC mapping       |
| ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- | ---------------- |
| `specs/08-coc-eval-harness.md` codifying §03–§07                                     | `specs/08-coc-eval-harness.md` (165 lines)                                       | AC-26            |
| `coc-eval/README.md` with quick-start + sandbox prereqs                              | `coc-eval/README.md` (rewritten)                                                 | AC-27            |
| `validators.py`: FIXTURE_NAME_RE + validate_name (CRIT-02)                           | `coc-eval/lib/validators.py` (107 lines)                                         | —                |
| `validators.py`: SUITE_MANIFEST + per-suite test manifests (CRIT-03)                 | Same file, `SUITE_MANIFEST` + 4 test manifests                                   | AC-32-bis        |
| `redact.py`: Python port of `redact_tokens` with word-boundary parity (R1-HIGH-01)   | `coc-eval/lib/redact.py` (175 lines)                                             | AC-20, AC-20a    |
| `launcher.py`: LaunchInputs + LaunchSpec + INV-PERM-1 stub + CliEntry + CLI_REGISTRY | `coc-eval/lib/launcher.py` (172 lines)                                           | —                |
| `states.py`: closed taxonomy + precedence ladder                                     | `coc-eval/lib/states.py` (113 lines) with R2-MED-01 split                        | —                |
| `suite-v1.json` schema + `suite_validator.py` (R3-CRIT-01)                           | `coc-eval/schemas/suite-v1.json` + `coc-eval/lib/suite_validator.py` (165 lines) | AC-1             |
| `tests/lib/`: pytest unit tests (stdlib only)                                        | 5 test modules, 116 passing tests                                                | —                |
| CI grep guards for shell=True / os.system / glob (R3-CRIT-04)                        | Verified via `grep -rn` (all empty)                                              | AC-13, AC-32-bis |

**Wiring:**

- Tests `from lib.X import ...` → resolved via `conftest.py` adding `coc-eval/` to `sys.path`.
- `suite_validator.py` `from .validators import ...` → relative import within `lib/` package.
- Launcher dataclasses + INV-PERM-1 are READY for H3's cc launcher to consume.
- redact_tokens is READY for H4's JSONL writer to apply on stdout/stderr persistence.
- SUITE_MANIFEST is READY for H5's run.py orchestrator to iterate (NOT glob).

**Journal constraints addressed:**

- Journal 0001 (port loom to Python stdlib): redact.py + launcher.py + states.py + validators.py are all stdlib-only. Verified via `find coc-eval/lib -name '*.py' | xargs grep '^import\|^from'` showing only stdlib imports.
- Journal 0002 (orthogonal axes): suite-v1 schema's `permission_profile` enum allows write/plan/read-only — supports both implementation-suite (write) and the other three (plan/read-only).
- Journal 0003 (stub-HOME architecturally incomplete): launcher.py exposes `home_root` field on LaunchInputs (R1-CRIT-02) and `sandbox_wrapper` on LaunchSpec (R1-CRIT-01) for H3 to populate.
- Journal 0004 (csq-loom boundary): nothing in H1 affects loom directly.
- Journal 0005 (round-2 convergence): INV-PERM-1 runtime check landed at the dataclass layer (`assert_permission_mode_valid`).

**Pre-existing failures resolved (zero-tolerance Rule 1):**

- `validators.py` originally had `isinstance(s, str)` after type annotation — Pyright flagged unreachable. Replaced with `type(s) is not str` exact-type check. Real bug in test-side strictness; runtime guard preserved.
- `suite_validator.py` `_load_schema` had `dict[str, Any] | None` return type bug. Fixed via local variable narrowing.
- `validate_name` errors propagated as bare ValueError from suite_validator. Wrapped in `try/except SuiteValidationError(...) from e` so callers get uniform exception type.

**Test results:**

- pytest coc-eval/tests/lib/: 116 passed, 0 failed.
- cargo test --workspace: 1614+ passed, 0 failed (zero regression).
- Three CI grep guards: all empty (no shell=True, no os.system/popen, no glob discovery in lib/).

**Verified ready for H2:** all H1 abstractions exist, are tested, and import correctly. H2 (fixture lifecycle) can `from lib.validators import validate_name, SUITE_TEST_MANIFESTS` immediately.
