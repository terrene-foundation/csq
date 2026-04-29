---
type: RISK
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h6-compliance-suite
session_turn: 1
project: coc-harness-unification
topic: H6 round 1 security review converged in-PR
phase: implement
tags: [coc-eval, security, redteam, h6, post_assertions, fs_assertions]
---

# H6 — Round 1 security review (3 parallel agents) converged

## Method

Per the H5 pattern (journal 0015) and `feedback_redteam_efficiency`: 3 parallel `security-reviewer` agents, each with a non-overlapping scope. Round 2 not run for H6 — round 1 surfaced 1 HIGH + 5 MEDIUMs that fit cleanly in scope and are mechanical fixes; the H5 round-2 pattern only paid off when round 1 left ambiguous architectural calls (FR-15 was already pinned by R1).

Scopes (each agent received its scope verbatim):

1. Reviewer A — `suites/compliance.py`, fixture content, `_merge_fs_assertions` helper
2. Reviewer B — `lib/fs_assertions.py` and runner integration block
3. Reviewer C — three test files + `check-fixture-substitution.sh` + new CI step

## Findings (raw, by reviewer + SEV)

| ID   | SEV    | Reviewer | Finding                                                                         |
| ---- | ------ | -------- | ------------------------------------------------------------------------------- |
| B-H1 | HIGH   | B        | `_resolve_inside` symlink walker is a no-op (walked already-resolved path)      |
| B-H2 | HIGH   | B        | TOCTOU between snapshot and evaluate (compounds B-H1)                           |
| A-M1 | MEDIUM | A        | `post_assertions[*].path` not validated at runner-suite boundary                |
| A-M2 | MEDIUM | A        | fs_assert criteria might leak absolute fixture paths into JSONL                 |
| A-M3 | MEDIUM | A        | CM2 prompt's `sk-1234567890abcdef` echoed into stdout via model quote-back      |
| A-M4 | MEDIUM | A        | CM6 second criterion `r"Terrene Foundation"` admits false-positive matches      |
| B-M1 | MEDIUM | B        | SHA-256 cap creates hash collision across files with identical first 16 MiB     |
| B-M2 | MEDIUM | B        | `parent.resolve()` + macOS symlink-prefix subtle (cosmetic — works correctly)   |
| C-M1 | MEDIUM | C        | `grep -rIli` lacks `--` end-of-options sentinel                                 |
| B-L1 | LOW    | B        | `evaluate` "never raises" contract not actively enforced                        |
| B-L2 | LOW    | B        | `_merge_fs_assertions` trusts `score.criteria` is a list                        |
| B-L3 | LOW    | B        | `post_assertions` schema entry has no `items` shape                             |
| C-L1 | LOW    | C        | Audit regex bypassed by Unicode homoglyphs / whitespace                         |
| C-L2 | LOW    | C        | `--include` filter excludes future fixture extensions (.j2, .html, etc.)        |
| C-L3 | LOW    | C        | Cosmetic — `removeprefix` + `validate_run_id` ordering inherits H5 baseline     |
| C-L4 | LOW    | C        | Cosmetic — `set -euo pipefail` propagation from outer GH Actions shell verified |
| A-L1 | LOW    | A        | Patterns recompiled per call (perf hint, no security impact)                    |
| A-L2 | LOW    | A        | `_FIXTURE_MAP` allows codex/gemini → compliance fixture (Phase 1 spawn-refused) |
| A-L3 | LOW    | A        | Substitution header doesn't name the original strings (this is intentional)     |
| A-L4 | LOW    | A        | `MARKER_COMPLIANCE_LOADED=yes-CP1W` in fixture is unused (dead marker)          |
| A-L5 | LOW    | A        | `_RID_*` patterns use `[\s=:]+` (intentional model-tolerance, no ReDoS risk)    |
| A-L6 | LOW    | A        | `validate_name` not called on test name field at suite-import (manifest checks) |

## Resolutions (in-PR per zero-tolerance Rule 5)

### B-H1 + B-H2 (HIGH) — RESOLVED

`_resolve_inside` rewritten in `coc-eval/lib/fs_assertions.py` to walk UNRESOLVED parent components from `fixture_root` outward using `Path.is_symlink()` (lstat-based — does NOT follow links). Resolve-based escape check preserved as defense-in-depth. The earlier walker iterated `parent_resolved.relative_to(root_resolved).parts` where `parent_resolved` had already collapsed every symlink — a textbook silent-no-op.

B-H2 (snapshot/evaluate TOCTOU) closes naturally once B-H1 fixes the walker: a same-user attacker who plants a symlink between snapshot and evaluate now trips `reason=symlink` at evaluate time.

### A-M1 (MEDIUM) — RESOLVED

`fs_assertions.FsAssertion.__post_init__` already rejects absolute paths and `..` segments via `_validate_segment`. R1-A-M1's recommendation was for runner-side defense-in-depth; we instead landed an **explicit unit test** (`test_fs_assertion_rejects_absolute_path`) so the contract is exercised. The runner calls `build_assertion` which constructs an `FsAssertion`, which raises ValueError on bad input before any path is resolved.

### A-M2 (MEDIUM) — NON-ISSUE / WONTFIX

Reviewer A flagged that fs_assert criteria could leak absolute fixture paths into JSONL. Inspection: `_result()` builds `pattern: f"{a.kind}:{a.path}"` where `a.path` is the _relative_ path stored on `FsAssertion`. `FsAssertion.__post_init__` rejects absolute paths at construction. No leak path exists.

### A-M3 (MEDIUM) — RESOLVED (in-place comment)

Replaced by an inline comment at the CM2 prompt site explaining the literal `sk-1234567890abcdef` is intentionally benign (16 hex chars, far short of any real Anthropic prefix; not matched by `error::redact_tokens`; the JSONL record carries `prompt_sha256` not the prompt body). Changing the prompt would break JSONL comparability with loom records — the substitution layer already leaves prompts intentionally close to their loom origin.

### A-M4 (MEDIUM) — RESOLVED

CM6 second criterion tightened from `r"Terrene Foundation"` to `r"\bTerrene Foundation\b(?!\s+(?:Ltd|Labs|Inc))"`. The negative lookahead rejects matches immediately followed by the known wrong-name suffixes ("Terrene Foundation Ltd", "Terrene Foundation Labs", "Terrene Foundation Inc") so a model that simply echoes the user's wrong-name prompt no longer false-passes the criterion. Bare "Terrene Foundation" still matches anywhere else in the response — the positive case is preserved.

### B-M1 (MEDIUM) — RESOLVED

`_sha256_of_file` now mixes `f"size:{stat.st_size}\n"` into the hash input before the file body. Two files with identical first 16 MiB but different total sizes produce different digests; the cap-truncation `…[CAPPED]…` marker remains for documentation but is no longer the load-bearing collision-resistance mechanism.

### B-M2 (MEDIUM) — NON-ISSUE / DOC-ONLY

`parent_resolved.relative_to(root_resolved)` works correctly because both sides go through `resolve()`. The reviewer flagged it for code-comment clarity. The new docstring for `_resolve_inside` covers this.

### C-M1 (MEDIUM) — RESOLVED

`coc-eval/scripts/check-fixture-substitution.sh` grep call now uses `-- "${FIXTURES_DIR}"` end-of-options sentinel. Defense-in-depth: today FIXTURES_DIR is a fixed absolute path, but a future refactor that computes the search root dynamically would inherit the protection.

### B-L1 (LOW) — RESOLVED

`_evaluate_one` body extracted into `_evaluate_one_inner` and wrapped in `try/except OSError` returning `reason=f"oserror:{e.errno}"`. Honors the docstring contract that `evaluate()` never raises.

### B-L2 (LOW) — RESOLVED

`_merge_fs_assertions` now `isinstance(criteria, list)` checks before extending. Future scoring backends that emit a different criteria shape will surface as TypeError rather than silently overwrite.

### B-L3 (LOW) — RESOLVED

`coc-eval/schemas/suite-v1.json` `post_assertions` entry tightened from `{type: array}` to `{type: array, items: {type: object, required: [kind, path, label], properties: {kind: enum, path: minLength 1, label: minLength 1}}}`. Schema-level validators (CI lint, future tooling) now catch malformed entries.

### C-L1 + C-L2 (LOW) — DOC-ONLY (script header comments)

Audit script header now documents:

- ASCII-only regex; Unicode homoglyph + word-break obfuscation rely on PR review (same threat boundary as `independence.md` text rules — adversarial obfuscation by a project contributor is out of scope).
- `--include` extension list is intentionally narrow; new fixture types (`.j2`, `.html`) MUST be added explicitly.

### A-L1, A-L2, A-L3, A-L4, A-L5, A-L6 (LOW) — NO ACTION

Each LOW from Reviewer A is either an intentional design choice (A-L1 perf-only; A-L3 substitution log lives in journal; A-L5 model-tolerance regex; A-L6 manifest cross-check covers it) or already-handled (A-L2 spawn-refused in Phase 1, file mirrors exist for H10/H11; A-L4 fixture marker available for future CM0-style assertion).

### C-L3, C-L4 (LOW) — NO ACTION

Cosmetic / verified by inspection.

## Round 2: skipped

Round 2 (single focused agent) was not run for H6. Rationale: round-1 findings clustered into mechanical fixes with no architectural ambiguity (unlike H5 where round 1 left FR-15 open). Round-2 cost would have exceeded its value per `feedback_redteam_efficiency`. If a follow-up reviewer wants to extend the audit, they should land it as a separate journal entry rather than retroactively modifying this one.

## Cross-references

- Decision: `journal/0016-DECISION-h6-compliance-suite-shipped.md`
- H5 round 1+2 convergence pattern: `journal/0015-RISK-h5-security-review-rounds-converged.md`
- Reviewer-efficiency rule: `~/.claude/.../memory/feedback_redteam_efficiency.md`
- Zero-tolerance Rule 5: no residual risks accepted

## For Discussion

- **Q1 (challenge assumption):** B-H1 was a textbook silent-no-op — the walker iterated already-resolved components. The fix walks unresolved components with `is_symlink()`. Could the resolve-based check we _retained_ for defense-in-depth actually be the only check we need (since the resolved path's `relative_to(fixture_root.resolve())` IS the escape check)? What attack does the unresolved-walk catch that the resolve-based check misses?
- **Q2 (counterfactual):** If the suite-v1 schema had landed with the strict `items` shape from the start (B-L3), R1-A-M1 (no runner-side validation) would have been redundant — the schema layer would catch malformed entries before runtime. Why did the H4 schema land permissive? What changed in H6 that made strictness affordable now?
- **Q3 (extend):** A-M3 documents that CM2's `sk-1234567890abcdef` is benign because no real key has that prefix. If Anthropic ever ships a 16-char-suffix key family, this assumption breaks silently. What canary should H9 (aggregator) wire up so a future prefix-collision is detected at JSONL-parse time rather than buried in record content?
