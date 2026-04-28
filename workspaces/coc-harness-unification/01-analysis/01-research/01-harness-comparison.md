# Harness Comparison — loom vs csq

Source survey for the consolidation. Read once; the contract files (03-08) build on this.

## What each harness measures

| Aspect                     | loom `~/.claude/test-harness/`                                                              | csq `coc-eval/`                                                                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------------------------------------ |
| **Question answered**      | Does the CLI follow rules, refuse adversarial prompts, and load artifacts correctly?        | Can the model fix real bugs when guided by COC artifacts?                                                                         |
| **Test scope**             | 3 suites × 3 CLIs × 7 fixtures × 18 tests = up to 54 cells                                  | 5 tests, 1 CLI (claude), 5 scaffolds                                                                                              |
| **Scoring**                | Regex contains/absent on stdout+stderr                                                      | 3-tier (artifact diff + full/partial regex), with optional COC-bonus tier                                                         |
| **Permission mode**        | cc=plan, codex=read-only sandbox, gemini=plan                                               | cc `--dangerously-skip-permissions` (model must write files for artifact tier to score)                                           |
| **Fixture lifecycle**      | Per-test `cp -r src dst` into `/tmp/coc-harness-<name>-<rand>/` + `git init` + commit       | Shared `coc-env/` working tree with `git checkout -- .` + `git clean -fd` between tests                                           |
| **HOME isolation**         | Stub HOME exists in code, defeated by OAuth coupling — uses real `~/.{claude,codex,gemini}` | Real `~/.claude/{agents,skills,rules,memory}` symlinked into temp config dir                                                      |
| **Output**                 | JSONL per suite + per-test `.log`, regex `score.criteria[]` shape                           | JSON aggregate per run, `score.tiers[]` shape, response previews truncated to 500 chars                                           |
| **State enum**             | `pass                                                                                       | fail                                                                                                                              | skipped_quota_exhausted` | `ok: bool + error: str` (open-ended) |
| **Retry policy**           | Gemini-only quota retry (10s busy-wait)                                                     | Empty-response retry-once (all CLIs)                                                                                              |
| **Settings/model routing** | None — uses whatever the user's CLI is configured for                                       | `~/.claude/settings-{profile}.json` overlay, `ANTHROPIC_*` env scrub, ablation modes (no-rules, no-agents, no-skills, rules-only) |
| **Runtime**                | Node.js (.mjs ESM, `node:child_process`, `node:fs`)                                         | Python 3 stdlib (`subprocess`, `tempfile`, `pathlib`)                                                                             |
| **Lines of code**          | harness.mjs ~380 + 3 suites × ~150 + aggregate.mjs ~175                                     | runner.py ~870 + scoring.py ~300 + 5 test modules                                                                                 |

## Key insight: orthogonal axes, not duplicates

The two harnesses measure **different things**:

- **loom** = compliance/safety/capability evaluator. "Does the CLI know what NOT to do? Does it cite the rule? Does it auto-load the right files?"
- **csq** = implementation-capability evaluator. "Given a real bug, does the model under COC produce a correct fix?"

Phase 1 consolidation = bring loom's 3 suites into csq's harness alongside the existing implementation suite. Result: **one harness, four suites, up to three CLIs**:

| Suite            | Origin | Tests                             | CLIs supported in Phase 1                  |
| ---------------- | ------ | --------------------------------- | ------------------------------------------ |
| `capability`     | loom   | 4 (C1–C4)                         | cc, codex, gemini                          |
| `compliance`     | loom   | 9 (CM1–CM9)                       | cc, codex, gemini                          |
| `safety`         | loom   | 5 (SF1–SF5)                       | cc, codex, gemini                          |
| `implementation` | csq    | 5 (EVAL-A004/A006/B001/P003/P010) | cc only (codex/gemini deferred to Phase 2) |

## What this means for the port

Five non-trivial design points fall out:

1. **Per-suite permission profile.** Implementation needs write; the other three need plan/read-only. The launcher table is keyed on `(suite, cli)` — see `05-launcher-table-contract.md`.
2. **Two scoring backends.** `regex` (loom-style) for capability/compliance/safety; `tiered_artifact` (csq-style) for implementation. Per-test discriminator `scoring_backend`.
3. **Two fixture strategies.** `per-cli-isolated` (loom — cp+git-init per test) for the new suites; `coc-env` (csq — shared mutate-and-reset) for implementation. Per-suite `fixture_strategy`.
4. **Two HOME models.** Stub HOME with credential-only symlink for capability/compliance/safety (resolves loom's punted contamination issue); real-HOME-shared-dirs for implementation (its whole point is real artifact load).
5. **Stdlib-only port to Python.** `independence.md` §3 forbids Node.js as a runtime dep on csq. Loom's `~380 LOC` is small enough to port cleanly.

## What we are NOT doing in Phase 1

- Coverage gaps from loom's "Known limitations" (hooks, skills auto-activation, slash commands, MCP, settings.json behavior). Deferred to v1.1+.
- Codex/Gemini implementation suite. Their sandbox modes vs cc's `--dangerously-skip-permissions` semantics differ; per-CLI fixture portability is its own piece of work. Deferred to Phase 2.
- Unified `.coc/` artifact format and capability layer. That is Phase 2a/2b in `coc-cli-phase2/`.
- Loom's harness retirement. Loom may keep its harness as an authoring-side validator; the csq harness becomes the canonical multi-CLI evaluator. The boundary rule (`csq/.claude/rules/csq-loom-boundary.md`) is its own piece of work.

## Inputs to subsequent files

- Failure register: `02-failure-modes.md`
- Functional requirements: `03-functional-requirements.md`
- Non-functional requirements & invariants: `04-nfr-and-invariants.md`
- Per-CLI launcher contract: `05-launcher-table-contract.md`
- JSONL schema v1: `06-jsonl-schema-v1.md`
- ADRs: `07-adrs.md`
- Acceptance criteria: `08-acceptance-criteria.md`
- Security review: `09-security-review.md`
