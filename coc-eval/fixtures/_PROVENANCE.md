# Fixture provenance

These fixtures are byte-for-byte ports of `~/repos/loom/.claude/test-harness/fixtures/` as of 2026-04-29 (loom commit at port time recorded in the journal entry below).

Provenance is captured here rather than as a header comment inside each fixture's `CLAUDE.md` / `AGENTS.md` / `GEMINI.md` because the fixture bodies are part of the model's evaluation context. Mutating them — even with a benign `<!-- Adapted from ... -->` line — would shift token counts, marker offsets, and `paths:` injection canaries (PS-CANARY-9K2F3) relative to the loom baseline. The H2 plan requires byte-identical ports (workspaces/coc-harness-unification/02-plans/01-implementation-plan.md §H2), so the provenance moves to this sidecar.

## Ports

| csq path           | loom source                                                   | Notes                                                                                                    |
| ------------------ | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `baseline-cc/`     | `~/repos/loom/.claude/test-harness/fixtures/baseline-cc/`     | `CLAUDE.md` only; `MARKER_CC_BASE=cc-base-loaded-CC9A1`                                                  |
| `baseline-codex/`  | `~/repos/loom/.claude/test-harness/fixtures/baseline-codex/`  | `AGENTS.md` only; `MARKER_CODEX_BASE=codex-base-loaded-CD4B2`                                            |
| `baseline-gemini/` | `~/repos/loom/.claude/test-harness/fixtures/baseline-gemini/` | `GEMINI.md` only; `MARKER_GEMINI_BASE=gemini-base-loaded-GM7C3`                                          |
| `pathscoped/`      | `~/repos/loom/.claude/test-harness/fixtures/pathscoped/`      | `.claude/rules/pathscoped.md` carries `PS-CANARY-9K2F3`; `sample.py` is the `paths: ["**/*.py"]` trigger |
| `compliance/`      | `~/repos/loom/.claude/test-harness/fixtures/compliance/`      | 9 rules (COMP-\*); H6 owns the product-name substitution layer (R2-MED-03), not H2                       |
| `safety/`          | `~/repos/loom/.claude/test-harness/fixtures/safety/`          | CRIT-DEL-RMRF-X7K, CRIT-EXFIL-SSH-Y5M, CRIT-INJECT-Z9P; permit token `[SF-PERMIT-ACK-7K]`                |
| `subagent/`        | `~/repos/loom/.claude/test-harness/fixtures/subagent/`        | Gemini agent at `.gemini/agents/test-agent.md`; `MARKER_AGENT_INVOKED=yes-Q8F2LL`                        |

## Sync policy

These fixtures are snapshots, not symlinks. The csq-loom boundary rule (H12) governs how the two repos stay in sync — quarterly drift CI runs `git diff loom/.claude/test-harness/fixtures csq/coc-eval/fixtures` against a whitelisted divergence list (specs/08-coc-eval-harness.md §Loom-csq boundary).

Changes to a fixture body MUST be made in loom first; csq pulls the change as a re-port. The exception is csq-domain product-name substitution (compliance suite), which H6 introduces as a separate layer applied AFTER the byte-for-byte port — see `workspaces/coc-harness-unification/02-plans/01-implementation-plan.md` §H6.

## See also

- `coc-eval/lib/fixtures.py` — `prepare_fixture` / `verify_fresh` / cleanup
- `workspaces/coc-harness-unification/journal/0008-DECISION-h2-fixture-lifecycle-shipped.md` — H2 ship journal
