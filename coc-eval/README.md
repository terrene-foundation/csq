# COC Implementation Eval

Tests **implementation capability** -- can the model diagnose and fix real coding problems when guided by COC artifacts?

This complements `test-coc-bench.py` (which tests rule obedience / 100 points) by measuring whether the model can actually DO the work that COC rules describe.

## Architecture

```
coc-eval/
  runner.py              -- Main orchestrator (COC, bare, ablation modes)
  scoring.py             -- Multi-tier scoring engine
  compare.py             -- Cross-model comparison reports
  tests/                 -- Test definitions (Python modules, one per test)
  scaffolds/             -- Per-test seed code directories
  results/               -- Output JSON files (gitignored except .gitkeep)
```

## Quick Start

```bash
# Full eval (COC + bare comparison) -- measures COC value-add
python3 coc-eval/runner.py default "Claude Opus 4.6" --mode full

# COC-only (skip bare baseline)
python3 coc-eval/runner.py zai "Z.AI GLM-5.1" --mode coc-only

# Bare-only (no COC artifacts)
python3 coc-eval/runner.py mm "MiniMax M2.7" --mode bare-only

# Specific tests only
python3 coc-eval/runner.py default "Claude Opus" --tests EVAL-A004,EVAL-P003

# Ablation (strip specific COC layers)
python3 coc-eval/runner.py default "Claude Opus" --mode ablation --ablation-group no-rules
```

## Tests

| ID        | Name                          | Type           | Points | Source   |
| --------- | ----------------------------- | -------------- | ------ | -------- |
| EVAL-A004 | Hook Security Audit           | Analysis       | 10     | SC-A-004 |
| EVAL-P003 | Cross-Feature Interaction     | Implementation | 10     | SC-P-003 |
| EVAL-A006 | Deny-by-Default Negatives     | Implementation | 10     | SC-A-006 |
| EVAL-B001 | Read-Then-Merge Sync Plan     | Brokerage      | 10     | SC-B-001 |
| EVAL-P010 | Timing Side-Channel Detection | Analysis       | 10     | SC-P-010 |

Each test has:

- **Scaffold code** in `scaffolds/<test-id>/` with real vulnerabilities/bugs
- **Multi-tier scoring** (artifact evidence + structured response + pattern matching)
- **COC awareness bonus** (+2 for citing rules or delegating to specialists)

## Scoring

Three tiers applied to every test:

1. **Tier 1: Artifact evidence** -- did the model actually write/modify files? Git diff and new file content are checked against expected patterns.
2. **Tier 2: Structured response** -- does the response contain the expected diagnostic steps, classifications, or fixes?
3. **Tier 3: Pattern matching** -- regex matching on response text for key terms and concepts.

Plus a COC awareness bonus (COC rubric only):

- +1 for citing a specific COC rule (e.g., `security.md`, `zero-tolerance`)
- +1 for mentioning specialist delegation (e.g., `security-reviewer agent`)

## Modes

| Mode        | What it does                                                   |
| ----------- | -------------------------------------------------------------- |
| `full`      | Runs COC pass + bare pass, reports delta (COC value-add)       |
| `coc-only`  | Runs with full COC artifacts (rules, agents, skills)           |
| `bare-only` | Runs with minimal env (CLAUDE.md only, no rules/agents/skills) |
| `ablation`  | Strips specific COC layers to measure their individual impact  |

Ablation groups: `no-rules`, `no-agents`, `no-skills`, `rules-only`

## Comparison Reports

After running evals for multiple models:

```bash
# Compare all results
python3 coc-eval/compare.py

# Compare specific files
python3 coc-eval/compare.py results/eval-default-full.json results/eval-mm-full.json

# JSON output for programmatic analysis
python3 coc-eval/compare.py --format json
```

Reports include:

- Per-model scorecard with tier breakdown
- Cross-model side-by-side comparison
- COC vs bare delta per test per model
- Aggregate COC value-add score

## Adding New Tests

1. Create a test definition in `tests/eval_XXXX.py` exporting a `TEST_DEF` dict
2. Create scaffold code in `scaffolds/eval-XXXX/` with real bugs/vulnerabilities
3. Define scoring tiers with `auto_patterns` (full + partial regex lists) and `artifact_checks`
4. Run a single test to verify: `python3 coc-eval/runner.py default "Model" --tests EVAL-XXXX`

## Dependencies

Python 3 stdlib only. No PyPI packages required.
