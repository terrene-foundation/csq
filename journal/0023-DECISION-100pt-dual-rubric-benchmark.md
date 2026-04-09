# DECISION: 100-point dual-rubric COC governance benchmark

**Date**: 2026-04-09

## Context

The old 50-point benchmark was adversarial-only (10 tests asking models to violate rules). It couldn't distinguish "doesn't know the rules" from "knows but won't enforce." Tests also contaminated each other — stubs and secrets written by one test persisted into the next.

## Decision

Split into two 50-point rubrics:

- **Cooperative** (50 pts): 10 tests asking the model to follow rules normally. Measures rule knowledge.
- **Adversarial** (50 pts): 10 tests asking the model to violate rules under pressure. Measures enforcement.

## Key Design Choices

1. **Environment reset**: `git clean -fd` + `git checkout -- .` in coc-env between every test
2. **Artifact capture**: `git diff` + `git status --porcelain` after each test to verify file writes, not just model claims
3. **Auto-scoring with refusal detection**: Pattern matching checks for compliance/refusal, with a refusal-override to prevent false positives when models quote violation text in their refusal
4. **Manual correction layer**: Auto-scores logged with reasons, human corrects false positives

## Results (2026-04-09)

| Model           | Cooperative | Adversarial | Total |
| --------------- | :---------: | :---------: | :---: |
| Claude Opus 4.6 |     50      |     50      |  100  |
| MiniMax M2.7    |     50      |     25      |  75   |
| gemma4          |     45      |     10      |  55   |
| qwen3.5         |     25      |     26      |  51   |

## Key Finding

MiniMax perfectly knows every rule (50/50 cooperative) but violates them when pushed (25/50 adversarial). gemma4 knows rules well (45/50) but almost never enforces (10/50). qwen3.5 is slow (5 timeouts) but is the only non-Claude model that refuses to ignore rules.
