---
type: DISCOVERY
date: 2026-04-29
created_at: 2026-04-29T08:55:00+08:00
author: agent
session_id: term-4164
session_turn: 130
project: coc-harness-unification
topic: coc-eval/ was blanket-gitignored — H1 work was untracked until prep PR
phase: implement
tags: [gitignore, h1, h2, prep, infra]
---

# DISCOVERY — `coc-eval/` was blanket-ignored; H1's deliverables never reached the index

The session-start audit before resuming H2 caught that `.gitignore:61` carried a single line `coc-eval/` (commented "COC eval environment (large, local-only)"), which transitively un-staged every H1 deliverable: `coc-eval/lib/`, `coc-eval/conftest.py`, `coc-eval/schemas/`, `coc-eval/tests/lib/`, plus the new pytest harness. `git status` showed only `pyrightconfig.json`, `specs/08-coc-eval-harness.md`, and the workspace dir as untracked — which made it look like H1 had committed the lib/ files when in fact those files were silently dropped by the ignore rule.

Compounding finding: the `coc-eval/coc-eval/` typo directory documented in journal 0007 (cwd-persistence bug during H1 implementation) was still on disk. Both blockers had to clear before H2 implementation could ship a tracked artifact.

Resolution: PR #216 surgical fix — replace the blanket `coc-eval/` rule with explicit ignores for ephemeral subdirs only (`__pycache__/`, `.pytest_cache/`, `.benchmarks/`, `coc-env/`, `results/`, `scaffolds/output/`, `run-environment-pin.json`, plus a recursive `**/__pycache__/`). All H1 + H2 durable code now tracks. Typo dir purged.

The blanket-ignore was probably a copy from the legacy `coc-bench` workspace state when csq forked from claude-squad — the old harness lived in a transient `coc-eval/` workspace that wasn't meant to be tracked. Once the H1–H13 plan made `coc-eval/` the permanent home for the unified harness, the rule should have been narrowed at the start of /implement, not at H2.

## For Discussion

1. The `git status` output that hid this — only 3 files visible, no warning about gitignored newfiles — is a known git footgun. `git status --ignored` would have surfaced it at H1 ship time, but `/validate` doesn't run `--ignored` and neither does the wrapup template. Should the wrapup template grow a `git status --ignored` step so future H#-style PRs catch this class of error before merge?

2. Counterfactual: if the H1 session had committed (vs the actual outcome where the wrap-up commit `2ca6d91` mentioned H1 in the message but the lib/ files were silently absent), the next session would have re-implemented H1 from scratch on the assumption that nothing was tracked. The journal 0007 entry _did_ land in that commit and would have been the only signal that H1 was already done — surfacing the contradiction. Is the journal entry alone sufficient as a tripwire, or does the workspace need a `.test-results` artifact that proves the code path actually exists in HEAD?

3. The gitignore comment said "large, local-only." The actual ephemeral subdirs (`coc-env/`, `results/`, etc.) ARE large and local-only — but they're a small subset of `coc-eval/`. The rule failed because the comment described a sub-tree but the rule covered the whole tree. Is this the same shape as the H7 sandbox-profile drift in journal 0065 B3 (intent narrower than implementation)? If so, would a single-rule "list every grant" pre-merge audit catch both?

## References

- `.gitignore` (post-fix) lines 60-69 — the surgical replacement
- `workspaces/coc-harness-unification/journal/0007-DECISION-h1-foundation-shipped.md` — H1 ship report (mentioned the cwd-persistence bug, NOT the gitignore issue, because the bug was invisible from inside that session)
- PR #216 — gitignore fix + H1 deliverables landed together
- `rules/zero-tolerance.md` Rule 1 — pre-existing failures must be fixed in-session (this is what triggered the prep PR rather than a wishlist defer)
