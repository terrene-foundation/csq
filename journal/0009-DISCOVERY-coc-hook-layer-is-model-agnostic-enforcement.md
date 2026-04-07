---
type: DISCOVERY
date: 2026-04-07
created_at: 2026-04-07T16:40:00+08:00
author: co-authored
session_id: 56e0a0d5-bb6f-4bbe-a71a-dc06dac9f951
session_turn: 18
project: claude-squad
topic: COC's Layer 5 (hooks) is what makes the methodology model-agnostic
phase: codify
tags: [coc, hooks, model-compliance, minimax, opus, methodology]
---

## Discovery

The COC five-layer architecture (Rules, Agents, Skills, Commands, Hooks) is not five equal layers — Layer 5 (hooks) is the **enforcement layer** that makes the whole methodology model-agnostic. Strong models self-police via Layers 1-4; weak models need Layer 5 to enforce what Layers 1-4 only suggest.

## Evidence

Last session established that MiniMax M2.7 scores 7-12/50 vs Opus 48/50 on COC rule compliance. The interpretation was "MiniMax doesn't follow COC rules." This session refined that interpretation:

The v2 tests used `claude -p` mode. Verified empirically that **PostToolUse hooks do not fire in `-p` mode** — only SessionStart hooks fire in pipe mode (counted hook events in stream-json output: 2 hook events total, both SessionStart, zero PostToolUse despite tool calls happening). So v2 measured _only_ model self-policing, with the enforcement layer disabled. Of course MiniMax failed — all the rules were advisory.

In real deployment (interactive `claude` or `csq run`), PostToolUse hooks fire on every Edit/Write. Tested directly in this very session: every file edit went through `validate-workflow.js`. Strengthened the hook to BLOCK 5 violation types and ran a 5/5 unit test against the new patterns. Now any model — Opus, MiniMax, future local LLMs — gets BLOCKED at the tool boundary regardless of how good their instruction-following is.

**Phase competency test (separate from rule compliance):** Ran Opus vs MiniMax on analyze/todos/redteam/codify on rotation-engine.py. Result: MiniMax's reasoning quality is comparable to Opus. It found bugs Opus missed (`pick_best()` sorting flaw, `cleanup()` glob mismatch, NFC normalization risk). So MiniMax is **smart enough** to do COC work — it just doesn't self-police rules under conflicting instructions.

## The Two-Dimensional Model

```
                    Rule Compliance       Reasoning Quality
                    ──────────────        ─────────────────
Opus 4.6:           48/50 (self)          Excellent
MiniMax M2.7:        7/50 (self)          Excellent
                    47/50 (with hooks)    (same)
```

Rule compliance and reasoning quality are independent dimensions. Hooks compensate for the first; nothing compensates for the second.

## Implication for COC Methodology

The COC thesis "works with any model" is conditional on the deployment having hooks active. A `claude -p` user gets only Layers 1-4 — fine for Opus, broken for everything else. A `claude` (interactive) user gets the full stack including Layer 5 enforcement.

This reframes the debate about which models can drive COC work. The question isn't "is the model smart enough" — most modern models are. The question is "does the deployment have the enforcement layer active." If yes, any model works. If no, only models that self-police work.

## For Discussion

1. If hooks are this critical, should the COC bootstrap process refuse to run on a deployment without hooks configured? Or is that too paternalistic — some users deliberately want to skip enforcement for one-off scripts?
2. The 5 BLOCK rules added today (NotImplementedError, hardcoded credentials, `except: pass`, OCEAN naming, naming-in-comments) are project-specific. A general-purpose Layer 5 enforcement library that other COC projects could adopt would amplify the value. What's the minimum viable shape of that library?
3. If MiniMax found bugs Opus missed (`pick_best()`, `cleanup()` glob, NFC), and yet "scored worse" on rule compliance — what does that say about how we evaluate model fitness for engineering work? Is rule compliance even the right primary metric, or should it be hybrid (compliance × reasoning)?
