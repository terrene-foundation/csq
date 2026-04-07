---
type: DECISION
date: 2026-04-07
created_at: 2026-04-07T16:35:00+08:00
author: co-authored
session_id: 56e0a0d5-bb6f-4bbe-a71a-dc06dac9f951
session_turn: 38
project: claude-squad
topic: Removed /rotate slash command in favor of in-CC `! csq swap N` pattern
phase: implement
tags: [rotation, slash-commands, ux, llm-availability, architecture]
---

## Decision

Removed the `/rotate` slash command entirely (deleted from `rotate.md` at repo root, `.claude/commands/rotate.md`, and `~/.claude/commands/rotate.md`). Replaced with the documented in-CC pattern: type `! csq swap N` directly inside CC.

## Rationale

The `/rotate` slash command was broken by design. It was implemented as a Claude skill (markdown file with bash steps), which means **the LLM has to read it and execute the bash**. But the only time you need rotation is when you've hit a rate limit — and at that exact moment, the LLM is unavailable to interpret the skill.

User's exact failure mode demonstrated this: `/rotate 7` returned "You've hit your limit · resets Apr 10 at 6am" — the LLM rate-limit refusal of the skill invocation, not a rotation logic failure. The skill never even ran.

The `! csq swap N` pattern works because:

1. **`!` prefix bypasses the LLM entirely.** Verified empirically: `! csq swap N` runs as a local shell command. No LLM call is involved, so it works even when CC is rate-limited.
2. **It runs in CC's process environment**, so `CLAUDE_CONFIG_DIR` is already set correctly for the affected terminal — no "which of 15 terminals do I target" problem.
3. **The next user message uses the new account** because CC's mtime-based credential reload kicks in (see journal entry 0007).

## Alternatives Considered

- **Add `csq swap` to a separate terminal**: Works, but the user correctly pointed out this is identical to `csq run N` which they already do. Adds zero value over the existing flow.
- **Make `/rotate` smarter**: No fix possible at the skill layer — the skill cannot run when the LLM is unavailable. The architectural mistake is the layer itself.
- **CC-side feature request**: Anthropic could add a built-in `/rotate` that's a `local-jsx` command (like `/login`), bypassing the LLM. Out of our control.

## Consequences

- **One less artifact to maintain.** The `rotate.md` file referenced bash steps that would need updating if `csq` evolves.
- **Discoverable through `csq help`**, which now documents the in-CC pattern.
- **The `csq swap N` shell command remains available** for use from non-CC terminals, with the same semantics.
- **install.sh actively removes** any prior install of `rotate.md` so users upgrading don't have a dead command lying around.

## For Discussion

1. The general principle: any "skill" that requires LLM availability cannot be the recovery mechanism for LLM-unavailability scenarios. What other COC artifacts in this repo or others have the same flaw? (Auto-rotate hook maybe? It runs on `UserPromptSubmit` so it has the same dependency.)
2. If the user had not pushed back on `csq swap` being separate from `csq run`, the cleanup would have been worse (more redundant surface area). What does this say about the importance of user UX intuition vs the implementer's mental model?
3. The `!` prefix is documented in CC's UI footer but most users don't know about it. Is there a way to make rate-limit recovery patterns more discoverable, or is this the kind of thing that has to be learned via failure?
