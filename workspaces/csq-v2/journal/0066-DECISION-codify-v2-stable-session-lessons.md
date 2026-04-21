---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T01:00:00+08:00
author: co-authored
session_id: 2026-04-21-stable-v2-readiness
session_turn: 78
project: csq-v2
topic: codify session-level lessons from the v2.0.0 stable cut into path-scoped repo rules and the svelte-reference skill; four new rule sections land as tripwires for the next session
phase: codify
tags:
  [
    codify,
    rules,
    svelte,
    testing,
    security,
    tauri-capabilities,
    untrack,
    partial-failure-cleanup,
    test-reality-gap,
  ]
---

# 0066 — DECISION: codify lessons from v2.0.0 stable cut

**Inputs:** journals 0061 (ChangeModelModal first-open), 0063 (security audit), 0064 (auto-rotate P0), 0065 (red-team convergence).
**Scope:** `.claude/rules/` and `.claude/skills/` only — claude-squad is a downstream repo and does not propose artifacts upstream.

## What was codified

### 1. `rules/svelte-patterns.md` §5 — `$state` writes inside `$effect` MUST use `untrack`

New rule with DO/DO NOT example, BLOCKED rationalization list, and Why line citing journal 0061. Tripwire phrases: "The cleanup only fires on unmount" / "The write doesn't invalidate because it's after the read". Both were internal reasoning paths we used when first diagnosing the ChangeModelModal spinner hang.

### 2. `rules/svelte-patterns.md` §6 — Conditional DOM from async `$state` MUST guard null

New rule. Renders the dependent markup only when the async-populated `$state` is non-null. Origin: journal 0063 P1-5 (hardcoded `v2.0.0-alpha.21` in Header.svelte).

### 3. `rules/testing.md` §6 — Component tests MUST exercise the production mount sequence

New rule. Modal / dialog / popover tests MUST include at least one mount-closed → rerender-open → assert-IPC-fires-and-DOM-renders scenario. Tripwire phrases: "The onMount path covers it" / "Rerender with different props doesn't happen in production" / "The second test is a duplicate". Origin: journal 0061 (the entire ChangeModelModal test suite mounted with `isOpen: true` and masked two independent bugs).

### 4. `rules/security.md` §5a — Partial-failure cleanup on sensitive-file writes

New rule inserted between §5 (secure*file) and §6 (fail-closed on keychain). Every `std::fs::write(&tmp, …)` of secret content MUST `let * = std::fs::remove_file(&tmp);`before propagating errors from`secure_file`/`atomic_replace`. Origin: journal 0065 B2 (three sites propagated errors via `?` and left umask-default tmp files with tokens on disk).

### 5. `rules/tauri-commands.md` — "Permission Grant Shape — Narrow by default"

New sub-section under `## Permissions`. Every non-`core:default` grant MUST either be a specific sub-permission OR have an explicit comment naming every sub-permission the plugin exposes. Includes an audit checklist (`grep -Eh '"[a-z-]+:default"' src-tauri/capabilities/*.json`) to run before merging any capability change. Origin: journal 0065 B3 (`updater:default` left unchanged while three sibling bundles were narrowed in the same PR).

### 6. `skills/svelte-reference/SKILL.md` — CRITICAL Gotchas row + new `$effect Cancellation Race` section

Added two rows to the Gotchas table (untrack for bookkeeping writes; test mount shape matches production) plus a standalone "`$effect` Cancellation Race (journal 0061)" section with the untrack pattern and a cross-reference to the rule. The skill is consumed directly by svelte-specialist agents — the fresh knowledge loads alongside the broader reference.

## What was NOT codified

### Memory-hygiene feedback

`feedback_verify_memory_before_briefing.md` lives in user-memory, not repo rules. The failure mode (stale session memory seeding a brief) is cross-project — it happens to csq here, but the same agent could carry it into loom, atelier, or any downstream repo. Putting it in csq `.claude/rules/` would scope it too narrowly.

### Cryptographic release-key spot-verification pattern

Too low-frequency to earn a rule. The 5-minute verifier script lives in journal 0065; a future key rotation can reconstruct it from that journal entry plus the `/tmp/keycheck/verify.rs` sketch. Adding it as a canonical rule risks locking in a specific crypto library version.

### Auto-rotate handle-dir-native design

That's spec work for 2.0.1, not a rule. Journal 0064 has the design brief under §Suggested fixes.

## Validation

All four rule files + the skill follow `rules/rule-authoring.md` conventions (MUST phrasing, DO/DO NOT examples, `**Why:**` line, `Origin:` reference). Total addition: ~180 lines of rule content; no file exceeds the 200-line rule-authoring ceiling.

`rules/cc-artifacts.md` compliance: the four edited rule files all already have `paths:` frontmatter (svelte-patterns and testing are path-scoped; security and tauri-commands are project-wide by necessity). No new agent files created, no new skill files created. SKILL.md changes fit the progressive-disclosure pattern — quick-reference row in the table, deep detail in the dedicated section.

## Consequences

- Next session that touches a Svelte `$effect` with a `$state` bookkeeping flag will load `svelte-patterns.md` §5 on the first `.svelte` file read.
- Next session that writes a new Tauri capability narrows bundles atomically (checklist forces enumeration) instead of piece-by-piece.
- Next session that propagates a `secure_file` error MUST cleanup the tmp file first (security.md §5a tripwire fires on `?` after `std::fs::write` to a sensitive path).
- Next session that adds a modal test will see testing.md §6 and write the rerender test alongside the mount-with-isOpen-true test.

## For Discussion

1. The four new rule sections all trace to red-team-caught defects. That suggests the three-agent /analyze phase — even with deep-analyst + security-reviewer + requirements-analyst in parallel — missed the class of bug that only a cross-cutting "walk every fix site against the production mount sequence" pass catches. Should /analyze gain a red-team agent by default, or is that duplicating /redteam's job?
2. `skills/svelte-reference/SKILL.md` now has a dedicated section on one very specific Svelte-5 quirk (the `untrack` pattern). If we add three more such quirks, the skill grows past its progressive-disclosure budget. At what length does the quirk collection belong in a sibling file (`svelte-reference/effect-patterns.md`) instead?
3. `rules/security.md` §5a is phrased as a general rule about "sensitive-file writes" but its DO example uses csq-specific types (`ConfigError`, `unique_tmp_path`). Does that couple the rule too tightly to one codebase, or is the specificity necessary to make the rule actionable for the next contributor?
