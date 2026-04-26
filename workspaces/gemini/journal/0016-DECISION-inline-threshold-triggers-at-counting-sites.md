---
type: DECISION
date: 2026-04-27
created_at: 2026-04-27T01:30:00Z
author: agent
session_id: 2026-04-27-v2.3-tail-cleanup
session_turn: 10
project: csq
topic: Inline §FD threshold triggers as doc-comments at their natural counting sites instead of leaving them buried in journal §For Discussion entries
phase: codify
tags:
  [
    codify,
    threshold,
    journal,
    doc-comments,
    institutional-knowledge,
    anti-amnesia,
  ]
---

# Decision — inline threshold triggers at natural counting sites

## Context

The v2.3 codify wrap-up (journal 0014) and earlier v2.1 codify wrap-up (csq-v2 journal 0073) accumulated three §For Discussion items whose actionability is gated on a future count threshold tripping:

1. **Secure-write pattern doc move** — when a 5th subsystem adopts the `unique_tmp_path → write → secure_file → atomic_replace` pipeline, move the canonical doc from `security.md` §5a into a doc-block on `unique_tmp_path` itself. Origin: csq-v2 journal 0073 §FD #2 + gemini journal 0014 §FD #2.
2. **`launch_gemini`/`exec_gemini` factoring (D4)** — at N=3 callers, factor the duplicated body into a `csq_core::providers::gemini::session` module. Origin: implicit in v2.3 review; documented at the `exec_gemini` site only, not its sibling.
3. **`provider-integration` skill split** — at N=4 surface variants OR when any single surface section grows past ~150 lines, reconsider splitting the 335-line skill at the surface boundary. Origin: gemini journal 0014 §FD #1.

The structural risk: §FD items live inside journals + skill files. The next session that lands the 5th caller, 3rd `launch_gemini` caller, or 4th `Surface::*` variant has no automatic signal that the threshold tripped — and no reason to re-read the §FD entry from a 3-month-old codify journal at the moment of the change.

## Decision

**Inline each threshold trigger as a 2–4 line doc-comment at the place where the count would change.** PR #208 landed three triggers:

- `csq-core/src/platform/fs.rs` — module-level `THRESHOLD` paragraph above `unique_tmp_path` enumerating the 4 current doc locations and naming the 5th-caller move target. The pipeline helpers (`unique_tmp_path`, `secure_file`, `atomic_replace`) all live in this file, so editing any of them surfaces the trigger.
- `csq-core/src/providers/catalog.rs` — `THRESHOLD` paragraph on the `Surface` enum doc-block citing journal 0014 §FD #1 and naming the 4-variant or 150-line trip points.
- `csq-cli/src/commands/run.rs::launch_gemini` — `THRESHOLD` paragraph paralleling the existing one on `exec_gemini` in `commands/swap.rs`. Both sites must be edited together at the 3rd-caller moment.

## Alternatives considered

**A. Build a registry of pending thresholds** — `.claude/THRESHOLD-WATCH.md` or similar single source of truth listing every active threshold-gated decision. Rejected: registries that depend on humans remembering to check them are a known anti-pattern. The §FD items already form an implicit registry in journals; the gap isn't "no registry" but "no surfacing at the moment of change."

**B. Refactor now even though the threshold hasn't tripped** — do the secure-write doc move now, factor `launch_gemini`/`exec_gemini` now, split the skill now. Rejected: violates `CLAUDE.md`'s "Don't add features, refactor, or introduce abstractions beyond what the task requires." The threshold-gating principle is correct; only the surfacing was broken.

**C. Amend `/codify` to scan §FD items at every codify pass** — turn each codify run into an audit of every prior §FD entry. Rejected: amplifies codify cost linearly with cycle count and does not change the surfacing problem (the codify session is not the session that lands the 5th caller).

**D. Do nothing — trust that a sufficiently careful future session will re-read the journal** — Rejected: this is the failure mode the §FD items already exhibited (two codify cycles passed without any of them tripping or being acted on; the invisibility was the symptom).

## Consequences

- The next session that lands a 5th secure-write caller, 3rd `launch_gemini` caller, or 4th `Surface::*` variant sees the trigger inline at the moment of the edit. The trigger names the source journal §FD entry so the rationale is one click away.
- Codify cycles can stop re-parking these specific carry-forwards — the trigger is now self-surfacing.
- The pattern generalises: any future §FD item whose actionability is gated on a count threshold SHOULD inline its trigger at the natural counting site (the function whose call-count matters, the enum whose variant-count matters, the helper whose adoption-count matters).
- Doc-comments rot if the threshold never trips, but the rot is ~3 lines of stale text per site versus the alternative failure mode of a forgotten §FD entry that turns into accumulated drift.

## For Discussion

1. **Counterfactual — had this pattern been adopted at the v2.1 codify pass (csq-v2 journal 0073 §FD #2), would the secure-write doc still be split across 4 locations today?** The v2.3 cycle added two new callers (vault writes, NDJSON event-log writes) without consolidating the doc — exactly the drift the §FD predicted. Inlining the trigger in v2.1 would have made the v2.3 implementer see the threshold question while writing the new caller. (Lean: yes, the inline trigger would have surfaced the question at the right moment, though it might still have been deferred — the doc-move work itself is non-trivial and threshold-gated decisions are about _when_, not _whether_.)

2. **Specific evidence — does the inline trigger actually work, or does it just relocate the invisibility?** The PR #208 doc-comments cite their source journals (0014 §FD #1, 0014/0073 §FD #2) explicitly. A future implementer who edits `unique_tmp_path` or adds a `Surface` variant sees the threshold paragraph in their editor's hover or rustdoc. The relocation is from "buried in a 3-month-old journal" to "next to the symbol being edited" — a strict improvement in surfacing locality. Validation: the next time a §FD threshold _does_ trip, the journal entry that records the work should cite the inline trigger as the surfacing mechanism. If it cites the original §FD instead, the inline trigger failed.

3. **Should `/codify` itself adopt this pattern as a rule — every §FD with a count threshold MUST land an inline trigger at codify time?** Lean: yes, but the rule belongs at the parent layer (`~/repos/terrene/.claude/rules/journal.md` or a new codify rule), not at csq, since it's a codify-process convention not a csq-specific one. Carry-forward: combine with terrene-foundation/terrene#2 framing (claims must cite evidence) into a unified parent-repo proposal at the next codify cycle if the inline-trigger pattern proves itself by surfacing one of the three triggers in PR #208 within the next 2-3 cycles.

## Cross-references

- **PR #208** (`0e34ff8`) — the implementation that landed the three doc-comments.
- `csq-core/src/platform/fs.rs` — secure-write pipeline THRESHOLD doc-comment.
- `csq-core/src/providers/catalog.rs` — `Surface` enum THRESHOLD doc-comment.
- `csq-cli/src/commands/run.rs::launch_gemini` + `csq-cli/src/commands/swap.rs::exec_gemini` — paired D4 THRESHOLD doc-comments.
- `workspaces/gemini/journal/0014-DECISION-codify-v2.3-cycle-knowledge.md` §FD #1 + §FD #2 — origin of two of the three triggers.
- `workspaces/csq-v2/journal/0073-DECISION-codify-v2.1-cycle-knowledge.md` §FD #2 — earlier origin of the secure-write trigger.
- `workspaces/gemini/journal/0015-CONNECTION-cross-repo-journal-citation-rule-handoff.md` — sibling meta-codify entry from the same session covering the cross-repo journal-citation handoff.
