---
type: CONNECTION
date: 2026-04-27
created_at: 2026-04-27T02:30:00Z
author: human
session_id: 2026-04-27-codify-wrapup-recodify
session_turn: 6
project: csq
topic: Once a cross-repo handoff issue is filed (e.g. terrene-foundation/terrene#2), it MUST be removed from csq's session-close-out actionable list — never re-surfaced as a "switch to repo Y to land Z" option
phase: codify
tags:
  [
    cross-repo,
    handoff,
    session-closeout,
    operational-pattern,
    institutional-knowledge,
    feedback,
  ]
---

# Connection — cross-repo handoffs do not appear on csq's actionable list

## Context

Journal 0015 (CONNECTION) recorded the externalisation of the cross-repo journal-citation rule as terrene-foundation/terrene#2 and concluded: _"The csq wrap-up note … can be retired from future session notes."_ The §FD #1 leant: _"any §FD item that recommends a parent-repo change MUST file a parent-repo GH issue in the same session, not just park it."_

This entry extends 0015 with the symmetric operational rule for the OUTPUT side: once the issue is filed, csq sessions MUST NOT re-surface the cross-repo work as something the user could "switch repos to land." It is closed from csq's vantage; the parent-repo authority is the only authority that re-opens it (via inheritance into csq's effective ruleset, or via direct user action in the parent session).

## What triggered this entry

Session 2026-04-27 (post-v2.3 tail cleanup): the previous session notes correctly listed terrene-foundation/terrene#2 under "Outstanding" with the marker _"NOT actionable from inside csq per `cross-repo.md` MUST Rule 3."_ The current session re-stated this when reporting state, then offered the user three close-out options, the second of which proposed "switch to the parent-repo session to land terrene#2." That violated the spirit of 0015.

User feedback was emphatic: _"NEVER EVER ASK TO SWITCH TO OTHER REPOS TO LAND WORK!"_ Capital-letter framing signals the pattern has burned the user before and is not negotiable.

## The rule

When csq's session close-out enumerates actionable options, the list MUST contain ONLY items that can be done from inside csq. Cross-repo handoff items that have already been externalised via GH issue:

- Are recorded in the session notes as a status line under "Outstanding (external)" or similar — for accuracy of state, not as an action.
- Are NOT framed as one of the user's choices for what to do next.
- Are NOT prefixed with verbs like "switch to," "open a session in," or "land in repo Y."

If csq's actionable list is empty after filtering out cross-repo handoffs, the correct close-out is to say so plainly and stop. The user opens the parent-repo session themselves if they want to act on the issue; csq's role is to keep its tracker honest, not to suggest workflow.

## Why csq must not propose repo-switching

Three reasons, each independently sufficient:

1. **Context-switch overhead is real.** Each new Claude Code session loads a fresh CLAUDE.md, fresh rules, fresh memory. Suggesting "open a parent-repo session to land terrene#2" implicitly proposes an N-minute setup tax for a SHOULD-rule edit the user may not have time-budget for. The decision belongs to the user.

2. **The handoff IS the work product.** From csq's vantage, externalising a parent-repo concern as a GH issue is the closing action. Continuing to surface it as csq-actionable would mean csq still owns it, contradicting 0015's "no longer csq's responsibility to track."

3. **Inheritance is the recovery channel.** When the parent rule lands, csq inherits it automatically. There is no scenario where csq must re-open the handoff to receive the rule's effect.

## Consequences

- Future session-close-out reports MUST filter the actionable list against the externalised-handoff registry (currently: terrene-foundation/terrene#2). If the filtered list is empty, the close-out is "no actionable items in csq, session closed" — full stop.
- Memory entry `feedback_never_suggest_repo_switch.md` captures this for the auto-memory layer; this journal entry is the institutional version.
- This pattern generalises beyond the journal-citation rule: any future cross-repo handoff (e.g. csq-side artifacts that should live in `loom/`, parent-repo content updates that follow csq-side spec changes) inherits the same close-out filter rule.
- If the parent-repo issue is rejected/closed without merge, csq's response is to record the closure status in the next codify pass (not to re-propose work). The parent decision is final; csq does not re-litigate.

## What this is NOT

- This is NOT a /codify rule amendment. The rule belongs in the operational layer (memory + journal), not in the procedural codify skill, because the codify cycle correctly closed in 0015 — the failure was in the close-out rendering, not in codify itself.
- This is NOT a new MUST/MUST NOT rule in `.claude/rules/`. A single incident at a single transition point doesn't yet justify a rule file (cf. `rule-authoring.md` "rules are frozen responses to past failures" — one failure is a journal entry; recurrence justifies a rule).
- This is NOT a workflow about WHEN to file cross-repo issues (that's 0015 §FD #1's territory). It's about how to render close-out output AFTER issues are filed.

## For Discussion

1. **Counterfactual — had the close-out filter rule been institutionalised at journal 0015, would this session's misstep have happened?** Lean: no. 0015 said the wrap-up note "can be retired"; the current session retired it from the wrap-up section but resurfaced it as an active option in the close-out menu. The two surfaces — wrap-up notes vs. close-out option list — were treated as different audiences. The right framing is: the issue is closed from csq's vantage everywhere, including options menus.

2. **Does the close-out filter scale to N handoffs?** Today there is one external handoff (terrene-foundation/terrene#2). At N=3+ external handoffs, the filter would benefit from a registry — `.claude/EXTERNAL-HANDOFFS.md` with one line per filed issue + status. Lean: defer until N=3. A single handoff is tracked verbally without drift.

3. **Does this rule apply to non-issue handoffs (e.g. an ADR draft sent to a sibling repo's PR)?** Lean: yes — anywhere csq has externalised a concern such that csq is no longer the authority. The general form is: "if it's not csq's to do, csq does not propose it as an option." File-an-issue is the most common externalisation channel, but the principle is channel-agnostic.

## Cross-references

- `workspaces/gemini/journal/0015-CONNECTION-cross-repo-journal-citation-rule-handoff.md` — the §FD #1 lean this entry operationalises on the output side.
- `~/.claude/.../memory/feedback_never_suggest_repo_switch.md` — auto-memory anchor for the rule.
- `terrene-foundation/terrene#2` — the externalised handoff that prompted this session's misstep.
- `~/repos/terrene/.claude/rules/cross-repo.md` MUST Rule 3 — the parent rule that gates csq from editing parent-repo files (the basis for externalising via GH issue in the first place).
- `~/repos/terrene/contrib/csq/.claude/rules/rule-authoring.md` — explains why this stays a journal entry rather than escalating to a rule file at single-incident scale.
