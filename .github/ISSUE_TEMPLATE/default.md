---
name: Default
about: Every csq issue that is not a plain defect carries three fields. They exist because issues without them do not get worked — they get re-triaged.
title: ""
labels: ""
assignees: ""
---

<!--
Three fields, then the body. They cost one line each at filing time and replace
a recurring per-sweep cost: two issues without them absorbed five sweeps of
triage attention between 2026-07-19 and 2026-08-03 and produced no disposition.

If you cannot fill all three, that is the signal — see "no anchor" below.
-->

**Value-anchor:** <!-- ONE sentence, in the user's language, of what this unlocks.
Cite a user-anchored source per value-prioritization.md MUST-1's closed allowlist:
(a) the user's brief this session, (b) briefs/ in the active workspace,
(c) a journal DECISION- entry, (d) a verbatim user quote, (e) a spec § success
criterion the user authored or approved.

"Surveyed, no user-anchored source" is a LEGITIMATE answer — and it means this is
a note, not an issue. Do not file it. -->

**Class:** <!-- exactly one -->

- `DEFECT` — has a done-state and is agent-runnable. Needs a reproducible wrong behaviour.
- `DECISION` — blocked on a named human's act. **Name them.** Not "maintainer" — who.
- `RESEARCH` — has no done-state. **Name the decision it feeds**, and the date it expires.
  If you cannot name a decision it feeds, it is not research, it is curiosity: close the tab.

**Owner:** <!-- who owes the NEXT act. For DEFECT this may be "anyone". For DECISION it is a person. -->

**Backstop:** <!-- YYYY-MM-DD. completion-criterion.md MUST-6's calendar backstop, applied to
issues. On this date the issue is re-surfaced REGARDLESS of whether its blocker
landed — because "blocked" with no expiry is indistinguishable from forgotten. -->

---

## What

<!-- The defect, decision, or question. -->

## Why it matters

<!-- Consequence if nothing happens. If you cannot state one, re-read the value-anchor. -->

## Acceptance criteria

<!-- Testable, for DEFECT and DECISION. Two readers should evaluate them identically.

For DECISION, at least one criterion is the human act itself ("X ruled on Y, recorded in Z") —
that is what makes it visibly blocked on a person rather than merely unstarted.

RESEARCH has no acceptance criteria by definition. That is why it needs an expiry
and a named downstream decision instead. -->

- [ ]
- [ ]

## Blocked on

<!-- If blocked: name the contract, and whether it is FILED upstream. An unfiled
blocker means nobody has been asked, which is indistinguishable from waiting
forever. Two csq issues carried blockers that had shipped ~7 weeks earlier, and a
third was blocked on a decision no one had requested. Re-verify before filing. -->
