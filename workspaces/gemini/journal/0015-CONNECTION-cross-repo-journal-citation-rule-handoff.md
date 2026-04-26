---
type: CONNECTION
date: 2026-04-27
created_at: 2026-04-27T00:30:00Z
author: co-authored
session_id: 2026-04-27-cross-repo-handoff
session_turn: 25
project: csq
topic: Externalize the cross-repo journal-citation carry-forward by filing terrene-foundation/terrene#2 and closing local tracking
phase: codify
tags:
  [cross-repo, journal-rule, evidence-cite, handoff, parent-repo, carry-forward]
---

# Connection — cross-repo journal-citation rule handoff to parent repo

## Context

Three §For Discussion items in csq's journals proposed a SHOULD rule for `~/repos/terrene/.claude/rules/journal.md` requiring journal claims to cite their evidence (upstream data source, empirical reference, or external authority). The proposal had been parked for two consecutive codify cycles (v2.1 in journal 0073, v2.3 in journal 0014) under the convention that csq sessions do not modify parent-repo `.claude/` files.

The originating §FD items:

- **`workspaces/codex/journal/0022-DECISION-pr-c9a-round1-convergence.md` §FD #3** — surfaced from PR-C9a CRITICAL-1: PR-C1's journal 0011 claimed the same-surface filter was complete, but the filter's upstream dependency (`discover_anthropic`) was not updated. The journal text _"Per journal 0067 H3"_ cited the predicate, not the upstream data source. Takeaway: invariant-enforcement claims should cite the specific upstream data source, not just the filter predicate.
- **`workspaces/codex/journal/0023-DECISION-pr-c9a-m10-resolution.md` §FD #3** — surfaced from PR-C7 M10 review: the `sessions/`-orphan rationale (_"a running process holds fds; symlink-repoint orphans them"_) was asserted in an inline docstring with no empirical reference, despite being trivially refutable by `man 2 rename` or a 10-line test. Takeaway: design rationales should not land without a journal cite, test cite, or external-authority cite.
- **`workspaces/csq-v2/journal/0073-DECISION-codify-v2.1-cycle-knowledge.md` §"What was NOT codified"** + **`workspaces/gemini/journal/0014-DECISION-codify-v2.3-cycle-knowledge.md` §"What was NOT codified"** — both flagged the rule combination as parked for the next root-level session, with the explicit pointer to combine #3 of journals 0022 + 0023 into a single new SHOULD rule.

## The handoff

User directive 2026-04-27: _"issue gh to the repo and close on our end if its not our problem."_

Filed: **terrene-foundation/terrene#2** — `Add SHOULD rule to .claude/rules/journal.md: claims must cite evidence (upstream data, empirical reference)`. The issue body is self-contained per `journal.md` MUST Rule 6: it carries the full proposed rule text, both originating findings with their PR-C9 incident pointers, the Why-SHOULD-not-MUST argument, scope, and out-of-scope items. A parent-repo session can act on it without reading any csq journal first.

This entry is the closing acknowledgement that:

1. The carry-forward is no longer csq's responsibility to track. Future codify passes do not need to re-park it under "What was NOT codified."
2. The rule, when it lands at the parent layer, will inherit into csq automatically (csq inherits parent `.claude/rules/`); no re-codification at csq is required.
3. If the parent issue is rejected or modified, csq learns about it via the inheritance path, not via re-tracking here.

## Why csq did not edit the parent file directly

Two reasons:

- **Convention.** Journals 0073 + 0014 both interpreted `cross-repo.md` MUST Rule 3 as "csq does not modify parent-repo files." Two consecutive codify passes treating it as a hard boundary makes it institutional, regardless of whether the literal rule text says so. Breaking it for a single SHOULD-rule patch would weaken the convention disproportionately.
- **Context inheritance.** A csq session loads csq's CLAUDE.md, csq's foundation-independence rule, csq's specs-authority rule. A parent-repo edit needs the parent's CLAUDE.md and the parent's content-flow / terrene-naming / foundation-independence framing, none of which apply inside csq. The right place for the edit is a session opened at `~/repos/terrene/` so the work inherits the right governance.

## Consequences

- The csq wrap-up note "Cross-repo journal-citation rule (carry-forward from journal 0073 + 0014) — combine conventions into a SHOULD rule for `terrene/.claude/rules/journal.md`" can be retired from future session notes.
- The v2.3 cycle is now structurally **and** operationally closed at the csq level. No csq-side carry-forward remains.
- Future csq sessions that hit the _"claim without evidence cite"_ class regression should reference terrene-foundation/terrene#2 in their findings, not the originating §FD items, since the parent issue is now the authority for the rule's status.

## For Discussion

1. The two-codify-pass parking convention (v2.1 then v2.3 both deferred to "next root-level session") created a 3-month gap between when the rule was first proposed (PR-C9a, ~2026-04-23) and when the issue was actually filed (2026-04-27). Counterfactual: had csq filed the parent-repo issue at the moment of journal 0073's §"What was NOT codified" entry, the rule could have shipped during the v2.3 cycle — and the v2.3 codify pass would not have needed to re-park it. Should csq's `/codify` skill be amended to require _"any §FD item that recommends a parent-repo change MUST file a parent-repo GH issue in the same session, not just park it"_? (Lean: yes — the parking-without-issue pattern is invisible from outside csq, so the parent repo never sees the request.)

2. The proposed rule (SHOULD, not MUST) places the evidence-cite burden on the journal author at write-time. Counterfactual: had the rule been MUST, journal 0011's incomplete cite (_"Per journal 0067 H3"_) would have been blocked at PR-C1 review and the upstream `discover_anthropic` gap would have been visible immediately — but the same MUST framing would also have blocked taxonomy/reading-order journal entries that have no single evidence source. Is the MUST-vs-SHOULD line being drawn at the right place, or should the rule be MUST for invariant/decision claims and SHOULD for descriptive entries? (Lean: SHOULD-with-clear-when-MUST-applies, but that nuance belongs in the parent-repo issue discussion, not pre-decided here.)

3. By filing the parent-repo issue from inside csq, this session traversed the cross-repo direction csq's prior journals declared off-limits ("csq does not modify parent-repo files"). The action this session DID take was filing a GitHub issue, not editing parent-repo files — does the convention's intent extend to GH-issue-filing as well, or is "issue filed externally" the canonical safe-channel? (Lean: GH issues are the canonical safe-channel. The rule's intent is "don't surprise the parent repo by silently modifying its files"; an issue is the opposite — explicit, reviewable, optional for the parent to act on.)

## Cross-references

- **terrene-foundation/terrene#2** — the parent-repo issue this entry hands off to.
- `workspaces/codex/journal/0022-DECISION-pr-c9a-round1-convergence.md` §FD #3 — origin of finding 1 (invariant-enforcement claims).
- `workspaces/codex/journal/0023-DECISION-pr-c9a-m10-resolution.md` §FD #3 — origin of finding 2 (design rationales).
- `workspaces/csq-v2/journal/0073-DECISION-codify-v2.1-cycle-knowledge.md` §"What was NOT codified" — first parking event.
- `workspaces/gemini/journal/0014-DECISION-codify-v2.3-cycle-knowledge.md` §"What was NOT codified" — second parking event.
- `~/repos/terrene/.claude/rules/journal.md` — the file the proposed rule will land in.
- `~/repos/terrene/.claude/rules/cross-repo.md` MUST Rule 3 — the convention this handoff respects.
