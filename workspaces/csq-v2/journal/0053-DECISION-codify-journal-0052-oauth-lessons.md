---
type: DECISION
date: 2026-04-14
created_at: 2026-04-14T17:50:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-14-refresh-rescue
project: csq-v2
topic: Codify the four durable lessons from journal 0052 (Anthropic refresh `invalid_scope` cascade) into the provider-integration skill, daemon-architecture skill, deep-analyst agent, security-reviewer agent, testing-specialist agent, and spec 01. Place the Anthropic server contract in exactly one place (the skill) and point every other artifact at it.
phase: codify
tags:
  [
    codify,
    oauth,
    contract-drift,
    cascade-failure,
    redaction,
    testing,
    journal-0052,
  ]
---

# 0053 — DECISION — Codify the journal-0052 lessons into long-lived artifacts

## What was codified

Journal 0052 captured the root cause and the rescue. This entry captures where the _durable lessons_ now live so future sessions inherit them without having to re-read the incident post-mortem.

Four distinct lessons came out of the incident. Each one lands in the artifact whose responsibility it is, and nowhere else:

| Lesson                                                                                                                                                                                                              | Where it lives now                                                                                                                                                   | Why that place                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Anthropic's refresh endpoint rejects the `scope` field. Reference request body shape + debugging runbook.                                                                                                        | `.claude/skills/provider-integration/SKILL.md` — new "OAuth refresh body: `scope` field is FORBIDDEN" section + "Runbook: dashboard says healthy but CC says /login" | This skill is already the single source of truth for Anthropic endpoint contract details. Putting the shape here keeps spec 01 (which is about CC's credential architecture, not Anthropic's server contract) from becoming a second authority that can drift. |
| 2. Classifier substring matches can make the _consequence_ of a cascade look like the _cause_. `is_rate_limited` showed `rate_limited` in the cache while the actual error was `invalid_scope`.                     | `.claude/skills/daemon-architecture/SKILL.md` — new Invariant 5 "`is_rate_limited` is Substring-Based and Can Lie"                                                   | Daemon subsystem design is this skill's domain. Agents working on refresher, broker_check, or any classifier now see the warning inline before they make a similar change.                                                                                     |
| 3. Mocked HTTP tests freeze what the client sends, not what the server accepts. A live-replay contract test gated behind `workflow_dispatch` would have caught this within hours.                                   | `.claude/agents/testing-specialist.md` — new subsection "Mocked transport hides server-side contract drift" under Injectable HTTP Transport                          | This is testing philosophy, not a per-subsystem fact. It belongs in the testing agent that reviews test PRs and can block tests that freeze the wrong shape.                                                                                                   |
| 4. `redact_tokens` erased the word `invalid_scope` from every log line. OAuth `error` type strings are a fixed spec-defined vocabulary and are NOT secrets — letting them through the redactor is a diagnostic win. | `.claude/agents/security-reviewer.md` — new subsection "Diagnostic Redaction vs. Defense Balance" under Error-Chain Token Leakage                                    | The security agent owns the redactor's policy. Future reviews will see the allowlist proposal and the open security question (prompt-injection via attacker-crafted error types) together.                                                                     |

Additionally:

- `.claude/agents/deep-analyst.md` got a new "Cascade-Failure Pattern: Consequence Masks the Cause" section under Failure Mode Analysis. This generalizes the incident into a pattern (with diagnostic questions) rather than naming the specific bug. That pattern is reusable the next time an upstream service tightens any contract.
- `specs/01-cc-credential-architecture.md` §1.9 got a forward-pointer to the provider-integration skill. The spec intentionally does NOT cover Anthropic server contract, but now says so explicitly, and names the two known drift events (journals 0034 and 0052) so a future reader knows the forward-pointer is load-bearing, not aspirational.

## Why I did NOT create new artifacts

Every lesson lands in an existing agent or skill. I considered:

- **New skill "oauth-debugging-runbook"** — rejected. The runbook is Anthropic-specific, and there's no second OAuth provider to justify a cross-provider skill. Inline under provider-integration keeps the token endpoint's full story in one place.
- **New rule "no-frozen-payload-tests"** — rejected. The testing-specialist agent is the right enforcer because it already reviews test PRs; a stand-alone rule would load on every turn even when no test files are being touched. The cc-artifacts path-scoping advice applies: a rule this specific should live where it's already going to be read.
- **New agent "contract-drift-detective"** — rejected. Deep-analyst already covers failure-mode analysis and root-cause work. The new "Cascade-Failure Pattern" subsection is one sub-pattern among many in its domain; a separate agent would duplicate tooling access and splinter the failure-analysis workflow.

## Alternatives considered

1. **Put the Anthropic contract in spec 04 (daemon architecture) instead of the skill.** Rejected — spec 04 is about the daemon's _internal_ design (subsystems, invariants, shutdown), not about upstream contracts. The skill is loaded by agents when they _work on_ daemon code, which is exactly when the contract matters.
2. **Add a `rules/provider-contract-drift.md` file.** Rejected — rules are for MUST / MUST NOT enforcement, not reference material. The content is "this is how you diagnose it", which is agent/skill knowledge, not a rule the linter can check.
3. **Expand journal 0052 with "how to codify" at the bottom.** Rejected — journals are immutable per `rules/journal.md`. A separate DECISION entry (this one) is the right place to record the codification choices.

## Red-team check against `.claude/rules/cc-artifacts.md`

- **Agent descriptions under 120 chars** — unchanged; I edited bodies, not frontmatter.
- **Agents under 400 lines** — deep-analyst 219 (was 195), security-reviewer 124 (was 110), testing-specialist 172 (was 158). All well under cap.
- **SKILL.md progressive disclosure** — both edited skills still answer routine questions without requiring sub-file reads. provider-integration grew from 147 → 215 lines; daemon-architecture 128 → 140. Neither directory has sub-files; neither has grown past the point where that matters.
- **No CLAUDE.md duplication** — none of the new content duplicates CLAUDE.md.
- **Cross-references resolve** — spec 01 now points at `.claude/skills/provider-integration/SKILL.md`; that file exists. provider-integration SKILL points at `csq-core/src/broker/check.rs::is_rate_limited`; that function exists at the named path.
- **Rules path-scoping** — N/A, no new rules added.

## Consequences

- **Next session's agent working on the refresher / broker_check / usage poller** will see the "substring classifier can lie" warning inline and know to check for cascade-failure shape before trusting `rate_limited` telemetry.
- **Next session's agent writing or reviewing an OAuth-related test** will be prompted by testing-specialist to think about whether they're locking in a frozen client payload or actually exercising the contract.
- **Next session's agent debugging a "dashboard healthy but CC says /login" report** will find the manual-replay runbook in the provider-integration skill instead of having to re-derive the python/curl one-liner from scratch.
- **Next session's security review of the redactor** will see the documented allowlist proposal and the unresolved prompt-injection question, not just the current defensive posture.

## Follow-ups tracked (not in scope for this entry)

- **Open PR** to add the OAuth error type allowlist to `redact_tokens`. Needs security review for prompt-injection risk before merging. Tracked at the end of journal 0052 and in the "Outstanding" section of this session's wrapup notes.
- **Open PR** to tighten `is_rate_limited` so genuine 429s are distinguished from other 4xx. Needs a reclassification plan first — the cooldown semantics depend on `RateLimited` being a transient state, not a contract failure, so the classifier and the cooldown TTL move together.
- **Add a live-replay contract test** (manual workflow trigger) against Anthropic's `/v1/oauth/token`. Requires a dedicated test account in Foundation secrets.

## For Discussion

1. The testing-specialist now carries a rule (new subsection rule #3) that "a payload-shape test is not a contract test." Several _existing_ csq integration tests still shape-assert captured bodies without any comment citing the server's documentation. Should we audit them as a single batch follow-up, or wait until the next drift incident forces the audit? What's the evidence-based argument for one versus the other, given journal 0034 and 0052 are the only two drift incidents we have data on?

2. I placed the Anthropic contract details in `provider-integration/SKILL.md` and not in `specs/01-cc-credential-architecture.md`. Spec 01 now has a forward-pointer and a "does NOT cover" disclaimer. If the provider-integration skill were ever deleted or renamed, spec 01's pointer would become a dangling reference. Is a forward-pointer from an authoritative spec to a skill the right relationship, or should spec 01 be the authority with the skill as a consumer? What changes if this is the 10th drift event instead of the 2nd?

3. The deep-analyst agent now has a "Cascade-Failure Pattern" section that abstracts this incident into a general debugging framework. The abstraction could turn out to be premature — one incident is not a pattern, two might be (with journal 0034 as the other). What other csq incidents would need to also fit the pattern for the abstraction to prove its worth, and what specific features of those hypothetical incidents would validate or invalidate the framing?
