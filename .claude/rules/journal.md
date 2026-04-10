---
paths:
  - "workspaces/**"
  - "journal/**"
---

# Journal Rules

## Scope

These rules apply to ALL workspace operations. The journal is the primary knowledge trail for every project.

## MUST Rules

### 1. Journal Every Insight

Every CO command that produces insights, decisions, or discoveries MUST create corresponding journal entries in the workspace's `journal/` directory. No insight should be lost between sessions.

**Why:** Unwritten insights rot between sessions; the next agent inheriting the project has to re-derive every conclusion from scratch, burning hours on work that was already done.

### 2. Sequential Naming

Journal entries MUST use sequential naming: `NNNN-TYPE-topic.md` (e.g., `0001-DECISION-chose-event-driven.md`, `0002-DISCOVERY-connection-pool-bottleneck.md`). Before creating a new entry, MUST check the highest existing number in the journal directory.

**Why:** Sequential numbering preserves chronology even when dates drift (timezone issues, clock skew) and makes `ls journal/` a valid history view without needing metadata.

### 3. Frontmatter Required

Journal entries MUST include YAML frontmatter with these fields:

```yaml
---
type: DECISION | DISCOVERY | TRADE-OFF | RISK | CONNECTION | GAP
date: YYYY-MM-DD
created_at: [ISO-8601 timestamp]
author: human | agent | co-authored
session_id: [session ID if available]
session_turn: [conversation turn number]
project: [project name]
topic: [brief description]
phase: analyze | todos | implement | redteam | codify | deploy
tags: [list of relevant tags]
---
```

- `created_at`: precise creation timestamp for temporal analysis
- `author`: who drove the insight, determined by decision tree:
  - `human` — user stated the conclusion before the AI elaborated. Test: would this insight exist without the AI?
  - `agent` — AI surfaced this unprompted. Test: did the user know this before the AI said it?
  - `co-authored` — insight evolved through exchange; neither party alone reached it. When uncertain, prefer `co-authored` over `human`.
- `session_id`: links the entry to the session that produced it
- `session_turn`: approximate conversation turn number; creates temporal fingerprint (entries within a session should show increasing turns)

### 4. Use Correct Entry Types

Six entry types exist. Use the right one:

| Type           | Purpose                                                                   | When Created                                                                      |
| -------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **DECISION**   | Record a choice with rationale, alternatives considered, and consequences | When making architectural, design, strategic, or scope decisions                  |
| **DISCOVERY**  | Capture something learned — a concept, pattern, insight, or finding       | When research, analysis, or exploration reveals new understanding                 |
| **TRADE-OFF**  | Document a trade-off evaluation — what was gained and what was sacrificed | When balancing competing concerns                                                 |
| **RISK**       | Record an identified risk, vulnerability, or concern                      | When stress-testing, reviewing, or validating reveals potential problems          |
| **CONNECTION** | Note a relationship between concepts, components, or findings             | When cross-referencing reveals links that matter                                  |
| **GAP**        | Flag something missing that needs attention                               | When analysis reveals missing data, untested assumptions, or unresolved questions |

### 5. For Discussion Section

Every journal entry MUST include a `## For Discussion` section with 2-3 questions that probe the reasoning behind the entry. Requirements:

- At least one question must reference specific data, sources, or constraints from the entry
- At least one must be a counterfactual ("If X had been different...")
- Question structures must vary across entries (compare, challenge assumption, extend, invert, ask for evidence)
- Questions must be answerable only by someone who genuinely engaged with the decision

### 6. Self-Contained Entries

Each journal entry MUST be self-contained — readable without requiring other context. Include enough background that a future session (or a different person) can understand the entry on its own.

**Why:** Entries that assume "you were there when this happened" decay the moment the author steps away, turning the journal into a set of cryptic one-liners that only help the person who didn't need them.

## SHOULD Rules

### 1. Decision Rationale

DECISION entries SHOULD include alternatives considered and the rationale for the choice, not just the decision itself.

### 2. Consequences and Follow-Up

Entries SHOULD include consequences, follow-up actions, or next steps where applicable.

## MUST NOT Rules

### 1. No Overwriting

MUST NOT overwrite existing journal entries. Each entry is immutable once created. If a decision changes, create a new entry that references the original.

**Why:** Overwriting destroys the history the journal is supposed to preserve — the "why we decided X" becomes unavailable once X is replaced with Y, and no one can audit the reasoning chain.

### 2. No Entries Without Frontmatter

MUST NOT create journal entries without proper YAML frontmatter. The frontmatter enables searching, filtering, and cross-referencing.

**Why:** Without frontmatter, the journal collapses into a pile of loose markdown files that can't be filtered by type, date, or author — the entire retrieval story depends on it.
