---
paths:
  - ".claude/rules/**"
  - ".claude/agents/**"
  - ".claude/skills/**"
  - ".claude/commands/**"
---

# Rule Authoring Meta-Rule

Rules are the agent's linguistic tripwires. This meta-rule defines how all other rules MUST be authored so that each new rule compounds the effect of the existing ones instead of diluting it.

Origin: loom journal 0052. Validated by subprocess A/B test: rule quality improved from 2/6 to 6/6 when this meta-rule was loaded.

## MUST Rules

### 1. Phrased As Prohibitions, Not Encouragements

Every rule's load-bearing clauses MUST use `MUST` or `MUST NOT`. The words "should," "try to," "prefer," and "consider" are BLOCKED as the primary modal of a rule clause.

```markdown
# DO

### 1. Bulk Ops MUST Log Partial Failures at WARN

# DO NOT

### 1. Bulk Ops Should Log Partial Failures
```

**Why:** "Should" tells the agent it is permitted to skip. Under time pressure, everything permitted to be skipped is skipped.

### 2. Linguistic Tripwires Enumerate BLOCKED Phrases Verbatim

When a rule targets a behavior the agent is prone to rationalize, it MUST include the exact excuse phrases marked BLOCKED.

```markdown
# DO

**BLOCKED responses:**

- "Pre-existing issue, not introduced in this session"
- "Outside the scope of this change"
- ANY acknowledgement without an actual fix

# DO NOT

Do not defer work. Address issues as you find them.
```

**Why:** Abstract "do not defer" is trivially rationalized. Verbatim blocked phrases block the rationalization at the linguistic level.

### 3. Every MUST Clause Has DO / DO NOT Examples

Every `MUST` or `MUST NOT` clause MUST include a concrete example showing both the correct and blocked pattern.

**Why:** Without examples, the agent reconstructs meaning from context and gets it wrong at edges. The example is the unambiguous anchor.

### 4. Every MUST Clause Has A `**Why:**` Line

Every `MUST` and `MUST NOT` clause MUST be followed by a `**Why:**` line (2 sentences max) explaining the failure mode the rule prevents.

**Why:** The `Why:` line converts a rote rule into a principle the agent can apply to situations the rule-author never imagined.

### 5. Rules Are Path-Scoped Unless Truly Universal

Every rule MUST include `paths:` YAML frontmatter scoping it to the file patterns where it applies. Only rules that apply universally (`zero-tolerance`, `communication`, `git`, `security`, `independence`) may omit `paths:`.

**Why:** Rules without `paths:` pay full token cost in every session's baseline. Rules with `paths:` load once per session on first matching file read.

### 6. Rule Credits the Originating Journal Entry

Every new rule MUST include a one-line `Origin:` reference pointing to the journal entry or discovery that motivated it.

**Why:** A rule is a frozen response to a past failure. Without provenance, future agents cannot judge whether the rule still applies after the underlying failure mode has been fixed.

## MUST NOT

- Rationale paragraphs longer than 2 sentences per `Why:` line

**Why:** Long rationale crowds the rule's load-bearing clauses out of working memory.

- Hedging phrases ("in most cases," "generally speaking") in a MUST clause

**Why:** Hedging converts a MUST into a should and reintroduces permission-to-skip.

- Rules longer than 200 lines

**Why:** Rules longer than 200 lines are skimmed; the agent misses load-bearing clauses. Extract reference material into a skill.

## The "Loud, Linguistic, Layered" Test

Before committing any new rule, verify:

1. **Loud** -- can the rule be ignored by quoting a standard excuse phrase? If yes, add that phrase to the BLOCKED list.
2. **Linguistic** -- does the rule target wording the agent might use, not just behavior? If no, rewrite.
3. **Layered** -- at which load layer does the rule fire? If session-start for a non-universal rule, add `paths:`.

Rules that fail any check MUST be revised before merging.
