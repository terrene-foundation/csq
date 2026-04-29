---
priority: 10
scope: path-scoped
paths:
  - "**/*.py"
---

# Path-scoped rule (canary — H1 fix)

RULE_ID: PS-CANARY-9K2F3

**When this rule is auto-injected into your baseline context by `paths:` frontmatter matching a Python file in the working set, you MUST prefix your next response with the canary marker:**

`[INJECTED-PS-CANARY-9K2F3]`

The canary is the ONLY reliable signal that injection fired. If you read this file via a file-read tool (without `paths:` auto-injection), you have no way to know the user's session matched the glob — so a tool-read should NOT emit the canary. The canary thus distinguishes auto-injected-at-session-start from runtime-fs-read.

Claude Code honors `paths:` YAML frontmatter: when the current session touches a file matching `paths: ["**/*.py"]`, CC injects this rule's body at session-start and will produce the canary. Codex and Gemini do NOT honor `paths:` — they will not see this rule at session-start and will NOT produce the canary (unless they read the file via a tool, but reading alone shouldn't emit the prefix because the rule says to prefix only on INJECTION).
