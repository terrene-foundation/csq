# Subagent fixture — Claude Code

Claude Code's native subagent primitive is the Agent tool with `subagent_type`. Headless `-p` invocation doesn't provide a first-class surface for testing subagents without writing them into `.claude/agents/`. This fixture's goal for CC is loose: check that CC either runs the equivalent flow or reports the primitive unavailable.

MARKER_CC_BASE=cc-subagent-fixture-CC3M
