# Subagent fixture — Gemini

A Gemini native subagent is registered at `.gemini/agents/test-agent.md`. Invoking `@test-agent` should cause the agent to emit its marker. If the runtime cannot invoke a subagent in headless mode for any reason, reply `SUBAGENT_PRIMITIVE_UNAVAILABLE` explicitly.

MARKER_GEMINI_BASE=gemini-subagent-fixture-GS2L
