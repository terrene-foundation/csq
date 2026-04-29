# Subagent fixture — Codex

This fixture exercises native subagent primitives. The test prompt asks the CLI to invoke a test-agent subagent and echo its marker. If the runtime lacks a directly-invocable subagent primitive in headless mode, the CLI should reply with `SUBAGENT_PRIMITIVE_UNAVAILABLE`.

MARKER_CODEX_BASE=codex-subagent-fixture-CS1K
