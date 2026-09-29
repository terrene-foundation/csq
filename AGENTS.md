# csq — Codex Project Entrypoint

csq is a governed execution layer for coding-agent CLIs, also embeddable through
its SDK/wire contract. Account slots and per-terminal isolation are its substrate.

Read `CLAUDE.md` first for repository directives and the maintained agent, rule,
and skill indexes. Despite that filename, its project guidance is relevant to
Codex work here. Resolve indexed `rules/`, `skills/`, and `agents/` paths under
`.claude/`; load the rules applicable to the paths and operation being changed.
Read `specs/00-manifest.md` before changing a normative contract.

For model metadata, historical pricing, selectors or daemon delivery, load:

- `.claude/skills/provider-integration/SKILL.md`
- `.claude/skills/daemon-architecture/SKILL.md`
- Their linked references relevant to the requested operation.

Canonical project knowledge stays in indexed, committed artifacts rather than
personal account memory. Do not fork a second divergent Codex-only runbook.
Claude Code hook registration does **not** automatically apply to Codex: verify
native artifact delivery and the actual harness/materializer path separately.
Presence of this entrypoint is discovery, not proof a runtime enforced every rule.

Do not modify protected `.claude/settings.json` or global harness configuration to
manufacture parity. Source changes, installed bytes, running processes, and observed
user behavior are separate evidence boundaries; retain the user's host-operation
scope and live-session safety constraints.
