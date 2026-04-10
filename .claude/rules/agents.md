---
name: agents
description: Agent orchestration rules for claude-squad. MUST delegation requirements, analysis chains, parallel execution, and structural gates.
---

# Agent Orchestration Rules

## MUST Delegation

When working with specific domains, consult the relevant specialist:

| Domain | Agent | When |
|--------|-------|------|
| Svelte 5 components | `svelte-specialist` | Rune patterns, stores, TypeScript, desktop UI |
| Tauri command API | `rust-desktop-specialist` | Command design, state, IPC |
| Platform/distribution | `tauri-platform-specialist` | App signing, system tray, permissions |
| Core Rust language | `rust-specialist` | Ownership, lifetimes, async, errors |
| Security-sensitive changes | `security-reviewer` | OAuth, keychain, credential handling |
| Tauri command design | `tauri-commands` rule | Naming, validation, error mapping |

**Why:** Specialists encode hard-won domain patterns that generalist agents miss.

## MUST NOT

- Delegate security-sensitive changes without `security-reviewer` before commit

```
DO NOT: Commit OAuth flow changes without a security review
DO NOT: Ship keychain write code without checking against security-reviewer
```

**Why:** Credential handling mistakes in Rust are unrecoverable — no runtime recovery, raw bytes in memory.

- Skip structural gates to save time

```
DO NOT: "Skipping review to save time"
DO NOT: "The changes are straightforward, no review needed"
```

**Why:** Every gate skipped is a risk compounding into the next session.

## Analysis Chain (Complex Features)

For features with unclear requirements or multiple valid approaches:

1. **deep-analyst** → Identify failure points
2. **requirements-analyst** → Break down requirements
3. Decide approach (design vs implement)
4. **tdd-implementer** → Implement with tests

## Parallel Execution

When multiple independent operations are needed, launch them in parallel. MUST NOT run sequentially when parallel is possible.

```
DO: Agent(prompt="task A...") + Agent(prompt="task B...") in parallel
DO NOT: Run task A, then task B sequentially
```

**Why:** Sequential execution wastes the autonomous execution multiplier.

## Cross-References

- `zero-tolerance.md` — failures must be fixed, not reported
- `no-stubs.md` — stub detection and enforcement
- `security.md` — security review checklist
- `git.md` — commit and branch workflow
