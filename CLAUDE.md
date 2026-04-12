# Claude Squad — Desktop Account Rotation & Session Management

Tauri desktop app with Svelte frontend and Rust backend. Multi-account Claude Code quota monitoring, OAuth rotation, and session management.

## Absolute Directives

### 1. .env Is the Single Source of Truth

All API keys and OAuth tokens MUST come from `.env` via Tauri's env-backed config system. Never hardcode credentials. See `rules/security.md`.

### 2. Implement, Don't Document

When you discover a missing feature — implement it. Do not note it as a gap. See `rules/no-stubs.md`.

### 3. Zero Tolerance

Pre-existing failures MUST be fixed, not reported. Stubs are BLOCKED. See `rules/zero-tolerance.md`.

## Tech Stack

| Layer    | Technology                         |
| -------- | ---------------------------------- |
| Frontend | Svelte 5 (runes, component props)  |
| Desktop  | Tauri 2.x (Rust backend, WebView)  |
| State    | Rust backend state + Svelte stores |
| IPC      | Tauri commands (`invoke`)          |
| Styling  | CSS (plain, no framework)          |
| Build    | Cargo + Vite                       |

## Project Structure

```
src/                          — Svelte frontend source
  lib/
    components/              — Reusable UI components
    stores/                  — Svelte stores (runes-based)
    utils/                   — Frontend utilities
src-tauri/                   — Rust backend
  src/
    commands/               — Tauri command handlers
    state/                  — App state management
    oauth/                  — OAuth token rotation logic
    models/                 — Rust data structures
  Cargo.toml
  tauri.conf.json
```

## Rules

| Concern                    | Rule File                            |
| -------------------------- | ------------------------------------ |
| Account/Terminal arch      | `rules/account-terminal-separation.md` |
| No stubs/placeholders      | `rules/no-stubs.md`                  |
| Security (secrets)         | `rules/security.md`                  |
| Git workflow               | `rules/git.md`                       |
| Zero tolerance             | `rules/zero-tolerance.md`            |
| Testing                    | `rules/testing.md`                   |
| Svelte patterns            | `rules/svelte-patterns.md`           |
| Tauri patterns             | `rules/tauri-patterns.md`            |
| Tauri commands             | `rules/tauri-commands.md`            |

## Agents

| Agent                       | Role                                             |
| --------------------------- | ------------------------------------------------ |
| `claude-code-architect`     | CC artifact quality auditing                     |
| `svelte-specialist`         | Svelte 5 runes, components, stores               |
| `rust-specialist`           | Rust ownership, lifetimes, async, error handling |
| `rust-desktop-specialist`   | Tauri + Rust backend, command patterns           |
| `tauri-platform-specialist` | Tauri IPC, windowing, system integration         |
| `uiux-designer`             | Layout, hierarchy, accessibility                 |
| `gold-standards-validator`  | Naming, licensing compliance                     |
| `security-reviewer`         | Security audit, secrets management               |
| `build-fix`                 | Build errors, linking, FFI issues                |
| `tdd-implementer`           | Rust TDD with cargo test, Arrange-Act-Assert     |
| `requirements-analyst`      | Desktop app requirements, feature specs          |
| `deep-analyst`              | Failure analysis, 5-Why, risk assessment         |
| `intermediate-reviewer`     | Rust/Svelte code review, ownership, security     |
| `testing-specialist`        | Rust + Svelte testing tiers, Tauri infra         |

## Skills

| Skill                  | Purpose                                          |
| ---------------------- | ------------------------------------------------ |
| `svelte-reference`     | Svelte 5 runes, component patterns, stores       |
| `tauri-reference`      | Tauri commands, IPC, state management            |
| `uiux-principles`      | Layout, hierarchy, motion, typography            |
| `ai-interaction`       | AI interaction patterns (desktop context)        |
| `daemon-architecture`  | Daemon subsystems, invariants, IPC security      |
| `provider-integration` | 3P provider catalog, polling, rate-limit headers |
