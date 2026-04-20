---
name: todos
description: "Load phase 02 (todos) for the current workspace"
---

## Workspace Resolution

1. If `$ARGUMENTS` specifies a project name, use `workspaces/$ARGUMENTS/`
2. Otherwise, use the most recently modified directory under `workspaces/` (excluding `instructions/`)
3. If no workspace exists, ask the user to create one first
4. Read all files in `workspaces/<project>/briefs/` for user context (this is the user's input surface)

## Phase Check

- Read files in `workspaces/<project>/02-plans/` for context
- Check if `todos/active/` already has files (resuming)
- All todos go into `workspaces/<project>/todos/active/`

## Execution Model

This phase executes under the **autonomous execution model** (see `rules/autonomous-execution.md`). All effort estimates in todos MUST use autonomous execution cycles, not human-days. When referencing external plans that estimate in human-days, apply the 10x multiplier to translate. Do not phase work based on "team bandwidth" — phase based on dependency order and validation gates.

**The /todos approval gate is a structural gate**: the human approves the plan (what and why), not the execution (how and when). Once approved, /implement executes autonomously.

## Workflow

### 1. Review plans with specialists

Reference plans in `workspaces/<project>/02-plans/` and work through every single file.

Review plans against claude-squad's architecture constraints: Python stdlib only (no PyPI deps), bash + POSIX tools for the shell layer, cross-platform (macOS/Linux/WSL/Windows). Any plan that requires a new runtime dependency is a non-starter unless justified and approved.

### 2. Codebase locations

- `csq-core/` — Rust crate holding quota, OAuth broker, sessions, handle-dir, daemon
- `csq-cli/` — Rust binary (`csq`) with all subcommands including `statusline`
- `csq-desktop/` — Tauri + Svelte app with tray UI + updater
- `install.sh` — one-time bootstrap installer (downloads CLI binary from latest release)
- `journal/` — project decisions, discoveries, gaps
- `workspaces/<project>/` — active workspace with briefs/plans/todos for larger initiatives

### 3. Create comprehensive todos

**CRITICAL: Write ALL todos for the ENTIRE project.**

- Do NOT limit to "phase 1" or "what should be done now"
- Do NOT prioritize or filter — write EVERY task required to complete the full project
- Cover backend, frontend, testing, deployment, documentation — everything
- Each todo should be detailed enough to implement independently
- If the plans reference it, there must be a todo for it
- For large projects (20+ todos), organize into numbered milestones/groups for clarity

**CRITICAL: Integration wiring is a separate todo.** Every component that consumes or produces data MUST have TWO todos:

1. **Build** — create the component with structure and logic (`"Build carpark page"`, `"Build prediction handler"`)
2. **Wire** — connect to real data sources, replace all mock/hardcoded data with live calls (`"Wire carpark page to backend API"`, `"Wire prediction handler to ML service"`)

This applies to frontend (pages calling APIs) AND backend (handlers calling services, databases, or external APIs). A handler returning `{"predictions": [0.9, 0.8]}` instead of calling the ML service is the same bug as a page using `generateHourlyOccupancy()`.

A "build" todo is complete when the component runs. A "wire" todo is complete when real data flows end-to-end with zero mock data remaining. These are NOT the same task and MUST NOT be collapsed.

**CRITICAL: Architecture plans are contractual.** Every abstraction in `02-plans/` (data fabric, ML fabric, service layers, etc.) MUST have a corresponding implementation todo. If a plan describes a `DataFabric` class, there must be a todo to build that class — not just ad-hoc calls that bypass the design.

Create detailed todos for EVERY task required. Place them in `todos/active/`.

### 4. Red team the todo list

Review with red team agents continuously until they are satisfied there are no gaps remaining.

### 5. STOP — wait for human approval before proceeding to implementation.

## Agent Teams

Deploy these agents as a team for todo creation:

- **todo-manager** — Create and organize the detailed todos, ensure completeness
- **requirements-analyst** — Break down requirements, identify missing tasks
- **deep-analyst** — Identify failure points, dependencies, and gaps
- **security-reviewer** — Flag security-sensitive tasks early (credentials, OAuth flow, atomic file handling)

Red team the todo list with agents until they confirm no gaps remain.

### Journal

Create journal entries for decisions made during planning:

- **DECISION** entries for scope choices, prioritization rationale, and architectural direction
- **TRADE-OFF** entries for competing approaches evaluated
- **RISK** entries for risks identified during planning

Use sequential naming: check the highest existing `NNNN-` prefix and increment.
