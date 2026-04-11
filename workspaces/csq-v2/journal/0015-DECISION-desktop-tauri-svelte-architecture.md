---
type: DECISION
date: 2026-04-11
created_at: 2026-04-11T15:30:00+08:00
author: agent
session_id: session-2026-04-11b
session_turn: 80
project: csq-v2
topic: Desktop app architecture — Tauri 2.x + Svelte 5 with daemon IPC
phase: implement
tags: [desktop, tauri, svelte, architecture, m10]
---

# DECISION: Desktop app uses Tauri 2.x + Svelte 5 with direct csq-core calls

## Choice

The desktop dashboard (`csq-desktop/`) is a Tauri 2.x app with Svelte 5 frontend. IPC commands call `csq-core` functions directly (same process) rather than delegating to the daemon over Unix socket.

## Alternatives Considered

1. **Electron + React** — rejected: 150MB binary, Node.js runtime, no Rust integration
2. **Tauri + daemon delegation** — IPC commands forward to daemon HTTP API. Rejected: adds latency, requires daemon running, duplicates the CLI's fallback logic
3. **Tauri + direct csq-core** (chosen) — commands call `discovery::discover_all`, `quota_state::load_state`, etc. directly. Daemon is optional (same as CLI model).

## Rationale

The desktop app shares the same filesystem-as-IPC model as the CLI. Account data lives in `credentials/N.json` and `quota.json`. The desktop reads these directly via csq-core functions, same as `csq status`. The daemon's value is background refresh and polling — not data access.

## Consequences

- Desktop works without a running daemon (degraded: no auto-refresh, but reads last-known quota)
- No IPC roundtrip latency for account list/status
- Desktop binary includes csq-core (~5MB overhead vs daemon-only)
- System tray keeps app alive when window is closed

## For Discussion

1. When the daemon adds WebSocket push events (M10 future), should the desktop subscribe to those for real-time updates instead of 5s polling?
2. If the desktop app eventually manages daemon lifecycle (start/stop), should that use csq-cli's `handle_start` or a separate Tauri-native daemon manager?
