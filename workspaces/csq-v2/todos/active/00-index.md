# csq v2.0 — Todo Index

112 tasks across 12 milestones. Covers the full Rust+Tauri rewrite from scaffolding through packaging.

## Priority Summary

| Priority  | Milestones | Tasks   | Sessions | Description                                            |
| --------- | ---------- | ------- | -------- | ------------------------------------------------------ |
| P0        | M0-M7      | 68      | 19       | v1.x CLI parity — every csq command works in Rust      |
| P1        | M8-M10     | 30      | 14       | Daemon + dashboard + tray — the v2.0 value proposition |
| P2        | M5a, M11   | 14      | 6        | Auto-rotation, packaging, CLI polish                   |
| **Total** | **12**     | **112** | **~34**  | **~12 days wall clock at 3 parallel sessions/day**     |

## Milestone Dependency Graph

```
M0 (Scaffolding)
 |
 v
M1 (Platform) ──────────────────────────> M7 (Providers/CLI)
 |                                              |
 v                                              v
M2 (Credentials) ──> M3 (Accounts) ──> M5 (Swap/Quota) ──> M7-11 (clap routing)
                          |                 |
                          v                 v
                     M4 (Broker) ──> M6 (Session/Run)
                                        |
                         ── P0 Complete ──
                                        |
                                        v
                                   M8 (Daemon)
                                   /    |    \
                                  v     v     v
                             M9 (OAuth)  M8-06 (Poller)
                                  \     |     /
                                   v    v    v
                              M10 (Desktop/Tauri)
                                        |
                         ── P1 Complete ──
                                        |
                                        v
                              M11 (Packaging)
                              M5a (Auto-rotation)
```

## Milestones

| #   | File                        | Tasks | Priority | Effort       | Dependencies |
| --- | --------------------------- | ----- | -------- | ------------ | ------------ |
| M0  | M0-project-scaffolding.md   | 7     | P0       | 1 session    | None         |
| M1  | M1-platform-abstraction.md  | 8     | P0       | 2 sessions   | M0           |
| M2  | M2-credential-management.md | 9     | P0       | 2.5 sessions | M1           |
| M3  | M3-account-identity.md      | 9     | P0       | 2 sessions   | M2           |
| M4  | M4-broker-sync.md           | 8     | P0       | 3.5 sessions | M2, M3       |
| M5  | M5-swap-quota-statusline.md | 9     | P0       | 3.5 sessions | M2-M4        |
| M6  | M6-session-management.md    | 6     | P0       | 2 sessions   | M2-M5        |
| M7  | M7-providers-cli.md         | 12    | P0       | 3 sessions   | M1, M2       |
| M8  | M8-daemon-core.md           | 11    | P1       | 6.5 sessions | M1-M5        |
| M9  | M9-oauth-flow.md            | 5     | P1       | 1 session    | M8           |
| M10 | M10-desktop-tauri.md        | 14    | P1       | 5 sessions   | M8, M9       |
| M5a | M5a-auto-rotation.md        | 3     | P2       | 1 session    | M8, M5       |
| M11 | M11-packaging.md            | 11    | P1/P2    | 5 sessions   | M8-M10       |

## Red Team Status

- Requirements review: PASS (all 123 scope matrix functions covered)
- Security review: PASS (IPC auth, CSP hardening, token zeroize, .gitignore, callback binding all addressed)
- Wire coverage: PASS (separate build/wire todos for account list, usage bars, token health, tray)
- Integration tests: covered in M1-08, M2-09, M4-08, M7-12, M8-11, M10-13, M11-11
