# csq v2.0 — Todo Index

112 tasks across 13 milestones (M0–M11 + M5a). Covers the full Rust+Tauri rewrite from scaffolding through packaging.

## Status (2026-04-28 close-out)

csq is shipped at v2.3.1. The 14 milestone todos in this workspace covered the original v2.0 build plan; bookkeeping below was reconciled against current production code (SWEEP-2026-04-28 LOW-01).

| State            | Count | Location                         |
| ---------------- | ----- | -------------------------------- |
| Completed        | 12    | `completed/M0..M10, M5a`         |
| Active (partial) | 1     | `active/M11-packaging.md`        |
| Index            | 1     | `active/00-index.md` (this file) |

**M11 outstanding** (see `active/M11-packaging.md` STATUS UPDATE block): Apple Developer ID notarization (M11-01), Windows Authenticode (M11-02), Homebrew tap (M11-03), Scoop manifest (M11-04), and cross-platform smoke sign-off (M11-11). All other M11 items shipped. None block shipped functionality — users install via `install.sh` (CLI) or download desktop bundles directly from Releases.

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

State as of 2026-04-28: completed/ for shipped, active/ for outstanding.

| #   | File                        | Tasks | Priority | State                       |
| --- | --------------------------- | ----- | -------- | --------------------------- |
| M0  | M0-project-scaffolding.md   | 7     | P0       | completed/                  |
| M1  | M1-platform-abstraction.md  | 8     | P0       | completed/                  |
| M2  | M2-credential-management.md | 9     | P0       | completed/                  |
| M3  | M3-account-identity.md      | 9     | P0       | completed/                  |
| M4  | M4-broker-sync.md           | 8     | P0       | completed/                  |
| M5  | M5-swap-quota-statusline.md | 9     | P0       | completed/                  |
| M6  | M6-session-management.md    | 6     | P0       | completed/                  |
| M7  | M7-providers-cli.md         | 12    | P0       | completed/                  |
| M8  | M8-daemon-core.md           | 11    | P1       | completed/                  |
| M9  | M9-oauth-flow.md            | 5     | P1       | completed/                  |
| M10 | M10-desktop-tauri.md        | 14    | P1       | completed/                  |
| M5a | M5a-auto-rotation.md        | 3     | P2       | completed/                  |
| M11 | M11-packaging.md            | 11    | P1/P2    | active/ — partial (6 of 11) |

## Red Team Status

- Requirements review: PASS (all 123 scope matrix functions covered)
- Security review: PASS (IPC auth, CSP hardening, token zeroize, .gitignore, callback binding all addressed)
- Wire coverage: PASS (separate build/wire todos for account list, usage bars, token health, tray)
- Integration tests: covered in M1-08, M2-09, M4-08, M7-12, M8-11, M10-13, M11-11
