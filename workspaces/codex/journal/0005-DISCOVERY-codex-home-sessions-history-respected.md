---
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T05:50:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c00
session_turn: 22
project: codex
topic: OPEN-C02 RESOLVED — codex CLI 0.122.0 fully respects CODEX_HOME for sessions, shell snapshots, logs, and plugin state; zero bleed into ~/.codex during probe window
phase: analyze
tags: [codex, CODEX_HOME, isolation, OPEN-C02, pr-c00]
---

# Discovery — OPEN-C02: `codex` respects `CODEX_HOME` end-to-end

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` lists OPEN-C02 as a PR-gating precondition with a C-CR3 kill-switch: if `codex` writes sessions or history into the user's real `~/.codex/` despite `CODEX_HOME` being set, §5.7 live capture (journal 0008) is BLOCKED until a wrapper-script mitigation lands + pre-snapshot + diff-and-delete post-probe. That contingency is expensive; a positive resolution downgrades csq's per-slot isolation from "active post-probe cleanup" to "just set the env var."

## Probe

Environment: macOS 25.3.0 (Darwin), `codex-cli` 0.122.0 (`/opt/homebrew/bin/codex`).

Pre-probe: `~/.codex/` exists with 22 top-level entries (config.toml, auth.json, sessions/, shell_snapshots/, history.json, logs_2.sqlite, state_5.sqlite, memories/, .tmp/plugins/, …). Snapshot at `~/.codex.bak-1776836710/` via `rsync -a`.

Probe:

```
rm -rf /tmp/codex-probe && mkdir -p /tmp/codex-probe
CODEX_HOME=/tmp/codex-probe codex exec 'say only: hi'
```

(Access token was expired at probe time, so the WebSocket call to `wss://api.openai.com/v1/responses` returned 401 Unauthorized and retried five times before giving up. This had no bearing on the filesystem question; codex still bootstraps the CODEX_HOME tree before any network call.)

Post-probe inventory:

**`/tmp/codex-probe/` (the injected `CODEX_HOME`):**

| Path                                                                 | Written by probe?              |
| -------------------------------------------------------------------- | ------------------------------ |
| `sessions/2026/04/22/rollout-2026-04-22T13-49-11-019db3bc-…jsonl`    | YES                            |
| `shell_snapshots/019db3bc-3f35-7181-bc3b-c6f4be6aa73b.1776836951…sh` | YES                            |
| `logs_2.sqlite` + `-shm` + `-wal`                                    | YES                            |
| `installation_id`                                                    | YES                            |
| `.tmp/plugins/plugins/<plugin-name>/…`                               | YES (bootstrapped from global) |

**`~/.codex/` (the user's real home state), filtered to probe session_id `019db3bc` + filtered to mtime > 13:49:00:**

```
$ find ~/.codex -name '*019db3bc*'
(no results)
$ find ~/.codex -type f -newermt '2026-04-22 13:49:00'
(no results)
```

Cross-check with the `rsync` snapshot (`diff -rq ~/.codex ~/.codex.bak-…`) confirmed no new files under `~/.codex/sessions/`, `~/.codex/shell_snapshots/`, or `~/.codex/logs_*` that correspond to the probe session.

## Discovery

`codex-cli` 0.122.0 respects `CODEX_HOME` fully for:

- Session rollout files (`sessions/YYYY/MM/DD/rollout-*.jsonl`)
- Shell snapshots (`shell_snapshots/<session-id>.<ts>.sh`)
- Local SQLite logs (`logs_2.sqlite` + WAL)
- Installation identifier (`installation_id`)
- Plugin state bootstrap (`.tmp/plugins/`)

No writes to `~/.codex/` were observed during the probe window. The C-CR3 kill-switch does NOT fire.

## Why this matters

1. **csq's per-slot isolation is a single env-var away.** PR-C3 spawns `codex` with `CODEX_HOME=config-<N>/` and inherits clean isolation — no wrapper script, no pre-snapshot, no diff-and-delete. The plan's `Surface::Codex` handle-dir layout in spec 07 §7.2.3.1 (Codex) is empirically achievable on 0.122.0.

2. **§5.7 live capture (journal 0008) is unblocked on the filesystem side.** The last remaining blocker for §5.7 is authentication — the expired access_token + burned refresh_token state left by this session's OPEN-C04/05 probes requires user re-sign-in before a real `wham/usage` capture can happen.

3. **Plugin bootstrap is a hidden cost.** The probe caused codex to copy `.tmp/plugins/plugins/*` into /tmp/codex-probe (read from a system-level default location). Each fresh `CODEX_HOME` triggers this copy — ~20+ subdirs of plugin manifests + icons. For csq's handle-dir model where every `csq run N` creates `term-<pid>/`, this means a one-off plugin-tree copy per spawn. Acceptable (100s of KB, runs in parallel with network handshake), but worth measuring in PR-C3.

4. **AUTH path is separate from HOME path.** The probe read auth.json from `/tmp/codex-probe/auth.json` — which was EMPTY at probe start — yet codex still attempted refresh+call against the WebSocket. This means codex falls back to some other auth source (keychain? OPENAI_API_KEY env? or silently tolerates missing auth.json and issues unauthenticated requests that 401). This is a separate question from OPEN-C02 and should be probed in PR-C3 when auth plumbing is implemented. For now: NOT a blocker for isolation.

## Limits of this probe

- **codex-cli 0.122.0 specifically.** A future rev could reintroduce writes to `~/.codex/logs` or `~/.codex/state`. PR-C3's integration test must re-assert the invariant on every version bump.
- **Did not probe `codex login`.** `codex login` interactively sets up auth; that flow may write to `~/.codex/auth.json` regardless of `CODEX_HOME`. PR-C3 follows the plan's spec 07 §7.3.3 ordering (config.toml FIRST, then `CODEX_HOME=config-<N> codex login`) — relies on login respecting CODEX_HOME, which this probe did not exercise.
- **Did not probe long-running sessions.** Probe was ~30s (codex retried 5x before giving up on auth). A multi-hour session could write additional files elsewhere that this short probe didn't surface.
- **macOS APFS only.** ext4 behavior should match (codex is platform-agnostic re: filesystem), but not empirically confirmed.

## Decision impact

- **C-CR3 kill-switch does NOT fire.** PR-C5 (`wham/usage` capture) proceeds against `CODEX_HOME=/tmp/x` without additional mitigation beyond the existing snapshot discipline.
- **PR-C3 integration test retains the invariant.** The test case `codex_exec_writes_only_to_codex_home` gates every codex-cli version bump.
- **Spec 07 §7.7.2 status flip.** OPEN-C02 → RESOLVED POSITIVE with citation to this journal.

## For Discussion

1. **Plugin-tree copy on every handle-dir is a latency cost not accounted for in the daemon-architecture spec. Is it worth caching `.tmp/plugins/` at a shared location and symlinking into handle dirs, or does the per-spawn copy stay cheap enough (sub-100ms) to not warrant the optimisation?** The answer depends on actual `csq run N` frequency — a user who swaps slots 50x/day pays 50x the copy cost.

2. **The probe ran with auth.json missing entirely, and codex still tried to connect. Where did it pull credentials from?** (Possible: keychain, OPENAI_API_KEY env inherited from my shell, or it falls through to an anonymous call that 401s immediately.) This matters because if there's an invisible keychain leak, the "CODEX_HOME isolates everything" claim is weaker than it appears.

3. **If `CODEX_HOME` respect had NOT held (kill-switch fires), the cheapest mitigation was a wrapper script that symlinks `~/.codex/sessions` into the handle dir. Is that materially different from what csq already does for Claude Code handle dirs, or is it a new architecture that deserves its own spec?** (Current lean: it's the same pattern — spec 02 handle-dir model — so it would have been copy-paste, not new architecture.)

## Cross-references

- Spec 07 §7.2.3 (Codex layout, now unblocked for PR-C3) + §7.7.2 (OPEN-C02 status flipped by PR-C00)
- `workspaces/codex/02-plans/01-implementation-plan.md` §C-CR3 — kill-switch does not fire
- Journal 0004 — daemon pre-expiry refresh (auth plumbing; separate concern)
- Journal 0007 (this PR) — OPEN-C04 transport findings (explains why the probe's WebSocket was 401)
- Snapshot: `~/.codex.bak-1776836710/` (safety net from this session; user may clean)
