# M6: Session Management (csq run)

Priority: P0 (Launch Blocker)
Effort: 2 autonomous sessions
Dependencies: M2-M5 (all core logic)
Phase: 2, Stream 2

---

## M6-01: Build config dir isolation (symlinks)

Symlink shared artifacts from `~/.claude` into `config-N/`: history, sessions, commands, skills, agents, rules, etc. Isolate: `.credentials.json`, `.current-account`, `.csq-account`, `.live-pid`, `.claude.json`, `accounts`, `settings.json`, `.quota-cursor`.

- Scope: 11.3
- Complexity: Complex
- Acceptance:
  - [x] Shared items are symlinks (not copies)
  - [x] Isolated items are per-terminal copies
  - [x] Existing symlinks: recreated if target changed
  - [x] Missing `~/.claude` dirs: created on demand

## M6-02: Build Windows junction support

Windows: use `mklink /J` for directory junctions (no admin required). Fall back to copy if junctions fail. Files use hardlinks or copies.

- Scope: 11.4 (Windows variant)
- Complexity: Moderate
- Acceptance:
  - [ ] Windows: junctions created for directories
  - [ ] Fallback to copy on junction failure
  - [ ] No admin elevation required

## M6-03: Build settings deep merge

Build per-terminal `settings.json` from default + optional profile overlay. Deep merge: overlay keys override, nested dicts merged recursively, arrays replaced (not appended). Supports truncated JSON auto-repair.

- Scope: 11.4
- Complexity: Moderate
- Acceptance:
  - [x] Overlay keys override defaults
  - [x] Nested objects merged recursively
  - [x] Truncated JSON repaired before merge

## M6-04: Build onboarding flag + credential copy

Set `hasCompletedOnboarding=true` in `.claude.json` (skip CC's setup wizard). Atomic copy from `credentials/N.json` to `config-N/.credentials.json`. Remove stale `.live-pid` from prior CC process.

- Scope: 11.5, 11.7, 11.11
- Complexity: Trivial
- Acceptance:
  - [x] `.claude.json` updated without corrupting other fields
  - [x] Credential copy is atomic
  - [x] Stale `.live-pid` removed

## M6-05: Build csq run command (full)

Account auto-resolution: 0 accounts -> vanilla `claude`. 1 account -> uses it. 2+ -> error requiring explicit N. Profile overlay support (`--profile`/`-p`). Profile auth detection (skips OAuth creds if profile provides own key). Synchronous broker refresh before copy. Env stripping (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`). Pass-through claude args. `exec()` on Unix, `spawn+wait` on Windows.

- Scope: 11.1-11.9
- Complexity: Complex (assembly of M6-01 through M6-04)
- Depends: M6-01, M6-03, M6-04, M4-01
- Acceptance:
  - [x] 0 accounts: launches vanilla `claude`
  - [x] 1 account: uses it without argument
  - [x] 2+ accounts without N: error with account list
  - [x] Profile with own auth: OAuth creds skipped
  - [x] Broker called before credential copy
  - [x] Dead token: clear error message, does not launch CC
  - [x] `csq run 1 --resume`: passes `--resume` to claude
  - [x] Env vars stripped before exec

## M6-06: Wire csq run to daemon

When daemon is running, `csq run` notifies it of the new session start (so the daemon can track active terminals). Falls back to synchronous broker if daemon unreachable.

- Scope: 11.6 + daemon integration
- Complexity: Trivial
- Depends: M8 (Daemon Core)
- Acceptance:
  - [x] Daemon running: IPC notification sent
  - [x] Daemon not running: silent fallback to synchronous broker
