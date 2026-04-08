---
type: DECISION
date: 2026-04-08
created_at: 2026-04-08T17:40:00+08:00
author: co-authored
session_id: unknown
session_turn: 140
project: claude-squad
topic: Three-layer defense against the "residual race" from 0018 — widen the refresh window, add broker recovery from live siblings, and run the broker synchronously on csq run with abort-on-failure
phase: implement
tags: [oauth, broker, recovery, defense-in-depth, decision, architecture]
---

## Context

Journal 0018 shipped the broker (Option C) and listed the "residual race"
as an acknowledged edge case: CC's own refresh path can still win against
the broker if the broker hasn't fired recently enough. Empirically this
turns out not to be an edge case — it's the dominant failure mode when
running 3+ concurrent terminals on the same account.

Observed on 2026-04-08 with 3 terminals on account 7:

- `credentials/7.json` mtime stuck at 08:42 (morning login) despite ~8
  hours of account activity, meaning the broker had NOT successfully
  updated canonical all day.
- A `7.refresh-lock` file timestamped 17:05 proved `broker_check` HAD
  fired inside that window, acquired the lock, and released it without
  updating canonical.
- The only way that can happen is `refresh_token()` returning `None` —
  Anthropic 401'd the refresh token in canonical because CC's own refresh
  path had rotated it out from under us at some earlier point.
- Once canonical holds a dead RT, every subsequent `broker_check` retries
  the same dead RT and fails the same way. **Canonical is stuck forever**,
  until the user runs `csq login N`. Any new `csq run 7` copies the dead
  canonical into the new config dir → first API call 401 → "Please run
  /login". This is the "the 3rd terminal hits login" symptom the user
  reported.

0018's backsync marker-fallback is supposed to heal canonical from a
terminal holding the rotated RT, but it only fires from whichever
terminal's statusline renders next. If that terminal's CC has since
refreshed AGAIN and rotated to yet another RT, canonical is frozen with
a dead RT and no live sibling can help — unless we actively try them.

## Decision

Ship three layers in one PR. Each addresses a distinct failure mode;
together they close the race at the design level.

| Layer | Change                                                                                                                                                                                                                                                      | Failure mode covered                                                                                                                                                                                |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | `REFRESH_AHEAD_SECS`: 600 → 7200 (10 min → 2 hours)                                                                                                                                                                                                         | Makes the race _rare_: broker fires from any terminal render inside a 2-hour pre-expiry window, so CC almost never sees an expired token first                                                      |
| **4** | `_broker_recover_from_live()`: when the primary refresh 401s, promote each live sibling's RT into canonical and retry under the same per-account lock                                                                                                       | Heals dead canonicals _automatically_ when the race does happen. No more `csq login N` for the residual race                                                                                        |
| **2** | `csq run N`: write `.csq-account` marker first, then call `rotation-engine.py broker` synchronously. If broker returns exit 2 (both primary AND recovery failed), abort with `account N's refresh token is dead — run: csq login N` before ever exec'ing CC | Prevents a new terminal from inheriting a genuinely unrecoverable canonical. Also makes the failure visible at a natural human-intervention point instead of 30 seconds into a confusing CC session |

Plus a visibility mechanism for Layer 1 being insufficient: when the
broker exhausts both primary and recovery paths, it touches
`credentials/N.broker-failed`. The `statusline` subcommand prepends
`⚠LOGIN-NEEDED ` to the account display while the flag exists, so a
silent broker failure can't go unnoticed for more than one CC render.
The flag is cleared automatically on the next successful refresh.

**Rationale for the order**:

- **Layer 1 alone** reduces the probability of dead canonicals but does
  nothing to recover existing ones. The user's current state is proof
  that once canonical is dead, nothing fixes it but manual `csq login`.
- **Layer 4 alone** fixes the recovery path but still lets the race
  happen in the first place — every race is a latency spike while the
  recovery iterates through siblings. Better to prevent most races.
- **Layer 2 alone** only helps new terminals, not running ones.
- **All three together**: race is rare (1), recoverable when it happens
  (4), and new terminals are guaranteed to start fresh (2). Each layer
  is bounded in scope; they don't interact in tricky ways.

## Implementation details

### Layer 1

One-line constant change plus a multi-line comment explaining the
thinking. ~25% more Anthropic `/v1/oauth/token` calls/day (now ~1 every
6 hours instead of ~1 every 7h50m per account). Anthropic does not
rate-limit at that volume.

### Layer 4

New helpers in `rotation-engine.py`:

- `_broker_failure_flag(account_num)` → path to `credentials/N.broker-failed`
- `_broker_mark_failed(account_num)` / `_broker_mark_recovered(account_num)`
- `_broker_recover_from_live(account_num, dead_canonical_content)`

`broker_check()` now:

1. Tries the primary refresh (unchanged).
2. If it fails, calls `_broker_recover_from_live` under the same lock.
3. On any success, calls `_broker_mark_recovered`.
4. On total failure, calls `_broker_mark_failed` and returns 2.
5. Otherwise returns 0.

The recovery helper iterates live config dirs, promotes each distinct
live RT into canonical atomically, and retries `refresh_token`. It tracks
tried RTs so duplicates (e.g., two siblings with the same token) don't
double-spend. If every candidate fails, it rolls canonical back to the
original dead content so the next `broker_check` starts from a
predictable baseline instead of retrying whichever candidate was tried
last.

The `broker` subcommand dispatch propagates the return value via
`sys.exit(rc)`. The `sync` subcommand (called from the statusline hook
in the background) ignores the exit code.

### Layer 2

`csq run` reordered:

```
OLD: cred copy → marker write → exec
NEW: marker write → broker (synchronous) → cred copy → exec
```

Common case cost measured on live system: **116 ms total** (canonical
fresh → early-return). Only pays the ~1-2 s Anthropic round-trip when
canonical actually needs a refresh.

### Tests

`test-broker-recovery.py` (new, POSIX-only via `multiprocessing.fork`):

1. **Recovery success**: canonical holds dead RT; 3 siblings (one holds
   the live rotated RT, one holds the dead RT, one holds a different
   dead RT). Assert: recovery promotes the live RT, refresh succeeds,
   canonical holds recovered tokens, fanout reaches all 3 siblings,
   flag absent.
2. **Recovery failure**: canonical and every sibling hold different
   dead RTs. Assert: exit code 2, flag touched, canonical rolled back
   to original dead content.
3. **Flag clearance**: a pre-existing broker-failed flag is cleared
   by the next successful refresh.

Existing tests still pass unchanged:

- `test-platform.sh`: 20/20
- `test-broker-concurrent.py`: 2/5/10 concurrent subprocesses + pullsync

## Consequences

- The user should no longer see `csq login 7` required during normal
  multi-terminal work. If they do, the `⚠LOGIN-NEEDED` prefix will be
  visible in the statusline on the very next render.
- The `csq run` abort gives a clear, actionable error when recovery
  genuinely cannot heal canonical (e.g., the user deleted
  `credentials/N.json` mid-session). No more "why did CC die with a
  401?" confusion.
- Recovery is bounded: at most one Anthropic call per live sibling, all
  under the per-account lock. On a 15-terminal system with ~3 siblings
  per account, worst-case recovery does 3 failed refreshes + 1 success
  = ~2 s under the lock. Acceptable.
- The residual race from 0018 is now a recoverable event, not a
  dead-end. 0018's "For Discussion #1" (all-terminals-idle edge case)
  is also mitigated: with a 2-hour window, any active terminal in the
  last 2 hours fires the broker well before expiry.

## Alternatives Considered

1. **Layer 1 alone** — rejected: does not heal existing dead canonicals,
   and the user is already in that state.
2. **Layer 4 alone** — rejected: still lets the race happen constantly,
   costing latency spikes on recovery.
3. **Daemon process holding the broker continuously** — rejected again
   (see 0018). The per-terminal statusline invocation plus the 2-hour
   window is sufficient and keeps the stdlib-only, no-long-running-
   processes design intact.
4. **Refactor `refresh_token` to accept an explicit RT parameter** —
   rejected in favour of promoting-then-retrying against canonical,
   which keeps the diff smaller and preserves the single-source-of-truth
   property of canonical.

## For Discussion

1. The recovery helper iterates live siblings in whatever order
   `Path.iterdir()` returns — typically unsorted on macOS. If two
   siblings hold _different_ valid RTs (two legitimate OAuth sessions
   for the same account, which shouldn't normally happen), recovery
   picks whichever iterator sees first and rotates that one. The
   "losing" session then has a dead RT and will need its own recovery
   pass. Is that acceptable, or should recovery prefer the sibling
   with the strictly-newest `expiresAt`?

2. The `⚠LOGIN-NEEDED` prefix is visible in the statusline but not
   intrusive enough to block CC. Should we add a secondary trigger
   (e.g., an explicit `csq status` warning line, or a PreToolUse hook
   that blocks on the flag) for users who don't actively watch the
   statusline?

3. `REFRESH_AHEAD_SECS = 7200` assumes ~8-hour token lifetime. If
   Anthropic silently reduces token lifetime (e.g., to 4 hours), the
   window becomes "refresh immediately on every render" — wasteful but
   not broken. Should the constant be computed as a fraction of
   observed lifetime (e.g., `expires_in / 4`) instead of a fixed value?
