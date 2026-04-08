---
type: DECISION
date: 2026-04-08
created_at: 2026-04-08T15:00:00+08:00
author: co-authored
session_id: unknown
session_turn: 80
project: claude-squad
topic: Build pullsync (Option A) + broker (Option C) instead of per-slot OAuth sessions (Option B), to solve multi-terminal-same-account without forcing K browser logins per account
phase: implement
tags: [oauth, broker, pullsync, multi-terminal, decision, architecture]
---

## Context

User constraint: ~15 terminals across 7 accounts, ~5 concurrent terminals per account on average (3 accounts are usually at max quota, so effective concurrency is higher on the active 4). The original csq data model assumed 1 OAuth session per account. Anthropic rotates the refresh token on some refreshes, which invalidates the previous token for the other N-1 terminals sharing the same session → 401 → forced re-login.

Three fixes were considered:

| Option       | How it works                                         | Logins per account               | Race elimination | Code change |
| ------------ | ---------------------------------------------------- | -------------------------------- | ---------------- | ----------- |
| A (pullsync) | Live ← canonical when canonical is newer             | 1                                | partial          | ~50 lines   |
| B (slots)    | N OAuth sessions per account, `credentials/N-K.json` | K (5 browser logins per account) | full             | ~300 lines  |
| C (broker)   | csq is the sole refresher, per-account lock + fanout | 1                                | near-full        | ~150 lines  |

## Decision

Build **A + C**. Drop B entirely.

**Rationale**:

- **B was rejected** because the UX is stupid: "5 terminals on account 2, need to swap them all to account 1, do I have to `csq login 1` five times?" (user's exact objection). Five browser flows per account is worse than the problem being solved.
- **C dominates B** on both dimensions: 1 login per account (same as A) AND full race elimination (same as B). B's only advantage was independence between sessions, but C achieves that by being the sole refresher — all sessions share one token but only csq touches Anthropic's endpoint.
- **A is shipped first** because it's the cheapest incremental win. Pullsync alone closes the propagation gap (when one terminal refreshes, others pick up the new tokens on their next render). It's not sufficient on its own (doesn't prevent the refresh race itself), but it's a prerequisite for C's fanout and it ships immediately.
- **C closes the remaining gap**: the broker holds a per-account `credentials/N.refresh-lock` (non-blocking try-lock). Only one terminal per account ever calls `/v1/oauth/token` per refresh cycle. After refresh, it fans out the new tokens to every `config-X/.credentials.json` where marker=N.

## Consequences

- `credentials/N.json` remains a single file per account — no migration, no schema change, fully backwards-compatible with earlier csq versions.
- CC's own refresh path is almost never triggered because the broker keeps the access token fresh ahead of expiry (refreshes at `expiresAt - 10 min`, gets ~60 min back from Anthropic).
- The residual race: CC gets a 401 mid-API-call because Anthropic invalidated the token for a reason the broker can't anticipate (server-side policy event). CC's own 401 retry path re-reads `.credentials.json` from disk — and the broker keeps that file fresh via fanout, so recovery works.
- The broker's correctness is now provable by automated subprocess test (`test-broker-concurrent.py`): 2, 5, and 10 concurrent subprocesses all fire `broker_check()`, exactly 1 wins the lock and refreshes, the rest skip, every config dir receives the fanout.

## Alternatives Considered

1. **B (per-slot OAuth)** — rejected for UX reasons above.
2. **Status quo + accept 401 interruptions** — rejected because user explicitly has 5+ concurrent terminals per account as a constraint, not an exception.
3. **API keys instead of OAuth** — rejected because the user is on Pro/Max subscriptions and API keys bill differently.
4. **Move OAuth into a daemon process** — rejected because csq is designed as stdlib-only, no long-running processes.

## For Discussion

1. The broker refreshes at `expiresAt - 10 min`. If a terminal is completely idle (no statusline renders) for more than 10 min, the broker never fires from that terminal. An active terminal on the same account will still cover the refresh via fanout — but if ALL terminals on an account go idle, the token eventually expires and CC's own refresh fires on the next prompt. Is that acceptable, or should we add a background daemon?

2. `test-broker-concurrent.py` uses `multiprocessing` with `fork` start method. On Windows, `fork` isn't available and the test would need `spawn`, which reimports the module and loses the monkey-patch. The test is currently POSIX-only. Should we add a Windows variant that uses a subprocess command wrapper instead?

3. The broker's fanout writes `.credentials.json` in every matching config dir, but doesn't update any `.quota-cursor` or trigger a quota refresh. Is there a scenario where the fanout write invalidates a stored quota value? (I don't think so — the quota cursor is about stale rate_limits from swaps, not about token lifetime.)
