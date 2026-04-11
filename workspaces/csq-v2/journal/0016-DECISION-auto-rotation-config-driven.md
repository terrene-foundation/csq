---
type: DECISION
date: 2026-04-11
created_at: 2026-04-11T15:35:00+08:00
author: agent
session_id: session-2026-04-11b
session_turn: 82
project: csq-v2
topic: Auto-rotation is config-driven, disabled by default, rotates all config dirs
phase: implement
tags: [auto-rotation, m5a, daemon, rotation]
---

# DECISION: Auto-rotation rotates all config dirs, not just idle ones

## Choice

The M5a auto-rotation daemon loop (`daemon/auto_rotate.rs`) rotates ALL config dirs whose account exceeds the quota threshold. It does not check whether the CC process is actively generating.

## Alternatives Considered

1. **Rotate only idle terminals** — check `/proc/{pid}/status` or similar to detect active generation. Rejected: platform-specific, complex, and `swap_to` is already atomic (CC picks up new token on next API call).
2. **Rotate all config dirs** (chosen) — simpler, safe because swap is atomic. CC reads `.credentials.json` on each API call and seamlessly uses the new token.

## Design Details

- **Config**: `rotation.json` with `enabled` (default: false), `threshold_percent` (default: 95), `cooldown_secs` (default: 300), `exclude_accounts` (default: [])
- **Interval**: 30s tick, 15s startup delay (lets poller populate quota first)
- **Cooldown**: per config-dir, not per-account (prevents re-rotating the same session)
- **Config reload**: fresh `rotation.json` read on every tick (live config without daemon restart)

## Consequences

- Users must explicitly enable auto-rotation (`rotation.json` → `enabled: true`)
- A terminal mid-generation gets swapped atomically — no corruption, but the response may split across two accounts' quota
- The 5-minute cooldown prevents thrashing when multiple accounts are near threshold

## For Discussion

1. Should the cooldown be per-config-dir (current) or per-account? Per-account would prevent rotating the same account across different terminals simultaneously.
2. If a user has 3 terminals on account 1 and all hit 95%, should all 3 rotate to account 2, or should they spread across accounts 2, 3, 4?
