# M5a: Auto-Rotation (Pre-emptive)

Priority: P2 (Future)
Effort: 1 autonomous session
Dependencies: M8 (Daemon Core), M5-03 (pick_best)
Phase: Post-launch

---

## M5a-01: Build auto-rotation daemon loop

Per GAP-6 resolution: every 30s, check each active terminal. Trigger when 5h usage >= threshold (default 95%) AND a better account exists AND terminal is idle AND cooldown elapsed (5 minutes). Uses `pick_best()` to select target account.

- Scope: 4.4 (enhanced), GAP-6
- Complexity: Moderate
- Acceptance:
  - [x] Rotates when threshold exceeded
  - [x] Does NOT rotate when no better account available
  - [x] Does NOT rotate during active CC response
  - [x] Cooldown prevents thrashing
  - [x] Per-terminal (not per-account)

## M5a-02: Build auto-rotation config

Store in `~/.claude/accounts/rotation.json`. Fields: `enabled` (default false), `threshold_percent` (default 95), `cooldown_secs` (default 300), `exclude_accounts` (default []). CLI: `csq config set auto_rotate.enabled true`.

- Scope: GAP-6
- Complexity: Trivial
- Acceptance:
  - [x] Config file created on first use
  - [x] CLI can read/write config
  - [x] Excluded accounts never rotated TO

## M5a-03: Build CLI fallback auto-rotation

Without daemon: auto-rotation runs synchronously during statusline hook (like v1.x `auto_rotate()` with `--force`). Same conditions, runs at most once per statusline render.

- Scope: 4.4
- Complexity: Moderate
- Depends: M5a-01
- Acceptance:
  - [x] Works without daemon
  - [x] At most once per render (no repeated swaps)
