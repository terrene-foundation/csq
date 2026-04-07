---
type: DECISION
date: 2026-04-03
created_at: 2026-04-03T10:30:00+08:00
author: co-authored
session_id: null
session_turn: 50
project: claude-squad
topic: CLAUDE_CONFIG_DIR per-terminal isolation replaces shared keychain
phase: implement
tags: [claude-squad, architecture, CLAUDE_CONFIG_DIR, keychain, isolation]
---

# Decision: CLAUDE_CONFIG_DIR Per-Terminal Isolation

## Choice

Use `CLAUDE_CONFIG_DIR` per account instead of shared macOS Keychain for multi-account rotation.

## Alternatives Considered

1. **Shared keychain + per-terminal assignments** (original) — Failed. Keychain is a global singleton; every write broadcasts to all Claude Code instances via `.credentials.json` touch. Assignment tracking was fiction.
2. **Fleet model** (all terminals on one account) — Worked but limited. Auto-rotation swapped everyone simultaneously. Post-limit recovery impossible (Claude Code caches rate limit locally).
3. **`CLAUDE_CODE_OAUTH_REFRESH_TOKEN` env var** — Only works for `-p` (programmatic) mode, not interactive sessions.
4. **`CLAUDE_CONFIG_DIR` per account** (chosen) — Each terminal gets isolated credentials via file. Shared state (projects, plugins, settings) symlinked to `~/.claude/`. Mid-session rotation by overwriting `.credentials.json`.

## Rationale

`CLAUDE_CONFIG_DIR` is the only mechanism that gives true per-terminal credential isolation while maintaining shared project context. The key insight: Claude Code reads credentials from `.credentials.json` in the config dir, completely bypassing the keychain.

## Consequences

- Must re-login all accounts with `ccc login N` (runs `claude auth login` inside config dir)
- `ccc N` launches terminals (not plain `claude`)
- Polling inactive accounts only gets 5h data (binary allowed/rejected), not 7d percentages
- 7d "all models" limit is invisible to polling; `blocked.json` catches it reactively

## For Discussion

1. If Claude Code changes how `CLAUDE_CONFIG_DIR` handles credential files, would the symlink approach break?
2. Given that `-p` mode doesn't report 7d data, is there value in maintaining a longer polling interval to reduce API costs?
3. If the user has 15+ terminals but only 7 accounts, how should `ccc` distribute accounts across terminals?
