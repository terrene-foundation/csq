---
type: DISCOVERY
date: 2026-04-20
created_at: 2026-04-20T21:00:00+08:00
author: co-authored
session_id: 2026-04-20-alpha21-ship-and-statusline-cleanup
session_turn: 22
project: csq-v2
topic: csq install only rewrites global settings.json; per-slot statusLine outlives the shell wrapper it points at and silently wins precedence, blanking the statusline on every terminal bound to affected slots
phase: implement
tags:
  [
    statusline,
    csq-install,
    settings-precedence,
    per-slot-settings,
    shell-wrapper,
    handle-dir,
    materialization,
    alpha22-candidate,
  ]
---

# 0059 — DISCOVERY: `csq install` upgrade path leaves per-slot `statusLine` pointing at renamed shell wrapper

**Status:** Mitigated (manual fix applied this session). Root fix deferred to alpha.22.
**Severity:** P1 — user-visible on every terminal bound to an affected slot; easy to mistake for a csq binary failure.

## Context

User reported "csq 6 does not have statusline." Audit across all 10 configured slots found 8 broken (config-1 through 6, 9, 10) and 3 live handle dirs (term-13397, 14848, 35932) holding stale merged settings. Only 2 slots were healthy: config-7 (no per-slot `settings.json`, inherits global) and config-8 (has per-slot settings but no `statusLine` key, inherits global).

## Mechanism

1. A prior `csq install` wrote `statusLine.command = "bash ~/.claude/accounts/statusline-quota.sh"` into every per-slot `config-N/settings.json`.
2. A later `csq install` (run this session to resolve the "double ⚡csq prefix" bug) upgraded global `~/.claude/settings.json` to `statusLine.command = "csq statusline"` AND renamed the shell wrapper to `statusline-quota.sh.bak`.
3. The later install did NOT touch per-slot files. CC merges settings with per-slot winning over global for leaf fields, so the broken path from step 1 beats the working path from step 2.
4. Handle dirs (`term-<pid>/settings.json`) are materialized deep-merges of global + per-slot written at handle-dir creation time; they freeze whichever values were live when `csq run N` last ran. Live sessions started before the upgrade kept the bad path in their own materialized copy.

## Evidence

```
$ ls ~/.claude/accounts/ | grep statusline
statusline-quota.sh.bak        # renamed 18 Apr
# no statusline-quota.sh  -> command fails silently, CC shows no statusline

$ python3 -c "import json; print(json.load(open('~/.claude/settings.json')).get('statusLine'))"
{'command': 'csq statusline', 'type': 'command'}        # global is correct

$ cat ~/.claude/accounts/config-6/settings.json | jq .statusLine
{"type": "command", "command": "bash ~/.claude/accounts/statusline-quota.sh"}   # per-slot stale
```

## Fix applied this session

- Patched 8 affected `config-N/settings.json` files in place: rewrote `statusLine.command` to `csq statusline`, preserved every other field (permissions, plugins, effortLevel, feedbackSurveyState).
- Re-materialized 3 live handle-dir `settings.json` files (same field rewrite; `term-13397`, `term-14848`, `term-35932`).
- CC re-stats `settings.json` before each render (spec 01 §1.4), so no restart needed.

## Root fix (alpha.22 candidate)

`csq install` on upgrade MUST walk every `config-N/settings.json` and rewrite `statusLine.command` when it equals a known legacy wrapper path — not just update global. Similarly for any new/changed `statusLine` contract. Consider also: `csq run N` should re-materialize handle-dir settings on launch so stale merges can't survive a global upgrade (same root cause as the 17-handle-dir cleanup earlier this session).

## For Discussion

1. The per-slot settings were originally written by `csq install` on initial setup to pin `statusLine` on slots that existed before `csq install` learned how to patch global. Given that today's global already uses `csq statusline`, should `csq install` on upgrade DELETE the per-slot `statusLine` block entirely (so global inherits forever) rather than rewriting it? What permissions or plugin fields would that strip as a side effect?
2. If handle-dir `settings.json` were symlinks to per-slot `settings.json` (instead of materialized deep-merges), this bug would not exist — a per-slot rewrite would flow through the symlink automatically. Why did the handle-dir model choose materialized merges over symlinks? What breaks if we flip that now?
3. The session's previous "double ⚡csq prefix" fix and today's "account 6 has no statusline" are both symptoms of the same class of drift: upgrade paths that touch global but leave per-slot/materialized copies frozen. How many other csq-install-era fields are at risk of the same silent staleness, and is there a per-slot schema audit step worth adding to `csq upgrade`?
