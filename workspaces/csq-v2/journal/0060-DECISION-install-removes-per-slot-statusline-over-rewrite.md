---
type: DECISION
date: 2026-04-21
created_at: 2026-04-21T23:30:00+08:00
author: co-authored
session_id: 2026-04-21-alpha22-fixes
session_turn: 14
project: csq-v2
topic: on csq install upgrade, per-slot settings.json with a legacy statusLine wrapper has its statusLine key removed (not rewritten) so global cascades forever and future statusline contract changes don't require another per-slot walk
phase: implement
tags:
  [
    statusline,
    csq-install,
    settings-precedence,
    per-slot-settings,
    migration,
    alpha22,
  ]
---

# 0060 — DECISION: `csq install` removes per-slot `statusLine` over rewriting

**Follows:** journal 0059 (DISCOVERY — the stale-per-slot-statusline bug).
**Scope:** `csq-cli/src/commands/install.rs` — new `migrate_per_slot_statuslines` step landed in alpha.22.

## Context

Journal 0059 identified that a prior `csq install` wrote `statusLine.command = "bash ~/.claude/accounts/statusline-quota.sh"` into per-slot `config-<N>/settings.json` files, and subsequent upgrades that only touched global `~/.claude/settings.json` left 8 of 10 slots with a statusline pointing at a renamed (non-existent) shell wrapper. CC merges settings with per-slot winning over global, so the global fix had no effect on those slots. The journal posed the question: on upgrade, should csq _rewrite_ the per-slot value to `csq statusline`, or _remove_ the per-slot `statusLine` key entirely so the global cascade applies?

## Decision

**Remove the per-slot `statusLine` key** when the command matches a known v1.x wrapper (`statusline-quota.sh` or `statusline-command.sh`). Leave every other field in `config-<N>/settings.json` untouched (permissions, plugins, effortLevel, etc.). Leave per-slot settings with `csq statusline` alone (no-op). Leave user-custom commands alone (preserve customisation).

## Alternatives considered

1. **Rewrite** the per-slot `statusLine.command` to `csq statusline`. Short-term equivalent behaviour; long-term every future statusline contract change requires another per-slot walk, and every slot ends up with a redundant copy of whatever global says.
2. **Delete the whole per-slot `settings.json`** when the legacy wrapper is detected. Would clear the statusline drift but destroys unrelated per-slot customisation (permissions, plugins). Unacceptable — journal 0059 explicitly notes these fields must survive.
3. **Symlink handle-dir settings to per-slot settings** (raised in 0059 "For Discussion" item 2). Structural fix that would eliminate this class of drift entirely, but requires reworking the handle-dir materialization model — deferred as a larger spec-level change.

## Rationale for removal

- `statusLine` in per-slot `settings.json` was only ever written by a much earlier csq installer, before csq learned to patch global. The per-slot override serves no user-facing purpose today.
- Global already has `csq statusline`. Removing the per-slot key lets every future global update flow through without touching per-slot files.
- Smaller blast radius than rewrite: rewrite silently keeps the per-slot block alive as a shadow value that a future bug could drift again. Remove makes the per-slot file clean and lets CC's merge rules do the right thing from now on.
- User customisation is still preserved — a command that doesn't contain `statusline-quota.sh` or `statusline-command.sh` is untouched. A user who deliberately overrode statusline per-slot keeps their override.

## Consequences

- Fresh `csq install` on a machine with legacy per-slot statuslines logs: `✓ Cleared stale per-slot statusLine on slot(s): 1, 3, 6, ...`
- Test coverage: 9 new unit tests in `csq-cli/src/commands/install.rs::tests` — strip-legacy / preserve-csq / preserve-custom / handle-none / skip-unparseable / skip-handle-dirs / empty-base-dir / sorted-output / legacy-wrapper-detection.
- Handle-dir materialization is NOT fixed by this change. If a live `term-<pid>/settings.json` was materialized before the `csq install` upgrade, it still carries the stale statusline. Journal 0059's second outstanding item (re-materialize handle-dir settings on `csq run`) remains open.
- If a future csq contract adds a new key like `statusLine.args`, it should live in global only — per-slot files should never carry it. This decision codifies that direction.

## For Discussion

1. The chosen detection is a substring match on two filenames (`statusline-quota.sh`, `statusline-command.sh`). Is substring matching the right granularity — or should we instead detect "command references a file that no longer exists" by actually resolving the path? The former catches renamed/backup variants (`statusline-quota.sh.bak`) without extra logic; the latter would accidentally strip a valid user command whose target binary happens to be missing at install time. Which failure mode is worse?
2. If csq had adopted the symlinked handle-dir model (0059 For-Discussion #2) before this class of bug surfaced, both the fresh-install statusline-pinning AND the upgrade-drift problem would have been structural non-issues. Does that make symlinking the correct endgame, with this per-slot migration as a temporary bandage until the handle-dir spec is revised?
3. The same upgrade-path drift affects any per-slot leaf field csq might write in the future. Should `csq install` grow a generic "per-slot drift audit" step that enumerates every csq-owned key and verifies its value matches global, rather than one migration function per field? What keys beyond `statusLine` are at risk today?
