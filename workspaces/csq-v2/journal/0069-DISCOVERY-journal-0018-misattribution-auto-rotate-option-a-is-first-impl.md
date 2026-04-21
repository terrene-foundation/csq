---
name: Journal 0018 misattribution; auto-rotate Option A is first implementation
description: Audit of journal 0064 §For Discussion Q1 claim — journal 0018 is about tray quick-swap, not auto-rotation; PR-A1 is the first handle-dir-native rotator
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T17:45:00Z
author: co-authored
session_id: post-v2.0.0-planning
session_turn: 10
project: csq
topic: pre-work audit for PR-A1 (P0-1 auto-rotate Option A)
phase: analyze
tags: [pre-work, auto-rotate, PR-A1, v2.0.1, journal-audit]
---

# Journal 0018 Audit — It Is Not About Auto-Rotation

Pre-work for PR-A1 (v2.0.1 patch — auto-rotate Option A structural fix). Journal 0064 §For Discussion Q1 stated:

> journal 0018 said "auto-rotation picks the handle dir, not the config dir"

Audit finds this statement **incorrect**. Journal 0018 is about a different subsystem entirely.

## What journal 0018 actually says

`workspaces/csq-v2/journal/0018-DECISION-tray-swap-single-most-recent-dir.md` — title: "Tray quick-swap retargets ONE config dir, chosen by `.credentials.json` mtime."

Scope: **tray click behaviour**. Specifically, when a user clicks a tray menu row to swap the active account, which `config-*` directory gets retargeted. The decision: retarget one dir, chosen by credentials.json mtime as the "most recently exercised session" signal.

0018 makes no statement about auto-rotation. It does not mention `auto_rotate.rs`, `tick()`, `pick_best`, `find_target`, or the rotation cooldown. Its entire scope is `handle_tray_event` in the desktop codebase.

## What the live auto-rotate code does

`csq-core/src/daemon/auto_rotate.rs` (current state on `main` at `b87a744`):

- Line 108: `pub(crate) fn tick(base_dir: &Path, cooldowns: &mut HashMap<PathBuf, Instant>)`
- Line 124-142: **v2.0.0 handle-dir-present guard** — refuses to run if any `term-*/` handle dir exists (journal 0064 P0-1 Option B gate-off)
- Line 147: `let entries = match std::fs::read_dir(base_dir) ...`
- Line 158-168: iterates directory entries, filters to `config-*`
- Line 174: reads `.csq-account` marker from the config dir
- Line 184-194: per-config-dir cooldown
- Line 243: `swap_to(base_dir, &config_dir, target)` — calls the legacy path that writes into `config-N`

The rotator has always operated on `config-*` dirs. It has never operated on `term-*` handle dirs. There is no record in `git log --follow csq-core/src/daemon/auto_rotate.rs` of a revert from a handle-dir-aware implementation.

## Implication for PR-A1

**PR-A1 is the first implementation** of handle-dir-native auto-rotation, not a revert or re-implementation of a prior decision. Journal 0064 §For Discussion Q1's concern about "a never-landed design" is resolved — there was no prior design to land.

The surface filter stub (Surface::ClaudeCode-only per journal 0067 H3) is therefore a forward-looking addition for Codex PR-C1 to flip, not a carry-over of anything 0018 specified.

## Consequences

- PR-A1 description does NOT need to cite a revert rationale.
- PR-A1 description SHOULD cite this journal as the audit closing journal 0064's outstanding For Discussion question.
- Journal 0064 §For Discussion Q1 can be marked resolved via this entry.
- Spec 02 §2.6 update in PR-A1 describes the rotator walk as "first introduction of handle-dir-native rotation."

## For Discussion

1. Journal 0064's misattribution was written during the v2.0.0 ship in a session under time pressure (it surfaced auto-rotate as a P0 discovery and routed to Option B gate-off within hours). Is there a process adjustment — e.g. spec-authority cross-check during journal writes — that would have caught "I think 0018 said X about auto-rotate" before it hit the discussion section? Or is this an acceptable failure rate for discovery-phase journals where speed is more important than citation precision?

2. If PR-A1 is the first implementation of handle-dir-native auto-rotation, then the rotator's end-to-end correctness has never been validated in production — v2.0.0 gates it off entirely. PR-A1 ships a brand-new code path whose first exposure to real users is the v2.0.1 release. Does PR-VP-final's two-agent redteam adequately cover this, or does the rotator warrant additional scrutiny such as a third agent specifically attacking it?

3. Journal 0018's tray behaviour (retarget ONE config dir by credentials.json mtime) is itself due for a revisit under the handle-dir model — tray clicks should repoint `term-<pid>` symlinks, not `config-N/.credentials.json`. Is that a v2.0.1 item (currently absent from the backlog) or does it land with Codex PR-C7's swap surface work in v2.1?
