---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T12:30:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-13
session_turn: 45
project: csq-v2
topic: statusline-quota.sh was never deployed by install.sh or csq update install, leaving every handle-dir user showing term-<pid> instead of account email; also the shell script itself had hardcoded config-* pattern matching from pre-handle-dir era
phase: implement
tags: [alpha-13, statusline, install, handle-dir, script-delivery]
---

# 0048 — DISCOVERY — alpha.13 statusline script delivery gap

**Status**: Fixed in v2.0.0-alpha.13 (PRs #106 + #107).

## Finding

The `statusline-quota.sh` shell script had two classes of bug:

1. **Script content** (PR #106): `is_csq_terminal` only matched
   `config-*` paths; `get_claude_account` fallback parsed the dir
   basename instead of reading `.csq-account` marker; binary search
   order preferred a stale `~/.claude/accounts/csq` over PATH.

2. **Script delivery** (PR #107): neither `install.sh` nor
   `csq update install` ever deployed the script. Every machine kept
   whatever version was manually placed during initial setup. There
   was no mechanism to update it alongside the binary.

Additionally, `csq update install` from alpha.12 → alpha.13 runs
the alpha.12 binary (which lacks the deploy function added in
alpha.13), so the first upgrade is a chicken-and-egg gap requiring
one manual `curl` to bootstrap. All subsequent upgrades from
alpha.13+ will deploy the script automatically.

## For Discussion

1. The script-delivery gap existed since the handle-dir model shipped
   (PR #79). What category of artifact does this fall into — "should
   have been in the install.sh from the start" or "install.sh was
   correctly scoped to the binary and the script is a separate concern"?

2. The chicken-and-egg bootstrap gap on the first upgrade from
   alpha.12 → alpha.13 is inherent to any "the update code is in the
   new version" design. Tauri's updater avoids this because the OLD
   binary downloads and launches the NEW installer which runs NEW
   code. Should `csq update install` adopt a similar two-phase model,
   or is the one-time manual curl acceptable for a CLI tool?

3. Should the statusline script be embedded in the binary via
   `include_str!` and written on `csq install` / `csq doctor --fix`
   instead of fetched from GitHub? That would make the script
   version-locked to the binary and remove the network dependency.
