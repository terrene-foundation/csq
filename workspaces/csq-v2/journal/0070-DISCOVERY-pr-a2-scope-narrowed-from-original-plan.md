---
name: PR-A2 scope narrowed — create_handle_dir already calls materialize
description: Investigation found that materialize_handle_settings is already called inside create_handle_dir; original PR-A2 plan described a missing step that was never missing. Narrow fix delivered.
type: DISCOVERY
date: 2026-04-22
created_at: 2026-04-22T18:30:00Z
author: agent
session_id: pr-a2-narrow-defensive
session_turn: 1
project: csq
topic: PR-A2 settings.json re-materialize on csq run N
phase: implement
tags:
  [
    PR-A2,
    handle-dir,
    settings.json,
    materialize,
    belt-and-suspenders,
    journal-0059,
    v2.0.1,
  ]
---

# PR-A2 Scope Narrowed — The Gap Was Not What the Original Plan Described

## Background

Journal 0059 (half-2) identified that LIVE terminals whose handle dir was created before a global settings upgrade keep a stale `settings.json` until they exit — CC is already exec'd and `csq` is no longer running in that terminal. The proposed structural fix (symlink `term-<pid>/settings.json` to `config-<N>/settings.json` per slot instead of materializing at create time) requires a spec 02 revision and was deferred to v2.1.

PR-A2 in the v2.0.1 backlog (journal 0068) was described as: "write `term-<pid>/settings.json` from canonical source on every `csq run N`."

## What Investigation Found

Reading `csq-core/src/session/handle_dir.rs`, `create_handle_dir` at line 184 already calls `materialize_handle_settings` internally on every invocation. Since `create_handle_dir` is called by both `launch_anthropic` (line 167) and `launch_third_party` (line 118) in `csq-cli/src/commands/run.rs`, the claimed gap — a missing materialize call on `csq run N` — **was never present in the codebase**. The invariant was already satisfied.

The original PR-A2 plan description either described a gap that was fixed earlier without a corresponding backlog update, or was based on an incorrect reading of the code at the time it was written.

## Narrow Fix Delivered

Rather than skip the PR entirely, a defensive version was implemented that pins the invariant so future refactors cannot silently break it:

### 1. `materialize_handle_settings` visibility changed to `pub`

`pub(crate)` → `pub` so csq-cli can call it directly. An explanatory note added to the doc-comment citing this PR and journal 0059.

Re-exported from `csq-core/src/session/mod.rs` alongside `create_handle_dir` and siblings.

### 2. Explicit re-materialize call at both `run.rs` call sites

After `session::create_handle_dir(...)` succeeds in both `launch_anthropic` and `launch_third_party`, an explicit `session::materialize_handle_settings(...)` call was added. The call is non-fatal: if it fails, the `settings.json` that `create_handle_dir` already wrote is still correct; the failure is surfaced as a `warning:` to stderr.

Purpose: the invariant is now visible at the call site and is preserved through any future refactor that factors `materialize_handle_settings` out of `create_handle_dir` (e.g. the v2.1 symlink structural change).

### 3. Regression tests added (`csq-cli/src/commands/run.rs`)

Two tests added to the existing `#[cfg(test)] mod tests` block:

- **`settings_json_exists_after_create_handle_dir`** — Arrange: tempdir with `~/.claude/settings.json` (global base) and `config-1/settings.json` (slot overlay). Act: `create_handle_dir` + explicit defensive re-materialize. Assert: `term-<pid>/settings.json` exists as a real file (not a symlink), is valid JSON, and contains merged content from both sources (overlay key wins over base key).

- **`materialize_handle_settings_is_idempotent`** — Calls `materialize_handle_settings` twice on the same handle dir, asserts byte-identical output. Pins the invariant that the defensive second call cannot corrupt what `create_handle_dir` already wrote.

## What Was NOT Delivered

The structural fix described in journal 0059 §For Discussion Q2 — repointing `term-<pid>/settings.json` as a symlink to a per-slot settings file so LIVE terminals pick up changes without a restart — remains deferred to v2.1. This requires:

1. A spec 02 revision (the materialize-vs-symlink design decision)
2. Testing that CC tolerates a settings.json that is a symlink (current spec 02 notes CC reads the file on startup; symlink behavior under hot-swap is not validated)
3. Coordination with the `repoint_handle_dir` (swap) path, which currently re-materializes settings.json atomically on every swap

The deferred fix does not affect any live session today — the belt-and-suspenders guard delivered in this PR is the correct scope boundary.

## For Discussion

1. The original PR-A2 description said the materialize call was missing from `csq run N`, but investigation found it was already present at `handle_dir.rs:184`. Is there a process by which the v2.0.1 backlog items (journal 0068) could be validated against the actual codebase state before implementation begins, rather than trusting the backlog description? For example, a "pre-work read" gate before any PR lands in `/implement`.

2. If `materialize_handle_settings` were factored OUT of `create_handle_dir` in a future refactor (e.g. the v2.1 symlink migration), would the tests added in this PR be sufficient to catch the regression — or would they also need to be updated to exercise the new structural path? Specifically: `settings_json_exists_after_create_handle_dir` calls both functions explicitly, so it tests the combined invariant; it does NOT fail if `create_handle_dir` stops calling `materialize` internally (which is the regression scenario). Is the test named and structured clearly enough that the next implementer recognizes it as a regression guard rather than a unit test of `create_handle_dir`?

3. The belt-and-suspenders pattern (call a function that is already called internally, non-fatally) adds visible noise at the call site. Is this the right trade-off at this layer, or would a better long-term approach be to restructure `create_handle_dir` to NOT call `materialize_handle_settings` internally — delegating that responsibility to callers — so the contract is explicit by construction? If so, that restructure belongs in the v2.1 spec 02 revision scope rather than as a tactical patch.
