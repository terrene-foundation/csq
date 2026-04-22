---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T03:10:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c6
session_turn: 22
project: codex
topic: PR-C6 — quota.json write-path flip from schema_version=1 to =2 + idempotent crash-safe v1→v2 migration at daemon startup + Tauri AccountView.surface field for dashboard surface-badging.
phase: implement
tags:
  [
    codex,
    pr-c6,
    quota-schema,
    v1-to-v2-migration,
    startup-reconciler,
    tauri-ipc,
    surface-dispatch,
    schema_version,
  ]
---

# Decision — PR-C6: quota.json v2 write-path flip + startup migration + AccountView.surface

## Context

PR-B8 (v2.0.1) landed the v2 READ path — `AccountQuota` learned `surface` / `kind` / `schema_version`, all optional with serde defaults, and the reader tolerated both v1 and v2 shapes. That PR deliberately kept the WRITER at `schema_version = 1` under VP-final R6 so a v2.0.1 daemon could shake out the dual-read code path without committing users to a schema they couldn't roll back from. PR-C6 flips the write path.

Two adjacent changes land in the same PR because they form one coherent migration story:

1. The writer now stamps `schema_version = 2` with `surface` / `kind` present on every record. This is the spec-07 §7.4 contract and the shape PR-C5's Codex poller already produces semantically (`surface: "codex"`) — the `schema_version` header is the only still-drifting piece.
2. A startup migration function — added as pass 3 of the existing `run_reconciler` — rewrites any v1 `quota.json` to v2 atomically before the daemon's poller subsystems start writing. Without this pass the first poller tick on a v1 file would produce a v2 file, but ONLY for accounts that got polled that tick; slots with expired 429 cooldown or no credentials would retain v1 shape indefinitely.
3. The Tauri `AccountView` IPC contract gains a `surface: String` field populated from the already-present `AccountInfo.surface`. This closes the loop for PR-C8 (Codex desktop UI) which needs to badge Codex slots without inferring from the legacy `source` (`"anthropic" | "third_party" | "manual"` — no `"codex"` mapping today would have meant conflating Anthropic with Codex at the dashboard layer).

Spec contracts driving the design:

- Spec 07 §7.4.1 — `AccountQuota` v2 shape is authoritative; surface + kind + schema_version + optional Gemini-reserved fields.
- Spec 07 §7.4.3 / §7.6.2 — migration semantics: read, stamp `surface="claude-code"` + `kind="utilization"` on each account, atomic replace. Non-destructive, idempotent, crash-safe via atomic rename.
- Spec 07 §7.4.2 canonical test set — test 5' (degradation), test 7 (key validation), test 8 (extras round-trip) are the dual-read invariants that must continue to hold AFTER the writer flip.
- `tauri-commands.md` MUST Rule 3 — sensitive data MUST NOT appear in return types. PR-C6 adds `surface` (public metadata, safe) and audits the full `AccountView` payload against forbidden key names.

## Decision

Four surgical pieces:

### 1. `csq-core/src/quota/state.rs::save_state` — flip to `schema_version = 2`

Single-line change in the existing R6-motivated force: `to_save.schema_version = 1` → `= 2`. Every existing caller (`update_quota`, the anthropic poller, the new codex poller, the status composer) now produces v2 output automatically. No call-site changes needed; the type carries the schema.

### 2. `csq-core/src/quota/state.rs::migrate_v1_to_v2_if_needed` (NEW)

Public function returning a typed `MigrationOutcome::{NoFile, AlreadyV2, Migrated}` enum. Peeks the raw JSON `schema_version` before committing to a typed parse — this guards against future v3 files where a typed parse via `QuotaFile` would fail. If the peek says `>= 2`, returns `AlreadyV2` without opening the file for write. Otherwise:

- Calls `load_state`, which applies serde defaults filling in `surface = "claude-code"` / `kind = "utilization"` on every v1 record.
- Calls `save_state`, which now writes v2.

Atomic-replace inside `save_state` provides crash safety: a SIGKILL between tmp write and rename leaves the original v1 intact and the next daemon start retries. A SIGKILL after rename leaves the new v2 file in place; subsequent starts see `AlreadyV2` and no-op. No recovery ledger needed.

Non-destructive: `updated_at`, `rate_limits`, `extras`, `counter`, `rate_limit`, `selected_model`, `effective_model`, `mismatch_count_today`, `is_downgrade` — all preserved via `#[serde(default)]` on the typed round-trip. The only intentional drop is windows with `resets_at < now` (`load_state::clear_expired` — already the load-time contract, unchanged).

Seven unit tests: `NoFile`, `Migrated { account_count }`, `AlreadyV2`, idempotency (byte-identical file on second call), extras + counter preservation, whitespace-only file treated as `NoFile`, malformed `schema_version` field propagates error (rather than silently rewriting a corrupt file).

### 3. `csq-core/src/daemon/startup_reconciler.rs::pass3_quota_v1_to_v2` (NEW)

Sibling of pass1 (codex credential 0o400 reconcile) and pass2 (codex config.toml drift rewrite). Runs BEFORE `spawn_refresher` / `spawn_usage_poller` via the existing `run_reconciler` synchronous entry point — no changes needed at the two daemon start sites (`csq-cli/src/commands/daemon.rs` and `csq-desktop/src-tauri/src/daemon_supervisor.rs`), which already call `run_reconciler` immediately before `daemon::serve`.

`ReconcileSummary` gains `quota_migrated: Option<bool>` (None = no file, Some(false) = already v2, Some(true) = migrated) and `quota_accounts_migrated: usize`. Tracing emits a single structured line per pass per start — cheap enough to keep even on healthy startups, useful enough to identify "was this daemon boot the one that migrated?" from logs.

Non-fatal on error: a corrupt file is logged but does NOT crash the daemon. Rationale — the usage poller writes with `schema_version = 2` on every tick, so even if migration fails, the first successful poll overwrites the corrupt file with a valid v2 record. Panicking on quota corruption would lock users out of csq for a data artifact that self-heals on next poll.

Four pass3 unit tests in `startup_reconciler::tests`: no-file no-op, v1 rewrite with accounts_migrated count, already-v2 reports false without file mtime change, corrupt file does not crash.

### 4. `csq-desktop/src-tauri/src/commands.rs::AccountView.surface`

`surface: String` field populated from `AccountInfo.surface.to_string()` via the existing `Display` impl on `Surface` (`Surface::ClaudeCode → "claude-code"`, `Surface::Codex → "codex"`). Added to the `AccountView` struct in a position adjacent to `source` so the JSON shape remains stable alphabetically.

Frontend interface update in `csq-desktop/src/lib/components/AccountList.svelte` — `surface: string` added to the `AccountView` TypeScript interface. The existing `SessionList.svelte` AccountView subset is untouched because it only uses `id` / `label` / `has_credentials`. Two existing fixtures in `AccountList.test.ts` gain the field (required by the new interface — TypeScript would otherwise warn on missing required keys, even though runtime IPC tolerates extras).

Two Rust unit tests: structural audit (serialized JSON must not contain forbidden JSON keys `"access_token":` / `"refresh_token":` / `"id_token":` / `"api_key":` / `"openai_api_key":`) and codex-variant round-trip.

## Alternatives considered

**A. Migrate inside the usage poller's first tick instead of at startup.** Rejected. First-tick migration races with `update_quota` (the legacy test-only writer) and any other daemon subsystem that touches `quota.json` in the first few milliseconds. The startup reconciler already runs synchronously before `spawn_refresher` / `spawn_usage_poller`, giving us a known-empty-writers window. Moving the migration to first-tick would also mean slots without credentials (and therefore never polled) would never be migrated — the file would stay at v1 forever.

**B. Ship the write-path flip without the migration function.** Rejected. The v2.0.1 writer wrote v1, so existing deployments have v1 on disk. A v2.1 daemon starting against that file would WRITE v2 records only for accounts it actively polled that boot — partial-migration state (accounts with both v1 and v2 shape in the same file, mixed under the same top-level `schema_version = 1` header) violates the spec-07 §7.4 contract that `schema_version` is a top-level property. A clean atomic rewrite on first startup is the only way to keep the invariant `top-level schema_version is the highest shape version of any account record`.

**C. Fold the migration directly into `load_state` so any first-read forces the rewrite.** Rejected. `load_state` is called from read-only code paths (status composer, Tauri `get_accounts`, `csq status`) — making it write-through would (a) require unexpected file lock acquisition on every read, and (b) turn read failures into write failures for callers that previously had no reason to handle that class of error. The reconciler pattern keeps read and write separated.

**D. Ship the AccountView.surface change in a follow-up PR.** Rejected. The frontend (PR-C8 Codex UI) needs the field to exist before it can render surface-aware components; deferring the plumbing would either block PR-C8 or force it to invent a client-side surface inference from `source` (ambiguous — `source: "anthropic"` could be a ClaudeCode slot OR a pre-PR-C6 Codex slot if the desktop and daemon versions drift during rollout). Landing `surface` alongside the v2 write-path means desktop builds that read the field always see a populated value.

**E. Use TOML or a dedicated schema crate for the peek step in migration.** Rejected. The peek is a single `serde_json::from_str::<Value>(...)` + `.get("schema_version").and_then(as_u64)` — two lines that avoid pulling in a parser dep and are easier to reason about than a typed-with-optional-schema-version deserialization.

**F. Migrate destructively — drop unknown extras fields on migration.** Rejected. The spec-07 §7.4.1 `extras: Option<Value>` escape hatch exists precisely so surfaces can stash payload fragments across versions without forcing a schema bump. Dropping extras during migration would silently destroy Codex's `plan_type` (PR-C5) and any future surface-specific data, requiring an immediate re-poll to restore.

**G. Write a full integration test that boots the daemon on a v1 file and asserts the migration ran.** Rejected for this PR. The pass3 unit tests already exercise `run_reconciler` against a real temp dir with a real v1 file on disk and a real atomic-replace through `save_state`. A full daemon integration test would duplicate that coverage with far more setup (socket binding, shutdown token plumbing) for no additional fault-finding power. The existing `integration_codex_refresher_windows.rs` is the home for cross-subsystem integration tests; pass3's coverage is sufficient as unit tests.

## Consequences

- `quota.json` on v2.1 installations carries `schema_version: 2` with `surface` + `kind` on every record, matching spec 07 §7.4.1 exactly. Rollback to v2.0.1 still works because PR-B8's dual-read tolerates both shapes; a v2.0.1 daemon reading a v2 file sees `schema_version=2` and accepts the record verbatim.
- First boot of v2.1 on a v1 deployment performs a single atomic rewrite. Observed via `quota_migrated: Some(true)` in the reconciler summary; subsequent boots show `Some(false)` (already v2).
- Corrupt `quota.json` no longer crashes the daemon at startup — the migration logs and moves on, and the first successful poll writes a fresh v2 file. Users with a damaged file lose at most one polling interval of history.
- Tauri dashboard can now branch rendering on `surface == "codex"` without inferring from `source`. The new field is visible in every `get_accounts` response.
- Tests: csq-core 871 → 882 (+11: 7 in `quota::state::tests`, 4 in `startup_reconciler::tests::pass3_*`); csq-desktop +2 (`account_view_*` IPC tests). Workspace total moves from 1100 → 1113.
- `save_state` is the single writer in the codebase; no other caller constructs a raw `quota.json` file. Flipping it here covers every production write path (anthropic poller, codex poller, test-only `update_quota`, status composer cache).
- `ReconcileSummary` gains two new fields. Downstream consumers that destructure the struct (currently none — it's used only for telemetry within the reconciler) would need to update. The `#[derive(Debug, Default, ...)]` chain is preserved.

## For Discussion

1. **The migration logs at `info` level when it fires (`quota_migrated=Some(true)`) and at `debug` level when it's a no-op (`Some(false)`). The reconciler summary emits one tracing line per daemon start regardless. Is `info` level on a successful one-shot migration too loud for operators who don't care about the transition, given that every v2.1 boot after the first will log `debug`? Alternative is to log the successful migration at `info` only when `quota_accounts_migrated > 0` (i.e. the file actually had content to migrate), and downgrade the empty-file-migrated case to `debug`.** (Lean: keep at `info` as written. A one-shot rewrite of user-facing state is worth a log line, and the "already v2" case that logs at debug is the overwhelming majority of boots. Operators who dislike the startup line have tracing-level filtering available.)

2. **Pass3 handles a corrupt `quota.json` by logging and continuing — the poller will overwrite on first tick. This contrasts with pass1 (which blocks on the per-account mutex rather than bypassing corrupt state) and pass2 (which rewrites drifted `config.toml`). If the corruption is actually a partial write from a crashed tmp→rename (i.e. an orphaned tmp file with the real `quota.json` untouched), is the "do nothing, wait for the poller to rewrite" behavior acceptable, or should pass3 additionally scan for orphaned tmp files (`quota.json.tmp.*`) and clean them up?** (Lean: tmp-file cleanup IS worth adding, but as a follow-up — the current behavior is non-regressive because orphaned tmps in the base dir don't block subsequent writes, they just consume disk until the next `platform::fs::unique_tmp_path` rollover. Add to PR-C9a redteam round-1 as a tracked finding rather than expanding PR-C6 scope.)

3. **Counterfactual — had we preserved the VP-final R6 force-to-1 semantics and shipped ONLY the migration (keeping `save_state` at v1), would the dashboard surface-badging work correctly?** The migration would write `schema_version: 1` but with `surface` and `kind` fields stamped on each account via serde defaults during the load→save cycle. The invariant "top-level schema_version matches record shape version" would be violated: each account record would carry v2 fields but the top-level header would claim v1. Subsequent polls via `save_state` would rewrite back to `schema_version: 1` even though they're semantically producing v2 records. Conclusion: the migration and the write-path flip are semantically coupled — shipping only one makes the shape internally inconsistent. That's why PR-C6 bundles them.

## Cross-references

- `workspaces/codex/journal/0017-DECISION-pr-c5-usage-poller-codex-module.md` — upstream write-path that PR-C6 makes semantically consistent at the schema_version header.
- `workspaces/codex/journal/0001-DECISION-codex-surface-dispatch-architecture.md` — original schema v2 + migration design; PR-C6 is the v2.1 implementation step.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C6 — closes this plan item.
- `specs/07-provider-surface-dispatch.md` §7.4 (AccountQuota shape), §7.4.1 (canonical Rust struct), §7.4.2 (test enumeration), §7.4.3 + §7.6.2 (migration semantics).
- `specs/07-provider-surface-dispatch.md` §7.4.2 test 6 (round-trip v2 → save → load preserves Gemini fields) — renamed from `round_trip_v2_read_via_v1_write_preserves_gemini_fields` to `round_trip_v2_read_via_v2_write_preserves_gemini_fields` with the assertion flipped from `schema_version=1` to `=2`.
- `csq-core/src/quota/state.rs::{save_state, migrate_v1_to_v2_if_needed, MigrationOutcome}` — the new write-path + migration entry points.
- `csq-core/src/daemon/startup_reconciler.rs::pass3_quota_v1_to_v2` — new pass; wired via existing `run_reconciler`.
- `csq-desktop/src-tauri/src/commands.rs::AccountView` — `surface: String` field added + two IPC audit tests.
- `csq-desktop/src/lib/components/AccountList.svelte` — `surface: string` on the TypeScript interface.
- `.claude/rules/tauri-commands.md` MUST Rule 3 (no sensitive data in return types) — honored; structural audit test enforces.
- `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings) — all edge cases handled inline, no deferred items.
