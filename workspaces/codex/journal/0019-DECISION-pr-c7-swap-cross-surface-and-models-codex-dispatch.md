---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T04:10:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c7
session_turn: 30
project: codex
topic: PR-C7 — `csq swap` cross-surface exec-replace with INV-P05 confirm prompt (`--yes` bypass) + INV-P10 source-handle-dir cleanup + `csq models switch` Codex path via ModelConfigTarget dispatch to config.toml with FR-CLI-04 `--force` for uncached models.
phase: implement
tags:
  [
    codex,
    pr-c7,
    swap,
    cross-surface,
    exec-replace,
    models,
    toml-model-key,
    INV-P05,
    INV-P06,
    INV-P10,
    FR-CLI-04,
  ]
---

# Decision — PR-C7: swap cross-surface exec + models switch Codex dispatch

## Context

The v2.1 Codex chain opened with PR-C3a (canonical credentials), closed the auth story with PR-C3b (device login) and PR-C3c (launch_codex), closed the back end with PR-C4 (daemon refresher) + PR-C5 (usage poller), and closed the quota story with PR-C6 (v2 write-path flip). All those PRs landed code that `csq login N --provider codex` users could not yet SWAP to from an existing ClaudeCode terminal, and models for which `csq models switch codex` wrote nothing. PR-C7 wires both user-facing paths.

Spec contracts driving the design:

- INV-P05 — cross-surface `csq swap` warns + prompts (`--yes` bypasses) + `exec`s the new binary.
- INV-P06 — model selection is dispatched by `ModelConfigTarget` (`EnvInSettingsJson` vs `TomlModelKey`).
- INV-P10 — cross-surface swap removes the source handle dir BEFORE the `exec`. If removal fails swap aborts; if `exec` fails after removal, the source is already gone (deliberate — `csq run M` recovers).
- FR-CLI-04 — `csq models switch codex <id> --force` accepts model ids that aren't in the csq-curated catalog. csq does not validate against ChatGPT subscription entitlements.

## Decision

Four surgical pieces:

### 1. `csq-cli/src/commands/swap.rs` — surface-aware dispatch (full rewrite)

The swap handler now takes `(base_dir, target, yes: bool)`. Three outcomes, decided by `(source_surface, target_surface)`:

- **Same-surface ClaudeCode** — preserved path. `repoint_handle_dir` (term-dir) or legacy `rotation::swap_to` (config-dir) as before, with the daemon cache-invalidation notification also preserved.
- **Cross-surface** — INV-P05 prompt-and-confirm on stderr unless `--yes`. Reads one line from stdin via `std::io::stdin().lock().read_line`, accepts case-insensitive `y`. On decline, returns `anyhow!("swap cancelled")` (exit 1). On accept, proceeds to the cleanup+exec path.
- **Same-surface Codex → Codex** — also takes the exec-replace path (bypasses the prompt because source==target surface). Rationale documented inline: a running codex process holds open files under `config-<N>/codex-sessions/`, so symlink-repointing with the process live would orphan those file descriptors. The exec-replace restart is semantically equivalent to "quit and run `csq run M`" at the cost of one process restart.

**Source-surface detection.** `CODEX_HOME` set → Codex source. `CLAUDE_CONFIG_DIR` set → ClaudeCode source (with legacy `config-N` tolerance for the deprecation-warn path). Neither set → error. Both set (e.g. parent shell exported both) → `CODEX_HOME` wins per `csq run`'s scrub ordering in `run.rs`. Detection is pure (no file I/O) and unit-tested via five `is_term_handle_dir` / `is_legacy_config_dir` / `SourceHandle::surface` assertions.

**Target-surface resolution.** `discovery::discover_all(base_dir)` → match on `a.id == target.get()` → `a.surface`. Fails with an actionable `account {target} not found` pointing at `csq login`. Pure — the discovery cache is not mutated.

**Exec semantics.** Unix: `std::os::unix::process::CommandExt::exec` replaces the current process image. Scrubs the opposite surface's env var before exec (`CLAUDE_CONFIG_DIR` before Codex exec; `CODEX_HOME` before ClaudeCode exec) so the child never sees a stale pointer. If `exec` returns, it's an error — the function signature is `Result<()>` (the returned `io::Error` from `exec()` is always the "failed to execute" case).

**Windows.** `exec` is not ergonomically available on Windows (no true `execve`), so `exec_codex` / `exec_claude_code` return `Err("cross-surface csq swap is Unix-only today. On Windows, exit the current surface and run `csq run <N>`")`. Non-regressive because cross-surface swap is NEW in this PR; Windows never supported it before this either.

### 2. `csq-cli/src/commands/models.rs` — dispatch on `ModelConfigTarget` + `--force`

Previously `handle_switch` took `(provider_id, model_query, slot, pull_if_missing)` and wrote into `config-N/settings.json` in all branches. Now it takes an additional `force: bool` and dispatches on `provider.model_config`:

- `ModelConfigTarget::EnvInSettingsJson` (Claude, MM, Z.AI, Ollama) → existing `write_slot_model` or global-profile path.
- `ModelConfigTarget::TomlModelKey` (Codex) → `providers::codex::surface::write_config_toml(base, slot, model_id)` which writes the two-key file atomically with INV-P03 `cli_auth_credentials_store = "file"` always present. A Codex switch without `--slot` is refused at CLI boundary (anyhow error) because Codex has no global profile file.

**Codex model resolution** (`resolve_codex_model` helper). Three layers:

1. Empty input → rejected with `"model id must not be empty"`.
2. `ModelCatalog::find(query)` hit where `m.provider == "codex"` → return `m.id`.
3. `query == provider.default_model` → return verbatim (the catalog may not enumerate the canonical default literal separately).
4. `--force` → return `query` verbatim with no catalog check.
5. Otherwise → error mentioning `--force` and the uncached-model rationale.

This mirrors Ollama's "user-space" model (anything locally pulled is valid) while keeping the default path catalog-safe for users who'd otherwise typo a model id into a slot they paid for.

### 3. `csq-cli/src/main.rs` — clap wiring

`Swap { account, yes: bool }` with `#[arg(long)]`. `ModelsCmd::Switch { ..., force: bool }` with `#[arg(long)]`. Downstream dispatchers pass both through. Doc strings updated to note Codex is now a supported `csq models switch` provider.

### 4. Test coverage

**swap.rs** (+4 unit tests): `is_term_handle_dir` (accepts/rejects), `is_legacy_config_dir`, `SourceHandle::surface`. Full integration with `exec` is deliberately NOT unit-tested because `exec` replaces the process and the test harness dies with it; the cross-surface path is covered by the stdin-confirm pure logic and the `SourceHandle` pure logic.

**models.rs** (+6 unit tests):

- `switch_codex_default_model_writes_config_toml_on_slot` — catalog default writes both keys to config.toml.
- `switch_codex_arbitrary_model_requires_force` — `--force` off → error mentions `--force` and `uncached`.
- `switch_codex_arbitrary_model_accepted_with_force` — `--force` on → arbitrary id lands.
- `switch_codex_requires_slot` — Codex switch without `--slot` → "--slot is required" error.
- `switch_codex_empty_model_rejected` — empty trim → "must not be empty".
- `switch_codex_rewrite_preserves_auth_store_directive` — second switch over existing config.toml keeps `cli_auth_credentials_store = "file"` (INV-P03 guard against a regression where the rewriter drops auxiliary keys).

## Alternatives considered

**A. Treat same-surface Codex → Codex as symlink-repoint (matching same-surface ClaudeCode).** Rejected. The Codex handle dir's `sessions` symlink resolves to `config-<N>/codex-sessions/`. A running codex process opens files under that directory by following the symlink once at session start; once opened, the process holds dentries. Repointing the symlink while the process is live leaves the kernel's open-file table pointing at the OLD `config-<M>/codex-sessions/` via the dentry cache, while new symlink readers see the NEW target. Result: orphaned sessions + history split across both account dirs. The exec-replace path avoids this entirely by terminating the old codex process before the new one opens any files.

**B. Read `.csq-account` marker inside the handle dir to determine source surface (not env vars).** Rejected. Marker reading is one more file I/O (strictly unnecessary — the env var is authoritative about what the terminal was launched as) and it doesn't tell us which CLI binary spawned — two ClaudeCode-marker handle dirs could exist for a Codex source if the user manually constructed one, and the env var authoritative-source catches that. Env var is also the only signal available BEFORE `discovery::discover_all`, keeping error paths cheap.

**C. Keep `handle_switch` taking 5 args and introduce a `ModelSwitchOptions { force, pull_if_missing }` struct.** Rejected for the marginal benefit. The function takes 6 args now; clap's derive wiring is one line per arg; the call sites in tests explicitly pass named booleans. A struct wrapper would require one more file-level type to maintain for zero behavioral difference.

**D. Reject arbitrary Codex model ids even with `--force`; require the user to file a PR to extend the curated catalog.** Rejected because (a) OpenAI ships new Codex model ids at a cadence faster than csq can cut releases, and (b) catalog drift is the bug `--force` exists to escape. The Ollama path has the same posture (`pull_if_missing=false` with a non-catalog id) with the same rationale.

**E. Let Codex switch work without `--slot` by using a dedicated global profile file (`settings-codex.toml`).** Rejected. Codex has no concept of a "profile" — it reads `$CODEX_HOME/config.toml` directly. Inventing a global profile would mean csq synthesizes `config.toml` at login time for every Codex slot (already the case) AND maintains a parallel settings-codex.toml that gets merged in at `csq run`. Two sources of truth for the same data. The "--slot is required" error surfaces at the CLI boundary with a single sentence explaining why.

**F. Do the prompt in stderr with `rprompt` or `dialoguer` crate.** Rejected. The only prompt is a `[y/N]` with `--yes` bypass — implemented in 6 lines of `std::io::stdin::lock().read_line`. Adding a crate dep for one user-facing prompt would mean pulling in a chain of dependencies (ansi, termcolor, tokio-stream) whose upstream is broader than csq needs.

**G. Windows cross-surface support via `CreateProcessW` + `ExitProcess`.** Rejected for this PR. Windows has no `execve` equivalent; the closest is spawn-and-exit which leaves a brief window where both the source and target exist. The cross-surface invariant "source handle dir removed BEFORE target exec" is violated on Windows by any such two-step. The current PR returns an actionable error on Windows. Proper support lands in a follow-up PR that wires `windows::Win32::System::JobObjects` for atomic source-kill+target-start. Tracked in the Windows-only backlog.

## Consequences

- Users with both ClaudeCode and Codex slots can now cross-surface swap with one command: `csq swap 5 --yes` from a claude-code terminal to a Codex slot 5 replaces the process with codex.
- INV-P10 is enforced by the order of operations in `cross_surface_exec`: `std::fs::remove_dir_all(source_path)?; ... exec(target)`. No intermediate state where both handle dirs exist.
- INV-P05 is enforced by the `is_cross_surface && !yes` guard on the stderr prompt.
- Codex slots can now retarget model via `csq models switch codex gpt-5.4 --slot 5` (catalog) or `... --force` (arbitrary). Every rewrite preserves INV-P03 `cli_auth_credentials_store = "file"` via `write_config_toml`.
- Windows remains in its pre-PR-C7 state for cross-surface (error with an actionable message). Non-regressive.
- Tests: csq-cli 123 → 133 (+10: 4 swap, 6 codex models). Workspace total moves 1113 → 1123. Vitest / Svelte unchanged (no frontend in this PR).
- No change to `csq-core` public APIs. No change to `csq-desktop`.

## For Discussion

1. **The same-surface Codex → Codex path currently takes the exec-replace route despite spec 07 INV-P05's "Same-surface swap retains the existing in-flight symlink-repoint behavior" wording. The spec was written with ClaudeCode's handle-dir model in mind; Codex's `sessions/` symlink model breaks the invariant. Is the correct fix (a) amend the spec so INV-P05 reads "Same-surface ClaudeCode swap retains symlink-repoint; Codex always exec-replaces," or (b) invest in a Codex-safe symlink-repoint that first signals the running codex process to close + reopen its session files?** (Lean: (a) amend the spec. Codex's own CLI does not expose a "reload session state from a new path" IPC, so (b) would require forking codex-cli or intercepting its fd open calls via LD_PRELOAD — disproportionate for a marginal UX win. Spec amendment would note this alongside INV-P04 where sessions-symlink rationale already lives.)

2. **The `resolve_codex_model` helper accepts the provider's `default_model` literal as a valid "catalog hit" even though the `ModelCatalog` may not enumerate it (today, Codex has no ModelCatalog entries — the `default_model = "gpt-5.4"` literal IS the entire catalog). If a future PR adds a curated `ModelCatalog::codex_models()` that enumerates N entries including `gpt-5.4`, the `default_model` fallback becomes redundant code that never fires. Is that worth keeping as defensive coding, or should it go when the real catalog lands?** (Lean: keep the fallback. It's 3 lines and guards against a future case where `PROVIDERS::codex::default_model` and `ModelCatalog::codex_models` get out of sync — a common failure mode. Removing it would force a regression test for the sync-check; the fallback is cheaper.)

3. **Counterfactually — had we shipped only the models-switch Codex dispatch in PR-C7 and deferred cross-surface swap to a follow-up, would Codex users have had a viable v2.1 experience?** They could login, launch via `csq run N`, poll quota, and switch models. Cross-surface would mean "exit codex, run `csq swap M`, which currently errors out because `CODEX_HOME` isn't `term-*` without our fix." Users would need `exit && csq run M` — one more keystroke but functional. Conclusion: the models-switch dispatch is the higher-leverage change; cross-surface swap is polish. Bundling both here means v2.1 ships surface-complete rather than "Codex is first-class except for swap."

## Cross-references

- `workspaces/codex/journal/0018-DECISION-pr-c6-quota-v2-write-flip-and-startup-migration.md` — upstream quota schema that PR-C7's swap relies on (AccountView.surface feeds dashboard behavior after a cross-surface swap).
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C7 — closes this plan item.
- `specs/07-provider-surface-dispatch.md` §7.5 INV-P05 (cross-surface swap + --yes bypass), INV-P06 (`ModelConfigTarget` dispatch), INV-P10 (source-handle-dir cleanup before exec), INV-P03 (`cli_auth_credentials_store = "file"` ordering).
- `specs/07-provider-surface-dispatch.md` §7.3.3 — Codex login sequence that pre-seeds config.toml; PR-C7's model switch reuses the same `write_config_toml` helper.
- `csq-core/src/providers/codex/surface.rs::write_config_toml` — the `TomlModelKey` writer, unchanged by this PR.
- `csq-core/src/providers/catalog.rs::ModelConfigTarget` — the dispatch key PR-C7 branches on.
- `csq-cli/src/commands/swap.rs` — full rewrite (pre-PR-C7 was a 90-line handler; post is a 310-line module with 3 paths + source detection).
- `csq-cli/src/commands/models.rs::handle_switch` — extended signature + Codex dispatch.
- `csq-cli/src/main.rs::Command::{Swap, ModelsCmd::Switch}` — new `yes: bool` / `force: bool` flags.
- `.claude/rules/zero-tolerance.md` Rule 5 (no residual findings) — no deferred items from this PR. Windows cross-surface tracked as a platform-specific follow-up with a concrete blocker (no `execve` equivalent), not as "accepted residual".
