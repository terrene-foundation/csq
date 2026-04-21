# 02 csq Handle-Dir Model

Spec version: 1.0.0 | Status: DRAFT | Governs: on-disk layout, config-N invariant, handle dir lifecycle, swap semantics, migration

---

## 2.0 Scope

This spec defines csq's authoritative on-disk layout: where accounts live, where running terminals live, which files are permanent, which are ephemeral, and how `csq swap` moves a terminal between accounts without affecting sibling terminals.

It depends entirely on spec 01 (Claude Code Credential Architecture). If spec 01 is wrong, this one is wrong. Read spec 01 first.

## 2.1 On-disk layout

Root directory: `$HOME/.claude/accounts/` (configurable via `CSQ_BASE_DIR`; default shown).

```
accounts/
├── config-1/                 ← permanent home for account 1
│   ├── .credentials.json     ← account 1's live OAuth tokens (daemon-refreshed)
│   ├── .csq-account          ← marker, content: "1", immutable
│   ├── settings.json         ← account 1's CC settings
│   ├── .claude.json          ← account 1's CC app state
│   ├── .quota-cursor         ← stale-read dedupe cursor
│   └── [symlinks to ~/.claude/* for shared items]
├── config-2/                 ← permanent home for account 2
│   └── ...
├── config-N/                 ← one per account
│   └── ...
│
├── credentials/              ← canonical per-account credential store (daemon-refreshed)
│   ├── 1.json                ← account 1 canonical, used by fanout
│   ├── 2.json
│   └── N.json
│
├── profiles.json             ← account labels (for display)
├── quota.json                ← daemon-owned quota cache (per-account)
├── rotation.json             ← auto-rotation config
├── csq.sock                  ← daemon IPC Unix socket (0o600)
│
└── term-<pid>/               ← ephemeral handle dir, one per running `claude` process
    ├── .credentials.json  → ../config-<current>/.credentials.json   (symlink)
    ├── .csq-account       → ../config-<current>/.csq-account        (symlink)
    ├── settings.json      ← materialized file (deep-merged: ~/.claude/settings.json + config-<current>/settings.json)
    ├── .claude.json       → ../config-<current>/.claude.json        (symlink)
    ├── .live-pid          ← contains the PID, used for sweep
    └── [shared symlinks to ~/.claude/*]
```

### Two tiers of state

1. **Permanent tier (`config-N`, `credentials/N.json`):** exists once per account, lives forever, only written by login or daemon refresh. Directory name encodes the account number and the name MUST match the `.csq-account` marker inside it.
2. **Ephemeral tier (`term-<pid>`):** exists once per live CC process, lives exactly as long as that process. Created by `csq run`. Deleted on process exit. Contains symlinks, the `.live-pid` file, and the materialized `settings.json` (deep-merged from user global + account overlay).

### The shared items (both tiers)

Every directory that CC launches into MUST have symlinks for the shared items (`history`, `sessions`, `commands`, `skills`, `agents`, `rules`, `mcp`, `plugins`, `snippets`, `todos`) pointing at `~/.claude/<item>`. See `csq-core/src/session/isolation.rs:12-15`. This is what preserves conversation history across swaps — CC writes history to the symlinked target, which is the same path regardless of which config or handle dir it launched in.

## 2.2 Invariants

**INV-01: `config-N` is permanent.**

- A directory `config-<N>` is account N's home forever. Once created, the name is immutable.
- The `.csq-account` marker inside `config-N` contains the literal string `N`. It is written once at account creation and never modified.
- `csq swap`, `csq run`, and any non-login flow MUST NOT write to `config-<N>/.credentials.json`, `config-<N>/.csq-account`, `config-<N>/settings.json`, or `config-<N>/.claude.json`.
- **Only three code paths write into `config-N`:**
  1. `csq login N` — on successful OAuth, writes the new tokens to `config-N/.credentials.json` and updates `credentials/N.json`.
  2. Daemon refresher — on successful refresh, writes the new tokens to `config-N/.credentials.json` and `credentials/N.json`.
  3. User edits — `settings.json`, `.claude.json` may be edited by CC running in that dir (via legacy launches) or by the user directly.

**INV-02: `term-<pid>` is ephemeral and per-process.**

- Created atomically by `csq run N` before execing `claude`.
- The directory name is `term-<pid>` where PID is the csq CLI's own process ID at handle-dir creation time (NOT the `claude` process that comes next, which is either the exec target of csq or a child). The PID is captured BEFORE `exec`, so it is stable for the lifetime of the resulting `claude` process.
- Every file in `term-<pid>` is either a symlink to a `config-<current>/*` target, the `.live-pid` sentinel, or the materialized `settings.json` (the sole non-symlink content file — deep-merged from `~/.claude/settings.json` + `config-<current>/settings.json`).
- On `claude` process exit, csq (via a wrapper OR via daemon sweep) removes `term-<pid>`. See section 2.5.
- **No long-lived content beyond settings.json.** If csq ever writes other real data into a `term-<pid>` dir, it's a bug against this spec.

**INV-03: Identity derivation reads `.csq-account` through the symlink.**

- To determine which account a terminal is currently bound to, code MUST read the `.csq-account` file within its `CLAUDE_CONFIG_DIR` (which is the handle dir). The symlink resolves to the current `config-<N>/.csq-account`, returning the account number.
- Code MUST NOT parse `config-N` or `term-<pid>` directory names for a number to determine account identity. The handle dir PID is not an account ID. The config dir N is the account identifier ONLY when reading permanent canonical state, never when reading live runtime state.
- This is the rule that retroactively fixes journal 0029 Finding 1.

**INV-04: Swap is a symlink repoint, never a file rewrite.**

- `csq swap M` run inside a handle-dir-bound terminal MUST:
  1. Look up the current handle dir from `CLAUDE_CONFIG_DIR`.
  2. Verify that path is a `term-<pid>` dir under the csq base.
  3. For each symlinked file in the handle dir (`.credentials.json`, `.csq-account`, `.claude.json`, and any additional symlinks the launch created), atomically replace the symlink to point at `../config-<M>/<same-filename>`.
  4. Re-materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with `config-<M>/settings.json` (new account's slot overlay) and writing the result to the handle dir.
  5. Atomic replace uses rename-over (`std::fs::rename` of a new symlink onto the old one — not delete-then-create, which races).
- csq swap MUST NOT write to the underlying `config-<M>/*` files. Those are permanent. The swap is purely a pointer change in the handle dir.
- After the repoint, the next time CC in that terminal calls `fs.stat('.credentials.json')`, the stat follows the new symlink to `config-<M>/.credentials.json`, returns a DIFFERENT mtime from what CC saw before (almost certainly — it's a different file), and CC's `invalidateOAuthCacheIfDiskChanged` clears its memoize. The next API call uses account M. See spec 01 section 1.4.
- **Other terminals (with their own `term-<otherPid>/.credentials.json` symlinks still pointing at `config-<current>`) are untouched.** Their stat resolves to the unchanged `config-<current>` files. They stay on their current account.

**INV-05: Daemon fanout writes to `config-N` only.**

- On successful token refresh for account N, the daemon writes the new tokens to `config-<N>/.credentials.json` and `credentials/<N>.json`.
- Every `term-<pid>` handle dir whose symlinks currently resolve to `config-<N>` automatically sees the new content on its next `fs.stat`. No per-handle-dir write is needed.
- This is a property of the symlink layer — the daemon refresh targets exactly one filesystem location per account; the handle dirs are just views.
- **Consequence:** the complexity of `broker::fanout::fan_out_credentials` reduces drastically. It only needs to iterate `config-*/` dirs (one per account), not `config-*` dirs crossed with `term-*` dirs. The per-handle-dir fanout is a filesystem side effect.

**INV-06: Subscription metadata is preserved on every write to `config-N/.credentials.json`.**

- As in spec 01 section 1.7: `subscriptionType` and `rateLimitTier` may be null in fresh OAuth responses. When writing new tokens to `config-N/.credentials.json`, csq MUST preserve the existing non-null values from the current file if the incoming tokens have null fields.
- This applies to `csq login` and daemon refresh. It does NOT apply to swap (swap never writes to `config-N`).

## 2.3 Directory-level operations

### 2.3.1 Account provisioning: `csq login N`

1. Create `config-<N>/` if it doesn't exist. Populate with symlinks via `session::isolate_config_dir`.
2. Write `.csq-account` containing `N`.
3. Run OAuth flow (CC's `claude auth login` delegated inside the config dir — see spec 03).
4. On success, capture tokens from `config-<N>/.credentials.json` and mirror to `credentials/<N>.json`.
5. Update `profiles.json` with account label.
6. Signal daemon to start refresh + usage polling for account N.

### 2.3.2 Terminal launch: `csq run N`

1. Verify `config-<N>` exists and has valid credentials.
2. Create `term-<my-pid>/` atomically. Populate with:
   - Symlinks for `.credentials.json`, `.csq-account`, `.claude.json` → `../config-<N>/<same>`.
   - Materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with `config-<N>/settings.json` (account overlay).
   - Symlinks for all shared items via `isolate_config_dir`.
   - Write `.live-pid` containing the csq CLI PID (which becomes the claude PID on exec).
3. Set `CLAUDE_CONFIG_DIR=<absolute path to term-<my-pid>>` in the child env.
4. Strip sensitive env vars (`ANTHROPIC_*`, etc.) — unchanged from current `run.rs`.
5. `exec claude` (Unix) or `spawn claude` + wait (Windows).
6. On any exec failure, csq removes `term-<my-pid>` before exiting.

### 2.3.3 Account switch: `csq swap M`

1. Resolve `CLAUDE_CONFIG_DIR` from env; verify it's a `term-<pid>` dir under the csq base. If not (legacy `config-N` launch, unset env, or non-csq-managed dir), refuse with an error that explains the cause. **Never rewrite a `config-<N>` dir on swap.**
2. Validate account M exists at `config-<M>/`. Refuse if not.
3. Validate M's credentials are not in `LOGIN-NEEDED` state. Refuse if so (with suggestion to run `csq login M`).
4. For each of `.credentials.json`, `.csq-account`, `.claude.json`:
   - Construct the target `../config-<M>/<same-filename>`.
   - `std::os::unix::fs::symlink(target, tmp_path)` to create a new symlink at a temp path inside the handle dir.
   - `std::fs::rename(tmp_path, final_path)` to atomically replace the existing symlink.
5. Re-materialize `settings.json` by deep-merging `~/.claude/settings.json` (user global) with `config-<M>/settings.json` (new account's slot overlay) and writing the result to `term-<pid>/settings.json`.
6. Notify daemon to invalidate caches (same as today).
7. Print confirmation: `"Swapped to account M — token valid Xm"`.

**Swap is advisory only.** The CC process in the same terminal picks up the change on its next API call via spec 01 section 1.4. No inter-process signal is needed or possible. Swap latency from the user's perspective is "next API call," which is typically the user's next keystroke plus CC's normal startup.

### 2.3.4 Terminal exit: `csq exit` or `claude` process termination

Two paths:

**Path A (user runs `csq exit` or csq-run wrapper catches the exit):**

- csq removes `term-<its-pid>/` directory.
- Returns cleanly.

**Path B (claude process dies without csq involvement — kill, crash, etc.):**

- Handle dir remains on disk.
- Daemon sweep (see section 2.5) detects it on its next tick and removes it.

## 2.4 What `csq swap` MUST refuse

- Target account does not exist (`config-<M>` missing): error `account M not provisioned — run csq login M`.
- Target account in LOGIN-NEEDED state: error `account M needs re-login — run csq login M`.
- Current `CLAUDE_CONFIG_DIR` is not a `term-<pid>` dir (legacy launch, env unset, non-csq dir): error `csq swap is only available inside a csq-managed terminal — relaunch with csq run N`.
- Current `CLAUDE_CONFIG_DIR` points into a `config-<N>` dir (legacy mode): error `this terminal was launched in legacy per-account mode; swap would affect all terminals on config-<N>. Relaunch with csq run N to use per-terminal swap.` (See section 2.6 for the migration story.)
- `.live-pid` in the handle dir does not match the current process's parent PID (suggests inheriting a handle dir from a dead parent): error `stale handle dir detected, current PID does not match owner — re-run csq run`.

## 2.5 Handle dir sweep

The daemon periodically (every N seconds, configurable; default 30) scans `accounts/term-*/` and, for each:

1. Read `.live-pid`.
2. If the PID does not exist (Unix: `kill(pid, 0)` returns ESRCH; Windows: `OpenProcess` returns null), remove the handle dir.
3. Log the sweep outcome at DEBUG level.

This sweep handles the case where `claude` crashed or was killed without csq cleaning up. It MUST be idempotent (safe to run concurrently with `csq run` creating new handle dirs). It MUST NOT remove a handle dir whose PID is alive under any circumstance, even if the symlinks are stale or broken — a live process owns its dir.

## 2.6 Legacy mode and migration

### Legacy mode

Before this spec, csq ran terminals with `CLAUDE_CONFIG_DIR=config-<N>` directly (no handle dir layer). The `config-N` dir was both the permanent account home AND the live config for any terminal launched on account N. `csq swap` rewrote `config-N/.credentials.json` in place, which forcibly moved every terminal bound to that config dir to the new account.

This mode is **deprecated**. The code to create legacy-mode terminals (`run.rs:33` `let config_dir = base_dir.join(format!("config-{}", account));` followed by setting `CLAUDE_CONFIG_DIR` to that path) MUST be removed when this spec is implemented.

### Migration (one release cycle)

**Phase 1 (this spec's implementation):**

- New `csq run` always creates `term-<pid>` handle dirs. No path produces a legacy-mode terminal.
- Existing `config-N` directories are preserved exactly as they are — they ARE the permanent canonical homes under the new model.
- Running legacy-mode terminals from before the upgrade keep working. They have `CLAUDE_CONFIG_DIR=config-<N>` and continue to read/write `config-<N>` directly. `csq swap` inside them triggers the error from section 2.4 (`launched in legacy per-account mode`) because the env var does not point at a `term-<pid>` dir.
- Users are instructed (in the error message and in the release notes) to exit and relaunch with `csq run N` to get per-terminal swap.

**Phase 2 (next release after Phase 1 soaks):**

- Add a `csq doctor` command that detects any running `claude` processes bound to a legacy `config-N` dir and warns the user to relaunch.
- Add auto-archival of legacy `.credentials.json.bak` files created during legacy swaps (they accumulated in `config-N/`). Not critical.

### Existing `term-*` dirs on upgrade

The first upgrade should not find any `term-*` dirs because they did not exist pre-spec. If found (future upgrade from a prior handle-dir version), the daemon sweep handles them as orphans.

## 2.7 Cross-references and retractions

This spec supersedes and partially retracts:

- **Journal 0029 Finding 1** ("Slot Number != Account Number"): Still correct in principle, but the new model makes the slot/account distinction IRRELEVANT for the swap path. Handle dirs carry the `.csq-account` marker (via symlink) which is always correct because the symlink points to the real canonical marker. Slot number confusion cannot arise when there are no slots — only permanent account dirs and ephemeral handle dirs.
- **Journal 0029 Finding 2** ("Subscription Contamination"): Still correct, but the guards at two sites (`rotation::swap_to` and `broker::fanout::fan_out_credentials`) collapse to ONE: the daemon refresher's write path into `config-<N>/.credentials.json`. csq swap no longer writes credentials at all, so it cannot contaminate. Fanout no longer exists as a separate concern — writing to `config-<N>` IS the fanout because all handle dirs see it through symlinks.
- **Journal 0029 Finding 4** ("Stale Session Detection"): RETRACTED entirely. See journal 0031 and spec 01 section 1.4. The `needs_restart` field in `SessionView`, the 5-second grace period, and the `SessionList.svelte` restart badge all must be deleted.
- **Journal 0018** (tray swap targets the single most-recent config dir): The tray swap mechanism must be reconceived. In the handle-dir model, the tray menu lists accounts, not config dirs, and a click targets the most-recently-active terminal (identified by PID or by a running-session-list query) rather than a mtime heuristic on credentials files. This is scoped to a follow-up; the retraction of the current behavior must be journaled.
- **Gap-resolutions.md:635** ("Auto-rotation is per-terminal, each terminal may end up on different accounts"): RESTORED as architecturally possible. The new model makes this a first-class feature, not a gap.

## 2.8 What this spec does NOT cover

- The CLI surface of `csq swap` and `csq run` (flags, exit codes, output format). See spec 03.
- Daemon internals (refresh cadence, lock file management, subsystem lifecycle). See spec 04.
- Third-party providers (Z.AI, MiniMax) — they have their own per-slot `settings.json` files outside the OAuth flow. See spec 05.
- Per-surface on-disk layouts for providers that run a non-Claude-Code native CLI (Codex via `CODEX_HOME`, Gemini via `GEMINI_CLI_HOME`). See spec 07. Per-surface persistence carve-outs from INV-02 live there as INV-P04 and do not alter the base invariant for the `Surface::ClaudeCode` case.

## Revisions

- 2026-04-12 — 1.0.0 — Initial draft replacing the `config-N = slot` model with permanent `config-N` + ephemeral `term-<pid>` handle dirs. Retracts journal 0029 Finding 4 via journal 0031.
- 2026-04-21 — 1.0.1 — §2.8 cross-reference added for spec 07 (Provider Surface Dispatch). INV-02 remains unchanged for the `Surface::ClaudeCode` case; per-surface carve-outs for Codex and Gemini are spec 07's responsibility and reference this spec as the base model. No invariant changes in this file. Journaled in workspaces/codex/journal/0001.
