# 03 csq Session Lifecycle

Spec version: 1.4.1 | Governs: `csq run`, `csq swap`, `csq login`, `csq exit` — CLI surface and state transitions

---

## 3.0 Scope

This spec defines the user-visible CLI commands that create, switch, and tear down csq terminal sessions. It assumes the handle-dir model from spec 02 and the Claude Code credential behavior from spec 01.

## 3.1 State diagram

```
           csq login N                      csq exit / process death
              ↓                                     ↓
   ┌─────────────────┐   csq run N    ┌──────────────────────┐
   │  no account     │ ──────────────→│  running terminal    │
   │  (fresh system) │                 │  term-<pid> → N      │
   └─────────────────┘                 └──────┬───────────────┘
              ↑                                │
              │                                │ csq swap M
              │                                ↓
              │                         ┌──────────────────┐
              └─────────────────────────│  term-<pid> → M  │
                                         └──────────────────┘
                                               │
                                               │ csq swap K …
                                               ↓
                                          (any other account)
```

Account dirs `config-<N>/` are created on login and persist forever. Handle dirs `term-<pid>/` are created on `csq run`, repointed on `csq swap`, and deleted on process exit.

## 3.2 `csq login N`

**Purpose:** provision account N — perform the OAuth flow and establish the canonical credentials file.

**Preconditions:**

- `N` is a valid account number (1..=999 per `AccountNum`).
- `config-<N>/` may or may not exist.

**Actions:**

1. Create `config-<N>/` if missing. Populate with shared-item symlinks via `session::isolate_config_dir`.
2. Ensure `settings.json` exists with a default template (if missing).
3. Delegate OAuth to Claude Code: set `CLAUDE_CONFIG_DIR=config-<N>` and run `claude auth login`. Claude Code handles the browser flow and writes the new credentials to `config-<N>/.credentials.json` (macOS: primarily to the keychain; file falls out of the fallback storage path if not already present).
4. On successful exit of `claude auth login`, csq verifies the credentials file is present and valid.
5. Seed `identities/<UUID>/credentials.json` (Anthropic) via `save_uuid_credentials` — the canonical write target. Mirror the credentials to `credentials/<N>.json` (compat-reader path).
6. Update `profiles.json` with the account label (email, display name).
7. Run `identity_mint::mint_for_login` (under `ProfilesFileLock`) to seed `profiles.json::by_slot[N] = <UUID>` + `by_email[email] = <UUID>` + `identities/<UUID>/identity.json` if not already present.
8. Write `.csq-account` marker. **Marker content semantic:** when `profiles::resolve_slot_to_uuid(base, N)` returns `Some(uuid)` (the post-mint normal case), the marker content is the slot's identity UUID via `markers::write_csq_account(config_dir, uuid)`. Pure-legacy installs where `mint_for_login` failed or was skipped fall back to the decimal slot id via `markers::write_csq_account_legacy(config_dir, account)`. The filename `.csq-account` is invariant (flip content only, never rename the marker file). The marker write happens AFTER step 7 so the UUID is resolvable.
9. Signal the daemon (POST to `/api/provision` on the Unix socket) to start refresh and usage polling for account N.

**Output:** `Account N provisioned — email <email>, subscription <tier>`.

**Idempotency:** safe to re-run on a provisioned account. Re-auth updates tokens in place. `config-<N>/` is never recreated or deleted on re-login.

**MUST NOT:**

- Write to any `term-<pid>/` handle dir. Login operates at the account tier only.
- Read `CLAUDE_CONFIG_DIR` from the environment — login operates on a specific N passed on the command line.

## 3.3 `csq run N`

**Purpose:** launch a new `claude` process bound to account N.

**Preconditions:**

- `config-<N>/` exists and has valid credentials (`csq login N` was run at some point).
- Account N is not in LOGIN-NEEDED state.

**Actions:**

1. Capture the csq CLI PID (`std::process::id()`).
2. Create handle dir `accounts/term-<pid>/`. This directory MUST be created via `std::fs::create_dir` (not `create_dir_all`) to catch collisions — a collision indicates a PID reuse bug or an orphan from a failed prior launch.
3. Populate handle dir (`csq-core/src/session/handle_dir.rs::create_handle_dir`):
   - Account-bound symlinks (`ACCOUNT_BOUND_ITEMS`, repointed on swap): `.credentials.json` → `identities/<UUID>/credentials.json` when `profiles.json::by_slot[N]` resolves a UUID, falling back to `../config-<N>/.credentials.json` for pure-legacy layouts; `.csq-account`, `.current-account`, `.quota-cursor` → `../config-<N>/<item>`.
   - `settings.json` is NOT a symlink — it is materialized as a real file by `handle_dir::materialize_handle_settings`, a deep-merge of `~/.claude/settings.json` (user-global customization) with `config-<N>/settings.json` (slot-specific overlay). A bare symlink would drop the user layer because `CLAUDE_CONFIG_DIR` overrides the home settings path.
   - `.claude.json` is NOT created — Claude Code writes per-project state (the `projects` map) into it, and sharing config-N's copy leaks project history across directories (breaks `--resume` CWD scoping). Claude Code creates a fresh one per handle dir.
   - Shared-item symlinks for every entry in `session::isolation::SHARED_ITEMS` (`csq-core/src/session/isolation.rs` — `projects`, `sessions`, `history`, `commands`, `skills`, `agents`, `rules`, `mcp`, `plugins`, `todos`, and the rest of the list), all pointing at `~/.claude/<item>`.
4. Write `.live-pid` to the handle dir. Content: the csq CLI PID as decimal ASCII.
5. Strip sensitive env vars (`ANTHROPIC_*`, `CLAUDE_CODE_OAUTH_TOKEN`, etc.).
6. Set `CLAUDE_CONFIG_DIR=<absolute path to accounts/term-<pid>>` in the child env.
7. On Unix: `exec claude [args...]`. The csq CLI process is replaced; `claude` inherits the same PID that matches the handle dir name.
8. On Windows: `spawn claude + wait`, then remove the handle dir on exit.
9. On exec failure (Unix) or spawn failure (Windows): remove `term-<pid>/` before exiting with the error.

**Post-launch cleanup:**

- On Unix the exec replaces csq's process image. There is no "after" for csq to run cleanup in. Handle dir removal is the responsibility of the daemon sweep (spec 02 section 2.5) which fires on `.live-pid` becoming invalid.
- On Windows csq waits for the child and removes the handle dir in its own cleanup block.

**Output:** `Launching claude for account N...` (before exec), then Claude Code takes over the terminal.

**MUST:**

- Use `create_dir` (not `create_dir_all`) to detect collisions.
- Verify the directory did not exist before creation. If it does (orphan from a previous crash with the same PID), log a warning and sweep-remove it before proceeding.
- Set `CLAUDE_CONFIG_DIR` to an ABSOLUTE path. Claude Code uses this value as its config dir path and as input to the keychain service name hash; a relative path would resolve differently from different working directories.

**MUST NOT:**

- Create a handle dir with a name other than `term-<pid>`. The naming scheme is load-bearing for the sweep logic.
- Write any real file content into the handle dir other than `.live-pid` and the materialized `settings.json` (step 3). Everything else csq creates is a symlink (`.claude.json` is real but Claude-Code-created).

## 3.4 `csq swap M`

**Purpose:** switch THIS terminal to account M without affecting sibling terminals.

**Preconditions:**

- `CLAUDE_CONFIG_DIR` is set and points at `accounts/term-<pid>/` under the csq base dir. **NOT a legacy `config-<N>/` path.**
- `config-<M>/` exists and has valid credentials.
- Account M is not in LOGIN-NEEDED state.

**Actions:**

1. Resolve the handle dir from `CLAUDE_CONFIG_DIR`. Canonicalize to protect against path traversal.
2. Verify the handle dir is a `term-<pid>` dir under the csq base. If it's a `config-<N>/` path, refuse with the legacy-mode error (section 3.7).
3. Verify account M is provisioned. If not, refuse with `account M not provisioned — run csq login M`.
4. Verify account M is not in LOGIN-NEEDED state. If it is, refuse with `account M needs re-login — run csq login M`.
5. For each symlinked file in the handle dir (`.credentials.json`, `.csq-account`, `settings.json`, `.claude.json`, `.quota-cursor`):
   - Construct the new target: relative path `../config-<M>/<same-filename>`.
   - Create a new symlink at a temp path inside the handle dir (e.g. `.credentials.json.swap-tmp`).
   - Atomically rename the temp symlink onto the existing symlink (`std::fs::rename(tmp, final)`).
6. Notify daemon via `POST /api/invalidate-cache` on the Unix socket. Best-effort; silent on failure.
7. Print: `Swapped to account M — token valid <mins>m`.

**Output:** `Swapped to account M — token valid 234m`.

**Post-swap behavior (non-actionable, for user understanding):**

- The running `claude` process in this terminal has NOT been restarted. It has a memoized OAuth token from account N (the previous account).
- On the NEXT API call (typically the user's next message or tool invocation), Claude Code runs `invalidateOAuthCacheIfDiskChanged` which stats `.credentials.json` via the symlink. The symlink now resolves to `config-<M>/.credentials.json`, a different file with a different mtime. Claude Code's cache clears and it reads the new tokens. The API call goes out as account M. See spec 01 section 1.4.
- Other `claude` processes in other terminals are not affected in their account binding — their handle dirs' symlinks still resolve to their own current accounts. The swap bumps the new target's mtime as part of `repoint_handle_dir`; sibling terminals already bound to the swap **target** account M will see the bumped mtime on their next Claude Code stat and reload identical credentials (one-time, no semantic change). See spec 02 INV-04 §"Sibling-terminal narrowed invariant".

**MUST:**

- Perform the symlink replacement atomically. Use `rename(2)` over an existing symlink — NOT `unlink` followed by `symlink`, which races.
- Preserve all symlinks in the handle dir that are not account-bound (shared items like `history`, `sessions`, etc.) — those always point at `~/.claude/<item>` regardless of which account the handle dir is currently on.

**MUST NOT:**

- Write to `config-<M>/.credentials.json` or any other file under `config-<M>/`. Swap is symlink-only.
- Write to `config-<current>/` (the previous account). Leave its state untouched.
- Use `remove_file` + `symlink` for the replacement — the gap between the two calls is a race that leaves the handle dir with a broken state if the process is killed mid-swap.

## 3.5 `csq exit` (optional)

**Purpose:** clean up the handle dir for the current terminal when the user exits their Claude Code session.

**Preconditions:** run inside a csq-managed terminal.

**Actions:**

1. Resolve the handle dir from `CLAUDE_CONFIG_DIR`.
2. Verify it is a `term-<pid>` dir under the csq base.
3. Remove the handle dir.
4. `exit 0`.

**Relationship to `claude` termination:**

- If the user exits `claude` normally (Ctrl-D, `/exit`), the shell returns. If they run `csq exit`, the handle dir is cleaned up. If they don't, the daemon sweep (spec 02 section 2.5) cleans it up on the next tick.
- The daemon sweep is the authoritative cleanup mechanism. `csq exit` is an optional user-facing convenience.

**MUST NOT:**

- Fail loudly if the handle dir has already been removed (e.g. by a prior sweep). Exit cleanly.

## 3.6 `csq status` and `csq statusline`

Both commands are read-only:

- `csq status` reads `quota.json`, `profiles.json`, and the daemon `/api/accounts` endpoint. Writes nothing.
- `csq statusline` reads `quota.json` and the current handle dir's `.csq-account` marker (via symlink). Writes nothing. Governed by rule 2 of `account-terminal-separation`.

## 3.7 Error: legacy mode

The `rotation::swap_to` writer does not exist in any code path. The pre-handle-dir swap mode that rewrote `config-<N>/.credentials.json` in place to forcibly move every terminal bound to that config dir is fully retired. The legacy refusal is the ONLY path when `csq swap` is invoked inside a terminal whose `CLAUDE_CONFIG_DIR` points at a `config-<N>/` (a terminal launched by a pre-handle-dir csq binary that the user has not yet relaunched).

The refusal threads the user-typed target slot `M` into the suggested `csq run` command so the hint is copy-pasteable:

```
error: this terminal was launched in legacy per-account mode; swap would affect all terminals on config-<N>.
Relaunch with: csq run M
```

This refusal is wired in `csq/src/cli/commands/swap.rs::detect_source_handle`. There is no `--force` flag because the legacy behavior (affecting all terminals) is no longer an intended mode in any current csq version. Users who actually want the old behavior can run a pre-2.x csq.

**Desktop dashboard swap:** there is none — the desktop offers no swap affordance. Desktop surfaces are status/management-only and `csq swap N` inside a terminal is the only swap entry point. See spec 02 §2.6.

## 3.8 Observability

Each command SHOULD emit structured log events (via `tracing`) with these fields:

- `command`: literal string (`csq.run`, `csq.swap`, `csq.login`, `csq.exit`).
- `account`: the target account number.
- `handle_dir`: the absolute path of the handle dir (for `run`, `swap`, `exit`).
- `latency_ms`: elapsed time from invocation to success (for swap, specifically).
- `error_kind`: fixed vocabulary on failure, never raw error text.

Log events MUST NOT contain tokens, keychain payloads, or OAuth response bodies. See the security rules and spec 01 section 1.7 for the redaction contract.

## 3.9 Exit code reservations

The `csq` CLI exit-code space is partitioned to keep csq's own failures distinguishable from upstream Claude Code CLI failures and from POSIX standard codes.

| Range | Owner    | Allocation                                                                                                                                                                                                                                                           |
| ----- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | csq      | Success.                                                                                                                                                                                                                                                             |
| 1     | csq      | Generic failure (legacy; new code paths use a more specific code).                                                                                                                                                                                                   |
| 2     | csq      | Argument-parse / usage error (clap default).                                                                                                                                                                                                                         |
| **3** | csq      | `EXIT_CODE_AUDIT_WRITE_FAILED` — a fail-loud audit write failed: even the `.pending/` fallback write was unwritable, so the audit record would be lost silently. Surfaced by `fail_loud_on_audit_write_failure` in `csq/src/cli/commands/run.rs`. See spec 12 §12.4. |
| 4–125 | reserved | Held for future csq-CLI-specific failures (handle-dir, daemon IPC, OAuth). Allocate one code per error class.                                                                                                                                                        |
| 126   | shell    | Command invoked cannot execute (POSIX).                                                                                                                                                                                                                              |
| 127   | shell    | Command not found (POSIX).                                                                                                                                                                                                                                           |
| 128–  | shell    | Fatal-signal exit (`128 + signo`).                                                                                                                                                                                                                                   |

A user or harness inspecting `echo $?` after `csq run` can distinguish a csq-CLI-shaped failure from an upstream-CLI-shaped one. Claude Code's CLI exit semantics (codes 0, 1, 2 as documented at `claude --help`) remain untouched on the pass-through path.

## 3.10 Cross-references

- `specs/01-cc-credential-architecture.md` — the Claude Code mtime-reload mechanism that makes swap in-flight (section 1.4).
- `specs/02-csq-handle-dir-model.md` — the on-disk layout and invariants (sections 2.1-2.6).
- `specs/04-csq-daemon-architecture.md` — the daemon sweep, provisioning, and refresh subsystems.
- `account-terminal-separation` — enforcement of the quota and identity rules across this CLI surface.
- `csq/src/cli/commands/run.rs`, `csq/src/cli/commands/swap.rs`, `csq/src/cli/commands/login.rs` — the implementation sites that MUST match this spec.
- `csq/src/cli/commands/run.rs` — `EXIT_CODE_AUDIT_WRITE_FAILED` (code 3) constant and `fail_loud_on_audit_write_failure` materialize the §3.9 code-3 row in code.
- `specs/12-audit-trail.md` §12.4 — the fail-loud audit-write contract that owns exit code 3.
