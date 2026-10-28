# 03 csq Session Lifecycle

Spec version: 1.5.5 | Governs: `csq run`, `csq swap`, `csq login`, `csq unlock`, `csq exit` — CLI surface and state transitions

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

1. Allocate a fresh `accounts::credential_transaction::VendorLoginGrant` and retain the same `Arc<Mutex<VendorLoginGrant>>` in the actual child owner's keepalive. The vendor home is `<base>/.login-grants/grant-<UUID>/`, private mode 0700 on Unix; it is not `config-<N>/`.
2. Persist `VendorLoginGrant::begin_launch` before actual spawn. Delegate OAuth using `CLAUDE_CONFIG_DIR` set to that private home, with no canonical session/history links. Claude owns the browser flow and writes its grant only in that home or its unique home-derived keychain service.
3. Require positive actual-child-exit and captured-reader-EOF/join completion under the custody rules below. Timeout or cancellation cannot authorize publication even if the vendor exits zero later; unknown custody retains the grant and names its quarantine path.
4. Read the fresh credential with `credentials::read_fresh_after_login` from the isolated vendor home, including its unique keychain service where applicable. A missing, malformed or expired grant refuses publication.
5. Atomically seal publication immediately before the first canonical write, then mint the slot identity through `accounts::login::ensure_login_identity_minted` and save through `accounts::login::save_login_credentials` and `credentials::file::save_canonical_for`. The Anthropic canonical target is `identities/<UUID>/credentials.json`; no unpublished raw grant is copied into the known slot credential path.
6. Perform the existing slot config/session preparation and UUID `.csq-account` marker writes only inside the admitted post-seal finalization. Existing canonical state is not a pre-seal vendor home.
7. Complete the existing profile/bookkeeping and optional fresh-grant delivery finalization. Canonical save does not certify that a running vendor adopted the token.
8. Mark the private grant complete only from the positive actual completion receipt, then clean its unique home and home-derived keychain service under the cleanup rules below. Unconfirmed cleanup reports its exact quarantine path rather than claiming the grant was removed.
9. Notify the daemon via `notify_daemon_cache_invalidation` and `POST /api/invalidate-cache`; polling/refresh admission remains the daemon's responsibility.

**Output:** `Account N provisioned — email <email>, subscription <tier>`.

**Idempotency:** safe to re-run on a provisioned account. Re-auth updates tokens in place. `config-<N>/` is never recreated or deleted on re-login.

### Vendor sign-in custody

`run_claude_auth_login` in `csq/src/cli/commands/login.rs` uses
`login_subprocess_timeout`: 300 seconds by default, or a positive
`CSQ_LOGIN_TIMEOUT_SECS`. Empty, invalid and zero values select the default;
an unrepresentable deadline refuses spawn authorization. Claude, Codex and
native Kimi/Grok sign-ins use `DeliveryPhase::Unknown` in
`csq/src/login_child_custody.rs`: elapsed time and opaque vendor output do not
prove that credential delivery has not begun. A deadline refuses publication,
including after a late exit zero, but never authorizes killing a vendor.

On Unix each vendor starts in its own process group. `GroupControl` in
`csq/src/login_child_custody/group.rs` retains an unreaped leader as the PGID
lease while group signaling is possible. The first Ctrl-C latches cancellation
and forwards SIGINT to that group while keeping custody. A second Ctrl-C
explicitly authorizes group SIGKILL, bounded captured-reader EOF and join, and
then actual leader reap. Desktop confirmed End sign-in authorizes that same
owned-group stop. Sibling operations are not targets. SIGTERM, SIGHUP and SIGQUIT
also atomically latch cancellation and forward their respective signal to the
owned group once. Those signals do not bypass the publication boundary below.

Normal completion requires the direct child's actual exit and EOF/join of every
captured reader; it does not require proof that the whole group is gone. With
no explicit stop or exceptional observation failure, csq never kills remaining
members. A known remaining-member count may be reported only as
`login_group_members_remaining=N`; it does not deny an otherwise authorized
normal completion. A vendor descendant that closes captured pipes and continues
as a daemon is the vendor's lifecycle, not an implicit csq stop request.

A positive vendor-finalized receipt belongs to the exact same operation and
records actual child reap plus every captured reader's EOF/join. If cancellation
arrives before the publication seal after that receipt, it still latches refusal
and waits for that operation's finalization/registration retirement, but does
not signal or census the already-reaped numeric PGID. The running-to-finalized
transition and the cancellation stop decision are covered atomically, so a
concurrent completion cannot turn that PGID into a later signal target. An
absent wait lease, ECHILD or ESRCH is not this positive receipt and never by
itself establishes successful completion. Bare unresolved custody remains an
actual unknown-custody refusal; the post-seal commit and best-effort rescue
boundaries below are unchanged.

For a running vendor requiring a second Ctrl-C, confirmed End sign-in or
authorized observation-failure stop, the order is retained unreaped leader/PGID lease, group signal, bounded
captured-reader EOF and join, then leader reap. Group disappearance afterwards
is best-effort evidence, not a completion precondition. A non-atomic Linux
membership census does not prove absence. Its receipt is exactly
`group membership after kill: not proven`. Cancellation still terminates with
refusal, exit 130 and no pre-seal publication; it must not become an infinite
wait for an unprovable all-members-gone result.

ECHILD immediately refuses publication and invalidates the wait/signal lease;
csq does not signal a potentially reused PGID. Three consecutive other wait
errors authorize stopping only the owned group and a bounded drain/reap attempt.
If custody cannot be resolved, the error explicitly names the PGID and
UNDETERMINED custody, refuses publication and does not silently drop a live
Child. The same bounded error policy applies during unwinding. Normal exit,
reader completion and best-effort group-membership evidence are distinct facts.

`spawn_cli_login`, `spawn_cli_inherited_login` and `spawn_cli_piped_login` in
`csq/src/login_cancel_guard.rs` share the scoped cancellation owner; the piped
path also owns the stdout reader. `print_cli_notice` explains that the sign-in
program is still running and says `press Ctrl-C to request cancellation, then
Ctrl-C again to end its process group`. This is CLI advice. The guard remains
installed through finalization as specified below.

Windows uses an owned Job for termination and CTRL_BREAK_EVENT for the
interrupt request; CTRL_BREAK_EVENT is not Unix SIGINT. Ctrl-C/Ctrl-Break console
callbacks latch explicit cancellation. CTRL_CLOSE, logoff and shutdown callbacks
are outside the robust-custody guarantee because the operating system imposes
termination deadlines. Native Windows runtime behavior is not established by a
Unix test or cross-compilation result.

### Unpublished vendor grant isolation

Claude and Codex share `VendorLoginGrant` in
`csq-core/src/accounts/credential_transaction.rs`. Every attempt uses a fresh
0700 Unix directory `<base>/.login-grants/grant-<UUID>/` and a shared
`Arc<Mutex<VendorLoginGrant>>`. The actual child owner's keepalive retains the
same Arc; an outer function returning is not proof that the vendor writer has
finished. On UNDETERMINED custody the keepalive/quarantine remains retained and
`VendorLoginGrant::quarantine_message` identifies the exact path.

The private `lease.json` records `Created`, `Spawning` or `Complete`, the exact
owner PID and birth from `sessions::ancestor_start`, and a no-follow kernel file
lease excludes simultaneous cleanup. `begin_launch` durably records `Spawning`
before actual spawn. Only a positive receipt of actual child reap and every
captured reader's EOF/join permits `mark_completed`; a timeout, guessed PID state
or return from an unknown-custody path is insufficient. As defined above, normal
completion does not require a whole-group-gone census.

`VendorLoginGrant::sweep` may remove only a positively safe `Created` or
`Complete` grant whose exact owner is gone and whose kernel lease is free.
`Spawning`, live/same-birth, busy-lease, unknown owner/birth, malformed/unreadable
records and unsupported absence observations are KEEP. A changed birth or typed
absence establishes owner disappearance; a bare PID guess or process-name census
does not. A crash across spawn remains quarantined behind the durable Spawning
fence. Cleanup clears only the unique home's keychain service and private home;
unknown cleanup retains the path and reports refusal explicitly.

Before the publication seal, neither provider exposes canonical auth, sessions,
history or caches to the vendor. Codex reads and writes `config.toml` and
`auth.json` in the same supplied `CODEX_HOME` private home. Existing
`config-<N>/auth.json` and `config-<N>/config.toml` remain byte-identical on refusal
or UNDETERMINED custody. Successful publication still uses the sealed UUID
publisher; full-success cleanup may retire the old known raw auth path, but no
new unpublished grant is persisted there. Timeout never authorizes a kill.

### Desktop unresolved-custody IPC

Before actual Claude or Codex spawn, `ChildRegistration::bind_quarantine` in
`csq/src/desktop/login_custody.rs` binds the home-relative sanitized message from
the exact same `VendorLoginGrant` retained by that operation's actual child
keepalive. The backend derives it from `VendorLoginGrant::quarantine_message`
and `cli_deps::sanitize::redact_display`; it does not accept a renderer path or
scan the filesystem for a candidate grant.

If actual custody becomes UNDETERMINED, the identity-bound cancellation IPC
returns the String error
`login_group_custody_unresolved: vendor_login_quarantined: <path>`, where `<path>`
is the bound home-relative location. This is refusal, not a successful end of
the program. The same child keepalive, Spawning lease and backend operation
registration remain retained; this observer error introduces no cleanup action.

`cancel_child_with_confirmation` rechecks actual unresolved custody while
awaiting registration retirement. Its 200 ms observation tick only wakes that
check; it never signals a child, kills a group, cleans a grant or changes
publication authorization. The user can receive the explicit refusal without
waiting indefinitely for another registration notification.

`AddAccountModal.svelte` recognizes the tagged sanitized home-relative path and
renders it as plaintext in its visible error alert. The operation remains
pending: unresolved cancellation does not report ended/success, refresh accounts
as if a login committed, or dismiss the modal. Later attempts use the same
backend operation identity. Unrelated errors remain generic; this message is
neither a renderer-controlled filesystem target nor permission to remove a grant.

### Login publication and cancellation boundary

This boundary applies to Claude, Codex and native Kimi/Grok login producers in
both CLI and desktop. Vendor completion does not release cancellation custody:
the guard/latch stays live through account finalization. Immediately before the
first canonical write, one atomic publication seal orders cancellation against
commit admission. `ScopedLoginCancellation::seal_publication` and
`with_cli_login_session` in `csq/src/login_cancel_guard.rs` retain CLI custody;
`ChildRegistration::seal_publication` and `mark_committed` in
`csq/src/desktop/login_custody.rs` provide the desktop boundary.

- Cancellation before the seal refuses publication: no canonical credentials,
  identity/profile registration or new native binding marker is committed. The
  operation drains retained writers and handles its uncommitted vendor grant
  under the refusal-cleanup policy; uncertain custody never authorizes commit.
- Cancellation after the seal does not interrupt the admitted crash-consistent
  finalization. The account commit finishes; CLI then exits 130 with
  `login_committed_cancelled: account <N> WAS signed in before cancellation;
  sign-in finalization completed`. Desktop reports the `COMMITTED_CANCELLED`
  result as a committed account sign-in with cancellation rather than an
  unpublished refusal.

The handler is restored only after refusal cleanup or admitted finalization.
Handler failure is explicit and cannot turn a pre-seal refusal into permission
to publish. Existing credential-write and crash-recovery rules govern commit;
this boundary adds no alternative credential store or finalization protocol.

### Desktop update and restart custody

Renderer-driven install and restart enter trusted backend commands
`install_update_with_custody` and `restart_with_custody` in
`csq/src/desktop/commands/update_custody.rs`. A command authorizes the trusted
main window and acquires `login_custody::begin_update` before update effects.
The canonical `UpdateLease` closes new sign-in admission and retains that
closure while registered vendor operations and admitted credential writers
finish. Install and process replacement occur only after verified drain.

The renderer receives `UpdateProgress` over the command's IPC channel.
`WaitingForSignIn` displays the live pending operations; the user may finish
sign-in or use the same operation-identity-bound, backend-confirmed cancellation
commands as the Add Account flow. The update continues when the gate is free;
it does not independently kill a login to meet an update deadline. Losing the
renderer observer does not discard the backend-owned task or its lease.

The default main-window capability does not grant `updater:allow-check`,
`updater:allow-download-and-install`, `process:allow-restart` or
`process:allow-exit`; otherwise raw plugin IPC could bypass this admission/drain
boundary. App-command enrollment supplies the trusted wrappers and the pending
login/cancellation commands. A no-update result or a verified pre-restart failure
explicitly releases the lease. Unverified installer completion keeps admission
closed and reports an explicit error; requesting restart retains the closed
lease through process replacement. Existing edition admission, update-channel
selection, signature verification and signing keys retain their own contracts.

**MUST NOT:**

- Write to any `term-<pid>/` handle dir. Login operates at the account tier only.
- Read `CLAUDE_CONFIG_DIR` from the environment — login operates on a specific N passed on the command line.

### 3.2.1 Login-lock recovery (`csq unlock N`)

Login paths using `accounts::login_lock::AccountLoginLock::acquire` serialize
per-slot login work with the OS lock and holder metadata specified in spec 02
§2.1.2. An OS-held lock refuses a contender even when its sidecar is missing or
names an apparently dead PID. Windows contention guidance names the recorded
holder when available and tells the operator to wait for the owning login to
finish; it does not advise force termination or bypassing the lock.

On Windows, `csq unlock N` calls `accounts::login_lock::force_release` without
termination authority. `--yes` cannot override its identity or exclusion checks.
The core ignores the `kill` argument on Windows and never calls a termination API
for login-lock recovery. With both lock and sidecar absent, recovery is a no-op.
Otherwise it requires exclusive ownership of the stable OS lock and a valid
Windows sidecar before checking the holder.

Recovery is authorized by mutual exclusion, not by exit proof: `csq unlock N`
must hold the stable OS lock exclusively, and holding it alone proves no
conforming login holder can be live. The sidecar must still carry valid
versioned metadata (nonzero PID, process-creation FILETIME, nonempty NUL-free
UTF-16 image); invalid metadata refuses before any process observation. Once the
lock is held, the recorded holder is cleared when its process has exited, when
the PID now names a different creation FILETIME (reuse), or when the process
cannot be opened or queried at all. Only a LIVE process carrying the recorded
creation FILETIME refuses; that state contradicts the held lock and is reported
as a lock-semantics violation. The retained lock file is preserved. Successful
Windows reports have no killed PID and list only the sidecar as removed; the CLI
reports stale metadata cleanup and a login retry, never that it stopped a
process.

A held OS lock comes first: it proves a conforming holder is live, so no
observation runs and nothing clears. After the lock is held, a LIVE process
carrying the recorded birth time, invalid sidecar metadata, an
absent/malformed/unreadable sidecar or a legacy PID-only record MUST refuse
without clearing metadata. PID reuse with a different birth time, an exited
process and an open/query failure are the gone-holder cases the held lock
authorizes clearing. Refusal identifies the recorded PID when readable,
otherwise an unknown holder. A retained lock file with no sidecar is not
cleanup authority.

Ordinary `csq login N` is safe recovery for stale unverifiable metadata when the
OS lock is free: successful acquisition replaces the record with the new writer's
own known identity. It does not infer identity from the stale PID or remove the
stable lock file. Unix login-lock recovery and decimal sidecars are unchanged.

Source: `csq-core/src/accounts/login_lock.rs::{inspect_lock,force_release,
force_release_windows_with,WindowsProcess::{open,identity,exited}}` and
`csq/src/cli/commands/{login.rs::acquire_login_lock,login.rs::kill_hint,
unlock.rs::handle}`. These source contracts do not certify native Windows
execution, installation or live-session behavior.

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

### 3.3.1 Owner-configured provider launch posture

The shared admission policy covers `csq run`, `csq exec`, exec-replace swaps and
supervised relaunch. It reads `<csq-base>/provider-session-policy.json` and, when
an enclosing primary checkout is identified, that outermost primary owner's
`.coc/csq.json`. A linked checkout outside a primary checkout does not supply
repository policy. Subdirectory or nested-repository configuration cannot replace
the outer primary owner's policy.

Both files use a `provider_session` object. `primary_checkout` selects `allow`,
`warn` or `refuse`; absence defaults to `allow`. The global posture is a floor:
repository policy may tighten it, but cannot weaken a restrictive global posture,
add trusted destinations or re-enable loopback trust. The global-only
`allow_repo_relax: true` explicitly permits those relaxations. When the global
posture is `allow` or absent, a repository may tighten it and choose its own trusted
origins. Repository trust lists replace rather than union with the global list;
under a restrictive floor, entries outside the global exemptions are removed.

`trusted_endpoints` contains credential-free HTTP(S) origins. Trust compares
scheme, host and effective port, never a model/provider label. The HTTPS Anthropic
API origin is admitted. Loopback trust is a removable default: an explicit trust
list removes it unless `trust_loopback: true` explicitly restores it;
`trust_loopback: false` disables it. Exact loopback origins can still be listed
individually. A loopback proxy can forward data elsewhere; trusting its origin
is an owner decision, not a data-residency or filesystem-isolation guarantee.

Admission classifies the effective start directory from supported directory
argument forms, including Codex `-C`/`--cd` and `--work-dir`/`--cwd` forms handled
by the shared guard. Malformed start-directory input is unresolved. The actual
Codex `csq exec` cwd is its supplied Claude-home directory. Discovery and project
settings walks use canonical paths; an enclosing primary checkout remains
protected even when the nearest Git marker belongs to a nested checkout. Linked
worktree registration/backlinks must agree. Admission governs where a session
starts and does not restrict its subsequent filesystem access.

Claude admission checks global/UUID/legacy inputs and materialized settings.
It composes project settings from the canonical project root toward the effective
start directory, applying `settings.json` before `settings.local.json` at each
directory, then managed settings and sorted managed fragments. Admission evaluates
each cumulative environment, so transport selection in one file cannot hide an
untrusted endpoint supplied by another. Trusted project candidates are admitted
without an additional precedence warning. Managed settings use the
vendor's system locations and bounded `managed-settings.d/*.json` fragments.
These are candidate checks; non-file managed policy and later vendor changes are
not certified. CLI settings overrides remain unresolved. Bedrock, Vertex and
Foundry candidates can be trusted using their explicit documented
`ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL` and
`ANTHROPIC_FOUNDRY_BASE_URL` origins. Cloud routing without such a base URL, or
with conflicting transport selectors, remains unresolved; csq does not inspect
SDK profiles or probe endpoints to infer it. The direct native harness checks its
actual catalog endpoint; other vendor destinations remain unresolved.

Invalid launch settings or endpoint decoding use the selected `warn`/`refuse`
unknown-destination posture. Selected malformed, oversized, symlinked or
nonregular policy files refuse because their posture cannot be trusted. Default
`allow` retains existing launch behavior. Diagnostics name
`provider_session.primary_checkout` and sanitized origins without credentials,
query strings or raw settings. Early checks precede handle creation and swap
teardown; terminal checks emit warnings once per spawn. `csq exec` returns
admission failures through its `SdkError` envelope before handle/keychain work.

Implementation: `run.rs::{provider_session_repository_context,admit_exec_provider_session,
admit_swap_provider_session}`;
`provider_session_policy.rs::{load_policy,check_claude_launch,
check_unknown_launch_with_args,effective_start_directory}`;
`exec.rs::run_exec`; `swap.rs::admit_materialized_claude_swap`.
Vendor references: [settings precedence](https://code.claude.com/docs/en/settings),
[managed settings](https://code.claude.com/docs/en/managed-settings),
[Bedrock](https://code.claude.com/docs/en/amazon-bedrock),
[Vertex](https://code.claude.com/docs/en/google-vertex-ai), and
[Foundry](https://code.claude.com/docs/en/microsoft-foundry).

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
| 130 | csq / shell | Explicit scoped login cancellation after actual child reap (`cli_error_exit_code`), or conventional SIGINT signal status. |

A user or harness inspecting `echo $?` after `csq run` can distinguish a csq-CLI-shaped failure from an upstream-CLI-shaped one. Claude Code's CLI exit semantics (codes 0, 1, 2 as documented at `claude --help`) remain untouched on the pass-through path.

## 3.10 Cross-references

- `specs/01-cc-credential-architecture.md` — the Claude Code mtime-reload mechanism that makes swap in-flight (section 1.4).
- `specs/02-csq-handle-dir-model.md` — the on-disk layout and invariants (sections 2.1-2.6).
- `specs/04-csq-daemon-architecture.md` — the daemon sweep, provisioning, and refresh subsystems.
- `account-terminal-separation` — enforcement of the quota and identity rules across this CLI surface.
- `csq/src/cli/commands/run.rs`, `csq/src/cli/commands/swap.rs`, `csq/src/cli/commands/login.rs` — the implementation sites that MUST match this spec.
- `csq/src/cli/commands/run.rs` — `EXIT_CODE_AUDIT_WRITE_FAILED` (code 3) constant and `fail_loud_on_audit_write_failure` materialize the §3.9 code-3 row in code.
- `specs/12-audit-trail.md` §12.4 — the fail-loud audit-write contract that owns exit code 3.


## Revisions

- 2026-10-19 — 1.5.5 — Isolated unpublished Claude/Codex grants, durable owner leases and positive completion receipts; retained canonical publisher and refusal byte preservation.

- 2026-10-19 — 1.5.4 — Defined owned vendor-group cancellation and bounded wait-error refusal; centralized cancellation versus publication-seal ordering for CLI and desktop sign-in.

- 2026-10-19 — 1.5.3 — Scoped terminal cancellation retains actual login custody through reap, restores the prior handler, refuses publication and exits 130; repeated interrupts do not escalate.

- 2026-10-19 — 1.5.2 — Corrected login’s daemon notification to best-effort cache invalidation and removed the phantom provisioning RPC.

- 2026-10-19 — 1.5.1 — The Claude vendor watchdog refuses timed-out login publication while retaining the foreground child and account lock through actual reap. Opaque authorization uses the unknown phase, with no automatic timeout stop.

- 2026-10-19 — 1.5.1 — Documented Windows login-lock recovery: bound PID/creation-time/image exit proof, strict unknown/live/mismatched-holder refusal, no termination or --yes override, retained lock identity and ordinary-login stale-metadata recovery. Unix behavior is unchanged; this source-contract revision does not certify native Windows execution, installation or live sessions.

- 2026-10-07 — 1.5.0 — Corrected §3.3.1 owner policy: SDK admission before
  handle/keychain work, effective CLI cwd, removable loopback trust, trusted project
  candidates, launch-decode unknown posture, restrictive global grant floor, outer
  owner retention, managed-file checks, canonical project walk and cumulative
  documented cloud routing. This revision does not certify installed native/vendor
  destinations, non-file managed modes, later vendor versions or Windows runtime.
