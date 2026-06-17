# 01 Claude Code Credential Architecture

Spec version: 1.1.0 | Status: DRAFT | Governs: how Claude Code reads, writes, caches, and invalidates OAuth credentials | Upstream: Claude Code CLI 2.1.104

---

## 1.0 Why this spec exists

Every csq design decision about credential handling depends on knowing exactly what Claude Code (CC) itself does. Prior credential bugs (stale-session detection, subscription contamination, slot-vs-account identity drift) were rooted in incorrect assumptions about CC's internal behavior. This spec eliminates the guesswork by documenting CC's published credential-reload behavior. When CC changes upstream (confirmed by a version bump of the installed binary), this spec must be re-verified before any code using it is modified.

The behaviors below reflect Claude Code CLI 2.1.104.

## 1.1 Configuration directory resolution

CC resolves its configuration directory from the `CLAUDE_CONFIG_DIR` environment variable, falling back to `~/.claude` when the variable is unset. The resolved value is memoized for the process lifetime, keyed on the env var.

**Derived facts:**

1. CC reads `CLAUDE_CONFIG_DIR` at process startup. If unset, it defaults to `~/.claude`.
2. The result is **memoized for the process lifetime**, keyed on the env var. CC cannot be made to change its config dir mid-process by mutating `CLAUDE_CONFIG_DIR` from inside CC itself (the memoization only re-runs when the key changes as observed at call time, and the call-time read goes through the same memoized getter).
3. CC cannot be made to change its config dir from outside the process at all — Unix env vars are copied at fork/exec and external mutation via `/proc` is not supported by the runtime and is blocked on macOS.
4. **Consequence for csq:** to put a terminal on a different `CLAUDE_CONFIG_DIR`, the `claude` process must be started with that env var set. csq's `csq run N` handles this at launch. Mid-process swap MUST operate through file-level changes inside the already-chosen dir, not by trying to swap the env var.

## 1.2 Credentials file path

CC stores its credentials at a fixed filename, `.credentials.json`, inside the resolved config directory.

**Derived facts:**

1. The credentials file path is literally `<CLAUDE_CONFIG_DIR>/.credentials.json`.
2. `fs.stat`, `fs.readFile`, and `fs.writeFile` calls against this path follow symlinks transparently (runtime default). This is the key fact that makes csq's handle-dir model work — a symlink in the handle dir resolving to a real file in `config-<N>` gives CC the same credentials it would have gotten if launched directly against `config-<N>`.
3. Exactly one file per `CLAUDE_CONFIG_DIR`. No per-process or per-session suffixing in CC.

## 1.3 Keychain service name derivation (macOS)

On macOS, CC derives the keychain service name it stores credentials under from the config directory path:

```
Default dir (no CLAUDE_CONFIG_DIR):  "Claude Code-credentials"
Custom dir:                          "Claude Code-credentials-<sha256(dir)[:8]>"
```

The hash is computed over the raw config dir path string (not canonicalized — resolving symlinks would change it). Only non-default directories get the hash suffix, preserving backwards compatibility for the default dir.

**Derived facts:**

1. **Default dir (`~/.claude`, no env var):** service name is `Claude Code-credentials`. No hash. All terminals launched without `CLAUDE_CONFIG_DIR` share one keychain entry.
2. **Custom dir:** service name is `Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR)[:8]>`. The hash uses the raw path string.
3. **Two distinct `CLAUDE_CONFIG_DIR` paths produce distinct keychain slots.** This is the mechanism that allows csq to run multiple accounts on one machine without keychain collisions.
4. **The keychain path is per-directory, not per-process.** Two `claude` processes launched with the same `CLAUDE_CONFIG_DIR` share one keychain slot.
5. **Consequence for csq:** handle dirs at different paths (`term-<pid-A>` vs `term-<pid-B>`) get different keychain slots even if they currently symlink to the same account's files. This is fine — the daemon owns the keychain for each handle dir it creates.

## 1.4 Credential reload via mtime check

Before every API call path, CC checks whether `.credentials.json` has changed on disk by comparing its modification time (mtime) against the last-seen mtime tracked in a per-process variable. If the mtime differs, CC clears its in-process OAuth token cache so the next read picks up the fresh file. If the file does not exist (the macOS keychain-only case), CC clears only its in-memory memoize and delegates to the keychain cache's TTL.

This reload exists to solve the multi-terminal case: one terminal's `/login` writes fresh tokens; a second terminal's `/login` then revokes the first server-side; without the mtime check, the first terminal's cache would never re-read, producing an infinite `/login` regress.

**Derived facts (CRITICAL — load-bearing for csq's swap semantics):**

1. **CC does NOT cache credentials forever at startup.** It caches them until the file mtime changes, then clears the cache on the next API call.
2. **The mtime is tracked per-process.** Each CC process has its own last-seen value. Two CC processes on the same config dir each track their own last-seen mtime.
3. **A write to `.credentials.json` from ANY process** (another CC instance, csq, the user, a shell script) triggers the reload in every CC process that subsequently runs its token check. The mtime comparison is an inequality test (not "newer than"), so even a backwards-seeming mtime (rare; atomic replace with preserved mtime) triggers reload.
4. **Missing-file branch:** if the file does not exist (pure-keychain case), CC clears only the memoize. The keychain cache 30-second TTL then bounds staleness — see section 1.5.
5. **Consequence for csq:** swap does NOT need to restart the CC process, send a signal, or do anything other than atomically change what `.credentials.json` resolves to. CC will pick it up via `fs.stat` within one API call.
6. **This reload behavior was added upstream specifically to solve the multi-terminal-sharing-a-config-dir case.** Cross-terminal credential sync is a designed feature of CC, not an accident.
7. **Implication for csq design:** any scheme that assumes CC pins credentials in memory at startup (and therefore needs a restart after a swap) is incorrect. Swap is in-flight by design; no restart, signal, or `needs_restart` badge is required.

## 1.5 Keychain read cache (30-second TTL)

On macOS, CC maintains a per-process cache of the value read from the keychain, with a 30-second TTL. Reads within the TTL window return the cached value without re-querying the keychain. On a failed keychain read, CC serves the previous value (stale-while-error) rather than caching a null.

**Derived facts:**

1. **Per-process cache, 30-second TTL.** Each CC process maintains its own keychain cache with a timestamp. Reads return stale data for up to 30 seconds.
2. **Writes from another process are not visible until the TTL expires** (or until something clears the keychain cache in this process — only the missing-file path and the 401 handler do that).
3. **Stale-while-error**: if the keychain read fails, the previous value is served with a fresh timestamp. This makes recovery from transient keychain failures graceful but means a terminal can serve stale creds beyond the 30-second window if the keychain is failing.
4. **Consequence for csq:** a pure keychain write with no file write gives other terminals up to 30 seconds of stale reads. For csq's handle-dir model this is not a concern because swap operates on the file-via-symlink, which is picked up instantly by the mtime check.

## 1.6 When the credential reload runs

CC runs the mtime/disk-change check inside its token-refresh routine, which is invoked from the API client path every time CC builds a new Anthropic client. `getAnthropicClient` is the entry point for all API traffic from the main CC process; the token check (and therefore the disk-change check) runs at the start of it.

A number of other subsystems (the main REPL, the bridge, voice streaming, the OAuth client, team-memory sync, remote/managed settings sync, settings sync, and remote-trigger tooling) also invoke the same token check. All of them trigger an mtime stat and cache clear on a credentials file change.

**Derived facts:**

1. **Every time CC builds a new Anthropic client**, the mtime check runs.
2. **Many subsystems beyond the API client** also run the token check, so a credentials change is observed through multiple code paths, not just one.
3. **Consequence for csq:** within one API call (and well under a second in practice), CC picks up a new `.credentials.json` written externally. csq swap's latency upper bound is the user's next keystroke plus CC's normal API call startup, not a restart cycle or a poll interval.

## 1.7 OAuth token write path

When CC saves OAuth tokens, it writes through a secure-storage abstraction. On macOS the primary backend is the keychain with the plaintext file as fallback; on Linux/Windows the plaintext file is the primary. Two behaviors matter for csq:

- **Subscription metadata is preserved.** CC's profile fetch can return null on transient failures (network, 5xx, rate limit). When saving tokens, CC falls back to the existing stored `subscriptionType` / `rateLimitTier` rather than clobbering a valid stored value with null.
- **First keychain write deletes the plaintext fallback.** On the first successful keychain write ever, CC deletes the plaintext file (this preserves credentials when sharing `~/.claude` between host and containers). After that, CC operates keychain-only and the mtime check goes through the missing-file branch on every call.

**Derived facts:**

1. **On macOS, `/login` writes ONLY to the keychain.** The `.credentials.json` file is not touched on a successful keychain write. csq, by contrast, keeps the file path canonical: the daemon refresher writes `identities/<UUID>/credentials.json` (`credentials::file::save_canonical_for`), and handle dirs reach it via symlink. (Swap repoints symlinks and writes no credentials.)
2. **On first successful keychain write ever, the plaintext fallback file is deleted.** After this, CC operates in keychain-only mode and the mtime check in section 1.4 goes through the missing-file branch on every call.
3. **On Linux/Windows, the secure-storage backend is the plaintext file directly.** Writes go to `<CLAUDE_CONFIG_DIR>/.credentials.json` with `0o600` permissions. File mtime changes, cross-process mtime check fires instantly.
4. **Subscription metadata preservation:** CC explicitly preserves `subscriptionType` and `rateLimitTier` from the existing stored value if the new tokens don't carry them. csq mirrors this behavior in the daemon refresher's canonical write path (`refresh::sync` back-sync preserves `subscription_type`/`rate_limit_tier` when the live file has `None` — see `backsync_preserves_subscription_type_when_live_has_none` in `csq-core/src/refresh/sync.rs`).
5. **After write, CC clears its own in-process memoize.** This is what makes `/login` in-flight inside the same process — the writing process sees its new tokens on the next call. Other processes, with their own separate memoizes, only see the new tokens via the mtime check (file path) or TTL expiry (keychain path).
6. **Consequence for csq:** when the csq CLI (a separate process from the running `claude`) writes credentials, it cannot clear CC's in-process memoize. It can only signal CC via the file-path mtime mechanism. This is why csq MUST write through the file (symlink-resolved in the handle-dir model), not keychain-only.

## 1.8 Shared account state in `~/.claude`

csq classifies a set of items as **shared** across all terminals — symlinked back to `~/.claude` — so that conversation history, user customization, and CC internals are consistent regardless of which account a terminal is bound to. The authoritative list is the `SHARED_ITEMS` const in `csq-core/src/session/isolation.rs`. It groups the shared items into four categories:

- **Conversation + session data:** `projects`, `sessions`, `history`, `history.jsonl`.
- **User customization:** `commands`, `skills`, `agents`, `rules`, `snippets`.
- **Infrastructure:** `mcp`, `plugins`, `todos`, `tasks`, `plans`, `teams`.
- **CC internals that must be shared:** caches, telemetry, IDE/chrome integration state, usage data, shell snapshots, file history, downloads, backups, debug state, session-env, keybindings, the local/default settings files, and the on-disk state DB.

The const in `isolation.rs` is authoritative for the exact set of entries.

CC addresses many of these items as subpaths of the resolved config dir — history (`history.jsonl`), user skills (`skills/`), commands, agents, rules, MCP, plugins, session-env, and others are all read from `getClaudeConfigHomeDir()`-relative paths.

**Derived facts:**

1. **CC reads many state files from its config dir.** History, skills, commands, agents, rules, MCP, plugins, session-env — all addressed as subpaths of the config dir.
2. **csq's `isolation::isolate_config_dir` populates these as symlinks back to `~/.claude/<item>`.** Result: every handle dir (and every legacy `config-N`) transparently reads and writes the SAME history, sessions, etc. as every other terminal. CC never knows it's following symlinks.
3. **Chat history / session continuity is preserved across account swaps.** CC keys `sessions/` by project cwd, not by config dir, so moving a terminal between accounts does not lose its conversation state.
4. **Settings are the exception.** `settings.json` is NOT in `SHARED_ITEMS` — it is per-account. In the handle-dir model it is not a symlink either: `handle_dir::materialize_handle_settings` writes a real per-terminal `settings.json` by deep-merging `~/.claude/settings.json` (user-global customization) with `config-<current-account>/settings.json` (slot overlay), and swap re-materializes it for the new account. A bare symlink would drop the user layer because `CLAUDE_CONFIG_DIR` overrides the home settings path (see spec 03 §3.3 step 3).

## 1.9 What this spec does NOT cover (intentionally)

- CC's OAuth flow (authorization code exchange, PKCE, scope list).
- CC's own token refresh timing and expiry check. csq keeps canonical tokens fresh ahead of expiry (2-hour window) to minimize cases where CC's refresh runs and rotates the refresh token without csq's knowledge. See spec 04 for the daemon design.
- **Anthropic's server-side contract for the OAuth token endpoint.** Authoritative documentation of the refresh request body shape, transport requirements, and known drift events lives in the `provider-integration` skill reference. Any change to csq's HTTP transport or refresh-body construction must re-verify against that runbook.
- The `CLAUDE_CODE_OAUTH_TOKEN` env var override. This is an SDK path bypassing all file and keychain logic. csq does not use it — env var overrides cannot be changed in a running process.
- Third-party provider credential handling. Those live in per-slot `settings.json` files, not `.credentials.json`. See spec 05.

## 1.10 How to re-verify this spec against a new CC version

When CC's binary version bumps, re-verify:

1. The config dir is still resolved from `CLAUDE_CONFIG_DIR` and memoized on it.
2. `.credentials.json` is still the credential file name and still lives at the config dir root.
3. The macOS keychain service name is still `Claude Code-credentials` for the default dir and `Claude Code-credentials-<sha256(dir)[:8]>` for custom dirs.
4. The disk-change/mtime check still runs inside the token-refresh routine and is called from the API client path.
5. The keychain 30-second TTL is still active.
6. The secure-storage fallback still writes keychain-primary on macOS.

Any of these changing invalidates this spec and requires both code and spec updates before csq should claim compatibility with that CC version.
