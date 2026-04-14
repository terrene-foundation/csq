# 01 Claude Code Credential Architecture

Spec version: 1.0.0 | Status: DRAFT | Governs: how CC reads, writes, caches, and invalidates OAuth credentials | Upstream: Claude Code CLI 2.1.104

---

## 1.0 Why this spec exists

Every csq design decision about credential handling depends on knowing exactly what Claude Code itself does. Three prior csq bugs (`needs_restart` stale-session detection, subscription contamination guards, `config-N` slot-vs-account identity drift) were rooted in incorrect assumptions about CC's internal behavior. This spec eliminates the guesswork by reading CC's source directly and citing the files and line numbers. When CC changes upstream (confirmed by a version bump of the binary at `/Users/esperie/.local/share/claude/versions/`), this spec must be re-verified before any code using it is modified.

All citations below reference `~/repos/contrib/claude-code-source-code/src/` at the snapshot corresponding to CC 2.1.104. Paths are relative to that root.

## 1.1 Configuration directory resolution

**File:** `utils/envUtils.ts:5-13`

```typescript
// Memoized: 150+ callers, many on hot paths. Keyed off CLAUDE_CONFIG_DIR so
export const getClaudeConfigHomeDir = memoize(
  () => process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), ".claude"),
  () => process.env.CLAUDE_CONFIG_DIR,
);
```

**Derived facts:**

1. CC reads `CLAUDE_CONFIG_DIR` at process startup. If unset, it defaults to `~/.claude`.
2. The result is **memoized for the process lifetime**, keyed on the env var. CC cannot be made to change its config dir mid-process by mutating `process.env.CLAUDE_CONFIG_DIR` from inside CC itself (setting the memo key does nothing because memoize only re-runs on key CHANGE observed at call time, and the call-time reads the same memoized getter).
3. CC cannot be made to change its config dir from outside the process at all — Unix env vars are copied at fork/exec and external mutation via `/proc` is not supported by Node/Bun and is blocked on macOS.
4. **Consequence for csq:** to put a terminal on a different CLAUDE_CONFIG_DIR, the `claude` process must be started with that env var set. csq's `csq run N` handles this at launch. Mid-process swap MUST operate through file-level changes inside the already-chosen dir, not by trying to swap the env var.

## 1.2 Credentials file path

**File:** `utils/secureStorage/plainTextStorage.ts:13-17`

```typescript
function getStoragePath() {
  const storageDir = getClaudeConfigHomeDir();
  const storageFileName = ".credentials.json";
  return { storageDir, storagePath: join(storageDir, storageFileName) };
}
```

**Derived facts:**

1. The credentials file path is literally `<CLAUDE_CONFIG_DIR>/.credentials.json`.
2. `fs.stat`, `fs.readFile`, and `fs.writeFile` calls against this path follow symlinks transparently (Node default). This is the key fact that makes csq's handle-dir model work — a symlink in the handle dir resolving to a real file in `config-<N>` gives CC the same credentials it would have gotten if launched directly against `config-<N>`.
3. Exactly one file per `CLAUDE_CONFIG_DIR`. No per-process or per-session suffixing in CC.

## 1.3 Keychain service name derivation (macOS)

**File:** `utils/secureStorage/macOsKeychainHelpers.ts:29-41`

```typescript
export function getMacOsKeychainStorageServiceName(
  serviceSuffix: string = "",
): string {
  const configDir = getClaudeConfigHomeDir();
  const isDefaultDir = !process.env.CLAUDE_CONFIG_DIR;

  // Use a hash of the config dir path to create a unique but stable suffix
  // Only add suffix for non-default directories to maintain backwards compatibility
  const dirHash = isDefaultDir
    ? ""
    : `-${createHash("sha256").update(configDir).digest("hex").substring(0, 8)}`;
  return `Claude Code${getOauthConfig().OAUTH_FILE_SUFFIX}${serviceSuffix}${dirHash}`;
}
```

**Derived facts:**

1. **Default dir (`~/.claude`, no env var):** service name is `Claude Code-credentials`. No hash. All terminals launched without `CLAUDE_CONFIG_DIR` share one keychain entry.
2. **Custom dir:** service name is `Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR)[:8]>`. The hash uses the raw path string (not canonicalized — resolving symlinks WOULD change it).
3. **Two distinct CLAUDE_CONFIG_DIR paths produce distinct keychain slots.** This is the mechanism that allows csq to run multiple accounts on one machine without keychain collisions.
4. **The keychain path is per-directory, not per-process.** Two `claude` processes launched with the same `CLAUDE_CONFIG_DIR` share one keychain slot.
5. **Consequence for csq:** handle dirs at different paths (`term-<pid-A>` vs `term-<pid-B>`) get different keychain slots even if they currently symlink to the same account's files. This is fine — the daemon owns the keychain for each handle dir it creates.

## 1.4 Credential reload via mtime check

**File:** `utils/auth.ts:1313-1336`

```typescript
let lastCredentialsMtimeMs = 0;

// Cross-process staleness: another CC instance may write fresh tokens to
// disk (refresh or /login), but this process's memoize caches forever.
// Without this, terminal 1's /login fixes terminal 1; terminal 2's /login
// then revokes terminal 1 server-side, and terminal 1's memoize never
// re-reads — infinite /login regress (CC-1096, GH#24317).
async function invalidateOAuthCacheIfDiskChanged(): Promise<void> {
  try {
    const { mtimeMs } = await stat(
      join(getClaudeConfigHomeDir(), ".credentials.json"),
    );
    if (mtimeMs !== lastCredentialsMtimeMs) {
      lastCredentialsMtimeMs = mtimeMs;
      clearOAuthTokenCache();
    }
  } catch {
    // ENOENT — macOS keychain path (file deleted on migration). Clear only
    // the memoize so it delegates to the keychain cache's 30s TTL instead
    // of caching forever on top. `security find-generic-password` is
    // ~15ms; bounded to once per 30s by the keychain cache.
    getClaudeAIOAuthTokens.cache?.clear?.();
  }
}
```

**This function runs before every API call path.** See section 1.6 for the call sites.

**Derived facts (CRITICAL — load-bearing for csq's swap semantics):**

1. **CC does NOT cache credentials forever at startup.** It caches them until the file mtime changes, then clears the cache on the next API call.
2. **The mtime is tracked per-process** in a module-scope variable `lastCredentialsMtimeMs`. Each CC process has its own. Two CC processes on the same config dir each track their own last-seen mtime.
3. **A write to `.credentials.json` from ANY process** (another CC instance, csq, the user, a shell script) triggers the reload in every CC process that subsequently calls `checkAndRefreshOAuthTokenIfNeeded()`. The mtime comparison is `!==` not `<`, so even a backwards-seeming mtime (rare; atomic replace with preserved mtime) triggers reload.
4. **ENOENT branch:** if the file does not exist (pure-keychain migration case), the catch fires and clears only the memoize. The keychain cache 30-second TTL then bounds staleness — see section 1.5.
5. **Consequence for csq:** swap does NOT need to restart the CC process, send a signal, or do anything other than atomically change what `.credentials.json` resolves to. CC will pick it up via `fs.stat` within one API call.
6. **This function was added by Anthropic specifically to solve the multi-terminal-sharing-a-config-dir case** described in the comment: "terminal 1's /login fixes terminal 1; terminal 2's /login then revokes terminal 1 server-side, and terminal 1's memoize never re-reads." Cross-terminal credential sync is a designed feature of CC, not an accident.
7. **Retraction:** journal 0029 Finding 4 claims "CC caches credentials in memory at startup. After a swap, the on-disk state changes but the running CC process retains old tokens." This is FALSE. Journal 0031 retracts it with citation to this section. Code implementing `needs_restart` based on the false claim MUST be deleted — see spec 02 and rules/account-terminal-separation.md rule 7.

## 1.5 Keychain read cache (30-second TTL)

**File:** `utils/secureStorage/macOsKeychainStorage.ts:28-66`

```typescript
read(): SecureStorageData | null {
  const prev = keychainCacheState.cache
  if (Date.now() - prev.cachedAt < KEYCHAIN_CACHE_TTL_MS) {
    return prev.data
  }

  try {
    const storageServiceName = getMacOsKeychainStorageServiceName(
      CREDENTIALS_SERVICE_SUFFIX,
    )
    const username = getUsername()
    const result = execSyncWithDefaults_DEPRECATED(
      `security find-generic-password -a "${username}" -w -s "${storageServiceName}"`,
    )
    if (result) {
      const data = jsonParse(result)
      keychainCacheState.cache = { data, cachedAt: Date.now() }
      return data
    }
  } catch (_e) {
    // fall through
  }
  // Stale-while-error: if we had a value before and the refresh failed,
  // keep serving the stale value rather than caching null.
  if (prev.data !== null) {
    keychainCacheState.cache = { data: prev.data, cachedAt: Date.now() }
    return prev.data
  }
  keychainCacheState.cache = { data: null, cachedAt: Date.now() }
  return null
}
```

**File:** `utils/secureStorage/macOsKeychainHelpers.ts:69`

```typescript
export const KEYCHAIN_CACHE_TTL_MS = 30_000;
```

**Derived facts:**

1. **Per-process cache, 30-second TTL.** Each CC process maintains its own `keychainCacheState.cache` with a `cachedAt` timestamp. Reads return stale data for up to 30 seconds.
2. **Writes from another process are not visible until the TTL expires** (or until something calls `clearKeychainCache()` in this process — only the mtime-check ENOENT path and the 401 handler do that).
3. **Stale-while-error**: if the keychain read fails, the previous value is served with a fresh `cachedAt`. This makes recovery from transient `security` CLI failures graceful but means a terminal can serve stale creds beyond the 30-second window if the keychain is failing.
4. **Consequence for csq:** a pure keychain write with no file write gives other terminals up to 30 seconds of stale reads. For csq's handle-dir model this is not a concern because swap operates on the file-via-symlink, which is picked up instantly by the mtime check.

## 1.6 Where `invalidateOAuthCacheIfDiskChanged` is called

**File:** `utils/auth.ts:1447-1453`

```typescript
async function checkAndRefreshOAuthTokenIfNeededImpl(
  retryCount: number,
  force: boolean,
): Promise<boolean> {
  const MAX_RETRIES = 5

  await invalidateOAuthCacheIfDiskChanged()
  ...
}
```

**File:** `services/api/client.ts:131-133`

```typescript
logForDebugging("[API:auth] OAuth token check starting");
await checkAndRefreshOAuthTokenIfNeeded();
logForDebugging("[API:auth] OAuth token check complete");
```

**Call chain:** `getAnthropicClient()` → `checkAndRefreshOAuthTokenIfNeeded()` → `checkAndRefreshOAuthTokenIfNeededImpl()` → `invalidateOAuthCacheIfDiskChanged()`.

**Derived facts:**

1. **Every time CC builds a new Anthropic client**, the mtime check runs. `getAnthropicClient` is the entry point for all API traffic from the main CC process.
2. Other callers of `checkAndRefreshOAuthTokenIfNeeded` (from `grep -rn "checkAndRefreshOAuthTokenIfNeeded" ~/repos/contrib/claude-code-source-code/src`): `main.tsx:3315`, `bridge/bridgeMain.ts:2377,2747`, `bridge/initReplBridge.ts:201`, `services/voiceStreamSTT.ts:116`, `services/oauth/client.ts:475`, `services/teamMemorySync/index.ts:194,320,469`, `services/remoteManagedSettings/index.ts:254`, `services/settingsSync/index.ts:249,351`, `tools/RemoteTriggerTool/RemoteTriggerTool.ts:79`. All of these will trigger a mtime stat and cache clear on credentials file change.
3. **Consequence for csq:** within one API call (and well under a second in practice), CC picks up a new `.credentials.json` written externally. csq swap's latency upper bound is the user's next keystroke plus CC's normal API call startup, not a restart cycle or a poll interval.

## 1.7 OAuth token write path (`saveOAuthTokensIfNeeded`)

**File:** `utils/auth.ts:1194-1253`

```typescript
export function saveOAuthTokensIfNeeded(tokens: OAuthTokens): {
  success: boolean
  warning?: string
} {
  ...
  const secureStorage = getSecureStorage()
  const storageBackend = secureStorage.name as ...

  try {
    const storageData = secureStorage.read() || {}
    const existingOauth = storageData.claudeAiOauth

    storageData.claudeAiOauth = {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
      scopes: tokens.scopes,
      // Profile fetch in refreshOAuthToken swallows errors and returns null on
      // transient failures (network, 5xx, rate limit). Don't clobber a valid
      // stored subscription with null — fall back to the existing value.
      subscriptionType:
        tokens.subscriptionType ?? existingOauth?.subscriptionType ?? null,
      rateLimitTier:
        tokens.rateLimitTier ?? existingOauth?.rateLimitTier ?? null,
    }

    const updateStatus = secureStorage.update(storageData)
    ...
    getClaudeAIOAuthTokens.cache?.clear?.()
    clearBetasCaches()
    clearToolSchemaCache()
    return updateStatus
  }
  ...
}
```

**File:** `utils/secureStorage/index.ts:11`

```typescript
// On macOS, primary is keychain, secondary is plainText file
return createFallbackStorage(macOsKeychainStorage, plainTextStorage);
```

**File:** `utils/secureStorage/fallbackStorage.ts:27-62`

```typescript
update(data: SecureStorageData): { success: boolean; warning?: string } {
  // Capture state before update
  const primaryDataBefore = primary.read()

  const result = primary.update(data)

  if (result.success) {
    // Delete secondary when migrating to primary for the first time
    // This preserves credentials when sharing .claude between host and containers
    if (primaryDataBefore === null) {
      secondary.delete()
    }
    return result
  }

  const fallbackResult = secondary.update(data)
  ...
}
```

**Derived facts:**

1. **On macOS, `/login` writes ONLY to the keychain.** The `.credentials.json` file is not touched on a successful keychain write. This is the opposite of what csq currently does in `rotation::swap_to`.
2. **On first successful keychain write ever, the plaintext fallback file is deleted** (`fallbackStorage.ts:34-38`). After this, CC operates in keychain-only mode and the mtime check in section 1.4 goes through the ENOENT catch branch on every call.
3. **On Linux/Windows, `getSecureStorage()` returns `plainTextStorage` directly** (see `index.ts`). Writes go to `<CLAUDE_CONFIG_DIR>/.credentials.json` with `0o600` permissions. File mtime changes, cross-process mtime check fires instantly.
4. **Subscription metadata preservation:** lines 1225-1228 of `saveOAuthTokensIfNeeded` explicitly preserve `subscriptionType` and `rateLimitTier` from the existing stored value if the new tokens don't carry them. This is CC's defense against the same contamination bug csq journal 0029 Finding 2 found. The behavior is mirrored in csq's `rotation::swap_to` and `broker::fanout::fan_out_credentials`.
5. **After write, CC clears its own in-process memoize** (`auth.ts:1239`: `getClaudeAIOAuthTokens.cache?.clear?.()`). This is what makes `/login` in-flight inside the same process — the writing process sees its new tokens on the next call. Other processes, with their own separate memoizes, only see the new tokens via the mtime check (file path) or TTL expiry (keychain path).
6. **Consequence for csq:** when the csq CLI (a separate process from the running `claude`) writes credentials, it cannot clear CC's in-process memoize. It can only signal CC via the file-path mtime mechanism. This is why csq MUST write through the file (symlink-resolved in the handle-dir model), not keychain-only.

## 1.8 Shared account state in `~/.claude`

**File:** `csq-core/src/session/isolation.rs:12-15` (csq, not CC, but documents the contract)

```rust
/// Items that are **shared** across all terminals — symlinked back to `~/.claude`.
pub const SHARED_ITEMS: &[&str] = &[
    "history", "sessions", "commands", "skills", "agents", "rules", "mcp", "plugins", "snippets",
    "todos",
];
```

**Cross-check from CC source** (`find ~/repos/contrib/claude-code-source-code/src -name '*.ts' | xargs grep -l "getClaudeConfigHomeDir.*'history'"`):

- `src/history.ts:115`: `const historyPath = join(getClaudeConfigHomeDir(), 'history.jsonl')`
- `src/services/MagicDocs/prompts.ts:68`: `join(getClaudeConfigHomeDir(), 'magic-docs', 'prompt.md')`
- `src/memdir/paths.ts:89`: `return getClaudeConfigHomeDir()`
- `src/skills/loadSkillsDir.ts:640`: `const userSkillsDir = join(getClaudeConfigHomeDir(), 'skills')`

**Derived facts:**

1. **CC reads many state files from `getClaudeConfigHomeDir()`.** History, skills, commands, agents, rules, MCP, plugins, session-env — all addressed as subpaths of the config dir.
2. **csq's `isolation::isolate_config_dir` populates these as symlinks back to `~/.claude/<item>`.** Result: every handle dir (and every legacy `config-N`) transparently reads and writes the SAME history, sessions, etc. as every other terminal. CC never knows it's following symlinks.
3. **Chat history / session continuity is preserved across account swaps.** CC keys `sessions/` by project cwd, not by config dir, so moving a terminal between accounts does not lose its conversation state.
4. **Settings are the exception.** `settings.json` is NOT in `SHARED_ITEMS` — it is per-account. This matters for the handle-dir model: the handle dir's `settings.json` symlinks to `config-<current-account>/settings.json`, and on swap the symlink is re-pointed to the new account's settings. Settings edited once per account apply everywhere that account is in use.

## 1.9 What this spec does NOT cover (intentionally)

- CC's OAuth flow (authorization code exchange, PKCE, scope list). See `src/services/oauth/client.ts` and `src/constants/oauth.ts` if needed.
- CC's own token refresh timing and expiry check. csq keeps canonical tokens fresh ahead of expiry (2-hour window) to minimize cases where CC's refresh runs and rotates the refresh token without csq's knowledge. See spec 04 for the broker design.
- **Anthropic's server-side contract for `/v1/oauth/token` (the token endpoint).** Authoritative documentation of the refresh request body shape, field requirements, and known server-side drift events lives in `.claude/skills/provider-integration/SKILL.md`. Two known drift events so far: journal 0034 (form-encoded → JSON-only) and journal 0052 (JSON body MUST NOT contain `scope` — Anthropic returns `400 invalid_scope` even when the value matches the original grant). Any change to csq's `build_refresh_body` or the broker classifier must re-verify against the skill's runbook.
- The `CLAUDE_CODE_OAUTH_TOKEN` env var override (`auth.ts:1260`). This is an SDK path bypassing all file and keychain logic. csq does not use it — env var overrides cannot be changed in a running process.
- Third-party provider credential handling. Those live in per-slot `settings.json` files, not `.credentials.json`. See spec 05.

## 1.10 How to re-verify this spec against a new CC version

When CC's binary version bumps (check `/Users/esperie/.local/share/claude/versions/`), re-verify:

1. `getClaudeConfigHomeDir` still memoized on `CLAUDE_CONFIG_DIR`.
2. `.credentials.json` is still the credential file name and still lives at the config dir root.
3. `getMacOsKeychainStorageServiceName` still hashes the config dir path with `sha256[:8]`.
4. `invalidateOAuthCacheIfDiskChanged` still runs inside `checkAndRefreshOAuthTokenIfNeededImpl` and is called from the API client path.
5. The keychain 30-second TTL is still active.
6. The secureStorage fallback still writes keychain-primary on macOS.

Any of these changing invalidates this spec and requires both code and spec updates before csq should claim compatibility with that CC version.

## Revisions

- 2026-04-12 — 1.0.0 — Initial draft from CC 2.1.104 source. Derived during the csq-v2 handle-dir redesign after journal 0029 Finding 4 was empirically disproved.
- 2026-04-14 — 1.0.1 — Added §1.9 forward-pointer to `provider-integration` skill for Anthropic token-endpoint contract; linked journals 0034 (JSON-only migration) and 0052 (scope-field rejection) as the two drift events this spec intentionally does NOT track inline.
