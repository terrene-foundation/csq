---
type: DECISION
date: 2026-04-13
created_at: 2026-04-13T22:15:00+08:00
author: co-authored
session_id: 2026-04-13-alpha-5-login-ux
session_turn: 75
project: csq-v2
topic: alpha.5 ships four user-visible fixes — login priority reversed, desktop modal paste-code, DMG ad-hoc signing, login email race
phase: implement
tags: [alpha-5, login, oauth, dmg, signing, desktop, keychain, release]
---

# alpha.5 — login UX + DMG signing + keychain cleanup

## Four fixes shipped in v2.0.0-alpha.5

### 1. `csq login N` — priority reversed, paste-code fallback actually works

**Before alpha.5**: `handle()` in `csq-cli/src/commands/login.rs` tried a "daemon-delegated" path first that asked the daemon for an auth URL, opened the browser, then **polled `credentials/N.json` for five minutes waiting for the daemon to write it**. Nothing ever wrote it because nothing called `/api/oauth/exchange` with the code. This was a leftover from the v1.x loopback era where the daemon was expected to catch the redirect itself. After journal 0020 deleted loopback, nobody updated `csq login` to prompt for the paste-code.

**alpha.5**:

1. If `claude` is on `PATH` (new `which_claude()` stdlib walk): delegate to `handle_direct`, which shells out to `claude auth login` with `CLAUDE_CONFIG_DIR=config-N/`. Same seamless UX as journal 0039 describes. csq imports credentials after CC exits.
2. If `claude` is not on PATH: new `handle_paste_code` path hits `/api/login/{N}`, opens the browser, **prompts on stdin** for the authorization code, then POSTs to `/api/oauth/exchange` with `{state, code}`.

Deleted: the broken polling loop, the `DaemonPathOutcome::Fallback` enum, the 5-minute `DAEMON_WAIT_CAP` constant.

Added: `csq_core::daemon::http_post_unix_json()` client helper (old `http_post_unix` only sent empty bodies for `/api/invalidate-cache`).

### 2. Desktop Add Account modal — in-process paste-code

**Before alpha.5**: `AddAccountModal.svelte::startClaudeOAuth` invoked `start_claude_login` (a Tauri command that shelled out to `claude auth login` via `Command::new("claude")`). **Failed in GUI context** because Finder-launched apps don't inherit shell `PATH` — user hit `failed to run claude auth login: no such file or directory (os error 2)`.

**alpha.5**: modal switched to `begin_claude_login` + `submit_oauth_code`. These Tauri commands already existed in alpha.4 (per journal 0020's paste-code rewrite) but the frontend was never updated to use them. New modal flow:

1. `invoke('begin_claude_login', {account})` → returns `ClaudeLoginView { auth_url, state, account, expires_in_secs }`
2. `openUrl(login.auth_url)` via `@tauri-apps/plugin-opener`
3. Transition to `paste-code` step with a text input
4. User pastes the code from Anthropic's hosted callback page
5. `invoke('submit_oauth_code', {baseDir, stateToken, code})` → exchange completes, credentials written, success
6. `cancelPasteCode` handler consumes the pending `OAuthStateStore` entry so abandoning the modal doesn't leak state

### 3. DMG ad-hoc signing in CI — fixes "file is damaged"

**Before alpha.5**: Tauri's macOS bundler left `.app` bundles with:

- Mach-O binary that's **linker-signed** (ad-hoc, from `rustc` default)
- **NO `Contents/_CodeSignature/CodeResources`** (no bundle-level seal)

macOS Gatekeeper reads this state as "code has no resources but signature indicates they must be present" and shows **"file is damaged and can't be opened"** — no user bypass.

**alpha.5 CI step** (between Tauri build and asset collection):

```bash
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"
# Tauri's DMG step already ran with the unsigned .app inside.
# Rebuild the DMG around the now-signed .app so the DMG's inner
# .app has the coherent signature.
hdiutil create -volname "Code Session Quota" -srcfolder "$TMP_DMG_DIR" \
    -ov -format UDZO "$DMG_PATH"
```

Result on the published DMG:

```text
$ codesign -dv "Code Session Quota.app"
Identifier=foundation.terrene.claude-squad
Format=app bundle with Mach-O thin (arm64)
flags=0x2(adhoc) hashes=3883+3
Sealed Resources version=2 rules=13 files=1
```

The signature is now ad-hoc bundle-level, not just linker-signed. `codesign --verify --deep --strict` passes. Gatekeeper shows the standard "Apple could not verify..." dialog with a user-visible bypass, instead of the "damaged" dead-end.

**Not fixed**: the app is still unnotarized (no Apple Developer ID). First launch still requires user bypass. The proper bypass on macOS Sonoma+ is either `xattr -cr "/Applications/Code Session Quota.app"` (fastest) or System Settings → Privacy & Security → Open Anyway. **Right-click → Open no longer works** on Sonoma+ for unnotarized apps; Apple removed that path in 2023.

### 4. Login email race — `.claude.json` over `claude auth status --json`

**Before alpha.5**: `get_email_from_cc` in `login.rs::finalize` shelled out to `claude auth status --json` immediately after `claude auth login` exited. There's a race window where CC's internal state hasn't fully flushed to disk — the JSON output comes back with `loggedIn: true` but missing the `email` field. csq fell back to writing `"unknown"` into `profiles.json` and printing `Logged in as unknown (account N)`.

**alpha.5**: `get_email_from_cc` now tries two sources in order:

1. `config_dir/.claude.json` → `oauthAccount.emailAddress` — file-based, no subprocess, no race window. CC writes this field as part of the auth flow.
2. `claude auth status --json` — legacy fallback for edge cases where `.claude.json` doesn't have the field (e.g. pre-existing config dirs populated via `.credentials.json` without local state).

Verified against live config-1 and config-3: both have `oauthAccount.emailAddress` populated correctly.

## Out-of-band cleanup: 707 stale keychain entries purged

Found on the user's macOS keychain:

- **1** entry at `Claude Code-credentials` (unhashed) — CC's canonical, used by `claude auth login` and `claude auth status`. Untouched.
- **707** entries at `Claude Code-credentials-{8-hex-hash}` — csq's historical per-config-dir entries, written by `csq_core::rotation::swap::keychain::write` in alpha.2 and earlier. Zero of these are what CC reads from.

Root cause: csq's `credentials::keychain::service_name()` derives the service name from SHA-256 of the config dir path (first 4 bytes hex). CC's own keychain item uses the unhashed name. **These naming schemes have never interoperated** — csq's hashed entries were dead weight from day one. Current main has already removed the `keychain::write` calls from `rotation/swap.rs`, but the 707 historical entries remained on disk.

Cleanup: bash loop calling `security delete-generic-password -s "Claude Code-credentials-$h"` for each hash. 704 deleted pre-session, 3 more deleted after the session (those were written during this session's `csq swap` operations before the alpha.5 install). All 707 removed, CC's canonical entry untouched.

**Follow-up for alpha.6**: remove the entire `csq_core::credentials::keychain` module. The `read` path is still called from `csq-cli/src/commands/login.rs::handle_direct` and `csq-desktop/src-tauri/src/commands.rs` as a fallback before file-based read, but since nothing writes to the hashed namespace anymore, the read always returns `None`. It's dead code that costs a `security-framework` import and 150+ LOC of platform abstraction.

## Tag re-cut procedure (reusable)

Alpha.5 was initially released, then re-cut after the email-race fix landed on main. Steps (safe when the initial release is newer than any user-visible download traffic):

```bash
gh release delete v2.0.0-alpha.5 --yes --cleanup-tag   # removes release + remote tag
git tag -d v2.0.0-alpha.5                              # local tag
git tag -a v2.0.0-alpha.5 -m "…"                       # re-tag on new HEAD
git push origin v2.0.0-alpha.5                         # triggers release workflow
```

This avoids a version bump when nothing external has pulled the release yet. Documented here because we did the same thing for alpha.4 earlier in the session chain (journal trail: alpha.3 tagged-but-failed, bumped to alpha.4; alpha.4 built-but-macos-13-cancelled, retagged after cross-compile fix; alpha.5 released-but-buggy, retagged after email fix).

## Test state

- **672 tests** passing on the alpha.5 tag commit
- **`cargo clippy --workspace --all-targets -- -D warnings`** clean
- **`cargo fmt --all -- --check`** clean
- **Svelte `npx svelte-check`** — 0 errors, 0 warnings
- **Vitest** — 22/22 pass
- **Release workflow** — 8/8 jobs green (cross-compile fix eliminates macos-13 shortage, DMG signing step validates the bundle seal)
- **Smoke-verified** on the user's primary machine: `csq login 1` delegates to `claude auth login` seamlessly; `csq --version` reports `2.0.0-alpha.5`; desktop app daemon running as pid 65095; all 7 accounts visible via `csq status`

## Outstanding for alpha.6

1. **`csq logout N` / `csq remove N`** — no command exists today to cleanly remove an account. Manual cleanup requires deleting `credentials/N.json`, `config-N/.credentials.json`, the profile entry, markers, and posting `/api/invalidate-cache` to the daemon. Blocks the user from testing the fresh-account flow in the desktop modal because all 7 of their slots are occupied.
2. **Desktop "Remove account" button** in `AccountList.svelte` — calls a new `remove_account` Tauri command.
3. **Delete `csq_core::credentials::keychain` module** — dead code after the hashed-namespace write was removed; read-path fallbacks can be inlined as `None` returns.
4. **DMG notarization** — blocks proper first-launch UX (right-click → Open would work again with notarization). Blocked on Apple Developer ID provisioning, not scheduled.

## For Discussion

1. The alpha.5 login priority ("delegate to `claude auth login` first") makes csq a thin wrapper over CC for the auth flow. That's fine operationally but it means csq's value-add in the login phase is close to zero — it's just setting `CLAUDE_CONFIG_DIR=config-N/` and importing the result. Should csq lean into this and also delegate `csq status` to `claude auth status` for the parts it doesn't have its own data for, or keep the separation?
2. The keychain cleanup (707 entries) is a one-off on one user's machine. Other users running csq alpha.2 or earlier have the same problem but no tool to clean it up. Does alpha.6 need a `csq doctor --fix-keychain` step, or is the accumulation small enough that leaving it is fine?
3. The tag re-cut procedure is load-bearing for this session's 3 releases (alpha.3 → alpha.4 → alpha.4 retag → alpha.5 → alpha.5 retag). It's destructive (`gh release delete --cleanup-tag`) and only safe when nobody has downloaded the release. What's the threshold where re-cut stops being OK — is it download count, time since publish, or an explicit versioning policy?
