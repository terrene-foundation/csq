# REMAINING-GAPS-2026-04-11 — csq v2 Desktop App Stocktake

**Status at end of session**: All gates green (478 Rust tests, 13 Svelte, clippy clean, fmt clean, svelte-check 0 errors, frontend builds). App launches; tray renders; `+ Add Account → Claude` opens the browser. No end-to-end sign-in was exercised because the user is already provisioned on 8 live accounts.

---

## 1. Verified-done this session

- Claude OAuth flow rewritten from dead loopback to paste-code: `start_claude_login` returns a URL; `submit_oauth_code` consumes PKCE state + verifier from `OAuthStateStore` and performs the token exchange.
- `oauth_callback` module and its ~1000 LOC of TCP-listener machinery deleted from `csq-core`.
- Multi-provider Add Account modal landed (Claude OAuth / MiniMax API key / Z.AI API key) at `csq-desktop/src/lib/components/AddAccountModal.svelte`.
- Daemon `/api/login/{N}` route rewritten to paste-code; new `/api/oauth/exchange` route added (`csq-core/src/daemon/server.rs`).
- `tauri_plugin_updater` init removed from `csq-desktop/src-tauri/src/lib.rs` and from `Cargo.toml` — it was panicking at startup because no `plugins.updater` config block existed (journal 0021).
- `AccountList.svelte` `homeDir()` concatenation bug fixed (was producing `/Users/esperie.claude/accounts`); now uses `join()` (journal 0021).
- `tracing-subscriber` default features disabled workspace-wide to prevent the `log`-facade collision with `tauri-plugin-log` (journal 0017).
- Tray quick-swap hardened to retarget a single `config-N` dir selected by `.credentials.json` mtime, with `SWAP_IN_FLIGHT` serialization (journal 0018).

## 2. Unverified — compiles and tests clean, nobody has run it end-to-end

- **Paste-code submit path** — the full `submit_oauth_code` → state consume → token exchange → `atomic_replace` credential write → `get_accounts` refresh sequence has never been exercised against a live Anthropic token endpoint. Unit tests cover the state store and the redaction path, not the round-trip. **Source**: `csq-desktop/src-tauri/src/commands.rs::submit_oauth_code` + `csq-core/src/oauth/exchange.rs`. **Why it matters**: the user's first real sign-in after this lands will be the integration test. If the exchange fails, the error surfacing is also untested (see gap 3.1).
- **MiniMax and Z.AI `set_provider_key` paths** — modal calls the Tauri command, but no one has pasted a real key and confirmed the account shows up in `get_accounts` and rotation still picks the correct provider. `csq-desktop/src-tauri/src/commands.rs::set_provider_key`.
- **`tray-swap-complete` emit path** runs when clicking an account row but has no frontend listener yet — see gap 3.1.
- **Dashboard first paint** — the 5s polling loop in `AccountList.svelte` works, but first-paint latency on a cold start hasn't been measured or budgeted.
- **`refresh_tray_menu` 30s interval** — `csq-desktop/src-tauri/src/lib.rs` runs in production but no one has verified what happens if the user deletes `~/.claude/accounts` while the ticker is running (the code path returns early but the ticker keeps firing).

## 3. Near-term gaps (<1 session each)

### 3.1 Toast/error surface listening for `tray-swap-complete`

**File to start work**: `csq-desktop/src/lib/App.svelte` (mount a global listener) or a new `csq-desktop/src/lib/components/Toast.svelte`.

**Why it matters**: today a tray click that fails because no live `config-N` dir exists (fresh machine, no CC session ever started) emits `tray-swap-complete { ok: false, error: "no live CC session found" }` into the void. The user clicks, nothing visibly happens, they click again, the second click is dropped by `SWAP_IN_FLIGHT` — now they are certain the app is broken. A single toast component listening for this event and also for exchange/provider errors from the modal closes this feedback gap cheaply.

**Backend contract already exists**: `csq-desktop/src-tauri/src/lib.rs` emits the event via `app.emit("tray-swap-complete", &result)`; the `TraySwapResult` struct is the payload shape.

### 3.2 Tray icon variants for warning states

**File to start work**: `csq-desktop/src-tauri/icons/` (add `tray-warn.png`, `tray-error.png`) and `csq-desktop/src-tauri/src/lib.rs::refresh_tray_menu` (check discovered accounts for `token_status == "expiring"` or `five_hour_pct >= 100`, call `tray.set_icon(...)`).

**Why it matters**: the user runs 8 accounts. Today the tray icon is static — they have to open the dashboard to learn that account #3 just hit the 5h ceiling. A yellow icon when any account is expiring and red when any account is out of quota lets them glance at the menu bar instead of context-switching to the window. The discovery pass already surfaces both fields via `discover_anthropic`.

### 3.3 Dashboard first-paint measurement

**File to start work**: `csq-desktop/src/lib/components/AccountList.svelte` (add `performance.now()` around `fetchAccounts()`).

**Why it matters**: the dashboard is the escape hatch when the tray quick-swap picks the wrong session. If first paint is >500ms after the window opens, users will feel the app is sluggish during the exact moment they're trying to recover from a rate-limit hit. Budget: 200ms to first usable paint. No instrumentation today — we don't know if we're meeting it.

### 3.4 `dashboard/oauth.py` is dead code with a credible-looking surface

**File to audit / delete**: `dashboard/oauth.py` + `dashboard/tests/test_oauth.py`.

**Finding**: the `csq` bash wrapper (`cmd_login` at line 86-100) shells out to `claude auth login` — it does **not** call `dashboard/oauth.py`. Grep confirms: `rg "dashboard/oauth" csq` returns no references. The Python file has its own PKCE implementation pointing at the dead loopback URL and looks working.

**Why it matters**: a future contributor reads `dashboard/oauth.py`, sees a working-looking PKCE implementation with a loopback callback, and assumes that's still how the desktop app works — doubling their onboarding confusion. Dead code with a credible surface is worse than no code. **Action**: either delete both files or add a header comment marking them as legacy reference.

## 4. The big gap — terminal instance / session management

**The user's actual workflow**: 15 terminal windows, 8 accounts. When terminal #5 hits its 5h ceiling, they need to know (a) that it was terminal #5, not #6 or #7, and (b) they need to swap _only that terminal's_ `config-N` to a fresh account without disturbing the other 14.

**What exists today**: `most_recent_config_dir` picks one dir by credential mtime. This picks the right dir most of the time but is invisible — the user cannot see _which terminal_ is bound to _which config-N_ until they run `lsof` by hand.

**What's missing**: a "Sessions" view in the dashboard listing every live CC process with its config dir, active account, and a swap picker.

### 4.1 Data required per row

- PID of the `claude` (or `node .../claude.js`) process
- `cwd` of that process (so the user can recognize "oh, terminal #5 is the one in `~/repos/terrene`")
- `CLAUDE_CONFIG_DIR` the process was launched with
- Derived: current account for that config dir (read from `profiles.json` + `.credentials.json`)
- Derived: that account's `five_hour_pct` and `seven_day_pct`
- Start time (so stale zombies are obvious)

### 4.2 Platform sourcing

- **macOS**: `ps -E -o pid,command` to dump environ inline (root not required for own-UID processes), filter rows whose env contains `CLAUDE_CONFIG_DIR=`, parse the value. `lsof -a -p <pid> -d cwd -Fn` for the cwd.
- **Linux**: `/proc/<pid>/environ` (NUL-separated, owned by the UID running the process — readable without root for own-UID) for `CLAUDE_CONFIG_DIR`. `/proc/<pid>/cwd` symlink (`readlink`) for cwd. `/proc/<pid>/stat` for start time.
- **Windows**: TBD — `wmic process` is deprecated; `Get-Process` via `powershell` or a `sysinfoapi` FFI call. Punt to a later session; document as an M8/M10 follow-up.

### 4.3 Discovery location

New module: `csq-core/src/sessions/mod.rs`. Tauri command: `list_sessions()` returning `Vec<SessionView>`. UI: new Svelte component `csq-desktop/src/lib/components/SessionList.svelte`, sibling of `AccountList.svelte`.

### 4.4 UI shape (not a full design — enough to start)

```
Sessions (live CC processes)
  [PID 48291]  ~/repos/terrene/contrib/claude-squad   config-5   #3 alice   [5h: 87%]  [Swap → ▼]
  [PID 48295]  ~/repos/dev/aegis                      config-7   #1 bob     [5h:  4%]  [Swap → ▼]
```

The `Swap` dropdown on a row targets that row's `config-N` specifically, bypassing `most_recent_config_dir` — deterministic, no guessing.

### 4.5 Why this matters for user workflow

When terminal #5 hits rate limit, the user today clicks the tray, the tray swaps the most-recently-refreshed dir (which might be terminal #7 because that's where auto-refresh last ran), and the user's actual problem terminal stays stuck. Terminal swap by PID fixes this; it is the single most valuable UX win outstanding for an 8-account workflow.

## 5. Long-tail milestones untouched this session

| ID     | Item                                               | File                                                                           | Why still a gap                                                                                                                                                                                             |
| ------ | -------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M7-10  | `csq update` self-update                           | new `csq-cli/src/commands/update.rs`                                           | needed for curl-pipe install story; requires GitHub Releases + Ed25519 signature verify + atomic binary swap; no work started                                                                               |
| M8-03  | Windows named-pipe IPC for daemon                  | `csq-core/src/daemon/platform/windows.rs` (new)                                | daemon currently Unix-socket only; Windows users have no daemon at all until this lands                                                                                                                     |
| M11-01 | macOS code signing (Apple Developer ID + notarize) | `csq-desktop/src-tauri/tauri.conf.json` signing block                          | **BLOCKER**: requires a Foundation Apple Developer account ($99/yr) — no workaround, users hit Gatekeeper quarantine today                                                                                  |
| M11-02 | Windows Authenticode signing                       | Windows CI pipeline                                                            | **BLOCKER**: requires Authenticode certificate — self-signed gets SmartScreen warnings but at least installs                                                                                                |
| M11-05 | Linux packaging (AppImage, .deb, .rpm)             | `.github/workflows/release.yml`                                                | needed for Linux distribution; Tauri emits the artifacts but no CI wiring                                                                                                                                   |
| M11-06 | Curl-pipe installer                                | `scripts/install.sh` (new)                                                     | enables `curl -fsSL ... \| sh` one-liner install story                                                                                                                                                      |
| —      | `tauri-plugin-updater` re-wire                     | `csq-desktop/src-tauri/Cargo.toml` + `tauri.conf.json` `plugins.updater` block | removed this session because its config was missing and it panicked at startup; MUST come back when M11-01/02 land real signing and M7-10 stands up a release endpoint, otherwise auto-update is impossible |

## 6. Follow-up cleanup from this session

- **`#[allow(deprecated)]` annotations**: `rg '#\[allow\(deprecated\)\]' csq-core csq-desktop csq-cli` returns no matches. Clean.
- **`let _ = x.show()` in tray handlers** (`csq-desktop/src-tauri/src/lib.rs`): pre-existing. These are fine — `show()` on an already-visible window is idempotent, and the discarded `Result` is the Tauri-standard pattern for menu actions. Not this session's problem; noting so the next pass doesn't try to "fix" them.
- **`tauri-plugin-updater` in Cargo.toml**: removed this session. Only `tauri-plugin-log` and `tauri-plugin-opener` remain. Re-add when M11 wires signing. Track under M7-10.
- **`dashboard/oauth.py` + `dashboard/tests/test_oauth.py`**: see gap 3.4.

## Blockers summary

1. **M11-01** Apple Developer ID account — external, money + paperwork gate.
2. **M11-02** Authenticode cert — external, money gate.

Neither blocks development; both block distribution. All other items in sections 3 and 4 are unblocked and can land in the next autonomous session.
