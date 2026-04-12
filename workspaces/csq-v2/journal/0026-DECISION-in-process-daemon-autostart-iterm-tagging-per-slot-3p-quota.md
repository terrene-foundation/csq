---
type: DECISION
date: 2026-04-12
created_at: 2026-04-12T10:35:00+08:00
author: co-authored
session_id: session-2026-04-12a
session_turn: 100
project: csq-v2
topic: In-process daemon supervisor, launch-on-login via tauri-plugin-autostart, iTerm2 terminal tagging in Sessions view, and per-slot 3P quota polling for slots 9 (MiniMax) and 10 (Z.AI)
phase: implement
tags: [desktop, daemon, autostart, iterm, 3p-quota, refresher, ux-critical]
---

# DECISION: Ship the daemon inside the app; tag iTerm sessions; poll per-slot 3P quotas

## Context

Three failure modes converged into a single work item:

1. **All 8 OAuth slots had been expired for 6–80 hours**. Root cause: the csq daemon — which owns the 5-minute refresher task — had not been running. The user hadn't launched `csq daemon start` for days. The desktop app's Header showed a red "Daemon stopped" dot but did nothing about it.
2. **Sessions view couldn't identify the current terminal.** The user saw several config-2 and config-8 rows but had no way to match a row to the iTerm tab they were currently typing in. The existing row showed PID, cwd, config dir, 5h quota, age — zero terminal identity.
3. **Slots 9 and 10 showed 0% quota.** The previous session (journal 0025) wired per-slot 3P discovery so MiniMax (slot 9) and Z.AI (slot 10) appeared in the Accounts tab, but the daemon's usage poller still read only the legacy global `settings-mm.json` / `settings-zai.json` at hardcoded synthetic slot IDs 901/902.

## Choice

Four coordinated deliveries in one PR:

### 1. In-process daemon supervisor

New module `csq-desktop/src-tauri/src/daemon_supervisor.rs`. On app setup, spawns a tokio task that:

- Calls `detect_daemon(base_dir)` to decide whether another daemon is already running.
- If `Healthy` (external daemon owns the socket), sleeps 60s and re-polls — never fights for the PidFile, just observes.
- If `NotRunning` or `Stale`, acquires `PidFile::acquire` and spawns the full subsystem stack (server + refresher + usage_poller + auto_rotate) using the same composition as `csq-cli/src/commands/daemon.rs::start`.
- Waits for cancellation (the outer token, fired on `RunEvent::Exit`).
- On drop, drains each subsystem with a 5s deadline, releases the PidFile, and loops back. If cancellation fired, exits. Otherwise waits 5s and retries — giving a crashed daemon a graceful restart path.

The supervisor cohabits with an external daemon gracefully. If the user runs `csq daemon start` while the app is open, the external daemon owns the PidFile, the supervisor observes, and when the external process exits, the supervisor takes over on the next 60s poll.

Wired via `AppState::daemon_supervisor: Mutex<Option<SupervisorHandle>>`. `Mutex` because `RunEvent::Exit` needs to `take()` the handle, but `tauri::State` gives us only an immutable borrow.

### 2. Launch-on-login via `tauri-plugin-autostart`

Added `tauri-plugin-autostart = "2"` to `csq-desktop/src-tauri/Cargo.toml`. Initialized in `run()` with `MacosLauncher::LaunchAgent` (installs `~/Library/LaunchAgents/<bundle-id>.plist` on macOS; registry Run key on Windows; `.desktop` file on Linux). Two Tauri commands: `get_autostart_enabled` and `set_autostart_enabled`. UI: a "Launch on login" checkbox in `Header.svelte` next to the daemon status.

Empty `args` vector on plugin init so launch-on-login doesn't open the dashboard window automatically — the tray keeps the app alive silently, and the user clicks the tray icon when they need the window.

Capability permission: `autostart:default` added to `src-tauri/capabilities/default.json`.

### 3. iTerm2 terminal tagging in Sessions view

New fields on `SessionInfo`:

```rust
pub tty: Option<String>,                // "ttys003"
pub term_window: Option<u8>,            // 3  (parsed from TERM_SESSION_ID)
pub term_tab: Option<u8>,               // 2
pub term_pane: Option<u8>,              // 0
pub iterm_profile: Option<String>,      // "Default"
pub terminal_title: Option<String>,     // iTerm tab title, osascript-resolved
```

`parse_term_session_id` (new, in `sessions::mod`) parses `w<N>t<M>p<K>:<uuid>` shape strings into `(Option<u8>, Option<u8>, Option<u8>)`. Handles partial prefixes (just window, just window+tab) and rejects u8-overflow gracefully.

macOS backend (`sessions/macos.rs`) extracts TTY via `ps -o tty=`, parses `TERM_SESSION_ID` and `ITERM_PROFILE` from the env blob, and resolves `terminal_title` via a best-effort `osascript` call against iTerm2. The osascript walks every window → tab → session and joins each session's `tty` to its tab's `name`, building a `HashMap<String, String>` once per `list()` call. Short-circuits if iTerm2 isn't running (pgrep check) so non-iTerm users don't pay the subprocess cost.

Linux backend (`sessions/linux.rs`) reads `/proc/<pid>/fd/0` symlink for the TTY (resolves to `/dev/pts/N`), and `/proc/<pid>/environ` for the iTerm env vars (terminals like WezTerm also populate them). No osascript equivalent; `terminal_title` stays None on Linux.

SessionList.svelte gains a `.terminal` row that shows, in priority order:
1. `terminal_title` (iTerm tab name — most specific)
2. `Window N • Tab M` (from TERM_SESSION_ID)
3. `iterm_profile` (profile name)
4. `tty` (e.g. `ttys003`)
5. `—` (none of the above)

Plus a pane suffix when `term_pane > 0` so split panes are distinguishable.

To identify the current terminal: the user runs `echo $TERM_SESSION_ID` or `tty` in the target terminal and matches the row.

### 4. Per-slot 3P quota polling

Updated `daemon::usage_poller::tick_3p` to use `discover_all` (filtering to `ThirdParty` rows) instead of `discover_third_party`. Per-slot bindings (slot < 900) take the per-slot path; legacy global synthetic slots (>= 900) take the legacy path.

New loaders in `usage_poller.rs`:

- `load_3p_api_key_for_slot(base, slot, provider_id)` reads `{base}/config-{slot}/settings.json` and extracts `env.ANTHROPIC_AUTH_TOKEN`.
- `load_3p_base_url_for_slot(base, slot)` extracts `env.ANTHROPIC_BASE_URL`. The user's actual setup uses `api.minimax.io` (not the catalog's `api.minimax.chat`), so the per-slot URL must override the catalog default — otherwise probes hit the wrong host and fail.

The poller loop now:
- For each 3P account, if slot < 900 → per-slot key + per-slot URL (with catalog fallback)
- If slot >= 900 → legacy global key + catalog URL
- Polls `{base_url}/v1/messages` with `max_tokens=1` + bearer key, reads `anthropic-ratelimit-*` headers
- Writes `quota.json[slot]` so the dashboard Accounts tab sees the quota alongside OAuth slots

## Alternatives Considered

- **Auto-shell-out to `csq daemon start` instead of in-process daemon.** Rejected. The external process would keep running even after the app quits, leaving a zombie refresher. In-process means one process, one lifecycle — simpler to reason about, cleaner to debug, and the tray icon already keeps the Tauri process alive across window closes so there's no refresh gap.
- **Rolling our own LaunchAgent plist writer instead of `tauri-plugin-autostart`.** Rejected. The plugin handles macOS/Windows/Linux uniformly in ~50 lines of consumer code. Rolling it ourselves means duplicating three platforms' quirks for no benefit.
- **Detect terminal identity via PPID → shell → terminal window chain.** Rejected as too fragile. On macOS an iTerm session's process tree is `iTerm2 → login → -zsh → claude`, and walking that back requires reading parent PIDs which change across launches. `TERM_SESSION_ID` is the ID the terminal itself publishes — much more reliable.
- **Skip the osascript call for terminal titles.** Considered. The env-based parsing (window/tab/pane) is enough to distinguish rows, and osascript adds 50–150ms to each `list_sessions` call. Decided to keep it because the user explicitly asked "I am using iTerm so you can see all their names" — "names" meaning tab titles, which env vars don't expose. The pgrep short-circuit means non-iTerm users pay zero cost.
- **Put the launch-on-login toggle in a Settings page instead of the Header.** Settings pages don't exist in csq-v2 yet, and the Header already has the Daemon status indicator that maps to the same lifecycle concerns. One checkbox next to it is the minimum viable UX; a Settings page can come later.
- **Always prefer per-slot 3P over legacy global.** Already the case via `discover_all`'s suppression rule (journal 0025). The poller's dual-path just mirrors that so a user migrating from legacy to per-slot doesn't lose quota data mid-migration.

## Consequences

- **Tokens now refresh for as long as the csq app is open**, without the user needing to run anything. Launching on login + in-process daemon means: log into macOS → csq starts → daemon starts → tokens refresh forever until the user quits the app. The 6–80-hour expiry window from journal 0026 context is closed.
- **External `csq daemon start` still works.** Users debugging the daemon with CLI flags can run it in a terminal; the app's supervisor observes and defers. When they kill the CLI daemon, the supervisor takes over within 60s.
- **Launch-on-login is opt-in.** Defaults to off so first-run doesn't silently install a LaunchAgent without permission. The user ticks the checkbox when they want it.
- **Sessions view shows per-row terminal identity** on macOS with iTerm2 (most specific: tab title) and Linux (less specific: TTY + iTerm env vars if present). Matching a row to the current terminal takes one shell command (`tty` or `echo $TERM_SESSION_ID`) instead of `lsof`-archaeology.
- **Slots 9 and 10 now poll their own API keys.** The probe hits `api.minimax.io` / `api.z.ai` (not the catalog defaults), reads rate-limit headers, and writes `quota.json` under slot 9 / slot 10 keys. The dashboard Accounts tab reflects live 3P quota alongside OAuth slots.
- **Test delta:** 526 → 540 Rust tests (+14: 6 `parse_term_session_id`, 2 iTerm env parser, 6 per-slot 3P loaders). Svelte: 22 unchanged.
- **Build size:** frontend 71 → 72 KB (autostart toggle + terminal identity row).
- **No osascript call on Linux** — `terminal_title` is always None there. The UI falls through to TTY + env-derived tags, which is fine.
- **The legacy 9xx synthetic slots are still supported.** A user who hasn't migrated to per-slot bindings gets the old behavior. Journal 0025 notes them as deprecated; this session makes them co-exist cleanly.

## Follow-Up

- **Windows sessions backend** — still deferred (M8-03). The in-process daemon cfg-gates its `run_daemon` body on `#[cfg(unix)]` and logs a warning on Windows. Launch-on-login via the plugin works on Windows — the daemon lifecycle does not.
- **Model catalog drift** — the 3P poller probes with the catalog's `default_model`. If MiniMax retires `MiniMax-M2` or Z.AI renames `glm-4.6`, probes will 404 until the catalog is bumped. A future session could switch to reading `env.ANTHROPIC_MODEL` from the per-slot settings.json so the probe model matches what the user is actually running.
- **3P→3P rotation** — the `swap_session` guard still refuses rotation between two 3P slots. Journal 0025 flagged this as an open design question.
- **`csq update` self-update** — M7-10, blocked on M11-01 Apple Developer cert.
- **Retina @2x tray icons** — cosmetic, still deferred.

## For Discussion

1. The supervisor's `detect_daemon → acquire → serve` path has a TOCTOU window: between `detect` reporting NotRunning and `acquire` succeeding, another process could race in. The current code handles that by gracefully failing the acquire and looping. Could this hot-loop under pathological conditions (e.g. two csq apps fighting over the same account dir), and should the retry backoff be exponential instead of fixed 60s?
2. The iTerm `osascript` call is a subprocess per `list_sessions` tick (every 5s while the Sessions tab is active). Is the ~50ms overhead cheap enough to ignore, or should we cache the TTY→title map with a short TTL (say 2s) since tab titles rarely change between polls?
3. The 3P poller reads `env.ANTHROPIC_BASE_URL` from per-slot settings but still uses the **catalog default model** for the probe body. If the user's `config-9/settings.json` says `ANTHROPIC_MODEL=MiniMax-M2.7-highspeed`, the probe still sends `MiniMax-M2` — wasted probe request. Should `load_3p_base_url_for_slot` grow a sibling `load_3p_model_for_slot` for symmetry, or is the catalog default safe enough because the probe only reads headers anyway?
