---
type: DISCOVERY
date: 2026-04-17
created_at: 2026-04-17T12:00:00+08:00
author: co-authored
session_id: 2026-04-17-post-alpha14-gui-launch-fixes
project: csq-v2
topic: GUI-launched Tauri apps on macOS inherit neither shell PATH nor single-instance semantics — both failures visible after the alpha.14 DMG rolled out
phase: implement
tags:
  [
    macos,
    tauri,
    gui-launch,
    path-inheritance,
    single-instance,
    launch-agent,
    runtime-resolution,
    anthropic-transport,
  ]
---

# 0057 — DISCOVERY: GUI-launched apps miss shell PATH and have no duplicate-instance guard

**Status:** Resolved (this branch)
**Severity:** P1 — silent token-refresh failure on every install outside the developer's own terminal; visible-but-benign duplicate tray icons at login.

## Context

Two independent bug reports from a fresh `.app` install of csq-desktop v2.0.0-alpha.14:

1. **"Upon restart, I get 2 copies of csq desktop."** Two tray icons, two dashboard windows, two daemon supervisors racing the PidFile.
2. **Auto-refresh silently dead on GUI-launched installs.** Every account's token expired on its own schedule despite the in-process daemon supposedly running. Spawning `csq` from a terminal made refresh work again.

Both reproduce only when the `.app` is launched from Finder, the Dock, `open`, or a `LaunchAgent` — never when launched from a shell session. That narrow reproduction pointed at macOS GUI launch behavior, not at our logic.

## Finding 1 — GUI launches inherit a hollow PATH

When macOS starts a `.app` from Finder, Dock, Spotlight, or a LaunchAgent plist, the child process inherits the system default environment:

```
PATH=/usr/bin:/bin:/usr/sbin:/sbin
```

None of the modern runtime install locations appear in that list:

| Installer                 | Install prefix      | In GUI PATH? |
| ------------------------- | ------------------- | ------------ |
| Homebrew (Apple Silicon)  | `/opt/homebrew/bin` | No           |
| Homebrew (Intel / manual) | `/usr/local/bin`    | No           |
| Bun                       | `~/.bun/bin`        | No           |
| Volta                     | `~/.volta/bin`      | No           |
| nvm / fnm                 | version-specific    | No           |

Since journal `0056` (Cloudflare TLS fingerprinting), `csq-core::http::find_js_runtime` shells out to `node` or `bun` for every Anthropic endpoint — OAuth token refresh, `GET /api/oauth/usage`, paste-code exchange. When that lookup misses, every Anthropic-bound HTTP call returns `Err("neither node nor bun found on PATH")`, and because the refresher catches and logs at `warn` (journal `0052` redaction discipline prevents it from surfacing upstream) the failure presents to the user as "tokens are expiring on schedule" — indistinguishable from an unmanaged install.

**Why this was invisible in dev and CI:**

- Developers launch csq from iTerm/Terminal, which spawned from a shell that sourced `~/.zshrc` and exported Homebrew's bindir into PATH. The child inherits that PATH.
- CI runs the binary as a subprocess of the runner shell, which also has a full PATH.
- The one environment where this breaks — launching from Finder — is the ONLY environment normal users see.

The `accounts::login::find_claude_binary` helper in `csq-core/src/accounts/login.rs` already solved the same problem for the `claude` executable, using the same two-stage pattern (PATH walk → system-wide dirs → per-user dirs under `$HOME`). `find_js_runtime` simply had not been given the same treatment.

## Finding 2 — No single-instance guard between autostart and login-restore

Tauri's `tauri-plugin-autostart` installs a macOS `LaunchAgent` plist at `~/Library/LaunchAgents/<bundle-id>.plist`. At login, two independent launch paths race:

1. The LaunchAgent fires.
2. macOS `System Settings → Desktops & Dock → "Reopen windows when logging back in"` restores the app if it was running at logout (on by default).

Without a single-instance guard, both reach `tauri::Builder::default()`, each builds its own tray icon, its own daemon supervisor, its own update-check thread, and its own OAuth state store. The duplicate tray icons are the user-visible symptom. The less-visible symptom is that the two daemon supervisors fight over the PidFile — one wins, one backs off into an observer loop that will never do useful work. Worse, if the losing supervisor inherits a GUI-launch PATH (see Finding 1), it sits silently not refreshing anything while appearing to be alive.

Neither `tauri-plugin-autostart` nor Tauri core provide single-instance behavior by default. The first-class fix is `tauri-plugin-single-instance`.

## Resolution

### Fix A — Node/Bun runtime probe

`csq-core/src/http.rs`:

- Changed `find_js_runtime()` return type from `&'static str` to owned `String` so callers can use the resolved full path with `Command::new`, bypassing PATH lookup entirely when an absolute path is cached.
- Added two-stage resolution mirroring `accounts::login::find_claude_binary`:
  1. **PATH walk** (`node` → `bun`) — fast path for CLI use and dev terminal launches.
  2. **Absolute-path probe** — new const lists:
     ```
     SYSTEM_WIDE_JS_RUNTIMES = [
       "/opt/homebrew/bin/node",
       "/opt/homebrew/bin/bun",
       "/usr/local/bin/node",
       "/usr/local/bin/bun",
       "/usr/bin/node",
     ]
     PER_USER_JS_RUNTIMES = [".bun/bin/bun", ".volta/bin/node"]
     ```
  3. Cached in a `OnceLock<Result<String, String>>` for the life of the process.
- Extracted `resolve_js_runtime()` as a pure function behind the cache so unit tests can exercise the lookup without latching on the first observed result.
- Added tests guarding the candidate lists and the happy path.

### Fix B — Single-instance plugin

`csq-desktop/src-tauri/`:

- Added `tauri-plugin-single-instance = "2"` to `Cargo.toml`.
- Registered as the **first** plugin in `lib.rs` (must precede `autostart`, `opener`, `log` so the second-instance detection fires before any tray icon or daemon supervisor is built).
- Callback shows/unminimizes/focuses the existing `main` window so the second launch behaves like "click the dock icon" rather than silently exiting.

### Spec correction

`specs/00-manifest.md` §0.3 invariant "csq must not require Node at runtime" was stale since journal 0056 (PR #125). Updated to describe the post-Cloudflare reality: Node or Bun is required for Anthropic endpoints only, resolved via PATH walk + absolute-path fallbacks. Marked revision 1.0.1.

## Impact on existing invariants and rules

- **INV-06 (daemon is sole refresher)** — still holds; the refresher just has a more robust runtime lookup.
- **Rule `account-terminal-separation.md` §1** — unaffected.
- **ADR-001** — partially superseded. The "no Node at runtime" goal fell to the Cloudflare constraint in journal 0056; this journal documents the fallout and makes it explicit in the manifest.
- **Spec 04 (daemon)** — no contract change. Transport details remain in `csq-core/src/http.rs` module docs.

## Consequences & follow-ups

1. **Installer-side guidance.** A fresh user with zero JS runtimes installed will hit `no JS runtime found in PATH or standard install locations`. `csq doctor` (outstanding milestone) MUST probe for Node/Bun and surface this clearly with an install hint. Until `doctor` lands, the error only surfaces in daemon logs.
2. **Windows and Linux.** The `SYSTEM_WIDE_JS_RUNTIMES` list is Unix-shaped. On Windows the standard install locations differ (`C:\Program Files\nodejs`, `%USERPROFILE%\AppData\Local\...`). The current fallback is a no-op there because `Path::new("/opt/homebrew/bin/node").is_file()` returns false on Windows anyway. Linux has enough overlap (`/usr/bin/node`, `~/.bun/bin/bun`) that the fallback still helps. A future refactor might split per `cfg(target_os)`.
3. **Observability.** The refresher still logs at `warn` when the runtime is missing. Consider promoting to `error` and surfacing a tray badge (tray-icon work item remains open).
4. **Single-instance on Linux/Windows.** `tauri-plugin-single-instance` uses a per-user IPC endpoint on every platform, so the fix applies uniformly. No platform-specific branching needed.

## For discussion

1. The candidate path list duplicates logic already in `accounts::login::SYSTEM_WIDE_DIRS` and `PER_USER_SUBDIRS`. Should a shared `platform::runtime_lookup` module absorb both, or is the coupling shallow enough that duplication reads cleaner than a cross-cutting abstraction?
2. If Cloudflare ever accepts rustls' JA3/JA4 fingerprint again, the Node.js transport becomes dead weight. Would reverting to `reqwest` rescue the manifest's original "no Node at runtime" promise, or has the shell-out already paid for itself in ways we'd want to keep (e.g., TLS-fingerprint parity with CC, no retry of the rustls upgrade churn)?
3. The duplicate-instance bug was visible (two tray icons) and therefore reported within hours. The PATH bug was invisible (tokens silently not refreshing) and therefore would have festered until a user noticed "I have to re-auth every day." What other GUI-vs-terminal environment deltas on macOS could be silently affecting csq — `DYLD_*`, `TMPDIR`, `HOME`, umask — and is there a `csq doctor` check that can assert parity between "launched from Finder" and "launched from shell" at install time?
