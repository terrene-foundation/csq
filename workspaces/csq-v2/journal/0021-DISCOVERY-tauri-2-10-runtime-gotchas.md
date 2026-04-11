---
type: DISCOVERY
date: 2026-04-11
created_at: 2026-04-11T19:45:00+08:00
author: co-authored
session_id: session-2026-04-11c
session_turn: 200
project: csq-v2
topic: Three Tauri 2.10 runtime traps only caught by actually launching the app
phase: implement
tags: [tauri, desktop, gotchas, runtime]
---

# DISCOVERY: Three Tauri 2.10 traps that CI-green apps still hit on `npm run tauri dev`

## Context

All 490 Rust tests, 13 Svelte tests, clippy, fmt, svelte-check, and `npm run build` were green. The app was believed ready to test. The user ran `npm run tauri dev` for the first time and hit **three** runtime failures in sequence, none of which any compile-time or test-suite gate would ever catch.

Each failure is documented here so a future session recognizes the symptom and fixes it in one step instead of debugging from scratch.

## Trap 1: `tauri-plugin-updater` crashes at `did_finish_launching` if `plugins.updater` is missing from `tauri.conf.json`

### Symptom

```
thread 'main' panicked at …/tauri-2.10.3/src/app.rs:1299:11:
Failed to setup app: error encountered during setup hook:
  failed to initialize plugin `updater`:
  Error deserializing 'plugins.updater' within your Tauri configuration:
  invalid type: null, expected struct Config
…
panic in a function that cannot unwind
thread caused non-unwinding panic. aborting.
```

Backtrace bottoms out in `tao::platform_impl::…::did_finish_launching` — the NSApplication delegate callback. macOS never even draws a window.

### Root cause

`tauri-plugin-updater` 2.10 refuses to initialize without a `plugins.updater` config block in `tauri.conf.json`. Earlier 2.x versions accepted a missing block and used empty defaults; 2.10 treats missing as an error, and because it happens inside the `setup` hook of a plugin, the error path is a non-unwinding panic that kills the whole process.

The plugin init was added by an earlier session in anticipation of M11 (signing + update server). No `plugins.updater` block was ever added to `tauri.conf.json` because there was no real endpoint or pubkey to configure. CI never caught it because CI builds the binary but doesn't launch the app. The re-wire lives under `workspaces/csq-v2/todos/active/M11-packaging.md:10` (M11-01 macOS signing) — that's the task that will pair real `endpoints` + `pubkey` with the plugin init.

### Fix in this session

Removed the plugin entirely until M11 wires real signing:

- `app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;` → deleted from `csq-desktop/src-tauri/src/lib.rs`
- `tauri-plugin-updater = "2"` → deleted from `csq-desktop/src-tauri/Cargo.toml`
- `"updater:default"` → deleted from `csq-desktop/src-tauri/capabilities/default.json`

### When re-adding (M11)

The minimum viable config is a `plugins.updater` block in `tauri.conf.json` with **both** `endpoints` and `pubkey`. Placeholder values like `"endpoints": ["https://example.invalid/"]` + a dummy pubkey will let the plugin initialize but fail on actual update checks, which is a better failure mode than crashing at startup. Real values come with signing setup — see `workspaces/csq-v2/todos/active/M11-packaging.md:10` (M11-01 macOS signing) for the task that will pair real `endpoints` + `pubkey` with the plugin init.

### Catchable by

A minimal boot-smoke test — `npm run tauri dev`, wait 3 seconds, check that the main window exists — would catch every "panics at setup" failure mode. Without one, these trap tickets will keep landing the same way.

---

## Trap 2: `homeDir()` in Tauri 2.10 has no trailing separator → string concat breaks paths

### Symptom

```
base directory does not exist: /Users/esperie.claude/accounts
```

The user clicked "+ Add Account → MiniMax → Save" and got a path with the home directory and `.claude` fused together.

### Root cause

```ts
const home = await homeDir(); // "/Users/esperie"  (no trailing /)
return home + ".claude/accounts"; // "/Users/esperie.claude/accounts"  ❌
```

Previous Tauri versions returned `homeDir()` **with** a trailing separator, so string concat worked. 2.10 drops the trailing separator. csq had this bug in at least three places (`AccountList.svelte::getBaseDir`, `AddAccountModal.svelte::submitBearerKey`, and by extension every command call that built the base dir client-side).

### Fix in this session

Always use `@tauri-apps/api/path::join` instead of string concat:

```ts
import { homeDir, join } from "@tauri-apps/api/path";

async function getBaseDir(): Promise<string> {
  const home = await homeDir();
  return await join(home, ".claude", "accounts"); // cross-platform + separator-correct
}
```

`join` handles the platform separator (`/` on Unix, `\` on Windows) and doesn't care whether `homeDir` has a trailing separator or not. It's the safe default for any `path = home + something` pattern in a Tauri app.

### Catchable by

svelte-check doesn't catch it (both sides are strings, the bug is semantic). A runtime test that calls `getBaseDir` and asserts the result exists on disk would catch it. Better: lint against `homeDir() + ` pattern in tsx/svelte files.

---

## Trap 3: `opener:allow-open-url` permission alone doesn't open URLs

### Symptom

User clicked "+ Add Account → Claude". No browser opened. No visible error. Modal transitioned to the "paste the code" step as if the browser had opened.

### Root cause

Capability declared just `opener:allow-open-url`:

```json
"permissions": [
  ...
  "opener:allow-open-url"
]
```

`tauri-plugin-opener` gates URL opening on **two** things: the `open-url` command permission **and** a URL scope that whitelists which URLs may be opened. Without a scope, the call is silently denied — `openUrl` throws, our `try/catch` swallowed the error into `console.warn`, and the modal advanced without feedback.

### Fix in this session

Use the bundled default permission which ships with a sensible scope (any `http`/`https` URL):

```json
"permissions": [
  ...
  "opener:default"
]
```

Also added visible error surfacing: when `openUrl` throws, the error now appears in a red banner at the top of the paste-code step instead of just `console.warn`, and the modal always shows a `<details>`-collapsed "Browser didn't open?" section containing the full authorize URL in a selectable textarea. Users always have the URL one copy-paste away.

### General lesson

`opener:allow-<verb>` and `<plugin>:allow-<verb>` permissions in Tauri are command allow-lists, not scope configurations. Most plugins with dangerous capabilities (opener, fs, shell) layer a second scope check on top. When in doubt, use `<plugin>:default` until you understand what scope the granular permission expects.

### Catchable by

If the modal had asserted "openUrl call returned without throwing" rather than swallowing exceptions, the permission miss would surface immediately. `console.warn` in a webview is not a user-visible signal.

---

## Common thread

All three traps share a root cause: **the CI pipeline doesn't launch the app**. A build-and-test pipeline catches type errors, linter warnings, unit test failures, and missing imports. It doesn't catch:

- Setup-hook panics (Trap 1)
- Runtime path bugs (Trap 2, semantic correctness)
- Silently-denied IPC calls (Trap 3, permission scopes)

A single "launch the binary, wait 5 seconds, check for a visible window, close it" smoke test would catch all three. Adding that to CI would prevent this class of failure from shipping to users.

## For Discussion

1. **Is a 3-second boot smoke test in CI worth the runner time?** Trap 1 would have been caught in under 10 seconds of wall time — `npm run tauri dev &; sleep 3; pgrep tauri && kill` would have flagged the panic at `did_finish_launching` immediately. The cost is one headed-display CI job (Linux Xvfb works; macOS runners can go `osascript`-less). Is the amortized cost of catching one "panics at setup" bug per quarter worth adding a new CI stage? Compare with the current catch mechanism, which is "user reports a bug on first launch".
2. **If `tauri-plugin-updater` had accepted a missing config in 2.10 the way it did in earlier 2.x releases** (Trap 1's counterfactual), csq would have shipped an app that silently had a dead updater plugin registered — the app would launch but `updater.check()` would always fail or return empty. Would that have been better or worse than the current panic? The panic is loud and gets fixed; a silent dead plugin persists across releases unnoticed. Trap 1 may actually be Tauri 2.10 _improving_ the failure mode.
3. **All three traps have the same catch mechanism**: "surface the error to a human instead of swallowing it" (surface the panic as a boot failure; surface the path mismatch as a runtime error; surface the `openUrl` exception in the UI instead of `console.warn`). Are there other silent-failure anti-patterns in csq-desktop that this discovery would flag if we audited the codebase for them? Candidate: every `let _ = window.show()` in the tray handlers, every empty `.catch(() => {})` in the Svelte layer, every `Result::ok()` call that discards the Err variant.

## Cross-references

- 0017-DISCOVERY-tracing-subscriber-log-facade-collision.md — related trap: CI-green code that panics at startup because two logging facades collide. Same pattern: runtime-only failure, silent in tests.
- `.claude/skills/tauri-reference/SKILL.md` — Trap 1-3 codified into the Gotchas section of the skill reference
- `csq-desktop/src-tauri/src/lib.rs` — post-fix setup hook, no plugin_updater
- `csq-desktop/src-tauri/capabilities/default.json` — uses `opener:default` now
