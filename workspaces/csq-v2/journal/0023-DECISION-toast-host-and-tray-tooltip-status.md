---
type: DECISION
date: 2026-04-11
created_at: 2026-04-11T21:08:00+08:00
author: co-authored
session_id: session-2026-04-11d
session_turn: 25
project: csq-v2
topic: Close tray-swap-complete feedback gap with a module-scoped Toast store + mount-once host in App.svelte, and roll account health into the tray tooltip instead of shipping new icon variants
phase: implement
tags: [desktop, ux, toast, tray, feedback, accessibility]
---

# DECISION: Toast host + tray tooltip rollup close the "silent failure" feedback gap

## Context

REMAINING-GAPS-2026-04-11.md §3.1 flagged that `tray-swap-complete` was emitted by the Rust tray handler with no frontend listener. The real-world symptom: on a fresh install with no live `config-N` dir, a tray click returns `{ok: false, error: "no live CC session found"}` into the void. The user clicks, nothing visibly happens, they click again, `SWAP_IN_FLIGHT` drops the second click — and the only way to see anything is to tail the OS log dir. They assume the app is broken.

§3.2 flagged the companion gap: the tray icon is static, so a user running 8 accounts has to open the dashboard to learn that #3 just hit the 5h ceiling. The gap doc suggested colored PNG icon variants.

## Choice

Two coordinated changes, one commit:

1. **Toast system**: `csq-desktop/src/lib/stores/toast.svelte.ts` exports a module-scoped `$state<Toast[]>` plus `showToast/dismissToast/clearAllToasts`. `csq-desktop/src/lib/components/Toast.svelte` is the single host rendered by `App.svelte`. `App.svelte` attaches a `tauri::listen("tray-swap-complete", ...)` in `onMount` that translates the `TraySwapResult` payload into a success or error toast. Cleanup on unmount calls the `unlisten` function returned by `listen()`.

2. **Tray tooltip rollup**: `csq-desktop/src-tauri/src/lib.rs::compute_tray_status` reads discovery + credentials + quota state and rolls it into a `TrayStatus { total, health }` where `health: TrayHealth` is one of `Empty | Healthy | Expiring { count } | OutOfQuota { count }`. `refresh_tray_menu` calls `tray.set_tooltip(&status.tooltip())` every 30s. The initial `TrayIconBuilder::tooltip` also uses the live aggregate so the first hover on a just-launched app shows live status (not a stale "Claude Squad" placeholder).

## Alternatives Considered

- **Colored PNG tray icon variants (what the gap doc initially suggested)**. Rejected for this session because it requires new design assets (yellow-warn.png, red-error.png) across 1x and 2x DPI, and the macOS tray icon color space needs template-image handling to work in both dark and light menu bars. The tooltip delivers 90% of the user-visible benefit (glance to know if anything needs attention) with zero new binary files. Re-added to the next-session punch list.
- **Dispatch `tray-swap-complete` via a Svelte store listener in `AccountList.svelte`**. Rejected because the event is orthogonal to the account list (it fires even when the window is hidden). Per-component listeners would either duplicate across mounting points or leak when the user closes the dashboard window.
- **Writable Svelte store (`writable`)**. Rejected in favor of module-scoped `$state<Toast[]>` because every consumer of a writable store has to manually `$subscribe` or use the `$store` sigil. A module-level rune array propagates directly through the Svelte 5 compiler — exported, imported, read in templates, no ceremony. Single-file test coverage confirms behavior (toast.test.ts, 9 tests with fake timers).
- **Per-toast timeouts tracked in the toast object itself**. Rejected because a dismissed-then-fires double-delete is a real hazard if the timer id lives inside an array element that gets spliced out. Centralized `Map<number, Timeout>` keyed by id is safer and the `dismissToast` path clears the timer before splicing.
- **Putting the TraySwapResult type in a shared types module**. Rejected because this is the one consumer; a type mismatch surfaces immediately on the next tray click. A shared module hides the contract.

## Consequences

- Failed tray swaps are now user-visible within ~100ms of the emit. "no live CC session found" appears as a red toast; success is a green toast ("Switched to account #N").
- Every 30s (on the existing `refresh_tray_menu` ticker), the tray tooltip updates to reflect current aggregate state: `Claude Squad — 7 account(s) healthy` / `Claude Squad — 2 of 7 account(s) token expiring` / `Claude Squad — 1 of 7 account(s) out of 5h quota`.
- Out-of-quota takes precedence over expiring in the rollup because out-of-quota blocks usage today whereas expiring resolves automatically on refresh.
- Test delta: +9 Svelte tests (toast store with fake timers) + +7 Rust tests (`compute_tray_status` over all health branches). Rust workspace 478 → 486; Svelte 13 → 22.
- Colored icon variants remain a next-session follow-up. The tooltip is not a complete replacement — users still can't see warning state at a glance without hovering.
- `TraySwapResult` struct on the Rust side is now a stable contract. Any future field addition needs a corresponding Svelte interface update.
- The `cancel_login` Tauri command was already wired from modal cleanup; the toast listener does not duplicate that cleanup path.

## Why Not Icons Right Now

Real macOS tray icon variants require three decisions I can't make alone: (1) color palette for "warning" and "error" that reads correctly in both dark and light menu bars, (2) whether to use template images (monochrome) or full-color icons, (3) whether the icon should flip back to normal after the condition clears or require user ack. None of those are reversible once shipped — if we pick colors and the user hates them, every existing install has to migrate on the next release. The tooltip delivers the signal today without locking in any of those design decisions.

## Follow-Up

- **Icon variants** back on the near-term list. Decide on the three questions above, then add `tray-warn.png` / `tray-error.png` under `csq-desktop/src-tauri/icons/` and call `tray.set_icon()` in `refresh_tray_menu` based on `status.health`.
- **Toast for Add Account modal errors**: `AddAccountModal.svelte` currently surfaces provider-key / OAuth exchange errors inline on the step. Consider routing them through the Toast store too, so closing the modal doesn't lose the error. Not urgent — the inline surface is already decent.
- **Dashboard first-paint measurement** (§3.3) is still open.

## For Discussion

1. The tooltip rollup reads the **same** `credentials::load` + `quota_state::load_state` path that `commands::get_accounts` uses. Is that duplication fine (two call sites doing the same work on the 30s tick and the 5s poll) or should the tray poll piggyback on the dashboard's already-cached result? The trade-off is a minor CPU win vs adding a shared cache module that has to survive window-closed state.
2. If we had shipped colored tray icons in this session instead of the tooltip, which reversible design decision above would have been hardest to walk back: the color palette, the template-vs-color choice, or the clear-on-ack semantics?
3. The `Toast` component is currently single-instance (`App.svelte` mounts one). What breaks first if a future feature adds a second `<Toast />` instance somewhere — duplicate rendering, duplicate timers, or duplicate dismissal events? The answer to that tells us whether module-scoped state was the right call or whether we should have scoped the store to a component context.
