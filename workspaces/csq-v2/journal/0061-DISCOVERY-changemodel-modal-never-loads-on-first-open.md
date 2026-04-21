---
type: DISCOVERY
date: 2026-04-21
created_at: 2026-04-21T23:50:00+08:00
author: co-authored
session_id: 2026-04-21-stable-v2-readiness
session_turn: 34
project: csq-v2
topic: ChangeModelModal never calls list_ollama_models on the first isOpen=false→true transition because a combination of (a) a mistaken skip-when-loading guard and (b) a Svelte-5 effect-re-run cancellation race silently swallowed the invoke; spinner hung forever
phase: analyze
tags:
  [
    svelte,
    tauri-ipc,
    ollama,
    modal,
    $effect,
    untrack,
    regression,
    test-harness-vs-reality,
    alpha21-shipped-broken,
  ]
---

# 0061 — DISCOVERY: `ChangeModelModal` never loads on first open — shipped broken in alpha.21

**Status:** Fixed in this session (still to ship as alpha.22 or stable).
**Severity:** P1 — the Ollama model-switch core feature was non-functional for every user who opened the modal.

## Mechanism

The modal is mounted by `AccountList` with `isOpen=false` and only toggled to `true` when the user clicks "Change model". Two code paths compete:

1. `onMount` runs once with `isOpen=false` → skips `loadInstalled`. Correct.
2. `$effect` reacts to the `isOpen=false→true` edge and was supposed to fire `loadInstalled`.

The `$effect` had two defects that combined silently:

### Defect A — the skip-when-loading guard

```ts
if (modalState.kind !== 'loading' && modalState.kind !== 'picker') {
  loadInstalled(...);
}
```

The initial `modalState` is `{ kind: 'loading' }`. On the first `isOpen=false→true` edge the guard sees `kind === 'loading'` and SKIPS the fetch. Intended as "don't re-fetch while a fetch is in flight," but conflated with the initial state.

### Defect B — Svelte-5 effect-re-run cancellation race

Even after removing Defect A, the first-open invoke fired but the modal state never transitioned out of `loading`. Writing `wasOpen = true` inside the `$effect` invalidates the effect in Svelte 5 — the effect is scheduled to re-run, and BEFORE the re-run, the previous effect's **cleanup** fires:

```ts
return () => {
  cancelled = true;   // <-- fires on re-run, not just on unmount
};
```

`cancelled=true` ticks _before_ the `invoke('list_ollama_models')` Promise resolves. When `loadInstalled` awaits the Promise and checks `isCancelled()`, it returns true and the result is discarded. The modal stays in `loading` forever with no visible error.

## Evidence

- `csq-desktop/src/lib/components/ChangeModelModal.svelte:52` — initial state is `{ kind: 'loading' }`.
- `csq-desktop/src/lib/components/ChangeModelModal.svelte:106-121` (pre-fix) — the skip-when-loading guard.
- Svelte 5 docs on `$effect` — writes to `$state` inside an effect invalidate the effect unless wrapped in `untrack`.
- Unit-test coverage gap: `csq-desktop/src/lib/components/ChangeModelModal.test.ts:46` — every test mounts with `isOpen: true`, so both defects are masked. The real-world sequence (mount closed, flip open) was not covered.

## Fix applied

1. Removed the skip-when-loading guard entirely. Loading on every open edge is cheap (2 s localhost timeout) and correct — a stale 'picker' state after reopen would miss any model the user pulled from a terminal in the meantime.
2. Wrapped all `wasOpen` reads and writes inside the `$effect` with Svelte's `untrack(...)` so the effect doesn't invalidate on its own write.
3. Added a regression test that mounts with `isOpen=false`, flips to `true` via `rerender`, and asserts both that `list_ollama_models` was invoked AND that the picker's `<select>` rendered with the expected options.

## Impact on the "ollama PATH hang" fix (#144)

The earlier theory (GUI-launched app's `PATH=/usr/bin:/bin:/usr/sbin:/sbin` can't find `ollama`) was plausible but not the actual root cause — the Tauri command was never even being invoked, so PATH was irrelevant. PR #144 still stands as defensive improvement: switching to HTTP API removes subprocess fragility from the list path AND gives pull a resolvable absolute path via `find_ollama_bin`. Both layers are now correct.

## Lessons / codify candidates

- **Test mount timing must match production mount timing.** A component that's rendered conditionally in production but unconditionally in tests is hiding half its state machine.
- **Treat every `$state` write inside `$effect` as suspicious.** Either untrack it or justify why effect re-run is desired. Journal this pattern as a codify candidate for a Svelte rule.
- **Silent cancellation swallows errors.** `loadInstalled` checks `isCancelled()` and returns without updating state. The user sees the spinner but no error, no log, no hint. Consider a debug log when a cancellation wins over a successful response.

## For Discussion

1. The skip-when-loading guard was added to prevent double-fetch on rapid open/close cycles (per the surrounding comment). With it removed, what's the actual cost of a double-fetch on a fast open/close? The `list_ollama_models` endpoint is local with a 2 s timeout — is the extra round-trip worth the code complexity, or is the untrack-based version simpler AND correct?
2. If the Svelte test had mounted with `isOpen=false` and flipped to `true`, would Defect A alone have triggered (missing load) and would we have caught it before shipping alpha.21? What does that tell us about the minimum property test should cover — "every reactive open-edge fires the side effect at least once"?
3. The cancellation pattern inside `$effect` is seductive because it parallels `AbortController` flows. But in a Svelte-5 world where effects re-run on their own writes, the cleanup semantics fire too eagerly. Would a monotonic-ID pattern (`let loadRequest = 0; ++loadRequest; if (myId !== loadRequest) return;`) be more robust across future effect refactors, and is that worth a component-level or workspace-level Svelte pattern rule?
