<script lang="ts">
  import { onMount } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import AccountList from "./lib/components/AccountList.svelte";
  import Header from "./lib/components/Header.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import { showToast } from "./lib/stores/toast.svelte";

  // ── Backend event payload shapes ─────────────────────────
  //
  // Must stay in sync with `TraySwapResult` in
  // `csq-desktop/src-tauri/src/lib.rs`. Kept inline (not in a shared
  // types module) because this is the only consumer and a type
  // mismatch here is caught immediately when the tray is clicked.
  interface TraySwapResult {
    account: number;
    config_dir: string | null;
    ok: boolean;
    error: string | null;
  }

  // ── Global event listeners ───────────────────────────────
  //
  // The tray-swap-complete listener is the whole reason this file
  // mounts a Toast host. The Rust side emits the event after every
  // `acct:{id}` tray click finishes (success or failure); without a
  // listener, failed swaps — "no live CC session found" being the
  // common one on a fresh install — are silent and the user gives
  // up on the app thinking it's broken.
  //
  // Listeners are attached in `onMount` (post-hydration, so
  // `listen()` has the IPC bridge) and unsubscribed in the cleanup
  // returned from `onMount`. Tauri's `listen()` returns an async
  // unsubscribe function; we store each one and call them all on
  // teardown.
  onMount(() => {
    const unlistenFns: UnlistenFn[] = [];
    let mounted = true;

    listen<TraySwapResult>("tray-swap-complete", (event) => {
      const payload = event.payload;
      if (payload.ok) {
        showToast("success", `Switched to account #${payload.account}.`);
      } else {
        const reason = payload.error ?? "unknown error";
        showToast(
          "error",
          `Could not switch to account #${payload.account}: ${reason}`,
        );
      }
    }).then((fn) => {
      if (mounted) {
        unlistenFns.push(fn);
      } else {
        // Component unmounted between subscribe call and resolution;
        // release the subscription immediately so we don't leak.
        fn();
      }
    });

    return () => {
      mounted = false;
      for (const fn of unlistenFns) {
        fn();
      }
    };
  });
</script>

<div class="app">
  <Header />
  <main>
    <AccountList />
  </main>
  <Toast />
</div>

<style>
  .app {
    font-family:
      system-ui,
      -apple-system,
      BlinkMacSystemFont,
      "Segoe UI",
      sans-serif;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--bg-primary);
    color: var(--text-primary);
  }
  main {
    flex: 1;
    padding: 1rem;
    overflow-y: auto;
  }
</style>
