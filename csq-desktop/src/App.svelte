<script lang="ts">
  import { onMount } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import AccountList from "./lib/components/AccountList.svelte";
  import SessionList from "./lib/components/SessionList.svelte";
  import Header from "./lib/components/Header.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import UpdateBanner from "./lib/components/UpdateBanner.svelte";
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

  // ── Tab state ────────────────────────────────────────────
  //
  // Accounts (existing) and Sessions (new). Accounts shows the
  // quota + token view per account; Sessions shows one row per
  // live `claude` process with its cwd and a targeted swap action.
  //
  // The default is Accounts because an empty fresh install has no
  // live sessions to show — Sessions would render the empty state
  // on first launch and feel broken.
  type Tab = "accounts" | "sessions";
  let activeTab = $state<Tab>("accounts");

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
  <UpdateBanner />
  <div class="tabs" role="tablist" aria-label="Dashboard views">
    <button
      class="tab"
      class:active={activeTab === "accounts"}
      role="tab"
      aria-selected={activeTab === "accounts"}
      aria-controls="accounts-panel"
      onclick={() => (activeTab = "accounts")}
    >
      Accounts
    </button>
    <button
      class="tab"
      class:active={activeTab === "sessions"}
      role="tab"
      aria-selected={activeTab === "sessions"}
      aria-controls="sessions-panel"
      onclick={() => (activeTab = "sessions")}
    >
      Sessions
    </button>
  </div>
  <main>
    {#if activeTab === "accounts"}
      <section id="accounts-panel" role="tabpanel">
        <AccountList />
      </section>
    {:else}
      <section id="sessions-panel" role="tabpanel">
        <SessionList />
      </section>
    {/if}
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
  .tabs {
    display: flex;
    gap: 0;
    padding: 0 1rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .tab {
    padding: 0.5rem 0.9rem;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    font: inherit;
    font-size: 0.8rem;
    cursor: pointer;
    transition:
      color 0.15s,
      border-color 0.15s;
  }
  .tab:hover {
    color: var(--text-primary);
  }
  .tab.active {
    color: var(--text-primary);
    border-bottom-color: var(--accent);
  }
  main {
    flex: 1;
    padding: 1rem;
    overflow-y: auto;
  }
</style>
