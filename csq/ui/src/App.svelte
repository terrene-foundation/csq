<script lang="ts">
  import AccountList from "./lib/components/AccountList.svelte";
  import SessionList from "./lib/components/SessionList.svelte";
  import Header from "./lib/components/Header.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import UpdateBanner from "./lib/components/UpdateBanner.svelte";
  import CorruptPrefsBanner from "./lib/components/CorruptPrefsBanner.svelte";

  // ── Tab state ────────────────────────────────────────────
  //
  // Accounts (existing) and Sessions (new). Accounts shows the
  // quota + token view per account; Sessions shows one row per
  // live `claude` process with its cwd and terminal identity.
  //
  // The default is Accounts because an empty fresh install has no
  // live sessions to show — Sessions would render the empty state
  // on first launch and feel broken.
  type Tab = "accounts" | "sessions";
  let activeTab = $state<Tab>("accounts");
</script>

<div class="app">
  <Header />
  <CorruptPrefsBanner />
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
