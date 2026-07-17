<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { untrack } from "svelte";
  import AccountList from "./lib/components/AccountList.svelte";
  import SessionList from "./lib/components/SessionList.svelte";
  import Header from "./lib/components/Header.svelte";
  import Toast from "./lib/components/Toast.svelte";
  import UpdateBanner from "./lib/components/UpdateBanner.svelte";
  import CorruptPrefsBanner from "./lib/components/CorruptPrefsBanner.svelte";
  import InteractiveConsole from "./lib/components/InteractiveConsole.svelte";
  import PolicyConsole from "./lib/components/PolicyConsole.svelte";

  // ── Tab state ────────────────────────────────────────────
  //
  // Accounts (existing) and Sessions (new). Accounts shows the
  // quota + token view per account; Sessions shows one row per
  // live `claude` process with its cwd and terminal identity.
  //
  // The default is Accounts because an empty fresh install has no
  // live sessions to show — Sessions would render the empty state
  // on first launch and feel broken.
  //
  // The Enforcement tab (#793 — M-IC interactive per-turn enforcement
  // console) is enterprise-only: the daemon routes it drives are stripped
  // from the community build, so the tab renders only when the binary
  // reports the enterprise edition.
  type Tab = "accounts" | "sessions" | "enforcement" | "policies";
  let activeTab = $state<Tab>("accounts");

  let isEnterprise = $state(false);
  $effect(() => {
    // One-shot edition fetch. The `cancelled` flag + cleanup ensure a slow
    // in-flight Promise can't write into a stale closure if the component
    // remounts (svelte-patterns Rule 3 — every async effect returns teardown).
    let cancelled = false;
    invoke<string>("get_build_edition")
      .then((e) => {
        if (!cancelled) isEnterprise = e === "enterprise";
      })
      .catch(() => {
        if (!cancelled) isEnterprise = false;
      });
    return () => {
      cancelled = true;
    };
  });

  // If the edition resolves to non-enterprise after the Enforcement tab was
  // selected, fall back to Accounts so a tab with no rendered panel can't be
  // left active. `isEnterprise` is the reactive trigger; the `activeTab`
  // read + write are untracked so the effect can't self-invalidate
  // (svelte-patterns Rule 5).
  $effect(() => {
    if (
      !isEnterprise &&
      (untrack(() => activeTab) === "enforcement" ||
        untrack(() => activeTab) === "policies")
    ) {
      untrack(() => {
        activeTab = "accounts";
      });
    }
  });
</script>

<div class="app">
  <Header />
  <CorruptPrefsBanner />
  <UpdateBanner />
  <div class="tabs" role="tablist" aria-label="Dashboard views">
    <button
      id="tab-accounts"
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
      id="tab-sessions"
      class="tab"
      class:active={activeTab === "sessions"}
      role="tab"
      aria-selected={activeTab === "sessions"}
      aria-controls="sessions-panel"
      onclick={() => (activeTab = "sessions")}
    >
      Sessions
    </button>
    {#if isEnterprise}
      <button
        id="tab-enforcement"
        class="tab"
        class:active={activeTab === "enforcement"}
        role="tab"
        aria-selected={activeTab === "enforcement"}
        aria-controls="enforcement-panel"
        onclick={() => (activeTab = "enforcement")}
      >
        Enforcement
      </button>
    {/if}
    {#if isEnterprise}
      <button
        id="tab-policies"
        class="tab"
        class:active={activeTab === "policies"}
        role="tab"
        aria-selected={activeTab === "policies"}
        aria-controls="policies-panel"
        onclick={() => (activeTab = "policies")}
      >
        Policies
      </button>
    {/if}
  </div>
  <main>
    {#if activeTab === "accounts"}
      <div id="accounts-panel" role="tabpanel" aria-labelledby="tab-accounts">
        <AccountList />
      </div>
    {:else if activeTab === "sessions"}
      <div id="sessions-panel" role="tabpanel" aria-labelledby="tab-sessions">
        <SessionList />
      </div>
    {:else if activeTab === "enforcement" && isEnterprise}
      <div id="enforcement-panel" role="tabpanel" aria-labelledby="tab-enforcement">
        <InteractiveConsole />
      </div>
    {:else if activeTab === "policies" && isEnterprise}
      <div id="policies-panel" role="tabpanel" aria-labelledby="tab-policies">
        <PolicyConsole />
      </div>
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
