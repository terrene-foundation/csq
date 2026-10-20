<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";

  interface AutoCompactFinding {
    location: string;
    root: boolean;
    per_model: boolean;
    pct_override: boolean;
    provider_window: boolean;
  }

  interface AutoCompactStatus {
    guidance: string;
    findings: AutoCompactFinding[];
    unreadable: string[];
  }

  // Read the same collector as doctor; only relative location labels and key
  // presence cross this boundary, never settings contents or credentials.
  const POLL_MS = 10_000;
  let status = $state<AutoCompactStatus | null>(null);
  let refreshFailed = $state(false);
  let requestSeq = 0;

  async function refresh(): Promise<void> {
    const mine = ++requestSeq;
    try {
      const home = await homeDir();
      if (mine !== requestSeq) return;
      const baseDir = await join(home, ".claude", "accounts");
      if (mine !== requestSeq) return;
      const fetched = await invoke<AutoCompactStatus>(
        "get_claude_autocompact_status",
        { baseDir },
      );
      if (mine !== requestSeq) return;
      status = fetched;
      refreshFailed = false;
    } catch {
      if (mine === requestSeq) refreshFailed = true;
    }
  }

  $effect(() => {
    void refresh();
    const id = setInterval(() => void refresh(), POLL_MS);
    return () => {
      requestSeq++;
      clearInterval(id);
    };
  });
</script>

{#if status === null || status.findings.length > 0 || status.unreadable.length > 0 || refreshFailed}
  <section class="autocompact-status" aria-label="Claude auto-compact settings" aria-live="polite">
    {#if status === null && !refreshFailed}
      <div class="notice">Checking Claude auto-compact settings…</div>
    {/if}
    {#if refreshFailed}
      <div class="notice" role="status">
        Could not refresh Claude auto-compact settings.
        {#if status !== null}
          Showing the last known findings; current settings may differ.
        {:else}
          Override status is unknown.
        {/if}
      </div>
    {/if}
    {#each status?.findings ?? [] as finding (finding.location)}
      <div class="notice" data-location={finding.location}>
        <strong>Claude auto-compact override in <code>{finding.location}</code></strong>
        {#if finding.root}
          <div data-override="root">Root override: <code>autoCompactWindow</code></div>
        {/if}
        {#if finding.per_model}
          <div data-override="per-model">Per-model override: <code>modelSettings.*.autoCompactWindow</code></div>
        {/if}
        {#if finding.pct_override}
          <div data-override="pct-override">Percentage override: <code>env.CLAUDE_AUTOCOMPACT_PCT_OVERRIDE</code></div>
        {/if}
        {#if finding.provider_window}
          <div data-override="provider-window">Provider window override: <code>env.CLAUDE_CODE_AUTO_COMPACT_WINDOW</code></div>
        {/if}
        <div data-guidance>{status?.guidance}</div>
      </div>
    {/each}
    {#each status?.unreadable ?? [] as location (location)}
      <div class="notice" data-unreadable={location}>
        Could not read <code>{location}</code>. Auto-compact override status is unknown for this location.
      </div>
    {/each}
  </section>
{/if}

<style>
  .autocompact-status {
    margin: 0.5rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .notice {
    background: #fff3cd;
    color: #664d03;
    border: 0.0625rem solid #ffe69c;
    border-radius: 0.25rem;
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
    line-height: 1.4;
    overflow-wrap: anywhere;
  }
  @media (prefers-color-scheme: dark) {
    .notice {
      background: var(--autocompact-notice-dark-bg);
      color: #ffe69c;
      border-color: var(--autocompact-notice-dark-border);
    }
  }
</style>
