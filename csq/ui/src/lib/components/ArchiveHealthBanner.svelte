<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";

  // Public view of csq_core::archive_health findings: fixed check id,
  // state, one-line reason and fix hint. Paths are "~/..." only.
  interface ArchiveFinding {
    check: string;
    state: "warn" | "unknown";
    reason: string;
    hint: string;
  }

  // The archive is opt-in by presence: an empty list shows nothing. The check
  // runs a 2 s-capped launchctl in the backend, so poll slowly.
  const POLL_MS = 120_000;
  let findings = $state<ArchiveFinding[]>([]);
  // Dismissal lasts for this session only (in memory) and is keyed to the SET of
  // findings (check + state): a new or changed finding re-shows the banner.
  let dismissedKey = $state<string | null>(null);
  // The command has never succeeded (e.g. it errors): say so instead of staying
  // silent, because an unchecked backup must not look healthy.
  // Consecutive failed polls. One failure with no prior success, or three in a
  // row after one, shows the error state (a transient blip does not).
  let loaded = $state(false);
  let failures = $state(0);
  const FAILURES_BEFORE_ERROR = 3;
  const checkFailed = $derived(
    failures > 0 && (!loaded || failures >= FAILURES_BEFORE_ERROR),
  );
  let requestSeq = 0;

  async function refresh(): Promise<void> {
    const mine = ++requestSeq;
    try {
      const home = await homeDir();
      if (mine !== requestSeq) return;
      const baseDir = await join(home, ".claude", "accounts");
      if (mine !== requestSeq) return;
      const fetched = await invoke<ArchiveFinding[]>("get_archive_health", {
        baseDir,
      });
      if (mine !== requestSeq) return;
      findings = fetched;
      loaded = true;
      failures = 0;
    } catch {
      // Keep the last known findings rather than hide a warning; with no prior
      // success, surface that the check itself failed.
      if (mine === requestSeq) failures += 1;
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

  const hasWarn = $derived(findings.some((f) => f.state === "warn"));
  const findingsKey = $derived(
    findings
      .map((f) => `${f.check}:${f.state}`)
      .sort()
      .join("|"),
  );
</script>

{#if checkFailed}
  <div role="alert" class="archive-banner">
    <div class="body">
      <strong>Backup status could not be checked</strong>
    </div>
  </div>
{/if}
{#if findings.length > 0 && dismissedKey !== findingsKey}
  <div role="alert" class="archive-banner" class:warn={hasWarn}>
    <div class="body">
      <strong>
        {hasWarn
          ? "Backup is not fully active"
          : "Backup status could not be verified"}
      </strong>
      <ul>
        {#each findings as f (f.check)}
          <li data-check={f.check}>
            <span class="state">{f.state === "warn" ? "WARN" : "UNKNOWN"}</span>
            {f.reason}
            <code class="hint">{f.hint}</code>
          </li>
        {/each}
      </ul>
    </div>
    <button
      type="button"
      class="dismiss"
      onclick={() => (dismissedKey = findingsKey)}
      aria-label="Dismiss backup notice for this session"
    >
      Dismiss
    </button>
  </div>
{/if}

<style>
  .archive-banner {
    background: #e7f1ff;
    color: #052c65;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #9ec5fe;
    font-size: 0.875rem;
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
  }
  .archive-banner.warn {
    background: #fff3cd;
    color: #664d03;
    border-bottom-color: #ffe69c;
  }
  .body {
    flex: 1;
  }
  ul {
    margin: 0.25rem 0 0;
    padding-left: 1.25rem;
  }
  .state {
    font-weight: 600;
  }
  .hint {
    display: block;
    font-size: 0.75rem;
    opacity: 0.85;
  }
  .dismiss {
    padding: 0.25rem 0.75rem;
    background: transparent;
    border: 1px solid currentColor;
    border-radius: 4px;
    color: inherit;
    cursor: pointer;
    font-size: 0.8125rem;
  }
</style>
