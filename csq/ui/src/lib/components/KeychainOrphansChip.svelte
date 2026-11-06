<script module lang="ts">
  // Mirrors `OrphanSweepStatus` (csq-core credentials/keychain/orphans.rs) as
  // the desktop serialises it inside `OrphanDiagnosticView.status`. Every field
  // is optional here so an older or newer daemon never crashes the chip.
  export interface OrphanSweepCounts {
    keychain_items?: number;
    orphan_candidates?: number;
    pending?: number;
    deleted_total?: number;
    kept_sole_copy?: number;
    kept_siblings?: number;
    kept_pid_in_use?: number;
    kept_revived_after_read?: number;
    dir_reappeared?: number;
    already_gone?: number;
    kept_mint_busy?: number;
    unattested_items?: number;
    kept_process_table_unknown?: number;
    kept_other?: number;
    undetermined?: string | null;
    counts_stale?: boolean;
    process_table_unknown?: string | null;
  }

  export interface KeychainOrphansView {
    level: 'ok' | 'info' | 'warn' | 'needs_action';
    summary: string;
    status?: OrphanSweepCounts | null;
    error?: string | null;
  }

  // One entry per counter worth showing; wording stays inside what the
  // producer's field docs say each counter means. Zero counters are skipped.
  const COUNTER_LINES: Array<[keyof OrphanSweepCounts, (n: number) => string]> = [
    ['orphan_candidates', (n) => `${n} leftover ${n === 1 ? 'item' : 'items'} from closed terminals`],
    ['pending', (n) => `${n} still waiting to be checked`],
    ['deleted_total', (n) => `${n} removed since the background service started`],
    ['kept_sole_copy', (n) => `${n} kept because ${n === 1 ? 'it may be' : 'they may be'} the only copy of a login`],
    ['kept_pid_in_use', (n) => `${n} kept because a program is still running as the closed terminal`],
    ['kept_revived_after_read', (n) => `${n} kept because the terminal came back or the item changed`],
    ['kept_mint_busy', (n) => `${n} kept because a terminal was being created`],
    ['kept_process_table_unknown', (n) => `${n} kept because csq could not rule out a program still running`],
    ['kept_other', (n) => `${n} kept for other reasons`],
    ['kept_siblings', (n) => `${n} kept because ${n === 1 ? 'it holds' : 'they hold'} non-login data such as MCP logins`],
    ['unattested_items', (n) => `${n} left alone because csq has no record of creating ${n === 1 ? 'it' : 'them'}`],
    ['dir_reappeared', (n) => `${n} had a terminal that reappeared before the check`],
    ['already_gone', (n) => `${n} already gone when checked`],
  ];

  const READ_ERROR_LINE: Record<string, string> = {
    unreadable: 'The cleanup status file could not be read.',
    oversized: 'The cleanup status file is larger than expected.',
    corrupt: 'The cleanup status file is damaged.',
  };

  /** Non-zero counters as plain-language lines (exported for tests). */
  export function countLines(status: OrphanSweepCounts | null | undefined): string[] {
    if (!status) return [];
    const lines: string[] = [];
    for (const [key, say] of COUNTER_LINES) {
      const n = status[key];
      if (typeof n === 'number' && n > 0) lines.push(say(n));
    }
    return lines;
  }

  /** The reason cleanup is not finishing, when the structured data names one. */
  export function reasonLine(view: KeychainOrphansView): string | null {
    if (view.error) {
      return `${READ_ERROR_LINE[view.error] ?? 'The cleanup status could not be read.'} Its counts are unknown.`;
    }
    const s = view.status;
    if (!s) return null;
    if (s.undetermined) {
      return 'The last check could not read the keychain, so nothing was deleted. csq will retry.';
    }
    if (s.process_table_unknown) {
      return 'Cleanup is paused: csq cannot tell whether a program is still running as a closed terminal.';
    }
    return null;
  }
</script>

<script lang="ts">
  import { tick } from 'svelte';

  let { orphans }: { orphans: KeychainOrphansView } = $props();

  let open = $state(false);
  let triggerEl: HTMLButtonElement | undefined = $state();
  let panelEl: HTMLDivElement | undefined = $state();

  const needsAction = $derived(orphans.level === 'needs_action');
  const label = $derived(needsAction ? 'Keychain: needs attention' : 'Keychain: cleanup incomplete');
  const tip = $derived(
    needsAction
      ? 'Keychain cleanup needs your attention. Click for details.'
      : 'Keychain cleanup is incomplete. Click for details.',
  );
  const reason = $derived(reasonLine(orphans));
  const lines = $derived(countLines(orphans.status));
  // Backend published a level but no structured counts: show its own summary
  // (bounded and wrapped below) rather than an empty popover.
  const showSummaryFallback = $derived(!orphans.status && !orphans.error && !!orphans.summary);

  async function closeAndRestoreFocus() {
    open = false;
    await tick();
    triggerEl?.focus();
  }

  async function toggle() {
    if (open) {
      await closeAndRestoreFocus();
      return;
    }
    open = true;
    await tick();
    panelEl?.focus();
  }

  $effect(() => {
    if (!open) return;
    function onMouseDown(e: MouseEvent) {
      const t = e.target as Node | null;
      if (!t) return;
      if (panelEl?.contains(t) || triggerEl?.contains(t)) return;
      open = false;
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') void closeAndRestoreFocus();
    }
    document.addEventListener('mousedown', onMouseDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onMouseDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  });
</script>

<div class="chip-wrap">
  <button
    bind:this={triggerEl}
    type="button"
    class="orphans"
    class:needs-action={needsAction}
    title={tip}
    aria-expanded={open}
    aria-haspopup="dialog"
    aria-controls="keychain-orphans-panel"
    data-testid="keychain-orphans"
    onclick={toggle}
  >
    {label}
  </button>

  {#if open}
    <div
      bind:this={panelEl}
      id="keychain-orphans-panel"
      class="panel"
      data-testid="keychain-orphans-panel"
      role="dialog"
      aria-label="Keychain cleanup details"
      tabindex="-1"
    >
      {#if reason}<p class="reason" data-testid="keychain-orphans-reason">{reason}</p>{/if}
      {#if lines.length > 0}
        <ul data-testid="keychain-orphans-lines">
          {#each lines as line (line)}<li>{line}</li>{/each}
        </ul>
      {/if}
      {#if orphans.status?.counts_stale}
        <p class="note">These counts are from the last successful check.</p>
      {/if}
      {#if showSummaryFallback}
        <p class="summary" data-testid="keychain-orphans-summary">{orphans.summary}</p>
      {/if}
      <p class="action">
        To see more or fix this, run <code>csq doctor</code> in a terminal.
      </p>
    </div>
  {/if}
</div>

<style>
  .chip-wrap {
    position: relative;
    display: inline-flex;
    -webkit-app-region: no-drag;
  }
  .orphans {
    font: inherit;
    font-size: 0.72rem;
    color: var(--text-secondary);
    white-space: nowrap;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.1rem 0.5rem;
    cursor: pointer;
  }
  .orphans:hover,
  .orphans[aria-expanded='true'] {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }
  .orphans:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .orphans.needs-action {
    color: var(--red);
    border-color: var(--red);
    font-weight: 600;
  }
  .panel {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    width: 20rem;
    max-width: calc(100vw - 1.5rem);
    max-height: calc(100vh - 5rem);
    overflow-y: auto;
    overflow-wrap: anywhere;
    box-sizing: border-box;
    padding: 0.6rem 0.8rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 8px 28px rgba(0, 0, 0, 0.4);
    color: var(--text-primary);
    font-size: 0.78rem;
    line-height: 1.4;
    white-space: normal;
    z-index: 100;
  }
  .panel:focus-visible {
    outline: 2px solid var(--accent);
  }
  .panel p {
    margin: 0 0 0.5rem;
  }
  .panel ul {
    margin: 0 0 0.5rem;
    padding-left: 1.1rem;
  }
  .panel li {
    margin-bottom: 0.2rem;
  }
  .reason {
    font-weight: 600;
  }
  .note {
    color: var(--text-secondary);
  }
  .summary {
    color: var(--text-secondary);
  }
  .action {
    margin: 0;
    color: var(--text-secondary);
  }
  code {
    font-family: var(--font-mono);
  }
</style>
