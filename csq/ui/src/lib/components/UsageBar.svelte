<script lang="ts">
  // `stale` — true when the quota row this bar renders has not been
  // successfully polled within `csq-core/src/quota/status.rs`'s
  // `STALE_THRESHOLD_SECS` (see AccountList.svelte's `isStale`, the
  // single source of truth for the threshold). A stale bar's color
  // is FORCED to a neutral tone regardless of `pct` — a stale row's
  // green/amber/red reading is not evidence of anything, since the
  // daemon may be stopped and the percentage may be hours old.
  let { label, pct, stale = false }: { label: string; pct: number; stale?: boolean } = $props();

  let color = $derived(
    stale ? 'var(--text-tertiary)' :
    pct >= 90 ? 'var(--red)' :
    pct >= 60 ? 'var(--yellow)' :
    'var(--green)'
  );
</script>

<div class="usage-bar" class:stale data-testid={stale ? 'usage-bar-stale' : undefined}>
  <span class="label">{label}</span>
  <div class="bar-track">
    <div class="bar-fill" style="width: {Math.min(pct, 100)}%; background: {color}"></div>
  </div>
  <span class="pct">{pct > 0 && pct < 1 ? '<1' : Math.round(pct)}%</span>
</div>

<style>
  .usage-bar { display: flex; align-items: center; gap: 0.4rem; flex: 1; }
  /* Dims the whole bar (track + fill + pct) — the visual half of
     F1's staleness marking; the age label lives in AccountList.svelte
     next to the bars. */
  .usage-bar.stale { opacity: 0.55; }
  .label { font-size: 0.75rem; color: var(--text-secondary); min-width: 1.5rem; }
  .bar-track {
    flex: 1;
    height: 6px;
    background: var(--bg-tertiary);
    border-radius: 3px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s ease;
  }
  .pct { font-size: 0.75rem; min-width: 2.5rem; text-align: right; font-variant-numeric: tabular-nums; }
</style>
