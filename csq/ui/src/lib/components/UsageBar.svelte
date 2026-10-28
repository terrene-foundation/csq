<script lang="ts">
  // `stale` — true when the quota row this bar renders has not been
  // successfully polled within `csq-core/src/quota/status.rs`'s
  // `STALE_THRESHOLD_SECS` (see AccountList.svelte's `isStale`, the
  // single source of truth for the threshold). A stale bar's color
  // is FORCED to a neutral tone regardless of `pct` — a stale row's
  // green/amber/red reading is not evidence of anything, since the
  // daemon may be stopped and the percentage may be hours old.
  //
  // `pct === null` — C2 (journal `operator-surfaces`): the account's
  // quota row matched (`has_quota=true` upstream) but carries no window
  // for THIS specific label (e.g. a weekly-only plan has a `seven_day`
  // window and no `five_hour` one). `AccountView.five_hour_pct` /
  // `seven_day_pct` are `number | null` precisely so this case is
  // representable — a `0` here would be a fabricated measurement,
  // indistinguishable from a genuine 0% reading. `emptyLabel` is the
  // text shown in place of a bar + percentage; callers pass the SAME
  // vocabulary `csq-core/src/quota/status.rs::render_status_table` uses
  // (`"idle"` for 5h, `"—"` for 7d) so the desktop and CLI agree.
  let {
    label,
    pct,
    stale = false,
    emptyLabel = '—',
  }: { label: string; pct: number | null; stale?: boolean; emptyLabel?: string } = $props();

  let color = $derived(
    stale ? 'var(--text-tertiary)' :
    pct !== null && pct >= 90 ? 'var(--red)' :
    pct !== null && pct >= 60 ? 'var(--yellow)' :
    'var(--green)'
  );
</script>

<div
  class="usage-bar"
  class:stale
  class:empty={pct === null}
  data-testid={stale ? 'usage-bar-stale' : pct === null ? 'usage-bar-empty' : undefined}
>
  <span class="label">{label}</span>
  <div class="bar-track">
    {#if pct !== null}
      <div class="bar-fill" style="width: {Math.min(pct, 100)}%; background: {color}"></div>
    {/if}
  </div>
  <span class="pct">{pct === null ? emptyLabel : `${pct > 0 && pct < 1 ? '<1' : Math.round(pct)}%`}</span>
</div>

<style>
  .usage-bar { display: flex; align-items: center; gap: 0.4rem; flex: 1; }
  /* Dims the whole bar (track + fill + pct) — the visual half of
     F1's staleness marking; the age label lives in AccountList.svelte
     next to the bars. */
  .usage-bar.stale { opacity: 0.55; }
  /* No window at all for this label (`pct === null`) — the track stays
     empty (no `.bar-fill` rendered above) and the text reads the
     caller's `emptyLabel` instead of a percentage, so an absent window
     never looks like a measured one. */
  .usage-bar.empty .pct { color: var(--text-tertiary); }
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
