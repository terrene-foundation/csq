<!--
  Phase B' (an internal journal entry D5) — pay-per-token usage display.

  Renders for accounts whose `quota_kind === 'unknown'` (DeepSeek, Ollama,
  any future pay-per-token catalog entry). Replaces the 5h/7d UsageBar pair
  for those slots. Subscription slots (utilization/counter) keep the bars.

  Two-line compact view occupies the same vertical real-estate as the bar
  pair, preserving row-height parity. The estimate note is one micro line;
  the per-dimension breakdown and the coverage counts sit behind a
  collapsed disclosure so the card does not grow into a wall (an internal ticket).

  Token figures are CACHE-INCLUSIVE: new input + replies + cache written +
  cache reused, four DISJOINT dimensions summed exactly once. Displaying
  input + output alone understated the maintainer's own slot by roughly two
  orders of magnitude, because cached reads dominate the real traffic.

  What this card shows is a LOCAL ESTIMATE computed from session records on
  this machine over a rolling window. It is not a provider invoice and not a
  provider-reported balance, and the copy says so.

  Data source: `get_account_usage(base_dir, account)` Tauri command. The
  command reads the daemon-published ledger first, with a cold-start scan
  fallback. This component polls independently: AccountList keeps keyed
  account cards mounted, so its poll does not reload unchanged child props.
-->
<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { untrack } from 'svelte';

  // The cache and coverage fields are additive and land with the producer
  // half of an internal ticket. They are typed OPTIONAL so this component renders
  // correctly against both the old and the new IPC payload: a cache
  // dimension the backend has not started reporting contributes 0 rather
  // than NaN, and a coverage line whose field is absent is not rendered at
  // all instead of printing "undefined".
  interface UsageSummary {
    total_input_tokens: number;
    total_output_tokens: number;
    total_cost_usd: number;
    last_30d_input_tokens: number;
    last_30d_output_tokens: number;
    last_30d_cost_usd: number;
    last_7d_input_tokens: number;
    last_7d_output_tokens: number;
    last_7d_cost_usd: number;
    last_5d_input_tokens: number;
    last_5d_output_tokens: number;
    last_5d_cost_usd: number;
    today_input_tokens: number;
    today_output_tokens: number;
    today_cost_usd: number;
    event_count: number;
    unestimated_cost_count: number;
    total_cache_creation_tokens?: number;
    total_cache_read_tokens?: number;
    last_30d_cache_creation_tokens?: number;
    last_30d_cache_read_tokens?: number;
    last_7d_cache_creation_tokens?: number;
    last_7d_cache_read_tokens?: number;
    last_5d_cache_creation_tokens?: number;
    last_5d_cache_read_tokens?: number;
    today_cache_creation_tokens?: number;
    today_cache_read_tokens?: number;
    request_count?: number;
    duplicate_snapshots_collapsed?: number;
    finalization_divergent_requests?: number;
    subagent_request_count?: number;
    unidentified_request_count?: number;
  }

  interface WindowRow {
    label: string;
    testid: string;
    cost: number;
    input: number;
    output: number;
    cacheWrite: number;
    cacheRead: number;
    total: number;
  }

  interface CoverageLine {
    key: string;
    text: string;
  }

  // `hideWhenEmpty`: when true, render NOTHING if the slot has no recorded
  // usage (instead of the "Run csq run N…" placeholder). Used by the balance
  // card (DeepSeek), which already shows the remaining balance — an empty
  // ledger placeholder there is noise, not signal.
  let {
    account,
    baseDir,
    hideWhenEmpty = false,
  }: { account: number; baseDir: string; hideWhenEmpty?: boolean } = $props();

  let summary = $state<UsageSummary | null>(null);
  let loadError = $state<string | null>(null);

  // Keep one IPC request in flight across prop changes as well as poll ticks.
  // Tauri invoke cannot be cancelled; a replaced context discards its reply,
  // then starts the newest context when that outstanding request settles.
  let inFlight = false;
  let currentLoad: (() => Promise<void>) | null = null;

  $effect(() => {
    const slot = account;
    const base = baseDir;
    let active = true;
    untrack(() => {
      summary = null;
      loadError = null;
    });

    async function load() {
      if (!active || inFlight) return;
      inFlight = true;
      try {
        const next = await invoke<UsageSummary>('get_account_usage', {
          baseDir: base,
          account: slot,
        });
        if (active) {
          summary = next;
          loadError = null;
        }
      } catch (e) {
        if (active) loadError = String(e);
      } finally {
        inFlight = false;
        if (!active) void currentLoad?.();
      }
    }

    currentLoad = load;
    void load();
    const interval = setInterval(() => void load(), 5000);
    return () => {
      active = false;
      clearInterval(interval);
      currentLoad = null;
    };
  });

  function fmtCost(usd: number): string {
    if (usd === 0) return '$0';
    if (usd < 0.01) return `$${usd.toFixed(4)}`;
    if (usd < 1) return `$${usd.toFixed(3)}`;
    return `$${usd.toFixed(2)}`;
  }

  function fmtTokens(n: number): string {
    if (n < 1000) return `${n}`;
    if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
    if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    return `${(n / 1_000_000_000).toFixed(2)}B`;
  }

  function fmtCount(n: number): string {
    return n.toLocaleString('en-US');
  }

  // The four dimensions are DISJOINT as the provider reports them: `input`
  // excludes anything served from cache, and cache-write and cache-read are
  // separate meters. Summing all four therefore counts every token exactly
  // once — adding a "cached" figure on top of an already-cache-inclusive
  // total is what double counting would look like, and does not happen here.
  function windowRows(s: UsageSummary): WindowRow[] {
    const rows: WindowRow[] = [
      {
        label: '7d',
        testid: 'ledger-7d',
        cost: s.last_7d_cost_usd,
        input: s.last_7d_input_tokens,
        output: s.last_7d_output_tokens,
        cacheWrite: s.last_7d_cache_creation_tokens ?? 0,
        cacheRead: s.last_7d_cache_read_tokens ?? 0,
        total: 0,
      },
      {
        label: '30d',
        testid: 'ledger-30d',
        cost: s.last_30d_cost_usd,
        input: s.last_30d_input_tokens,
        output: s.last_30d_output_tokens,
        cacheWrite: s.last_30d_cache_creation_tokens ?? 0,
        cacheRead: s.last_30d_cache_read_tokens ?? 0,
        total: 0,
      },
    ];
    for (const row of rows) {
      row.total = row.input + row.output + row.cacheWrite + row.cacheRead;
    }
    return rows;
  }

  // Each line is rendered only when its field is actually present, so this
  // component never asserts a coverage figure the backend did not report.
  function coverageLines(s: UsageSummary): CoverageLine[] {
    const lines: CoverageLine[] = [];
    if (s.request_count !== undefined) {
      lines.push({
        key: 'requests',
        text: `${fmtCount(s.request_count)} requests counted from session records on this computer.`,
      });
    }
    if (s.subagent_request_count !== undefined) {
      lines.push({
        key: 'subagents',
        text: `${fmtCount(s.subagent_request_count)} of them came from helper sessions your main session started.`,
      });
    }
    if (s.duplicate_snapshots_collapsed !== undefined) {
      lines.push({
        key: 'duplicates',
        text: `${fmtCount(s.duplicate_snapshots_collapsed)} repeated progress readings were merged, so no request is counted twice.`,
      });
    }
    if (s.finalization_divergent_requests !== undefined) {
      lines.push({
        key: 'divergent',
        text: `${fmtCount(s.finalization_divergent_requests)} requests ended on readings that disagreed; each was counted at its final reading.`,
      });
    }
    if (s.unidentified_request_count !== undefined) {
      lines.push({
        key: 'unidentified',
        text: `${fmtCount(s.unidentified_request_count)} records carried no request id, so each one was counted on its own.`,
      });
    }
    return lines;
  }

  let showDetails = $state(false);
  let rows = $derived(summary == null ? [] : windowRows(summary));
  let coverage = $derived(summary == null ? [] : coverageLines(summary));
  let requestCount = $derived(summary?.request_count);
</script>

{#if hideWhenEmpty && loadError == null && summary != null && summary.event_count === 0}
  <!--
    Balance card (hideWhenEmpty) with no recorded usage: render NOTHING —
    not even the wrapper div — so no empty padded box paints below the
    balance row (redteam an internal ticket L2). The balance row already carries the signal.
    The `loadError == null` guard keeps a future poll error surfacing through
    the inner {#if loadError} branch rather than being swallowed by this gate
    Poll failures stay visible even after a previously empty successful read.
  -->
{:else}
<div class="billing-ledger" data-testid="billing-ledger">
  {#if loadError}
    <div class="ledger-error" title={loadError}>usage data unavailable</div>
  {:else if summary == null}
    <div class="ledger-loading">…</div>
  {:else if summary.event_count === 0}
    <div class="ledger-empty">
      <span class="ledger-line">No usage recorded yet for this slot.</span>
      <span class="ledger-hint">Run <code>csq run {account}</code> in your project dir; sessions appear after CC writes session-meta.</span>
    </div>
  {:else}
    {#each rows as row (row.testid)}
      <div class="ledger-row" data-testid={row.testid} data-total-tokens={row.total}>
        <span class="ledger-window">{row.label}</span>
        <span class="ledger-cost">{fmtCost(row.cost)}</span>
        <span class="ledger-tokens">
          ({fmtTokens(row.total)} tokens, cached input included)
        </span>
      </div>
    {/each}
    <div class="ledger-note" data-testid="ledger-estimate-note">
      <span class="ledger-note-text">
        Estimated here from this computer's session records over a rolling
        window — not a bill from your provider.{#if requestCount !== undefined}
          Covers {fmtCount(requestCount)} requests.{/if}
      </span>
      <button
        type="button"
        class="ledger-details-toggle"
        data-testid="ledger-details-toggle"
        aria-expanded={showDetails}
        onclick={() => (showDetails = !showDetails)}
      >
        {showDetails ? 'Hide details' : 'Show details'}
      </button>
    </div>
    {#if showDetails}
      <div class="ledger-details" data-testid="ledger-details">
        {#each rows as row (row.testid)}
          <div class="ledger-breakdown" data-testid="breakdown-{row.label}">
            <span class="ledger-window">{row.label}</span>
            <span class="ledger-part">new input {fmtTokens(row.input)}</span>
            <span class="ledger-part">replies {fmtTokens(row.output)}</span>
            <span class="ledger-part">cache written {fmtTokens(row.cacheWrite)}</span>
            <span class="ledger-part">cache reused {fmtTokens(row.cacheRead)}</span>
          </div>
        {/each}
        {#each coverage as line (line.key)}
          <span class="ledger-coverage" data-testid="coverage-{line.key}">{line.text}</span>
        {/each}
      </div>
    {/if}
    {#if summary.unestimated_cost_count > 0}
      <!--
        Counted per REQUEST, not per session: the ledger records one event per
        normalized request (an internal ticket producer half), so "session(s)" would name a
        unit this number is not measured in.
      -->
      <div class="ledger-warn" title="No verified rate for one or more request models/timestamps; token counts remain available and cost is partial.">
        ⚠ {summary.unestimated_cost_count} request(s) without verified pricing — cost partially n/a
      </div>
    {/if}
  {/if}
</div>
{/if}

<style>
  .billing-ledger {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    padding: 0.4rem 0;
    font-size: 0.78rem;
  }
  .ledger-row {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }
  .ledger-window {
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 0.7rem;
    min-width: 1.5rem;
  }
  .ledger-cost {
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    font-weight: 500;
  }
  .ledger-tokens {
    color: var(--text-secondary);
    font-size: 0.72rem;
    font-variant-numeric: tabular-nums;
  }
  .ledger-empty {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    color: var(--text-secondary);
  }
  .ledger-empty code {
    background: var(--bg-tertiary);
    padding: 1px 4px;
    border-radius: 2px;
    font-size: 0.7rem;
  }
  .ledger-note {
    display: flex;
    align-items: baseline;
    gap: 0.4rem;
    color: var(--text-secondary);
    font-size: 0.68rem;
    line-height: 1.25;
  }
  .ledger-note-text { flex: 1 1 auto; }
  .ledger-details-toggle {
    flex: 0 0 auto;
    background: none;
    border: none;
    padding: 0;
    color: var(--text-secondary);
    font-size: 0.68rem;
    font-family: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
  .ledger-details-toggle:hover,
  .ledger-details-toggle:focus-visible {
    color: var(--text-primary);
  }
  .ledger-details {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    padding-top: 0.15rem;
  }
  .ledger-breakdown {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.4rem;
    font-size: 0.7rem;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }
  .ledger-coverage {
    font-size: 0.68rem;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
    line-height: 1.3;
  }
  .ledger-line { font-weight: 500; }
  .ledger-hint { font-size: 0.72rem; opacity: 0.85; }
  .ledger-loading { color: var(--text-secondary); font-style: italic; }
  .ledger-error { color: var(--red); font-style: italic; }
  .ledger-warn { color: var(--text-secondary); font-size: 0.7rem; opacity: 0.9; }
</style>
