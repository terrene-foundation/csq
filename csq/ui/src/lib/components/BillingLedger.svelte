<!--
  Phase B' (an internal journal entry D5) — pay-per-token usage display.

  Renders for accounts whose `quota_kind === 'unknown'` (DeepSeek, Ollama,
  any future pay-per-token catalog entry). Replaces the 5h/7d UsageBar pair
  for those slots. Subscription slots (utilization/counter) keep the bars.

  Two-line compact view occupies the same vertical real-estate as the bar
  pair, preserving row-height parity.

  Data source: `get_account_usage(base_dir, account)` Tauri command. The
  command runs the aggregator inline (CC's session-meta + csq's launch log
  → post-hoc time-correlation attribution → cost estimate via static rate
  table). Reload happens on the same 5s poll as the rest of AccountList.
-->
<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

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

  async function load() {
    try {
      summary = await invoke<UsageSummary>('get_account_usage', {
        baseDir,
        account,
      });
      loadError = null;
    } catch (e) {
      loadError = String(e);
    }
  }

  $effect(() => {
    load();
    // No interval here — AccountList's 5s fetchAccounts loop is the
    // refresh driver. Re-rendering this component (props unchanged)
    // wouldn't fire the effect; the parent fetch triggers a remount
    // on data change in practice. If we observe staleness, add a
    // setInterval here mirroring AccountList's cadence.
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
    return `${(n / 1_000_000).toFixed(2)}M`;
  }
</script>

{#if hideWhenEmpty && loadError == null && summary != null && summary.event_count === 0}
  <!--
    Balance card (hideWhenEmpty) with no recorded usage: render NOTHING —
    not even the wrapper div — so no empty padded box paints below the
    balance row (redteam an internal ticket L2). The balance row already carries the signal.
    The `loadError == null` guard keeps a future poll error surfacing through
    the inner {#if loadError} branch rather than being swallowed by this gate
    (forward-looking: today load() fires once per mount, so unreachable).
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
    <div class="ledger-row" data-testid="ledger-7d">
      <span class="ledger-window">7d</span>
      <span class="ledger-cost">{fmtCost(summary.last_7d_cost_usd)}</span>
      <span class="ledger-tokens">
        ({fmtTokens(summary.last_7d_input_tokens + summary.last_7d_output_tokens)} tokens)
      </span>
    </div>
    <div class="ledger-row" data-testid="ledger-30d">
      <span class="ledger-window">30d</span>
      <span class="ledger-cost">{fmtCost(summary.last_30d_cost_usd)}</span>
      <span class="ledger-tokens">
        ({fmtTokens(summary.last_30d_input_tokens + summary.last_30d_output_tokens)} tokens)
      </span>
    </div>
    {#if summary.unestimated_cost_count > 0}
      <div class="ledger-warn" title="The slot's configured model is not in csq's cost-rate table. Tokens are correct; cost is approximate.">
        ⚠ {summary.unestimated_cost_count} session(s) with unrecognized model — cost partially n/a
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
  .ledger-line { font-weight: 500; }
  .ledger-hint { font-size: 0.72rem; opacity: 0.85; }
  .ledger-loading { color: var(--text-secondary); font-style: italic; }
  .ledger-error { color: var(--red); font-style: italic; }
  .ledger-warn { color: var(--text-secondary); font-size: 0.7rem; opacity: 0.9; }
</style>
