<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";

  // The desktop twin of `csq doctor`'s `codex_slot_write_status` rows: one row per Codex slot
  // whose config writes recorded a condition, read through the same backend reader. The
  // `raced` row carries the owner's acknowledgement button, which runs the SAME core operation as `csq doctor --ack-raced <N>`.

  interface SlotWriteStatusView {
    slot: number;
    status: string[];
    ackable: boolean;
    overflow_stuck?: boolean;
  }

  const MESSAGES: Record<string, string> = {
    raced:
      "a concurrent write raced csq's config update or a leftover tmp file was kept: csq's update may be in place over a concurrent Codex write. Re-check this slot's hook approvals, then acknowledge.",
    "exchange-unsupported":
      "this filesystem has no atomic exchange; a Codex write landing during a csq config update can still be overwritten.",
    "carry-skipped":
      "hook approvals were not copied to a terminal (the config raced or could not be used); approve them in Codex or relaunch.",
    "purge-failed":
      "csq could not clear stale hook approvals from this slot; a swap re-approves.",
    "unrecognised-marker": "unrecognised marker; inspect and remove manually",
  };

  const POLL_MS = 10_000;

  let rows = $state<SlotWriteStatusView[]>([]);
  // Per-slot ack error text, shown on the row that failed.
  let errors = $state<Record<number, string>>({});
  let busy = $state<Record<number, boolean>>({});

  // Newest-request-wins: a slow earlier reply never overwrites a later one.
  let requestSeq = 0;

  async function getBaseDir(): Promise<string> {
    const home = await homeDir();
    return await join(home, ".claude", "accounts");
  }

  async function refresh() {
    const mine = ++requestSeq;
    try {
      const baseDir = await getBaseDir();
      const fetched = await invoke<SlotWriteStatusView[]>(
        "get_codex_slot_write_status",
        { baseDir },
      );
      if (mine === requestSeq) rows = fetched;
    } catch {
      // IPC unavailable or the read failed: keep the last known rows.
    }
  }

  async function acknowledge(slot: number) {
    busy = { ...busy, [slot]: true };
    const { [slot]: _gone, ...rest } = errors;
    errors = rest;
    try {
      const baseDir = await getBaseDir();
      await invoke("ack_codex_slot_raced", { baseDir, slot });
      await refresh();
    } catch (e) {
      errors = { ...errors, [slot]: String(e) };
    } finally {
      const { [slot]: _done, ...left } = busy;
      busy = left;
    }
  }

  $effect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => {
      requestSeq++;
      clearInterval(id);
    };
  });
</script>

{#if rows.length > 0}
  <section class="codex-status" aria-label="Codex config write conditions">
    {#each rows as row (row.slot)}
      <div class="row" data-slot={row.slot}>
        <div class="text">
          <strong>Codex slot {row.slot}</strong>
          {#each row.status as st (st)}
            <div class="msg" data-status={st}>
              {MESSAGES[st] ?? st}{#if st === "unrecognised-marker"}:
                <code>config-{row.slot}/.csq-status-markers/&lt;name&gt;</code>{/if}
            </div>
          {/each}
          {#if row.overflow_stuck}
            <div class="msg" data-status="overflow-stuck">
              Events past the marker cap were folded into an overflow marker the
              acknowledgement does not clear; after re-checking this slot, remove
              <code>config-{row.slot}/.csq-status-markers/overflow</code>
            </div>
          {/if}
          {#if errors[row.slot]}
            <div class="err" role="alert">{errors[row.slot]}</div>
          {/if}
        </div>
        {#if row.ackable}
          <button
            type="button"
            class="ack"
            disabled={busy[row.slot] === true}
            aria-label="Acknowledge raced Codex slot {row.slot}"
            onclick={() => acknowledge(row.slot)}
          >
            Acknowledge
          </button>
        {/if}
      </div>
    {/each}
  </section>
{/if}

<style>
  .codex-status {
    margin: 0.5rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .row {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    background: #fff3cd;
    color: #664d03;
    border: 1px solid #ffe69c;
    border-radius: 4px;
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
  }
  .text {
    flex: 1;
  }
  .err {
    color: var(--danger-text);
    margin-top: 0.25rem;
  }
  .ack {
    padding: 0.25rem 0.75rem;
    background: transparent;
    border: 1px solid #664d03;
    border-radius: 4px;
    color: inherit;
    cursor: pointer;
    font-size: 0.8125rem;
  }
  .ack:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
