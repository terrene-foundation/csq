<script lang="ts">
  let { status, expiresSecs }: { status: string; expiresSecs: number | null } = $props();

  let color = $derived(
    status === 'healthy' ? 'var(--green)' :
    status === 'expiring' ? 'var(--yellow)' :
    status === 'expired' ? 'var(--red)' :
    'var(--text-tertiary)'
  );

  let label = $derived(
    status === 'healthy' ? formatTime(expiresSecs) :
    status === 'expiring' ? `Expires ${formatTime(expiresSecs)}` :
    status === 'expired' ? 'Expired' :
    'No token'
  );

  function formatTime(secs: number | null): string {
    if (secs == null || secs <= 0) return '';
    // Show minutes through the entire final 2h. A healthy token is topped up
    // by the daemon at the 2h refresh window, so the 1h–2h band is the live
    // pending-refresh countdown — flooring it to a static "1h" (the old
    // `< 3600` cutoff) read as a stuck token (journal 0062 Q3). Minutes make
    // it legible as a countdown: "119m" → "61m".
    if (secs < 7200) return `${Math.floor(secs / 60)}m`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
    return `${Math.floor(secs / 86400)}d`;
  }
</script>

<span class="token-badge" style="color: {color}">
  <span class="dot" style="background: {color}"></span>
  {label}
</span>

<style>
  .token-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.75rem;
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }
</style>
