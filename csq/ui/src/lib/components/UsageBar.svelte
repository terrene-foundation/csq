<script lang="ts">
  let { label, pct }: { label: string; pct: number } = $props();

  let color = $derived(
    pct >= 90 ? 'var(--red)' :
    pct >= 60 ? 'var(--yellow)' :
    'var(--green)'
  );
</script>

<div class="usage-bar">
  <span class="label">{label}</span>
  <div class="bar-track">
    <div class="bar-fill" style="width: {Math.min(pct, 100)}%; background: {color}"></div>
  </div>
  <span class="pct">{pct > 0 && pct < 1 ? '<1' : Math.round(pct)}%</span>
</div>

<style>
  .usage-bar { display: flex; align-items: center; gap: 0.4rem; flex: 1; }
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
  .pct { font-size: 0.75rem; min-width: 2.5rem; text-align: right; }
</style>
