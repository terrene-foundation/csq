<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { homeDir, join } from '@tauri-apps/api/path';
  import { setMachineRotationEnabled } from '../stores/machineRotation.svelte';

  // Mirrors the serialized `csq_core::rotation::RotationConfig` returned by
  // the `get_rotation_config` command (csq-core/src/rotation/config.rs).
  // `exclude_accounts` is part of the payload but this setting does not
  // show or edit it, so it is left out of the typed shape.
  interface RotationConfig {
    enabled: boolean;
    threshold_percent: number;
    cooldown_secs: number;
  }

  // Fixed user-facing text. The raw backend error can carry a filesystem
  // path, so it is never rendered (security.md MUST-2 spirit).
  const READ_ERROR = "Couldn't read the auto-swap setting. Try reopening Settings.";
  const WRITE_ERROR = "Couldn't save the auto-swap setting. It was left unchanged.";

  let config = $state<RotationConfig | null>(null);
  let errorText = $state<string | null>(null);
  let busy = $state(false);

  async function baseDir(): Promise<string> {
    const home = await homeDir();
    return join(home, '.claude', 'accounts');
  }

  function isRotationConfig(v: unknown): v is RotationConfig {
    if (typeof v !== 'object' || v === null) return false;
    const c = v as Record<string, unknown>;
    return (
      typeof c.enabled === 'boolean' &&
      typeof c.threshold_percent === 'number' &&
      Number.isFinite(c.threshold_percent) &&
      typeof c.cooldown_secs === 'number' &&
      Number.isFinite(c.cooldown_secs)
    );
  }

  async function load() {
    try {
      const b = await baseDir();
      const cfg = await invoke<unknown>('get_rotation_config', { baseDir: b });
      if (!isRotationConfig(cfg)) throw new Error('malformed rotation config');
      config = cfg;
      setMachineRotationEnabled(cfg.enabled);
      errorText = null;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('rotation config read failed:', e);
      config = null;
      // The stored machine value is no longer trustworthy: per-session rows fall
      // back to what the backend returned for them.
      setMachineRotationEnabled(null);
      errorText = READ_ERROR;
    }
  }

  $effect(() => {
    void load();
  });

  async function toggle() {
    if (busy || config === null) return;
    busy = true;
    const prev = config.enabled;
    const next = !prev;
    // Optimistic: show the new state at once, revert if the write fails.
    config = { ...config, enabled: next };
    errorText = null;
    try {
      const b = await baseDir();
      await invoke('set_rotation_enabled', { baseDir: b, enabled: next });
      // Shared only once the backend confirmed it: per-session controls that
      // follow the machine setting re-derive their state from this.
      setMachineRotationEnabled(next);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('rotation toggle failed:', e);
      if (config !== null) config = { ...config, enabled: prev };
      errorText = WRITE_ERROR;
    } finally {
      busy = false;
    }
  }

  function formatCooldown(secs: number): string {
    const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'}`;
    if (secs > 0 && secs % 3600 === 0) return plural(secs / 3600, 'hour');
    if (secs > 0 && secs % 60 === 0) return plural(secs / 60, 'minute');
    return plural(secs, 'second');
  }
</script>

<section data-testid="auto-rotate-section">
  <h3>Auto-swap</h3>
  <label class="row">
    <input
      type="checkbox"
      data-testid="setting-auto-rotate"
      checked={config?.enabled ?? false}
      disabled={busy || config === null}
      onchange={toggle}
      aria-describedby="auto-rotate-hint"
    />
    <span>Auto-swap when an account runs low</span>
  </label>
  {#if config !== null}
    <p class="hint" id="auto-rotate-hint" data-testid="auto-rotate-hint">
      When a terminal's account passes {config.threshold_percent}% of its
      5-hour limit, csq moves that terminal to a less-used account of the same
      kind. Each terminal waits {formatCooldown(config.cooldown_secs)} before
      moving again.
    </p>
  {:else}
    <span id="auto-rotate-hint" hidden></span>
  {/if}
  {#if errorText !== null}
    <p class="error" role="alert" data-testid="auto-rotate-error">{errorText}</p>
  {/if}
</section>

<style>
  section {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  section h3 {
    margin: 0 0 6px 0;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    font-size: 0.8rem;
    cursor: pointer;
    user-select: none;
  }
  .row input {
    cursor: pointer;
    margin: 0;
  }
  .row input:disabled {
    cursor: wait;
  }
  .hint {
    margin: 4px 0 0 22px;
    font-size: 0.7rem;
    color: var(--text-secondary);
    line-height: 1.4;
  }
  .error {
    margin: 4px 0 0 22px;
    font-size: 0.7rem;
    color: var(--red);
    line-height: 1.4;
  }
</style>
