<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { getVersion } from '@tauri-apps/api/app';
  import { homeDir, join } from '@tauri-apps/api/path';
  import SettingsPopover from './SettingsPopover.svelte';

  interface DaemonStatusView {
    running: boolean;
    pid: number | null;
  }

  let daemonRunning = $state(false);
  let appVersion = $state<string | null>(null);

  async function fetchDaemonStatus() {
    try {
      // Use `join` so the platform's path separator is honored.
      // Tauri 2.10's `homeDir()` returns a path without a trailing
      // separator, so naive concatenation produces an invalid path
      // like `/Users/esperie.claude/accounts` (see journal 0021).
      const home = await homeDir();
      const baseDir = await join(home, '.claude', 'accounts');
      const status = await invoke<DaemonStatusView>('get_daemon_status', { baseDir });
      daemonRunning = status.running;
    } catch {
      daemonRunning = false;
    }
  }

  async function fetchVersion() {
    try {
      appVersion = await getVersion();
    } catch {
      // Version lookup should never fail — but if it does, hide
      // the span rather than show misleading text (journal 0063 P1-5:
      // alpha.21 shipped with a literal that drifted).
      appVersion = null;
    }
  }

  $effect(() => {
    fetchDaemonStatus();
    fetchVersion();
    const interval = setInterval(fetchDaemonStatus, 10000);
    return () => clearInterval(interval);
  });
</script>

<header>
  <div class="left">
    <h1>Code Squad Q</h1>
    {#if appVersion}<span class="version">v{appVersion}</span>{/if}
  </div>
  <div class="right">
    <div
      class="status"
      title={daemonRunning ? 'Daemon running' : 'Daemon stopped'}
      aria-label={daemonRunning ? 'Daemon running' : 'Daemon stopped'}
    >
      <span class="dot" class:running={daemonRunning}></span>
      <span class="status-label">{daemonRunning ? 'Running' : 'Stopped'}</span>
    </div>
    <SettingsPopover {daemonRunning} />
  </div>
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 1rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    /* Single row, never wrap — the prior layout packed five elements into
       this row and wrapped on narrow widths (the user's reported "squeezy"
       title). Toggles now live in the SettingsPopover. */
    flex-wrap: nowrap;
    gap: 1rem;
    min-height: 2.5rem;
    -webkit-app-region: drag;
  }
  .left {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    flex-shrink: 0;
    min-width: 0;
    white-space: nowrap;
  }
  h1 {
    font-size: 0.9rem;
    font-weight: 600;
    margin: 0;
    white-space: nowrap;
  }
  .version {
    font-size: 0.72rem;
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .right {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-shrink: 0;
    -webkit-app-region: no-drag;
  }
  .status {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.72rem;
    color: var(--text-secondary);
    white-space: nowrap;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--red);
    flex-shrink: 0;
  }
  .dot.running {
    background: var(--green);
  }
  .status-label {
    white-space: nowrap;
  }
</style>
