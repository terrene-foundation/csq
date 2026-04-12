<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { homeDir, join } from '@tauri-apps/api/path';

  interface DaemonStatusView {
    running: boolean;
    pid: number | null;
  }

  let daemonRunning = $state(false);
  let autostartEnabled = $state(false);
  let autostartBusy = $state(false);

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

  // ── Launch-on-login toggle ───────────────────────────────
  //
  // Reflects whether the csq app is registered to start at OS
  // login via `tauri-plugin-autostart`. The plugin handles all
  // three platforms: LaunchAgent on macOS, Run key on Windows,
  // .desktop file on Linux.
  async function fetchAutostart() {
    try {
      autostartEnabled = await invoke<boolean>('get_autostart_enabled');
    } catch {
      autostartEnabled = false;
    }
  }

  async function toggleAutostart() {
    if (autostartBusy) return;
    autostartBusy = true;
    const next = !autostartEnabled;
    try {
      await invoke('set_autostart_enabled', { enabled: next });
      autostartEnabled = next;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('autostart toggle failed:', e);
    } finally {
      autostartBusy = false;
    }
  }

  $effect(() => {
    fetchDaemonStatus();
    fetchAutostart();
    const interval = setInterval(fetchDaemonStatus, 10000);
    return () => clearInterval(interval);
  });
</script>

<header>
  <div class="left">
    <h1>Claude Squad</h1>
    <span class="version">v2.0.0-alpha</span>
  </div>
  <div class="right">
    <label class="autostart" title="Start Claude Squad automatically when you log in">
      <input
        type="checkbox"
        checked={autostartEnabled}
        disabled={autostartBusy}
        onchange={toggleAutostart}
      />
      <span>Launch on login</span>
    </label>
    <div class="status">
      <span class="dot" class:running={daemonRunning}></span>
      <span class="label">{daemonRunning ? 'Daemon running' : 'Daemon stopped'}</span>
    </div>
  </div>
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1rem;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    -webkit-app-region: drag;
  }
  .left { display: flex; align-items: center; gap: 0.5rem; }
  h1 { font-size: 0.9rem; font-weight: 600; margin: 0; }
  .version { font-size: 0.75rem; color: var(--text-secondary); }
  .right {
    display: flex;
    align-items: center;
    gap: 1rem;
    -webkit-app-region: no-drag;
  }
  .autostart {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.72rem;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }
  .autostart input {
    cursor: pointer;
    margin: 0;
  }
  .autostart input:disabled {
    cursor: wait;
  }
  .status {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--red);
  }
  .dot.running { background: var(--green); }
  .label { font-size: 0.75rem; color: var(--text-secondary); }
</style>
