<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { getVersion } from '@tauri-apps/api/app';
  import { homeDir, join } from '@tauri-apps/api/path';
  import { tick } from 'svelte';

  let { daemonRunning = false }: { daemonRunning?: boolean } = $props();

  let open = $state(false);
  let autostartEnabled = $state(false);
  let autostartBusy = $state(false);
  let dockHideSupported = $state(false);
  let dockHidden = $state(false);
  let dockHiddenBusy = $state(false);
  let dashboardAtLaunch = $state(true);
  let dashboardAtLaunchBusy = $state(false);
  let appVersion = $state<string | null>(null);

  let panelEl: HTMLDivElement | undefined = $state();
  let triggerEl: HTMLButtonElement | undefined = $state();

  async function baseDir(): Promise<string> {
    const home = await homeDir();
    return join(home, '.claude', 'accounts');
  }

  async function fetchAll() {
    try {
      appVersion = await getVersion();
    } catch {
      appVersion = null;
    }
    try {
      autostartEnabled = await invoke<boolean>('get_autostart_enabled');
    } catch {
      autostartEnabled = false;
    }
    try {
      dockHideSupported = await invoke<boolean>('is_dock_hide_supported');
    } catch {
      dockHideSupported = false;
    }
    // Cache the base dir for the file-system-backed prefs so we don't call
    // homeDir()+join() twice per fetch (R1 svelte-specialist NIT).
    let b: string | null = null;
    try {
      b = await baseDir();
    } catch {
      b = null;
    }
    if (dockHideSupported && b !== null) {
      try {
        dockHidden = await invoke<boolean>('get_dock_hidden', { baseDir: b });
      } catch {
        dockHidden = false;
      }
    }
    if (b !== null) {
      try {
        dashboardAtLaunch = await invoke<boolean>('get_dashboard_at_launch', { baseDir: b });
      } catch {
        dashboardAtLaunch = true;
      }
    } else {
      dashboardAtLaunch = true;
    }
  }

  // Initial fetch on mount; the popover surfaces persisted state without
  // requiring the user to open it first (so the About section is current
  // whenever the panel is opened).
  $effect(() => {
    fetchAll();
  });

  // Closes the panel and returns focus to the trigger button. The single
  // close path — used by `toggleOpen` (trigger re-click), the close button,
  // and the ESC handler — so any future change to dismissal behavior (e.g.
  // an animation delay before focus) lives in one place. `triggerEl?.focus()`
  // is safe across unmount: the optional chain silently skips when the
  // component has been torn down between `open = false` and the tick await.
  async function closePanelAndRestoreFocus() {
    open = false;
    await tick();
    triggerEl?.focus();
  }

  async function toggleOpen() {
    // Event handlers run outside any reactive tracking context, so a bare
    // read of `open` is safe (no self-invalidation risk that `untrack`
    // would defend against — R1 svelte-specialist LOW).
    if (open) {
      await closePanelAndRestoreFocus();
      return;
    }
    open = true;
    // Re-fetch on open so a freshly-toggled tray pref (or an external
    // file edit) is reflected in the panel even after the initial mount.
    await fetchAll();
    // Focus management for `role="dialog"` (R1 svelte-specialist HIGH):
    // move focus into the panel so keyboard users can Tab through the
    // toggles without traversing every header element first. The panel
    // itself carries `tabindex="-1"` so it accepts programmatic focus.
    await tick();
    panelEl?.focus();
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
      // Revert the checkbox to its pre-flip value so the visible state
      // matches the unchanged underlying pref (R1 svelte-specialist NIT —
      // parity with the dock-hide and dashboard-at-launch reverts).
      autostartEnabled = !next;
    } finally {
      autostartBusy = false;
    }
  }

  async function toggleDockHidden() {
    if (dockHiddenBusy) return;
    dockHiddenBusy = true;
    const next = !dockHidden;
    try {
      const b = await baseDir();
      const saved = await invoke<boolean>('set_dock_hidden', { baseDir: b, hidden: next });
      dockHidden = saved;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('dock-hide toggle failed:', e);
      dockHidden = !next;
    } finally {
      dockHiddenBusy = false;
    }
  }

  async function toggleDashboardAtLaunch() {
    if (dashboardAtLaunchBusy) return;
    dashboardAtLaunchBusy = true;
    const next = !dashboardAtLaunch;
    try {
      const b = await baseDir();
      const saved = await invoke<boolean>('set_dashboard_at_launch', {
        baseDir: b,
        enabled: next,
      });
      dashboardAtLaunch = saved;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('dashboard_at_launch toggle failed:', e);
      dashboardAtLaunch = !next;
    } finally {
      dashboardAtLaunchBusy = false;
    }
  }

  // Click-outside closes the panel. The trigger button is excluded from
  // the outside set so a click on it falls through to toggleOpen (which
  // would otherwise immediately re-open after we close).
  $effect(() => {
    if (!open) return;
    function handler(e: MouseEvent) {
      const t = e.target as Node | null;
      if (!t) return;
      if (panelEl?.contains(t)) return;
      if (triggerEl?.contains(t)) return;
      open = false;
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  });

  // ESC closes the panel AND restores focus to the trigger (a11y parity
  // with the close button — keyboard users must end up where they started).
  $effect(() => {
    if (!open) return;
    function handler(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        void closePanelAndRestoreFocus();
      }
    }
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  });
</script>

<div class="settings-popover">
  <button
    bind:this={triggerEl}
    class="trigger"
    data-testid="settings-trigger"
    aria-label="Settings"
    aria-expanded={open}
    aria-haspopup="dialog"
    onclick={toggleOpen}
    title="Settings"
  >
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
      <path
        fill="currentColor"
        d="M14.6 8.6a6.7 6.7 0 0 0 0-1.2l1.3-1a.4.4 0 0 0 .1-.5l-1.2-2.1a.4.4 0 0 0-.5-.2l-1.6.6a5 5 0 0 0-1-.6L11.4.9a.4.4 0 0 0-.4-.4H8.6a.4.4 0 0 0-.4.4l-.3 1.7a5 5 0 0 0-1 .6l-1.6-.6a.4.4 0 0 0-.5.2L3.6 4.9a.4.4 0 0 0 .1.5l1.3 1a6.7 6.7 0 0 0 0 1.2l-1.3 1a.4.4 0 0 0-.1.5l1.2 2.1a.4.4 0 0 0 .5.2l1.6-.6a5 5 0 0 0 1 .6l.3 1.7a.4.4 0 0 0 .4.4h2.4a.4.4 0 0 0 .4-.4l.3-1.7a5 5 0 0 0 1-.6l1.6.6a.4.4 0 0 0 .5-.2l1.2-2.1a.4.4 0 0 0-.1-.5l-1.3-1zM8 10.5A2.5 2.5 0 1 1 8 5.5a2.5 2.5 0 0 1 0 5z"
      />
    </svg>
  </button>

  {#if open}
    <div
      bind:this={panelEl}
      class="panel"
      data-testid="settings-panel"
      role="dialog"
      aria-label="csq settings"
      tabindex="-1"
    >
      <div class="panel-header">
        <h2>Settings</h2>
        <button
          class="close"
          aria-label="Close settings"
          onclick={closePanelAndRestoreFocus}>✕</button
        >
      </div>

      <section>
        <h3>Startup</h3>
        <label class="row">
          <input
            type="checkbox"
            data-testid="setting-launch-on-login"
            checked={autostartEnabled}
            disabled={autostartBusy}
            onchange={toggleAutostart}
          />
          <span>Launch on login</span>
        </label>
        <label class="row">
          <input
            type="checkbox"
            data-testid="setting-dashboard-at-launch"
            checked={dashboardAtLaunch}
            disabled={dashboardAtLaunchBusy}
            onchange={toggleDashboardAtLaunch}
            aria-describedby="dashboard-at-launch-hint"
          />
          <span>Open dashboard at launch</span>
        </label>
        <p class="hint" id="dashboard-at-launch-hint">
          When off, csq launches into the menu bar/tray. Click the tray icon
          to open the dashboard.
        </p>
      </section>

      {#if dockHideSupported}
        <section>
          <h3>Appearance</h3>
          <label class="row">
            <input
              type="checkbox"
              data-testid="setting-hide-dock-icon"
              checked={dockHidden}
              disabled={dockHiddenBusy}
              onchange={toggleDockHidden}
              aria-describedby="hide-dock-icon-hint"
            />
            <span>Hide Dock icon</span>
          </label>
          <p class="hint" id="hide-dock-icon-hint">
            When hidden, csq runs as a menu-bar app — no Dock icon, no
            Cmd-Tab entry. macOS only.
          </p>
        </section>
      {/if}

      <section>
        <h3>About</h3>
        <p class="about">
          csq
          {#if appVersion}<span class="version">v{appVersion}</span>{/if}
          <span class="sep">·</span>
          <span class="dot" class:running={daemonRunning} aria-hidden="true"
          ></span>
          <span>daemon {daemonRunning ? 'running' : 'stopped'}</span>
        </p>
      </section>
    </div>
  {/if}
</div>

<style>
  .settings-popover {
    position: relative;
    display: inline-flex;
    -webkit-app-region: no-drag;
  }
  .trigger {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 0;
  }
  .trigger:hover,
  .trigger[aria-expanded='true'] {
    background: var(--bg-tertiary, rgba(255, 255, 255, 0.06));
    border-color: var(--border);
    color: var(--text-primary);
  }
  .panel {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    min-width: 280px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 8px 28px rgba(0, 0, 0, 0.4);
    z-index: 100;
    -webkit-app-region: no-drag;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  .panel-header h2 {
    margin: 0;
    font-size: 0.85rem;
    font-weight: 600;
  }
  .close {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 0.9rem;
    line-height: 1;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
  }
  .close:hover {
    color: var(--text-primary);
    background: var(--bg-tertiary, rgba(255, 255, 255, 0.06));
  }
  section {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
  }
  section:last-child {
    border-bottom: none;
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
  .about {
    margin: 0;
    font-size: 0.75rem;
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
  }
  .about .version {
    color: var(--text-secondary);
  }
  .about .sep {
    color: var(--text-tertiary, var(--text-secondary));
    margin: 0 2px;
  }
  .dot {
    display: inline-block;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--red);
  }
  .dot.running {
    background: var(--green);
  }
</style>
