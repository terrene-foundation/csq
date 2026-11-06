<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";
  import {
    machineRotation,
    machineRotationReadToken,
    refreshMachineRotation,
  } from "../stores/machineRotation.svelte";

  // Per-terminal auto-swap override. Mirrors `SessionRotationView` in
  // `csq/src/desktop/commands/mod.rs`. The UI only reads and writes the
  // override through `get_session_rotation` / `set_session_rotation`; it
  // never derives anything about the account from the terminal.
  type StoredMode = "default" | "on" | "off" | "unreadable";
  type SetMode = "default" | "on" | "off";
  interface SessionRotationView {
    pid: number;
    mode: StoredMode;
    machine_enabled: boolean;
    effective: boolean;
  }

  // `pid` is the csq terminal number (`term-<pid>`, `SessionView.handle_pid`),
  // NOT the `claude` process id.
  let { pid }: { pid: number } = $props();

  let view = $state<SessionRotationView | null>(null);
  let errorText = $state<string | null>(null);
  let busy = $state(false);

  function isView(v: unknown): v is SessionRotationView {
    if (typeof v !== "object" || v === null) return false;
    const c = v as Record<string, unknown>;
    return (
      typeof c.pid === "number" &&
      (c.mode === "default" || c.mode === "on" || c.mode === "off" || c.mode === "unreadable") &&
      typeof c.machine_enabled === "boolean" &&
      typeof c.effective === "boolean"
    );
  }

  async function baseDir(): Promise<string> {
    const home = await homeDir();
    return join(home, ".claude", "accounts");
  }

  // The backend refuses with fixed text that carries no path or secret;
  // it is shown after a plain lead-in so the user knows what failed.
  function explain(lead: string, e: unknown): string {
    const detail = typeof e === "string" ? e : e instanceof Error ? e.message : "";
    return detail ? `${lead} ${detail}` : lead;
  }

  // The list replaces every row object on each poll, which re-notifies a
  // plain `pid` prop read even though the number is unchanged. A $derived
  // only notifies on a changed value, so the read below runs once per row.
  let target = $derived(pid);

  // Read once when the row renders (the row is keyed by pid), not polled.
  $effect(() => {
    const current = target;
    let active = true;
    (async () => {
      try {
        const b = await baseDir();
        const token = machineRotationReadToken();
        const next = await invoke<unknown>("get_session_rotation", { baseDir: b, pid: current });
        if (!active) return;
        if (!isView(next)) throw new Error("The app returned an unexpected answer.");
        view = next;
        // The backend read is the freshest answer (the CLI may have changed the
        // machine setting since Settings last loaded it): share it, so a stale
        // stored value cannot override it in `effective`.
        refreshMachineRotation(next.machine_enabled, token);
        errorText = null;
      } catch (e) {
        if (!active) return;
        view = null;
        errorText = explain("Couldn't read this session's auto-swap setting.", e);
      }
    })();
    return () => {
      active = false;
    };
  });

  async function choose(mode: SetMode) {
    if (busy) return;
    busy = true;
    errorText = null;
    try {
      const b = await baseDir();
      const next = await invoke<unknown>("set_session_rotation", { baseDir: b, pid, mode });
      if (!isView(next)) throw new Error("The app returned an unexpected answer.");
      view = next;
    } catch (e) {
      errorText = explain("Couldn't change this session's auto-swap setting.", e);
    } finally {
      busy = false;
    }
  }

  // Whether the daemon may move this session now, computed here from the stored
  // `mode` and the shared machine setting so a toggle in Settings is reflected at
  // once (the backend `effective` is a one-time snapshot). Same rule as the
  // rotator: `on` rotates, `off` and a damaged setting do not, and `default`
  // follows the machine setting. Before the Settings toggle has loaded, the
  // backend's own `machine_enabled` stands in.
  let effective = $derived.by(() => {
    if (view === null) return false;
    if (view.mode === "on") return true;
    if (view.mode === "off" || view.mode === "unreadable") return false;
    return machineRotation.enabled ?? view.machine_enabled;
  });

  let summary = $derived.by(() => {
    if (view === null) return "";
    if (view.mode === "unreadable") return "Setting damaged — treated as off";
    const word = effective ? "on" : "off";
    return view.mode === "default"
      ? `Auto-swap: ${word} (following machine setting)`
      : `Auto-swap: ${word} (this session)`;
  });

  const OPTIONS: { mode: SetMode; label: string }[] = [
    { mode: "default", label: "Follow machine" },
    { mode: "on", label: "On" },
    { mode: "off", label: "Off" },
  ];
</script>

{#if view !== null || errorText !== null}
  <div class="rotation" data-testid="session-rotation-{pid}">
    {#if view !== null}
      <span class="summary" data-testid="session-rotation-{pid}-summary">{summary}</span>
      {#if view.mode === "unreadable"}
        <button
          type="button"
          class="opt"
          disabled={busy}
          onclick={() => choose("default")}
          data-testid="session-rotation-{pid}-reset"
        >Reset to default</button>
      {:else}
        <div class="group" role="group" aria-label="Auto-swap for this session">
          {#each OPTIONS as opt (opt.mode)}
            <button
              type="button"
              class="opt"
              class:active={view.mode === opt.mode}
              aria-pressed={view.mode === opt.mode}
              disabled={busy}
              onclick={() => choose(opt.mode)}
              data-testid="session-rotation-{pid}-{opt.mode}"
            >{opt.label}</button>
          {/each}
        </div>
      {/if}
    {/if}
    {#if errorText !== null}
      <span class="error" role="alert" data-testid="session-rotation-{pid}-error">{errorText}</span>
    {/if}
  </div>
{/if}

<style>
  .rotation {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.75rem;
  }
  .summary {
    color: var(--text-secondary);
  }
  .group {
    display: inline-flex;
    gap: 2px;
  }
  .opt {
    padding: 0.1rem 0.45rem;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--text-tertiary);
    font: inherit;
    font-size: 0.7rem;
    line-height: 1.4;
    cursor: pointer;
  }
  .opt:hover:not(:disabled) {
    border-color: var(--text-secondary);
    color: var(--text-secondary);
  }
  .opt.active {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-low);
  }
  .opt:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .opt:disabled {
    cursor: wait;
    opacity: 0.6;
  }
  .error {
    color: var(--red);
  }
</style>
