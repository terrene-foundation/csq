<script lang="ts">
  // Change-model modal for Ollama account slots.
  //
  // Users bind an Ollama slot to a specific model at Add Account
  // time (via AddAccountModal's keyless-confirm step). As they
  // pull more models locally, they need a way to retarget the slot
  // without deleting + re-adding. This modal is that path.
  //
  // Flow:
  //   1. Mount → `invoke('list_ollama_models')` populates the
  //      dropdown with whatever `ollama list` reports.
  //   2. User picks one OR types a custom model id. Custom entries
  //      that aren't in the installed list trigger a confirmation
  //      to pull on submit.
  //   3. Submit → if pull needed, call `pull_ollama_model`, stream
  //      the progress event onto the banner, then call
  //      `set_slot_model`. Otherwise straight to
  //      `set_slot_model`.
  //   4. On success close the modal and fire `onChanged` so the
  //      parent can refresh the card (not strictly required — the
  //      model isn't shown on the card — but keeps the UI in sync
  //      with any future field that does surface it).
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { homeDir, join } from '@tauri-apps/api/path';
  import { onMount, untrack } from 'svelte';

  interface Props {
    isOpen: boolean;
    slot: number;
    /// Upstream CLI surface binding for the slot. Drives the
    /// source-of-models branch inside the modal — `claude-code`
    /// stays on the Ollama `ollama list` path; `codex` swaps to
    /// the `list_codex_models` + cache + `set_codex_slot_model`
    /// path. Default `claude-code` keeps legacy callers working.
    surface?: string;
    onClose: () => void;
    onChanged: () => void;
  }

  let { isOpen, slot, surface = 'claude-code', onClose, onChanged }: Props = $props();

  // PR-C8 types for the Codex branch.
  interface CodexModel {
    id: string;
    label: string;
  }
  interface CodexModelList {
    models: CodexModel[];
    /// "live" | "cached" | "bundled"
    source: string;
    fetched_at: number;
  }

  type ModalState =
    | { kind: 'loading' }
    | {
        kind: 'picker';
        installed: string[];
        selected: string;
        custom: string;
        error: string | null;
        submitting: boolean;
      }
    // PR-C8 — Codex branch. The source hint is rendered next to the
    // picker ("Cached 3m ago", "Live", "Cold-start") so users know
    // whether the list is fresh.
    | {
        kind: 'codex-picker';
        list: CodexModelList;
        selected: string;
        custom: string;
        submitting: boolean;
        error: string | null;
      }
    | { kind: 'pulling'; model: string; lines: string[] }
    | { kind: 'applying'; model: string }
    | { kind: 'done'; model: string }
    | { kind: 'error'; message: string };

  let modalState: ModalState = $state({ kind: 'loading' });
  let pullUnlisten: UnlistenFn | null = null;
  // Incremented whenever a new pull starts so a late event from
  // a cancelled or prior pull can be rejected on arrival. Plain
  // `let` (not `$state`) because the listener closure captures
  // the current value at registration and we only use it for an
  // equality compare — no reactivity required.
  let pullEpoch = 0;

  async function getBaseDir(): Promise<string> {
    const home = await homeDir();
    return await join(home, '.claude', 'accounts');
  }

  /// Formats a Unix-epoch seconds value as "Nm ago" / "Nh ago" for
  /// the Codex model list freshness hint. Called only from the
  /// template so we don't need reactivity on it.
  function formatFetchedAgo(epochSecs: number): string {
    const now = Math.floor(Date.now() / 1000);
    const delta = Math.max(0, now - epochSecs);
    if (delta < 60) return `${delta}s`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m`;
    return `${Math.floor(delta / 3600)}h`;
  }

  /// Shared fetch-installed-list helper used by both onMount and
  /// the modal-reopen effect. Takes a cancellation flag so stale
  /// resolutions (modal closed mid-request, then reopened) don't
  /// overwrite a fresh `loading` modalState.
  async function loadInstalled(isCancelled: () => boolean) {
    if (surface === 'codex') {
      await loadCodexModels(isCancelled);
      return;
    }
    try {
      const installed = await invoke<string[]>('list_ollama_models');
      if (isCancelled()) return;
      modalState = {
        kind: 'picker',
        installed,
        selected: installed[0] ?? '',
        custom: '',
        error: null,
        submitting: false,
      };
    } catch (e) {
      if (isCancelled()) return;
      modalState = { kind: 'error', message: `Could not list models: ${e}` };
    }
  }

  /// Codex path — fetch via `list_codex_models` (cached + bundled
  /// fallback in the backend; this frontend only renders the result).
  /// Guaranteed non-empty per the Rust invariant so an empty models
  /// array is treated as a fatal UI bug rather than "no models."
  async function loadCodexModels(isCancelled: () => boolean) {
    try {
      const baseDir = await getBaseDir();
      const list = await invoke<CodexModelList>('list_codex_models', { baseDir });
      if (isCancelled()) return;
      if (!list.models || list.models.length === 0) {
        modalState = {
          kind: 'error',
          message: 'Codex models response was empty (backend invariant violated)',
        };
        return;
      }
      modalState = {
        kind: 'codex-picker',
        list,
        selected: list.models[0]!.id,
        custom: '',
        submitting: false,
        error: null,
      };
    } catch (e) {
      if (isCancelled()) return;
      modalState = { kind: 'error', message: `Could not load Codex models: ${e}` };
    }
  }

  async function submitCodex() {
    if (modalState.kind !== 'codex-picker' || modalState.submitting) return;
    const current = modalState;
    const customTrimmed = current.custom.trim();
    const target = customTrimmed !== '' ? customTrimmed : current.selected;
    if (!target) {
      modalState = { ...current, error: 'Pick a model or enter a custom id', submitting: false };
      return;
    }

    modalState = { ...current, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      await invoke('set_codex_slot_model', { baseDir, slot, model: target });
      modalState = { kind: 'done', model: target };
      onChanged();
    } catch (e) {
      modalState = { kind: 'error', message: String(e) };
    }
  }

  let wasOpen = $state(false);

  onMount(() => {
    let cancelled = false;
    if (isOpen) {
      // Mounted already open — load now. Mark wasOpen=true so the
      // $effect below doesn't double-fire on the same edge.
      wasOpen = true;
      loadInstalled(() => cancelled);
    }
    return () => {
      cancelled = true;
      if (pullUnlisten) pullUnlisten();
    };
  });

  // Load (or reload) the installed list on every `false → true`
  // isOpen edge after mount. The modal is rendered by AccountList
  // even when closed, so the first-open transition — user clicks
  // "Change model" — flips isOpen here. Any model the user pulled
  // in a terminal while the modal was closed should show up on
  // reopen. `wasOpen` anchors the edge so we don't re-fetch on
  // every internal modalState transition (pulling → error → etc.).
  //
  // Regression guard (journal 0061): an earlier version had a guard
  // `modalState.kind !== 'loading'` that skipped the load when the
  // modal was already in its initial 'loading' state — which it
  // always was on first open, so list_ollama_models was never
  // invoked and the spinner hung forever. The guard is removed;
  // loading on every open edge is cheap (2s-timeout localhost call)
  // and correct.
  // `wasOpen` is written inside the effect but we don't want its
  // write to invalidate the effect — otherwise Svelte schedules a
  // re-run whose cleanup sets `cancelled=true` before `loadInstalled`
  // resolves, and the modal stays stuck in 'loading'. `untrack` tells
  // Svelte not to invalidate this effect just because wasOpen changed.
  $effect(() => {
    if (isOpen && !untrack(() => wasOpen)) {
      untrack(() => {
        wasOpen = true;
      });
      let cancelled = false;
      modalState = { kind: 'loading' };
      loadInstalled(() => cancelled);
      return () => {
        cancelled = true;
      };
    } else if (!isOpen && untrack(() => wasOpen)) {
      untrack(() => {
        wasOpen = false;
      });
    }
  });

  async function submit() {
    // H1 guard: reject the second click of a rapid double-submit.
    // The first click flips `submitting = true`; subsequent clicks
    // short-circuit here until the picker modalState renders again.
    if (modalState.kind !== 'picker' || modalState.submitting) return;
    const current = modalState;
    modalState = { ...current, submitting: true, error: null };

    const customTrimmed = current.custom.trim();
    const target = customTrimmed !== '' ? customTrimmed : current.selected;

    if (!target) {
      modalState = {
        ...current,
        error: 'Pick a model or enter a custom id',
        submitting: false,
      };
      return;
    }

    // H2: re-fetch the installed list right before deciding
    // whether to pull. The user may have run `ollama pull` in a
    // terminal after opening the modal — the stale list captured
    // at open time would trigger a spurious network fetch.
    let freshInstalled: string[] = current.installed;
    try {
      freshInstalled = await invoke<string[]>('list_ollama_models');
    } catch {
      // Falling back to the stale list is fine — we'll spuriously
      // pull a model that's actually present, but ollama pull is
      // a no-op in that case so no real harm.
    }
    const needsPull = !freshInstalled.includes(target);

    try {
      if (needsPull) {
        // R2: subscribe to the progress channel BEFORE flipping
        // modalState to `pulling`. A slow backend that fires its first
        // event immediately would otherwise race the modalState
        // transition and drop the first chunk of output.
        const epoch = ++pullEpoch;
        pullUnlisten = await listen<{ stream: string; line: string }>(
          'ollama-pull-progress',
          (e) => {
            // Guard against late events from an earlier pull
            // (e.g. user hit Retry after Cancel): ignore unless
            // our epoch is still the active one.
            if (
              modalState.kind === 'pulling' &&
              modalState.model === target &&
              pullEpoch === epoch
            ) {
              modalState = {
                ...modalState,
                lines: [...modalState.lines, e.payload.line].slice(-30),
              };
            }
          },
        );
        modalState = { kind: 'pulling', model: target, lines: [] };
        await invoke('pull_ollama_model', { model: target });
        if (pullUnlisten) {
          pullUnlisten();
          pullUnlisten = null;
        }
      }

      modalState = { kind: 'applying', model: target };
      const baseDir = await getBaseDir();
      await invoke('set_slot_model', { baseDir, slot, model: target });
      modalState = { kind: 'done', model: target };
      onChanged();
    } catch (e) {
      if (pullUnlisten) {
        pullUnlisten();
        pullUnlisten = null;
      }
      modalState = { kind: 'error', message: String(e) };
    }
  }

  /// Cancels an in-flight pull subprocess. Called from the
  /// Cancel button on the pulling modalState and from `close()`
  /// when the user dismisses the modal mid-pull, so we don't
  /// leave a zombie `ollama pull` running after the UI is gone.
  async function cancelPull() {
    try {
      await invoke('cancel_ollama_pull');
    } catch {
      // Best-effort — if the backend refused (nothing to cancel,
      // modalState poisoned) we still want to close the modal below.
    }
    if (pullUnlisten) {
      pullUnlisten();
      pullUnlisten = null;
    }
  }

  function close() {
    // If the user closes mid-pull, kill the subprocess so we
    // don't leak a multi-GB download no one is waiting for.
    if (modalState.kind === 'pulling') {
      cancelPull();
    } else if (pullUnlisten) {
      pullUnlisten();
      pullUnlisten = null;
    }
    onClose();
  }
</script>

{#if isOpen}
  <div class="backdrop" onclick={close} onkeydown={(e) => { if (e.key === 'Escape') close(); }} role="button" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="change-model-title" tabindex="-1">
      <header>
        <h2 id="change-model-title">
          {surface === 'codex' ? 'Change Codex model' : 'Change Ollama model'}
        </h2>
        <button class="close" onclick={close} aria-label="Close">×</button>
      </header>

      <div class="body">
        {#if modalState.kind === 'loading'}
          <p class="hint">Loading installed models…</p>
        {:else if modalState.kind === 'codex-picker'}
          <p class="lede">Retarget slot #{slot} to a different Codex model.</p>
          <p class="hint" data-testid="codex-source">
            {#if modalState.list.source === 'live'}
              Live — fetched from <code>chatgpt.com/backend-api/codex/models</code>.
            {:else if modalState.list.source === 'cached'}
              Cached {formatFetchedAgo(modalState.list.fetched_at)} ago.
            {:else}
              Cold-start list (offline). Live refresh will update on the
              next open if the endpoint is reachable.
            {/if}
          </p>
          <label class="field">
            <span>Model</span>
            <select
              bind:value={modalState.selected}
              disabled={modalState.custom.trim() !== '' || modalState.submitting}
            >
              {#each modalState.list.models as m (m.id)}
                <option value={m.id}>{m.label}</option>
              {/each}
            </select>
            <span class="hint">
              csq writes <code>model = "&lt;id&gt;"</code> into
              <code>config-{slot}/config.toml</code> atomically, preserving
              the <code>cli_auth_credentials_store = "file"</code> directive
              (INV-P03).
            </span>
          </label>
          <label class="field">
            <span>…or custom model id</span>
            <input
              type="text"
              bind:value={modalState.custom}
              placeholder="e.g. gpt-5.5"
              autocomplete="off"
              spellcheck="false"
              disabled={modalState.submitting}
            />
            <span class="hint">
              Anything Codex accepts on your subscription. csq does not
              validate against ChatGPT entitlements (FR-CLI-04).
            </span>
          </label>
          {#if modalState.error}
            <div class="error-banner">{modalState.error}</div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={close} disabled={modalState.submitting}>Cancel</button>
            <button class="primary" onclick={submitCodex} disabled={modalState.submitting}>
              {modalState.submitting ? 'Applying…' : 'Apply'}
            </button>
          </div>
        {:else if modalState.kind === 'picker'}
          <p class="lede">Retarget slot #{slot} to a different Ollama model.</p>

          {#if modalState.installed.length === 0}
            <p class="hint">
              No Ollama models found locally. Enter a model id below —
              we'll run <code>ollama pull</code> before switching.
            </p>
          {:else}
            <label class="field">
              <span>Installed model</span>
              <select bind:value={modalState.selected} disabled={modalState.custom.trim() !== ''}>
                {#each modalState.installed as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
              <span class="hint">From <code>ollama list</code>.</span>
            </label>
          {/if}

          <label class="field">
            <span>…or custom model</span>
            <input
              type="text"
              bind:value={modalState.custom}
              placeholder="e.g. qwen3:latest"
              autocomplete="off"
              spellcheck="false"
            />
            <span class="hint">
              If the model isn't installed, we'll pull it first.
            </span>
          </label>

          {#if modalState.error}
            <div class="error-banner">{modalState.error}</div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={close} disabled={modalState.submitting}>Cancel</button>
            <button class="primary" onclick={submit} disabled={modalState.submitting}>
              {modalState.submitting ? 'Applying…' : 'Apply'}
            </button>
          </div>
        {:else if modalState.kind === 'pulling'}
          <p class="lede">Pulling <code>{modalState.model}</code>…</p>
          <p class="hint">
            Large models take several minutes. Progress streams below.
          </p>
          <pre class="log" aria-live="polite">{modalState.lines.join('\n')}</pre>
          <div class="actions">
            <button
              class="danger"
              onclick={async () => { await cancelPull(); modalState = { kind: 'error', message: 'Pull cancelled' }; }}
              aria-label="Cancel the ollama pull"
            >
              Cancel pull
            </button>
          </div>
        {:else if modalState.kind === 'applying'}
          <p class="lede">Applying <code>{modalState.model}</code> to slot #{slot}…</p>
        {:else if modalState.kind === 'done'}
          <div class="success-banner">
            Slot #{slot} now uses <code>{modalState.model}</code>.
          </div>
          <div class="actions">
            <button class="primary" onclick={close}>Done</button>
          </div>
        {:else if modalState.kind === 'error'}
          <div class="error-banner">{modalState.message}</div>
          <div class="actions">
            <button class="secondary" onclick={() => (modalState = { kind: 'loading' })}>Try again</button>
            <button class="danger" onclick={close}>Close</button>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .modal {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: min(520px, 92vw);
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35);
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.85rem 1rem;
    border-bottom: 1px solid var(--border);
  }
  header h2 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
  }
  .close {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.4rem;
    cursor: pointer;
  }
  .body {
    padding: 1rem;
  }
  .lede {
    margin: 0 0 0.75rem 0;
    font-size: 0.9rem;
  }
  .hint {
    margin: 0.25rem 0;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .hint code {
    background: var(--bg-tertiary);
    padding: 0.1em 0.35em;
    border-radius: 3px;
    font-size: 0.95em;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin: 0.5rem 0;
  }
  .field span {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .field input,
  .field select {
    padding: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: inherit;
    font: inherit;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
  }
  .field input:focus,
  .field select:focus {
    outline: 2px solid var(--accent);
    outline-offset: -1px;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 0.85rem;
  }
  .actions button {
    padding: 0.45rem 0.85rem;
    border-radius: 4px;
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: inherit;
  }
  .actions button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: white;
  }
  .actions button.danger {
    color: var(--red);
    border-color: var(--red);
  }
  .error-banner {
    background: rgba(255, 80, 80, 0.12);
    border: 1px solid var(--red);
    border-radius: 4px;
    padding: 0.55rem 0.7rem;
    color: var(--red);
    font-size: 0.85rem;
    margin: 0.5rem 0;
  }
  .success-banner {
    background: rgba(80, 200, 120, 0.12);
    border: 1px solid #4caf50;
    border-radius: 4px;
    padding: 0.55rem 0.7rem;
    color: #4caf50;
    font-size: 0.9rem;
  }
  .log {
    max-height: 260px;
    overflow-y: auto;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.5rem;
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    white-space: pre-wrap;
  }
</style>
