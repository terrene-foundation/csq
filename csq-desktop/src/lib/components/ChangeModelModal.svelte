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
  import { onMount } from 'svelte';

  interface Props {
    isOpen: boolean;
    slot: number;
    onClose: () => void;
    onChanged: () => void;
  }

  let { isOpen, slot, onClose, onChanged }: Props = $props();

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

  /// Shared fetch-installed-list helper used by both onMount and
  /// the modal-reopen effect. Takes a cancellation flag so stale
  /// resolutions (modal closed mid-request, then reopened) don't
  /// overwrite a fresh `loading` modalState.
  async function loadInstalled(isCancelled: () => boolean) {
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

  onMount(() => {
    let cancelled = false;
    if (isOpen) {
      loadInstalled(() => cancelled);
    }
    return () => {
      cancelled = true;
      if (pullUnlisten) pullUnlisten();
    };
  });

  // When the modal is toggled OPEN (false → true edge) after a
  // close/reopen cycle, re-fetch the installed list so any model
  // the user pulled in a terminal while the modal was closed
  // shows up. Reading `isOpen` reactively; `wasOpen` anchors the
  // edge detection so we don't re-fetch on every internal modalState
  // transition (pulling → error → etc.).
  let wasOpen = $state(false);
  $effect(() => {
    if (isOpen && !wasOpen) {
      wasOpen = true;
      // Already fetched on initial mount; skip that one.
      if (modalState.kind !== 'loading' && modalState.kind !== 'picker') {
        let cancelled = false;
        modalState = { kind: 'loading' };
        loadInstalled(() => cancelled);
        return () => {
          cancelled = true;
        };
      }
    } else if (!isOpen && wasOpen) {
      wasOpen = false;
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
        <h2 id="change-model-title">Change Ollama model</h2>
        <button class="close" onclick={close} aria-label="Close">×</button>
      </header>

      <div class="body">
        {#if modalState.kind === 'loading'}
          <p class="hint">Loading installed models…</p>
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
