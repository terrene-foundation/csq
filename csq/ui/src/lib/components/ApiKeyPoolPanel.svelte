<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { onMount, onDestroy, tick } from 'svelte';

  type Reset = { day_of_month: number } | { date: string };
  type Row = { name: string; provider: string; source: 'env-file' | 'secret-store'; reset: Reset | null; monthly_cap_usd: number | null; added_at: string; present: boolean };
  let rows = $state<Row[]>([]);
  let busy = $state(true);
  let error = $state('');
  let status = $state('');
  let pendingRemove = $state<string | null>(null);
  let confirmRemoveButton = $state<HTMLButtonElement | undefined>();
  let removeTrigger = $state<HTMLButtonElement | undefined>();
  let name = $state('');
  let provider = $state('anthropic');
  let resetKind = $state('none');
  let day = $state<number | undefined>(undefined);
  let date = $state('');
  let cap = $state<number | undefined>(undefined);
  let editing = $state<string | null>(null);
  let keyInput = $state<HTMLInputElement | undefined>();
  let disposed = false;

  const messages: Record<string, string> = {
    pool_invalid_name: 'Use 1–64 letters, numbers, dots, underscores or hyphens for the name.',
    pool_invalid_provider: 'Choose anthropic, openai or a supported API provider ID.',
    pool_invalid_reset: 'Choose a reset day from 1 to 28 or a valid calendar date.',
    pool_invalid_cap: 'Enter a monthly cap greater than zero.',
    pool_invalid_key: 'Enter an API key without whitespace (up to 4096 bytes).',
    pool_manifest_invalid: 'Pool metadata is invalid. Repair it with your administrator before retrying.',
    pool_manifest_unavailable: 'Pool metadata is unavailable. Check file access and retry.',
    pool_env_file_invalid: 'The configured env file is invalid. Correct its entries and retry.',
    pool_env_file_unavailable: 'The configured env file is unavailable. Check file access and retry.',
    pool_key_missing: 'The key is missing. Restore its source or remove the entry.',
    pool_name_exists: 'That name already exists. Choose a different name.',
    pool_store_unavailable: 'The secret store is unavailable. Unlock it and retry.',
    pool_custody_busy: 'Another pool operation is running. Retry shortly.',
    pool_mutation_refused: 'The pool entry changed or the change was refused. Refresh the pool, review the entry, and retry.',
    pool_partial_failure_recovery_required: 'Pool recovery is required. Run csq pool recover in a terminal, then retry.',
    pool_recovery_writer_alive: 'A pool writer is still running. Wait for it to finish. If the csq app is stuck, quit or restart it, then run csq pool recover in a terminal and retry.',
    pool_removal_cancelled: 'Removal cancelled. The pool entry was kept.',
    pool_permission_denied: 'This window cannot change the pool. Use the main settings window.',
    pool_base_unavailable: 'The pool location is unavailable. Check application configuration.',
    pool_worker_unavailable: 'The pool worker is unavailable. Retry or restart the application.'
  };
  function showError(value: unknown): void {
    // Only exact fixed tags are admitted. Never render an arbitrary IPC error body.
    error = typeof value === 'string' && Object.hasOwn(messages, value)
      ? messages[value] : 'The pool operation failed. Retry or contact your administrator.';
  }
  function clearKey(): void { if (keyInput) keyInput.value = ''; }
  async function load(): Promise<void> {
    const result = await invoke<Row[]>('pool_list');
    if (!disposed) rows = result;
  }
  async function refresh(): Promise<void> {
    if (busy && rows.length) return;
    busy = true; error = ''; status = '';
    try { await load(); } catch (e) { if (!disposed) showError(e); }
    finally { if (!disposed) { busy = false; status = ''; } }
  }
  onMount(() => { void refresh(); });
  onDestroy(() => { disposed = true; clearKey(); });
  function clearEditor(): void {
    editing = null; name = ''; cap = undefined; resetKind = 'none'; day = undefined; date = '';
  }
  function resetValue(): Reset | null {
    return resetKind === 'day' ? { day_of_month: Number(day) }
      : resetKind === 'date' ? { date } : null;
  }
  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy) { clearKey(); status = 'Another pool operation is running. Wait for it to finish, then re-enter the key and try again.'; return; }
    busy = true; error = ''; status = '';
    let key = keyInput?.value ?? '';
    clearKey();
    try {
      const request = editing
        ? invoke('pool_set_reset', { name: editing, reset: resetValue() })
        : invoke('pool_add', { name, provider, key, reset: resetValue(), monthlyCapUsd: cap ?? null });
      key = '';
      await request;
      if (disposed) return;
      clearEditor();
      await load();
    } catch (e) {
      if (!disposed) {
        if (editing && e === 'pool_key_missing') {
          clearEditor();
          error = 'This entry is no longer available. The pool list has been refreshed; add it again if needed.';
          try { await load(); } catch (refreshError) { if (!disposed) showError(refreshError); }
        } else showError(e);
      }
    }
    finally { key = ''; clearKey(); if (!disposed) { busy = false; status = ''; } }
  }
  function edit(row: Row): void {
    clearKey(); editing = row.name; error = ''; status = '';
    resetKind = row.reset === null ? 'none' : 'day_of_month' in row.reset ? 'day' : 'date';
    day = row.reset && 'day_of_month' in row.reset ? row.reset.day_of_month : undefined;
    date = row.reset && 'date' in row.reset ? row.reset.date : '';
  }
  async function requestRemove(name: string, trigger: HTMLButtonElement): Promise<void> {
    if (busy) return;
    clearKey(); pendingRemove = name; status = ''; removeTrigger = trigger;
    await tick();
    if (!disposed) confirmRemoveButton?.focus();
  }
  async function remove(name: string): Promise<void> {
    if (busy) return;
    clearKey(); pendingRemove = null; busy = true; error = ''; status = '';
    try { await invoke('pool_remove', { name }); if (!disposed) { if (editing === name) clearEditor(); await load(); } }
    catch (e) { if (!disposed) showError(e); }
    finally { clearKey(); if (!disposed) { busy = false; status = ''; } }
  }
</script>

<section aria-labelledby="api-pool-title" aria-busy={busy}>
  <h3 id="api-pool-title">API key pool</h3>
  <p>Store named API keys for direct API requests. Keys are separate from CLI account slots.</p>
  {#if error}<p role="alert">{error}</p><button type="button" disabled={busy} onclick={refresh}>Retry pool</button>{/if}
  {#if busy || status}<p role="status">{status || 'Working…'}</p>{/if}
  {#if !busy && !error && rows.length === 0}<p>No API keys yet. Add one below.</p>{/if}
  <ul>
    {#each rows as row (row.name)}
      <li>
        <strong>{row.name}</strong> · {row.provider}
        <span>{row.source === 'env-file' ? 'Env file' : 'Secret store'} · {row.present ? 'Present' : 'Missing'}</span>
        {#if !row.present}<span>Editing the reset does not restore this key. Restore its source or remove this entry.</span>{/if}
        <span>Reset: {row.reset === null ? 'None' : 'day_of_month' in row.reset ? `Day ${row.reset.day_of_month}` : row.reset.date} · Cap: {row.monthly_cap_usd === null ? 'None' : `$${row.monthly_cap_usd}/month`}</span>
        <div class="actions"><button type="button" disabled={busy} onclick={() => edit(row)} aria-label={`Edit reset for ${row.name}`}>Edit reset</button><button type="button" disabled={busy} onclick={(event) => void requestRemove(row.name, event.currentTarget)} aria-label={`Remove ${row.name}`}>Remove</button></div>
      </li>
    {/each}
  </ul>
  {#if pendingRemove}
    <div class="confirmation" role="alertdialog" aria-labelledby="pool-remove-title" aria-describedby="pool-remove-description">
      <strong id="pool-remove-title">Remove {pendingRemove}?</strong>
      <p id="pool-remove-description">This removes the pool entry and permanently deletes its stored key. Env-file values stay in their source file.</p>
      <div class="actions"><button type="button" bind:this={confirmRemoveButton} disabled={busy} aria-label={`Confirm remove ${pendingRemove}`} onclick={() => { if (pendingRemove) void remove(pendingRemove); }}>Confirm removal</button><button type="button" onclick={() => { clearKey(); pendingRemove = null; removeTrigger?.focus(); }}>Cancel removal</button></div>
    </div>
  {/if}
  <form onsubmit={save}>
    <fieldset disabled={busy}>
      <legend>{editing ? `Reset for ${editing}` : 'Add API key'}</legend>
      {#if !editing}
        <label>Name<input bind:value={name} required maxlength="64" pattern="[A-Za-z0-9._\-]+" /></label>
        <label>Provider<input bind:value={provider} required placeholder="anthropic, openai or provider ID" /></label>
        <label>API key<input bind:this={keyInput} type="password" required autocomplete="new-password" data-1p-ignore data-lpignore="true" spellcheck="false" autocapitalize="off" maxlength="4096" /></label>
        <label>Monthly cap (USD, optional)<input bind:value={cap} type="number" min="0.01" step="any" /></label>
      {/if}
      <label>Reset<select bind:value={resetKind}><option value="none">None</option><option value="day">Day of month</option><option value="date">Calendar date</option></select></label>
      {#if resetKind === 'day'}<label>Reset day<input bind:value={day} type="number" min="1" max="28" required /></label>{/if}
      {#if resetKind === 'date'}<label>Reset date<input bind:value={date} type="date" required /></label>{/if}
      <div class="actions"><button type="submit">{editing ? 'Save reset' : 'Add key'}</button>{#if editing}<button type="button" onclick={() => { clearKey(); clearEditor(); }}>Cancel reset</button>{/if}</div>
    </fieldset>
  </form>
</section>
<style>
  section { padding: 12px 14px; border-bottom: 1px solid var(--border); color: var(--text-primary); }
  h3 { margin: 0 0 8px; font-size: .85rem; }
  p, span { font-size: .8rem; color: var(--text-secondary); }
  [role='alert'] { color: var(--text-primary); }
  ul { list-style: none; padding: 0; margin: 10px 0; }
  li { padding: 8px 0; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; font-size: .85rem; }
  span { display: block; margin-top: 4px; }
  fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
  legend { font-size: .85rem; font-weight: 600; margin-bottom: 8px; }
  label { display: grid; gap: 4px; font-size: .8rem; margin: 8px 0; }
  input, select { width: 100%; box-sizing: border-box; padding: 7px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg-primary); color: var(--text-primary); }
  button { padding: 7px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg-tertiary, var(--bg-secondary)); color: var(--text-primary); cursor: pointer; }
  button:disabled { opacity: .6; cursor: wait; }
  input:focus-visible, select:focus-visible, button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .confirmation { padding: 10px; border: 1px solid var(--border); border-radius: 4px; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
</style>
