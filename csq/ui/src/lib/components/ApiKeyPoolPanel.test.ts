import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, cleanup, fireEvent, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';
import SettingsPopover from './SettingsPopover.svelte';

const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => mockInvoke(...args) }));
vi.mock('@tauri-apps/api/path', () => ({ homeDir: async () => '/fixture', join: async (...parts: string[]) => parts.join('/') }));
vi.mock('@tauri-apps/api/app', () => ({ getVersion: async () => 'fixture' }));
const row = { name: 'pool.one', provider: 'anthropic', source: 'secret-store', reset: { day_of_month: 12 }, monthly_cap_usd: 20, added_at: '2026-10-11T00:00:00Z', present: true };
async function open() {
  const view = render(SettingsPopover);
  await tick();
  expect(mockInvoke.mock.calls.some(([cmd]) => cmd === 'pool_list')).toBe(false);
  await fireEvent.click(view.getByRole('button', { name: 'Settings' }));
  await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith('pool_list'));
  await waitFor(() => expect((view.getByRole('button', { name: 'Add key' }).closest('fieldset') as HTMLFieldSetElement)?.disabled).toBe(false));
  return view;
}
async function fill(view: Awaited<ReturnType<typeof open>>, key: string) {
  await fireEvent.input(view.getByLabelText('Name'), { target: { value: 'pool.two' } });
  await fireEvent.input(view.getByLabelText('API key'), { target: { value: key } });
}
beforeEach(() => {
  mockInvoke.mockReset();
  mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [] : cmd === 'get_dashboard_at_launch');
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('API pool through closed settings → open settings', () => {
  it('explains missing-vault recovery when settings first opens', async () => {
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [{ ...row, present: false, vault_file_missing: true }] : false);
    const view = await open();
    expect(view.getByText('Vault file missing: restore it, or remove these entries.')).toBeTruthy();
    expect(view.queryByText('Editing the reset does not restore this key. Restore its source or remove this entry.')).toBeNull();
    expect(view.getByRole('button', { name: 'Remove pool.one' })).toBeTruthy();
  });
  it('explains metadata publication failure after adding a key', async () => {
    const view = await open();
    await fill(view, 'synthetic-write-failure-key');
    mockInvoke.mockImplementation(async (cmd: string) => { if (cmd === 'pool_add') throw 'pool_manifest_write_unavailable'; return []; });
    await fireEvent.submit(view.getByRole('button', { name: 'Add key' }).closest('form')!);
    await waitFor(() => expect(view.getByRole('alert').textContent).toBe('Pool metadata could not be saved. Check disk space and file access, then retry.'));
    expect((view.getByLabelText('API key') as HTMLInputElement).value).toBe('');
  });
  it('acknowledges removal of a row whose vault file was missing', async () => {
    let removed = false;
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'pool_list') return removed ? [] : [{ ...row, present: false, vault_file_missing: true }];
      if (cmd === 'pool_remove') { removed = true; return { vault_file_missing: true }; }
      return false;
    });
    const view = await open();
    await fireEvent.click(view.getByRole('button', { name: 'Remove pool.one' }));
    await fireEvent.click(view.getByRole('button', { name: 'Confirm remove pool.one' }));
    await waitFor(() => expect(view.getByRole('status').textContent).toBe('Pool entry removed. The vault file was missing; no stored key remained to delete.'));
    expect(view.queryByText('pool.one')).toBeNull();
    expect(view.getByText('No API keys yet. Add one below.')).toBeTruthy();
  });
  it('loads metadata on first open and exposes empty state without a key response', async () => {
    const view = await open();
    expect(view.getByText('No API keys yet. Add one below.')).toBeTruthy();
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [row] : false);
    await fireEvent.click(view.getByRole('button', { name: 'Close settings' }));
    await fireEvent.click(view.getByRole('button', { name: 'Settings' }));
    await waitFor(() => expect(view.getByText('pool.one')).toBeTruthy());
    expect(view.container.textContent).toContain('Secret store · Present');
    expect(view.container.textContent).toContain('Day 12');
    expect(view.container.textContent).toContain('$20/month');
    expect((view.getByLabelText('API key') as HTMLInputElement).type).toBe('password');
  });
  it('clears the password before add IPC, blocks duplicate requests, and refreshes after success', async () => {
    const view = await open();
    const fixtureKey = 'fixture-api-value';
    await fill(view, fixtureKey);
    await fireEvent.input(view.getByLabelText('Monthly cap (USD, optional)'), { target: { value: '42.5' } });
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'day' } });
    await fireEvent.input(view.getByLabelText('Reset day'), { target: { value: '7' } });
    let finish!: () => void;
    let valueAtInvoke: string | undefined;
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === 'pool_add') {
        valueAtInvoke = (view.getByLabelText('API key') as HTMLInputElement).value;
        return new Promise<void>((resolve) => { finish = resolve; });
      }
      return Promise.resolve(cmd === 'pool_list' ? [row] : false);
    });
    await fireEvent.submit(view.getByRole('button', { name: 'Add key' }).closest('form')!);
    expect(valueAtInvoke).toBe('');
    expect((view.getByLabelText('API key') as HTMLInputElement).value).toBe('');
    expect(mockInvoke).toHaveBeenCalledWith('pool_add', { name: 'pool.two', provider: 'anthropic', key: fixtureKey, reset: { day_of_month: 7 }, monthlyCapUsd: 42.5 });
    expect(view.container.textContent).not.toContain(fixtureKey);
    await fireEvent.submit(view.getByRole('button', { name: 'Add key' }).closest('form')!);
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === 'pool_add')).toHaveLength(1);
    expect(view.getByRole('status').textContent).toContain('Another pool operation is running.');
    finish();
    await waitFor(() => expect(view.getByText('pool.one')).toBeTruthy());
    expect((view.getByLabelText('API key') as HTMLInputElement).value).toBe('');
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === 'pool_list')).toHaveLength(2);
    await waitFor(() => expect(view.queryByRole('status')).toBeNull());
  });
  it('clears keys on failures and dismissal and never renders or logs an arbitrary error body', async () => {
    const view = await open();
    const methods = Object.getOwnPropertyNames(console).filter((method) => typeof Reflect.get(console, method) === 'function') as (keyof Console)[];
    const spies = methods.map((method) => vi.spyOn(console, method).mockImplementation(() => {}));
    const fixtureKey = 'fixture-api-value';
    await fill(view, fixtureKey);
    mockInvoke.mockImplementation(async (cmd: string) => { if (cmd === 'pool_add') throw `echo ${fixtureKey}`; return []; });
    await fireEvent.submit(view.getByRole('button', { name: 'Add key' }).closest('form')!);
    await waitFor(() => expect(view.getByRole('alert').textContent).toContain('The pool operation failed.'));
    expect(view.container.textContent).not.toContain(fixtureKey);
    const input = view.getByLabelText('API key') as HTMLInputElement;
    expect(input.value).toBe('');
    for (const spy of spies) expect(JSON.stringify(spy.mock.calls)).not.toContain(fixtureKey);
    await fireEvent.input(input, { target: { value: fixtureKey } });
    await fireEvent.click(view.getByRole('button', { name: 'Close settings' }));
    expect(input.value).toBe('');
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [] : false);
    await fireEvent.click(view.getByRole('button', { name: 'Settings' }));
    await waitFor(() => expect((view.getByLabelText('API key') as HTMLInputElement).value).toBe(''));
  });
  it('edits or clears reset and removes rows using metadata-only IPC', async () => {
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [row] : false);
    const view = await open();
    await fireEvent.click(view.getByRole('button', { name: 'Edit reset for pool.one' }));
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'date' } });
    await fireEvent.input(view.getByLabelText('Reset date'), { target: { value: '2026-11-02' } });
    await fireEvent.submit(view.getByRole('button', { name: 'Save reset' }).closest('form')!);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith('pool_set_reset', { name: 'pool.one', reset: { date: '2026-11-02' } }));
    await waitFor(() => expect((view.getByRole('button', { name: 'Edit reset for pool.one' }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(view.getByRole('button', { name: 'Edit reset for pool.one' }));
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'none' } });
    await fireEvent.submit(view.getByRole('button', { name: 'Save reset' }).closest('form')!);
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith('pool_set_reset', { name: 'pool.one', reset: null }));
    await waitFor(() => expect((view.getByRole('button', { name: 'Remove pool.one' }) as HTMLButtonElement).disabled).toBe(false));
    await fireEvent.click(view.getByRole('button', { name: 'Remove pool.one' }));
    await fireEvent.click(view.getByRole('button', { name: 'Confirm remove pool.one' }));
    await waitFor(() => expect(mockInvoke).toHaveBeenCalledWith('pool_remove', { name: 'pool.one' }));
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd.startsWith('pool_')).every(([, args]) => !args || !('baseDir' in args))).toBe(true);
  });
  it('requires removal confirmation, cancels without IPC, and clears keys before confirmed removal', async () => {
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [row] : false);
    const view = await open();
    const key = view.getByLabelText('API key') as HTMLInputElement;
    expect(key.autocomplete).toBe('new-password');
    expect(key.hasAttribute('data-1p-ignore')).toBe(true);
    expect(key.getAttribute('data-lpignore')).toBe('true');
    await fireEvent.input(key, { target: { value: 'fixture-delete-value' } });
    await fireEvent.click(view.getByRole('button', { name: 'Remove pool.one' }));
    expect(view.getByRole('alertdialog')).toBeTruthy();
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === 'pool_remove')).toHaveLength(0);
    await fireEvent.click(view.getByRole('button', { name: 'Cancel removal' }));
    expect(view.queryByRole('alertdialog')).toBeNull();
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === 'pool_remove')).toHaveLength(0);
    await fireEvent.click(view.getByRole('button', { name: 'Remove pool.one' }));
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'pool_remove') throw 'pool_removal_cancelled';
      return cmd === 'pool_list' ? [row] : null;
    });
    await fireEvent.click(view.getByRole('button', { name: 'Confirm remove pool.one' }));
    await waitFor(() => expect(view.getByRole('alert').textContent).toBe('Removal cancelled. The pool entry was kept.'));
    expect(view.getByText('pool.one')).toBeTruthy();
    await fireEvent.click(view.getByRole('button', { name: 'Remove pool.one' }));
    // A value entered while confirmation is displayed is also cleared at the actual IPC boundary.
    await fireEvent.input(key, { target: { value: 'fixture-delete-value' } });
    let valueAtRemove: string | undefined;
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'pool_remove') valueAtRemove = key.value;
      return cmd === 'pool_list' ? [] : null;
    });
    await fireEvent.click(view.getByRole('button', { name: 'Confirm remove pool.one' }));
    expect(valueAtRemove).toBe('');
    expect(key.value).toBe('');
    await waitFor(() => expect(view.queryByText('pool.one')).toBeNull());
    expect(view.container.textContent).not.toContain('fixture-delete-value');
  });
  it('refreshes the list and explains a vanished row during reset editing', async () => {
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [{ ...row, present: false }] : false);
    const view = await open();
    expect(view.container.textContent).toContain('Editing the reset does not restore this key.');
    await fireEvent.click(view.getByRole('button', { name: 'Edit reset for pool.one' }));
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'date' } });
    await fireEvent.input(view.getByLabelText('Reset date'), { target: { value: '2026-11-02' } });
    mockInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'pool_set_reset') throw 'pool_key_missing';
      return cmd === 'pool_list' ? [] : false;
    });
    await fireEvent.submit(view.getByRole('button', { name: 'Save reset' }).closest('form')!);
    await waitFor(() => expect(view.getByRole('alert').textContent).toContain('This entry is no longer available.'));
    await waitFor(() => expect(view.queryByText('pool.one')).toBeNull());
    expect(mockInvoke.mock.calls.filter(([cmd]) => cmd === 'pool_list')).toHaveLength(2);
    expect(view.queryByRole('button', { name: 'Save reset' })).toBeNull();
    expect((view.getByLabelText('Reset') as HTMLSelectElement).value).toBe('none');
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'date' } });
    expect((view.getByLabelText('Reset date') as HTMLInputElement).value).toBe('');
    await fireEvent.change(view.getByLabelText('Reset'), { target: { value: 'day' } });
    expect((view.getByLabelText('Reset day') as HTMLInputElement).value).toBe('');
  });
  it('shows a fixed actionable tag on list failure and retry recovers', async () => {
    mockInvoke.mockImplementation(async (cmd: string) => { if (cmd === 'pool_list') throw 'pool_store_unavailable'; return false; });
    const view = render(SettingsPopover);
    await fireEvent.click(view.getByRole('button', { name: 'Settings' }));
    await waitFor(() => expect(view.getByRole('alert').textContent).toContain('Unlock it and retry.'));
    const tags = ['pool_invalid_name', 'pool_invalid_provider', 'pool_invalid_reset', 'pool_invalid_cap', 'pool_invalid_key', 'pool_manifest_invalid', 'pool_manifest_unavailable', 'pool_manifest_write_unavailable', 'pool_env_file_invalid', 'pool_env_file_unavailable', 'pool_key_missing', 'pool_name_exists', 'pool_custody_busy', 'pool_mutation_refused', 'pool_partial_failure_recovery_required', 'pool_recovery_writer_alive', 'pool_removal_cancelled', 'pool_permission_denied', 'pool_base_unavailable', 'pool_worker_unavailable'];
    for (const tag of tags) {
      mockInvoke.mockImplementation(async (cmd: string) => { if (cmd === 'pool_list') throw tag; return false; });
      await fireEvent.click(view.getByRole('button', { name: 'Retry pool' }));
      await waitFor(() => expect((view.getByRole('button', { name: 'Retry pool' }) as HTMLButtonElement).disabled).toBe(false));
      expect(view.getByRole('alert').textContent).not.toContain('The pool operation failed.');
      expect(view.getByRole('alert').textContent).not.toContain(tag);
      if (tag === 'pool_partial_failure_recovery_required') expect(view.getByRole('alert').textContent).toContain('Run csq pool recover in a terminal');
      if (tag === 'pool_recovery_writer_alive') {
        expect(view.getByRole('alert').textContent).toContain('quit or restart');
        expect(view.getByRole('alert').textContent).toContain('csq pool recover');
      }
      if (tag === 'pool_mutation_refused') expect(view.getByRole('alert').textContent).toContain('Refresh the pool, review the entry, and retry.');
    }
    mockInvoke.mockImplementation(async (cmd: string) => cmd === 'pool_list' ? [] : false);
    await fireEvent.click(view.getByRole('button', { name: 'Retry pool' }));
    await waitFor(() => expect(view.queryByRole('alert')).toBeNull());
    expect(view.getByText('No API keys yet. Add one below.')).toBeTruthy();
  });
});
