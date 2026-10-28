import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@testing-library/svelte';
import { tick } from 'svelte';

const invokeMock = vi.fn();
const cancelReply = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));
vi.mock('@tauri-apps/api/path', () => ({ homeDir: async () => '/private/inert', join: async (...parts: string[]) => parts.join('/') }));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: async () => {} }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: async () => null }));
import AddAccountModal from './AddAccountModal.svelte';

const providers = ['claude', 'codex'].map(id => ({ id, name: id === 'claude' ? 'Claude' : 'Codex', auth_type: 'oauth', default_base_url: null, default_model: '' }));
const kimi = { id: 'kimi-cli', display_name: 'Kimi', default_model: '', surface: 'kimi', binary: 'kimi' };
let refuseVendor: ((reason: Error) => void) | undefined;
let finishVendor: ((value: unknown) => void) | undefined;
type PendingRow = { operation_id: string; provider: string; account: number; native_id: string | null };
let activeRows: PendingRow[] = [];
let queryResponder: (() => Promise<unknown>) | undefined;
const cancelCalls = () => invokeMock.mock.calls.filter(([cmd]) => String(cmd).startsWith('cancel_'));
async function settle() { for (let i = 0; i < 18; i++) await tick(); }

beforeEach(() => {
  invokeMock.mockReset(); cancelReply.mockReset(); cancelReply.mockResolvedValue(false);
  refuseVendor = undefined; finishVendor = undefined; activeRows = []; queryResponder = undefined;
  invokeMock.mockImplementation((cmd: string, args?: Record<string, unknown>) => {
    if (cmd === 'get_pending_logins') return queryResponder ? queryResponder() : Promise.resolve(activeRows.map(row => ({ ...row })));
    if (cmd === 'list_providers') return Promise.resolve(providers);
    if (cmd === 'list_native_clis') return Promise.resolve([kimi]);
    if (cmd === 'get_accounts') return Promise.resolve([]);
    if (cmd === 'get_build_edition') return Promise.resolve('community');
    if (cmd === 'provider_cli_installed') return Promise.resolve(true);
    if (cmd === 'start_codex_login') return Promise.resolve({ account: 3, tos_required: false, awaiting_keychain_decision: false, keychain: 'absent', device_auth_prereq_message: '', device_auth_prereq_url: '' });
    if (cmd === 'start_native_login') return Promise.resolve({ native_id: 'kimi-cli', display_name: 'Kimi', cli_installed: true });
    if (['start_claude_login_subprocess', 'complete_codex_login', 'complete_native_login'].includes(cmd)) {
      const provider = cmd === 'start_claude_login_subprocess' ? 'claude' : cmd === 'complete_codex_login' ? 'codex' : 'native';
      activeRows = [{ operation_id: `owned-${provider}`, provider, account: 3, native_id: provider === 'native' ? 'kimi-cli' : null }];
      return new Promise((resolve, reject) => { finishVendor = value => { activeRows = []; resolve(value); }; refuseVendor = reject; });
    }
    if (cmd.startsWith('cancel_')) {
      if (!activeRows.some(row => row.operation_id === args?.operationId)) return Promise.reject(new Error('login_cancel_target_changed'));
      return Promise.resolve(cancelReply()).then(ended => { if (ended === true) activeRows = activeRows.filter(row => row.operation_id !== args?.operationId); return ended; });
    }
    return Promise.resolve(undefined);
  });
});
afterEach(cleanup);

async function start(kind: 'claude' | 'codex' | 'native' = 'claude') {
  const props = { isOpen: false, nextAccountId: 3, onClose: vi.fn(), onAccountAdded: vi.fn() };
  const view = render(AddAccountModal, { props });
  await settle();
  expect(invokeMock).not.toHaveBeenCalled();
  await view.rerender({ ...props, isOpen: true });
  await settle();
  expect(invokeMock).toHaveBeenCalledWith('list_providers');
  const label = kind === 'claude' ? 'Claude' : kind === 'codex' ? 'Codex' : 'Kimi';
  const card = [...view.container.querySelectorAll<HTMLButtonElement>('.provider-card')].find(el => el.querySelector('.provider-name')?.textContent?.trim() === label);
  expect(card, 'production picker must expose selected provider').toBeTruthy();
  await fireEvent.click(card!); await settle();
  if (kind === 'native') {
    await fireEvent.click(view.getByTestId('native-cli-confirm-button')); await settle();
  }
  const command = kind === 'claude' ? 'start_claude_login_subprocess' : kind === 'codex' ? 'complete_codex_login' : 'complete_native_login';
  expect(invokeMock.mock.calls.some(([cmd]) => cmd === command)).toBe(true);
  return { view, props };
}

describe('explicit sign-in cancellation', () => {
  it.each(['claude', 'codex', 'native'] as const)('destroy alone never cancels %s sign-in', async kind => {
    const { view } = await start(kind);
    view.unmount(); await settle();
    expect(cancelCalls(), 'destruction alone is not confirmed user cancellation').toEqual([]);
  });

  it.each([false, undefined])('backend decline or unexpected response (%s) keeps the sign-in action available', async answer => {
    const { view } = await start();
    cancelReply.mockResolvedValue(answer);
    const button = view.queryByTestId('end-sign-in');
    expect(button, 'explicit end action must be reachable').not.toBeNull();
    await fireEvent.click(button!); await settle();
    expect(cancelReply).toHaveBeenCalledOnce();
    expect(cancelCalls(), 'frontend requests only its selected vendor; backend owns actual confirmation').toEqual([['cancel_claude_login', { account: 3, operationId: 'owned-claude', confirmed: true }]]);
    expect(view.queryByTestId('end-sign-in')).not.toBeNull();
  });

  it.each([
    ['claude', 'cancel_claude_login', { account: 3, operationId: 'owned-claude', confirmed: true }],
    ['codex', 'cancel_codex_login', { operationId: 'owned-codex', confirmed: true }],
    ['native', 'cancel_native_login', { nativeId: 'kimi-cli', operationId: 'owned-native', confirmed: true }],
  ] as const)('confirmed %s action addresses only its actual vendor', async (kind, command, args) => {
    const { view } = await start(kind);
    cancelReply.mockResolvedValue(true);
    const button = view.queryByTestId('end-sign-in');
    expect(button, 'explicit end action must be reachable').not.toBeNull();
    await fireEvent.click(button!); await settle();
    // Native dialog is inside the backend; this component tests request/response only.
    expect(cancelCalls(), 'confirmed cancellation must target only the selected vendor').toEqual([[command, args]]);
  });

  it.each(['claude', 'codex', 'native'] as const)('declined dismissal preserves %s timeout action across reopen', async kind => {
    const { view, props } = await start(kind);
    expect(refuseVendor).toBeDefined();
    refuseVendor!(new Error('login_timeout_refused: sign-in program is still running'));
    await settle();
    expect(props.onAccountAdded, 'timeout refusal must not report account added').not.toHaveBeenCalled();
    expect(view.queryByTestId('end-sign-in'), 'retained timeout must keep explicit end action reachable').not.toBeNull();
    await fireEvent.click(view.container.querySelector<HTMLButtonElement>('button.close')!); await settle();
    await view.rerender({ ...props, isOpen: false }); await settle();
    await view.rerender({ ...props, isOpen: true }); await settle();
    expect(props.onClose, 'declined native confirmation must keep modal open').not.toHaveBeenCalled();
    expect(cancelCalls()).toHaveLength(1);
    cancelReply.mockResolvedValue(true);
    await fireEvent.click(view.getByTestId('end-sign-in')); await settle();
    expect(cancelCalls()).toHaveLength(2);
    expect(cancelCalls().every(call => call[1]?.confirmed === true)).toBe(true);
  });

  it('completion while backend confirmation is open ignores a stale accepted response', async () => {
    const { view } = await start();
    let answer: ((value: boolean) => void) | undefined;
    cancelReply.mockImplementation(() => new Promise(resolve => { answer = resolve; }));
    await fireEvent.click(view.getByTestId('end-sign-in')); await settle();
    finishVendor!({ account: 3, email: 'fixture@example.invalid' }); await settle();
    expect(answer).toBeDefined(); answer!(true); await settle();
    expect(cancelCalls(), 'only the original backend-owned request may exist').toEqual([['cancel_claude_login', { account: 3, operationId: 'owned-claude', confirmed: true }]]);
    expect(view.container.textContent, 'stale accepted response must not replace completed success').not.toContain('Sign-in ended at your request');
  });
});


async function reopenInNewComponent(onClose = vi.fn()) {
  const props = { isOpen: false, nextAccountId: 3, onClose, onAccountAdded: vi.fn() };
  const view = render(AddAccountModal, { props });
  await settle();
  await view.rerender({ ...props, isOpen: true }); await settle();
  return view;
}

describe('backend-owned pending sign-ins across component lifetime', () => {
  it('restores timeout-retained action after actual destroy/remount and preserves it on backend decline', async () => {
    const { view } = await start('claude');
    refuseVendor!(new Error('login_timeout_refused: sign-in program is still running')); await settle();
    view.unmount(); await settle();
    const remounted = await reopenInNewComponent();
    expect(invokeMock).toHaveBeenCalledWith('get_pending_logins');
    expect(remounted.queryByTestId('end-sign-in'), 'actual remount must restore backend-owned cancellation action').not.toBeNull();
    cancelReply.mockResolvedValue(false);
    await fireEvent.click(remounted.getByTestId('end-sign-in')); await settle();
    expect(remounted.queryByTestId('end-sign-in'), 'backend decline must retain restored operation').not.toBeNull();
    expect(cancelCalls()).toEqual([['cancel_claude_login', { account: 3, operationId: 'owned-claude', confirmed: true }]]);
    cancelReply.mockResolvedValue(true);
    await fireEvent.click(remounted.getByTestId('end-sign-in')); await settle();
    expect(remounted.queryByTestId('end-sign-in')).toBeNull();
  });

  it('false status response grants no cancellation action or new vendor admission', async () => {
    queryResponder = async () => false;
    const view = await reopenInNewComponent();
    expect(view.queryByTestId('end-sign-in'), 'false query response must grant no stop capability').toBeNull();
    expect(view.container.textContent).toContain('Could not check running sign-ins');
    for (const card of view.container.querySelectorAll<HTMLButtonElement>('.provider-card')) expect(card.disabled).toBe(true);
    expect(cancelCalls()).toEqual([]);
  });

  it('older delayed query cannot resurrect a stale cancellation target', async () => {
    let oldReply: ((rows: PendingRow[]) => void) | undefined;
    queryResponder = () => new Promise(resolve => { oldReply = resolve; });
    const view = await reopenInNewComponent();
    expect(oldReply).toBeDefined();
    queryResponder = async () => [];
    await fireEvent.click(view.getByTestId('refresh-sign-ins')); await settle();
    oldReply!([{ operation_id: 'old-owned', provider: 'claude', account: 3, native_id: null }]); await settle();
    expect(view.queryByTestId('end-sign-in'), 'older query must not resurrect stale operation capability').toBeNull();
    expect(cancelCalls()).toEqual([]);
  });

  it('fresh identity mismatch refuses stale-row cancellation instead of targeting replacement', async () => {
    activeRows = [{ operation_id: 'first-owned', provider: 'claude', account: 3, native_id: null }];
    const view = await reopenInNewComponent();
    const original = view.getByTestId('end-sign-in');
    activeRows = [{ operation_id: 'replacement-owned', provider: 'claude', account: 3, native_id: null }];
    cancelReply.mockResolvedValue(true);
    await fireEvent.click(original); await settle();
    expect(cancelCalls(), 'stale operation identity must not address replacement child').toEqual([]);
    expect(view.queryByTestId('end-sign-in')).not.toBeNull();
    await fireEvent.click(view.getByTestId('end-sign-in')); await settle();
    expect(cancelCalls()).toEqual([['cancel_claude_login', { account: 3, operationId: 'replacement-owned', confirmed: true }]]);
  });
});

async function dismiss(view: Awaited<ReturnType<typeof start>>['view'], action: 'close' | 'Escape' | 'backdrop') {
  if (action === 'Escape') await fireEvent.keyDown(document, { key: 'Escape' });
  else await fireEvent.click(view.container.querySelector<HTMLElement>(action === 'close' ? 'button.close' : '.backdrop')!);
}
const dismissalRows = (['claude', 'codex', 'native'] as const).flatMap(kind =>
  (['close', 'Escape', 'backdrop'] as const).map(action => [kind, action] as const));
describe('R2 dismissal and completed ownership', () => {
  it.each(dismissalRows)('%s %s waits for exact backend-confirmed retirement before dismissal', async (kind, action) => {
    const { view, props } = await start(kind);
    let confirm: ((value: boolean) => void) | undefined;
    cancelReply.mockImplementation(() => new Promise(resolve => { confirm = resolve; }));
    await dismiss(view, action);
    await waitFor(() => expect(cancelCalls().length + props.onClose.mock.calls.length).toBeGreaterThan(0));
    expect(props.onClose, 'modal must remain until actual retirement reply').not.toHaveBeenCalled();
    expect(cancelCalls(), 'dismissal must request backend-confirmed cancellation').toHaveLength(1);
    expect(cancelCalls()[0]?.[1]).toMatchObject({ operationId: `owned-${kind}`, confirmed: true });
    expect(confirm).toBeDefined();confirm!(true);
    await waitFor(() => expect(props.onClose).toHaveBeenCalledOnce());
  });

  it.each(['claude', 'codex', 'native'] as const)('empty backend registry clears completed %s timeout ownership', async kind => {
    const { view, props } = await start(kind);
    refuseVendor!(new Error('login_timeout_refused: still owned'));await settle();
    activeRows = []; // backend has since reaped; the local timeout response is old
    await fireEvent.click(view.getByTestId('refresh-sign-ins'));
    await waitFor(() => expect(view.queryByTestId('end-sign-in'), 'completed backend ownership must not leave a stale local cancel action').toBeNull());
    const retry = [...view.container.querySelectorAll('button')].find(button => button.textContent?.includes('Try again'));
    expect(retry).toBeDefined();await fireEvent.click(retry!);
    await waitFor(() => {
      const cards = [...view.container.querySelectorAll<HTMLButtonElement>('.provider-card')];
      expect(cards.length).toBeGreaterThan(0);
      expect(cards.every(card => !card.disabled), 'completed ownership must restore provider admission').toBe(true);
    });
    expect(cancelCalls()).toEqual([]);expect(props.onAccountAdded).not.toHaveBeenCalled();
  });

  it('empty status does not discard an active unbound local attempt before timeout', async () => {
    const { view, props } = await start();
    activeRows = [];
    await fireEvent.click(view.getByTestId('refresh-sign-ins'));await settle();
    expect(view.queryByTestId('end-sign-in'), 'pre-registration empty status must retain active local custody').not.toBeNull();
    expect(props.onAccountAdded).not.toHaveBeenCalled();
    expect(cancelCalls()).toEqual([]);
  });

  it('empty query begun before a new local attempt cannot clear that newer attempt', async () => {
    const onAccountAdded = vi.fn();
    const view = render(AddAccountModal, { props: { isOpen: false, nextAccountId: 3, onClose: vi.fn(), onAccountAdded } });
    await view.rerender({ isOpen: true });await settle();
    let oldReply: ((rows: PendingRow[]) => void) | undefined;
    queryResponder = () => new Promise(resolve => { oldReply = resolve; });
    await fireEvent.click(view.getByTestId('refresh-sign-ins'));await settle();
    // No newer query is issued: the attempt-ID guard must carry this race.
    await fireEvent.click(view.container.querySelector('.provider-card')!);await settle();
    expect(refuseVendor).toBeDefined();
    refuseVendor!(new Error('login_timeout_refused: newer operation'));await settle();
    expect(oldReply).toBeDefined();oldReply!([]);await settle();
    expect(view.queryByTestId('end-sign-in'), 'older empty query must not clear newer local operation').not.toBeNull();
    expect(onAccountAdded).not.toHaveBeenCalled();
  });

  it('dismissal refuses a replacement identity appearing after its initial snapshot', async () => {
    activeRows = [{ operation_id: 'first-owned', provider: 'claude', account: 3, native_id: null }];
    const onClose = vi.fn();
    const view = await reopenInNewComponent(onClose);
    let query = 0;
    queryResponder = async () => [{ operation_id: ++query === 1 ? 'first-owned' : 'replacement-owned', provider: 'claude', account: 3, native_id: null }];
    cancelReply.mockResolvedValue(true);
    await fireEvent.click(view.container.querySelector('button.close')!);await settle();
    expect(onClose, 'replacement identity must prevent dismissal').not.toHaveBeenCalled();
    expect(cancelCalls(), 'stale dismissal snapshot must never cancel replacement operation').toEqual([]);
    expect(view.queryByTestId('end-sign-in'), 'replacement remains visible for a fresh user decision').not.toBeNull();
  });

  it.each(['claude', 'codex', 'native'] as const)('committed %s cancellation reports signed-in success and refreshes accounts', async kind => {
    const { view, props } = await start(kind);
    let accepted: ((answer: boolean) => void) | undefined;
    cancelReply.mockImplementation(() => new Promise(resolve => { accepted = resolve; }));
    await fireEvent.click(view.getByTestId('end-sign-in'));
    await waitFor(() => expect(cancelReply).toHaveBeenCalledOnce());
    activeRows = [];
    refuseVendor!(new Error('login_committed_cancelled: account was signed in before cancellation'));
    await waitFor(() => expect(props.onAccountAdded, 'committed cancellation must refresh signed-in account').toHaveBeenCalledOnce());
    expect(view.container.textContent).toContain('was signed in before cancellation');
    expect(view.container.querySelector('.error-banner')).toBeNull();
    expect(accepted).toBeDefined();accepted!(true);await settle();
    expect(props.onAccountAdded).toHaveBeenCalledOnce();
    expect(view.container.textContent).toContain('was signed in before cancellation');
    expect(view.container.textContent).not.toContain('Sign-in ended at your request');
  });

  it('late committed cancellation refreshes accounts without clearing a newer operation', async () => {
    const { view, props } = await start();
    const refuseFirst = refuseVendor;
    cancelReply.mockResolvedValue(true);
    await fireEvent.click(view.getByTestId('end-sign-in'));
    await waitFor(() => expect(view.container.textContent).toContain('Sign-in ended at your request'));
    await fireEvent.click([...view.container.querySelectorAll('button')].find(button => button.textContent?.includes('Try again'))!);
    await fireEvent.click(view.container.querySelector('.provider-card')!);await settle();
    expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'start_claude_login_subprocess')).toHaveLength(2);
    refuseFirst!(new Error('login_committed_cancelled: account was signed in before cancellation'));
    await waitFor(() => expect(props.onAccountAdded).toHaveBeenCalledOnce());
    expect(view.queryByTestId('end-sign-in'), 'late committed receipt must retain newer operation').not.toBeNull();
    expect(view.container.textContent).toContain('Signing in to account #3');
  });

  it('confirmed dismissal still refreshes a committed login whose result arrives after modal close', async () => {
    const { view, props } = await start();
    cancelReply.mockResolvedValue(true);
    await dismiss(view, 'close');
    await waitFor(() => expect(props.onClose).toHaveBeenCalledOnce());
    await view.rerender({ ...props, isOpen: false });
    refuseVendor!(new Error('login_committed_cancelled: account was signed in before cancellation'));
    await waitFor(() => expect(props.onAccountAdded).toHaveBeenCalledOnce());
    expect(view.container.querySelector('.modal')).toBeNull();
  });
});


describe('R2 follow-up operation state and committed cancel receipts', () => {
  it('starting and binding a local login never reloads the open picker', async () => {
    const { view } = await start();
    await waitFor(() => {
      expect(view.container.textContent, 'starting a vendor must retain the running view').toContain('Signing in to account #3');
    });
    expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'get_pending_logins'), 'starting a vendor must not rerun the open-edge status query').toHaveLength(1);
    expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'list_providers')).toHaveLength(1);
    await fireEvent.click(view.getByTestId('refresh-sign-ins'));await settle();
    expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'get_pending_logins'), 'binding an operation identity must not rerun the open effect').toHaveLength(2);
    expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'list_providers')).toHaveLength(1);
    expect(view.container.textContent).toContain('Signing in to account #3');
    refuseVendor!(new Error('login_timeout_refused: retained'));await settle();
  });

  it.each(['claude', 'codex', 'native'] as const)('committed %s cancellation IPC reports success exactly once across its delayed login result', async kind => {
    const { view, props } = await start(kind);
    const lateLoginResult = refuseVendor;
    cancelReply.mockImplementation(() => {
      activeRows = [];
      return Promise.reject(new Error('login_committed_cancelled: account was signed in before cancellation'));
    });
    await fireEvent.click(view.getByTestId('end-sign-in'));
    await waitFor(() => expect(props.onAccountAdded, 'committed cancellation IPC must refresh signed-in account').toHaveBeenCalledOnce());
    expect(view.queryByTestId('end-sign-in')).toBeNull();
    expect(view.container.textContent).toContain('was signed in before cancellation');
    expect(view.container.textContent).not.toContain('Could not end the sign-in program');
    lateLoginResult!(new Error('login_committed_cancelled: account was signed in before cancellation'));await settle();
    expect(props.onAccountAdded, 'cancel and login receipts describe one committed sign-in').toHaveBeenCalledOnce();
    expect(view.container.textContent).toContain('was signed in before cancellation');
  });

  it('dismissal accepts a committed cancellation IPC receipt and refreshes before closing', async () => {
    const { view, props } = await start();
    cancelReply.mockImplementation(() => {
      activeRows = [];
      return Promise.reject(new Error('login_committed_cancelled: account was signed in before cancellation'));
    });
    await dismiss(view, 'close');
    await waitFor(() => expect(props.onClose, 'committed retired operation must permit dismissal').toHaveBeenCalledOnce());
    expect(props.onAccountAdded).toHaveBeenCalledOnce();
    refuseVendor!(new Error('login_committed_cancelled: account was signed in before cancellation'));await settle();
    expect(props.onAccountAdded).toHaveBeenCalledOnce();
  });

  it('an already delivered successful login is not counted twice by a committed cancellation IPC receipt', async () => {
    const { view, props } = await start();
    let rejectCancel: ((error: Error) => void) | undefined;
    cancelReply.mockImplementation(() => new Promise((_resolve, reject) => { rejectCancel = reject; }));
    await fireEvent.click(view.getByTestId('end-sign-in'));
    await waitFor(() => expect(cancelReply).toHaveBeenCalledOnce());
    finishVendor!({ account: 3, email: 'already@example.invalid' });
    await waitFor(() => expect(props.onAccountAdded).toHaveBeenCalledOnce());
    expect(rejectCancel).toBeDefined();
    rejectCancel!(new Error('login_committed_cancelled: account was signed in before cancellation'));await settle();
    expect(props.onAccountAdded).toHaveBeenCalledOnce();
    expect(view.container.textContent).toContain('was signed in before cancellation');
    expect(view.container.textContent).not.toContain('Could not end the sign-in program');
  });
});


describe('unresolved cancellation quarantine location', () => {
  it.each(['claude', 'codex', 'native'] as const)('unresolved %s cancellation exposes the exact sanitized quarantine location and retains ownership', async kind => {
    const { view, props } = await start(kind);
    const quarantine = '<csq-base>/.login-grants/grant-123e4567-e89b-42d3-a456-426614174000';
    const warning = `login_group_custody_unresolved: vendor_login_quarantined: ${quarantine}`;
    cancelReply.mockRejectedValue(new Error(warning));
    await fireEvent.click(view.getByTestId('end-sign-in'));
    await waitFor(() => {
      const alert = view.container.querySelector('[role="alert"]');
      expect(alert?.textContent, 'unresolved cancellation must expose exact sanitized quarantine path in visible alert').toContain(quarantine);
      expect(alert?.textContent).toContain(warning);
    });
    expect(view.queryByTestId('end-sign-in'), 'unresolved cancellation must retain pending operation action').not.toBeNull();
    expect(view.container.textContent).not.toContain('Sign-in ended at your request');
    expect(props.onAccountAdded).not.toHaveBeenCalled();
    expect(props.onClose).not.toHaveBeenCalled();
    expect(cancelCalls()).toHaveLength(1);
    expect(cancelCalls()[0]?.[1]).toMatchObject({ operationId: `owned-${kind}`, confirmed: true });
    // Dismissal must retry the same backend/native-confirmation path, never
    // silently clear custody because the first cancel returned UNKNOWN.
    await fireEvent.click(view.container.querySelector('button.close')!);
    await waitFor(() => expect(cancelCalls()).toHaveLength(2));
    expect(cancelCalls()[1]?.[1]).toMatchObject({ operationId: `owned-${kind}`, confirmed: true });
    expect(props.onClose).not.toHaveBeenCalled();
    expect(props.onAccountAdded).not.toHaveBeenCalled();
    expect(view.queryByTestId('end-sign-in')).not.toBeNull();
  });
});
