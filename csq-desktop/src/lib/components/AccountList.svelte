<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { homeDir, join } from '@tauri-apps/api/path';
  import UsageBar from './UsageBar.svelte';
  import TokenBadge from './TokenBadge.svelte';
  import AddAccountModal from './AddAccountModal.svelte';

  interface AccountView {
    id: number;
    label: string;
    source: string;
    has_credentials: boolean;
    five_hour_pct: number;
    seven_day_pct: number;
    updated_at: number;
    token_status: string;
    expires_in_secs: number | null;
    /// Fixed-vocabulary tag from the most recent refresh failure,
    /// or null if the last refresh succeeded / no flag is set.
    /// Rendered next to the token status so "Expired" grows a
    /// "— invalid token" suffix when the refresh token is dead.
    last_refresh_error: string | null;
  }

  /// Maps the backend's fixed-vocabulary error tag to human text.
  /// Keeps the vocabulary stable on the backend while letting the
  /// UI phrase things idiomatically.
  function formatRefreshError(tag: string | null): string {
    if (!tag) return '';
    switch (tag) {
      case 'broker_token_invalid':
        return 'invalid token — re-login needed';
      case 'broker_refresh_failed':
        return 'refresh failed — check network or re-login';
      case 'broker_other':
        return 'broker error';
      case 'credential':
        return 'credential file error';
      case 'platform':
        return 'platform error';
      case 'oauth':
        return 'oauth error';
      case 'daemon':
        return 'daemon error';
      case 'config':
        return 'config error';
      default:
        return tag; // pass through unknown tags
    }
  }

  let accounts = $state<AccountView[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let modalOpen = $state(false);

  // ── First-paint instrumentation ──────────────────────────
  //
  // Budget: first usable paint <200ms from module import. The
  // dashboard is the escape hatch when the tray quick-swap picks
  // the wrong session, so sluggish first paint during a rate-limit
  // recovery moment is the worst time for it. This instrumentation
  // logs one line per cold load in dev builds so the 200ms budget
  // is visible in the console as the app evolves. Stripped in
  // production — `import.meta.env.DEV` is a Vite-injected compile
  // constant, not a runtime feature flag.
  const firstPaintStart =
    typeof performance !== 'undefined' ? performance.now() : 0;
  let firstPaintLogged = false;
  function logFirstPaint(label: string) {
    if (firstPaintLogged || !import.meta.env.DEV) return;
    firstPaintLogged = true;
    const elapsed = performance.now() - firstPaintStart;
    // eslint-disable-next-line no-console
    console.info(`[csq] first paint (${label}) in ${elapsed.toFixed(1)}ms`);
  }

  async function getBaseDir(): Promise<string> {
    // Use `join` so the platform's path separator is honored.
    // Tauri 2.10's `homeDir()` returns the home path without a
    // trailing separator (`/Users/esperie`, not `/Users/esperie/`),
    // so naive string concatenation produces an invalid path like
    // `/Users/esperie.claude/accounts`.
    const home = await homeDir();
    return await join(home, '.claude', 'accounts');
  }

  async function fetchAccounts() {
    try {
      const baseDir = await getBaseDir();
      accounts = await invoke<AccountView[]>('get_accounts', { baseDir });
      error = null;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
      // The list is about to render in the next microtask — that's
      // the first moment the user sees either the rows or the
      // error banner. Log here so the measurement covers the full
      // IPC round-trip, not just component mount.
      logFirstPaint(error ? 'error' : 'ready');
    }
  }

  // The next free slot is the smallest 1..=999 integer not already
  // taken by an existing account. Using `length + 1` would skip
  // past gaps (e.g. after the user deletes account 3 from five).
  function nextAccountId(): number {
    const taken = new Set(accounts.map((a) => a.id));
    for (let i = 1; i <= 999; i++) {
      if (!taken.has(i)) return i;
    }
    return accounts.length + 1;
  }

  async function handleSwap(accountId: number) {
    try {
      const baseDir = await getBaseDir();
      await invoke('swap_account', { baseDir, target: accountId });
      await fetchAccounts();
    } catch (e) {
      error = String(e);
    }
  }

  // Initial fetch + 5-second poll
  $effect(() => {
    fetchAccounts();
    const interval = setInterval(fetchAccounts, 5000);
    return () => clearInterval(interval);
  });
</script>

{#if loading}
  <div class="loading">Loading accounts...</div>
{:else if error}
  <div class="error">{error}</div>
{:else if accounts.length === 0}
  <div class="empty">
    <p>No accounts configured.</p>
    <p class="hint">Run <code>csq login 1</code> to add your first account.</p>
  </div>
{:else}
  <div class="account-list">
    {#each accounts as account (account.id)}
      <button class="account-card" class:no-creds={!account.has_credentials}
              onclick={() => handleSwap(account.id)}>
        <div class="account-header">
          <span class="account-id">#{account.id}</span>
          <span class="account-label">{account.label}</span>
          <TokenBadge status={account.token_status} expiresSecs={account.expires_in_secs} />
        </div>
        {#if account.last_refresh_error}
          <div class="refresh-error" title="Most recent refresh failure tag from the daemon">
            ⚠ {formatRefreshError(account.last_refresh_error)}
          </div>
        {/if}
        <div class="usage-bars">
          <UsageBar label="5h" pct={account.five_hour_pct} />
          <UsageBar label="7d" pct={account.seven_day_pct} />
        </div>
      </button>
    {/each}
  </div>
{/if}

<div class="actions">
  <button class="add-account" onclick={() => (modalOpen = true)}>+ Add Account</button>
</div>

<AddAccountModal
  isOpen={modalOpen}
  nextAccountId={nextAccountId()}
  onClose={() => (modalOpen = false)}
  onAccountAdded={() => fetchAccounts()}
/>

<style>
  .account-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .account-card {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    color: inherit;
    font: inherit;
    width: 100%;
    transition: border-color 0.15s;
  }
  .account-card:hover { border-color: var(--accent); }
  .account-card.no-creds { opacity: 0.5; }
  .account-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .account-id { font-weight: 700; font-size: 0.85rem; color: var(--text-secondary); }
  .account-label { flex: 1; font-weight: 500; }
  .refresh-error {
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
    margin-top: -0.15rem;
  }
  .usage-bars { display: flex; gap: 1rem; }
  .loading, .error, .empty { padding: 2rem; text-align: center; }
  .error { color: var(--red); }
  .hint { font-size: 0.85rem; color: var(--text-secondary); }
  code { background: var(--bg-tertiary); padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.85em; }
  .actions { margin-top: 0.75rem; }
  .add-account {
    width: 100%;
    padding: 0.6rem;
    background: transparent;
    border: 1px dashed var(--border);
    border-radius: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    transition: border-color 0.15s, color 0.15s;
  }
  .add-account:hover { border-color: var(--accent); color: var(--accent); }
</style>
