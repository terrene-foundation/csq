<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { homeDir, join } from '@tauri-apps/api/path';
  import UsageBar from './UsageBar.svelte';
  import TokenBadge from './TokenBadge.svelte';
  import AddAccountModal from './AddAccountModal.svelte';
  import ChangeModelModal from './ChangeModelModal.svelte';

  interface AccountView {
    id: number;
    label: string;
    source: string;
    has_credentials: boolean;
    five_hour_pct: number;
    five_hour_resets_in: number | null;
    seven_day_pct: number;
    seven_day_resets_in: number | null;
    updated_at: number;
    token_status: string;
    expires_in_secs: number | null;
    /// Fixed-vocabulary tag from the most recent refresh failure,
    /// or null if the last refresh succeeded / no flag is set.
    /// Rendered next to the token status so "Expired" grows a
    /// "— invalid token" suffix when the refresh token is dead.
    last_refresh_error: string | null;
    /// Stable 3P provider id ("mm" | "zai" | "ollama"), or null
    /// for Anthropic OAuth slots. Used to branch UI on provider
    /// type (e.g. only Ollama slots get a "Change model" button).
    provider_id: string | null;
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
        return 'recovery failed — re-login needed';
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
  let displayOrder = $state<number[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let modalOpen = $state(false);
  let reauthSlot = $state<number | null>(null);
  // Ollama-slot model-change modal. `null` = closed; number = slot id.
  let changeModelSlot = $state<number | null>(null);
  // Two-tap remove: the first click on the × button arms the
  // confirmation; the second click on the same card commits. Tapping
  // any other card or letting the auto-disarm timer fire resets it.
  let armedRemoveId = $state<number | null>(null);
  let armedRemoveTimer: ReturnType<typeof setTimeout> | null = null;

  // ── Sort mode ────────────────────────────────────────────

  type SortMode = 'custom' | '5h' | '7d';

  function loadSortMode(): SortMode {
    try {
      const raw = localStorage.getItem('csq-sort-mode');
      if (raw === '5h' || raw === '7d') return raw;
    } catch {}
    return 'custom';
  }

  function saveSortMode(mode: SortMode) {
    try { localStorage.setItem('csq-sort-mode', mode); } catch {}
  }

  let sortMode = $state<SortMode>(loadSortMode());

  function setSortMode(mode: SortMode) {
    sortMode = mode;
    saveSortMode(mode);
  }

  // ── Reorder ──────────────────────────────────────────────

  function orderedAccounts(): AccountView[] {
    if (displayOrder.length === 0) return accounts;
    const byId = new Map(accounts.map(a => [a.id, a]));
    const ordered: AccountView[] = [];
    for (const id of displayOrder) {
      const a = byId.get(id);
      if (a) { ordered.push(a); byId.delete(id); }
    }
    for (const a of byId.values()) ordered.push(a);
    return ordered;
  }

  // Final display list: custom order or sorted by reset time.
  // Nulls sort to the bottom in both reset-time modes.
  let displayedAccounts = $derived.by(() => {
    const base = orderedAccounts();
    if (sortMode === 'custom') return base;
    const key: keyof AccountView = sortMode === '5h' ? 'five_hour_resets_in' : 'seven_day_resets_in';
    return [...base].sort((a, b) => {
      const av = a[key] as number | null;
      const bv = b[key] as number | null;
      const aValid = av != null && av > 0;
      const bValid = bv != null && bv > 0;
      if (aValid && bValid) return av! - bv!;
      if (aValid) return -1;
      if (bValid) return 1;
      return 0;
    });
  });

  let justMovedId = $state<number | null>(null);

  function moveCard(idx: number, direction: -1 | 1) {
    const items = [...orderedAccounts()];
    const newIdx = idx + direction;
    if (newIdx < 0 || newIdx >= items.length) return;
    const movedId = items[idx].id;
    [items[idx], items[newIdx]] = [items[newIdx], items[idx]];
    displayOrder = items.map(a => a.id);
    saveOrder(displayOrder);
    // Highlight the moved card briefly
    justMovedId = movedId;
    setTimeout(() => { justMovedId = null; }, 600);
  }

  function saveOrder(order: number[]) {
    try { localStorage.setItem('csq-card-order', JSON.stringify(order)); } catch {}
  }
  function loadOrder(): number[] {
    try {
      const raw = localStorage.getItem('csq-card-order');
      return raw ? JSON.parse(raw) : [];
    } catch { return []; }
  }

  // ── "Resets soonest" badge ───────────────────────────────
  //
  // Only show a badge when 2+ accounts have a positive reset value
  // for a given window. The badge appears on the one account whose
  // reset time is smallest (i.e. the soonest to free up quota).

  // ── 7d reset ranking ─────────────────────────────────────
  //
  // Rank accounts by 7d reset time (soonest = 1st). Accounts
  // with >= 99.5% usage are excluded — they have no usable quota
  // until reset. Same-rank ties are allowed when reset times match.
  let resetRank = $derived.by((): Map<number, number> => {
    const ranked = new Map<number, number>();
    const candidates = accounts
      .filter(a => a.seven_day_resets_in != null && a.seven_day_resets_in > 0 && a.seven_day_pct < 99.5)
      .sort((a, b) => a.seven_day_resets_in! - b.seven_day_resets_in!);
    if (candidates.length < 2) return ranked;
    let rank = 1;
    for (let i = 0; i < candidates.length; i++) {
      if (i > 0 && candidates[i].seven_day_resets_in !== candidates[i - 1].seven_day_resets_in) {
        rank = i + 1;
      }
      ranked.set(candidates[i].id, rank);
    }
    return ranked;
  });

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
      const raw = String(e);
      if (raw.includes('THIRD_PARTY_NOT_SWAPPABLE')) {
        // Strip the typed prefix so the user sees the human sentence.
        error = raw.replace(/^.*THIRD_PARTY_NOT_SWAPPABLE:\s*/, '');
      } else {
        error = raw;
      }
    }
  }

  function disarmRemove() {
    armedRemoveId = null;
    if (armedRemoveTimer) {
      clearTimeout(armedRemoveTimer);
      armedRemoveTimer = null;
    }
  }

  function armRemove(accountId: number) {
    disarmRemove();
    armedRemoveId = accountId;
    // Auto-disarm after 4s if the user doesn't follow through.
    armedRemoveTimer = setTimeout(() => disarmRemove(), 4000);
  }

  async function handleRemove(accountId: number, e: MouseEvent) {
    e.stopPropagation();
    if (armedRemoveId !== accountId) {
      armRemove(accountId);
      return;
    }
    disarmRemove();
    try {
      const baseDir = await getBaseDir();
      await invoke('remove_account', { baseDir, account: accountId });
      await fetchAccounts();
    } catch (e) {
      // Surface the typed error message to the banner. Backend
      // returns prefixed tags like ACCOUNT_IN_USE / NOT_CONFIGURED
      // so the user can self-diagnose.
      const raw = String(e);
      if (raw.startsWith('ACCOUNT_IN_USE:')) {
        error = `Cannot remove account ${accountId} — a Claude Code session is still running. Exit it first, then retry.`;
      } else {
        error = raw;
      }
    }
  }

  // ── Inline rename ───────────────────────────────────────
  let editingId = $state<number | null>(null);
  let editValue = $state('');

  function startRename(account: AccountView, e: MouseEvent) {
    e.stopPropagation();
    editingId = account.id;
    editValue = account.label;
  }

  async function saveRename(accountId: number) {
    if (!editValue.trim()) { editingId = null; return; }
    try {
      const baseDir = await getBaseDir();
      await invoke('rename_account', { baseDir, account: accountId, name: editValue.trim() });
      editingId = null;
      await fetchAccounts();
    } catch (e) {
      error = String(e);
      editingId = null;
    }
  }

  function formatResetTime(secs: number | null): string {
    if (secs == null || secs <= 0) return '';
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return m > 0 ? `${h}h${m}m` : `${h}h`;
  }

  function handleRenameKeydown(e: KeyboardEvent, accountId: number) {
    if (e.key === 'Enter') saveRename(accountId);
    if (e.key === 'Escape') editingId = null;
  }

  // Initial fetch + 5-second poll + load saved order
  $effect(() => {
    displayOrder = loadOrder();
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
  <div class="sort-control">
    <button
      class="sort-pill"
      class:active={sortMode === 'custom'}
      onclick={() => setSortMode('custom')}
    >custom</button>
    <button
      class="sort-pill"
      class:active={sortMode === '5h'}
      onclick={() => setSortMode('5h')}
    >5h reset</button>
    <button
      class="sort-pill"
      class:active={sortMode === '7d'}
      onclick={() => setSortMode('7d')}
    >7d reset</button>
  </div>
  <div class="account-list">
    {#each displayedAccounts as account, idx (account.id)}
      <div class="account-card" class:no-creds={!account.has_credentials} class:just-moved={justMovedId === account.id}>
        <div class="card-controls">
          {#if sortMode === 'custom'}
            <button class="move-btn" onclick={(e) => { e.stopPropagation(); moveCard(idx, -1); }} disabled={idx === 0} title="Move up">▲</button>
            <button class="move-btn" onclick={(e) => { e.stopPropagation(); moveCard(idx, 1); }} disabled={idx === displayedAccounts.length - 1} title="Move down">▼</button>
          {/if}
          <button
            class="remove-btn"
            class:armed={armedRemoveId === account.id}
            onclick={(e) => handleRemove(account.id, e)}
            title={armedRemoveId === account.id ? 'Click again to confirm removal' : 'Remove this account'}
          >{armedRemoveId === account.id ? 'Confirm' : '×'}</button>
        </div>
        {#if armedRemoveId === account.id}
          <button
            type="button"
            class="armed-overlay"
            aria-label="Cancel remove"
            onclick={(e) => { e.stopPropagation(); disarmRemove(); }}
          ></button>
        {/if}
        <button class="card-body" onclick={() => handleSwap(account.id)}>
          <div class="account-header">
            <span class="account-id">#{account.id}</span>
            {#if editingId === account.id}
              <!-- svelte-ignore a11y_autofocus -->
              <input
                class="rename-input"
                bind:value={editValue}
                onkeydown={(e) => handleRenameKeydown(e, account.id)}
                onblur={() => saveRename(account.id)}
                autofocus
                onclick={(e) => e.stopPropagation()}
              />
            {:else}
              <span class="account-label" role="button" tabindex="0" ondblclick={(e) => startRename(account, e)} title="Double-click to rename">{account.label}</span>
            {/if}
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
          {#if account.five_hour_resets_in || account.seven_day_resets_in}
            <div class="reset-info">
              {#if account.five_hour_resets_in}
                <span>5h resets in {formatResetTime(account.five_hour_resets_in)}</span>
              {/if}
              {#if account.seven_day_resets_in}
                <span>
                  7d resets in {formatResetTime(account.seven_day_resets_in)}
                  {#if resetRank.has(account.id)}
                    <span class="rank-badge">{resetRank.get(account.id)}</span>
                  {/if}
                </span>
              {/if}
            </div>
          {/if}
        </button>
        {#if account.token_status === 'expired' || account.token_status === 'missing' || account.last_refresh_error}
          <button
            class="reauth-btn"
            onclick={(e) => {
              e.stopPropagation();
              reauthSlot = account.id;
              modalOpen = true;
            }}
            title="Re-authenticate this account with a fresh OAuth login"
          >
            Re-auth
          </button>
        {/if}
        {#if account.provider_id === 'ollama'}
          <button
            class="change-model-btn"
            onclick={(e) => {
              e.stopPropagation();
              changeModelSlot = account.id;
            }}
            title="Switch which local Ollama model this slot uses"
          >
            Change model
          </button>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<div class="actions">
  <button class="add-account" onclick={() => { reauthSlot = null; modalOpen = true; }}>+ Add Account</button>
</div>

<AddAccountModal
  isOpen={modalOpen}
  nextAccountId={reauthSlot ?? nextAccountId()}
  reauthSlot={reauthSlot}
  onClose={() => { reauthSlot = null; modalOpen = false; }}
  onAccountAdded={() => fetchAccounts()}
/>

<ChangeModelModal
  isOpen={changeModelSlot !== null}
  slot={changeModelSlot ?? 0}
  onClose={() => { changeModelSlot = null; }}
  onChanged={() => fetchAccounts()}
/>

<style>
  .sort-control {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 0.5rem;
  }
  .sort-pill {
    padding: 0.2rem 0.55rem;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--text-tertiary);
    font: inherit;
    font-size: 0.72rem;
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
    line-height: 1.4;
  }
  .sort-pill:hover {
    border-color: var(--text-secondary);
    color: var(--text-secondary);
  }
  .sort-pill.active {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-low);
  }
  .rank-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.58rem;
    font-weight: 700;
    min-width: 1.2em;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 999px;
    padding: 0 0.3em;
    line-height: 1.5;
    vertical-align: middle;
    margin-left: 0.25em;
    opacity: 0.85;
  }
  .account-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .account-card {
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    transition: border-color 0.15s;
    overflow: hidden;
  }
  .account-card { position: relative; }
  .account-card:hover { border-color: var(--accent); }
  .account-card.no-creds { opacity: 0.5; }
  .account-card.just-moved {
    border-color: var(--accent);
    transition: border-color 0.3s;
  }
  .card-controls {
    position: absolute;
    right: 0.4rem;
    bottom: 0.4rem;
    display: flex;
    gap: 2px;
    opacity: 0;
    transition: opacity 0.15s;
    z-index: 3;
  }
  .account-card:hover .card-controls { opacity: 1; }
  /* Keep controls visible while the remove button is armed so the
     user can complete the second tap without re-hovering. */
  .account-card:has(.remove-btn.armed) .card-controls { opacity: 1; }
  .move-btn {
    background: var(--bg-tertiary);
    border: none;
    color: var(--text-secondary);
    font-size: 0.55rem;
    padding: 0.15rem 0.25rem;
    cursor: pointer;
    border-radius: 2px;
    line-height: 1;
  }
  .move-btn:hover { color: var(--accent); }
  .move-btn:disabled { opacity: 0.2; cursor: default; }
  .remove-btn {
    background: var(--bg-tertiary);
    border: none;
    color: var(--text-secondary);
    font-size: 0.65rem;
    padding: 0.15rem 0.35rem;
    cursor: pointer;
    border-radius: 2px;
    line-height: 1;
    margin-left: 2px;
  }
  .remove-btn:hover { color: var(--red); }
  .remove-btn.armed {
    background: var(--red);
    color: white;
    font-weight: 600;
    font-size: 0.6rem;
  }
  /* Transparent click-trap covering the card body. Lets the user
     dismiss an armed remove by clicking anywhere on the card (not
     the × button). The button itself sits above this overlay
     because .card-controls has a higher z-index. */
  .armed-overlay {
    position: absolute;
    inset: 0;
    background: transparent;
    border: none;
    cursor: default;
    z-index: 2;
    padding: 0;
  }
  .card-body {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.75rem;
    background: transparent;
    border: none;
    cursor: pointer;
    text-align: left;
    color: inherit;
    font: inherit;
    width: 100%;
  }
  .reauth-btn {
    padding: 0.4rem 0.75rem;
    background: rgba(244, 67, 54, 0.08);
    border: none;
    border-top: 1px solid var(--border);
    color: var(--red);
    font: inherit;
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    transition: background 0.15s;
  }
  .reauth-btn:hover {
    background: rgba(244, 67, 54, 0.18);
  }
  .change-model-btn {
    padding: 0.4rem 0.75rem;
    background: var(--bg-secondary);
    border: none;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font: inherit;
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    transition: color 0.15s;
  }
  .change-model-btn:hover {
    color: var(--accent);
  }
  .account-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .account-id { font-weight: 700; font-size: 0.85rem; color: var(--text-secondary); }
  .account-label { flex: 1; font-weight: 500; cursor: text; }
  .rename-input {
    flex: 1;
    font: inherit;
    font-weight: 500;
    background: var(--bg-tertiary);
    border: 1px solid var(--accent);
    border-radius: 3px;
    padding: 0.1rem 0.3rem;
    color: inherit;
    outline: none;
  }
  .refresh-error {
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
    margin-top: -0.15rem;
  }
  .usage-bars { display: flex; gap: 1rem; }
  .reset-info {
    display: flex;
    gap: 1rem;
    font-size: 0.68rem;
    color: var(--text-tertiary);
    font-family: var(--font-mono, ui-monospace, monospace);
    margin-top: -0.1rem;
  }
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
