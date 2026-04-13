<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import { homeDir, join } from '@tauri-apps/api/path';

  // ── Props ─────────────────────────────────────────────────
  let {
    isOpen,
    nextAccountId,
    reauthSlot = null,
    onClose,
    onAccountAdded,
  }: {
    isOpen: boolean;
    nextAccountId: number;
    /// When set, the modal is in re-auth mode for this specific slot.
    /// The slot input is locked, the "already in use" warning is
    /// suppressed (re-auth on a configured slot is the correct
    /// behavior), and the OAuth button stays enabled regardless of
    /// `takenSlots` membership.
    reauthSlot?: number | null;
    onClose: () => void;
    onAccountAdded: () => void;
  } = $props();

  // ── Types ─────────────────────────────────────────────────
  interface ProviderView {
    id: string;
    name: string;
    auth_type: 'oauth' | 'bearer' | 'none';
    default_base_url: string | null;
    default_model: string;
  }

  interface ClaudeLoginView {
    auth_url: string;
    state: string;
    account: number;
    expires_in_secs: number;
  }

  // ── Local state ───────────────────────────────────────────
  //
  // Claude OAuth flow (preferred — shell out to `claude auth login`
  // via absolute path, mirroring `csq login N`):
  //   1. `picker`             — user picks a provider
  //   2. `running-claude`     — `claude auth login` subprocess running
  //   3. `success` / `error`
  //
  // Claude OAuth paste-code fallback (used when `claude` binary
  // cannot be located on disk — the start_claude_login command
  // returns CLAUDE_NOT_FOUND and we drop into the in-process flow):
  //   1. `paste-code`     — browser is open, user pastes the code
  //   2. `exchanging`     — submitting code to Anthropic
  //
  // Bearer-key flow (MiniMax, Z.AI):
  //   1. `picker`        — user picks a provider
  //   2. `bearer-form`   — user pastes an API key
  type Step =
    | { kind: 'picker' }
    | { kind: 'running-claude'; account: number }
    | {
        kind: 'paste-code';
        login: ClaudeLoginView;
        code: string;
        error: string | null;
      }
    | { kind: 'exchanging'; account: number }
    | {
        kind: 'bearer-form';
        provider: ProviderView;
        key: string;
        submitting: boolean;
        error: string | null;
      }
    | { kind: 'success'; message: string }
    | { kind: 'error'; message: string };

  let step = $state<Step>({ kind: 'picker' });
  let providers = $state<ProviderView[]>([]);
  let providersError = $state<string | null>(null);

  // Slot picker — the dashboard suggests `nextAccountId` as a
  // default, but the user can override (e.g. if they want to log
  // back into the slot they just removed). Validated against the
  // current account list so we don't silently overwrite a slot
  // that's already configured.
  //
  // Initialized to 0 and synced from the prop in the effect below;
  // `$state(nextAccountId)` would only capture the initial prop
  // value at component construction (Svelte 5 warning
  // state_referenced_locally) and miss subsequent prop updates.
  let chosenSlot = $state<number>(0);
  let takenSlots = $state<Set<number>>(new Set());

  // Recompute the default slot whenever the parent's nextAccountId
  // prop changes (e.g. after the user removes an account, or when
  // re-auth is invoked for a specific slot).
  $effect(() => { chosenSlot = nextAccountId; });

  let isReauth = $derived(reauthSlot !== null);

  let slotError = $derived.by((): string | null => {
    if (!Number.isInteger(chosenSlot) || chosenSlot < 1 || chosenSlot > 999) {
      return 'Slot must be an integer between 1 and 999';
    }
    // In re-auth mode, the slot is *expected* to be taken — we're
    // refreshing the credentials for that exact slot. Skip the
    // "already in use" check.
    if (!isReauth && takenSlots.has(chosenSlot)) {
      return `Slot #${chosenSlot} is already configured. Remove it first or pick another slot.`;
    }
    return null;
  });

  // ── Provider fetch ────────────────────────────────────────
  async function loadProviders() {
    try {
      providers = await invoke<ProviderView[]>('list_providers');
      providersError = null;
    } catch (e) {
      providersError = String(e);
    }
  }

  // Loads the current account list so the slot picker can warn
  // before clobbering an existing slot.
  async function loadTakenSlots() {
    try {
      const baseDir = await getBaseDir();
      const accounts = await invoke<Array<{ id: number }>>('get_accounts', { baseDir });
      takenSlots = new Set(accounts.map(a => a.id));
    } catch {
      takenSlots = new Set();
    }
  }

  // Reset to picker whenever the modal re-opens. Cancel any
  // in-flight PKCE state when the modal closes mid-flow so the
  // state store doesn't fill with abandoned entries.
  $effect(() => {
    if (isOpen) {
      step = { kind: 'picker' };
      chosenSlot = nextAccountId;
      let cancelled = false;
      (async () => {
        if (!cancelled) {
          await loadProviders();
          await loadTakenSlots();
        }
      })();
      return () => { cancelled = true; };
    }
  });

  async function getBaseDir(): Promise<string> {
    // `join` honors the platform path separator and Tauri 2.10's
    // `homeDir()` has no trailing separator, so naive string
    // concatenation would produce `/Users/x.claude/accounts`.
    const home = await homeDir();
    return await join(home, '.claude', 'accounts');
  }

  // ── Provider pick ─────────────────────────────────────────
  async function pickProvider(provider: ProviderView) {
    // Slot picker is only meaningful for the OAuth (account) flow.
    // 3P provider keys live in settings-mm.json / settings-zai.json
    // — no per-account slot semantics.
    if (provider.auth_type === 'oauth') {
      if (slotError) return; // disabled in UI but defend in JS too
      await startClaudeOAuth(chosenSlot);
    } else if (provider.auth_type === 'bearer') {
      step = {
        kind: 'bearer-form',
        provider,
        key: '',
        submitting: false,
        error: null,
      };
    }
  }

  // ── Claude OAuth (shell-out via absolute path, with fallback) ─
  //
  // PRIMARY: invoke `start_claude_login` which finds `claude` via
  // csq_core::accounts::login::find_claude_binary (walks $PATH plus
  // a fixed list of well-known install dirs so the Finder-launched
  // bundle can find it). Same flow as `csq login N`: spawn a real
  // `claude auth login` subprocess, let CC own the browser dance,
  // read the credentials file when it exits.
  //
  // FALLBACK: if start_claude_login returns CLAUDE_NOT_FOUND, the
  // user has no `claude` install we can locate. Drop into the in-
  // process paste-code flow (`begin_claude_login` +
  // `submit_oauth_code`) which exchanges the code through the
  // daemon and never touches a subprocess.
  async function startClaudeOAuth(account: number) {
    step = { kind: 'running-claude', account };
    try {
      const baseDir = await getBaseDir();
      const result = await invoke<number>('start_claude_login', { baseDir, account });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Account ${result} added successfully.`,
      };
    } catch (e) {
      const raw = String(e);
      if (raw.includes('CLAUDE_NOT_FOUND')) {
        // Binary missing — fall back to paste-code automatically.
        try {
          const login = await invoke<ClaudeLoginView>('begin_claude_login', { account });
          await openUrl(login.auth_url);
          step = { kind: 'paste-code', login, code: '', error: null };
        } catch (e2) {
          step = { kind: 'error', message: String(e2) };
        }
      } else {
        step = { kind: 'error', message: raw };
      }
    }
  }

  async function submitOAuthCode() {
    if (step.kind !== 'paste-code') return;
    const current = step;
    const code = current.code.trim();
    if (!code) {
      step = { ...current, error: 'Authorization code must not be empty' };
      return;
    }

    step = { kind: 'exchanging', account: current.login.account };
    try {
      const baseDir = await getBaseDir();
      const account = await invoke<number>('submit_oauth_code', {
        baseDir,
        stateToken: current.login.state,
        code,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Account ${account} added successfully.`,
      };
    } catch (e) {
      step = {
        kind: 'paste-code',
        login: current.login,
        code: current.code,
        error: String(e),
      };
    }
  }

  async function cancelPasteCode() {
    if (step.kind === 'paste-code') {
      // Best-effort: consume the pending state so it doesn't linger.
      try {
        await invoke('cancel_login', { stateToken: step.login.state });
      } catch (_) {
        // Silently ignore — the server will expire the state TTL anyway.
      }
    }
    step = { kind: 'picker' };
  }

  // ── Bearer key flow ───────────────────────────────────────
  async function submitBearerKey() {
    if (step.kind !== 'bearer-form') return;
    const providerStep = step;
    if (!providerStep.key.trim()) {
      step = { ...providerStep, error: 'API key must not be empty' };
      return;
    }

    step = { ...providerStep, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      const fingerprint = await invoke<string>('set_provider_key', {
        baseDir,
        providerId: providerStep.provider.id,
        key: providerStep.key.trim(),
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `${providerStep.provider.name} key saved (${fingerprint}).`,
      };
    } catch (e) {
      step = { ...providerStep, submitting: false, error: String(e) };
    }
  }

  // ── Close behavior ────────────────────────────────────────
  async function handleClose() {
    onClose();
  }
</script>

{#if isOpen}
  <div
    class="backdrop"
    onclick={handleClose}
    onkeydown={(e) => {
      if (e.key === 'Escape') handleClose();
    }}
    role="button"
    tabindex="-1"
  >
    <div
      class="modal"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-account-title"
      tabindex="-1"
    >
      <header>
        <h2 id="add-account-title">Add Account</h2>
        <button class="close" onclick={handleClose} aria-label="Close">×</button>
      </header>

      <div class="body">
        {#if step.kind === 'picker'}
          <p class="lede">
            {#if isReauth}
              Re-authenticate slot #{reauthSlot}. Sign in again to refresh expired credentials.
            {:else}
              Pick a provider, then choose which account slot to bind it to.
            {/if}
          </p>

          <label class="slot-field">
            <span>Account slot</span>
            <input
              type="number"
              min="1"
              max="999"
              step="1"
              bind:value={chosenSlot}
              disabled={isReauth}
            />
            <span class="slot-hint">
              {#if slotError}
                <span class="slot-warn">{slotError}</span>
              {:else if isReauth}
                Re-auth mode — slot is locked
              {:else}
                Suggested: #{nextAccountId} (next free slot)
              {/if}
            </span>
          </label>

          {#if providersError}
            <div class="error-banner">Could not load providers: {providersError}</div>
          {/if}
          <div class="provider-grid">
            {#each providers as provider (provider.id)}
              <button
                class="provider-card"
                onclick={() => pickProvider(provider)}
                disabled={provider.auth_type === 'oauth' && slotError !== null}
                title={provider.auth_type === 'oauth' && slotError ? slotError : ''}
              >
                <div class="provider-name">{provider.name}</div>
                <div class="provider-meta">
                  {provider.auth_type === 'oauth' ? `Sign in with Anthropic → slot #${chosenSlot}` : 'Paste an API key'}
                </div>
                {#if provider.default_model}
                  <div class="provider-model">{provider.default_model}</div>
                {/if}
              </button>
            {/each}
          </div>
        {:else if step.kind === 'running-claude'}
          <p class="lede">
            Launching Claude Code to sign in to account #{step.account}…
          </p>
          <p class="hint">
            A browser window should open shortly. Complete the sign-in
            there — csq will pick up the credentials automatically when
            Claude Code finishes.
          </p>
          <p class="hint">
            If nothing happens after a minute, check whether the
            <code>claude</code> binary is installed and on your shell PATH.
          </p>
        {:else if step.kind === 'paste-code'}
          <p class="lede">
            Signing in to account #{step.login.account}…
          </p>
          <p class="hint">
            A browser window should open to Anthropic. Sign in, then
            copy the authorization code from the callback page and
            paste it below.
          </p>
          <p class="hint">
            If the browser didn't open, <a
              href={step.login.auth_url}
              target="_blank"
              rel="noopener noreferrer">open the sign-in URL manually</a
            >.
          </p>
          <label class="field">
            <span>Authorization code</span>
            <input
              type="text"
              bind:value={step.code}
              placeholder="Paste the code from Anthropic's page"
              autocomplete="off"
              spellcheck="false"
            />
          </label>
          {#if step.error}
            <div class="error-banner">{step.error}</div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={cancelPasteCode}>Cancel</button>
            <button
              class="primary"
              onclick={submitOAuthCode}
              disabled={!step.code.trim()}
            >
              Complete sign-in
            </button>
          </div>
        {:else if step.kind === 'exchanging'}
          <p class="lede">
            Exchanging the code for account #{step.account}…
          </p>
          <p class="hint">Talking to Anthropic. This usually takes a second.</p>
        {:else if step.kind === 'bearer-form'}
          <p class="lede">Paste your {step.provider.name} API key.</p>
          <label class="field">
            <span>API key</span>
            <input
              type="password"
              bind:value={step.key}
              placeholder="sk-…"
              disabled={step.submitting}
              autocomplete="off"
            />
          </label>
          {#if step.provider.default_base_url}
            <p class="hint">
              Using default endpoint: <code>{step.provider.default_base_url}</code>
            </p>
          {/if}
          {#if step.error}
            <div class="error-banner">{step.error}</div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Back</button>
            <button class="primary" onclick={submitBearerKey} disabled={step.submitting}>
              {step.submitting ? 'Saving…' : 'Save key'}
            </button>
          </div>
        {:else if step.kind === 'success'}
          <div class="success-banner">{step.message}</div>
          <div class="actions">
            <button class="primary" onclick={handleClose}>Done</button>
          </div>
        {:else if step.kind === 'error'}
          <div class="error-banner">{step.message}</div>
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Try again</button>
            <button class="danger" onclick={handleClose}>Close</button>
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
    cursor: default;
  }
  .modal {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: min(480px, 90vw);
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
    line-height: 1;
    cursor: pointer;
    padding: 0 0.25rem;
  }
  .close:hover {
    color: var(--text-primary);
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
  .provider-grid {
    display: grid;
    gap: 0.5rem;
  }
  .provider-card {
    text-align: left;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem;
    cursor: pointer;
    color: inherit;
    font: inherit;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    transition: border-color 0.15s;
  }
  .provider-card:hover:not(:disabled) {
    border-color: var(--accent);
  }
  .provider-card:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .slot-field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin: 0 0 0.85rem 0;
  }
  .slot-field > span:first-child {
    font-size: 0.78rem;
    color: var(--text-secondary);
  }
  .slot-field input {
    padding: 0.4rem 0.55rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: inherit;
    font: inherit;
    font-size: 0.9rem;
    font-family: ui-monospace, monospace;
    width: 6rem;
  }
  .slot-field input:focus {
    outline: 2px solid var(--accent);
    outline-offset: -1px;
  }
  .slot-hint {
    font-size: 0.72rem;
    color: var(--text-secondary);
  }
  .slot-warn {
    color: var(--red);
  }
  .provider-name {
    font-weight: 600;
    font-size: 0.95rem;
  }
  .provider-meta {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .provider-model {
    font-size: 0.75rem;
    color: var(--text-secondary);
    font-family: ui-monospace, monospace;
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
  .field input {
    padding: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: inherit;
    font: inherit;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
  }
  .field input:focus {
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
  .actions button.primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
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

  .url-box {
    width: 100%;
    padding: 0.5rem;
    margin: 0.35rem 0;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: inherit;
    font: inherit;
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    resize: vertical;
    word-break: break-all;
  }
</style>
