<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import { open as openDialog } from '@tauri-apps/plugin-dialog';
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

  // PR-C8 — Codex device-auth flow types.
  interface CodexStartLoginView {
    account: number;
    tos_required: boolean;
    /// "absent" | "present" | "unsupported" | "probe_failed"
    keychain: string;
    awaiting_keychain_decision: boolean;
  }
  interface CodexDeviceCode {
    user_code: string;
    verification_url: string;
  }

  // ── Local state ───────────────────────────────────────────
  //
  // Claude OAuth — parallel-race flow (default since v2.4):
  //   1. `picker`              — user picks a provider
  //   2. `claude-race-init`    — Tauri command starting; waiting for
  //                              the first event from the backend
  //   3. `claude-race-active`  — auto URL emitted; modal shows
  //                              "Browser opening…" and after 3 s
  //                              expands to show the manual URL
  //                              + paste input
  //   4. `claude-race-resolving` — one path captured a code; UI
  //                              freezes inputs and shows "Authorizing…"
  //   5. `claude-race-exchanging` — backend POSTing to the token
  //                              endpoint
  //   6. `success` / `error`
  //
  // Legacy Claude OAuth (kept for backward-compat / emergency rollback):
  //   - `running-claude` — `claude auth login` subprocess running
  //   - `paste-code`     — pre-race in-process paste-code flow
  //
  // Bearer-key flow (MiniMax, Z.AI):
  //   1. `picker`        — user picks a provider
  //   2. `bearer-form`   — user pastes an API key
  //
  // Keyless flow (Ollama):
  //   1. `picker`         — user picks Ollama
  //   2. `keyless-confirm` — info screen, Confirm binds slot
  type Step =
    | { kind: 'picker' }
    // ── Claude race flow (current default) ─────────────────────
    | { kind: 'claude-race-init'; account: number }
    | {
        kind: 'claude-race-active';
        account: number;
        /// URL the browser was asked to open. Held so the
        /// "Browser didn't open?" link can fall back to it.
        autoUrl: string;
        /// URL displayed for manual copy after the 3 s delay.
        /// `null` until the `claude-login-manual-url-ready` event
        /// fires — keeps the manual panel hidden during the
        /// initial "Browser opening…" window per CC's UX.
        manualUrl: string | null;
        /// Paste buffer for the manual code path.
        pasteCode: string;
        /// Inline error from a failed paste submission. Cleared
        /// when the user edits the input again.
        error: string | null;
        /// "" while idle; "Copied!" for ~2 s after the user clicks
        /// the manual-URL copy button. Drives the inline confirmation.
        copyState: '' | 'copied';
      }
    | {
        kind: 'claude-race-resolving';
        account: number;
        /// Which path won — "loopback" (browser callback fired)
        /// or "paste" (user submitted a code). Drives the
        /// "Browser sign-in completed" overlay text.
        via: 'loopback' | 'paste';
      }
    | { kind: 'claude-race-exchanging'; account: number }
    // ── Legacy Claude flows (preserved for fallback/rollback) ──
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
    | {
        kind: 'keyless-confirm';
        provider: ProviderView;
        /// Installed models from the provider (e.g. `ollama list`).
        /// Populated asynchronously on step entry; null while loading.
        availableModels: string[] | null;
        /// The model the user has selected. Empty string = catalog
        /// default (shown to the user as "(default: <model>)").
        selectedModel: string;
        submitting: boolean;
        error: string | null;
      }
    // ── Codex device-auth flow (PR-C8) ─────────────────────────
    | { kind: 'codex-tos'; account: number }
    | {
        kind: 'codex-keychain-prompt';
        account: number;
      }
    | {
        kind: 'codex-running';
        account: number;
        /// Populated by the `codex-device-code` event when the
        /// subprocess emits it; null until then.
        deviceCode: CodexDeviceCode | null;
      }
    // ── Gemini API-key / Vertex SA flow (PR-G5) ────────────────
    // FR-G-UI-01: ToS disclosure on first Gemini provisioning, then
    // a two-tab panel (AI Studio paste / Vertex SA file picker).
    // The residue path (when present) carries through both steps so
    // the inline warning fires on the provision panel even if the
    // user has already acknowledged the ToS in a prior session.
    | {
        kind: 'gemini-tos';
        account: number;
        /// Absolute path of `~/.gemini/oauth_creds.json` if present;
        /// null otherwise. Drives the inline OAuth-residue warning.
        residue: string | null;
      }
    | {
        kind: 'gemini-provision';
        account: number;
        /// "api-key" | "vertex" — currently active tab.
        mode: 'api-key' | 'vertex';
        /// AI Studio API key paste buffer.
        key: string;
        /// Vertex SA absolute path. Empty until the user picks one.
        vertexPath: string;
        residue: string | null;
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
  //
  // IMPORTANT: this effect MUST only track `isOpen`. Reading
  // `nextAccountId` here re-fires the effect when an account is
  // added (parent recomputes the next free slot), which previously
  // slammed the user back to `picker` the instant they saw the
  // success banner. Slot sync lives in the separate effect above.
  $effect(() => {
    if (isOpen) {
      step = { kind: 'picker' };
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
    // The slot picker gates every flow that writes `config-<N>/` —
    // OAuth (credentials) AND keyless (settings.json with a provider
    // env block). Only the global bearer-key flow is slot-free.
    if (provider.id === 'codex') {
      if (slotError) return;
      await startCodexFlow(chosenSlot);
      return;
    }
    if (provider.id === 'gemini') {
      if (slotError) return;
      await startGeminiFlow(chosenSlot);
      return;
    }
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
    } else if (provider.auth_type === 'none') {
      if (slotError) return;
      step = {
        kind: 'keyless-confirm',
        provider,
        availableModels: null,
        selectedModel: '',
        submitting: false,
        error: null,
      };
      // Kick off model discovery in the background. Empty result is
      // legitimate (Ollama not installed or no models pulled); the
      // UI falls back to the catalog default with a warning.
      if (provider.id === 'ollama') {
        try {
          const models = await invoke<string[]>('list_ollama_models');
          if (step.kind === 'keyless-confirm' && step.provider.id === provider.id) {
            step = {
              ...step,
              availableModels: models,
              selectedModel: models[0] ?? '',
            };
          }
        } catch {
          if (step.kind === 'keyless-confirm' && step.provider.id === provider.id) {
            step = { ...step, availableModels: [] };
          }
        }
      } else if (step.kind === 'keyless-confirm') {
        step = { ...step, availableModels: [] };
      }
    }
  }

  // ── Claude OAuth — parallel-race flow ─────────────────────
  //
  // Mirrors CC's reference UX (`ConsoleOAuthFlow.tsx`): one auth
  // URL, two convergent paths. Loopback callback OR paste code,
  // whichever resolves first.
  //
  // Lifecycle:
  //   1. Subscribe to `claude-login-*` events BEFORE invoking
  //      `start_claude_login_race`. Otherwise a fast loopback fires
  //      before `listen()` has registered the handler and the first
  //      event is dropped.
  //   2. Backend emits `claude-login-browser-opening` with the URL
  //      to open. The frontend opens it via `tauri-plugin-opener`.
  //   3. After 3 s the backend emits `claude-login-manual-url-ready`
  //      with the same URL. The modal expands to show a copy button
  //      and a paste input.
  //   4. Either path resolves first — backend emits
  //      `claude-login-resolved` with `via: "loopback" | "paste"`,
  //      then `claude-login-exchanging`, then either
  //      `claude-login-success` or `claude-login-error`.
  //   5. Cancel: closing the modal calls `cancel_race_login` which
  //      aborts the orchestrator task and emits
  //      `claude-login-cancelled`.

  /// All in-flight Tauri event subscriptions for the race. Cleared
  /// in `cleanupRaceListeners` on cancel / completion / unmount so
  /// late events from an aborted login cannot touch a closed modal
  /// (matches the journal-0021 pattern from the Codex flow).
  let raceUnlistens = $state<UnlistenFn[]>([]);
  /// Set BEFORE we invoke `start_claude_login_race` so `await listen`
  /// callbacks (which can complete after the modal is closed) can
  /// detect the closed state and unregister immediately.
  let raceListenersClosed = $state(false);

  /// Resets the inline copy-state flash after the timeout fires.
  /// Stored on the closure so a second click before the previous
  /// timeout fires resets the timer cleanly.
  let copyResetTimer: ReturnType<typeof setTimeout> | null = null;

  async function cleanupRaceListeners() {
    raceListenersClosed = true;
    for (const fn of raceUnlistens) {
      try { fn(); } catch (_) { /* best effort */ }
    }
    raceUnlistens = [];
    if (copyResetTimer !== null) {
      clearTimeout(copyResetTimer);
      copyResetTimer = null;
    }
  }

  async function startClaudeOAuth(account: number) {
    // Reset listener bookkeeping for a fresh race. Previous event
    // handles (if any) were already cleaned in `handleClose` —
    // this is defensive for the user clicking Try Again.
    await cleanupRaceListeners();
    raceListenersClosed = false;
    step = { kind: 'claude-race-init', account };

    // Subscribe to every `claude-login-*` event BEFORE invoking the
    // command. Order matters: a fast loopback callback can fire
    // before listen() resolves if we reverse it. Guard each handler
    // against `raceListenersClosed` so a late event from an aborted
    // race cannot touch a disposed modal.
    try {
      const browserOpening = await listen<{ auto_url: string }>(
        'claude-login-browser-opening',
        async (e) => {
          if (raceListenersClosed) return;
          if (step.kind !== 'claude-race-init' && step.kind !== 'claude-race-active') return;
          step = {
            kind: 'claude-race-active',
            account,
            autoUrl: e.payload.auto_url,
            manualUrl: null,
            pasteCode: '',
            error: null,
            copyState: '',
          };
          // Best-effort browser open. If the OS reports failure we
          // surface the manual URL immediately rather than waiting
          // the 3 s delay — the user already needs to act.
          try {
            await openUrl(e.payload.auto_url);
          } catch (_) {
            if (step.kind === 'claude-race-active') {
              step = { ...step, manualUrl: e.payload.auto_url };
            }
          }
        },
      );
      if (raceListenersClosed) { browserOpening(); return; }
      raceUnlistens = [...raceUnlistens, browserOpening];

      const manualUrlReady = await listen<{ manual_url: string }>(
        'claude-login-manual-url-ready',
        (e) => {
          if (raceListenersClosed) return;
          if (step.kind === 'claude-race-active') {
            step = { ...step, manualUrl: e.payload.manual_url };
          }
        },
      );
      if (raceListenersClosed) { manualUrlReady(); return; }
      raceUnlistens = [...raceUnlistens, manualUrlReady];

      const resolved = await listen<{ via: 'loopback' | 'paste' }>(
        'claude-login-resolved',
        (e) => {
          if (raceListenersClosed) return;
          if (
            step.kind === 'claude-race-active' ||
            step.kind === 'claude-race-init'
          ) {
            step = {
              kind: 'claude-race-resolving',
              account,
              via: e.payload.via,
            };
          }
        },
      );
      if (raceListenersClosed) { resolved(); return; }
      raceUnlistens = [...raceUnlistens, resolved];

      const exchanging = await listen<Record<string, never>>(
        'claude-login-exchanging',
        () => {
          if (raceListenersClosed) return;
          if (
            step.kind === 'claude-race-resolving' ||
            step.kind === 'claude-race-active'
          ) {
            step = { kind: 'claude-race-exchanging', account };
          }
        },
      );
      if (raceListenersClosed) { exchanging(); return; }
      raceUnlistens = [...raceUnlistens, exchanging];

      const success = await listen<{ email: string; account: number }>(
        'claude-login-success',
        async (e) => {
          if (raceListenersClosed) return;
          await cleanupRaceListeners();
          onAccountAdded();
          step = {
            kind: 'success',
            message: `Account ${e.payload.account} added successfully (${e.payload.email}).`,
          };
        },
      );
      if (raceListenersClosed) { success(); return; }
      raceUnlistens = [...raceUnlistens, success];

      const errorEvt = await listen<{ message: string; kind: string }>(
        'claude-login-error',
        async (e) => {
          if (raceListenersClosed) return;
          await cleanupRaceListeners();
          step = { kind: 'error', message: e.payload.message };
        },
      );
      if (raceListenersClosed) { errorEvt(); return; }
      raceUnlistens = [...raceUnlistens, errorEvt];

      const cancelled = await listen<Record<string, never>>(
        'claude-login-cancelled',
        async () => {
          if (raceListenersClosed) return;
          await cleanupRaceListeners();
          // Cancellation is a user-initiated outcome; drop straight
          // back to the picker rather than showing an error.
          step = { kind: 'picker' };
        },
      );
      if (raceListenersClosed) { cancelled(); return; }
      raceUnlistens = [...raceUnlistens, cancelled];
    } catch (e) {
      await cleanupRaceListeners();
      step = { kind: 'error', message: `Could not subscribe to login events: ${e}` };
      return;
    }

    // Now invoke the orchestrator. Returns immediately; the rest of
    // the flow plays out via the events above.
    try {
      const baseDir = await getBaseDir();
      await invoke('start_claude_login_race', { baseDir, account });
    } catch (e) {
      await cleanupRaceListeners();
      step = { kind: 'error', message: String(e) };
    }
  }

  async function submitRacePasteCode() {
    if (step.kind !== 'claude-race-active') return;
    const current = step;
    const code = current.pasteCode.trim();
    if (!code) {
      step = { ...current, error: 'Authorization code must not be empty' };
      return;
    }
    try {
      await invoke('submit_paste_code', { account: current.account, code });
      // Don't transition state here — wait for the
      // `claude-login-resolved` event so the via-flag is accurate.
    } catch (e) {
      step = { ...current, error: String(e) };
    }
  }

  /// Best-effort copy-to-clipboard for the manual URL. Uses the
  /// browser Clipboard API (available in Tauri's WebView). Falls
  /// back silently — the URL is also clickable, so a copy failure
  /// just means the user has to click rather than paste.
  async function copyManualUrl() {
    if (step.kind !== 'claude-race-active' || !step.manualUrl) return;
    try {
      await navigator.clipboard.writeText(step.manualUrl);
      step = { ...step, copyState: 'copied' };
      if (copyResetTimer !== null) clearTimeout(copyResetTimer);
      copyResetTimer = setTimeout(() => {
        if (step.kind === 'claude-race-active') {
          step = { ...step, copyState: '' };
        }
        copyResetTimer = null;
      }, 2000);
    } catch (_) {
      /* clipboard API blocked — ignore, user can still click the link */
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

  // ── Keyless flow (Ollama) ─────────────────────────────────
  async function submitKeyless() {
    if (step.kind !== 'keyless-confirm') return;
    const current = step;
    step = { ...current, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      // Pass the user's selection only when it differs from the
      // catalog default — an empty string means "accept default"
      // and the backend will fall back to `provider.default_model`.
      const model = current.selectedModel.trim();
      await invoke('bind_keyless_provider', {
        baseDir,
        providerId: current.provider.id,
        slot: chosenSlot,
        model: model.length > 0 ? model : null,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `${current.provider.name} bound to slot #${chosenSlot}.`,
      };
    } catch (e) {
      step = { ...current, submitting: false, error: String(e) };
    }
  }

  // ── Codex device-auth flow (PR-C8) ────────────────────────
  //
  // Four backend calls drive this flow:
  //
  // 1. `start_codex_login` — pre-check: returns tos_required +
  //    keychain state. No side effects beyond the probe.
  // 2. `acknowledge_codex_tos` — records the disclosure click.
  // 3. `complete_codex_login` — drives `codex login --device-auth`.
  //    Spawns the subprocess, emits `codex-device-code` events as
  //    soon as the verification URL + code are visible, blocks
  //    until the process exits, then relocates auth.json to
  //    `credentials/codex-<N>.json`.
  //
  // The `codex-device-code` event carries `{ user_code,
  // verification_url }`. We open the URL in the user's browser
  // AND show the code so they can type it on the OpenAI page.
  let codexDeviceCodeUnlisten: UnlistenFn | null = null;

  // Journal 0021 finding 14: listener-registration race. If the user
  // closes the modal while `await listen()` is still resolving,
  // `codexDeviceCodeUnlisten` is null in `handleClose`, so there is
  // nothing to unregister — and when `listen()` finally resolves,
  // the live handler installs on a closed modal. This flag lets the
  // post-resolve guard detect "already closed" and unregister
  // immediately.
  let codexListenerClosed = false;

  async function startCodexFlow(account: number, tosRetry: boolean = false) {
    try {
      const baseDir = await getBaseDir();
      const pre = await invoke<CodexStartLoginView>('start_codex_login', {
        baseDir,
        account,
      });
      if (pre.tos_required) {
        if (tosRetry) {
          // Journal 0021 finding M2: the caller already tried to
          // acknowledge once. A second `tos_required` means the
          // marker write didn't stick — probably a disk/permissions
          // problem. Surface an error instead of recursing
          // (pre-fix: `acknowledgeCodexTos` → `startCodexFlow` →
          // `acknowledgeCodexTos` → …infinite async recursion).
          step = {
            kind: 'error',
            message:
              'ToS marker did not persist after acknowledgement — check base-dir permissions and disk space',
          };
          return;
        }
        step = { kind: 'codex-tos', account };
        return;
      }
      if (pre.awaiting_keychain_decision) {
        step = { kind: 'codex-keychain-prompt', account };
        return;
      }
      await runCodexLogin(account, false);
    } catch (e) {
      step = { kind: 'error', message: `Codex pre-check failed: ${e}` };
    }
  }

  async function acknowledgeCodexTos() {
    if (step.kind !== 'codex-tos') return;
    const account = step.account;
    try {
      const baseDir = await getBaseDir();
      await invoke('acknowledge_codex_tos', { baseDir });
      // Re-run the pre-check so the keychain decision is surfaced
      // even if the user has acknowledged ToS before in a prior
      // session — a new keychain entry may have appeared since.
      //
      // Journal 0021 finding M2: pass `_tosRetry=true` so if the
      // backend still reports `tos_required` (stale read / race /
      // broken disk), we surface an error rather than recurse
      // indefinitely. One retry is enough — a second `tos_required`
      // after acknowledge means the marker write didn't stick.
      await startCodexFlow(account, /* tosRetry */ true);
    } catch (e) {
      step = { kind: 'error', message: `Could not record acknowledgement: ${e}` };
    }
  }

  async function resolveCodexKeychain(purgeKeychain: boolean) {
    if (step.kind !== 'codex-keychain-prompt') return;
    await runCodexLogin(step.account, purgeKeychain);
  }

  async function runCodexLogin(account: number, purgeKeychain: boolean) {
    step = { kind: 'codex-running', account, deviceCode: null };
    codexListenerClosed = false;

    // Subscribe BEFORE invoke so a fast backend cannot race the
    // event listener registration — otherwise the very first
    // device-code emission would be dropped. Matches the
    // pull_ollama_model pattern (R2 in ChangeModelModal).
    if (codexDeviceCodeUnlisten) {
      codexDeviceCodeUnlisten();
      codexDeviceCodeUnlisten = null;
    }
    const unlistenFn = await listen<CodexDeviceCode>(
      'codex-device-code',
      async (e) => {
        if (step.kind === 'codex-running' && step.account === account) {
          step = { ...step, deviceCode: e.payload };
          // Best-effort open the verification URL. User can still
          // copy the URL from the UI if the open fails (e.g.
          // default browser missing).
          try {
            await openUrl(e.payload.verification_url);
          } catch (_) {
            /* fall through — user can click the link in the UI */
          }
        }
      },
    );

    // Journal 0021 finding 14: if the modal was closed while
    // `await listen()` was resolving, `handleClose` has already
    // run but had null to unregister. Check the flag here —
    // if closed, drop the handler immediately so no late event
    // can touch a disposed modal.
    if (codexListenerClosed) {
      unlistenFn();
      return;
    }
    codexDeviceCodeUnlisten = unlistenFn;

    try {
      const baseDir = await getBaseDir();
      await invoke('complete_codex_login', {
        baseDir,
        account,
        purgeKeychain,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Codex account ${account} added successfully.`,
      };
    } catch (e) {
      step = { kind: 'error', message: String(e) };
    } finally {
      if (codexDeviceCodeUnlisten) {
        codexDeviceCodeUnlisten();
        codexDeviceCodeUnlisten = null;
      }
    }
  }

  // ── Gemini API-key / Vertex SA flow (PR-G5) ───────────────
  //
  // FR-G-UI-01: Disclosure-first, then provision. Two paths:
  //
  // 1. `gemini-tos` — disclosure panel. User clicks "Accept" →
  //    `acknowledge_gemini_tos` writes the marker, then we drop into
  //    `gemini-provision`. The OAuth-residue probe runs on entry so
  //    the user sees the warning even before submitting (the residue
  //    was the original reason ADR-G12 added the ToS guard).
  //
  // 2. `gemini-provision` — two-tab panel (AI Studio API key paste /
  //    Vertex service account JSON). Submit invokes the appropriate
  //    Tauri command (`gemini_provision_api_key` / `gemini_provision_vertex_sa`).
  async function startGeminiFlow(account: number) {
    try {
      const baseDir = await getBaseDir();
      // Probe ALWAYS — even if ToS was acknowledged in a prior
      // session, the residue path may have appeared since.
      let residue: string | null = null;
      try {
        residue = await invoke<string | null>('gemini_probe_tos_residue');
      } catch (_) {
        residue = null;
      }
      const acked = await invoke<boolean>('is_gemini_tos_acknowledged', { baseDir });
      if (!acked) {
        step = { kind: 'gemini-tos', account, residue };
        return;
      }
      step = {
        kind: 'gemini-provision',
        account,
        mode: 'api-key',
        key: '',
        vertexPath: '',
        residue,
        submitting: false,
        error: null,
      };
    } catch (e) {
      step = { kind: 'error', message: `Gemini pre-check failed: ${e}` };
    }
  }

  async function acknowledgeGeminiTos() {
    if (step.kind !== 'gemini-tos') return;
    const account = step.account;
    const residue = step.residue;
    try {
      const baseDir = await getBaseDir();
      await invoke('acknowledge_gemini_tos', { baseDir });
      step = {
        kind: 'gemini-provision',
        account,
        mode: 'api-key',
        key: '',
        vertexPath: '',
        residue,
        submitting: false,
        error: null,
      };
    } catch (e) {
      step = { kind: 'error', message: `Could not record acknowledgement: ${e}` };
    }
  }

  function setGeminiMode(mode: 'api-key' | 'vertex') {
    if (step.kind !== 'gemini-provision') return;
    step = { ...step, mode, error: null };
  }

  /// Opens the OS file picker scoped to JSON files. Tauri-plugin-dialog
  /// is gated by the `dialog:allow-open` capability — narrow enough
  /// that the renderer can't save / message / ask. Returns the
  /// absolute path the user picked, or null on cancel.
  async function pickVertexFile() {
    if (step.kind !== 'gemini-provision') return;
    try {
      const picked = await openDialog({
        multiple: false,
        directory: false,
        filters: [{ name: 'Vertex service account JSON', extensions: ['json'] }],
      });
      // openDialog returns string | string[] | null. We disabled
      // multiple so the array case is impossible — narrow defensively.
      const path = typeof picked === 'string' ? picked : null;
      if (path) {
        step = { ...step, vertexPath: path, error: null };
      }
    } catch (e) {
      step = { ...step, error: `File picker failed: ${e}` };
    }
  }

  async function submitGeminiApiKey() {
    if (step.kind !== 'gemini-provision' || step.mode !== 'api-key') return;
    const current = step;
    const key = current.key.trim();
    if (!key) {
      step = { ...current, error: 'API key must not be empty' };
      return;
    }
    step = { ...current, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      await invoke('gemini_provision_api_key', {
        baseDir,
        slot: current.account,
        key,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Gemini account ${current.account} provisioned (AI Studio API key).`,
      };
    } catch (e) {
      step = { ...current, submitting: false, error: String(e) };
    }
  }

  async function submitGeminiVertexSa() {
    if (step.kind !== 'gemini-provision' || step.mode !== 'vertex') return;
    const current = step;
    const path = current.vertexPath.trim();
    if (!path) {
      step = { ...current, error: 'Pick a Vertex service account JSON file' };
      return;
    }
    step = { ...current, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      const canonical = await invoke<string>('gemini_provision_vertex_sa', {
        baseDir,
        slot: current.account,
        saPath: path,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Gemini account ${current.account} provisioned (Vertex SA: ${canonical}).`,
      };
    } catch (e) {
      step = { ...current, submitting: false, error: String(e) };
    }
  }

  // ── Close behavior ────────────────────────────────────────
  async function handleClose() {
    // Journal 0021 finding 13 + 14: flag the listener as "closed"
    // BEFORE dropping the unlisten handle. If `await listen()` is
    // still in-flight at this moment (race), its post-resolve guard
    // in `runCodexLogin` will see `codexListenerClosed` and drop
    // the handler immediately on its side.
    codexListenerClosed = true;

    // Drop any in-flight Codex device-code subscription so a late
    // event from an aborted login cannot slam the modal back into
    // `codex-running` after the user closed it.
    if (codexDeviceCodeUnlisten) {
      codexDeviceCodeUnlisten();
      codexDeviceCodeUnlisten = null;
    }

    // Same hardening for the parallel-race Claude login: tear down
    // the event subscriptions BEFORE invoking `cancel_race_login`
    // so the cancellation event itself doesn't bounce the modal
    // back into a stale state.
    await cleanupRaceListeners();

    // Tell the backend to abort the orchestrator task. Best-effort:
    // a no-op cancel (no race in flight) is `Ok(())`, so the only
    // failure mode here is a transport error from a torn-down IPC
    // channel during shutdown — log only.
    try {
      await invoke('cancel_race_login');
    } catch (_) {
      /* best-effort — ignore */
    }

    // Journal 0021 finding 6: kill the running codex subprocess so
    // it does not orphan for the minutes-long device-auth window.
    // Best-effort — the backend treats a no-op (no child running)
    // as success. Runs BEFORE the step reset so the invoke is not
    // cancelled by a state change.
    try {
      await invoke('cancel_codex_login');
    } catch (_) {
      /* best-effort — ignore */
    }

    // Journal 0021 finding 13: reset `step` to 'picker' so a late
    // `codex-device-code` delivery (e.g. a Tauri event bus race)
    // does NOT satisfy the `step.kind === 'codex-running'` guard in
    // the listener closure and slam the modal back into the running
    // state after it was closed.
    step = { kind: 'picker' };

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
                disabled={(provider.auth_type === 'oauth' || provider.auth_type === 'none') && slotError !== null}
                title={(provider.auth_type === 'oauth' || provider.auth_type === 'none') && slotError ? slotError ?? '' : ''}
              >
                <div class="provider-name">{provider.name}</div>
                <div class="provider-meta">
                  {#if provider.auth_type === 'oauth'}
                    Sign in with Anthropic → slot #{chosenSlot}
                  {:else if provider.auth_type === 'none'}
                    Local provider → slot #{chosenSlot} (no key)
                  {:else}
                    Paste an API key
                  {/if}
                </div>
                {#if provider.default_model}
                  <div class="provider-model">{provider.default_model}</div>
                {/if}
              </button>
            {/each}
          </div>
        {:else if step.kind === 'claude-race-init'}
          <p class="lede" data-testid="race-init-lede">
            Starting sign-in for account #{step.account}…
          </p>
          <p class="hint">
            Opening Anthropic's authorize page in your browser.
          </p>
        {:else if step.kind === 'claude-race-active'}
          <p class="lede" data-testid="race-active-lede">
            Signing in to account #{step.account}…
          </p>
          <p class="hint">
            A browser window should be open to Anthropic. Approve the
            sign-in there — csq will pick up the credentials
            automatically.
          </p>
          {#if !step.manualUrl}
            <p class="hint">
              Browser didn't open?
              <button
                type="button"
                class="link-btn"
                data-testid="race-open-url"
                onclick={() => openUrl(step.kind === 'claude-race-active' ? step.autoUrl : '')}
              >Open the sign-in URL</button>
            </p>
          {/if}
          {#if step.manualUrl}
            <!--
              Manual URL panel appears 3 s after the browser open per
              CC's reference UX (`ConsoleOAuthFlow.tsx`). Most users on
              well-configured boxes never see it; the delay keeps
              clutter out of the common path.
            -->
            <div class="manual-url-panel" data-testid="race-manual-panel">
              <p class="hint">
                Or, after authorizing in your browser, paste the code
                Anthropic shows you here:
              </p>
              <div class="manual-url-row">
                <a
                  href={step.manualUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  class="manual-url-link"
                  data-testid="race-manual-url"
                >{step.manualUrl}</a>
                <button
                  type="button"
                  class="copy-btn"
                  data-testid="race-copy-url"
                  onclick={copyManualUrl}
                >{step.copyState === 'copied' ? 'Copied!' : 'Copy'}</button>
              </div>
              <label class="field">
                <span>Authorization code</span>
                <input
                  type="password"
                  bind:value={step.pasteCode}
                  oninput={() => {
                    if (step.kind === 'claude-race-active' && step.error) {
                      step = { ...step, error: null };
                    }
                  }}
                  placeholder="Paste the code from Anthropic's page"
                  autocomplete="off"
                  spellcheck="false"
                  data-testid="race-paste-input"
                />
              </label>
              {#if step.error}
                <div class="error-banner" data-testid="race-error">{step.error}</div>
              {/if}
              <div class="actions">
                <button
                  class="primary"
                  data-testid="race-submit-paste"
                  onclick={submitRacePasteCode}
                  disabled={!step.pasteCode.trim()}
                >Sign in</button>
              </div>
            </div>
          {/if}
        {:else if step.kind === 'claude-race-resolving'}
          <p class="lede" data-testid="race-resolving-lede">
            Authorizing account #{step.account}…
          </p>
          <p class="hint" data-testid="race-via">
            {step.via === 'loopback'
              ? 'Browser sign-in completed — finishing up.'
              : 'Code accepted — finishing up.'}
          </p>
        {:else if step.kind === 'claude-race-exchanging'}
          <p class="lede" data-testid="race-exchanging-lede">
            Exchanging credentials for account #{step.account}…
          </p>
          <p class="hint">Talking to Anthropic. This usually takes a second.</p>
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
        {:else if step.kind === 'keyless-confirm'}
          <p class="lede">
            Bind <strong>{step.provider.name}</strong> to slot #{chosenSlot}.
          </p>
          <p class="hint">
            {step.provider.name} is keyless — no API token needed. Claude Code
            will route every request on this slot to the endpoint below.
          </p>
          {#if step.provider.default_base_url}
            <p class="hint">
              Endpoint: <code>{step.provider.default_base_url}</code>
            </p>
          {/if}
          <label class="field">
            <span>Model</span>
            {#if step.availableModels === null}
              <p class="hint">Loading installed models…</p>
            {:else if step.availableModels.length === 0}
              <p class="hint">
                No {step.provider.name} models found locally. The binding will use
                <code>{step.provider.default_model}</code>; pull it with
                <code>ollama pull {step.provider.default_model}</code>
                before launching.
              </p>
            {:else}
              <select
                bind:value={step.selectedModel}
                disabled={step.submitting}
              >
                {#each step.availableModels as m}
                  <option value={m}>{m}</option>
                {/each}
              </select>
              <span class="hint">
                Installed via <code>ollama list</code>. Change later with
                <code>csq models switch ollama &lt;model&gt;</code>.
              </span>
            {/if}
          </label>
          {#if step.error}
            <div class="error-banner">{step.error}</div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>
              Back
            </button>
            <button class="primary" onclick={submitKeyless} disabled={step.submitting}>
              {step.submitting ? 'Binding…' : `Bind to slot #${chosenSlot}`}
            </button>
          </div>
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
        {:else if step.kind === 'codex-tos'}
          <p class="lede">Codex authentication — disclosure</p>
          <p class="hint">
            Signing in to slot #{step.account} consumes
            <strong>ChatGPT-subscription quota</strong> from your OpenAI account.
            Your Codex sessions run on OpenAI's infrastructure; csq only
            orchestrates the login and tracks quota locally.
          </p>
          <p class="hint">
            Surface-specific session state (sessions, history) does
            <strong>not transfer</strong> between Codex and Claude Code terminals —
            <code>csq swap</code> across surfaces starts a fresh session on the
            target surface.
          </p>
          <p class="hint">
            csq will pre-seed <code>config-{step.account}/config.toml</code> with
            <code>cli_auth_credentials_store = "file"</code> so the OAuth token
            lives on disk instead of the system keychain (spec 07 §7.3.3).
          </p>
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Cancel</button>
            <button
              class="primary"
              data-testid="codex-tos-accept"
              onclick={acknowledgeCodexTos}
            >
              I understand — continue
            </button>
          </div>
        {:else if step.kind === 'codex-keychain-prompt'}
          <p class="lede">Existing Codex keychain entry found</p>
          <p class="hint">
            macOS has a <code>com.openai.codex</code> keychain entry from a
            prior <code>codex login</code>. csq needs the file-backed auth store,
            so we'll purge it before proceeding.
          </p>
          <p class="hint">
            The credentials csq provisions for slot #{step.account} go to
            <code>credentials/codex-{step.account}.json</code> (file, 0o400),
            not the keychain.
          </p>
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Cancel</button>
            <button
              class="primary"
              onclick={() => resolveCodexKeychain(true)}
            >
              Purge and continue
            </button>
          </div>
        {:else if step.kind === 'codex-running'}
          <p class="lede">
            Signing in to Codex account #{step.account}…
          </p>
          {#if step.deviceCode}
            <p class="hint">
              Open the verification page and enter the code shown below:
            </p>
            <div class="device-code-panel">
              <div class="device-code">{step.deviceCode.user_code}</div>
              <a
                class="device-code-url"
                href={step.deviceCode.verification_url}
                target="_blank"
                rel="noopener noreferrer"
              >{step.deviceCode.verification_url}</a>
            </div>
            <p class="hint">
              The browser should already be open. If not, click the URL above.
            </p>
          {:else}
            <p class="hint">
              Launching <code>codex login --device-auth</code>… waiting for
              codex-cli to surface the device code.
            </p>
          {/if}
          <p class="hint">
            Once you finish the OpenAI sign-in page, this window will update
            automatically. Do not close it.
          </p>
        {:else if step.kind === 'gemini-tos'}
          <!--
            FR-G-UI-01: ToS disclosure — explicit acceptance is
            required before any Gemini provisioning. Google's ToS
            prohibits OAuth subscription rerouting through third-
            party tools; csq guards against accidental fall-through
            via the EP1–EP7 layered defence (see csq-core
            providers/gemini/tos_guard.rs). Disclosure text mirrors
            ADR-G01 / G12 wording.
          -->
          <p class="lede">Gemini provisioning — disclosure</p>
          <p class="hint">
            csq writes Gemini API keys to your platform-native vault
            (<strong>Keychain</strong> on macOS, <strong>Secret Service</strong> on Linux,
            <strong>DPAPI</strong> on Windows). Plaintext never touches the
            <code>config-{step.account}/</code> directory.
          </p>
          <p class="hint">
            Google's Gemini API Terms <strong>prohibit OAuth
            subscription rerouting</strong> through third-party tools. csq is
            an API-key-only client. Routing OAuth subscription quota
            through csq would be a violation that may trigger Google
            recertification on first offence and a permanent ban on
            second. csq actively defends against this with a 7-layer
            guard (see <code>tos_guard.rs</code>).
          </p>
          {#if step.residue}
            <div class="error-banner" data-testid="gemini-residue-warning">
              ⚠ A prior <code>gemini-cli</code> OAuth session was detected at
              <code>{step.residue}</code>.
              csq will <strong>not</strong> use it. The drift detector
              re-asserts API-key mode on every spawn — but if you want to
              avoid any risk of OAuth fall-through, delete that file
              before continuing.
            </div>
          {/if}
          <div class="actions">
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Cancel</button>
            <button
              class="primary"
              data-testid="gemini-tos-accept"
              onclick={acknowledgeGeminiTos}
            >
              I understand — continue
            </button>
          </div>
        {:else if step.kind === 'gemini-provision'}
          <p class="lede">Provision Gemini slot #{step.account}.</p>
          {#if step.residue}
            <!--
              Residue warning persists from the ToS step into the
              provision step so the user sees it again right before
              entering credentials. The drift detector handles the
              actual neutralisation; this banner is informational.
            -->
            <div class="warning-banner" data-testid="gemini-residue-warning">
              ⚠ <code>{step.residue}</code> was found. csq's drift detector
              re-asserts API-key mode on every spawn — Google ToS
              forbids OAuth subscription rerouting and csq does not
              use that file. Delete it manually if you prefer not
              to keep it on disk.
            </div>
          {/if}
          <div class="gemini-tabs" role="tablist" aria-label="Gemini auth mode">
            <button
              role="tab"
              class="gemini-tab"
              class:active={step.mode === 'api-key'}
              aria-selected={step.mode === 'api-key'}
              data-testid="gemini-tab-api-key"
              onclick={() => setGeminiMode('api-key')}
              disabled={step.submitting}
            >AI Studio API key</button>
            <button
              role="tab"
              class="gemini-tab"
              class:active={step.mode === 'vertex'}
              aria-selected={step.mode === 'vertex'}
              data-testid="gemini-tab-vertex"
              onclick={() => setGeminiMode('vertex')}
              disabled={step.submitting}
            >Vertex service account</button>
          </div>
          {#if step.mode === 'api-key'}
            <p class="hint">
              Paste an API key from
              <a
                href="https://aistudio.google.com/apikey"
                target="_blank"
                rel="noopener noreferrer"
              >Google AI Studio</a>.
              Keys start with <code>AIza</code>. The plaintext goes
              straight to your platform vault and is not echoed back over
              IPC.
            </p>
            <label class="field">
              <span>API key</span>
              <input
                type="password"
                bind:value={step.key}
                placeholder="AIza…"
                autocomplete="off"
                spellcheck="false"
                disabled={step.submitting}
                data-testid="gemini-api-key-input"
              />
            </label>
            {#if step.error}
              <div class="error-banner">{step.error}</div>
            {/if}
            <div class="actions">
              <button class="secondary" onclick={() => (step = { kind: 'picker' })} disabled={step.submitting}>Back</button>
              <button
                class="primary"
                onclick={submitGeminiApiKey}
                disabled={step.submitting || !step.key.trim()}
                data-testid="gemini-api-key-submit"
              >
                {step.submitting ? 'Provisioning…' : 'Provision'}
              </button>
            </div>
          {:else}
            <p class="hint">
              Pick a <strong>Vertex AI service account JSON</strong> file. csq
              stores the absolute path (not the contents) in the binding
              marker; gemini-cli reads the file at spawn time via
              <code>GOOGLE_APPLICATION_CREDENTIALS</code>.
            </p>
            <div class="vertex-pick">
              <button
                type="button"
                class="secondary"
                onclick={pickVertexFile}
                disabled={step.submitting}
                data-testid="gemini-vertex-pick"
              >Choose file…</button>
              <code class="vertex-path" data-testid="gemini-vertex-path">
                {step.vertexPath || '(no file selected)'}
              </code>
            </div>
            {#if step.error}
              <div class="error-banner">{step.error}</div>
            {/if}
            <div class="actions">
              <button class="secondary" onclick={() => (step = { kind: 'picker' })} disabled={step.submitting}>Back</button>
              <button
                class="primary"
                onclick={submitGeminiVertexSa}
                disabled={step.submitting || !step.vertexPath.trim()}
                data-testid="gemini-vertex-submit"
              >
                {step.submitting ? 'Provisioning…' : 'Provision'}
              </button>
            </div>
          {/if}
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
  .device-code-panel {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    align-items: center;
    padding: 0.85rem;
    margin: 0.5rem 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .device-code {
    font-family: ui-monospace, monospace;
    font-size: 1.4rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    color: var(--accent);
  }
  .device-code-url {
    font-size: 0.75rem;
    color: var(--text-secondary);
    word-break: break-all;
    text-align: center;
  }

  /* Parallel-race Claude OAuth — manual URL panel */
  .manual-url-panel {
    margin-top: 0.85rem;
    padding-top: 0.6rem;
    border-top: 1px dashed var(--border);
  }
  .manual-url-row {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    margin: 0.4rem 0;
  }
  .manual-url-link {
    flex: 1;
    font-size: 0.75rem;
    color: var(--text-secondary);
    background: var(--bg-tertiary);
    padding: 0.3rem 0.5rem;
    border-radius: 3px;
    word-break: break-all;
    min-height: 1.6rem;
    text-decoration: none;
  }
  .manual-url-link:hover {
    color: var(--accent);
  }
  .copy-btn {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.35rem 0.7rem;
    color: inherit;
    font: inherit;
    font-size: 0.8rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .copy-btn:hover {
    border-color: var(--accent);
  }
  .link-btn {
    background: transparent;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
    font-size: inherit;
    padding: 0;
    text-decoration: underline;
  }

  /* PR-G5 Gemini provision panel */
  .warning-banner {
    padding: 0.5rem 0.7rem;
    background: rgba(217, 119, 6, 0.08);
    border: 1px solid rgba(217, 119, 6, 0.4);
    border-radius: 4px;
    color: var(--orange, #d97706);
    font-size: 0.8rem;
    margin: 0.25rem 0;
  }
  .gemini-tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    margin: 0.25rem 0 0.6rem 0;
  }
  .gemini-tab {
    flex: 1;
    padding: 0.45rem 0.7rem;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-secondary);
    font: inherit;
    font-size: 0.85rem;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }
  .gemini-tab:hover:not(:disabled) {
    color: var(--text-primary);
  }
  .gemini-tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  .gemini-tab:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .vertex-pick {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.4rem 0;
  }
  .vertex-path {
    flex: 1;
    font-size: 0.75rem;
    color: var(--text-secondary);
    background: var(--bg-tertiary);
    padding: 0.3rem 0.5rem;
    border-radius: 3px;
    word-break: break-all;
    min-height: 1.6rem;
  }
</style>
