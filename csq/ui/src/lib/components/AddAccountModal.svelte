<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import { open as openDialog } from '@tauri-apps/plugin-dialog';
  import { homeDir, join } from '@tauri-apps/api/path';
  import { tick } from 'svelte';

  // Phase 2 of #389 — the Claude OAuth flow now shells out to
  // `claude auth login` via `start_claude_login_subprocess`. CC is
  // the reference OAuth client; csq invokes it and waits. The race
  // flow's loopback `redirect_uri` (`http://127.0.0.1:<port>/callback`)
  // had been rejected by Anthropic for the Claude Code client_id ever
  // since the IPv4 loopback was retired; CC itself uses IPv6 `[::1]`
  // plus a hosted-page JS bridge that we cannot replicate from this
  // process. See `feedback_delegate_to_reference_client`.

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

  // PR-C8 — Codex device-auth flow types.
  // an internal journal entry / round-3 redteam HIGH-A — `device_auth_prereq_*` fields
  // carry the ChatGPT Security Settings prerequisite so the modal can
  // render it BEFORE the device-auth subprocess starts. csq has no way
  // to detect whether the operator's "Device code authorization" toggle
  // is on (OpenAI exposes no API), so this is a heads-up banner.
  interface CodexStartLoginView {
    account: number;
    tos_required: boolean;
    /// "absent" | "present" | "unsupported" | "probe_failed"
    keychain: string;
    awaiting_keychain_decision: boolean;
    device_auth_prereq_message: string;
    device_auth_prereq_url: string;
  }
  interface CodexDeviceCode {
    user_code: string;
    verification_url: string;
  }

  // ── Local state ───────────────────────────────────────────
  //
  // Claude OAuth — subprocess shell-out flow (#389 Phase 2):
  //   1. `picker`                      — user picks a provider
  //   2. `claude-subprocess-running`   — `start_claude_login_subprocess`
  //                                      is awaiting `claude auth login`.
  //                                      CC owns the browser flow + JS
  //                                      bridge end-to-end; csq blocks
  //                                      until the subprocess exits.
  //   3. `success` / `error` / `login-in-progress`
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
    // ── Claude subprocess flow (default since #389 Phase 2) ────
    /// Round-1 redteam HIGH-1 — monotonic `invocationId` disambiguates
    /// rapid-re-open-same-slot timing. The success/error guards check
    /// the id so a stale Promise from a prior invoke can't fire
    /// onAccountAdded against the wrong invocation. Slot equality
    /// alone is insufficient when the user closes + re-opens the
    /// modal targeting the SAME slot before the first subprocess
    /// resolves.
    | { kind: 'claude-subprocess-running'; account: number; invocationId: number }
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
        /// "api-key" | "vertex" | "oauth" — currently active tab.
        /// Stage 2 of an internal journal entry added "oauth" (Code Assist OAuth).
        mode: 'api-key' | 'vertex' | 'oauth';
        /// AI Studio API key paste buffer.
        key: string;
        /// Vertex SA absolute path. Empty until the user picks one.
        vertexPath: string;
        residue: string | null;
        submitting: boolean;
        error: string | null;
      }
    | { kind: 'success'; message: string }
    /// UX-R2-03 / SEC-R2-01: dedicated recovery UI when the backend
    /// reports another csq process (CLI or desktop) holds the
    /// per-account login lock for the slot we tried to use. Distinct
    /// from `error` so the action button is "Close and retry"
    /// rather than the generic "Try again" — the user needs to
    /// resolve the OTHER login (wait or kill) before retrying.
    | {
        kind: 'login-in-progress';
        account: number;
        /// The full backend message (includes PID hint when
        /// available). Surfaced verbatim so the user has the
        /// concrete next action.
        message: string;
      }
    | {
        /// The selected provider's CLI binary is not installed. Surfaced as a
        /// friendly install prompt (with the exact install command + a copy
        /// button + a Recheck action) BEFORE launching a login that would
        /// otherwise fail mid-device-auth with a raw error.
        kind: 'cli-missing';
        account: number;
        provider: 'codex' | 'gemini';
        binary: string;
        installCmd: string;
      }
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

  // ── Claude OAuth — subprocess shell-out (#389 Phase 2) ────
  //
  // Delegates to CC's reference OAuth flow by spawning
  // `claude auth login` with `CLAUDE_CONFIG_DIR=<base>/config-<N>`.
  // CC owns the browser open + IPv6 loopback + hosted JS bridge
  // end-to-end. `start_claude_login_subprocess` blocks on the
  // subprocess exit, captures the credentials CC writes, persists
  // them canonically, and resolves the invoke Promise with
  // `{ account, email }`.
  //
  // The synchronous-from-frontend invoke shape means there are NO
  // intermediate events to subscribe to. The modal sits in
  // `claude-subprocess-running` while the Promise is pending and
  // transitions on resolve/reject.
  //
  // Cancellation: closing the modal mid-subprocess does NOT abort
  // the running `claude auth login` — the subprocess is owned by
  // CC, not csq, and the per-account login flock prevents another
  // attempt from racing. If the user finishes auth in the browser
  // after closing, credentials still land on disk (correct
  // behavior — they asked to log in). If they cancel in the browser,
  // CC exits non-zero and the Promise rejects (we just drop the
  // result because the modal is gone).

  /// Backend response shape for `start_claude_login_subprocess`.
  /// Mirrors the trailing `claude-login-success` event payload
  /// from the retired race flow.
  interface SubprocessLoginResponse {
    account: number;
    email: string;
  }

  /// Round-1 redteam HIGH-1 — monotonic counter for `startClaudeOAuth`
  /// invocations. Each call captures `++claudeOauthInvocations` and
  /// the success/error guards check both `step.account === account`
  /// AND `step.invocationId === myInvocation` so a late-resolving
  /// Promise from a prior call cannot mutate the modal's state when
  /// a fresh call for the SAME slot has since been started.
  let claudeOauthInvocations = 0;

  /// Round-1 redteam MEDIUM (security) — defense-in-depth client-side
  /// redaction of OAuth-shaped substrings that COULD appear in an
  /// error string surfaced from the backend. The backend wraps
  /// everything through `csq_core::error::redact_tokens` per
  /// `rules/security.md` MUST Rule 2; this mirror catches any future
  /// regression where a new error path skips the backend redactor.
  ///
  /// Patterns:
  /// - `sk-ant-…` Anthropic API key prefix (stable, catches every
  ///   length variant)
  /// - 65+ hex character runs (covers refresh-token-like blobs).
  ///   Round-2 redteam M1: threshold raised from 40 to 65 so common
  ///   debugging hashes survive — git SHA-1 commit hashes are 40 hex
  ///   chars; SHA-256 hex digests are 64 chars. Real Anthropic
  ///   refresh tokens are several hundred chars (the API returns
  ///   them base64url-encoded), so a 65-char floor still catches
  ///   everything we care about while letting `commit abcd1234…`
  ///   and `sha256=…` render readably in error banners.
  function redactClientSide(s: string): string {
    return s
      .replace(/sk-ant-[A-Za-z0-9_-]+/g, 'sk-ant-…')
      .replace(/[0-9a-fA-F]{65,}/g, '[REDACTED]');
  }

  async function startClaudeOAuth(account: number) {
    const myInvocation = ++claudeOauthInvocations;
    step = { kind: 'claude-subprocess-running', account, invocationId: myInvocation };

    let baseDir: string;
    try {
      baseDir = await getBaseDir();
    } catch (e) {
      if (
        step.kind === 'claude-subprocess-running' &&
        step.invocationId === myInvocation
      ) {
        step = { kind: 'error', message: `Could not resolve base dir: ${redactClientSide(String(e))}` };
      }
      return;
    }

    try {
      const response = await invoke<SubprocessLoginResponse>(
        'start_claude_login_subprocess',
        { baseDir, account },
      );
      // Late-resolve guard (H1): check both slot AND invocationId.
      // A bare slot check would let invocation #1 fire success
      // after the user closed and re-opened the modal for the same
      // slot (invocation #2). The invocation id is monotonic so it
      // never collides across calls.
      if (
        step.kind === 'claude-subprocess-running' &&
        step.invocationId === myInvocation
      ) {
        // svelte M2: set step BEFORE calling onAccountAdded so a
        // synchronous parent re-render sees the success state, not
        // a stale running state. Matches the ordering in the
        // bearer + keyless flows below.
        step = {
          kind: 'success',
          message: `Account ${response.account} added successfully (${response.email}).`,
        };
        onAccountAdded();
      }
    } catch (e) {
      // Round-1 redteam M1 (security + deep-analyst): the backend
      // now emits stable error-code prefixes (LOCK_HELD, LOCK_FAILED,
      // INVALID_INPUT, BASE_DIR_MISSING, CLAUDE_BIN_MISSING,
      // SPAWN_FAILED, CC_EXITED_NONZERO, NO_CREDENTIALS,
      // STALE_CREDENTIALS, CRED_WRITE_FAILED, MARKER_WRITE_FAILED,
      // FINALIZE_FAILED). STALE_CREDENTIALS currently falls through to
      // the generic error banner (verbatim message); add an explicit
      // arm here if a distinct 'retry login' hint is ever wanted.
      // The renderer branches on the tag rather than substring-
      // matching prose so a future backend wording tweak cannot
      // silently route a real contention into the generic error
      // banner. The legacy substring checks are retained for one
      // release of forward-compat so a downgrade-then-upgrade
      // dogfood install hits a recognized shape.
      const rawErr = String(e);
      const errStr = redactClientSide(rawErr);
      // Use `.includes()` not `.startsWith()` — when invoked from a
      // Tauri command, the error string is the raw payload; when
      // bubbled via `new Error(msg)` (test mocks, future indirection
      // through a higher-level wrapper), `String(e)` prefixes
      // "Error: " before the tag. The tag itself (`LOCK_HELD:` etc.)
      // is unique enough that substring is unambiguous.
      const isLockContention =
        errStr.includes('LOCK_HELD:') ||
        errStr.includes('LOCK_FAILED:') ||
        // Legacy wording (pre-Phase-2 backend) — keep one release.
        errStr.toLowerCase().includes('another login is in progress') ||
        errStr.toLowerCase().includes('login already in progress');
      if (
        step.kind === 'claude-subprocess-running' &&
        step.invocationId === myInvocation
      ) {
        step = isLockContention
          ? { kind: 'login-in-progress', account, message: errStr }
          : { kind: 'error', message: errStr };
      }
    }
  }

  /// UX-R2-03: clicked from the login-in-progress recovery UI.
  /// Invokes cancel on the race that's blocking us (we don't have
  /// its race token, but if the holder is the desktop app's own
  /// state, the user must manually cancel it from the OTHER modal
  /// — this button cannot cancel another process's lock). Closes
  /// the current modal so the user can retry.
  ///
  /// In practice the lock holder is almost always the CLI, in which
  /// case the only recovery is for the user to wait or kill the CLI
  /// process. The recovery button text reflects this: "Close and
  /// retry" rather than "Cancel previous login".
  async function dismissLoginInProgressAndRetry() {
    if (step.kind !== 'login-in-progress') return;
    const account = step.account;
    step = { kind: 'picker' };
    // Brief tick so Svelte renders the picker before we re-trigger.
    await tick();
    await startClaudeOAuth(account);
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
      const trimmedKey = providerStep.key.trim();
      // Two-step write: the global file (`settings-{provider}.json`)
      // feeds `csq listkeys`; the per-slot file
      // (`config-N/settings.json`) is what `discover_per_slot_third_party`
      // walks for the slot list. Skipping the second call leaves the
      // newly-added slot invisible to the dashboard — the originating
      // bug from 2026-05-08.
      const fingerprint = await invoke<string>('set_provider_key', {
        baseDir,
        providerId: providerStep.provider.id,
        key: trimmedKey,
      });
      await invoke('bind_keyed_provider', {
        baseDir,
        providerId: providerStep.provider.id,
        slot: chosenSlot,
        key: trimmedKey,
        model: null,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `${providerStep.provider.name} bound to slot #${chosenSlot} (${fingerprint}).`,
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

  // an internal journal entry finding 14: listener-registration race. If the user
  // closes the modal while `await listen()` is still resolving,
  // `codexDeviceCodeUnlisten` is null in `handleClose`, so there is
  // nothing to unregister — and when `listen()` finally resolves,
  // the live handler installs on a closed modal. This flag lets the
  // post-resolve guard detect "already closed" and unregister
  // immediately.
  let codexListenerClosed = false;

  // Round-3 redteam HIGH-A (an internal journal entry) — populated by `startCodexFlow`
  // from the `start_codex_login` Tauri response. Rendered in the
  // `codex-tos` and `codex-keychain-prompt` screens so the user sees
  // the ChatGPT Security Settings prerequisite BEFORE the device code
  // is generated. Cleared on modal close / picker reset.
  let codexPrereq = $state<{ message: string; url: string } | null>(null);

  // Copy-to-clipboard helper, shared by the device-auth code and the CLI
  // install command. `navigator.clipboard` is available in the Tauri WKWebView
  // under a user gesture (the button click); the copied text is also
  // user-selectable (CSS) so manual copy is the fallback if the async write is
  // rejected. `copiedText` holds the most-recently-copied string so each button
  // shows its own transient "Copied!" affordance without cross-triggering.
  let copiedText = $state<string | null>(null);
  async function copyText(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copiedText = text;
      setTimeout(() => {
        if (copiedText === text) copiedText = null;
      }, 1500);
    } catch {
      // Clipboard blocked (no gesture / permission) — the text stays
      // selectable, so the user can still copy it manually.
    }
  }

  // Provider CLI install commands, surfaced by the `cli-missing` prompt.
  const CLI_INSTALL: Record<'codex' | 'gemini', { binary: string; cmd: string }> = {
    codex: { binary: 'codex', cmd: 'npm install -g @openai/codex' },
    gemini: { binary: 'gemini', cmd: 'npm install -g @google/gemini-cli' },
  };

  // Pre-flight: is the provider's CLI installed? Returns true → proceed with the
  // login; false → the step has been switched to `cli-missing` (a friendly
  // install prompt) so the caller must abort. Fail-OPEN on the check itself: if
  // the pre-flight invoke errors, proceed and let the login surface its own
  // error rather than blocking on a broken probe.
  async function ensureCliInstalled(
    account: number,
    provider: 'codex' | 'gemini',
  ): Promise<boolean> {
    const { binary, cmd } = CLI_INSTALL[provider];
    let installed = true;
    try {
      // Fail-OPEN: only an explicit `false` means "missing". Any other value
      // (a rejected invoke, an unexpected shape) proceeds and lets the login
      // surface its own error rather than blocking on a broken pre-flight.
      installed = (await invoke<boolean>('provider_cli_installed', { binary })) !== false;
    } catch {
      installed = true;
    }
    if (!installed) {
      step = { kind: 'cli-missing', account, provider, binary, installCmd: cmd };
      return false;
    }
    return true;
  }

  // Recheck action for the `cli-missing` prompt: re-run the provider flow (which
  // re-runs the pre-flight) after the user has installed the CLI.
  async function retryAfterInstall() {
    if (step.kind !== 'cli-missing') return;
    const { account, provider } = step;
    if (provider === 'codex') await startCodexFlow(account);
    else await startGeminiFlow(account);
  }

  async function startCodexFlow(account: number, tosRetry: boolean = false) {
    if (!(await ensureCliInstalled(account, 'codex'))) return;
    try {
      const baseDir = await getBaseDir();
      const pre = await invoke<CodexStartLoginView>('start_codex_login', {
        baseDir,
        account,
      });
      // Round-3 redteam HIGH-A — capture the prerequisite for the
      // codex-tos / codex-keychain-prompt screens to render.
      codexPrereq = {
        message: pre.device_auth_prereq_message,
        url: pre.device_auth_prereq_url,
      };
      if (pre.tos_required) {
        if (tosRetry) {
          // an internal journal entry finding M2: the caller already tried to
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
      // an internal journal entry finding M2: pass `_tosRetry=true` so if the
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

    // an internal journal entry finding 14: if the modal was closed while
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
  // 1. `gemini-tos` — informational walkthrough panel. User clicks
  //    "Accept" → `acknowledge_gemini_tos` writes the marker, then
  //    we drop into `gemini-provision`. The OAuth-residue probe runs
  //    on entry so the user sees a neutral note when prior gemini-cli
  //    OAuth credentials exist on disk — the slot they're about to
  //    bind to API-key mode won't exercise those credentials. Earlier
  //    revisions framed this as ToS enforcement (ADR-G12) — retracted
  //    in an internal journal entry
  //
  // 2. `gemini-provision` — two-tab panel (AI Studio API key paste /
  //    Vertex service account JSON). Submit invokes the appropriate
  //    Tauri command (`gemini_provision_api_key` / `gemini_provision_vertex_sa`).
  async function startGeminiFlow(account: number) {
    if (!(await ensureCliInstalled(account, 'gemini'))) return;
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

  function setGeminiMode(mode: 'api-key' | 'vertex' | 'oauth') {
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

  /// Stage 2 of an internal journal entry: provisions a Gemini slot in Code Assist
  /// OAuth mode. Invokes `gemini_provision_oauth` which shells out to
  /// `gemini auth login` and waits for the browser-driven OAuth flow
  /// to finish (typically 30-120s). UI stays in `submitting` state for
  /// the entire wait — the renderer shows the "browser is opening"
  /// banner so the user knows what to expect.
  async function submitGeminiOauth() {
    if (step.kind !== 'gemini-provision' || step.mode !== 'oauth') return;
    const current = step;
    step = { ...current, submitting: true, error: null };
    try {
      const baseDir = await getBaseDir();
      await invoke('gemini_provision_oauth', {
        baseDir,
        slot: current.account,
      });
      onAccountAdded();
      step = {
        kind: 'success',
        message: `Gemini account ${current.account} provisioned (Code Assist OAuth).`,
      };
    } catch (e) {
      step = { ...current, submitting: false, error: String(e) };
    }
  }

  // ── Close behavior ────────────────────────────────────────
  async function handleClose() {
    // an internal journal entry finding 13 + 14: flag the listener as "closed"
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

    // Claude OAuth has no event subscription to tear down — the
    // subprocess flow is a single `invoke` whose Promise either
    // resolves (success/error) or stays pending until the
    // subprocess exits on its own. The `start_claude_login_subprocess`
    // command holds an `AccountLoginLock` flock; closing the modal
    // does NOT release it. CC owns the running browser flow and
    // will write credentials regardless. Re-opening the modal
    // before the previous subprocess exits surfaces the
    // login-in-progress recovery UI from the lock acquire path.

    // an internal journal entry finding 6: kill the running codex subprocess so
    // it does not orphan for the minutes-long device-auth window.
    // Best-effort — the backend treats a no-op (no child running)
    // as success. Runs BEFORE the step reset so the invoke is not
    // cancelled by a state change.
    try {
      await invoke('cancel_codex_login');
    } catch (_) {
      /* best-effort — ignore */
    }

    // an internal journal entry finding 13: reset `step` to 'picker' so a late
    // `codex-device-code` delivery (e.g. a Tauri event bus race)
    // does NOT satisfy the `step.kind === 'codex-running'` guard in
    // the listener closure and slam the modal back into the running
    // state after it was closed.
    step = { kind: 'picker' };
    // Round-4 redteam LOW-1 — clear codexPrereq so a stale value
    // from a prior Codex flow does not leak into the next modal open.
    // startCodexFlow re-populates from `start_codex_login`, so this
    // is defense-in-depth rather than a load-bearing reset.
    codexPrereq = null;

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
                  {#if provider.id === 'claude'}
                    Sign in with Anthropic → slot #{chosenSlot}
                  {:else if provider.id === 'codex'}
                    Sign in with ChatGPT → slot #{chosenSlot}
                  {:else if provider.id === 'gemini'}
                    AI Studio key or Vertex SA → slot #{chosenSlot}
                  {:else if provider.id === 'ollama'}
                    Local provider → slot #{chosenSlot} (no key)
                  {:else if provider.auth_type === 'bearer'}
                    Paste an API key
                  {:else if provider.auth_type === 'oauth'}
                    Sign in → slot #{chosenSlot}
                  {:else}
                    slot #{chosenSlot}
                  {/if}
                </div>
                {#if provider.default_model}
                  <div class="provider-model">{provider.default_model}</div>
                {/if}
              </button>
            {/each}
          </div>
        {:else if step.kind === 'claude-subprocess-running'}
          <p class="lede" data-testid="claude-subprocess-lede">
            <span
              class="liveness-spinner"
              data-testid="claude-subprocess-spinner"
              aria-hidden="true"
            ></span>
            Signing in to account #{step.account}…
          </p>
          <p class="hint">
            Launching Claude Code to handle the sign-in. A browser
            window should open shortly. Approve the sign-in there —
            csq will pick up the credentials when Claude Code
            finishes.
          </p>
          <p class="hint">
            If nothing happens after a minute, check whether the
            <code>claude</code> binary is installed and on your shell
            PATH. Closing this window does not cancel the running
            sign-in.
          </p>
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
          {#if codexPrereq}
            <div class="prereq-banner" data-testid="codex-device-auth-prereq">
              <p class="prereq-title">Before you continue:</p>
              <p class="prereq-body">{codexPrereq.message}</p>
              <p class="prereq-link">
                Open ChatGPT settings:
                <a href={codexPrereq.url} target="_blank" rel="noopener noreferrer">
                  {codexPrereq.url}
                </a>
              </p>
            </div>
          {/if}
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
          {#if codexPrereq}
            <div class="prereq-banner" data-testid="codex-device-auth-prereq">
              <p class="prereq-title">Before you continue:</p>
              <p class="prereq-body">{codexPrereq.message}</p>
              <p class="prereq-link">
                Open ChatGPT settings:
                <a href={codexPrereq.url} target="_blank" rel="noopener noreferrer">
                  {codexPrereq.url}
                </a>
              </p>
            </div>
          {/if}
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
          <!--
            Round-4 redteam HIGH-1 (an internal journal entry) — render the prereq
            in the codex-running screen too. CLI prints the banner
            unconditionally before the device-auth subprocess
            (csq-cli/src/commands/login.rs:580-593); desktop achieves
            parity here. Returning users (ToS already acknowledged + no
            keychain residue) bypass the pre-step screens and arrive
            here directly; first-time users land here right when the
            browser is opening to OpenAI's auth page — exactly when the
            "Enable device code authorization" reminder is most useful.
          -->
          {#if codexPrereq}
            <div class="prereq-banner" data-testid="codex-device-auth-prereq-running">
              <p class="prereq-title">If OpenAI rejects the code:</p>
              <p class="prereq-body">{codexPrereq.message}</p>
              <p class="prereq-link">
                Open ChatGPT settings:
                <a href={codexPrereq.url} target="_blank" rel="noopener noreferrer">
                  {codexPrereq.url}
                </a>
              </p>
            </div>
          {/if}
          {#if step.deviceCode}
            <p class="hint">
              Open the verification page and enter the code shown below:
            </p>
            <div class="device-code-panel">
              <div class="device-code-row">
                <div class="device-code">{step.deviceCode.user_code}</div>
                <button
                  type="button"
                  class="copy-code-btn"
                  data-testid="copy-device-code"
                  title="Copy code to clipboard"
                  aria-label="Copy code to clipboard"
                  onclick={() => copyText(step.kind === 'codex-running' && step.deviceCode ? step.deviceCode.user_code : '')}
                >{step.kind === 'codex-running' && step.deviceCode && copiedText === step.deviceCode.user_code ? '✓ Copied' : '⧉ Copy'}</button>
              </div>
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
            One-time informational disclosure shown before the first
            Gemini provisioning. Explains how csq wraps the official
            gemini-cli, what state csq writes to the slot's
            .gemini/settings.json, and how to switch auth modes.
            Earlier revisions framed this as a ToS-driven warning —
            that framing was retracted in an internal journal entry (the cited
            ToS targets reimplementations that bypass the official
            CLI; csq just spawns the official gemini binary as a
            subprocess).
          -->
          <p class="lede">Gemini provisioning — how csq uses gemini-cli</p>
          <p class="hint">
            csq spawns the official <code>gemini</code> CLI as a
            subprocess. Authentication uses whatever gemini-cli is
            configured for — AI Studio API key, Google Code Assist
            OAuth, or Vertex SA. csq does not reimplement Google's
            auth flows.
          </p>
          <p class="hint">
            For AI Studio API-key slots, csq writes the key to your
            platform-native vault (<strong>Keychain</strong> on macOS,
            <strong>Secret Service</strong> on Linux, <strong>DPAPI</strong>
            on Windows). Plaintext never touches the
            <code>config-{step.account}/</code> directory. csq also
            pre-seeds <code>security.auth.selectedType = "gemini-api-key"</code>
            in the slot's settings.json so gemini-cli doesn't
            interactively prompt for auth choice on first spawn.
          </p>
          {#if step.residue}
            <div class="warning-banner" data-testid="gemini-residue-warning">
              ℹ A prior <code>gemini-cli</code> OAuth session was detected at
              <code>{step.residue}</code>.
              For AI Studio API-key slots, gemini-cli will use the
              key csq provides via <code>GEMINI_API_KEY</code> env
              var (the OAuth credentials remain on disk but are not
              exercised by this slot).
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
              Informational note: the slot is being bound to API-key
              mode, so the OAuth credentials at .gemini/oauth_creds.json
              will not be exercised by this slot. Earlier revisions
              framed this as ToS enforcement — retracted in an internal journal entry
            -->
            <div class="hint" data-testid="gemini-residue-warning">
              ℹ <code>{step.residue}</code> was found. This slot will be
              bound to API-key mode, so gemini-cli will use the
              key you provide instead of those OAuth credentials.
              The file remains untouched — gemini-cli will use it
              again if you bind a separate slot to Code Assist OAuth.
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
              class:active={step.mode === 'oauth'}
              aria-selected={step.mode === 'oauth'}
              data-testid="gemini-tab-oauth"
              onclick={() => setGeminiMode('oauth')}
              disabled={step.submitting}
            >Code Assist (Sign in with Google)</button>
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
          {:else if step.mode === 'oauth'}
            <p class="hint">
              Sign in with your Google account to use a
              <strong>Gemini Code Assist</strong> subscription. csq
              shells out to <code>gemini auth login</code> — gemini-cli
              opens your browser and writes OAuth tokens to
              <code>~/.gemini/oauth_creds.json</code>. csq is
              read-only on those tokens (refresh stays gemini-cli's
              job; the daemon reads <code>access_token</code> to poll
              your Code Assist quota).
            </p>
            <p class="hint">
              On <code>csq run {step.account}</code> this slot leaves
              <code>security.auth.selectedType</code> unset so
              gemini-cli auto-discovers your Code Assist credentials.
            </p>
            {#if step.submitting}
              <div class="info-banner" data-testid="gemini-oauth-progress">
                Browser is opening — finish signing in to Google. This
                window will update once the OAuth flow completes.
              </div>
            {/if}
            {#if step.error}
              <div class="error-banner">{step.error}</div>
            {/if}
            <div class="actions">
              <button class="secondary" onclick={() => (step = { kind: 'picker' })} disabled={step.submitting}>Back</button>
              <button
                class="primary"
                onclick={submitGeminiOauth}
                disabled={step.submitting}
                data-testid="gemini-oauth-submit"
              >
                {step.submitting ? 'Waiting for browser…' : 'Sign in with Google'}
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
        {:else if step.kind === 'login-in-progress'}
          <!--
            UX-R2-03 / SEC-R2-01: dedicated recovery banner for
            "another csq process holds the per-account login lock".
            The action is "Close and retry" because the only resolution
            is for the user to wait for the OTHER login to finish (or
            kill it if they know the PID — the message includes the
            PID hint when the backend could read it). After they
            resolve the other login they re-enter via this modal.
          -->
          <div class="warning-banner" data-testid="login-in-progress-banner">
            ⚠ {step.message}
          </div>
          <p class="hint">
            Wait for the other sign-in to finish, then click <strong>Retry</strong>.
            If you started the other sign-in from a terminal and it's
            stuck, close that terminal first.
          </p>
          <div class="actions">
            <button class="secondary" onclick={handleClose}>Close</button>
            <button
              class="primary"
              data-testid="login-in-progress-retry"
              onclick={dismissLoginInProgressAndRetry}
            >Retry</button>
          </div>
        {:else if step.kind === 'cli-missing'}
          <div class="cli-missing" data-testid="cli-missing-prompt">
            <p class="lede">
              {step.provider === 'codex' ? 'codex-cli' : 'gemini-cli'} is not installed
            </p>
            <p class="hint">
              csq drives the official
              <code>{step.binary}</code>
              CLI to sign in to this account. Install it, then click
              <strong>Recheck</strong>. csq keeps the CLI up to date automatically
              once it's installed.
            </p>
            <div class="install-cmd-row">
              <code class="install-cmd">{step.installCmd}</code>
              <button
                type="button"
                class="copy-code-btn"
                data-testid="copy-install-cmd"
                title="Copy install command"
                aria-label="Copy install command"
                onclick={() =>
                  copyText(step.kind === 'cli-missing' ? step.installCmd : '')}
              >{step.kind === 'cli-missing' && copiedText === step.installCmd
                  ? '✓ Copied'
                  : '⧉ Copy'}</button>
            </div>
          </div>
          <div class="actions">
            <button class="primary" data-testid="cli-missing-recheck" onclick={retryAfterInstall}
              >Recheck</button
            >
            <button class="secondary" onclick={() => (step = { kind: 'picker' })}>Back</button>
            <button class="danger" onclick={handleClose}>Close</button>
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
  /* Round-3 redteam HIGH-A — Codex device-auth prerequisite banner. */
  .prereq-banner {
    margin: 0.75rem 0;
    padding: 0.75rem 0.9rem;
    background: var(--bg-tertiary);
    border-left: 3px solid var(--accent, #ffb454);
    border-radius: 4px;
  }
  .prereq-title {
    margin: 0 0 0.4rem 0;
    font-size: 0.85rem;
    font-weight: 600;
  }
  .prereq-body {
    margin: 0 0 0.4rem 0;
    font-size: 0.8rem;
    line-height: 1.4;
  }
  .prereq-link {
    margin: 0;
    font-size: 0.78rem;
  }
  /* Round-4 redteam LOW-2 — `--text-link` is not defined globally;
     use `--accent` (Foundation gold) so the banner matches the rest
     of the modal's visual language. */
  .prereq-link a {
    color: var(--accent);
    text-decoration: underline;
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
  /*
   * Info banner — neither error nor success. Used for the Gemini
   * Code Assist OAuth "browser is opening — finish signing in"
   * progress notice (a neutral informational state where the user
   * is waiting on an external flow). Subtle blue tone keeps the
   * message informational, not alarming.
   */
  .info-banner {
    background: rgba(80, 140, 220, 0.10);
    border: 1px solid rgba(80, 140, 220, 0.55);
    border-radius: 4px;
    padding: 0.55rem 0.7rem;
    color: var(--text-primary);
    font-size: 0.85rem;
    margin: 0.5rem 0;
  }
  /*
   * Round-1 redteam M1 (svelte) — liveness signal in the
   * `claude-subprocess-running` lede. The subprocess flow has no
   * progress events (CC owns the browser flow end-to-end), so the
   * spinner is the only visual cue that the modal is alive while
   * the subprocess runs. Pure CSS, no JS — won't stall on a
   * blocked render thread.
   */
  .liveness-spinner {
    display: inline-block;
    width: 0.75rem;
    height: 0.75rem;
    margin-right: 0.4rem;
    vertical-align: -0.05rem;
    border: 2px solid var(--accent, #ffb454);
    border-top-color: transparent;
    border-radius: 50%;
    animation: liveness-spin 0.9s linear infinite;
  }
  @keyframes liveness-spin {
    to {
      transform: rotate(360deg);
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .liveness-spinner {
      animation: none;
      border-top-color: var(--accent, #ffb454);
      opacity: 0.6;
    }
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
  .device-code-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }
  .device-code {
    font-family: ui-monospace, monospace;
    font-size: 1.4rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    color: var(--accent);
    /* Selectable so the user can manually copy even if the clipboard
       API write is rejected (no gesture / permission). */
    user-select: text;
    -webkit-user-select: text;
    cursor: text;
  }
  .copy-code-btn {
    font-size: 0.75rem;
    padding: 0.2rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary, transparent);
    color: var(--text-secondary);
    cursor: pointer;
    white-space: nowrap;
  }
  .copy-code-btn:hover {
    color: var(--accent);
    border-color: var(--accent);
  }
  .cli-missing {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin: 0.25rem 0 0.75rem 0;
  }
  .install-cmd-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.55rem 0.7rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  .install-cmd {
    flex: 1;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
    color: var(--text-primary, var(--accent));
    user-select: text;
    -webkit-user-select: text;
    word-break: break-all;
  }
  .device-code-url {
    font-size: 0.75rem;
    color: var(--text-secondary);
    word-break: break-all;
    text-align: center;
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
