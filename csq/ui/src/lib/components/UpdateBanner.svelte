<script lang="ts">
  // The backend owns sign-in custody, verified installation, and restart on every platform.
  // This component observes progress; unmounting never cancels the owned operation.
  import { onMount } from "svelte";
  import { Channel, invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  // Must match `CachedUpdateInfo` in `csq/src/desktop/mod.rs`.
  // Kept inline because this component is the only consumer.
  interface UpdateInfo {
    version: string;
    current_version: string;
    release_url: string;
  }

  type InstallState =
    | { kind: "idle" }
    | { kind: "preparing" }
    | { kind: "waiting" }
    | { kind: "downloading"; downloaded: number; total: number | null }
    | { kind: "installing" }
    | { kind: "done" }
    | { kind: "error"; message: string; retryable?: boolean };

  let update = $state<UpdateInfo | null>(null);
  let dismissed = $state(false);
  let installState = $state<InstallState>({ kind: "idle" });
  interface PendingLogin {
    operation_id: string;
    provider: "claude" | "codex" | "native";
    account: number;
    native_id: string | null;
  }
  type UpdateProgress =
    | { event: "WaitingForSignIn" }
    | { event: "Started"; data: { contentLength: number | null } }
    | { event: "Progress"; data: { chunkLength: number } }
    | { event: "Finished" };
  let pendingLogins = $state<PendingLogin[]>([]);
  let pendingError = $state("");
  let endingOperation = $state<string | null>(null);

  // Status is an affordance only. The backend's durable lease owns admission.
  $effect(() => {
    if (installState.kind !== "waiting") return;
    let current = true;
    let inFlight = false;
    const refresh = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const pending = await invoke<PendingLogin[]>("get_pending_logins");
        if (current) pendingLogins = pending;
      } catch {
        if (current) pendingError = "Sign-in status unavailable. Open Accounts to end a sign-in, or wait.";
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = setInterval(() => { void refresh(); }, 1000);
    return () => { current = false; clearInterval(timer); };
  });

  function loginLabel(login: PendingLogin): string {
    return login.provider === "native" ? (login.native_id === "kimi-cli" ? "Kimi" : "Grok")
      : login.provider === "codex" ? "Codex" : "Claude";
  }
  async function endSignIn(login: PendingLogin) {
    endingOperation = login.operation_id;
    pendingError = "";
    try {
      const args = { operationId: login.operation_id, confirmed: true };
      const ended = login.provider === "native"
        ? await invoke<boolean>("cancel_native_login", { ...args, nativeId: login.native_id })
        : login.provider === "codex"
          ? await invoke<boolean>("cancel_codex_login", args)
          : await invoke<boolean>("cancel_claude_login", { ...args, account: login.account });
      // confirmed=true is intent only; the existing backend owns the one native dialog.
      if (!ended) pendingError = "Sign-in left running. The update will wait.";
    } catch {
      pendingError = "Could not end sign-in. Open Accounts to retry, or wait.";
    } finally {
      endingOperation = null;
    }
  }

  let mounted = false;
  let attempt = 0;
  let inFlight = false;
  let detachProgress: (() => void) | null = null;

  onMount(() => {
    mounted = true;
    const unlistenFns: UnlistenFn[] = [];
    invoke<UpdateInfo | null>("get_update_status")
      .then((cached) => {
        if (mounted && cached !== null) update = cached;
      })
      .catch(() => { /* The update event remains the primary delivery path. */ });
    listen<UpdateInfo>("update-available", (event) => {
      if (mounted) update = event.payload;
    }).then((fn) => {
      if (mounted) unlistenFns.push(fn);
      else fn();
    }).catch(() => { /* Cached status can still provide the banner. */ });
    return () => {
      mounted = false;
      attempt += 1;
      detachProgress?.();
      detachProgress = null;
      for (const fn of unlistenFns) fn();
    };
  });

  function downloadState(downloaded: number, total: number | null): InstallState {
    return {
      kind: "downloading",
      downloaded: Number.isFinite(downloaded) && downloaded >= 0 ? downloaded : 0,
      total: total !== null && Number.isFinite(total) && total > 0 ? total : null,
    };
  }

  async function installInApp(): Promise<void> {
    if (!mounted || inFlight) return;
    inFlight = true;
    const currentAttempt = ++attempt;
    const current = () => mounted && inFlight && attempt === currentAttempt;
    installState = { kind: "preparing" };
    pendingError = "";
    const onEvent = new Channel<UpdateProgress>();
    detachProgress = () => { onEvent.onmessage = () => {}; };
    onEvent.onmessage = (event) => {
      if (!current()) return;
      switch (event.event) {
        case "WaitingForSignIn": installState = { kind: "waiting" }; break;
        case "Started": installState = downloadState(0, event.data.contentLength); break;
        case "Progress":
          if (installState.kind === "downloading") {
            installState = downloadState(installState.downloaded + event.data.chunkLength, installState.total);
          }
          break;
        case "Finished": installState = { kind: "installing" }; break;
      }
    };
    try {
      // This command retains custody even when its renderer observer disappears.
      const installed = await invoke<boolean>("install_update_with_custody", { onEvent });
      if (!current()) return;
      if (installed === false) {
        installState = { kind: "idle" };
        await openReleasePage();
      } else if (installed === true) {
        installState = { kind: "done" };
      } else {
        installState = { kind: "error", message: "Could not complete the update. Try again or open the release page." };
      }
    } catch (e) {
      if (!current()) return;
      const tag = typeof e === "string" ? e : e instanceof Error ? e.message : "";
      const messages: Record<string, string> = {
        update_permission_denied: "This window cannot install updates. Open the release page to update manually.",
        update_community_channel_disabled: "Use the enterprise update channel for this edition.",
        update_configuration_refused: "Update configuration is unavailable. Use Manual to download the release.",
        update_check_failed: "Could not check for an update. Retry or use Manual.",
        update_download_or_signature_failed: "Could not download or verify the update. Retry or use Manual.",
        update_signature_invalid: "The update signature or signed version is invalid. Open the release page and report this release; do not install this download.",
        update_install_failed: "Could not install the update. Retry or use Manual.",
        update_custody_release_refused: "Sign-in admission remains closed. Finish pending sign-ins before restarting.",
        update_owner_completion_unverified: "Update completion could not be verified. Keep the app open and check pending sign-ins.",
        update_installer_completion_unverified: "Installer completion could not be verified. Keep the app open; sign-in admission remains closed.",
        desktop_update_unverified: "Update completion could not be verified; sign-in admission remains closed. Restart the app before signing in.",
        update_quiescence_lost: "Update custody could not be verified. Keep the app open and check pending sign-ins.",
        credential_write_gate_poisoned: "Sign-in custody could not be verified. Keep the app open and finish pending sign-ins.",
        credential_write_drain_superseded: "Another exit or update took priority. Finish pending sign-ins before retrying.",
        desktop_exit_intent_pending: "The app is already finishing sign-ins before exiting.",
        desktop_quiescence_conflict: "Another update or exit is already waiting for sign-ins. Keep the app open.",
        desktop_update_lease_superseded: "Another update or exit took priority. Keep the app open and finish pending sign-ins.",
      };
      installState = {
        kind: "error",
        message: messages[tag] ?? "Could not complete the update. Try again or open the release page.",
        retryable: tag !== "update_signature_invalid",
      };
    } finally {
      if (attempt === currentAttempt) {
        detachProgress?.();
        detachProgress = null;
        inFlight = false;
      }
    }
  }

  async function openReleasePage(): Promise<void> {
    const currentAttempt = attempt;
    try {
      await invoke("open_release_page");
    } catch {
      if (mounted && attempt === currentAttempt) installState = {
        kind: "error",
        message: "Could not open the release page. Check your browser and try again.",
        retryable: installState.kind !== "error" || installState.retryable !== false,
      };
    }
  }

  function progressPercent(s: InstallState): number | null {
    if (s.kind !== "downloading" || s.total === null || s.total === 0) {
      return null;
    }
    return Math.min(100, Math.max(0, Math.round((s.downloaded / s.total) * 100)));
  }
</script>

{#if update && !dismissed}
  <div class="update-banner" role="status" aria-live="polite">
    <span class="update-icon" aria-hidden="true">↑</span>
    <div class="update-text">
      <span class="update-title">
        {#if installState.kind === "preparing"}
          Preparing update…
        {:else if installState.kind === "waiting"}
          Sign-in in progress — update waiting
        {:else if installState.kind === "downloading"}
          Downloading v{update.version}…
          {#if progressPercent(installState) !== null}
            ({progressPercent(installState)}%)
          {/if}
        {:else if installState.kind === "installing"}
          Installing v{update.version}…
        {:else if installState.kind === "done"}
          Installed — restarting…
        {:else if installState.kind === "error"}
          Update failed
        {:else}
          Update available
        {/if}
      </span>
      <span class="update-versions">
        {#if installState.kind === "error"}
          {installState.message}
        {:else}
          v{update.current_version} → v{update.version}
        {/if}
      </span>
    </div>
    {#if installState.kind === "waiting"}
      <div class="update-waiting">
        <span>Finish sign-in, or choose End sign-in to continue the update.</span>
        {#each pendingLogins as login (login.operation_id)}
          <button type="button" class="update-action"
            disabled={endingOperation !== null}
            onclick={() => endSignIn(login)}>
            End {loginLabel(login)} sign-in for slot {login.account}
          </button>
        {/each}
        {#if pendingLogins.length === 0}<span>Finishing sign-in work…</span>{/if}
        {#if pendingError}<span role="alert">{pendingError}</span>{/if}
      </div>
    {:else if installState.kind === "idle"}
      <button
        type="button"
        class="update-action"
        onclick={installInApp}
        aria-label="Install update in-app"
      >
        Install
      </button>
      <button
        type="button"
        class="update-secondary"
        onclick={openReleasePage}
        aria-label="Open release page in browser"
      >
        Manual
      </button>
    {:else if installState.kind === "error"}
      {#if installState.retryable !== false}
        <button
          type="button"
          class="update-action"
          onclick={installInApp}
          aria-label="Retry in-app install"
        >
          Retry
        </button>
      {/if}
      <button
        type="button"
        class="update-secondary"
        onclick={openReleasePage}
        aria-label="Open release page in browser"
      >
        Manual
      </button>
    {/if}
    {#if installState.kind === "idle" || installState.kind === "error"}
      <button
        type="button"
        class="update-dismiss"
        onclick={() => (dismissed = true)}
        aria-label="Dismiss update notification"
      >
        ×
      </button>
    {/if}
  </div>
{/if}

<style>
  .update-banner {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.5rem 0.9rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border-bottom: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    font-size: 0.8rem;
    flex-shrink: 0;
  }
  .update-icon {
    color: var(--accent);
    font-weight: 600;
    font-size: 0.9rem;
  }
  .update-text {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    flex: 1;
    min-width: 0;
  }
  .update-title {
    font-weight: 500;
  }
  .update-versions {
    color: var(--text-secondary);
    font-size: 0.72rem;
    /* Long version strings (e.g. `2.0.0-alpha.13` → `2.1.0-rc.2`)
       wrap to the next line on narrow windows rather than truncate. */
    word-break: break-word;
  }
  .update-action {
    padding: 0.3rem 0.7rem;
    background: var(--accent);
    color: var(--bg-primary);
    border: none;
    border-radius: 3px;
    font: inherit;
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.15s;
    flex-shrink: 0;
  }
  .update-action:hover {
    opacity: 0.85;
  }
  .update-secondary {
    padding: 0.3rem 0.6rem;
    background: transparent;
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 3px;
    font: inherit;
    font-size: 0.72rem;
    cursor: pointer;
    flex-shrink: 0;
  }
  .update-secondary:hover {
    border-color: var(--accent);
  }
  .update-dismiss {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.05rem;
    line-height: 1;
    cursor: pointer;
    padding: 0 0.2rem;
    flex-shrink: 0;
  }
  .update-dismiss:hover {
    color: var(--text-primary);
  }
</style>
