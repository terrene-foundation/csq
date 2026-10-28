<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  // HIGH-1 + MED-1: payload now carries `occurred_at` from the backend
  // clock (set in setup() at the authoritative recovery time). The
  // frontend no longer uses `new Date().toISOString()` as the recovery
  // timestamp — it uses `event.payload.occurred_at` instead.
  interface RecoveryPayload {
    reason: string;
    occurred_at: string;
  }

  // localStorage key that records when the user last dismissed this banner.
  // The value is an ISO-8601 timestamp string. On each new recovery event we
  // compare the dismissal timestamp against the recovery timestamp — if the
  // user already dismissed a recovery that fired at or after the current
  // recovery time, the banner stays hidden.
  const DISMISSAL_KEY = "csq-prefs-recovery-dismissed-at";

  let show = $state(false);
  let recoveryAt = $state<string | null>(null);

  function isDismissed(occurredAt: string): boolean {
    try {
      const dismissedAt = localStorage.getItem(DISMISSAL_KEY);
      return dismissedAt !== null && dismissedAt >= occurredAt;
    } catch {
      return false;
    }
  }

  function dismiss() {
    try {
      localStorage.setItem(
        DISMISSAL_KEY,
        recoveryAt ?? new Date().toISOString(),
      );
    } catch {
      // localStorage may fail in private-browsing / quota-exceeded contexts;
      // the banner will not persist dismissal across restarts in that case but
      // will close for the rest of the session.
    }
    show = false;
  }

  onMount(() => {
    const unlistenFns: UnlistenFn[] = [];
    let mounted = true;

    // HIGH-1 fix — cached-state path: catches the case where setup()
    // emitted `prefs-reset-to-defaults` BEFORE the WebView mounted and
    // the listen() call registered. Tauri's emit is fire-and-forget;
    // without this invoke, a cold-launch corruption event is always lost.
    //
    // MED-1 fix — `cached.occurred_at` is the authoritative backend clock
    // timestamp set by setup(). The frontend does NOT generate its own
    // timestamp here.
    invoke<RecoveryPayload | null>("consume_prefs_recovery")
      .then((cached) => {
        if (!mounted || cached === null) return;
        recoveryAt = cached.occurred_at;
        if (!isDismissed(cached.occurred_at)) show = true;
      })
      .catch(() => {
        // IPC unavailable (e.g. test harness or SSR); banner stays hidden.
      });

    // Event-listener path: catches future corruption events fired AFTER
    // mount (e.g. hot-reload, future manual app.emit). Defense in depth —
    // both paths must be present so neither is a single point of failure.
    //
    // MED-1: use `event.payload.occurred_at` (backend clock), with fallback
    // to `new Date().toISOString()` for forward-compat if a future emit
    // omits the field.
    listen<RecoveryPayload>("prefs-reset-to-defaults", (event) => {
      if (!mounted) return;
      const occurredAt =
        event.payload.occurred_at ?? new Date().toISOString();
      recoveryAt = occurredAt;
      if (!isDismissed(occurredAt)) show = true;
    })
      .then((fn) => {
        if (mounted) {
          unlistenFns.push(fn);
        } else {
          // Component unmounted between subscribe call and resolution;
          // release the subscription immediately so we don't leak.
          fn();
        }
      })
      .catch(() => {
        // Tauri IPC unavailable (e.g. test harness or SSR); banner stays hidden.
      });

    return () => {
      mounted = false;
      for (const fn of unlistenFns) fn();
    };
  });
</script>

{#if show}
  <div role="alert" class="banner">
    <strong>Preferences reset:</strong>
    Your desktop preferences file was corrupted and has been reset to defaults.
    If you previously set "Launch to tray" or "Hide Dock icon", you may need to
    re-apply those settings.
    <button
      type="button"
      class="dismiss"
      onclick={dismiss}
      aria-label="Dismiss preferences-reset notice"
    >
      Dismiss
    </button>
  </div>
{/if}

<style>
  .banner {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
    background: #fff3cd;
    color: #664d03;
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #ffe69c;
    font-size: 0.875rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .dismiss {
    margin-left: auto;
    padding: 0.25rem 0.75rem;
    background: transparent;
    border: 1px solid #664d03;
    border-radius: 4px;
    color: inherit;
    cursor: pointer;
    font-size: 0.8125rem;
  }
  .dismiss:hover {
    background: rgba(102, 77, 3, 0.1);
  }
</style>
