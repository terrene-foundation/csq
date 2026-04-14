<script lang="ts">
  // Update-available banner — shown above the tabs when the
  // background update check (fired 10s after app launch by the
  // Rust `setup` hook in `lib.rs`) finds a newer GitHub release.
  //
  // The banner is passive: clicking "Download" opens the GitHub
  // release page in the user's default browser. In-app install is
  // intentionally absent — the Foundation's Ed25519 signing key is
  // still a placeholder, so `csq_core::update::download_and_apply`
  // would refuse. Showing an install button that always fails is
  // worse than linking out.
  //
  // Dismissal is session-scoped: the banner re-appears on the next
  // app launch until the user actually updates. We do not persist
  // dismissal to avoid the "silenced forever" failure mode where a
  // user dismisses once and never sees update notices again.
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  // Must match `CachedUpdateInfo` in `csq-desktop/src-tauri/src/lib.rs`.
  // Kept inline because this component is the only consumer.
  interface UpdateInfo {
    version: string;
    current_version: string;
    release_url: string;
  }

  let update = $state<UpdateInfo | null>(null);
  let dismissed = $state(false);

  onMount(() => {
    const unlistenFns: UnlistenFn[] = [];
    let mounted = true;

    // Case 1: check already ran and cached a result before the
    // component mounted (background thread fires at T+10s but user
    // may tab away and back after). Pull the cached value.
    invoke<UpdateInfo | null>("get_update_status")
      .then((cached) => {
        if (mounted && cached !== null) {
          update = cached;
        }
      })
      .catch(() => {
        // Lock poisoned or IPC error — silent. The event listener
        // below is the primary delivery path.
      });

    // Case 2: check runs while this component is mounted. The Rust
    // side emits `update-available` with the CachedUpdateInfo
    // payload; update the banner immediately.
    listen<UpdateInfo>("update-available", (event) => {
      if (mounted) {
        update = event.payload;
      }
    }).then((fn) => {
      if (mounted) {
        unlistenFns.push(fn);
      } else {
        fn();
      }
    });

    return () => {
      mounted = false;
      for (const fn of unlistenFns) {
        fn();
      }
    };
  });

  async function openReleasePage() {
    try {
      await invoke("open_release_page");
    } catch (e) {
      // The backend command fails only if the cache was cleared
      // between render and click — treat as dismiss so the user
      // isn't stuck looking at a dead button.
      dismissed = true;
      console.error("failed to open release page:", e);
    }
  }
</script>

{#if update && !dismissed}
  <div class="update-banner" role="status" aria-live="polite">
    <span class="update-icon" aria-hidden="true">↑</span>
    <div class="update-text">
      <span class="update-title">Update available</span>
      <span class="update-versions">
        v{update.current_version} → v{update.version}
      </span>
    </div>
    <button
      type="button"
      class="update-action"
      onclick={openReleasePage}
      aria-label="Open release page in browser"
    >
      Download
    </button>
    <button
      type="button"
      class="update-dismiss"
      onclick={() => (dismissed = true)}
      aria-label="Dismiss update notification"
    >
      ×
    </button>
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
