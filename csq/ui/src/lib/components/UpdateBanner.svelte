<script lang="ts">
  // Update-available banner — shown above the tabs when the
  // background update check (fired 10s after app launch by the
  // Rust `setup` hook in `lib.rs`) finds a newer GitHub release.
  //
  // Two install paths coexist:
  //
  //   1. **In-app install** (primary) — `tauri-plugin-updater`
  //      downloads the signed bundle for this platform, verifies
  //      the minisign signature against the pubkey embedded in
  //      `tauri.conf.json`, swaps the `.app`/`.AppImage`/`.exe` in
  //      place, then relaunches. Available whenever a `latest.json`
  //      manifest exists in the release AND the running platform's
  //      `<os>-<arch>` key is present.
  //
  //   2. **Manual download** (fallback) — opens the GitHub release
  //      page in the default browser. Used when `check()` returns
  //      no match (e.g. Intel Mac or a platform we didn't publish
  //      an updater bundle for), or when the in-app install errors.
  //
  // Dismissal is session-scoped: the banner re-appears on the next
  // app launch until the user actually updates. We do not persist
  // dismissal to avoid the "silenced forever" failure mode where a
  // user dismisses once and never sees update notices again.
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { check, type Update } from "@tauri-apps/plugin-updater";
  import { relaunch } from "@tauri-apps/plugin-process";

  // Must match `CachedUpdateInfo` in `csq-desktop/src-tauri/src/lib.rs`.
  // Kept inline because this component is the only consumer.
  interface UpdateInfo {
    version: string;
    current_version: string;
    release_url: string;
  }

  type InstallState =
    | { kind: "idle" }
    | { kind: "downloading"; downloaded: number; total: number | null }
    | { kind: "installing" }
    | { kind: "done" }
    | { kind: "error"; message: string };

  let update = $state<UpdateInfo | null>(null);
  let dismissed = $state(false);
  let installState = $state<InstallState>({ kind: "idle" });
  // Plugin handle. Set on first user click so we only hit the
  // `latest.json` endpoint when the user actually wants to install —
  // the banner's initial visibility is driven by the existing
  // GitHub-API-backed `get_update_status` path, which is cheaper
  // and pre-dates the plugin wiring.
  let pluginUpdate: Update | null = null;

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

  async function installInApp() {
    installState = { kind: "downloading", downloaded: 0, total: null };
    try {
      // Plugin's check() hits the `endpoints` configured in
      // tauri.conf.json and returns a match for this platform, or
      // null if no matching `<os>-<arch>` key exists in latest.json.
      pluginUpdate = await check();
      if (!pluginUpdate) {
        // No updater bundle for our platform (arch mismatch,
        // missing manifest, or already up to date per the plugin's
        // internal version check). Fall back to the browser path.
        await openReleasePage();
        return;
      }

      await pluginUpdate.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            installState = {
              kind: "downloading",
              downloaded: 0,
              total: event.data.contentLength ?? null,
            };
            break;
          case "Progress":
            if (installState.kind === "downloading") {
              installState = {
                kind: "downloading",
                downloaded: installState.downloaded + event.data.chunkLength,
                total: installState.total,
              };
            }
            break;
          case "Finished":
            installState = { kind: "installing" };
            break;
        }
      });

      installState = { kind: "done" };
      await relaunch();
    } catch (e) {
      const msg = String((e as { message?: string })?.message ?? e);
      installState = { kind: "error", message: msg };
    }
  }

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

  function progressPercent(s: InstallState): number | null {
    if (s.kind !== "downloading" || s.total === null || s.total === 0) {
      return null;
    }
    return Math.min(100, Math.round((s.downloaded / s.total) * 100));
  }
</script>

{#if update && !dismissed}
  <div class="update-banner" role="status" aria-live="polite">
    <span class="update-icon" aria-hidden="true">↑</span>
    <div class="update-text">
      <span class="update-title">
        {#if installState.kind === "downloading"}
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
    {#if installState.kind === "idle"}
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
      <button
        type="button"
        class="update-action"
        onclick={installInApp}
        aria-label="Retry in-app install"
      >
        Retry
      </button>
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
