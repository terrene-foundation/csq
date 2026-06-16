<script lang="ts">
  // Global toast host component — mounts once in `App.svelte` and
  // renders every live entry from the module-scoped `toasts` store.
  //
  // Why a dedicated host:
  //   - Decouples emission (anywhere) from rendering (one place).
  //   - Absolute positioning: a per-row toast on each modal would
  //     reposition awkwardly on scroll.
  //   - aria-live="polite" on the container announces new messages
  //     to screen readers without interrupting focus.
  import { toasts, dismissToast, type Toast } from "../stores/toast.svelte";

  function colorFor(kind: Toast["kind"]): string {
    switch (kind) {
      case "success":
        return "var(--green)";
      case "error":
        return "var(--red)";
      case "info":
      default:
        return "var(--accent)";
    }
  }
</script>

<div class="toast-host" role="status" aria-live="polite" aria-atomic="false">
  {#each toasts as toast (toast.id)}
    <div
      class="toast"
      class:toast-success={toast.kind === "success"}
      class:toast-error={toast.kind === "error"}
      class:toast-info={toast.kind === "info"}
      style="border-left-color: {colorFor(toast.kind)}"
    >
      <span class="toast-message">{toast.message}</span>
      <button
        type="button"
        class="toast-close"
        aria-label="Dismiss notification"
        onclick={() => dismissToast(toast.id)}
      >
        ×
      </button>
    </div>
  {/each}
</div>

<style>
  .toast-host {
    position: fixed;
    right: 1rem;
    bottom: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    z-index: 200;
    /* Never intercept clicks on empty host area. */
    pointer-events: none;
    max-width: min(360px, calc(100vw - 2rem));
  }
  .toast {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.65rem 0.85rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-left-width: 4px;
    border-radius: 4px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    font-size: 0.85rem;
    /* Host is pointer-events:none; re-enable on each toast so the
       close button is clickable and the text is selectable. */
    pointer-events: auto;
  }
  .toast-message {
    flex: 1;
    /* Long daemon error messages wrap rather than overflow. */
    word-break: break-word;
  }
  .toast-close {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.1rem;
    line-height: 1;
    cursor: pointer;
    padding: 0 0.15rem;
    flex-shrink: 0;
  }
  .toast-close:hover {
    color: var(--text-primary);
  }
</style>
