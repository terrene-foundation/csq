// Toast store — runes-based reactive list of transient notifications.
//
// Built as a module-level `$state` array so any component can import
// `toasts` + `showToast` without needing a store context provider.
// The module is `.svelte.ts` so Svelte 5 runes (`$state`) compile in
// a plain TypeScript file.
//
// ### Why module-scoped runes, not a writable store
//
// The app has exactly one window and exactly one Toast root. A
// `writable` store adds subscription plumbing that every consumer has
// to manually unwrap; module-scoped `$state` reactivity propagates
// into any component that reads it through the Svelte 5 compiler.
//
// ### Auto-dismiss
//
// Each toast has its own timeout; dismissing manually is also
// supported. Timeouts are tracked so manual dismissal clears them
// (prevents a dismissed-then-timer-fires double-delete).

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

// Monotonic id generator. Module-level; not reset across the
// lifetime of the process.
let nextId = 1;

// Active timeouts keyed by toast id so `dismissToast(id)` can cancel
// the auto-dismiss timer before the toast is manually removed.
const timers = new Map<number, ReturnType<typeof setTimeout>>();

// Reactive list of live toasts. Exported for components to read.
export const toasts = $state<Toast[]>([]);

/** Default auto-dismiss window in milliseconds. */
export const DEFAULT_DURATION_MS = 5000;

/**
 * Push a toast onto the stack.
 *
 * Returns the id so callers can dismiss programmatically. If
 * `durationMs` is 0, the toast is sticky (no auto-dismiss).
 */
export function showToast(
  kind: ToastKind,
  message: string,
  durationMs: number = DEFAULT_DURATION_MS,
): number {
  const id = nextId++;
  toasts.push({ id, kind, message });
  if (durationMs > 0) {
    const handle = setTimeout(() => {
      dismissToast(id);
    }, durationMs);
    timers.set(id, handle);
  }
  return id;
}

/** Remove a toast by id and clear its pending timer. */
export function dismissToast(id: number): void {
  const t = timers.get(id);
  if (t !== undefined) {
    clearTimeout(t);
    timers.delete(id);
  }
  const idx = toasts.findIndex((toast) => toast.id === id);
  if (idx >= 0) {
    toasts.splice(idx, 1);
  }
}

/**
 * Clear every live toast and cancel every pending timer.
 *
 * Used by tests between runs; not called from the app itself.
 */
export function clearAllToasts(): void {
  for (const handle of timers.values()) {
    clearTimeout(handle);
  }
  timers.clear();
  toasts.splice(0, toasts.length);
}
