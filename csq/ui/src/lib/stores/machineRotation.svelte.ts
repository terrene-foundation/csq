// Machine-wide auto-swap setting, shared between the Settings toggle
// (`AutoRotateSetting`, the only writer) and every per-session control
// (`SessionRotationControl`, readers).
//
// A session set to "Follow machine" rotates iff the machine setting is on.
// Each control reads the machine setting from the backend once per mount, so
// without a shared value, flipping the toggle would leave those rows showing
// the old answer until the list re-mounted. `enabled` is `null` until the
// toggle has loaded or saved a value; readers fall back to what the backend
// returned for them. Only a value the backend confirmed is written here — a
// failed save never changes it.
//
// The module is `.svelte.ts` so `$state` compiles in plain TypeScript, the same
// shape as `toast.svelte.ts`.

export const machineRotation = $state<{ enabled: boolean | null }>({ enabled: null });

// Counts the values the Settings toggle confirmed (or cleared). A per-session
// read remembers the count when it starts and may only refresh the store if no
// such value landed meanwhile, so an older read can never overwrite a newer one.
let generation = 0;

/** Records the machine setting the backend last confirmed (or `null` = unknown). */
export function setMachineRotationEnabled(enabled: boolean | null): void {
  generation += 1;
  machineRotation.enabled = enabled;
}

/** The token a backend read passes back to [`refreshMachineRotation`]. */
export function machineRotationReadToken(): number {
  return generation;
}

/**
 * Records the machine setting a per-session backend read returned, unless the
 * Settings toggle confirmed or cleared a value since the read began. The row
 * read is fresher than a stored value (the CLI may have changed the file), so
 * it replaces it; a read that started earlier than a confirmed write does not.
 */
export function refreshMachineRotation(enabled: boolean, token: number): void {
  if (token !== generation) return;
  machineRotation.enabled = enabled;
}
