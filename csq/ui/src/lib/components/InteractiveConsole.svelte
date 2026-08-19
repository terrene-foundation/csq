<script lang="ts">
  // ── Interactive per-turn enforcement console (an internal ticket) ──────────────────
  //
  // Operator-facing surface for the M-IC governed-turn hold/override flow.
  // The daemon owns every enforcement decision; this renderer ONLY relays the
  // operator's input (submit / override-with-justification / abandon) and
  // displays the daemon's redacted state verdict (R1-S7 — the decision
  // originates in the daemon, never here).
  //
  // Lifecycle: the operator clicks "Open session" → the daemon mints a session
  // key (echoed on every later call) → the operator submits a turn → the daemon
  // returns `complete` (passed governance) or `blocked` (held). On `blocked` the
  // operator authorizes an override (recording a signed justification) or
  // abandons. Closing the panel closes the daemon session.
  //
  // This surface is enterprise-only and ships INERT behind the §10.5 activation
  // gate: until an operator opens go-live, every daemon call returns
  // `interactive_unavailable` and the console shows the inactive notice.

  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";
  import { onDestroy } from "svelte";

  // The daemon's per-input / per-justification byte caps (mirrored for UX; the
  // daemon is the authoritative validator). Matches
  // csq_core::phase2b::interactive::{INPUT_MAX_BYTES, JUSTIFICATION_MAX_BYTES}.
  const INPUT_MAX_BYTES = 16 * 1024;
  const JUSTIFICATION_MAX_BYTES = 16 * 1024;

  // Forbidden control characters: any C0/C1/DEL control point EXCEPT ordinary
  // tab (0x09), newline (0x0A), and carriage return (0x0D) — mirrors the
  // daemon's `char::is_control()` rule.
  function hasForbiddenControl(s: string): boolean {
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      const isControl = c <= 0x1f || (c >= 0x7f && c <= 0x9f);
      if (isControl && c !== 0x09 && c !== 0x0a && c !== 0x0d) return true;
    }
    return false;
  }

  interface StateView {
    state: "idle" | "enforcing" | "blocked" | "complete";
    reason?: string;
    content?: unknown;
  }
  // The auth mode tag the daemon stamps on the session (an internal ticket): `subscription`
  // = degraded CLI-capture tier, `direct-api` = the paid-key Phase-2b moat.
  // Captured once at open; later turn responses carry only `StateView`.
  type AuthMode = "subscription" | "direct-api";
  interface OpenView {
    session_key: string;
    state: StateView;
    auth_mode?: AuthMode;
  }
  // One pickable subscription account (an internal ticket §FD1 escape hatch). The daemon
  // resolves the default (PR-3: lowest NON-capped account with credentials); the
  // operator can override it here. `seven_day_pct` is the account's last-polled
  // 7-day utilization (0-100) or null/absent when the daemon has no quota row.
  interface CandidateSlot {
    slot: number;
    label: string;
    seven_day_pct?: number | null;
  }
  interface SessionOptions {
    provider: string;
    candidate_slots: CandidateSlot[];
  }

  // Daemon fixed-vocabulary error tags → operator-facing text
  // (rules/tauri-commands.md MUST Rule 6: every named error maps to actionable
  // UI text).
  const ERROR_TEXT: Record<string, string> = {
    interactive_unavailable:
      "Interactive enforcement is not active on this daemon yet.",
    daemon_unreachable: "The daemon isn't running. Start it and try again.",
    session_not_found: "This session has expired — open a new one.",
    session_wrong_state: "That action isn't valid in the current state.",
    session_not_blocked: "There's no held turn to act on right now.",
    input_invalid:
      "Input must be non-empty, under 16 KB, and free of control characters.",
    justification_invalid:
      "Justification must be non-empty, under 16 KB, and free of control characters.",
    session_key_invalid: "The session key is malformed — open a new session.",
    session_config_invalid: "The enforcement configuration is invalid.",
    too_many_sessions: "Too many active sessions — close one and retry.",
    conversation_too_long:
      "This conversation hit its size limit — open a new session.",
    turn_operational_error: "The turn couldn't be processed — try again.",
    interactive_deserialize_error: "The daemon rejected the request payload.",
    interactive_bad_response: "The daemon returned an unexpected response.",
    interactive_request_failed: "The request to the daemon failed.",
  };

  function errorText(tag: string): string {
    return ERROR_TEXT[tag] ?? `Something went wrong (${tag}).`;
  }

  // A failed `invoke` rejects with the command's `Err(String)` tag in real
  // Tauri; normalize defensively in case an `Error` is thrown instead.
  function asTag(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // ── Reactive state ──────────────────────────────────────────────────
  let sessionKey = $state<string | null>(null);
  // Auth mode tag for the open session (an internal ticket). Captured at open, cleared on
  // close; the daemon omits it for untagged (mock/test) sessions → no badge.
  let authMode = $state<AuthMode | null>(null);
  let view = $state<StateView | null>(null);
  let inputText = $state("");
  let justification = $state("");
  let busy = $state(false);
  let errorTag = $state<string | null>(null);
  // Account picker (an internal ticket §FD1). `candidateSlots` is queried before open; when
  // ≥2 are available the operator sees a dropdown and `selectedSlot` is the
  // chosen account (`null` → daemon default). Empty list → no picker (single or
  // zero subscription account, or a direct-API/keyed provider).
  let candidateSlots = $state<CandidateSlot[]>([]);
  let selectedSlot = $state<number | null>(null);

  function byteLen(s: string): number {
    return new TextEncoder().encode(s).length;
  }

  function textInvalidReason(s: string, cap: number): string | null {
    if (s.length === 0) return "empty";
    if (byteLen(s) > cap) return "too long";
    if (hasForbiddenControl(s)) return "control characters";
    return null;
  }

  // Override is enabled only when the justification mirrors the daemon's rule —
  // this is UX, not the enforcement decision (which the daemon owns).
  let justificationError = $derived(
    textInvalidReason(justification, JUSTIFICATION_MAX_BYTES),
  );
  let inputError = $derived(textInvalidReason(inputText, INPUT_MAX_BYTES));
  let justificationBytes = $derived(byteLen(justification));

  async function baseDir(): Promise<string> {
    const home = await homeDir();
    return join(home, ".claude", "accounts");
  }

  // Query the pickable subscription accounts before the operator opens a session
  // (an internal ticket §FD1). Best-effort: if the gate is closed or the daemon is unreachable,
  // the picker stays empty and `openSession` falls back to the daemon default —
  // the inactive notice surfaces on the open attempt, not here.
  async function loadOptions() {
    try {
      const base = await baseDir();
      const opts = await invoke<SessionOptions>("interactive_options", {
        baseDir: base,
      });
      candidateSlots = opts.candidate_slots ?? [];
      // Default to the lowest NON-capped account (PR-3) — the SAME default the
      // daemon resolves (`pick_default_slot`) — so the dropdown reflects the
      // selection the session would actually open with.
      selectedSlot = pickDefaultSlot(candidateSlots);
    } catch {
      candidateSlots = [];
      selectedSlot = null;
    }
  }

  // 7-day utilization (0-100) at/above which an account is treated as capped and
  // is NOT chosen as the default (PR-3). Mirrors the daemon's
  // SEVEN_DAY_AVOID_THRESHOLD so UI default == daemon default.
  const SEVEN_DAY_AVOID_THRESHOLD = 95;

  // Mirror of the daemon's `pick_default_slot`: the lowest candidate whose 7-day
  // utilization is below the avoid threshold; an account with no quota row
  // (null/undefined) is pickable (absence ≠ capped); if every candidate is
  // capped, fall back to the lowest so the operator is never stranded.
  // `cands` is lowest-first (the daemon sorts it).
  function pickDefaultSlot(cands: CandidateSlot[]): number | null {
    if (cands.length === 0) return null;
    const healthy = cands.find(
      (c) => c.seven_day_pct == null || c.seven_day_pct < SEVEN_DAY_AVOID_THRESHOLD,
    );
    return (healthy ?? cands[0]).slot;
  }

  // Operator-facing option label: "email (slot N)" plus the 7-day utilization
  // when known — e.g. "tabula.rasa (slot 5) · 7d 31%". Omits the quota suffix
  // when the daemon has no quota row for the slot.
  function slotLabel(cand: CandidateSlot): string {
    const base = `${cand.label} (slot ${cand.slot})`;
    return cand.seven_day_pct == null
      ? base
      : `${base} · 7d ${Math.round(cand.seven_day_pct)}%`;
  }

  // Load the picker options once on mount. The body reads nothing reactive, so
  // this effect runs a single time (svelte-patterns.md Rule 5: no self-invalidation
  // — it writes candidateSlots/selectedSlot but never reads them here).
  $effect(() => {
    void loadOptions();
  });

  async function openSession() {
    busy = true;
    errorTag = null;
    try {
      const base = await baseDir();
      const res = await invoke<OpenView>("interactive_open", {
        baseDir: base,
        terminalLabel: "desktop",
        // `null` → daemon default (lowest-with-creds). A chosen slot is validated
        // daemon-side; an invalid pick returns `session_config_invalid`.
        slot: selectedSlot,
      });
      sessionKey = res.session_key;
      authMode = res.auth_mode ?? null;
      view = res.state;
    } catch (e) {
      errorTag = asTag(e);
    } finally {
      busy = false;
    }
  }

  async function submitTurn() {
    if (!sessionKey || inputError) return;
    busy = true;
    errorTag = null;
    try {
      const base = await baseDir();
      view = await invoke<StateView>("interactive_submit", {
        baseDir: base,
        sessionKey,
        input: inputText,
      });
      inputText = "";
    } catch (e) {
      errorTag = asTag(e);
    } finally {
      busy = false;
    }
  }

  async function authorizeOverride() {
    if (!sessionKey || justificationError) return;
    busy = true;
    errorTag = null;
    try {
      const base = await baseDir();
      view = await invoke<StateView>("interactive_override", {
        baseDir: base,
        sessionKey,
        justification,
      });
      justification = "";
    } catch (e) {
      errorTag = asTag(e);
    } finally {
      busy = false;
    }
  }

  async function abandonTurn() {
    if (!sessionKey) return;
    busy = true;
    errorTag = null;
    try {
      const base = await baseDir();
      view = await invoke<StateView>("interactive_abandon", {
        baseDir: base,
        sessionKey,
      });
      justification = "";
    } catch (e) {
      errorTag = asTag(e);
    } finally {
      busy = false;
    }
  }

  async function closeSession() {
    // Don't tear down a session while another action's IPC is in flight — the
    // UI button is already `disabled={busy}`, this guards any programmatic call.
    if (busy) return;
    const key = sessionKey;
    sessionKey = null;
    authMode = null;
    view = null;
    inputText = "";
    justification = "";
    errorTag = null;
    if (!key) return;
    try {
      const base = await baseDir();
      await invoke<StateView>("interactive_close", { baseDir: base, sessionKey: key });
    } catch {
      // Best-effort: the daemon reaps dead-PID sessions regardless.
    }
  }

  // Close the daemon session if the panel is torn down mid-session.
  onDestroy(() => {
    const key = sessionKey;
    if (!key) return;
    baseDir()
      .then((base) =>
        invoke<StateView>("interactive_close", { baseDir: base, sessionKey: key }),
      )
      .catch(() => {});
  });

  function prettyContent(content: unknown): string {
    try {
      return JSON.stringify(content, null, 2);
    } catch {
      return String(content);
    }
  }
</script>

<div class="console" data-testid="interactive-console">
  <div class="head">
    <h2>Interactive Enforcement</h2>
    <div class="head-right">
      {#if authMode}
        <span
          class="auth-badge"
          class:direct={authMode === "direct-api"}
          data-testid="auth-mode-badge"
          title={authMode === "direct-api"
            ? "Direct provider API (paid key) — full capability"
            : "Subscription via the reference CLI — degraded tier"}
        >
          {authMode === "direct-api" ? "Direct API" : "Subscription"}
        </span>
      {/if}
      {#if sessionKey}
        <button class="link" onclick={closeSession} disabled={busy}>Close session</button>
      {/if}
    </div>
  </div>

  {#if errorTag}
    <p class="error" role="alert">{errorText(errorTag)}</p>
  {/if}

  {#if !sessionKey}
    <!-- No open session: offer to open one. -->
    <p class="hint">
      Open a governed session to submit a turn. The daemon holds any turn that
      fails governance so you can review and override or abandon it.
    </p>
    {#if candidateSlots.length > 1}
      <!-- an internal ticket §FD1 account picker: choose which subscription account runs this
           session when the default (lowest-numbered) is rate-limited. -->
      <div class="picker">
        <label for="account-select">Subscription account</label>
        <select
          id="account-select"
          data-testid="account-select"
          bind:value={selectedSlot}
          disabled={busy}
        >
          {#each candidateSlots as cand (cand.slot)}
            <option value={cand.slot}>{slotLabel(cand)}</option>
          {/each}
        </select>
      </div>
    {/if}
    <button class="primary" onclick={openSession} disabled={busy}>
      {busy ? "Opening…" : "Open session"}
    </button>
  {:else}
    <!-- State badge -->
    <div class="state-row">
      <span class="badge" class:blocked={view?.state === "blocked"} class:complete={view?.state === "complete"}>
        {view?.state ?? "idle"}
      </span>
    </div>

    {#if view?.state === "blocked"}
      <!-- Held turn: show the redacted reason + override / abandon. -->
      <div class="block">
        <p class="reason-label">Governance blocked this turn:</p>
        <p class="reason" data-testid="block-reason">{view.reason}</p>

        <label for="justification">Justification (required to override)</label>
        <textarea
          id="justification"
          data-testid="justification-input"
          bind:value={justification}
          rows="3"
          placeholder="Why are you authorizing this turn?"
          disabled={busy}
        ></textarea>
        <div class="counter" class:over={justificationBytes > JUSTIFICATION_MAX_BYTES}>
          {justificationBytes} / {JUSTIFICATION_MAX_BYTES} bytes
        </div>

        <div class="actions">
          <button
            class="primary"
            data-testid="override-btn"
            onclick={authorizeOverride}
            disabled={busy || justificationError !== null}
            title={justificationError ? `Justification ${justificationError}` : "Authorize this turn"}
          >
            {busy ? "Working…" : "Override"}
          </button>
          <button
            class="danger"
            data-testid="abandon-btn"
            onclick={abandonTurn}
            disabled={busy}
            title="Discard this blocked turn without authorizing it"
            aria-label="Abandon blocked turn"
          >
            Abandon
          </button>
        </div>
      </div>
    {:else if view?.state === "complete"}
      <!-- Turn passed governance: show the redacted result + next turn. -->
      <div class="complete-block">
        <p class="reason-label">Turn completed and passed governance:</p>
        <pre class="content" data-testid="complete-content">{prettyContent(view.content)}</pre>
      </div>
      {@render turnInput()}
    {:else if view?.state === "enforcing"}
      <p class="hint" data-testid="enforcing">Running the turn through governance…</p>
    {:else}
      <!-- idle -->
      {@render turnInput()}
    {/if}
  {/if}
</div>

{#snippet turnInput()}
  <div class="turn">
    <label for="input">Submit a turn</label>
    <textarea
      id="input"
      data-testid="input-field"
      bind:value={inputText}
      rows="2"
      placeholder="Enter the input for this governed turn"
      disabled={busy}
    ></textarea>
    <button
      class="primary"
      data-testid="submit-btn"
      onclick={submitTurn}
      disabled={busy || inputError !== null}
      title={inputError ? `Input ${inputError}` : "Submit this turn"}
    >
      {busy ? "Working…" : "Submit"}
    </button>
  </div>
{/snippet}

<style>
  .console {
    max-width: 640px;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .head-right {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  /* an internal ticket auth-mode tag: subscription (degraded) is the neutral default;
     direct-api (the paid-key moat) is accented to signal full capability. */
  .auth-badge {
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.04em;
    padding: 0.12rem 0.45rem;
    border-radius: 999px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    white-space: nowrap;
  }
  .auth-badge.direct {
    color: var(--accent, #2d7dd2);
    border-color: var(--accent, #2d7dd2);
  }
  h2 {
    font-size: 1rem;
    margin: 0;
  }
  .hint {
    color: var(--text-secondary);
    font-size: 0.85rem;
    margin: 0;
  }
  /* an internal ticket §FD1 account picker */
  .picker {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .picker label {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .picker select {
    padding: 0.35rem 0.5rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    font-size: 0.85rem;
  }
  .error {
    color: var(--danger, #c0392b);
    font-size: 0.85rem;
    margin: 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-left: 3px solid var(--danger, #c0392b);
    border-radius: 3px;
  }
  .state-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .badge {
    text-transform: uppercase;
    font-size: 0.7rem;
    letter-spacing: 0.04em;
    padding: 0.15rem 0.5rem;
    border-radius: 999px;
    background: var(--bg-secondary);
    color: var(--text-secondary);
    border: 1px solid var(--border);
  }
  .badge.blocked {
    color: var(--danger, #c0392b);
    border-color: var(--danger, #c0392b);
  }
  .badge.complete {
    color: var(--success, #27ae60);
    border-color: var(--success, #27ae60);
  }
  .reason-label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin: 0.25rem 0 0.15rem;
  }
  .reason {
    font-size: 0.9rem;
    margin: 0 0 0.5rem;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .content {
    font-size: 0.8rem;
    margin: 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow-x: auto;
    max-height: 240px;
  }
  label {
    display: block;
    font-size: 0.8rem;
    color: var(--text-secondary);
    margin-bottom: 0.2rem;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    font: inherit;
    font-size: 0.85rem;
    padding: 0.45rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    resize: vertical;
  }
  .counter {
    font-size: 0.72rem;
    color: var(--text-secondary);
    text-align: right;
    margin-top: 0.15rem;
  }
  .counter.over {
    color: var(--danger, #c0392b);
  }
  .actions,
  .turn {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin-top: 0.4rem;
  }
  .turn {
    flex-direction: column;
    align-items: stretch;
  }
  button {
    font: inherit;
    font-size: 0.85rem;
    padding: 0.4rem 0.85rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    /* i-audit sweep — white-on-accent measured 2.21:1 in the default
       dark theme (WCAG AA needs 4.5:1). var(--bg-primary) flips per
       theme and clears AA on both (dark 7.93:1, light 6.20:1) — same
       fix as an internal ticket's AddAccountModal .actions button.primary. */
    color: var(--bg-primary);
  }
  button.danger {
    color: var(--danger, #c0392b);
    border-color: var(--danger, #c0392b);
    background: transparent;
  }
  button.link {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 0.2rem 0.3rem;
    font-size: 0.8rem;
    text-decoration: underline;
  }
</style>
