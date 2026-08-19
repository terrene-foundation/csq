<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { homeDir, join } from '@tauri-apps/api/path';
  import UsageBar from './UsageBar.svelte';
  import BillingLedger from './BillingLedger.svelte';
  import TokenBadge from './TokenBadge.svelte';
  import AddAccountModal from './AddAccountModal.svelte';
  import ChangeModelModal from './ChangeModelModal.svelte';

  interface AccountView {
    id: number;
    label: string;
    source: string;
    /// "claude-code" | "codex" | "gemini" | "kimi" | "grok" — the
    /// upstream CLI surface the slot spawns. PR-C6 added codex; PR-G5
    /// added gemini; an internal journal entry C5 added the native Kimi/Grok
    /// surfaces (self-authenticating vendor binaries, Design B —
    /// distinct from the 3P-bearer Kimi provider, which stays
    /// `surface="claude-code"`).
    /// Distinct from `source` (the credential *origin*): a 3P
    /// provider slot has `source="third_party"` but
    /// `surface="claude-code"`.
    /// Round-1-redteam-fix: tightened from `string` to a literal
    /// union so a missing-surface bug surfaces as a TS error rather
    /// than as a silently-missing badge. Origin: redteam round 1 M4
    /// (an internal journal entry).
    surface: 'claude-code' | 'codex' | 'gemini' | 'kimi' | 'grok';
    has_credentials: boolean;
    /// True when `quota.json` holds a row for this slot whose surface
    /// matches the slot's own dispatch shape (HIGH-1, an internal ticket redteam).
    /// `false` means no row has been polled yet — `five_hour_pct` /
    /// `seven_day_pct` are `0.0` as a serialization default, NOT a
    /// measured "0% used". Optional (backend always sends it; the `?`
    /// only lets older test fixtures omit it and default to the
    /// has-data rendering path).
    has_quota?: boolean;
    five_hour_pct: number;
    five_hour_resets_in: number | null;
    seven_day_pct: number;
    seven_day_resets_in: number | null;
    updated_at: number;
    token_status: string;
    expires_in_secs: number | null;
    /// Fixed-vocabulary tag from the most recent refresh failure,
    /// or null if the last refresh succeeded / no flag is set.
    /// Rendered next to the token status so "Expired" grows a
    /// "— invalid token" suffix when the refresh token is dead.
    last_refresh_error: string | null;
    /// Stable 3P provider id ("mm" | "zai" | "deepseek" | "ollama"),
    /// or null for first-party OAuth slots. Used to branch UI on
    /// provider type (e.g. only Ollama slots get a "Change model"
    /// button).
    provider_id: string | null;
    /// Billing-mode classification (Phase B of an internal journal entry).
    /// Drives the quota render: `subscription` shows 5h/7d bars,
    /// `api-key` shows "API-key billing" with no bars, `local`
    /// shows "Local provider — no billing". Renderers MUST branch
    /// on this — `provider_id` / `surface` / `source` are
    /// credential-origin fields, not user-visible-quota-shape.
    billing_mode: 'subscription' | 'api-key' | 'local';
    /// Phase B' (an internal journal entry D5) — catalog quota_kind:
    /// "utilization" | "counter" | "unknown" | "balance". `unknown` slots
    /// render the tokens-and-cost-over-time ledger view; `balance` slots
    /// render the formatted balance string from `balance_display`.
    quota_kind?: 'utilization' | 'counter' | 'unknown' | 'balance' | 'native';
    /// Formatted remaining balance for pay-per-token providers (e.g. DeepSeek).
    /// Present when `quota_kind === "balance"`. Format: "$196.42" (USD) or
    /// "196.42 CNY" (other currencies). Absent (null/undefined) for every
    /// non-balance slot.
    balance_display?: string | null;
    // ── PR-G5 — Gemini-specific quota fields ──────────────────
    // None on non-Gemini slots; populated by the daemon's NDJSON
    // event drain. The card renders these instead of the 5h/7d
    // UsageBar when surface === "gemini".
    /// Number of requests issued today, or null when no events
    /// have drained yet (renders "quota: n/a").
    gemini_counter_today?: number | null;
    /// ISO-8601 UTC timestamp when the active 429 retry window
    /// ends; null when no retry is active.
    gemini_rate_limit_reset_at?: string | null;
    /// Model the user pinned via the binding marker.
    gemini_selected_model?: string | null;
    /// Model Gemini actually served on the most recent response.
    gemini_effective_model?: string | null;
  }

  /// Formats `gemini_rate_limit_reset_at` (ISO-8601 UTC) into a
  /// human-readable countdown like "resets in 59m 58s". Returns the
  /// empty string when the reset is in the past or the input is
  /// malformed — the caller falls back to the counter view.
  function formatGeminiResetCountdown(iso: string | null | undefined): string {
    if (!iso) return '';
    const ms = Date.parse(iso);
    if (Number.isNaN(ms)) return '';
    const remaining = Math.max(0, Math.floor((ms - Date.now()) / 1000));
    if (remaining <= 0) return '';
    if (remaining < 60) return `resets in ${remaining}s`;
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    if (m < 60) return `resets in ${m}m ${s}s`;
    const h = Math.floor(m / 60);
    const mm = m % 60;
    return `resets in ${h}h ${mm}m`;
  }

  /// Maps the backend's fixed-vocabulary error tag to human text.
  /// Keeps the vocabulary stable on the backend while letting the
  /// UI phrase things idiomatically.
  function formatRefreshError(tag: string | null): string {
    if (!tag) return '';
    switch (tag) {
      case 'broker_token_invalid':
        return 'invalid token — re-login needed';
      case 'broker_refresh_failed':
        return 'refresh failed — check network or re-login';
      case 'broker_other':
        return 'recovery failed — re-login needed';
      case 'credential':
        return 'credential file error';
      case 'platform':
        return 'platform error';
      case 'oauth':
        return 'oauth error';
      case 'daemon':
        return 'daemon error';
      case 'config':
        return 'config error';
      default:
        return tag; // pass through unknown tags
    }
  }

  // ── Quota staleness (F1) ─────────────────────────────────
  //
  // Matches `csq-core/src/quota/status.rs::STALE_THRESHOLD_SECS` (3600s)
  // EXACTLY — per `account-terminal-separation.md` MUST Rule 4 (Anthropic
  // utilization is the sole source of truth) and this fix's brief, the
  // desktop card MUST reuse the CLI's canonical threshold rather than
  // introduce a second, divergent one; an internal ticket (`csq doctor`'s
  // stale_quota_slots diagnostic) reads the SAME constant via
  // `AccountStatus::stale_secs`, so all three surfaces (status/doctor/
  // desktop) now agree about whether a given quota row is stale.
  //
  // Derivation (`tooling-self-verification.md` Rule 3 — not re-derived
  // here, only cited; see `status.rs`'s `STALE_THRESHOLD_SECS` doc
  // comment for the full two-outcome derivation table):
  //   - Healthy outcome: the daemon polls every 300s (Anthropic/Codex/
  //     Gemini OAuth, `daemon::usage_poller::POLL_INTERVAL`) or 900s (3P
  //     bearer + native-CLI billing, `POLL_INTERVAL_3P`) — 3600s clears
  //     2+ consecutive missed cycles on every live cadence.
  //   - Broken outcome: the incident this constant was sized against
  //     (2026-08-02) was a dead native-CLI vendor token sitting stale for
  //     15.6h = 56,160s — caught with enormous margin (56,160s vs the
  //     3,600s trip point).
  const STALE_THRESHOLD_SECS = 3600;

  // Ticking wall-clock reference for the staleness computation below.
  // Updated on its own interval (not tied to the fetch/poll cycle) so a
  // card's age keeps advancing even while `get_accounts` itself is
  // failing (F2) — staleness is exactly what should be visible then.
  let nowSecs = $state(Math.floor(Date.now() / 1000));

  // Age in seconds since the slot's quota row was last successfully
  // polled, or `null` when there is no age to report — mirrors
  // `PollFreshness::NeverPolled` in `status.rs`: a slot with
  // `has_quota === false` (no row matched yet — see the doc comment on
  // that field above) or an `updated_at` of `0`/negative has never been
  // polled, so "stale" would misreport "was fresh, has gone stale" for a
  // slot that was simply never measured. Negative ages (a clock-skewed
  // `updated_at` briefly ahead of `nowSecs`) are also treated as "no age
  // to report" rather than floored to 0, matching the honest-uncertainty
  // posture of the CLI's `NeverPolled` classification.
  function accountAgeSecs(account: AccountView): number | null {
    if (account.has_quota === false) return null;
    if (!account.updated_at || account.updated_at <= 0) return null;
    const age = nowSecs - account.updated_at;
    return age >= 0 ? age : null;
  }

  // Strict `>`, matching `status.rs::poll_freshness`'s classifier exactly
  // — `age_secs === STALE_THRESHOLD_SECS` reads Fresh on both surfaces.
  function isStale(account: AccountView): boolean {
    const age = accountAgeSecs(account);
    return age !== null && age > STALE_THRESHOLD_SECS;
  }

  // "1h14m" / "2h" / "45m" / "30s" — elapsed-time rendering for the
  // staleness label. Deliberately separate from `formatResetTime` below
  // (which renders a COUNTDOWN to a future reset, not elapsed age) even
  // though the bucketing logic is similar — the two read misleadingly if
  // merged into one "is this counting up or down?" function.
  function formatAge(secs: number): string {
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return m > 0 ? `${h}h${m}m` : `${h}h`;
  }

  let accounts = $state<AccountView[]>([]);
  // F2 (desktop account-list redteam): a poll failure (the 5s interval,
  // or a post-action re-fetch after remove/move/rename) is TRANSIENT and
  // MUST NOT blank the card list — the daemon may just be mid-restart.
  // `pollError` drives a non-destructive banner ABOVE a still-rendered
  // list (see the `{#if pollError}` block below `{:else}`). It is only
  // rendered as a full-page replacement when there is nothing else to
  // show (`accounts.length === 0` — e.g. the very first load fails and
  // there is no cached list to fall back to).
  let pollError = $state<string | null>(null);
  // Inline remove-failure error (F2): rendered on the affected card only,
  // following the `renameError` precedent already in this file — does
  // NOT set `pollError`, so the rest of the card list stays visible.
  // Scoped by id (not a boolean) since the error must attach to the
  // specific card that failed, not whichever card is currently armed.
  let removeError = $state<string | null>(null);
  let removeErrorId = $state<number | null>(null);
  // Inline move-failure error (F2): rendered inside the open renumber
  // picker. Only one picker can be open at a time (`movingFromId`), so
  // no separate id is needed — `movingFromId === account.id` scopes it.
  let moveError = $state<string | null>(null);
  // Informational notice surfaced after a successful `csq move` when the
  // pre-rename scan found live processes bound to the source slot. Phase 3
  // (M3-6) replaced the `SLOT_IN_USE` refusal with `live_pids_bound`
  // telemetry; the renderer displays this notice so the user knows daemon
  // attribution survived the renumber. Auto-clears after ~5s.
  let moveNotice = $state<string | null>(null);
  let moveNoticeTimer: ReturnType<typeof setTimeout> | null = null;
  let loading = $state(true);
  let modalOpen = $state(false);
  let reauthSlot = $state<number | null>(null);
  // Slot model-change modal. `null` = closed. Carries the slot id
  // AND the slot's surface so the modal can branch between the
  // Ollama `ollama list` path and the Codex `list_codex_models`
  // path (PR-C8).
  let changeModelSlot = $state<{ id: number; surface: string } | null>(null);
  // Two-tap remove: the first click on the × button arms the
  // confirmation; the second click on the same card commits. Tapping
  // any other card or letting the auto-disarm timer fire resets it.
  let armedRemoveId = $state<number | null>(null);
  let armedRemoveTimer: ReturnType<typeof setTimeout> | null = null;

  // Inline move-slot picker: when a row's "Move..." button is
  // clicked, this is set to the source slot id and the row renders a
  // free-slot picker. Phase 3 (M3-6) removed the live-process refusal —
  // handle-dir symlinks retarget through `identities/<UUID>/` and the
  // remaining `config-N/`-keyed symlinks are rewritten by Step 5.5 of
  // `move_account`. The Tauri command returns `MoveAccountSummary` with
  // `live_pids_bound: u32[]` telemetry; the renderer surfaces it via the
  // `moveNotice` state.
  let movingFromId = $state<number | null>(null);
  let moveTargetId = $state<number | null>(null);
  let moveBusy = $state(false);

  // ── Sort mode ────────────────────────────────────────────

  type SortMode = 'custom' | '5h' | '7d';

  function loadSortMode(): SortMode {
    try {
      const raw = localStorage.getItem('csq-sort-mode');
      if (raw === '5h' || raw === '7d') return raw;
    } catch {}
    return 'custom';
  }

  function saveSortMode(mode: SortMode) {
    try { localStorage.setItem('csq-sort-mode', mode); } catch {}
  }

  let sortMode = $state<SortMode>(loadSortMode());

  function setSortMode(mode: SortMode) {
    sortMode = mode;
    saveSortMode(mode);
  }

  // ── Ordering ─────────────────────────────────────────────
  //
  // "custom" is no longer a user-draggable order backed by its own
  // localStorage-persisted array — that was a SECOND ordering with no
  // relationship to the slot number, and nothing reconciled it when
  // slots were renumbered (`csq move`), so it silently went stale and
  // won over slot order. Slot number (`AccountView.id`) is now the
  // single source of truth: "custom" means ascending by id. Manual
  // reordering still exists — via the "#" renumber picker below, which
  // performs a REAL `csq move` through `move_account` rather than a
  // cosmetic, unreconciled local reorder. See the design note at the
  // top of this file's PR description for the tradeoff.

  // Provider identity used to group accounts for the 5h/7d reset-time
  // sort modes. Order: Claude native -> Codex -> Kimi (both account
  // shapes) -> Grok -> Z.AI -> MiniMax -> everything else. Derived from
  // `surface` / `provider_id` / `source` — NEVER from slot id, which the
  // maintainer is actively renumbering (18->11, 11->12, 12->15, ...).
  function providerGroupRank(a: AccountView): number {
    if (a.source === 'anthropic') return 1; // Claude native (Anthropic OAuth)
    if (a.surface === 'codex') return 2;
    // Kimi has two account shapes: a native self-authenticating CLI slot
    // (surface === 'kimi') and a 3P Bearer-key slot that runs the
    // `claude` CLI against Kimi's base URL (surface === 'claude-code',
    // provider_id === 'kimi'). Both belong in the same group even though
    // their `surface`/`method` differ.
    if (a.surface === 'kimi' || a.provider_id === 'kimi') return 3;
    if (a.surface === 'grok') return 4;
    if (a.provider_id === 'zai') return 5;
    if (a.provider_id === 'mm') return 6;
    return 7; // everything else (Gemini, Ollama, manual, ...)
  }

  // True when the account carries a real usage WINDOW (a 5h and/or 7d
  // reset time). Mirrors `csq-core/src/quota/status.rs::shows_window` —
  // billing mode is per-PLAN, not per-provider (an internal ticket: "a usage
  // window beats a balance"), so a "balance" provider like DeepSeek
  // would sort WITH the subscriptions if it ever carried a real window
  // (e.g. a DeepSeek subscription plan). Deliberately checks the
  // `*_resets_in` fields (nullable, only populated when the underlying
  // quota row actually has that window) rather than `*_pct` (always a
  // number — `0.0` by wire-format default when no quota row exists yet,
  // per the `has_quota` doc comment above).
  function hasWindow(a: AccountView): boolean {
    return a.five_hour_resets_in != null || a.seven_day_resets_in != null;
  }

  // Final display list. "custom" = ascending slot id. "5h"/"7d" = grouped
  // by provider identity (balance-only accounts sort last within/after
  // every group, since a reset-time sort is meaningless for them), then
  // by reset time within each group. Nulls/invalid reset values sort to
  // the bottom of their group.
  let displayedAccounts = $derived.by(() => {
    if (sortMode === 'custom') {
      return [...accounts].sort((a, b) => a.id - b.id);
    }
    const key: keyof AccountView = sortMode === '5h' ? 'five_hour_resets_in' : 'seven_day_resets_in';
    return [...accounts].sort((a, b) => {
      const aWindow = hasWindow(a);
      const bWindow = hasWindow(b);
      if (aWindow !== bWindow) return aWindow ? -1 : 1;
      const groupDiff = providerGroupRank(a) - providerGroupRank(b);
      if (groupDiff !== 0) return groupDiff;
      const av = a[key] as number | null;
      const bv = b[key] as number | null;
      const aValid = av != null && av > 0;
      const bValid = bv != null && bv > 0;
      if (aValid && bValid) return av! - bv!;
      if (aValid) return -1;
      if (bValid) return 1;
      return 0;
    });
  });

  let justMovedId = $state<number | null>(null);

  // ── "Resets soonest" badge ───────────────────────────────
  //
  // Only show a badge when 2+ accounts have a positive reset value
  // for a given window. The badge appears on the one account whose
  // reset time is smallest (i.e. the soonest to free up quota).

  // ── 7d reset ranking ─────────────────────────────────────
  //
  // Rank accounts by 7d reset time (soonest = 1st). Accounts
  // with >= 99.5% usage are excluded — they have no usable quota
  // until reset. Same-rank ties are allowed when reset times match.
  let resetRank = $derived.by((): Map<number, number> => {
    const ranked = new Map<number, number>();
    const candidates = accounts
      .filter(a => a.seven_day_resets_in != null && a.seven_day_resets_in > 0 && a.seven_day_pct < 99.5)
      .sort((a, b) => a.seven_day_resets_in! - b.seven_day_resets_in!);
    if (candidates.length < 2) return ranked;
    let rank = 1;
    for (let i = 0; i < candidates.length; i++) {
      if (i > 0 && candidates[i].seven_day_resets_in !== candidates[i - 1].seven_day_resets_in) {
        rank = i + 1;
      }
      ranked.set(candidates[i].id, rank);
    }
    return ranked;
  });

  // ── First-paint instrumentation ──────────────────────────
  //
  // Budget: first usable paint <200ms from module import. The
  // dashboard is the recovery surface during a rate-limit moment,
  // so sluggish first paint is worst exactly when the user most
  // needs the quota view. This instrumentation
  // logs one line per cold load in dev builds so the 200ms budget
  // is visible in the console as the app evolves. Stripped in
  // production — `import.meta.env.DEV` is a Vite-injected compile
  // constant, not a runtime feature flag.
  const firstPaintStart =
    typeof performance !== 'undefined' ? performance.now() : 0;
  let firstPaintLogged = false;
  function logFirstPaint(label: string) {
    if (firstPaintLogged || !import.meta.env.DEV) return;
    firstPaintLogged = true;
    const elapsed = performance.now() - firstPaintStart;
    // eslint-disable-next-line no-console
    console.info(`[csq] first paint (${label}) in ${elapsed.toFixed(1)}ms`);
  }

  async function getBaseDir(): Promise<string> {
    // Use `join` so the platform's path separator is honored.
    // Tauri 2.10's `homeDir()` returns the home path without a
    // trailing separator (`/Users/example`, not `/Users/example/`),
    // so naive string concatenation produces an invalid path like
    // `/Users/example.claude/accounts`.
    const home = await homeDir();
    return await join(home, '.claude', 'accounts');
  }

  // Cached base dir for sync prop passing to child components
  // (BillingLedger). Populated on first fetchAccounts; null until
  // then, in which case BillingLedger renders a loading state.
  let baseDirCached = $state<string>('');

  async function fetchAccounts() {
    try {
      const baseDir = await getBaseDir();
      baseDirCached = baseDir;
      // Deliberately assign to a local first: if `invoke` rejects, the
      // catch block below must NOT touch `accounts` — the whole point of
      // F2 is that a poll failure leaves the last-known list rendered.
      const fetched = await invoke<AccountView[]>('get_accounts', { baseDir });
      accounts = fetched;
      pollError = null;
    } catch (e) {
      // Non-destructive: `accounts` is left exactly as it was. The
      // `{#if pollError}` banner (rendered above a still-visible list)
      // is the only surface for this failure, UNLESS there is no cached
      // list at all (`accounts.length === 0`), in which case the
      // template falls back to a full-page error — there is nothing to
      // preserve on a first-load failure.
      pollError = String(e);
    } finally {
      loading = false;
      // The list is about to render in the next microtask — that's
      // the first moment the user sees either the rows or the
      // error banner. Log here so the measurement covers the full
      // IPC round-trip, not just component mount.
      logFirstPaint(pollError ? 'error' : 'ready');
    }
  }

  // The next free slot is the smallest 1..=999 integer not already
  // taken by an existing account. Using `length + 1` would skip
  // past gaps (e.g. after the user deletes account 3 from five).
  function nextAccountId(): number {
    const taken = new Set(accounts.map((a) => a.id));
    for (let i = 1; i <= 999; i++) {
      if (!taken.has(i)) return i;
    }
    return accounts.length + 1;
  }

  function disarmRemove() {
    armedRemoveId = null;
    if (armedRemoveTimer) {
      clearTimeout(armedRemoveTimer);
      armedRemoveTimer = null;
    }
  }

  function armRemove(accountId: number) {
    disarmRemove();
    armedRemoveId = accountId;
    // A fresh attempt supersedes any error left over from a prior one.
    removeError = null;
    removeErrorId = null;
    // Auto-disarm after 4s if the user doesn't follow through.
    armedRemoveTimer = setTimeout(() => disarmRemove(), 4000);
  }

  async function handleRemove(accountId: number, e: MouseEvent) {
    e.stopPropagation();
    if (armedRemoveId !== accountId) {
      armRemove(accountId);
      return;
    }
    disarmRemove();
    try {
      const baseDir = await getBaseDir();
      await invoke('remove_account', { baseDir, account: accountId });
      await fetchAccounts();
    } catch (e) {
      // F2: surface the typed error message INLINE on the affected card
      // (`removeError`/`removeErrorId`) rather than the global banner —
      // this failure is specific to one account, not the whole list, and
      // must not blank the other cards. Backend returns prefixed tags
      // like ACCOUNT_IN_USE / NOT_CONFIGURED so the user can self-diagnose.
      const raw = String(e);
      if (raw.startsWith('ACCOUNT_IN_USE:')) {
        removeError = `Cannot remove account ${accountId} — a Claude Code session is still running. Exit it first, then retry.`;
      } else {
        removeError = raw;
      }
      removeErrorId = accountId;
    }
  }

  // ── Inline move-slot ────────────────────────────────────

  // Free slots = integers in 1..=999 (the AccountNum range) not currently
  // held by any account, offered up to one past the highest occupied slot so
  // the user can always move "higher" AND fill any gap. The upper bound scales
  // with the actual working set rather than a hardcoded 9 — a user running
  // slots 10+ must be able to renumber from the GUI, not only via the CLI.
  // Floored at 9 so a small working set still shows a useful range; bounded by
  // 999 (the AccountNum max) so the dropdown never lists an invalid slot. For
  // an arbitrary far jump beyond highest+1, `csq move N M` remains available.
  function freeMoveTargets(fromId: number): number[] {
    const taken = new Set(accounts.map((a) => a.id));
    const highest = accounts.reduce((m, a) => Math.max(m, a.id), 0);
    const upper = Math.min(999, Math.max(9, highest + 1));
    const free: number[] = [];
    for (let i = 1; i <= upper; i++) {
      if (!taken.has(i) && i !== fromId) free.push(i);
    }
    return free;
  }

  function startMove(fromId: number, e: MouseEvent) {
    e.stopPropagation();
    // Cancel any other active picker first.
    movingFromId = fromId;
    const free = freeMoveTargets(fromId);
    moveTargetId = free.length > 0 ? free[0] : null;
    // A freshly opened picker supersedes any error left over from a
    // prior failed attempt on this (or another) card.
    moveError = null;
  }

  function cancelMove(e?: MouseEvent) {
    if (e) e.stopPropagation();
    movingFromId = null;
    moveTargetId = null;
    moveBusy = false;
    moveError = null;
  }

  async function submitMove(e: MouseEvent) {
    e.stopPropagation();
    if (movingFromId == null || moveTargetId == null) return;
    const from = movingFromId;
    const to = moveTargetId;
    moveBusy = true;
    moveError = null;
    try {
      const baseDir = await getBaseDir();
      // Phase 3 (M3-6): `move_account` returns `MoveAccountSummary` with
      // `live_pids_bound: u32[]` telemetry. The Tauri command no longer
      // emits `SLOT_IN_USE` — bound live processes are surfaced as a
      // non-blocking notice instead.
      const summary = (await invoke('move_account', { baseDir, from, to })) as {
        live_pids_bound?: number[];
      };
      cancelMove();
      justMovedId = to;
      setTimeout(() => { if (justMovedId === to) justMovedId = null; }, 1200);

      const livePids = summary?.live_pids_bound ?? [];
      if (livePids.length > 0) {
        if (moveNoticeTimer != null) clearTimeout(moveNoticeTimer);
        moveNotice =
          `Moved slot ${from} → ${to} while ${livePids.length} Claude Code session(s) ` +
          `were bound (PID${livePids.length === 1 ? '' : 's'} ${livePids.join(', ')}). ` +
          `Their next API call will continue against slot ${to}.`;
        moveNoticeTimer = setTimeout(() => {
          moveNotice = null;
          moveNoticeTimer = null;
        }, 5000);
      }

      await fetchAccounts();
    } catch (e) {
      // F2: surface the error INLINE inside the still-open renumber
      // picker (`moveError`) rather than the global banner — the picker
      // is deliberately NOT closed (no `cancelMove()` here) so the user
      // can see the reason and retry or cancel manually, mirroring the
      // `renameError` precedent (input stays open on failure).
      const raw = String(e);
      if (raw.startsWith('TARGET_EXISTS:')) {
        moveError = `Slot ${to} is already configured. Pick an unused slot or remove slot ${to} first.`;
      } else if (raw.startsWith('NOT_CONFIGURED:')) {
        moveError = `Slot ${from} has no state to move.`;
      } else if (raw.startsWith('SAME_SLOT:')) {
        moveError = 'Source and target slots must be different.';
      } else {
        moveError = raw;
      }
      moveBusy = false;
    }
  }

  // ── Inline rename ───────────────────────────────────────
  let editingId = $state<number | null>(null);
  let editValue = $state('');
  // Per-rename inline error — shown below the input instead of
  // replacing the whole account list. Auto-clears when the user
  // starts editing again or closes the rename field. The backend
  // returns descriptive strings (e.g. "name exceeds 256 characters
  // (got 300)", "name must not contain control characters") that are
  // safe to display verbatim. Does NOT set the global `pollError` state
  // so the rest of the card list remains visible during a failed rename.
  let renameError = $state<string | null>(null);

  // F5: accepts a keyboard event too — the label carries
  // `role="button" tabindex="0"` (below) so it MUST support Enter/Space
  // like any other interactive element reachable by Tab, not just the
  // double-click that originally drove it.
  function startRename(account: AccountView, e: MouseEvent | KeyboardEvent) {
    e.stopPropagation();
    editingId = account.id;
    editValue = account.label;
    renameError = null;
  }

  // F5: Enter/Space activation for `.account-label` (role="button",
  // tabindex="0"). Space additionally MUST call `preventDefault` — the
  // browser's default Space behavior scrolls the page, which a
  // keyboard-only user does not expect from a focused "button".
  function handleLabelKeydown(account: AccountView, e: KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      startRename(account, e);
    }
  }

  async function saveRename(accountId: number) {
    renameError = null;
    if (!editValue.trim()) { editingId = null; return; }
    try {
      const baseDir = await getBaseDir();
      await invoke('rename_account', { baseDir, account: accountId, name: editValue.trim() });
      editingId = null;
      await fetchAccounts();
    } catch (e) {
      // Surface the error inline (below the rename input) rather than
      // replacing the whole account list. The input stays open so the
      // user can correct the value without re-activating rename mode.
      renameError = String(e).replace(/^rename failed:\s*/i, '');
    }
  }

  function formatResetTime(secs: number | null): string {
    if (secs == null || secs <= 0) return '';
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return m > 0 ? `${h}h${m}m` : `${h}h`;
  }

  function handleRenameKeydown(e: KeyboardEvent, accountId: number) {
    if (e.key === 'Enter') saveRename(accountId);
    if (e.key === 'Escape') { editingId = null; renameError = null; }
  }

  // Initial fetch + 5-second poll. The `csq-card-order` localStorage key
  // (the retired second-ordering array — see the "Ordering" design note
  // above) is a one-time cleanup: it is no longer read anywhere, but a
  // stale entry left on disk is dead weight for any future key reuse.
  $effect(() => {
    try { localStorage.removeItem('csq-card-order'); } catch {}
    fetchAccounts();
    const interval = setInterval(fetchAccounts, 5000);
    // F1: advances `nowSecs` independently of the fetch cycle so a
    // card's staleness age keeps ticking forward even while
    // `get_accounts` itself is failing (F2) — that is exactly the
    // moment the age needs to be visible. This effect only WRITES
    // `nowSecs`, never reads it, so it does not self-invalidate
    // (`svelte-patterns.md` Rule 5 governs effects that both read AND
    // write the same `$state`; this one does neither on `nowSecs`, it
    // only writes, from inside an async interval callback rather than
    // the effect body's synchronous execution).
    const clockInterval = setInterval(() => {
      nowSecs = Math.floor(Date.now() / 1000);
    }, 15000);
    return () => {
      clearInterval(interval);
      clearInterval(clockInterval);
    };
  });
</script>

{#if loading}
  <div class="loading">Loading accounts...</div>
{:else if pollError && accounts.length === 0}
  <!-- F2: a poll failure with NOTHING cached to fall back on (typically
       the very first load) has no list to preserve — this is the only
       remaining case that replaces the whole view with an error. -->
  <div class="error">{pollError}</div>
{:else if accounts.length === 0}
  <div class="empty">
    <p>No accounts configured.</p>
    <p class="hint">Run <code>csq login 1</code> to add your first account.</p>
  </div>
{:else}
  {#if pollError}
    <!-- F2: a poll failure that DOES have a cached list is non-destructive
         — the banner sits above the still-rendered cards instead of
         replacing them. Card ages keep advancing via `nowSecs` (F1), so
         the longer a refresh stays broken the more visibly stale the
         bars become — the two fixes reinforce each other by design. -->
    <div class="poll-error-banner" role="alert" data-testid="poll-error-banner">
      Couldn't refresh — showing last known values. Retrying…
    </div>
  {/if}
  {#if moveNotice}
    <div class="info-notice" role="status">{moveNotice}</div>
  {/if}
  <div class="sort-control">
    <button
      class="sort-pill"
      class:active={sortMode === 'custom'}
      onclick={() => setSortMode('custom')}
    >custom</button>
    <button
      class="sort-pill"
      class:active={sortMode === '5h'}
      onclick={() => setSortMode('5h')}
    >5h reset</button>
    <button
      class="sort-pill"
      class:active={sortMode === '7d'}
      onclick={() => setSortMode('7d')}
    >7d reset</button>
  </div>
  <div class="account-list">
    {#each displayedAccounts as account (account.id)}
      <div class="account-card" class:no-creds={!account.has_credentials} class:just-moved={justMovedId === account.id}>
        <div class="card-controls">
          <button
            class="renumber-btn"
            data-testid="renumber-btn"
            onclick={(e) => startMove(account.id, e)}
            title="Renumber this slot"
            disabled={movingFromId !== null && movingFromId !== account.id}
          >#</button>
          <button
            class="remove-btn"
            class:armed={armedRemoveId === account.id}
            onclick={(e) => handleRemove(account.id, e)}
            title={armedRemoveId === account.id ? 'Click again to confirm removal' : 'Remove this account'}
          >{armedRemoveId === account.id ? 'Confirm' : '×'}</button>
        </div>
        {#if movingFromId === account.id}
          <div class="renumber-picker" data-testid="renumber-picker" role="dialog" aria-label={`Renumber slot ${account.id}`}>
            {#if freeMoveTargets(account.id).length === 0}
              <span class="renumber-hint">No free slots available. Use CLI <code>csq move {account.id} N</code> to pick any slot.</span>
              <button class="secondary" onclick={cancelMove}>Cancel</button>
            {:else}
              <span class="renumber-hint">Move slot {account.id} → </span>
              <select
                bind:value={moveTargetId}
                onclick={(e) => e.stopPropagation()}
                disabled={moveBusy}
                data-testid="renumber-target"
              >
                {#each freeMoveTargets(account.id) as slot}
                  <option value={slot}>{slot}</option>
                {/each}
              </select>
              <button
                class="primary"
                data-testid="renumber-confirm"
                onclick={submitMove}
                disabled={moveBusy || moveTargetId == null}
              >{moveBusy ? 'Moving…' : 'Move'}</button>
              <button class="secondary" onclick={cancelMove} disabled={moveBusy}>Cancel</button>
              {#if moveError}
                <!--
                  F2: inline move-failure error. The picker stays open
                  (submitMove does NOT call cancelMove on failure) so the
                  user can read the reason and retry/cancel — the same
                  precedent as `.rename-error-msg` below.
                -->
                <div class="move-error-msg" data-testid="move-error" role="alert">{moveError}</div>
              {/if}
            {/if}
          </div>
        {/if}
        {#if armedRemoveId === account.id}
          <button
            type="button"
            class="armed-overlay"
            aria-label="Cancel remove"
            onclick={(e) => { e.stopPropagation(); disarmRemove(); }}
          ></button>
        {/if}
        <!--
          The card body is non-interactive. The whole-card click/
          Enter/Space swap affordance was removed: spec 02 §2.8
          retired the legacy dashboard-swap mechanism (M4-8), so the
          handler could only ever surface a DESKTOP_SWAP_UNAVAILABLE
          refusal — a dead flow that read as a bug. Swap is a
          per-terminal action: `csq swap N` inside the terminal.
          Interactive children (rename, re-auth, renumber, remove)
          keep their own controls.
        -->
        <div class="card-body">
          <div class="account-header">
            <span class="account-id">#{account.id}</span>
            {#if editingId === account.id}
              <!-- svelte-ignore a11y_autofocus -->
              <input
                class="rename-input"
                bind:value={editValue}
                onkeydown={(e) => handleRenameKeydown(e, account.id)}
                onblur={() => saveRename(account.id)}
                autofocus
                onclick={(e) => e.stopPropagation()}
              />
            {:else}
              <!-- F7: title carries the full label (a long email/identity
                   string truncates visually via CSS below) AND keeps the
                   "double-click to rename" affordance discoverable —
                   both purposes share one tooltip since only one title
                   attribute is allowed per element. F5: Enter/Space now
                   activate rename, matching the element's own
                   role="button" tabindex="0" contract. -->
              <span
                class="account-label"
                role="button"
                tabindex="0"
                ondblclick={(e) => startRename(account, e)}
                onkeydown={(e) => handleLabelKeydown(account, e)}
                title={`${account.label} — double-click or press Enter to rename`}
              >{account.label}</span>
            {/if}
            <!--
              Span with role="status" + tabindex=0: the badge is a
              read-only status chip that stays keyboard-focusable per
              PR-C8 acceptance criteria. The svelte-ignore below
              acknowledges the deliberate tabindex on a
              noninteractive role.

              Round-7 — display all three surfaces consistently.
              The displayed text maps `claude-code` → `claude` so
              the badge reads as CLAUDE (uppercase via CSS
              text-transform).

              Round-1-redteam-fix: render an explicit UNKNOWN badge
              for any out-of-vocabulary surface value rather than
              silently hiding the badge. A missing/null/empty
              `surface` is now a visible bug (a card with an UNKNOWN
              badge) rather than an invisible inconsistency (some
              cards show badges, one card doesn't). Origin: M4
              (an internal journal entry). The new TS type literal-union prevents
              this at compile time; the runtime fallback covers any
              IPC-side patch that bypasses the typecheck.

              an internal journal entry C5: kimi/grok added alongside claude-code/
              codex/gemini — a native slot previously fell through to
              the UNKNOWN badge (the account's identity label like
              "kimi-14" was the only visible surface hint).
            -->
            {#if account.surface === 'claude-code' || account.surface === 'codex' || account.surface === 'gemini' || account.surface === 'kimi' || account.surface === 'grok'}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
              <span
                class="surface-badge"
                class:surface-claude={account.surface === 'claude-code'}
                class:surface-codex={account.surface === 'codex'}
                class:surface-gemini={account.surface === 'gemini'}
                class:surface-kimi={account.surface === 'kimi'}
                class:surface-grok={account.surface === 'grok'}
                role="status"
                tabindex="0"
                aria-label={`Upstream surface: ${account.surface}`}
                data-testid="surface-badge"
                title={`Upstream surface: ${account.surface}`}
              >{account.surface === 'claude-code' ? 'claude' : account.surface}</span>
            {:else}
              <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
              <span
                class="surface-badge surface-unknown"
                role="status"
                tabindex="0"
                aria-label="Upstream surface: unknown"
                data-testid="surface-badge"
                title="Upstream surface: unknown. Slot is in an unrecognized state — file a bug."
              >unknown</span>
            {/if}
            <TokenBadge status={account.token_status} expiresSecs={account.expires_in_secs} />
          </div>
          {#if editingId === account.id && renameError}
            <!--
              Inline rename error: shown when the backend rejects the label
              (e.g. "name exceeds 256 characters", "control characters not
              allowed"). Rendered below the input header rather than replacing
              the whole card list so the user can correct in-place.
            -->
            <div class="rename-error-msg" data-testid="rename-error" role="alert">{renameError}</div>
          {/if}
          {#if removeErrorId === account.id && removeError}
            <!--
              F2: inline remove-failure error — same precedent as
              `.rename-error-msg` above. Rendered on THIS card only; the
              rest of the list (and every other card) stays untouched.
            -->
            <div class="remove-error-msg" data-testid="remove-error" role="alert">{removeError}</div>
          {/if}
          {#if account.last_refresh_error}
            <div class="refresh-error" title="Most recent refresh failure tag from the daemon">
              ⚠ {formatRefreshError(account.last_refresh_error)}
            </div>
          {/if}
          {#if account.surface === 'gemini'}
            <!--
              FR-G-UI-03: Gemini accounts render a counter / 429
              countdown / "n/a" instead of the synthesised 5h / 7d
              utilization bars — Google does NOT publish a usage
              percentage for API-key accounts so any bar would be
              fabricated. The downgrade chip lights up when the
              served model differs from the user's selected model.
            -->
            <div class="gemini-quota" data-testid="gemini-quota">
              {#if account.gemini_rate_limit_reset_at && formatGeminiResetCountdown(account.gemini_rate_limit_reset_at)}
                <span class="gemini-rate-limit" data-testid="gemini-rate-limit">
                  ⏳ rate-limited — {formatGeminiResetCountdown(account.gemini_rate_limit_reset_at)}
                </span>
              {:else if account.gemini_counter_today !== null && account.gemini_counter_today !== undefined}
                <span class="gemini-counter" data-testid="gemini-counter">
                  {account.gemini_counter_today} {account.gemini_counter_today === 1 ? 'request' : 'requests'} today
                </span>
              {:else}
                <span class="gemini-quota-na" data-testid="gemini-quota-na">quota: n/a</span>
              {/if}
              {#if account.gemini_selected_model && account.gemini_effective_model && account.gemini_selected_model !== account.gemini_effective_model}
                <span
                  class="gemini-downgrade"
                  data-testid="gemini-downgrade"
                  title="Your tier returned a different model than the one you selected. Preview tiers may silently downgrade."
                >
                  ⚠ {account.gemini_selected_model} → {account.gemini_effective_model}
                </span>
              {/if}
            </div>
          {:else if account.quota_kind === 'native'}
            {#if account.surface === 'kimi'}
              <!--
                Defense-in-depth (HIGH-1, an internal ticket redteam): the Rust
                quota_kind mapping routes a native Kimi slot through
                "utilization", not "native" — Kimi IS polled by the
                dedicated usage_poller::kimi (unlike Grok's genuine
                vendor-managed subscription with no csq quota endpoint).
                This branch is unreachable for a Kimi slot on a
                version-matched desktop/daemon pair; it exists only so a
                stale backend that still tags a Kimi slot "native" during
                a version-skew window renders bars instead of stranding
                the slot behind the static subscription text below. Mirrors
                the surface-match defense-in-depth pattern the Rust side
                uses for the 5h/7d gate (commands/mod.rs).
              -->
              <div class="usage-bars">
                <UsageBar label="5h" pct={account.five_hour_pct} stale={isStale(account)} />
                <UsageBar label="7d" pct={account.seven_day_pct} stale={isStale(account)} />
              </div>
              {#if isStale(account)}
                <!-- F1: the daemon may be stopped or this slot's poll
                     may have silently frozen — the bars above are dimmed
                     AND named explicitly stale, not just quietly old. -->
                <div class="quota-stale-label" data-testid="quota-stale-label" title="Last successful quota poll — the daemon may be stopped">
                  stale — as of {formatAge(accountAgeSecs(account) ?? 0)} ago
                </div>
              {/if}
            {:else}
              <!--
                Native-CLI session surfaces — currently Grok (journals
                0133/0135) — are vendor-managed SUBSCRIPTIONS: the vendor
                CLI owns auth, refresh, and billing, and csq polls no
                quota for it. Neither the pay-per-token ledger (would
                read "$0 / 0 tokens") nor stuck-at-zero 5h/7d bars apply
                — render a clean subscription state instead (0135 issue
                3). Kimi's native session is polled (see the
                `surface === 'kimi'` branch above) and no longer reaches
                this arm on a version-matched pair.
              -->
              <div class="native-quota" data-testid="native-quota">
                <span class="native-quota-label">Subscription · vendor-managed</span>
              </div>
            {/if}
          {:else if account.quota_kind === 'unknown'}
            <!--
              Phase B' (an internal journal entry D5): pay-per-token slots whose
              quota_kind is Unknown have no quota signal — the 5h/7d
              bars would render stuck-at-zero. Render the tokens-and-
              cost-over-time ledger instead. See an internal journal entry for the
              "don't hide bars without a replacement" feedback that
              motivated this design.
            -->
            <BillingLedger account={account.id} baseDir={baseDirCached} />
          {:else if account.quota_kind === 'balance' || account.balance_display}
            <!--
              Balance-based providers (e.g. DeepSeek): no 5h/7d reset
              windows — the daemon populates `balance_display` with the
              formatted remaining credit instead. Render it in the usage
              area in place of the bars, then show the spend ledger below.
            -->
            <div class="balance-row">
              <span class="balance-label">Balance</span>
              {#if account.balance_display}
                <span class="balance-value" data-testid="balance-display">{account.balance_display}</span>
                <span class="balance-suffix">remaining</span>
              {:else}
                <!--
                  quota_kind is `balance` but the daemon hasn't polled
                  `/user/balance` yet (balance_display is null). Show a
                  checking state rather than a bare "—", which reads as a
                  failure indistinguishable from a genuine error (redteam an internal ticket F4).
                -->
                <span class="balance-value balance-pending" data-testid="balance-display">checking…</span>
              {/if}
            </div>
            <BillingLedger account={account.id} baseDir={baseDirCached} hideWhenEmpty={true} />
          {:else if account.has_quota === false}
            <!--
              HIGH-1 (an internal ticket redteam): `has_quota === false` means no
              quota.json row has been matched for this slot yet — the
              daemon hasn't polled it (fresh slot, or a poll cycle away).
              `five_hour_pct`/`seven_day_pct` are `0.0` only because that
              is the wire-format default, NOT a measured "0% used" — a
              bare 0%-width bar here would be indistinguishable from
              "quota exhausted" or "genuinely unused". Render an honest
              pending state instead, matching the `balance-pending`
              precedent above (redteam an internal ticket F4).
            -->
            <div class="usage-bars-pending" data-testid="usage-bars-pending">
              <span class="quota-pending-label">Checking usage…</span>
            </div>
          {:else}
            <div class="usage-bars">
              <UsageBar label="5h" pct={account.five_hour_pct} stale={isStale(account)} />
              <UsageBar label="7d" pct={account.seven_day_pct} stale={isStale(account)} />
            </div>
            {#if isStale(account)}
              <!-- F1 (CRITICAL): the #1 correctness defect this shard
                   fixes. `get_accounts` reads `quota.json` from DISK — it
                   never talks to the daemon — so when the daemon stops,
                   this card keeps rendering the last-written percentages
                   with full confidence. Past `STALE_THRESHOLD_SECS`
                   (reused from `status.rs`, see the constant's doc
                   comment above) the bars are dimmed (UsageBar's `stale`
                   prop) AND explicitly named stale here, so an operator
                   choosing which account to run against is told the
                   truth instead of a confident-looking lie. -->
              <div class="quota-stale-label" data-testid="quota-stale-label" title="Last successful quota poll — the daemon may be stopped">
                stale — as of {formatAge(accountAgeSecs(account) ?? 0)} ago
              </div>
            {/if}
            {#if account.five_hour_resets_in || account.seven_day_resets_in}
              <div class="reset-info">
                {#if account.five_hour_resets_in}
                  <span>5h resets in {formatResetTime(account.five_hour_resets_in)}</span>
                {/if}
                {#if account.seven_day_resets_in}
                  <span>
                    7d resets in {formatResetTime(account.seven_day_resets_in)}
                    {#if resetRank.has(account.id)}
                      <span class="rank-badge">{resetRank.get(account.id)}</span>
                    {/if}
                  </span>
                {/if}
              </div>
            {/if}
          {/if}
        </div>
        {#if account.token_status === 'expired' || account.token_status === 'missing' || account.last_refresh_error}
          <button
            class="reauth-btn"
            onclick={(e) => {
              e.stopPropagation();
              reauthSlot = account.id;
              modalOpen = true;
            }}
            title="Re-authenticate this account with a fresh OAuth login"
          >
            Re-auth
          </button>
        {/if}
        {#if account.provider_id === 'ollama' || account.surface === 'codex' || account.surface === 'gemini'}
          <button
            class="change-model-btn"
            onclick={(e) => {
              e.stopPropagation();
              changeModelSlot = { id: account.id, surface: account.surface };
            }}
            title={account.surface === 'codex'
              ? 'Switch which Codex model this slot spawns'
              : account.surface === 'gemini'
                ? 'Switch which Gemini model this slot spawns'
                : 'Switch which local Ollama model this slot uses'}
          >
            Change model
          </button>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<div class="actions">
  <button class="add-account" onclick={() => { reauthSlot = null; modalOpen = true; }}>+ Add Account</button>
</div>

<AddAccountModal
  isOpen={modalOpen}
  nextAccountId={reauthSlot ?? nextAccountId()}
  reauthSlot={reauthSlot}
  onClose={() => { reauthSlot = null; modalOpen = false; }}
  onAccountAdded={() => fetchAccounts()}
/>

<ChangeModelModal
  isOpen={changeModelSlot !== null}
  slot={changeModelSlot?.id ?? 0}
  surface={changeModelSlot?.surface ?? 'claude-code'}
  onClose={() => { changeModelSlot = null; }}
  onChanged={() => fetchAccounts()}
/>

<style>
  .sort-control {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 0.5rem;
  }
  .sort-pill {
    padding: 0.2rem 0.55rem;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--text-tertiary);
    font: inherit;
    font-size: 0.72rem;
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
    line-height: 1.4;
  }
  .sort-pill:hover {
    border-color: var(--text-secondary);
    color: var(--text-secondary);
  }
  .sort-pill.active {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--accent-low);
  }
  .rank-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.58rem;
    font-weight: 700;
    min-width: 1.2em;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 999px;
    padding: 0 0.3em;
    line-height: 1.5;
    vertical-align: middle;
    margin-left: 0.25em;
    opacity: 0.85;
  }
  .account-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .account-card {
    display: flex;
    flex-direction: column;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    transition: border-color 0.15s;
    overflow: hidden;
  }
  .account-card { position: relative; }
  .account-card:hover { border-color: var(--accent); }
  .account-card.no-creds { opacity: 0.5; }
  .account-card.just-moved {
    border-color: var(--accent);
    transition: border-color 0.3s;
  }
  .card-controls {
    position: absolute;
    right: 0.4rem;
    bottom: 0.4rem;
    display: flex;
    gap: 2px;
    opacity: 0;
    transition: opacity 0.15s;
    z-index: 3;
  }
  .account-card:hover .card-controls { opacity: 1; }
  /* F5: renumber/remove are in the tab order at ALL times (they carry
     no tabindex removal), painted at opacity 0 by default. Without this
     rule a keyboard-only operator tabs through invisible controls —
     including a destructive remove button — with zero visual feedback
     about where focus is. `:focus-within` covers focus landing on
     either child button. */
  .account-card:focus-within .card-controls { opacity: 1; }
  /* Keep controls visible while the remove button is armed so the
     user can complete the second tap without re-hovering. */
  .account-card:has(.remove-btn.armed) .card-controls { opacity: 1; }
  .remove-btn {
    background: var(--bg-tertiary);
    border: none;
    color: var(--text-secondary);
    font-size: 0.65rem;
    padding: 0.15rem 0.35rem;
    cursor: pointer;
    border-radius: 2px;
    line-height: 1;
    margin-left: 2px;
  }
  .renumber-btn {
    background: var(--bg-tertiary);
    border: none;
    color: var(--text-secondary);
    font-size: 0.65rem;
    padding: 0.15rem 0.35rem;
    cursor: pointer;
    border-radius: 2px;
    line-height: 1;
    margin-left: 2px;
    font-weight: 600;
  }
  .renumber-btn:hover:not(:disabled) { color: var(--accent); }
  .renumber-btn:disabled { opacity: 0.2; cursor: default; }
  .renumber-picker {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.6rem;
    margin: 0.4rem 0 0.2rem;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.75rem;
    flex-wrap: wrap;
    position: relative;
    z-index: 3;
  }
  .renumber-hint { color: var(--text-secondary); }
  .renumber-picker code {
    background: var(--bg-secondary);
    padding: 1px 4px;
    border-radius: 2px;
    font-size: 0.7rem;
  }
  .renumber-picker select {
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 0.1rem 0.3rem;
    font-size: 0.75rem;
  }
  .renumber-picker .primary,
  .renumber-picker .secondary {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 0.15rem 0.5rem;
    cursor: pointer;
    font-size: 0.7rem;
  }
  .renumber-picker .primary { background: var(--accent); color: white; border-color: var(--accent); }
  .renumber-picker .primary:disabled { opacity: 0.5; cursor: default; }
  .renumber-picker .secondary:hover { color: var(--text-primary); }
  .remove-btn:hover { color: var(--red); }
  .remove-btn.armed {
    background: var(--red);
    color: white;
    font-weight: 600;
    font-size: 0.6rem;
  }
  /* Transparent click-trap covering the card body. Lets the user
     dismiss an armed remove by clicking anywhere on the card (not
     the × button). The button itself sits above this overlay
     because .card-controls has a higher z-index. */
  .armed-overlay {
    position: absolute;
    inset: 0;
    background: transparent;
    border: none;
    cursor: default;
    z-index: 2;
    padding: 0;
  }
  .card-body {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    padding: 0.75rem;
    background: transparent;
    border: none;
    text-align: left;
    color: inherit;
    font: inherit;
    width: 100%;
  }
  .reauth-btn {
    padding: 0.4rem 0.75rem;
    background: rgba(244, 67, 54, 0.08);
    border: none;
    border-top: 1px solid var(--border);
    color: var(--red);
    font: inherit;
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    transition: background 0.15s;
  }
  .reauth-btn:hover {
    background: rgba(244, 67, 54, 0.18);
  }
  .change-model-btn {
    padding: 0.4rem 0.75rem;
    background: var(--bg-secondary);
    border: none;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font: inherit;
    font-size: 0.78rem;
    font-weight: 500;
    cursor: pointer;
    text-align: center;
    transition: color 0.15s;
  }
  .change-model-btn:hover {
    color: var(--accent);
  }
  .account-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    /* F7: a flex container's children default to min-width:auto, which
       ignores `overflow` on a shrinking child. Without this, a long
       label pushes the surface/token badges out of the card instead of
       truncating. */
    min-width: 0;
  }
  .account-id { font-weight: 700; font-size: 0.85rem; color: var(--text-secondary); }
  /* F7: long identity strings (e.g. an email-shaped label) truncate
     instead of pushing the surface/token badges out of the card. The
     full label — plus the rename affordance — moves into `title`
     (set on the element in the markup) since the visible text is now
     potentially clipped. */
  .account-label {
    flex: 1;
    min-width: 0;
    font-weight: 500;
    cursor: text;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .surface-badge {
    font-size: 0.65rem;
    font-weight: 600;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    cursor: help;
  }
  .surface-badge:focus {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  /* Round-7 — Anthropic Claude tag uses the warm amber that matches
     the existing Anthropic brand palette. */
  .surface-badge.surface-claude {
    background: rgba(204, 132, 90, 0.15);
    color: #cc845a;
    border: 1px solid rgba(204, 132, 90, 0.4);
  }
  .surface-badge.surface-codex {
    background: rgba(16, 163, 127, 0.15);
    color: #10a37f;
    border: 1px solid rgba(16, 163, 127, 0.4);
  }
  .surface-badge.surface-gemini {
    /* Google blue (#4285F4) at the same low-saturation tint level as
       the Codex green so the badge reads as a sibling. The downgrade
       chip below uses an amber accent to stand apart from the
       surface chip. */
    background: rgba(66, 133, 244, 0.15);
    color: #4285f4;
    border: 1px solid rgba(66, 133, 244, 0.4);
  }
  /* an internal journal entry C5 — native Kimi/Grok badges. Distinct hues from the
     three OAuth surfaces above AND from surface-unknown's amber (a
     kimi/grok badge must never read as "unrecognized state"). */
  .surface-badge.surface-kimi {
    /* Moonshot AI violet. */
    background: rgba(139, 92, 246, 0.15);
    color: #8b5cf6;
    border: 1px solid rgba(139, 92, 246, 0.4);
  }
  .surface-badge.surface-grok {
    /* xAI rose — visibly distinct from every other surface tint. */
    background: rgba(236, 72, 153, 0.15);
    color: #ec4899;
    border: 1px solid rgba(236, 72, 153, 0.4);
  }
  .surface-badge.surface-unknown {
    /* Amber accent — visibly different from the three known-surface
       tints so an out-of-vocabulary surface value (failure mode the
       TS literal-union prevents at compile time, but the runtime
       fallback catches IPC patches that bypass the typecheck) reads
       as "this is wrong" rather than "this is some new feature."
       Origin: redteam round 1 M4 (an internal journal entry). */
    background: rgba(255, 167, 38, 0.15);
    color: #ffa726;
    border: 1px solid rgba(255, 167, 38, 0.4);
  }
  .gemini-quota {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: baseline;
    font-size: 0.72rem;
    color: var(--text-secondary);
    font-family: var(--font-mono, ui-monospace, monospace);
  }
  .gemini-counter {
    color: var(--text-primary);
    font-weight: 500;
  }
  .gemini-rate-limit {
    color: var(--orange, #d97706);
    font-weight: 500;
  }
  .gemini-quota-na {
    color: var(--text-tertiary);
    font-style: italic;
  }
  .native-quota-label {
    color: var(--text-tertiary);
    font-size: 0.72rem;
  }
  .gemini-downgrade {
    color: var(--orange, #d97706);
    font-size: 0.68rem;
    cursor: help;
  }
  .rename-input {
    flex: 1;
    font: inherit;
    font-weight: 500;
    background: var(--bg-tertiary);
    border: 1px solid var(--accent);
    border-radius: 3px;
    padding: 0.1rem 0.3rem;
    color: inherit;
    outline: none;
  }
  /* Inline error shown when the rename_account Tauri command rejects
     the label. Distinct from .refresh-error (daemon token) and the
     global error banner (network / IPC). */
  .rename-error-msg {
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
    margin-top: -0.1rem;
  }
  /* F2: inline remove-failure error — same shape as .rename-error-msg,
     scoped to the card whose remove_account call rejected. */
  .remove-error-msg {
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
    margin-top: -0.1rem;
  }
  /* F2: inline move-failure error, rendered inside the still-open
     renumber picker. */
  .move-error-msg {
    flex-basis: 100%;
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
  }
  .refresh-error {
    font-size: 0.72rem;
    color: var(--red);
    font-family: ui-monospace, monospace;
    margin-top: -0.15rem;
  }
  /* F1: staleness label paired with UsageBar's dimmed `stale` prop.
     Reuses the `.balance-pending` / `.quota-pending-label` idiom
     (italic, tertiary text) already established in this file for
     "the number you're seeing may not mean what it looks like" states —
     rather than inventing a fourth visual language for the same class
     of honest-uncertainty message. */
  .quota-stale-label {
    color: var(--text-tertiary);
    font-weight: 400;
    font-style: italic;
    font-size: 0.72rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    font-variant-numeric: tabular-nums;
    margin-top: -0.1rem;
  }
  /* F2: non-destructive poll-failure banner — sits above a still-visible
     card list (see the template). Amber/warning tone (matches
     .gemini-rate-limit / .gemini-downgrade's `--orange` accent already
     used elsewhere in this file) rather than the harder `--red` used for
     the full-page .error state, since this is explicitly recoverable. */
  .poll-error-banner {
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.5rem;
    border-radius: 4px;
    background: rgba(217, 119, 6, 0.1);
    color: var(--orange, #d97706);
    font-size: 0.85rem;
    line-height: 1.3;
  }
  .balance-row {
    display: flex;
    align-items: baseline;
    gap: 0.35rem;
    font-size: 0.72rem;
    font-family: var(--font-mono, ui-monospace, monospace);
    margin-top: -0.1rem;
  }
  .balance-label,
  .balance-suffix {
    color: var(--text-tertiary);
    font-weight: 400;
  }
  .balance-value {
    color: var(--text-primary);
    font-weight: 500;
  }
  .balance-pending {
    color: var(--text-tertiary);
    font-weight: 400;
    font-style: italic;
  }
  .usage-bars { display: flex; gap: 1rem; }
  /* HIGH-1 (an internal ticket redteam): honest "no row yet" state, styled like
     .balance-pending so the two "checking…" idioms read as one pattern. */
  .usage-bars-pending {
    display: flex;
    align-items: baseline;
    gap: 0.35rem;
    font-size: 0.72rem;
    font-family: var(--font-mono, ui-monospace, monospace);
  }
  .quota-pending-label {
    color: var(--text-tertiary);
    font-weight: 400;
    font-style: italic;
  }
  .reset-info {
    display: flex;
    gap: 1rem;
    font-size: 0.68rem;
    color: var(--text-tertiary);
    font-family: var(--font-mono, ui-monospace, monospace);
    margin-top: -0.1rem;
    /* F12: numbers scanned down 18 stacked cards must not jitter width
       digit-to-digit ("1h" vs "24h" vs "1h1m"). */
    font-variant-numeric: tabular-nums;
  }
  .loading, .error, .empty { padding: 2rem; text-align: center; }
  .error { color: var(--red); }

  .info-notice {
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.5rem;
    border-radius: 4px;
    background: var(--bg-emphasis, rgba(64, 128, 255, 0.1));
    color: var(--text-emphasis, #4080ff);
    font-size: 0.85rem;
    line-height: 1.3;
  }
  .hint { font-size: 0.85rem; color: var(--text-secondary); }
  code { background: var(--bg-tertiary); padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.85em; }
  .actions { margin-top: 0.75rem; }
  .add-account {
    width: 100%;
    padding: 0.6rem;
    background: transparent;
    border: 1px dashed var(--border);
    border-radius: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    font: inherit;
    font-size: 0.85rem;
    transition: border-color 0.15s, color 0.15s;
  }
  .add-account:hover { border-color: var(--accent); color: var(--accent); }
</style>
