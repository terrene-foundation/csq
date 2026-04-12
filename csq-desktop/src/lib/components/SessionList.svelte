<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { homeDir, join } from "@tauri-apps/api/path";
  import { showToast } from "../stores/toast.svelte";

  // ── Types ─────────────────────────────────────────────────
  //
  // Must stay in sync with `SessionView` in
  // `csq-desktop/src-tauri/src/commands.rs`. A mismatch shows up on
  // the very next poll as a TypeScript runtime shape error.
  interface SessionView {
    pid: number;
    cwd: string;
    config_dir: string;
    account_id: number | null;
    account_label: string | null;
    five_hour_pct: number;
    seven_day_pct: number;
    started_at: number | null;
    tty: string | null;
    term_window: number | null;
    term_tab: number | null;
    term_pane: number | null;
    iterm_profile: string | null;
    terminal_title: string | null;
  }

  interface AccountView {
    id: number;
    label: string;
    has_credentials: boolean;
  }

  // ── State ─────────────────────────────────────────────────
  let sessions = $state<SessionView[]>([]);
  let accounts = $state<AccountView[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let pickerPid = $state<number | null>(null);
  let pickerDropup = $state(false);
  let sessionOrder = $state<number[]>([]);

  // ── Session nicknames (user-editable titles) ────────────
  let sessionNames = $state<Record<string, string>>({});
  let editingPid = $state<number | null>(null);
  let editNameValue = $state('');

  function loadSessionNames(): Record<string, string> {
    try {
      const raw = localStorage.getItem('csq-session-names');
      return raw ? JSON.parse(raw) : {};
    } catch { return {}; }
  }
  function saveSessionNames() {
    try { localStorage.setItem('csq-session-names', JSON.stringify(sessionNames)); } catch {}
  }
  function sessionKey(session: SessionView): string {
    return `${session.config_dir}::${session.cwd}`;
  }
  function getSessionTitle(session: SessionView): string {
    const nickname = sessionNames[sessionKey(session)];
    if (nickname) return nickname;
    if (session.terminal_title && session.terminal_title !== 'Claude Code') return session.terminal_title;
    // Extract just the project folder name from the path
    const parts = session.cwd.split('/');
    return parts[parts.length - 1] || formatCwd(session.cwd);
  }
  function startNameEdit(session: SessionView, e: MouseEvent) {
    e.stopPropagation();
    editingPid = session.pid;
    editNameValue = sessionNames[sessionKey(session)] || '';
  }
  function saveNameEdit(session: SessionView) {
    if (editNameValue.trim()) {
      sessionNames[sessionKey(session)] = editNameValue.trim();
    } else {
      delete sessionNames[sessionKey(session)];
    }
    saveSessionNames();
    editingPid = null;
  }
  function handleNameKeydown(e: KeyboardEvent, session: SessionView) {
    if (e.key === 'Enter') saveNameEdit(session);
    if (e.key === 'Escape') editingPid = null;
  }



  // ── Sort mode ────────────────────────────────────────────
  type SessionSortMode = 'custom' | 'title' | 'account';

  function loadSessionSortMode(): SessionSortMode {
    try {
      const raw = localStorage.getItem('csq-session-sort');
      if (raw === 'title' || raw === 'account') return raw;
    } catch {}
    return 'custom';
  }

  let sessionSortMode = $state<SessionSortMode>(loadSessionSortMode());

  function setSessionSortMode(mode: SessionSortMode) {
    sessionSortMode = mode;
    try { localStorage.setItem('csq-session-sort', mode); } catch {}
  }

  function orderedSessions(): SessionView[] {
    if (sessionOrder.length === 0) return sessions;
    const byPid = new Map(sessions.map(s => [s.pid, s]));
    const ordered: SessionView[] = [];
    for (const pid of sessionOrder) {
      const s = byPid.get(pid);
      if (s) { ordered.push(s); byPid.delete(pid); }
    }
    for (const s of byPid.values()) ordered.push(s);
    return ordered;
  }

  let displayedSessions = $derived.by(() => {
    const base = orderedSessions();
    if (sessionSortMode === 'custom') return base;
    if (sessionSortMode === 'title') {
      return [...base].sort((a, b) =>
        getSessionTitle(a).localeCompare(getSessionTitle(b))
      );
    }
    // account — sort by account number, nulls last
    return [...base].sort((a, b) => {
      if (a.account_id == null && b.account_id == null) return 0;
      if (a.account_id == null) return 1;
      if (b.account_id == null) return -1;
      return a.account_id - b.account_id;
    });
  });

  let justMovedPid = $state<number | null>(null);

  function moveSession(idx: number, direction: -1 | 1) {
    const items = [...orderedSessions()];
    const newIdx = idx + direction;
    if (newIdx < 0 || newIdx >= items.length) return;
    const movedPid = items[idx].pid;
    [items[idx], items[newIdx]] = [items[newIdx], items[idx]];
    sessionOrder = items.map(s => s.pid);
    try { localStorage.setItem('csq-session-order', JSON.stringify(sessionOrder)); } catch {}
    justMovedPid = movedPid;
    setTimeout(() => { justMovedPid = null; }, 600);
  }

  async function getBaseDir(): Promise<string> {
    // `join` honors the platform path separator and Tauri 2.10's
    // `homeDir()` has no trailing separator — see journal 0021.
    const home = await homeDir();
    return await join(home, ".claude", "accounts");
  }

  async function fetchSessions() {
    try {
      const baseDir = await getBaseDir();
      const [s, a] = await Promise.all([
        invoke<SessionView[]>("list_sessions", { baseDir }),
        invoke<AccountView[]>("get_accounts", { baseDir }),
      ]);
      sessions = s;
      accounts = a.filter((acc) => acc.has_credentials);
      error = null;
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function handleTargetedSwap(session: SessionView, targetAccount: number) {
    pickerPid = null;
    try {
      const baseDir = await getBaseDir();
      const msg = await invoke<string>("swap_session", {
        baseDir,
        configDir: session.config_dir,
        target: targetAccount,
      });
      showToast(
        "success",
        `PID ${session.pid}: ${msg}. Run /exit in the terminal to apply.`,
      );
      // Poke the account list and session list to reflect the new
      // binding immediately instead of waiting for the next poll.
      await fetchSessions();
    } catch (e) {
      showToast(
        "error",
        `Could not swap PID ${session.pid}: ${String(e)}`,
      );
    }
  }

  function formatCwd(cwd: string): string {
    // Collapse `/Users/esperie` → `~` so long paths fit the row.
    // We don't have the real home path client-side without another
    // IPC call; use a cheap prefix match on the common macOS/Linux
    // pattern. The full path is still available in the `title=`
    // hover tooltip for truth.
    const match = cwd.match(/^\/(Users|home)\/[^/]+(.*)$/);
    if (match) {
      return "~" + match[2];
    }
    return cwd;
  }

  function formatConfigDir(configDir: string): string {
    // Show only the `config-N` basename — the parent dir is always
    // `~/.claude/accounts/`.
    const parts = configDir.split("/");
    return parts[parts.length - 1] || configDir;
  }

  function formatAge(startedAt: number | null): string {
    if (startedAt == null) return "";
    const nowSecs = Math.floor(Date.now() / 1000);
    const age = Math.max(0, nowSecs - startedAt);
    if (age < 60) return `${age}s`;
    if (age < 3600) return `${Math.floor(age / 60)}m`;
    if (age < 86400) return `${Math.floor(age / 3600)}h`;
    return `${Math.floor(age / 86400)}d`;
  }

  function quotaClass(pct: number): string {
    if (pct >= 100) return "quota-error";
    if (pct >= 80) return "quota-warn";
    return "quota-ok";
  }

  /// Human-readable terminal identity: prefers the iTerm2 tab title
  /// resolved via osascript, falls back to "Window N Tab M" from
  /// TERM_SESSION_ID, then to the iTerm profile, then to the TTY
  /// device, then to a dash. At least one of these is populated
  /// for any iTerm-launched terminal on macOS.
  function formatTerminal(session: SessionView): string {
    if (session.terminal_title) return session.terminal_title;
    if (session.term_window != null && session.term_tab != null) {
      return `Window ${session.term_window} • Tab ${session.term_tab}`;
    }
    if (session.iterm_profile) return session.iterm_profile;
    if (session.tty) return session.tty;
    return "—";
  }

  /// Pane subscript suffix so multi-pane tabs are still
  /// distinguishable. Blank when pane is 0 (the default) or
  /// missing.
  function formatPaneSuffix(session: SessionView): string {
    if (session.term_pane != null && session.term_pane > 0) {
      return ` · pane ${session.term_pane}`;
    }
    return "";
  }

  // Poll every 5s so rotation / new terminals show up quickly.
  $effect(() => {
    try {
      const raw = localStorage.getItem('csq-session-order');
      sessionOrder = raw ? JSON.parse(raw) : [];
    } catch { sessionOrder = []; }
    sessionNames = loadSessionNames();
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  });
</script>

<div class="session-list-container">
  {#if loading}
    <div class="loading">Loading sessions…</div>
  {:else if error}
    <div class="error">{error}</div>
  {:else if sessions.length === 0}
    <div class="empty">
      <p>No live Claude Code sessions detected.</p>
      <p class="hint">
        Run <code>claude</code> in any terminal to see it appear here.
      </p>
    </div>
  {:else}
    <div class="sort-control">
      <button
        class="sort-pill"
        class:active={sessionSortMode === 'custom'}
        onclick={() => setSessionSortMode('custom')}
      >custom</button>
      <button
        class="sort-pill"
        class:active={sessionSortMode === 'title'}
        onclick={() => setSessionSortMode('title')}
      >title</button>
      <button
        class="sort-pill"
        class:active={sessionSortMode === 'account'}
        onclick={() => setSessionSortMode('account')}
      >account</button>
    </div>
    <div class="session-list">
      {#each displayedSessions as session, idx (session.pid)}
        <div class="session-row" class:just-moved={justMovedPid === session.pid}>
          {#if sessionSortMode === 'custom'}
          <div class="move-btns">
            <button class="move-btn" onclick={() => moveSession(idx, -1)} disabled={idx === 0}>▲</button>
            <button class="move-btn" onclick={() => moveSession(idx, 1)} disabled={idx === displayedSessions.length - 1}>▼</button>
          </div>
          {/if}
          <div class="session-primary">
            <div class="session-title-row">
              {#if editingPid === session.pid}
                <!-- svelte-ignore a11y_autofocus -->
                <input
                  class="rename-input"
                  bind:value={editNameValue}
                  onkeydown={(e) => handleNameKeydown(e, session)}
                  onblur={() => saveNameEdit(session)}
                  autofocus
                  placeholder="Session name..."
                  onclick={(e) => e.stopPropagation()}
                />
              {:else}
                <span
                  class="session-title"
                  role="button"
                  tabindex="0"
                  ondblclick={(e) => startNameEdit(session, e)}
                  title="Double-click to rename"
                >{getSessionTitle(session)}</span>
              {/if}
              <span class="age" title="Session age">{formatAge(session.started_at)}</span>
            </div>
            <span class="session-path" title={session.cwd}>{formatCwd(session.cwd)}</span>
            <div class="session-meta-row">
              {#if session.account_id !== null}
                <span class="account-badge">
                  #{session.account_id}
                  {#if session.account_label}
                    {session.account_label}
                  {/if}
                </span>
              {/if}
              <span class="quota-badge {quotaClass(session.five_hour_pct)}">
                5h:{session.five_hour_pct > 0 && session.five_hour_pct < 1 ? '<1' : Math.round(session.five_hour_pct)}%
              </span>
              <span class="quota-badge {quotaClass(session.seven_day_pct)}">
                7d:{session.seven_day_pct > 0 && session.seven_day_pct < 1 ? '<1' : Math.round(session.seven_day_pct)}%
              </span>
            </div>
          </div>
          <div class="session-actions">
            <button
              class="swap-btn"
              onclick={(e) => {
                if (pickerPid === session.pid) {
                  pickerPid = null;
                } else {
                  const btn = e.currentTarget as HTMLElement;
                  const rect = btn.getBoundingClientRect();
                  const spaceBelow = window.innerHeight - rect.bottom;
                  pickerDropup = spaceBelow < 260;
                  pickerPid = session.pid;
                }
              }}
              aria-label="Swap this session to another account"
            >
              Swap {pickerPid === session.pid && pickerDropup ? '▴' : '▾'}
            </button>
            {#if pickerPid === session.pid}
              <div class="picker" class:dropup={pickerDropup} role="menu">
                {#each accounts as account (account.id)}
                  <button
                    class="picker-item"
                    class:active={account.id === session.account_id}
                    onclick={() => handleTargetedSwap(session, account.id)}
                  >
                    #{account.id} {account.label}
                  </button>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

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
  .session-list-container {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .session-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .session-row {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    padding: 0.6rem 0.75rem 0.6rem 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.85rem;
    transition: border-color 0.15s;
  }
  .session-row:hover { border-color: var(--accent); }
  .session-row.just-moved { border-color: var(--accent); transition: border-color 0.3s; }
  .move-btns {
    position: absolute;
    right: 0.4rem;
    bottom: 0.4rem;
    display: flex;
    gap: 2px;
    opacity: 0;
    transition: opacity 0.15s;
    z-index: 2;
  }
  .session-row:hover .move-btns { opacity: 1; }
  .move-btn {
    background: var(--bg-tertiary);
    border: none;
    color: var(--text-secondary);
    font-size: 0.55rem;
    padding: 0.15rem 0.25rem;
    cursor: pointer;
    border-radius: 2px;
    line-height: 1;
  }
  .move-btn:hover { color: var(--accent); }
  .move-btn:disabled { opacity: 0.2; cursor: default; }
  .session-primary {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    flex: 1;
    min-width: 0;
  }
  .session-title-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .session-title {
    font-weight: 600;
    font-size: 0.9rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
    cursor: text;
  }
  .session-path {
    font-size: 0.78rem;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .rename-input {
    flex: 1;
    font: inherit;
    font-weight: 600;
    font-size: 0.9rem;
    background: var(--bg-tertiary);
    border: 1px solid var(--accent);
    border-radius: 3px;
    padding: 0.1rem 0.3rem;
    color: inherit;
    outline: none;
  }
  .session-meta-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.75rem;
  }
  .account-badge {
    font-weight: 500;
    color: var(--text-primary);
  }
  .quota-badge {
    font-family: ui-monospace, monospace;
    font-size: 0.72rem;
  }
  .quota {
    font-family: ui-monospace, monospace;
  }
  .quota-ok {
    color: var(--green);
  }
  .quota-warn {
    color: var(--yellow);
  }
  .quota-error {
    color: var(--red);
    font-weight: 600;
  }
  .age {
    font-family: ui-monospace, monospace;
  }
  .session-actions {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
  }
  .swap-btn {
    padding: 0.35rem 0.6rem;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: inherit;
    font: inherit;
    font-size: 0.75rem;
    cursor: pointer;
    transition: border-color 0.15s;
  }
  .swap-btn:hover {
    border-color: var(--accent);
  }
  .picker {
    position: absolute;
    right: 0;
    top: calc(100% + 4px);
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    min-width: 180px;
    max-height: 240px;
    overflow-y: auto;
    z-index: 50;
    display: flex;
    flex-direction: column;
  }
  .picker.dropup {
    top: auto;
    bottom: calc(100% + 4px);
    box-shadow: 0 -4px 12px rgba(0, 0, 0, 0.25);
  }
  .picker-item {
    text-align: left;
    padding: 0.5rem 0.75rem;
    background: transparent;
    border: none;
    color: inherit;
    font: inherit;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .picker-item:hover {
    background: var(--bg-secondary);
  }
  .picker-item.active {
    background: var(--bg-tertiary);
    font-weight: 600;
  }
  .loading,
  .error,
  .empty {
    padding: 1.5rem;
    text-align: center;
  }
  .error {
    color: var(--red);
  }
  .hint {
    font-size: 0.85rem;
    color: var(--text-secondary);
  }
  code {
    background: var(--bg-tertiary);
    padding: 0.15em 0.4em;
    border-radius: 3px;
    font-size: 0.85em;
    font-family: ui-monospace, monospace;
  }
</style>
