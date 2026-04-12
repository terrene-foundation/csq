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
  /// PID the user has opened a swap dropdown for (only one at a time).
  let pickerPid = $state<number | null>(null);

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
        `PID ${session.pid}: ${msg}`,
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
    if (startedAt == null) return "—";
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
    <div class="session-list">
      {#each sessions as session (session.pid)}
        <div class="session-row">
          <div class="session-primary">
            <span class="pid" title="Process ID">PID {session.pid}</span>
            <span class="cwd" title={session.cwd}>{formatCwd(session.cwd)}</span>
            <span
              class="terminal"
              title={session.tty
                ? `TTY ${session.tty} · ${session.terminal_title ?? "iTerm tab title unavailable"}`
                : "No TTY detected"}
            >
              {formatTerminal(session)}{formatPaneSuffix(session)}
            </span>
          </div>
          <div class="session-meta">
            <span class="config-dir">{formatConfigDir(session.config_dir)}</span>
            {#if session.account_id !== null}
              <span class="account">
                #{session.account_id}
                {#if session.account_label}
                  <span class="account-label">{session.account_label}</span>
                {/if}
              </span>
            {/if}
            <span class="quota {quotaClass(session.five_hour_pct)}">
              5h: {Math.round(session.five_hour_pct)}%
            </span>
            <span class="age" title="Session age">{formatAge(session.started_at)}</span>
          </div>
          <div class="session-actions">
            <button
              class="swap-btn"
              onclick={() =>
                (pickerPid = pickerPid === session.pid ? null : session.pid)}
              aria-label="Swap this session to another account"
            >
              Swap ▾
            </button>
            {#if pickerPid === session.pid}
              <div class="picker" role="menu">
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
  .session-list-container {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .session-row {
    position: relative;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.6rem 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.85rem;
  }
  .session-primary {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    flex: 1;
    min-width: 0;
  }
  .pid {
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .cwd {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .terminal {
    font-size: 0.72rem;
    color: var(--accent);
    font-family: ui-monospace, monospace;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    margin-top: 0.1rem;
  }
  .session-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .config-dir {
    font-family: ui-monospace, monospace;
    background: var(--bg-tertiary);
    padding: 0.05em 0.4em;
    border-radius: 3px;
  }
  .account {
    font-weight: 500;
    color: var(--text-primary);
  }
  .account-label {
    color: var(--text-secondary);
    font-weight: 400;
    margin-left: 0.25rem;
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
    position: relative;
    flex-shrink: 0;
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
