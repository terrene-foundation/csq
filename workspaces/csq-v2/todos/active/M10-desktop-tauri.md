# M10: Desktop (Tauri + Svelte)

Priority: P1 (Fast-Follow)
Effort: 5 autonomous sessions
Dependencies: M8 (Daemon Core — HTTP API), M9 (OAuth)
Phase: 3, Stream 2

---

## M10-01: Build Tauri IPC command handlers

Thin wrappers in `src-tauri/src/commands/` that call `csq-core` functions and return serialized results. Commands: `get_accounts`, `get_usage`, `get_token_status`, `swap_account`, `refresh_account`, `start_login`, `get_daemon_status`. All return `Result<T, String>`.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] All commands registered in Tauri handler
  - [ ] Each command validates input at boundary
  - [ ] No secrets in return types (AccessToken not serializable)
  - [ ] Errors mapped to typed string codes per GAP-4

## M10-02: Build Tauri security configuration

IPC allowlist: scope commands per-window. CSP headers. Isolation mode if supported. Capability file `capabilities/main.json` restricting commands to main window.

- Scope: New, tauri-commands rule
- Complexity: Moderate
- Acceptance:
  - [ ] Only allowed commands accessible from renderer
  - [ ] CSP: no `unsafe-eval`, `connect-src` restricted to `platform.claude.com` (S18, S19)
  - [ ] `freezePrototype: true` in Tauri config (S6)
  - [ ] DevTools disabled in production build

## M10-03: Build Svelte account list component

Display all accounts with: email, status indicator (active/idle/expired), 5h and 7d usage bars, last-updated timestamp. Fetches from Tauri `get_accounts` command. Reactive updates via `$state`.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] All accounts rendered
  - [ ] Active account highlighted
  - [ ] Usage bars proportional and colored (green/yellow/red)
  - [ ] Refreshes on interval (5s)

## M10-04: Wire account list to live data

Replace any mock data with live Tauri IPC calls. Account data flows from daemon -> Tauri command -> Svelte store -> component.

- Scope: New (wire)
- Complexity: Moderate
- Depends: M10-03, M10-01
- Acceptance:
  - [ ] Zero mock data in production component
  - [ ] Data matches daemon's cache
  - [ ] Empty state handled (no accounts configured)

## M10-05: Build usage bars component

Per-account usage visualization: 5-hour bar + 7-day bar. Color gradient: green (<60%), yellow (60-89%), red (90%+). Shows percentage label. Tooltip with reset time.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Colors match thresholds
  - [ ] Tooltip shows "Resets in 2h 15m"
  - [ ] 100%: shows "Exhausted" label
  - [ ] No data: shows "No usage data" placeholder

## M10-05a: Wire usage bars to live data

Connect usage bars to Tauri `get_usage` IPC command. Data flows: daemon poller -> cache -> HTTP API -> Tauri command -> Svelte store -> usage bars component.

- Scope: New (wire)
- Complexity: Moderate
- Depends: M10-05, M10-01
- Acceptance:
  - [ ] Usage data from daemon cache, not computed locally
  - [ ] Updates when poller refreshes data
  - [ ] Zero mock data in production path

## M10-06: Build token health component

Per-account token status: healthy (green dot), expiring soon (yellow), expired (red), missing (gray). Shows time until expiry. Last refresh timestamp.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Color coding matches health status
  - [ ] "Expires in 3h 42m" countdown
  - [ ] "Expired 15m ago" for dead tokens
  - [ ] "Re-login required" for broker-failed accounts

## M10-07: Wire token health to live data

Connect to Tauri `get_token_status` command. Real-time updates from daemon's refresher subsystem.

- Scope: New (wire)
- Complexity: Trivial
- Depends: M10-06, M10-01
- Acceptance:
  - [ ] Token status from daemon, not computed locally
  - [ ] Updates when daemon refreshes a token

## M10-08: Build OAuth login flow UI

"Add Account" button initiates PKCE flow via Tauri command. Opens system browser for Anthropic authorization. Shows "Waiting for authorization..." state. On callback success: account appears in list. On failure: error message.

- Scope: New
- Complexity: Complex
- Depends: M9-03, M9-04
- Acceptance:
  - [ ] Browser opens to correct authorize URL
  - [ ] Waiting state shown with cancel option
  - [ ] Success: new account appears immediately
  - [ ] Failure: actionable error message

## M10-09: Build system tray

macOS menu bar / Linux tray / Windows tray icon. Menu items: account list with status, quick-swap (click account to make active), "Open Dashboard", separator, "Quit". Account status icons: green (healthy), yellow (expiring), red (needs login).

- Scope: New
- Complexity: Complex
- Acceptance:
  - [ ] Tray icon appears on launch
  - [ ] All accounts listed with status
  - [ ] Quick-swap changes active account
  - [ ] "Open Dashboard" opens/focuses webview window
  - [ ] "Quit" triggers graceful shutdown

## M10-10: Wire system tray to daemon

Tray menu populated from daemon's account cache. Quick-swap calls `swap_to()` via daemon IPC. Tray updates reactively when daemon state changes (token refresh, usage update).

- Scope: New (wire)
- Complexity: Moderate
- Depends: M10-09, M8-10
- Acceptance:
  - [ ] Tray reflects current daemon state
  - [ ] Quick-swap completes within 200ms
  - [ ] Tray updates after token refresh

## M10-11: Build dashboard layout and navigation

App shell: sidebar navigation (Accounts, Settings), main content area, header with app title + daemon status indicator. System font stack. Relative CSS units.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Layout renders correctly at various window sizes
  - [ ] Navigation between views works
  - [ ] Daemon status: green dot (running), red dot (stopped)

## M10-12: Build Tauri auto-update

Ed25519 signed update manifests via `tauri-plugin-updater`. Check on launch + daily interval. Download, verify signature, atomic replace.

- Scope: New
- Complexity: Moderate
- Acceptance:
  - [ ] Update check on launch
  - [ ] Signature verification before install
  - [ ] User prompted before update (not silent)

## M10-13: Svelte component tests

Vitest + testing-library tests for all components. Account list with mock data. Usage bars with edge cases. Token health with various states.

- Scope: Phase 3 test strategy
- Complexity: Moderate
- Acceptance:
  - [ ] All components have tests
  - [ ] Edge cases covered (empty, expired, error)
