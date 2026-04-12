mod commands;
mod daemon_supervisor;

use csq_core::accounts::discovery;
use csq_core::credentials::{self, file as cred_file};
use csq_core::oauth::OAuthStateStore;
use csq_core::quota::{state as quota_state, QuotaFile};
use csq_core::rotation;
use csq_core::types::AccountNum;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use tauri_plugin_autostart::MacosLauncher;

use daemon_supervisor::SupervisorHandle;

// ── Tray icon assets ──────────────────────────────────────
//
// Compile-time embed of the three tray icon variants generated
// from the Terrene Foundation TF monogram favicon. We ship the
// **@2x (64x64) PNGs** as the canonical tray icon and let macOS
// AppKit downscale to the menu bar height with its high-quality
// filter. Sampling 22 logical points from a 64-pixel source
// produces a visibly crisper result on retina displays than
// starting from a 32-pixel source — the downscale path preserves
// more edge detail than the upscale path does.
//
// Tauri's `Image::from_bytes` decodes RGBA at the encoded pixel
// dimensions and reports that as the logical size. AppKit's
// NSImage then scales it to the tray slot. If Tauri ever exposes
// an NSImage representation-list API (multiple `NSBitmapImageRep`
// instances sharing a single NSImage), we can pass both the 32
// and 64 PNGs and AppKit will pick the best fit per display —
// for now, 64-source-with-downscale is the best we can do with
// the single-Image API.
//
// Normal is a white/near-white glyph with transparency — loaded as
// a template image on macOS so the OS auto-inverts for dark vs
// light menu bars. Warn and error are full-color (amber / red) and
// are NOT template images, because the whole point is that the
// color communicates the state.
const TRAY_NORMAL_PNG: &[u8] = include_bytes!("../icons/tray-normal@2x.png");
const TRAY_WARN_PNG: &[u8] = include_bytes!("../icons/tray-warn@2x.png");
const TRAY_ERROR_PNG: &[u8] = include_bytes!("../icons/tray-error@2x.png");

/// Which tray icon to show for a given `TrayHealth` rollup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayIconKind {
    /// White/near-white glyph; macOS template image.
    Normal,
    /// Amber glyph; full color (not a template image).
    Warn,
    /// Red glyph; full color (not a template image).
    Error,
}

impl TrayIconKind {
    /// Returns the packed PNG bytes for this variant (64x64
    /// source, for retina-friendly downscaling).
    fn bytes(self) -> &'static [u8] {
        match self {
            TrayIconKind::Normal => TRAY_NORMAL_PNG,
            TrayIconKind::Warn => TRAY_WARN_PNG,
            TrayIconKind::Error => TRAY_ERROR_PNG,
        }
    }

    /// macOS template mode — the OS auto-inverts template images
    /// for dark/light menu bars. Only the normal (near-white) glyph
    /// benefits; warn/error want their colors preserved.
    fn is_template(self) -> bool {
        matches!(self, TrayIconKind::Normal)
    }
}

/// State shared with Tauri commands.
///
/// Holds the PKCE state store for in-flight Claude OAuth logins.
/// Anthropic's current OAuth flow for the Claude Code client_id is
/// paste-code — the user authorizes in a browser, receives a code
/// on-screen, and pastes it back into the desktop app. That means
/// there is **no TCP callback listener**; the `start_claude_login`
/// command returns a paste-code URL the frontend opens, and
/// `submit_oauth_code` consumes the pending state + verifier from
/// this store to exchange the code for a token pair.
///
/// Also holds the in-process daemon supervisor handle so the exit
/// hook can shut it down cleanly. The handle is wrapped in a Mutex
/// because we need interior mutability (to `take` it on the single
/// RunEvent::Exit) from inside an immutable `tauri::State` borrow.
pub struct AppState {
    pub oauth_store: Arc<OAuthStateStore>,
    pub daemon_supervisor: Mutex<Option<SupervisorHandle>>,
}

/// Maximum length of an account label shown in the tray.
const MAX_LABEL_LEN: usize = 64;

/// Returns the base directory for csq state — `~/.claude/accounts`.
///
/// Honors the `CSQ_BASE_DIR` environment variable for testing.
fn base_dir() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("CSQ_BASE_DIR") {
        return Some(PathBuf::from(override_path));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".claude").join("accounts"))
}

/// Sanitizes a label for display in the tray menu.
///
/// Strips control characters and Unicode bidirectional overrides
/// (homograph attack vector) and caps length. Labels come from
/// `profiles.json`, which is user-writable — a misbehaving tool
/// could inject newlines, ANSI-like sequences, or RTL overrides
/// that mangle the menu rendering.
fn sanitize_label(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| {
            !c.is_control()
                // Bidirectional overrides: LRO, RLO, LRE, RLE, PDF, LRI, RLI, FSI, PDI
                && !matches!(
                    *c,
                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                )
        })
        .take(MAX_LABEL_LEN)
        .collect();
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

/// Returns the config-N directory whose `.credentials.json` was
/// most recently modified, where `N` is a valid account number
/// (1..=999).
///
/// **Why `.credentials.json` mtime, not dir mtime**: directory
/// mtime changes only on child entry creation/deletion/rename. A
/// user actively using `config-5` (reading the file, modifying
/// in-place state) would NOT bump the dir's mtime, so a dir-mtime
/// heuristic picks whichever dir had a credential rotated last in
/// an auto-refresh sweep — not the dir the user's terminal is on.
/// The `.credentials.json` file itself is rewritten via
/// `atomic_replace` on every token refresh and login, and those
/// writes happen against the specific active dir.
///
/// Tray quick-swap targets only ONE config dir — retargeting every
/// live session at once is destructive and silent. Picking the
/// most-recently-rewritten credential approximates "the session
/// the user is actively using" without needing `CLAUDE_CONFIG_DIR`
/// (which GUI-launched apps don't inherit).
///
/// Rejects:
/// * Non-directories
/// * Symlinks (could redirect writes outside base_dir)
/// * Names not matching `config-<1..=999>`
/// * Directories with no readable `.credentials.json`
fn most_recent_config_dir(base: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(base).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;

    for entry in entries.flatten() {
        // Reject symlinks via `file_type()` which does NOT follow.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }

        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };

        // Must match `config-<1..=999>` exactly.
        let Some(num_str) = name.strip_prefix("config-") else {
            continue;
        };
        let Ok(n) = num_str.parse::<u16>() else {
            continue;
        };
        if !(1..=999).contains(&n) {
            continue;
        }

        // Signal: mtime of `{dir}/.credentials.json`, which is
        // rewritten via atomic_replace on every refresh/login.
        // Dirs without a credentials file are skipped entirely —
        // they're not live sessions.
        let path = entry.path();
        let cred_path = path.join(".credentials.json");
        let Ok(meta) = std::fs::metadata(&cred_path) else {
            continue;
        };
        let Ok(mtime) = meta.modified() else { continue };

        match best.as_ref() {
            None => best = Some((mtime, path)),
            Some((t, _)) if mtime > *t => best = Some((mtime, path)),
            _ => {}
        }
    }

    best.map(|(_, path)| path)
}

/// Builds the tray menu from the current account list.
///
/// Menu layout:
///   #{id} {label}  ← one row per account (no active checkmark —
///                    see note below)
///   ---
///   Open Dashboard
///   Hide Dashboard
///   ---
///   Quit csq
///
/// No checkmark is shown for an "active" account because the
/// desktop app has no single active session — each live config-*
/// dir has its own active account, and `CLAUDE_CONFIG_DIR` is not
/// set in a GUI-launched Tauri process, so there is no unambiguous
/// signal to choose. The tray action is a "quick-swap" that
/// retargets *all* live config dirs to the clicked account.
fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let mut builder = MenuBuilder::new(app);

    // Show account status (read-only) — quota at a glance without
    // opening the dashboard. No swap action — use Sessions tab for that.
    if let Some(base) = base_dir() {
        if base.is_dir() {
            let accounts = discovery::discover_all(&base);
            let quota = csq_core::quota::state::load_state(&base)
                .unwrap_or_else(|_| csq_core::quota::QuotaFile::empty());
            let mut had_any = false;
            for a in &accounts {
                if !a.has_credentials {
                    continue;
                }
                had_any = true;
                let q = quota.get(a.id);
                let fh = q.map(|q| q.five_hour_pct()).unwrap_or(0.0);
                let sd = q.map(|q| q.seven_day_pct()).unwrap_or(0.0);
                let label = format!(
                    "#{} {}  5h:{:.0}%  7d:{:.0}%",
                    a.id,
                    sanitize_label(&a.label),
                    fh,
                    sd,
                );
                // Use "info:" prefix so click handler knows this is status-only
                let id = format!("info:{}", a.id);
                let item = MenuItemBuilder::with_id(id, label)
                    .enabled(false)
                    .build(app)?;
                builder = builder.item(&item);
            }
            if had_any {
                builder = builder.item(&PredefinedMenuItem::separator(app)?);
            }
        }
    }

    let open_dashboard = MenuItemBuilder::with_id("open", "Open Dashboard").build(app)?;
    let hide_dashboard = MenuItemBuilder::with_id("hide", "Hide Dashboard").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit csq").build(app)?;

    builder
        .item(&open_dashboard)
        .item(&hide_dashboard)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&quit)
        .build()
}

/// Coarse health of the full account set, rolled up for the tray
/// tooltip and icon variant.
///
/// The tray icon updates every 30s via `refresh_tray_menu` along with
/// the tooltip. Three icon variants are available: normal (white
/// template), warn (amber), and error (red). `TrayStatus::icon_kind`
/// maps health to the correct variant, and `apply_tray_icon` sets the
/// icon on the tray handle. A user with 8 accounts can see at a glance
/// whether any account needs attention without opening the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TrayHealth {
    /// No accounts with credentials, or no `credentials/` dir.
    Empty,
    /// Every account is healthy: token not expiring within 2h and
    /// `five_hour_pct` < 100.
    Healthy,
    /// At least one account's access token is expiring within 2h or
    /// already expired.
    Expiring { count: usize },
    /// At least one account is at 100% of its 5h quota. This takes
    /// precedence over expiring because out-of-quota blocks use
    /// today whereas expiring resolves automatically on refresh.
    OutOfQuota { count: usize },
}

/// Aggregate status summary for the tray.
#[derive(Debug, Clone)]
struct TrayStatus {
    /// Number of accounts that have readable credentials. Shown in
    /// the tooltip as "N of M account(s)".
    total: usize,
    /// Rolled-up health used to pick the tooltip wording. The
    /// `Expiring` and `OutOfQuota` variants carry their own count
    /// fields, so the outer struct does not duplicate them.
    health: TrayHealth,
}

impl TrayStatus {
    /// Which icon variant to show for this rollup.
    ///
    /// Empty and Healthy → normal (template image, adapts to
    /// menu-bar theme). Expiring → warn (amber). OutOfQuota →
    /// error (red). The mapping mirrors `TrayHealth`'s precedence
    /// rules: out-of-quota blocks work today and wins over
    /// expiring, which resolves automatically on refresh.
    fn icon_kind(&self) -> TrayIconKind {
        match self.health {
            TrayHealth::Empty | TrayHealth::Healthy => TrayIconKind::Normal,
            TrayHealth::Expiring { .. } => TrayIconKind::Warn,
            TrayHealth::OutOfQuota { .. } => TrayIconKind::Error,
        }
    }

    /// Human-readable tooltip string shown when the user hovers the
    /// tray icon. Tooltip format intentionally starts with "csq" so
    /// the app is identifiable before the status summary.
    fn tooltip(&self) -> String {
        match &self.health {
            TrayHealth::Empty => "csq — no accounts configured".to_string(),
            TrayHealth::Healthy => {
                format!("csq — {} account(s) healthy", self.total)
            }
            TrayHealth::Expiring { count } => {
                format!("csq — {count} of {} account(s) token expiring", self.total)
            }
            TrayHealth::OutOfQuota { count } => {
                format!("csq — {count} of {} account(s) out of 5h quota", self.total)
            }
        }
    }
}

/// Rolls up the current account/credential/quota state into a
/// single `TrayStatus` for the tooltip.
///
/// Uses the same discovery + credentials + quota primitives that
/// `commands::get_accounts` uses, so the tray tooltip and the
/// dashboard window always agree on what "healthy" means.
///
/// Unit-tested via a tmpdir because pointing this at the real
/// `~/.claude/accounts` would make tests order-dependent on every
/// developer's machine.
fn compute_tray_status(base: &Path) -> TrayStatus {
    let accounts = discovery::discover_anthropic(base);
    let quota: QuotaFile = quota_state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut total = 0usize;
    let mut expiring = 0usize;
    let mut out_of_quota = 0usize;

    for info in &accounts {
        if !info.has_credentials {
            continue;
        }
        let Ok(num) = AccountNum::try_from(info.id) else {
            continue;
        };
        total += 1;

        let canonical = cred_file::canonical_path(base, num);
        if let Ok(creds) = credentials::load(&canonical) {
            let exp_ms = creds.claude_ai_oauth.expires_at;
            let secs = exp_ms as i64 - now_ms as i64;
            // "Expiring" matches `commands::get_accounts` — anything
            // expired or within 2h (7200s) of expiry.
            if secs <= 0 || creds.claude_ai_oauth.is_expired_within(7200) {
                expiring += 1;
            }
        }

        if let Some(q) = quota.get(info.id) {
            if q.five_hour_pct() >= 100.0 {
                out_of_quota += 1;
            }
        }
    }

    let health = if total == 0 {
        TrayHealth::Empty
    } else if out_of_quota > 0 {
        TrayHealth::OutOfQuota {
            count: out_of_quota,
        }
    } else if expiring > 0 {
        TrayHealth::Expiring { count: expiring }
    } else {
        TrayHealth::Healthy
    };

    TrayStatus { total, health }
}

/// Returns true if the given slot number resolves to a third-party
/// provider binding under `base`. Reads the live discovery so the
/// tray click handler's routing decision always matches the
/// dashboard view — a slot that was OAuth at boot but got rebound
/// to a 3P provider mid-session is correctly routed.
fn is_third_party_slot(base: &Path, slot: u16) -> bool {
    let accounts = discovery::discover_all(base);
    accounts.iter().any(|a| {
        a.id == slot
            && matches!(
                a.source,
                csq_core::accounts::AccountSource::ThirdParty { .. }
            )
    })
}

/// Outcome of a tray swap click emitted as `tray-swap-complete`.
#[derive(serde::Serialize, Clone)]
struct TraySwapResult {
    account: u16,
    /// The config dir that was retargeted, if any.
    config_dir: Option<String>,
    /// `true` on success; `false` if no dir found or swap failed.
    ok: bool,
    /// Human-readable error if `ok == false`.
    error: Option<String>,
}

/// Performs the blocking swap work for a tray `acct:{id}` click.
///
/// Retargets the **single most recently modified** `config-N` dir
/// to the clicked account. Running on a tokio `spawn_blocking`
/// worker — MUST not be invoked from the Tauri main thread.
///
/// # Why one dir, not all
///
/// Retargeting every live `config-*` dir would silently collapse a
/// multi-session workflow (5 CC sessions on 5 accounts → all on
/// one account) with no confirmation. The most-recently-modified
/// dir approximates "the session the user is actively using" and
/// matches the intent of a tray quick-switch.
fn perform_tray_swap(base: &Path, account: AccountNum) -> TraySwapResult {
    // 3P slots (e.g. MiniMax, Z.AI) use settings.json for provider
    // config, not OAuth credential files. `rotation::swap_to` only
    // knows how to copy `credentials/N.json` into `.credentials.json`
    // — calling it on a 3P slot fails with NotFound at best and
    // corrupts the target config dir at worst. Short-circuit with
    // a dashboard-directing error toast instead.
    //
    // This check runs against a fresh `discover_all` read so the
    // routing logic always reflects the current slot → provider
    // binding, even if the user just added a new 3P slot between
    // menu builds.
    if is_third_party_slot(base, account.get()) {
        return TraySwapResult {
            account: account.get(),
            config_dir: None,
            ok: false,
            error: Some("3P slots can only be swapped from the dashboard Sessions tab".into()),
        };
    }

    let target_dir = match most_recent_config_dir(base) {
        Some(d) => d,
        None => {
            log::warn!(
                "tray swap: no live config-N dir under {} — start a CC session first",
                base.display()
            );
            return TraySwapResult {
                account: account.get(),
                config_dir: None,
                ok: false,
                error: Some("no live CC session found".into()),
            };
        }
    };

    match rotation::swap_to(base, &target_dir, account) {
        Ok(res) => {
            log::info!(
                "tray swap ok: account {} -> {}",
                res.account,
                target_dir.display()
            );
            TraySwapResult {
                account: account.get(),
                config_dir: Some(target_dir.display().to_string()),
                ok: true,
                error: None,
            }
        }
        Err(e) => {
            log::warn!(
                "tray swap failed: account {} -> {}: {}",
                account,
                target_dir.display(),
                e
            );
            TraySwapResult {
                account: account.get(),
                config_dir: Some(target_dir.display().to_string()),
                ok: false,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Serialization guard for tray clicks — atomic "is a swap in
/// flight?" flag. Prevents concurrent tray clicks from racing each
/// other's writes to the same config dir. A click arriving while
/// another swap is in-flight is dropped with a log line (not
/// queued — queuing leads to confusing "which click won?" UX).
static SWAP_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Handles a tray menu click.
///
/// Account rows dispatch the swap work to a `spawn_blocking` worker
/// so the Tauri main thread (UI, tray rendering) stays responsive.
/// Concurrent clicks are serialized via `SWAP_IN_FLIGHT` — a
/// subsequent click while a swap is running is dropped to avoid
/// non-deterministic writes.
fn handle_tray_event(app: &AppHandle, id: &str) {
    match id {
        "open" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }
        "hide" => {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.hide();
            }
        }
        "quit" => {
            app.exit(0);
        }
        s if s.starts_with("acct:") => {
            let Some(num_str) = s.strip_prefix("acct:") else {
                return;
            };
            let Ok(n) = num_str.parse::<u16>() else {
                return;
            };
            let Ok(account) = AccountNum::try_from(n) else {
                return;
            };
            let Some(base) = base_dir() else { return };

            // Serialize: drop the click if another swap is in
            // flight. Release-ordered CAS so only one worker runs.
            use std::sync::atomic::Ordering;
            if SWAP_IN_FLIGHT
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                log::warn!(
                    "tray click ignored: account {} — another swap is in flight",
                    n
                );
                return;
            }

            let app_handle = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                // RAII guard so the flag always clears, even on
                // panic inside perform_tray_swap.
                struct ClearFlag;
                impl Drop for ClearFlag {
                    fn drop(&mut self) {
                        SWAP_IN_FLIGHT.store(false, Ordering::Release);
                    }
                }
                let _clear = ClearFlag;

                let result = perform_tray_swap(&base, account);
                if let Err(e) = app_handle.emit("tray-swap-complete", &result) {
                    log::warn!("failed to emit tray-swap-complete: {e}");
                }
            });
        }
        _ => {}
    }
}

/// Applies an icon variant + its template-image mode to the tray.
///
/// Separated out from `refresh_tray_menu` so failures to load or
/// set either of the two independent properties (icon bytes,
/// template flag) produce a single cohesive log line with the
/// intended `TrayIconKind` for forensic context.
///
/// On Windows and Linux the template-image flag is a no-op at the
/// platform layer — Tauri's API accepts the call everywhere but
/// only macOS acts on it.
fn apply_tray_icon(tray: &TrayIcon, kind: TrayIconKind) {
    match Image::from_bytes(kind.bytes()) {
        Ok(image) => {
            if let Err(e) = tray.set_icon(Some(image)) {
                log::warn!("failed to set tray icon for {kind:?}: {e}");
                return;
            }
        }
        Err(e) => {
            log::warn!("failed to decode tray icon png for {kind:?}: {e}");
            return;
        }
    }
    if let Err(e) = tray.set_icon_as_template(kind.is_template()) {
        log::warn!("failed to set tray template mode for {kind:?}: {e}");
    }
}

/// Rebuilds the tray menu and refreshes the tooltip + icon status.
///
/// Called on a 30s interval so the tray reflects account additions,
/// deletions, active-session changes from the CLI, and token/quota
/// status transitions.
///
/// Three things update on every tick:
/// 1. The menu item list (accounts discovered under `~/.claude/
///    accounts`).
/// 2. The tooltip text (aggregate status summary).
/// 3. The tray icon variant (normal / warn / error, matching
///    `TrayStatus::icon_kind`).
fn refresh_tray_menu(app: &AppHandle, tray: &TrayIcon) {
    if let Ok(menu) = build_tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
    if let Some(base) = base_dir() {
        let status = compute_tray_status(&base);
        // `set_tooltip` returns `Result<()>`; a failure here only
        // means the platform tray handle is gone, which also
        // silently breaks the menu — nothing more to do than log.
        if let Err(e) = tray.set_tooltip(Some(&status.tooltip())) {
            log::warn!("failed to set tray tooltip: {e}");
        }
        apply_tray_icon(tray, status.icon_kind());
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // `tauri-plugin-autostart` registers the app with the OS login
    // service on each target platform. The `MacosLauncher::LaunchAgent`
    // variant is the right choice for a menu-bar app: it installs a
    // `~/Library/LaunchAgents/<bundle-id>.plist` that launches the
    // app at user login. Windows uses a `HKCU\...\Run` registry key;
    // Linux uses `~/.config/autostart/<bundle-id>.desktop`. All of
    // those are unified behind the plugin's get/enable/disable API.
    //
    // The initial `args` slice is empty because launch-on-login
    // should NOT open the main window automatically — the tray keeps
    // the app alive silently, and the user clicks the tray icon to
    // open the dashboard when they need it.
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        .invoke_handler(tauri::generate_handler![
            commands::get_accounts,
            commands::swap_account,
            commands::rename_account,
            commands::get_rotation_config,
            commands::set_rotation_enabled,
            commands::get_daemon_status,
            commands::list_providers,
            commands::begin_claude_login,
            commands::submit_oauth_code,
            commands::cancel_login,
            commands::start_claude_login,
            commands::set_provider_key,
            commands::list_sessions,
            commands::swap_session,
            commands::get_autostart_enabled,
            commands::set_autostart_enabled,
        ])
        .setup(|app| {
            // ── Logging ────────────────────────────────────────
            //
            // Two independent logging facades coexist:
            //
            // 1. **tracing** — csq-core emits via `tracing::warn!`
            //    etc. A `tracing_subscriber::fmt` subscriber
            //    writes those events to stderr filtered by
            //    `CSQ_LOG` (default: `warn`).
            //
            // 2. **log** — `tauri-plugin-log` claims the `log`
            //    facade for tray-click errors and plugin
            //    lifecycle messages. Output goes to the OS app-
            //    data log dir (Console.app on macOS, etc.).
            //
            // **Critical**: `tracing-subscriber`'s default
            // features include `tracing-log`, which would make
            // `try_init()` silently call `log::set_logger`. That
            // then collides with `tauri-plugin-log`'s own
            // `set_boxed_logger` and panics the app at startup.
            // The workspace `tracing-subscriber` dep is
            // configured with `default-features = false` +
            // explicit `fmt`/`env-filter`/`std`/`ansi`/`smallvec`
            // to avoid this collision. See Cargo.toml.
            let filter = tracing_subscriber::EnvFilter::try_from_env("CSQ_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();

            let log_level = if cfg!(debug_assertions) {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Info
            };
            app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log_level)
                    .build(),
            )?;

            // ── OAuth state store ────────────────────────────
            //
            // Anthropic's current Claude Code OAuth flow is
            // paste-code: the user authorizes in a browser,
            // Anthropic shows a code on-screen, the user pastes it
            // back into the desktop app, and the app exchanges it
            // at the token endpoint. There is no TCP callback
            // listener — only an in-memory PKCE state store keyed
            // by the per-login state token. That store is shared
            // between `start_claude_login` (which inserts a pending
            // entry) and `submit_oauth_code` (which consumes it and
            // performs the exchange).
            let oauth_store = Arc::new(OAuthStateStore::new());

            // ── In-process daemon supervisor ─────────────────
            //
            // Starts the csq daemon (refresher + usage poller +
            // auto-rotate + IPC server) inside the Tauri process so
            // tokens stay refreshed for as long as the desktop app
            // is running. Without this, the user's only option is
            // `csq daemon start` in a terminal — and journal 0026
            // shows what happens when they forget (every OAuth
            // account expired for 6–80 hours).
            //
            // The supervisor cohabits with an existing external
            // daemon gracefully: if a `csq daemon start` is already
            // running, the supervisor's PidFile::acquire fails and
            // it falls back to observing. It takes over only when
            // the external daemon exits.
            let supervisor = base_dir().map(daemon_supervisor::start);
            if supervisor.is_none() {
                log::warn!(
                    "base_dir not available — in-process daemon \
                     supervisor skipped; tokens will not auto-refresh"
                );
            }

            app.manage(AppState {
                oauth_store,
                daemon_supervisor: Mutex::new(supervisor),
            });

            // ── System tray ──────────────────────────────────
            //
            // Initial tooltip + icon are both computed from the
            // account set so the first hover on a just-launched
            // app already shows live status (e.g. "7 accounts
            // healthy") and the menu bar already reflects whether
            // anything needs attention. Without this the tooltip
            // would say "csq" and the icon would stay neutral
            // until the 30s refresh ticker first fires.
            let (initial_tooltip, initial_icon_kind) = match base_dir() {
                Some(b) => {
                    let status = compute_tray_status(&b);
                    (status.tooltip(), status.icon_kind())
                }
                None => ("csq".to_string(), TrayIconKind::Normal),
            };
            let initial_image = Image::from_bytes(initial_icon_kind.bytes())?;
            let menu = build_tray_menu(app.handle())?;
            let tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip(&initial_tooltip)
                .icon(initial_image)
                .icon_as_template(initial_icon_kind.is_template())
                .on_menu_event(move |app, event| {
                    handle_tray_event(app, event.id().as_ref());
                })
                .build(app)?;

            // Refresh the tray menu every 30s so account changes
            // made from the CLI show up without restarting the app.
            //
            // `MissedTickBehavior::Skip` prevents the ticker from
            // firing N catch-up ticks when the process wakes from
            // laptop sleep — we only ever want the next scheduled
            // tick after a gap, not a burst of 20 catch-ups.
            let app_handle = app.handle().clone();
            let tray_handle = tray.clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // First tick fires immediately; skip it since we
                // just built the menu synchronously above.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    refresh_tray_menu(&app_handle, &tray_handle);
                }
            });

            // Hide window on close instead of quitting (tray keeps app alive)
            if let Some(window) = app.get_webview_window("main") {
                let w = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = w.hide();
                    }
                });
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // On app exit, shut down the in-process daemon
            // supervisor. The subsystem cancellation tokens propagate
            // through the refresher, usage poller, and auto-rotator,
            // each of which has a 5s drain deadline in run_daemon.
            //
            // We `take()` the handle out of the Mutex so a stray
            // second Exit event (shouldn't happen, but Tauri doesn't
            // promise single-delivery across all platforms) doesn't
            // double-cancel an already-dropped token.
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    if let Ok(mut guard) = state.daemon_supervisor.lock() {
                        if let Some(handle) = guard.take() {
                            log::info!("app exiting — cancelling in-process daemon");
                            handle.shutdown();
                        }
                    }
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    // ── sanitize_label ──────────────────────────────────────

    #[test]
    fn sanitize_label_strips_control_chars() {
        assert_eq!(sanitize_label("alice\nbob"), "alicebob");
        assert_eq!(sanitize_label("a\tb\rc"), "abc");
        assert_eq!(sanitize_label("x\u{0}y"), "xy");
    }

    #[test]
    fn sanitize_label_strips_bidi_overrides() {
        // U+202E is Right-to-Left Override (homograph attack)
        assert_eq!(
            sanitize_label("gro.eniRrreT\u{202E}@alice"),
            "gro.eniRrreT@alice"
        );
        // U+2066..=U+2069 are isolates
        assert_eq!(sanitize_label("a\u{2066}b\u{2069}c"), "abc");
        // U+202A..=U+202D are other bidi controls
        assert_eq!(sanitize_label("a\u{202A}b\u{202B}c\u{202C}d"), "abcd");
    }

    #[test]
    fn sanitize_label_caps_length() {
        let long = "x".repeat(200);
        let out = sanitize_label(&long);
        assert_eq!(out.chars().count(), MAX_LABEL_LEN);
    }

    #[test]
    fn sanitize_label_empty_returns_placeholder() {
        assert_eq!(sanitize_label(""), "unknown");
        // Also when everything gets stripped.
        assert_eq!(sanitize_label("\n\r\t"), "unknown");
    }

    #[test]
    fn sanitize_label_preserves_normal_unicode() {
        assert_eq!(sanitize_label("alice@example.com"), "alice@example.com");
        // Non-ASCII but not a control/bidi char.
        assert_eq!(sanitize_label("Ålice"), "Ålice");
    }

    // ── most_recent_config_dir ──────────────────────────────

    fn touch_credentials(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(".credentials.json"), b"{}").unwrap();
    }

    #[test]
    fn most_recent_picks_newest_credentials_mtime() {
        let base = TempDir::new().unwrap();
        touch_credentials(&base.path().join("config-1"));
        thread::sleep(Duration::from_millis(20));
        touch_credentials(&base.path().join("config-2"));
        thread::sleep(Duration::from_millis(20));
        touch_credentials(&base.path().join("config-3"));

        let result = most_recent_config_dir(base.path()).unwrap();
        assert_eq!(result.file_name().unwrap(), "config-3");
    }

    #[test]
    fn most_recent_skips_dirs_without_credentials() {
        let base = TempDir::new().unwrap();
        fs::create_dir_all(base.path().join("config-1")).unwrap();
        touch_credentials(&base.path().join("config-2"));

        let result = most_recent_config_dir(base.path()).unwrap();
        assert_eq!(result.file_name().unwrap(), "config-2");
    }

    #[test]
    fn most_recent_rejects_out_of_range_numbers() {
        let base = TempDir::new().unwrap();
        touch_credentials(&base.path().join("config-0"));
        touch_credentials(&base.path().join("config-1000"));

        assert!(most_recent_config_dir(base.path()).is_none());
    }

    #[test]
    fn most_recent_rejects_non_numeric_suffix() {
        let base = TempDir::new().unwrap();
        touch_credentials(&base.path().join("config-abc"));
        touch_credentials(&base.path().join("config-"));

        assert!(most_recent_config_dir(base.path()).is_none());
    }

    #[test]
    fn most_recent_rejects_non_config_prefix() {
        let base = TempDir::new().unwrap();
        touch_credentials(&base.path().join("other-1"));
        touch_credentials(&base.path().join("xconfig-1"));

        assert!(most_recent_config_dir(base.path()).is_none());
    }

    #[test]
    fn most_recent_returns_none_on_empty_dir() {
        let base = TempDir::new().unwrap();
        assert!(most_recent_config_dir(base.path()).is_none());
    }

    #[test]
    fn most_recent_returns_none_when_base_missing() {
        let base = TempDir::new().unwrap();
        let missing = base.path().join("missing-dir");
        assert!(most_recent_config_dir(&missing).is_none());
    }

    #[test]
    #[cfg(unix)]
    fn most_recent_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let base = TempDir::new().unwrap();
        // Real dir outside base that we want to protect.
        let outside = TempDir::new().unwrap();
        touch_credentials(outside.path());

        // Create a symlink config-5 → outside. file_type() must NOT
        // follow the symlink, so this must be rejected.
        symlink(outside.path(), base.path().join("config-5")).unwrap();

        assert!(
            most_recent_config_dir(base.path()).is_none(),
            "symlinks must be rejected to prevent writes outside base_dir"
        );
    }

    // ── compute_tray_status ─────────────────────────────────

    /// Writes a credential file under `{base}/credentials/{id}.json`
    /// with `expiresAt` set `offset_secs` from "now". Use a positive
    /// offset for healthy/expiring, a negative offset for expired.
    fn write_credential(base: &Path, id: u16, offset_secs: i64) {
        let creds_dir = base.join("credentials");
        fs::create_dir_all(&creds_dir).unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let expires_at_ms = now_ms + offset_secs * 1000;
        let json = format!(
            r#"{{
                "claudeAiOauth": {{
                    "accessToken": "sk-ant-oat01-test-{id}",
                    "refreshToken": "sk-ant-ort01-test-{id}",
                    "expiresAt": {expires_at_ms},
                    "scopes": ["user:inference"]
                }}
            }}"#
        );
        fs::write(creds_dir.join(format!("{id}.json")), json).unwrap();
    }

    /// Writes a quota.json with `five_hour` usage for one account.
    fn write_quota(base: &Path, id: u16, five_hour_pct: f64) {
        // `resets_at` needs to be in the future so `clear_expired`
        // leaves the window intact during `load_state`. One hour
        // into the future is plenty — tests never sleep that long.
        let resets_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let json = format!(
            r#"{{
                "accounts": {{
                    "{id}": {{
                        "five_hour": {{
                            "used_percentage": {five_hour_pct},
                            "resets_at": {resets_at}
                        }},
                        "seven_day": null,
                        "updated_at": 0.0
                    }}
                }}
            }}"#
        );
        fs::write(base.join("quota.json"), json).unwrap();
    }

    #[test]
    fn tray_status_empty_when_no_credentials_dir() {
        let base = TempDir::new().unwrap();
        let status = compute_tray_status(base.path());
        assert_eq!(status.total, 0);
        assert_eq!(status.health, TrayHealth::Empty);
        assert!(status.tooltip().contains("no accounts"));
    }

    #[test]
    fn tray_status_empty_when_credentials_dir_has_no_files() {
        let base = TempDir::new().unwrap();
        fs::create_dir_all(base.path().join("credentials")).unwrap();
        let status = compute_tray_status(base.path());
        assert_eq!(status.total, 0);
        assert_eq!(status.health, TrayHealth::Empty);
    }

    #[test]
    fn tray_status_healthy_when_all_tokens_fresh_and_no_quota() {
        let base = TempDir::new().unwrap();
        // Expires in 24 hours — well outside the 2h "expiring"
        // buffer that matches `commands::get_accounts`.
        write_credential(base.path(), 1, 86_400);
        write_credential(base.path(), 2, 86_400);

        let status = compute_tray_status(base.path());
        assert_eq!(status.total, 2);
        assert_eq!(status.health, TrayHealth::Healthy);
        let tip = status.tooltip();
        assert!(tip.contains("2 account"), "tooltip was: {tip}");
        assert!(tip.contains("healthy"));
    }

    #[test]
    fn tray_status_expiring_when_token_within_two_hours() {
        let base = TempDir::new().unwrap();
        write_credential(base.path(), 1, 86_400);
        // Expires in 30 minutes — inside the 2h buffer.
        write_credential(base.path(), 2, 1_800);

        let status = compute_tray_status(base.path());
        assert_eq!(status.total, 2);
        assert_eq!(status.health, TrayHealth::Expiring { count: 1 });
        assert!(status.tooltip().contains("expiring"));
    }

    #[test]
    fn tray_status_expiring_counts_already_expired_tokens() {
        let base = TempDir::new().unwrap();
        write_credential(base.path(), 1, -3_600); // expired 1h ago

        let status = compute_tray_status(base.path());
        assert_eq!(status.health, TrayHealth::Expiring { count: 1 });
    }

    #[test]
    fn tray_status_out_of_quota_when_five_hour_is_100() {
        let base = TempDir::new().unwrap();
        write_credential(base.path(), 1, 86_400);
        write_quota(base.path(), 1, 100.0);

        let status = compute_tray_status(base.path());
        assert_eq!(status.health, TrayHealth::OutOfQuota { count: 1 });
        assert!(status.tooltip().contains("out of"));
    }

    #[test]
    fn tray_status_out_of_quota_takes_precedence_over_expiring() {
        let base = TempDir::new().unwrap();
        // Account 1 is expiring; account 2 is out of quota.
        // Out-of-quota should win the rollup because it blocks usage
        // today while expiring resolves automatically on refresh.
        write_credential(base.path(), 1, 1_800);
        write_credential(base.path(), 2, 86_400);
        write_quota(base.path(), 2, 100.0);

        let status = compute_tray_status(base.path());
        assert!(matches!(status.health, TrayHealth::OutOfQuota { count: 1 }));
    }

    #[test]
    fn tray_status_healthy_when_quota_below_hundred() {
        let base = TempDir::new().unwrap();
        write_credential(base.path(), 1, 86_400);
        write_quota(base.path(), 1, 99.9);

        let status = compute_tray_status(base.path());
        assert_eq!(status.health, TrayHealth::Healthy);
    }

    // ── icon_kind ───────────────────────────────────────────

    #[test]
    fn icon_kind_normal_for_empty_and_healthy() {
        let empty = TrayStatus {
            total: 0,
            health: TrayHealth::Empty,
        };
        assert_eq!(empty.icon_kind(), TrayIconKind::Normal);

        let healthy = TrayStatus {
            total: 3,
            health: TrayHealth::Healthy,
        };
        assert_eq!(healthy.icon_kind(), TrayIconKind::Normal);
    }

    #[test]
    fn icon_kind_warn_for_expiring() {
        let status = TrayStatus {
            total: 3,
            health: TrayHealth::Expiring { count: 2 },
        };
        assert_eq!(status.icon_kind(), TrayIconKind::Warn);
    }

    #[test]
    fn icon_kind_error_for_out_of_quota() {
        let status = TrayStatus {
            total: 3,
            health: TrayHealth::OutOfQuota { count: 1 },
        };
        assert_eq!(status.icon_kind(), TrayIconKind::Error);
    }

    #[test]
    fn icon_kind_template_only_for_normal() {
        assert!(TrayIconKind::Normal.is_template());
        assert!(!TrayIconKind::Warn.is_template());
        assert!(!TrayIconKind::Error.is_template());
    }

    // ── is_third_party_slot ────────────────────────────────

    fn write_slot_settings(base: &Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        fs::write(dir.join("settings.json"), json).unwrap();
    }

    #[test]
    fn is_third_party_slot_detects_minimax_per_slot_binding() {
        let base = TempDir::new().unwrap();
        write_slot_settings(base.path(), 9, "https://api.minimax.io/anthropic", "tok");
        assert!(is_third_party_slot(base.path(), 9));
    }

    #[test]
    fn is_third_party_slot_false_for_oauth_slot() {
        let base = TempDir::new().unwrap();
        // OAuth slot 1 with a credentials file.
        write_credential(base.path(), 1, 86_400);
        assert!(!is_third_party_slot(base.path(), 1));
    }

    #[test]
    fn is_third_party_slot_false_for_unknown_slot() {
        let base = TempDir::new().unwrap();
        assert!(!is_third_party_slot(base.path(), 42));
    }

    #[test]
    fn icon_bytes_are_non_empty_and_distinct() {
        let normal = TrayIconKind::Normal.bytes();
        let warn = TrayIconKind::Warn.bytes();
        let error = TrayIconKind::Error.bytes();
        assert!(normal.len() > 16);
        assert!(warn.len() > 16);
        assert!(error.len() > 16);
        // PNG magic (first 8 bytes)
        const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
        assert_eq!(&normal[..8], PNG_MAGIC);
        assert_eq!(&warn[..8], PNG_MAGIC);
        assert_eq!(&error[..8], PNG_MAGIC);
        // Variants must differ from each other (otherwise the icon
        // swap is a no-op and the regression would be invisible).
        assert_ne!(normal, warn);
        assert_ne!(warn, error);
        assert_ne!(normal, error);
    }
}
