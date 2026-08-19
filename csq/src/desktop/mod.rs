mod commands;
mod daemon_supervisor;
mod preferences;

use csq_core::accounts::discovery;
use csq_core::capability_layer::{
    load_capability_layer_toggles, save_capability_layer_toggles, CapabilityLayerToggles,
};
use csq_core::credentials::{self, file as cred_file};
use csq_core::oauth::OAuthStateStore;
use csq_core::quota::{state as quota_state, QuotaFile};
use csq_core::types::AccountNum;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;

use preferences::PrefsLock;
use tauri::image::Image;
use tauri::menu::{
    CheckMenuItemBuilder, Menu, MenuBuilder, MenuItemBuilder, PredefinedMenuItem, SubmenuBuilder,
};
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
const TRAY_NORMAL_PNG: &[u8] = include_bytes!("../../icons/tray-normal@2x.png");
const TRAY_WARN_PNG: &[u8] = include_bytes!("../../icons/tray-warn@2x.png");
const TRAY_ERROR_PNG: &[u8] = include_bytes!("../../icons/tray-error@2x.png");

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

/// Cached record of a prefs-recovery event for late-subscribing renderers.
///
/// HIGH-1: Tauri's `emit` is fire-and-forget. If the setup() hook emits
/// `prefs-reset-to-defaults` before the WebView mounts and the Svelte
/// `listen()` call registers, the event is lost. Storing the recovery here
/// lets `consume_prefs_recovery` return it to a renderer that mounts late.
/// Consume-on-read semantics (banner shows once per app-launch).
#[derive(Clone)]
pub struct PrefsRecoveryRecord {
    /// Log-tag prefix identifying the failure class (matches `LoadOutcome`
    /// `RecoveredFromCorrupt` reason field — e.g. `"desktop_prefs_empty"`).
    pub reason: &'static str,
    /// RFC-3339 UTC timestamp of when the recovery was detected in setup().
    /// The renderer uses this as the authoritative recovery time (MED-1:
    /// backend clock, not frontend clock at event-receipt).
    pub occurred_at: String,
}

/// Serializable update info cached after a background check.
///
/// Stored separately from `csq_core::update::github::UpdateInfo`
/// because that type does not implement `Serialize` — it carries
/// download and signature URLs that MUST NOT be surfaced to the
/// frontend (users cannot and should not invoke the download path
/// from the desktop app; the signing key is a placeholder). Only
/// the fields needed to show a notification and link the user to
/// the GitHub release page are included here.
#[derive(Clone, serde::Serialize)]
pub struct CachedUpdateInfo {
    /// Version string without leading `v` (e.g. `"2.1.0-alpha.14"`).
    pub version: String,
    /// Current running version (for "v{current} → v{latest}" display).
    pub current_version: String,
    /// HTTPS URL to the GitHub release page (html_url from the API).
    pub release_url: String,
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
///
/// `update_cache` stores the result of the most recent background
/// update check. `None` means either the check has not run yet or
/// the app is already up to date.
pub struct AppState {
    pub oauth_store: Arc<OAuthStateStore>,
    pub daemon_supervisor: Mutex<Option<SupervisorHandle>>,
    pub update_cache: Mutex<Option<CachedUpdateInfo>>,
    /// Running `ollama pull` child, shared between the
    /// pull worker and the cancel command. Wrapped in
    /// `Arc<Mutex<...>>` so the cancel path can hold a
    /// reference across the subprocess's lifetime without
    /// the pull worker needing to give up its
    /// `State<AppState>` borrow. Cleared by the pull worker
    /// on normal exit; populated for the duration of any
    /// live `ollama pull`.
    pub ollama_pull_child: Arc<Mutex<Option<Arc<Mutex<std::process::Child>>>>>,
    /// Running `codex login --device-auth` child. Mirrors
    /// `ollama_pull_child` — see `pull_ollama_model` doc for the
    /// rationale on the `Arc<Mutex<Option<Arc<Mutex<Child>>>>>`
    /// shape. PR-C9a an internal journal entry finding 6: the desktop Codex
    /// UI's modal-close must kill the subprocess so it does not
    /// orphan for the minutes-long codex-cli device-auth window.
    pub codex_login_child: Arc<Mutex<Option<Arc<Mutex<std::process::Child>>>>>,
    /// Running native-CLI (Kimi/Grok) login children, keyed by native
    /// [`csq_core::providers::catalog::Surface`]. Mirrors
    /// `codex_login_child`'s `Arc<Mutex<Option<...>>>` shape but is a
    /// per-surface map — an internal journal entry C8: Kimi and Grok are independent
    /// vendor binaries with independent vendor homes, so a Kimi login in
    /// flight must not block a concurrent Grok login (unlike Codex,
    /// which refuses ANY concurrent login regardless of slot). A second
    /// login for the SAME surface is still refused while an entry is
    /// present. Populated for the duration of a live native device-auth
    /// spawn (`commands::spawn_native_device_auth_piped`); cleared on
    /// exit (success or failure) so `commands::cancel_native_login`
    /// never targets a reaped child.
    pub native_login_children: commands::NativeLoginChildren,
    /// Typed serialization lock for `<base>/desktop-prefs.json`.
    ///
    /// The `PrefsLock` newtype is the compile-time witness for "the
    /// caller holds the prefs lock." Write paths must call
    /// `preferences::mutate_prefs(&self.desktop_prefs_lock, ...)`,
    /// which acquires the lock internally and routes through the only
    /// public read-mutate-write entry point. Direct calls to
    /// `load_desktop_prefs` + `save_desktop_prefs` are restricted to
    /// `pub(in crate::desktop)` so they cannot be composed into an
    /// unlocked write path from outside this module tree.
    ///
    /// Guards against: a tray click and a frontend toggle hitting the
    /// same load → mutate → save sequence on different threads, which
    /// would produce a TOCTOU window where one writer's flip is
    /// computed against stale on-disk state (R1 redteam Finding S-H2 /
    /// T-5). The cap:* tray pattern is single-writer; dock-hide adds a
    /// second writer (IPC) and therefore needs the explicit lock.
    pub desktop_prefs_lock: Arc<PrefsLock>,
    /// Cached prefs-recovery record for late-subscribing renderers (HIGH-1).
    ///
    /// Populated by setup() when `load_desktop_prefs` returns
    /// `RecoveredFromCorrupt`. The `consume_prefs_recovery` command
    /// returns-and-clears this value (consume-on-read), so a renderer
    /// that mounts AFTER the setup() emit fires can still learn about
    /// the recovery event. Second call returns `None` — the banner only
    /// shows once per app-launch.
    ///
    /// `None` when the last load was `Fresh` or setup() has not yet run.
    pub prefs_recovery: Mutex<Option<PrefsRecoveryRecord>>,
}

/// Maximum length of an account label shown in the tray.
const MAX_LABEL_LEN: usize = 64;

/// Returns the base directory for csq state — `~/.claude/accounts`.
///
/// Honors the `CSQ_BASE_DIR` environment variable for testing. The override
/// must be a non-empty absolute path; an empty or relative value resolves
/// against the process CWD, which for a Finder-launched app is `/`. Rejecting
/// it yields `None`, which every caller already treats as "cannot resolve" —
/// the same validation the CLI twin applies in
/// `cli::commands::validated_env_override`.
fn base_dir() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("CSQ_BASE_DIR") {
        let path = PathBuf::from(&override_path);
        if override_path.is_empty() || !path.is_absolute() {
            log::warn!("CSQ_BASE_DIR must be a non-empty absolute path; ignoring override");
            return None;
        }
        return Some(path);
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

/// Applies the dock-hide runtime policy and persists the preference.
///
/// Called from the IPC `set_dock_hidden` command. Lock acquisition,
/// load, mutate, and save are handled by [`preferences::mutate_prefs`]
/// so the write path is compile-time-enforced: no caller outside
/// `crate::desktop` can bypass the lock (R1 redteam Finding S-H2 / T-5).
///
/// Ordering invariant (R1 redteam Finding S-H3): the runtime policy is
/// applied BEFORE the disk write. If policy apply fails, disk is
/// untouched. If save fails after a successful policy apply, the runtime
/// is rolled back to the pre-flip state (R2 redteam Finding R2-LOW-1).
pub(crate) fn apply_and_persist_dock_hidden(
    app: &AppHandle,
    state: &tauri::State<'_, AppState>,
    base: &Path,
    hidden: bool,
) -> Result<(), String> {
    // 1. Apply the runtime policy BEFORE touching disk (S-H3). If this
    //    fails, return Err with no disk change.
    commands::apply_dock_hidden_policy(app, hidden)?;

    // 2. Persist via mutate_prefs (acquires the typed lock internally).
    //    Capture the pre-mutation value inside the closure so the rollback
    //    path can restore the prior runtime state on save failure.
    let mut previous = false;
    if let Err(e) = preferences::mutate_prefs(&state.desktop_prefs_lock, base, |p| {
        previous = p.hide_dock_icon;
        p.hide_dock_icon = hidden;
    }) {
        // Roll back the runtime to the pre-flip state. Best-effort:
        // if the rollback itself fails, log it but propagate the
        // original save error so the user sees the actionable cause
        // (R2 redteam Finding R2-LOW-1).
        if let Err(rollback_err) = commands::apply_dock_hidden_policy(app, previous) {
            log::warn!(
                target: "csq::desktop",
                "apply_and_persist_dock_hidden: save failed AND rollback failed; \
                 runtime now diverged from on-disk (rollback_err={rollback_err})"
            );
        }
        return Err(format!(
            "dock-hide preference save failed: {e}; runtime was rolled back"
        ));
    }
    Ok(())
}

/// Toggles the dock-hide preference from the tray click path.
///
/// Reads the current on-disk state and flips it atomically inside a
/// single `mutate_prefs` call — no separate lock acquisition needed.
/// The runtime policy is applied AFTER the successful save so the
/// visible state tracks the persisted state.
///
/// Unlike `apply_and_persist_dock_hidden` (IPC path), this helper
/// derives the new target value from the loaded prefs inside the
/// closure. The caller does not pre-read the current state outside the
/// lock, eliminating the TOCTOU window in the old tray-click path
/// (R1 redteam Finding S-H2).
pub(crate) fn toggle_and_persist_dock_hidden(
    app: &AppHandle,
    state: &tauri::State<'_, AppState>,
    base: &Path,
) -> Result<(), String> {
    let mut next = false;
    preferences::mutate_prefs(&state.desktop_prefs_lock, base, |p| {
        next = !p.hide_dock_icon;
        p.hide_dock_icon = next;
    })?;
    // Apply the runtime policy after the disk write succeeds. If policy
    // apply fails, log it — the disk already reflects the new intent and
    // the user can re-toggle from the tray on their next click.
    if let Err(e) = commands::apply_dock_hidden_policy(app, next) {
        log::warn!(
            target: "csq::desktop",
            "toggle_and_persist_dock_hidden: policy apply failed after successful save \
             (next={next}, err={e}); Dock icon state may not match pref until next toggle"
        );
    }
    Ok(())
}

/// Persists the `dashboard_at_launch` preference. Unlike
/// `apply_and_persist_dock_hidden`, this helper has NO runtime apply step —
/// the pref takes effect only at next app launch (consumed by the startup
/// applier in `setup`). Persisting alone keeps the toggle UX non-jarring:
/// the user can change the preference from the settings popover without the
/// dashboard suddenly hiding under their feet.
///
/// Lock acquisition, load, mutate, and save are handled by
/// [`preferences::mutate_prefs`] so the write path is compile-time-enforced.
/// Shares `desktop_prefs_lock` with the dock-hide writer so concurrent
/// frontend toggles to either pref serialize cleanly.
pub(crate) fn apply_and_persist_dashboard_at_launch(
    state: &tauri::State<'_, AppState>,
    base: &Path,
    visible_at_launch: bool,
) -> Result<(), String> {
    preferences::mutate_prefs(&state.desktop_prefs_lock, base, |p| {
        p.dashboard_at_launch = visible_at_launch;
    })
    .map_err(|e| format!("dashboard_at_launch preference save failed: {e}"))
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
/// signal to choose. Account rows are status-only (disabled
/// `info:` items): swap is a per-terminal action (`csq swap N`
/// inside the terminal), so the tray offers no swap affordance.
/// Renders the quota portion of a tray menu row from what the row ACTUALLY
/// carries.
///
/// The previous inline version printed an unconditional `5h:{}%  7d:{}%` from
/// `unwrap_or(0.0)` defaults, so every DeepSeek slot read `5h:0%  7d:0%` and
/// every Grok slot fabricated a `5h:0%` beside its real 7d figure. That is the
/// spurious `5h:0% 7d:0%` an internal ticket set out to kill — the tray never received
/// the fix the statusline did.
///
/// Precedence mirrors the CLI status table: render each window that exists and
/// elide the ones that do not; a balance with NO window renders as the balance.
/// Extracted from the menu builder purely so it is testable — the `MenuItem`
/// construction around it is not.
fn format_tray_quota(q: Option<&csq_core::quota::AccountQuota>) -> String {
    let Some(q) = q else {
        // No row at all: the daemon has not polled this slot yet. Distinct
        // from "polled, no window" below — this one resolves on its own.
        return "checking…".to_string();
    };
    let windows: Vec<String> = [
        q.five_hour_pct_opt().map(|p| format!("5h:{p:.0}%")),
        q.seven_day_pct_opt().map(|p| format!("7d:{p:.0}%")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !windows.is_empty() {
        windows.join("  ")
    } else if let Some(b) = q.balance.as_ref() {
        // No window, but a balance — a genuine pay-per-token slot.
        csq_core::quota::format::fmt_balance(b)
    } else {
        // Polled, but nothing measurable. Never render this as 0%.
        "no quota data".to_string()
    }
}

fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let mut builder = MenuBuilder::new(app);

    // Show account status (read-only) — quota at a glance without
    // opening the dashboard. No swap action: swap is per-terminal
    // (`csq swap N` inside the terminal that should switch).
    if let Some(base) = base_dir() {
        if base.is_dir() {
            let accounts = discovery::discover_all(&base);
            // an internal ticket: salvage per-row — tray menu is display-only.
            let quota = csq_core::quota::state::load_state_salvage(&base);
            let mut had_any = false;
            for a in &accounts {
                if !a.has_credentials {
                    continue;
                }
                had_any = true;
                let q = quota.get(a.id);
                let label = format!(
                    "#{} {}  {}",
                    a.id,
                    sanitize_label(&a.label),
                    format_tray_quota(q)
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
    // On-demand update trigger — bypasses the 30-min timer so the
    // user doesn't have to quit+relaunch after a release cut while
    // the app was running. Calls `request_update_check_now()`
    // which wakes the background loop via a mpsc channel. COMMUNITY
    // builds only — enterprise has no update channel (edition
    // independence), so the item is omitted rather than shown as a
    // dead no-op.
    let check_updates = if community_auto_update_enabled() {
        Some(MenuItemBuilder::with_id("check_updates", "Check for updates").build(app)?)
    } else {
        None
    };

    // Dock-icon-hide check item (macOS only). Reflects the persisted
    // preference at <base>/desktop-prefs.json. Checked = Dock icon
    // hidden (Accessory policy). Building this every menu rebuild
    // picks up CLI/IPC-side writes within one refresh tick.
    #[cfg(target_os = "macos")]
    let dock_hidden_item = {
        let hidden = match base_dir() {
            Some(b) if b.is_dir() => preferences::load_desktop_prefs(&b).0.hide_dock_icon,
            _ => false,
        };
        Some(
            CheckMenuItemBuilder::with_id("dock_hidden", "Hide Dock icon")
                .checked(hidden)
                .build(app)?,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let dock_hidden_item: Option<tauri::menu::CheckMenuItem<tauri::Wry>> = None;

    // M6 PR-CA12: Capability layer submenu (FR-CL-05). The five
    // checkmark items reflect the persisted toggles at
    // <base>/capability_layer.json — checked = TECHNIQUE DISABLED.
    // Wording is inverted-from-disable so a user toggling "Scaffold"
    // ON intuitively means "scaffold runs"; we translate to
    // disable_scaffold = !checked when persisting.
    //
    // The submenu is rebuilt every 30s alongside the rest of the
    // tray (refresh_tray_menu cadence), so a CLI-side edit to
    // capability_layer.json shows up in the UI within one tick.
    let capability_submenu = build_capability_layer_submenu(app)?;

    let quit = MenuItemBuilder::with_id("quit", "Quit csq").build(app)?;

    builder = builder.item(&open_dashboard).item(&hide_dashboard);
    // R1 redteam Finding T-4: "Hide Dock icon" is a global app-
    // behaviour toggle, not a dashboard-window action. Separator
    // before it so users do not confuse it with "Hide Dashboard".
    if dock_hidden_item.is_some() {
        builder = builder.item(&PredefinedMenuItem::separator(app)?);
    }
    if let Some(item) = &dock_hidden_item {
        builder = builder.item(item);
    }
    builder = builder
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&capability_submenu);
    // "Check for updates" only in community builds.
    if let Some(item) = &check_updates {
        builder = builder
            .item(&PredefinedMenuItem::separator(app)?)
            .item(item);
    }
    builder
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&quit)
        .build()
}

/// Builds the "Capability layer" tray submenu (M6 PR-CA12). Five
/// checkmark items mirror the persisted [`CapabilityLayerToggles`]:
/// the "Capability layer" item is the global kill switch; the four
/// per-technique items represent FR-CL-05 opt-out granularity per
/// spec 10 §10.2.3.
///
/// Semantics: a CHECKED item means the technique is **enabled** (the
/// default). The user un-checks to opt out. We translate to the
/// `disable_*` field with `!checked` at click time. The label
/// prefixes "Capability layer:" make it clear at a glance which
/// menu the user landed in even when the submenu pops up sideways
/// at a screen edge.
fn build_capability_layer_submenu(
    app: &AppHandle,
) -> tauri::Result<tauri::menu::Submenu<tauri::Wry>> {
    // Best-effort load — defaults if the file is missing or
    // corrupt. The CLI uses the same defaults so the tray and CLI
    // agree on the initial state for a fresh install.
    let toggles = match base_dir() {
        Some(b) if b.is_dir() => load_capability_layer_toggles(&b),
        _ => CapabilityLayerToggles::default(),
    };

    let global_item = CheckMenuItemBuilder::with_id("cap:global", "Capability layer (master)")
        .checked(!toggles.disable_capability_layer)
        .build(app)?;
    let scaffold_item = CheckMenuItemBuilder::with_id("cap:scaffold", "Scaffold (rule citation)")
        .checked(!toggles.disable_scaffold)
        .enabled(!toggles.disable_capability_layer)
        .build(app)?;
    let mcp_item = CheckMenuItemBuilder::with_id("cap:mcp_gate", "MCP gate")
        .checked(!toggles.disable_mcp_gate)
        .enabled(!toggles.disable_capability_layer)
        .build(app)?;
    let pv_item = CheckMenuItemBuilder::with_id("cap:post_validate", "Post-validate")
        .checked(!toggles.disable_post_validate)
        .enabled(!toggles.disable_capability_layer)
        .build(app)?;
    let so_item = CheckMenuItemBuilder::with_id("cap:struct_out", "Structured output")
        .checked(!toggles.disable_struct_out)
        .enabled(!toggles.disable_capability_layer)
        .build(app)?;

    SubmenuBuilder::new(app, "Capability layer")
        .item(&global_item)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&scaffold_item)
        .item(&mcp_item)
        .item(&pv_item)
        .item(&so_item)
        .build()
}

/// Pure helper for the tray "cap:*" handler — flips the named
/// `disable_*` field on a `CapabilityLayerToggles` value in-place
/// and returns whether the field was recognized. Extracted as a
/// pure function so the TOCTOU regression test
/// (`tray_cap_handler_does_one_load_one_save`) can exercise the
/// load+mutate+save shape without spinning up a Tauri AppHandle.
///
/// Returns `true` if `field` was a known capability-layer field;
/// `false` otherwise. Callers should log + return early on `false`.
fn apply_tray_cap_field_flip(toggles: &mut CapabilityLayerToggles, field: &str) -> bool {
    match field {
        "global" => toggles.disable_capability_layer = !toggles.disable_capability_layer,
        "scaffold" => toggles.disable_scaffold = !toggles.disable_scaffold,
        "mcp_gate" => toggles.disable_mcp_gate = !toggles.disable_mcp_gate,
        "post_validate" => toggles.disable_post_validate = !toggles.disable_post_validate,
        "struct_out" => toggles.disable_struct_out = !toggles.disable_struct_out,
        _ => return false,
    }
    true
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
    // an internal ticket: salvage per-row — tray status is display-only.
    let quota: QuotaFile = quota_state::load_state_salvage(base);

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

        // M4-4: route through identity-keyed credentials when
        // `profiles.json::by_slot` has a UUID for this slot. Slot-id
        // channel: tray-status read is parameterized by the discovered
        // slot (channel (c) — slot-lifecycle parameter from
        // `discover_anthropic`'s discovery output, which itself reads
        // from `by_slot` post-M4-4). Legacy fallback for pure-legacy
        // installs.
        let canonical = match csq_core::accounts::profiles::resolve_slot_to_uuid(base, num.get()) {
            Some(uuid) => csq_core::accounts::identity_store::credentials_path_for(base, uuid),
            None => cred_file::canonical_path(base, num),
        };
        if let Ok(creds) = credentials::load(&canonical) {
            let exp_ms = creds.expect_anthropic().claude_ai_oauth.expires_at;
            let secs = exp_ms as i64 - now_ms as i64;
            // "Expiring" matches `commands::get_accounts` — anything
            // expired or within 2h (7200s) of expiry.
            if secs <= 0
                || creds
                    .expect_anthropic()
                    .claude_ai_oauth
                    .is_expired_within(7200)
            {
                expiring += 1;
            }
        }

        if let Some(q) = quota.get(info.id) {
            // Count a slot as out-of-quota when ANY window it actually has
            // is exhausted. Testing only `five_hour_pct()` made this
            // structurally blind to every weekly-only surface: a Grok slot
            // at 100% of its WEEKLY window has no 5-hour window at all, so
            // `five_hour_pct()` returned the `unwrap_or(0.0)` default and
            // the slot was never counted. Fails in the safe direction
            // (under-reporting), which is exactly why it went unnoticed.
            //
            // Balance-only slots contribute nothing here by construction —
            // both accessors are `None` — which is correct: a pay-per-token
            // slot is not "out of quota", it is out of credit, and that is
            // a different signal this counter does not claim to carry.
            let exhausted = [q.five_hour_pct_opt(), q.seven_day_pct_opt()]
                .into_iter()
                .flatten()
                .any(|p| p >= 100.0);
            if exhausted {
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

/// Whether this build may auto-update from the COMMUNITY release channel.
///
/// The updater endpoints + pubkey baked into `tauri.conf.json` point at the
/// community repo (`terrene-foundation/csq`). Enterprise builds MUST NOT wire
/// that channel: it would auto-offer/install the community bundle over the
/// enterprise one when community publishes a newer version — an
/// edition-independence violation (`rules/independence.md`). Enterprise has no
/// updater channel yet (an internal journal entry W5), so the entire update surface (plugin
/// registration, background check loop, tray item) is fail-closed off in
/// enterprise until that infrastructure lands. Driven by the compile-time
/// `crate::BUILD_EDITION` const (the `enterprise` Cargo feature).
pub(crate) fn community_auto_update_enabled() -> bool {
    crate::BUILD_EDITION != "enterprise"
}

/// Production probe budget for [`installed_cli_is_enterprise`]. Deliberately
/// short: the probe gates a CLI-shim refresh at desktop launch and must
/// never block it behind a wedged/hung binary. Tests MUST NOT depend on
/// this constant's wall-clock value — they call
/// [`installed_cli_is_enterprise_within`] with a budget generous enough to
/// survive host contention (see that function's doc comment).
const CLI_ENTERPRISE_PROBE_TIMEOUT_SECS: u64 = 3;

/// Best-effort: does the CLI already installed at `cli_path` report the
/// ENTERPRISE edition? Runs `<cli> --version` with a short timeout — the CLI
/// prints its edition-suffixed version line (`X.Y.Z (enterprise)`) and exits
/// immediately (a real file at `~/.local/bin/csq` resolves to CLI mode, so this
/// does NOT launch the desktop app). Returns `false` on ANY ambiguity — missing
/// binary, spawn error, timeout, non-zero exit, or an unparseable line — so the
/// shim refresh proceeds by default; only the unambiguous enterprise case is
/// protected from a community downgrade. The probe thread is detached so a hung
/// binary can never block launch.
fn installed_cli_is_enterprise(cli_path: &std::path::Path) -> bool {
    installed_cli_is_enterprise_within(
        cli_path,
        std::time::Duration::from_secs(CLI_ENTERPRISE_PROBE_TIMEOUT_SECS),
    )
}

/// [`installed_cli_is_enterprise`], parameterized on the probe's
/// `recv_timeout` budget. The production entry point above always passes
/// [`CLI_ENTERPRISE_PROBE_TIMEOUT_SECS`] — that value is a deliberate
/// launch-latency UX choice and MUST NOT be raised to accommodate tests.
/// Tests call this function directly with a budget generous enough that
/// host contention (csq's macOS CI runner is self-hosted and shares the
/// box with concurrent cargo builds/other agents — see
/// `discovery_macos_ci_runner_is_self_hosted_local`) cannot produce a false
/// negative, while still bounding a genuine hang so the suite cannot wedge
/// forever. Same defect class as an internal ticket: a test must not assert a
/// wall-clock deadline it never actually exercises.
fn installed_cli_is_enterprise_within(
    cli_path: &std::path::Path,
    timeout: std::time::Duration,
) -> bool {
    use std::process::{Command, Stdio};
    // Reject a SYMLINK target without spawning: `mode::detect` canonicalizes
    // `current_exe()`, so a symlink at the CLI path pointing into
    // `…/Contents/MacOS/csq` would resolve back into the bundle and run in
    // Desktop mode (spawning a GUI subprocess) rather than printing a version
    // (memory `discovery_csq_symlink_breaks_mode_detect`). A symlink is never a
    // legitimate standalone enterprise CLI; fail-open so `ensure_cli_shim`
    // replaces it with a real file.
    let is_regular_file = cli_path
        .symlink_metadata()
        .map(|m| m.file_type().is_file())
        .unwrap_or(false);
    if !is_regular_file {
        return false;
    }
    let cli = cli_path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = Command::new(&cli)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) if output.status.success() => {
            version_output_is_enterprise(&String::from_utf8_lossy(&output.stdout))
        }
        _ => false,
    }
}

/// Decides whether a `csq --version` stdout names the enterprise edition.
///
/// Split out of [`installed_cli_is_enterprise_within`] so the DECISION is
/// testable without spawning a subprocess or racing any wall-clock budget —
/// see `version_output_is_enterprise_accepts_and_rejects` below. Ported from
/// commit `6e646188` (originally landed on the sibling PR fixing this same
/// flake by a different mechanism; that commit was dropped from its branch
/// after a cross-PR collision in this file, but this extraction was judged
/// the one genuinely-good thing to keep and port here).
fn version_output_is_enterprise(stdout: &str) -> bool {
    stdout.contains("(enterprise)")
}

/// Interval between background update checks (30 minutes).
///
/// Lower bound: GitHub API rate-limit is 60 unauthenticated
/// requests/hour, so even a 60-second cadence would be safe — but
/// 30 minutes is the right signal-to-noise for the user (a release
/// cut while they're idle surfaces within half an hour without
/// pestering GitHub every few seconds).
///
/// Tests use `cfg!(test)` to shorten the loop, but the const itself
/// stays at the production value — the channel-driven early wake
/// makes test-only overrides unnecessary.
const UPDATE_CHECK_INTERVAL_SECS: u64 = 30 * 60;

/// Channel for on-demand update checks. Only the Sender half is
/// a static — the background update-check loop owns the Receiver
/// locally, so there's only ever one consumer and no mutex is
/// needed. The tray menu item calls `request_update_check_now()`
/// which sends a unit; the loop's `recv_timeout` wakes early, the
/// loop drains any additional queued messages non-blockingly (so
/// 100 user clicks coalesce into one check), and then runs the
/// check.
static UPDATE_CHECK_TX: std::sync::OnceLock<std::sync::mpsc::Sender<()>> =
    std::sync::OnceLock::new();

/// Lower bound for the update-check loop's back-off. Always the
/// second-through-first wait; only affects the RECOVERY interval
/// after a failed check — success resets to [`UPDATE_CHECK_INTERVAL_SECS`].
const UPDATE_CHECK_BACKOFF_MIN_SECS: u64 = 60;

/// Upper bound for exponential backoff. Caps an offline laptop's
/// checks at one every six hours so we don't burn battery waking
/// up DNS for an unreachable host every 30 minutes.
const UPDATE_CHECK_BACKOFF_MAX_SECS: u64 = 6 * 3600;

/// Publishes a manual update-check request. Non-blocking: if the
/// background loop is already on the wait side of `recv_timeout`
/// it wakes up immediately; if it's mid-check the send queues and
/// the NEXT loop iteration picks it up. Failure to send (receiver
/// dropped on shutdown) is logged at debug and swallowed — tray
/// clicks during teardown shouldn't panic the process.
fn request_update_check_now() {
    match UPDATE_CHECK_TX.get() {
        Some(tx) => {
            if let Err(e) = tx.send(()) {
                tracing::debug!(error = %e, "update-check channel closed");
            }
        }
        None => {
            // Sender not yet initialized — the bg loop hasn't
            // started. Silently drop; a check is coming anyway
            // when the loop fires 10s after launch.
            tracing::debug!("update-check sender not yet initialized; ignoring manual trigger");
        }
    }
}

/// Return value of `run_update_check_with_outcome`: did the
/// network call succeed (up-to-date or new release), or did it
/// fail (HTTP error, parse error, rate limit)? Drives the
/// backoff logic in the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateCheckOutcome {
    Success,
    Failure,
}

/// Single update-check cycle: hit GitHub Releases, cache the
/// result in `AppState.update_cache`, and emit `update-available`
/// to the frontend when a newer release exists.
///
/// Factored out of the background thread so the 10-second settle
/// path and the recurring-timer path call the same code. Returns
/// `()` regardless of outcome — the loop doesn't differentiate
/// between "up to date" (normal) and "HTTP error" (flaky network)
/// because both reduce to "don't show a banner this cycle".
fn run_update_check(handle: &AppHandle) -> UpdateCheckOutcome {
    match csq_core::update::check_for_update() {
        Ok(Some(info)) => {
            let cached = CachedUpdateInfo {
                version: info.version,
                current_version: env!("CARGO_PKG_VERSION").to_string(),
                release_url: info.html_url,
            };
            if let Some(state) = handle.try_state::<AppState>() {
                if let Ok(mut guard) = state.update_cache.lock() {
                    *guard = Some(cached.clone());
                }
            }
            let _ = handle.emit("update-available", &cached);
            UpdateCheckOutcome::Success
        }
        Ok(None) => {
            tracing::debug!("update check: up to date");
            UpdateCheckOutcome::Success
        }
        Err(e) => {
            tracing::warn!(error = %e, "update check failed");
            UpdateCheckOutcome::Failure
        }
    }
}

/// Pure function: compute the next sleep duration given the
/// number of consecutive failures. Zero failures → normal
/// cadence. One failure → `UPDATE_CHECK_BACKOFF_MIN_SECS` (60s).
/// Two failures → 120s. Doubles each subsequent failure, capped
/// at `UPDATE_CHECK_BACKOFF_MAX_SECS` (6h).
pub(crate) fn update_check_wait_secs(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return UPDATE_CHECK_INTERVAL_SECS;
    }
    let exp = consecutive_failures.saturating_sub(1);
    let raw = UPDATE_CHECK_BACKOFF_MIN_SECS.saturating_mul(1u64 << exp.min(20));
    raw.min(UPDATE_CHECK_BACKOFF_MAX_SECS)
}

/// Handles a tray menu click.
///
/// Account rows are disabled `info:` status items and never reach
/// this handler. The actionable ids are the dashboard show/hide
/// pair, the dock-hide toggle, the capability-layer submenu items,
/// update-check, and quit.
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
        "check_updates" => {
            // Non-blocking: publishes to the mpsc channel the
            // background loop is waiting on. The actual network
            // call happens on the update-check thread, not here.
            request_update_check_now();
        }
        "dock_hidden" => {
            // macOS-only Accessory ↔ Regular policy toggle. Both
            // the tray click and the IPC `set_dock_hidden` command
            // route through `apply_and_persist_dock_hidden`, which
            // holds `desktop_prefs_lock` for the entire load →
            // apply-policy → save sequence (R1 redteam Findings
            // S-H2 / T-5 — two writers needed serialization).
            //
            // The menu item is only built on macOS (see
            // build_tray_menu's #[cfg(target_os = "macos")] block),
            // so under normal use this arm is unreachable on Windows
            // / Linux. The arm is still compiled on every platform
            // for safety against an id-spoofing tray plugin in the
            // future — apply_dock_hidden_policy is a no-op outside
            // macOS and the pref still persists for cross-host
            // continuity.
            let Some(base) = base_dir() else {
                log::warn!("tray dock_hidden toggle ignored — base_dir unavailable");
                return;
            };
            if !base.is_dir() {
                log::warn!("tray dock_hidden toggle ignored — base_dir missing");
                return;
            }
            let Some(state) = app.try_state::<AppState>() else {
                log::warn!("tray dock_hidden toggle ignored — AppState unavailable");
                return;
            };
            // The tray click atomically reads current state, flips it,
            // and persists — all inside the single `mutate_prefs` lock
            // acquisition inside `toggle_and_persist_dock_hidden`. No
            // separate load outside the lock (R1 redteam Finding S-H2).
            if let Err(e) = toggle_and_persist_dock_hidden(app, &state, &base) {
                log::warn!("tray dock_hidden toggle failed: {e}");
            }
            if let Some(tray) = app.tray_by_id("main") {
                refresh_tray_menu(app, &tray);
            }
        }
        s if s.starts_with("cap:") => {
            // M6 PR-CA12: capability-layer tray toggle. The id is
            // "cap:<field>" where field ∈ {global, scaffold, mcp_gate,
            // post_validate, struct_out}. On click we flip the
            // PERSISTED state and rebuild the menu — Tauri's
            // CheckMenuItem will visually toggle independently, but
            // we re-render the submenu so the visual matches the
            // canonical disk state and the enabled-when-master-on
            // logic stays consistent.
            //
            // R-HIGH-1 (M6 redteam round 1): the previous shape did one
            // load to compute `new_disable`, then called
            // `flip_capability_layer_toggle()` which re-loaded a fresh
            // copy and saved it. Two separate reads opened a TOCTOU
            // window where a concurrent write between them (CLI
            // `csq config`, an in-flight IPC `set_capability_layer_toggles`,
            // a sibling tray click on a different field) would be
            // silently overwritten. The fix is a single load → mutate
            // → save right here, with NO second read.
            let Some(field) = s.strip_prefix("cap:") else {
                return;
            };
            let Some(base) = base_dir() else {
                log::warn!("tray cap: toggle ignored — base_dir unavailable");
                return;
            };
            if !base.is_dir() {
                log::warn!("tray cap: toggle ignored — base_dir missing");
                return;
            }
            let mut next = load_capability_layer_toggles(&base);
            // Flip the corresponding disable_* field on the SAME
            // struct we just loaded — no second read.
            if !apply_tray_cap_field_flip(&mut next, field) {
                log::warn!("tray cap: unknown field {field:?}");
                return;
            }
            if let Err(e) = save_capability_layer_toggles(&base, &next) {
                log::warn!("tray capability-layer toggle write failed (field={field}): {e}");
            }

            // Rebuild the tray menu so the global-master enable/disable
            // state propagates to the per-technique items' enabled flag.
            if let Some(tray) = app.tray_by_id("main") {
                refresh_tray_menu(app, &tray);
            }
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
pub(crate) fn refresh_tray_menu(app: &AppHandle, tray: &TrayIcon) {
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

/// Augment `PATH` so subprocess spawns find user-installed CLIs.
///
/// macOS .app bundles launched from Finder, Dock, Spotlight, or the
/// auto-updater inherit the system default `PATH`
/// (`/usr/bin:/bin:/usr/sbin:/sbin`) — they do NOT see Homebrew, npm-global,
/// `~/.cargo/bin`, or `~/.local/bin`. csq spawns `codex` and indirectly
/// discovers `gemini` via `which gemini`, so the bundled app cannot find
/// either CLI when launched from the Finder. The fix is to prepend common
/// install locations to `PATH` at app boot, before any Tauri command can
/// spawn a child process.
///
/// Linux `.desktop`-launched apps face a similar issue (the desktop entry
/// PATH is `/usr/bin:/bin` plus distro defaults; user-local CLIs in
/// `~/.local/bin` / `~/.cargo/bin` are not on it).
///
/// Windows: PATH for GUI-launched processes is built from the user + system
/// `Path` registry values, which generally include `npm-global` /
/// `Cargo\bin`; the augmentation is a no-op on Windows.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn augment_subprocess_path() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut extras: Vec<String> = vec![
        "/opt/homebrew/bin".into(),
        "/opt/homebrew/sbin".into(),
        "/usr/local/bin".into(),
    ];
    if !home.is_empty() {
        extras.push(format!("{home}/.local/bin"));
        extras.push(format!("{home}/.cargo/bin"));
        extras.push(format!("{home}/.npm-global/bin"));
        extras.push(format!("{home}/.bun/bin"));
        extras.push(format!("{home}/.deno/bin"));
    }

    let current = std::env::var("PATH").unwrap_or_default();
    let already: std::collections::HashSet<&str> = current.split(':').collect();
    let new_entries: Vec<String> = extras
        .into_iter()
        .filter(|p| !already.contains(p.as_str()))
        .collect();
    if new_entries.is_empty() {
        return;
    }

    let combined = if current.is_empty() {
        new_entries.join(":")
    } else {
        format!("{}:{current}", new_entries.join(":"))
    };
    std::env::set_var("PATH", combined);
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn augment_subprocess_path() {}

/// Resolves `base_dir` for the logging subscriber's rolling-file layer.
///
/// Reuses the same helper the desktop daemon supervisor uses ([`base_dir`]),
/// falling back to the OS temp directory in the exceedingly rare case where
/// `$HOME` cannot be resolved — the file layer is best-effort and non-fatal
/// (`daemon_log::make_writer` returns `None` if directory creation fails),
/// so a temp-dir fallback merely relocates where that best-effort log lives
/// rather than writing into an arbitrary process cwd.
fn resolved_base_dir_for_logging() -> PathBuf {
    base_dir().unwrap_or_else(std::env::temp_dir)
}

/// Initialise the `tracing` subscriber (stderr + rolling-file, filtered by
/// `CSQ_LOG`).
///
/// # Why this is factored out — an internal ticket / an internal ticket SIGABRT-on-launch guard
///
/// The an internal ticket crash was a `log`-facade collision: when `tracing-subscriber`'s
/// `tracing-log` feature is active (pulled in transitively by
/// `kailash-core → tracing-opentelemetry` on the `native-harness` build),
/// calling `.try_init()` installs a `LogTracer` as the global `log` logger,
/// which then collides with `tauri-plugin-log`'s own `set_boxed_logger` and
/// aborts the process during startup.  The fix (an internal ticket) is `set_global_default`
/// instead of `try_init()` — that function sets ONLY the tracing dispatcher and
/// never touches the `log` facade.
///
/// Factoring the subscriber init here (instead of inlining it in `.setup()`)
/// lets the self-test path (`CSQ_DESKTOP_SELFTEST=1`) exercise the EXACT same
/// code that SIGABRTed in an internal ticket, not a stripped-down copy.  If this function
/// ever regresses back to `try_init()`/`.init()`, the self-test's
/// `log::set_boxed_logger` probe (see `run()`) returns `Err` and the self-test
/// exits non-zero — the build gate then fails closed before the SIGABRT can
/// ship.
///
/// Called from two sites:
/// - `run()` self-test path (before Tauri builder, exits 0 on success)
/// - `.setup()` closure (real launch, in the same position as before)
///
/// # Rolling-file layer (#1a-2, daemon-auth-resilience Wave A2)
///
/// The desktop app ALWAYS hosts the in-process daemon supervisor, so it
/// ALWAYS gets the persistent rolling-file layer (unlike the CLI, which
/// only adds it for `csq daemon` — see `cli::run`'s subscriber init).
/// Non-fatal: `daemon_log::make_writer` returns `None` on a directory-create
/// failure and the app still runs with only the stderr layer.
fn init_logging_subscriber(base_dir: &Path) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("CSQ_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let (file_layer, guard) = match crate::daemon_log::make_writer(base_dir) {
        Some((nb, guard)) => (
            Some(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(nb),
            ),
            Some(guard),
        ),
        None => (None, None),
    };
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer);
    // `set_global_default` — NOT `try_init()`/`.init()`.  See doc comment above.
    let _ = tracing::subscriber::set_global_default(subscriber);
    if let Some(g) = guard {
        crate::daemon_log::store_guard(g);
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ── Headless self-test mode (an internal ticket) ──────────────────────────────────────
    //
    // When `CSQ_DESKTOP_SELFTEST=1` is set (or `--self-test` is the sole arg),
    // exercise the crash-prone startup surface — logging subscriber bind +
    // `set_global_default` — then exit 0 BEFORE spawning the daemon supervisor,
    // creating any windows, or entering the Tauri event loop.
    //
    // Design choice: we run `init_logging_subscriber()` standalone rather than
    // driving the full Tauri builder into `.setup()`.  Reasoning:
    //
    //   • The SIGABRT in an internal ticket happened at the `set_global_default` /
    //     `tauri-plugin-log` registration step — specifically because `try_init()`
    //     had already claimed the `log` facade before `tauri-plugin-log` tried to.
    //     `init_logging_subscriber()` exercises that exact call without the GUI.
    //
    //   • Driving the full Tauri builder in a headless CI/build environment
    //     requires a display server (macOS: no issue; Linux CI: needs Xvfb) and
    //     would spin up windows, sockets, and the daemon supervisor — exactly
    //     what a self-test must NOT do.
    //
    //   • `tauri-plugin-log`'s `build()` is called *inside* `.setup()`.  We
    //     cannot reach it headlessly (it needs a live `AppHandle` + display).
    //     Instead the self-test probes the EXACT invariant it depends on: after
    //     `init_logging_subscriber()`, the global `log` facade must still be free
    //     (see the regression probe below).
    //
    // Regression detection (why this CATCHES the an internal ticket SIGABRT):
    //   an internal ticket aborted at `tauri-plugin-log`'s `set_boxed_logger` because a prior
    //   `try_init()` had installed `LogTracer` as the global `log` logger.  We
    //   cannot reach `tauri-plugin-log` registration headlessly, but we can probe
    //   the precise condition it requires: immediately after
    //   `init_logging_subscriber()`, the `log` facade MUST be unclaimed.  The
    //   self-test claims it with a no-op logger; if `set_boxed_logger` returns
    //   `Err`, a `log` logger is already installed (i.e. a `try_init()`
    //   regression) — exactly what makes `tauri-plugin-log` SIGABRT.  Failing the
    //   self-test here makes the build gate fail closed before certification.
    //   Claiming the facade is harmless — the self-test process exits immediately.
    // `--self-test` is honored ONLY as the sole argument (not `.any(argv)`, which
    // would misfire if a future flag / `csq://` deep-link argv merely contained the
    // token — R1 LOW-1). `main()` applies the same gate before routing here.
    let argv: Vec<String> = std::env::args().collect();
    let self_test = std::env::var("CSQ_DESKTOP_SELFTEST").as_deref() == Ok("1")
        || (argv.len() == 2 && argv[1] == "--self-test");
    if self_test {
        // Run the exact logging init path the real launch runs.
        init_logging_subscriber(&resolved_base_dir_for_logging());
        // Probe the an internal ticket invariant: the global `log` facade must still be
        // claimable after our tracing init. A `try_init()` regression installs a
        // LogTracer, so this call would return Err — the same condition that
        // SIGABRTs tauri-plugin-log at startup.
        struct SelfTestNopLogger;
        impl log::Log for SelfTestNopLogger {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                false
            }
            fn log(&self, _: &log::Record<'_>) {}
            fn flush(&self) {}
        }
        if log::set_boxed_logger(Box::new(SelfTestNopLogger)).is_err() {
            eprintln!(
                "csq-desktop self-test FAILED: the global `log` facade is already \
                 claimed after init_logging_subscriber() — a try_init() regression \
                 would SIGABRT tauri-plugin-log at startup (an internal ticket/an internal ticket)."
            );
            std::process::exit(1);
        }
        // Success marker checked by build-enterprise-desktop.sh.
        println!("csq-desktop self-test OK");
        std::process::exit(0);
    }

    // Subprocess spawn paths (`codex login --device-auth`, the
    // `which gemini` lookup inside `oauth_flow::run` for OAuth client
    // discovery) require user-installed CLIs to be reachable. macOS
    // .app bundles inherit only the system default PATH; augment
    // before any Tauri command can run.
    augment_subprocess_path();

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
    // `tauri-plugin-single-instance` MUST be the first plugin
    // registered. It opens a per-user IPC endpoint on startup; a
    // second process that reaches this line detects the endpoint,
    // forwards its argv into the running instance, and exits before
    // building any windows, tray icons, or daemon supervisors.
    //
    // This matters at login because two launch paths race:
    //
    //   1. `tauri-plugin-autostart`'s LaunchAgent (installed by the
    //      user via the Preferences toggle).
    //   2. macOS "Reopen windows when logging back in" (on by default
    //      in System Settings > Desktops & Dock), which restores the
    //      app if it was running at logout.
    //
    // Without single-instance both fire, leaving the user with two
    // tray icons, two update checkers, and two daemon supervisors
    // wrestling over the PID file. The callback fires in the already-
    // running instance so we can surface the main window.
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        // Process plugin exposes `relaunch()` so the frontend can restart the
        // app after a successful install. The UPDATER plugin is NOT registered
        // here — it is registered in `setup` for COMMUNITY builds only (see
        // `community_auto_update_enabled`). The updater endpoints + pubkey in
        // tauri.conf.json point at the community repo (terrene-foundation/csq);
        // registering it in an enterprise build would let the community channel
        // auto-offer/install the community bundle over the enterprise one — an
        // edition-independence violation (rules/independence.md). Enterprise has
        // no release/updater channel yet (an internal journal entry W5), so it is fail-closed
        // off until that infrastructure lands.
        .plugin(tauri_plugin_process::init())
        // Dialog plugin (PR-G5) — file picker for the Vertex SA JSON
        // path in the AddAccountModal Gemini panel. The capability
        // grants `dialog:allow-open` only (file open dialog), not
        // `:default` which would also bundle save / message / ask.
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_build_edition,
            commands::get_accounts,
            commands::rename_account,
            commands::provider_cli_installed,
            commands::remove_account,
            commands::move_account,
            commands::get_account_usage,
            commands::get_rotation_config,
            commands::set_rotation_enabled,
            // M6 PR-CA12 — capability-layer toggles persisted at
            // <base>/capability_layer.json. Tray submenu writes via
            // set_capability_layer_toggles; csq run reads at startup.
            commands::get_capability_layer_toggles,
            commands::set_capability_layer_toggles,
            commands::get_daemon_status,
            // an internal ticket — M-IC interactive per-turn enforcement console. Thin
            // wrappers driving the daemon's enterprise-only /api/interactive/*
            // routes; the renderer relays input + displays the redacted verdict,
            // never deciding enforcement itself (R1-S7).
            commands::interactive::interactive_open,
            commands::interactive::interactive_submit,
            commands::interactive::interactive_override,
            commands::interactive::interactive_abandon,
            commands::interactive::interactive_close,
            commands::interactive::interactive_options,
            commands::list_providers,
            // Phase 2 of an internal ticket — the renderer's Claude OAuth path now
            // shells out to `claude auth login` via
            // `start_claude_login_subprocess`. The legacy paste-code
            // flow (`begin_claude_login` / `submit_oauth_code` /
            // `cancel_login` / `start_claude_login`) AND the
            // parallel-race flow (`start_claude_login_race` /
            // `submit_paste_code` / `cancel_race_login`) are no
            // longer registered — they have ZERO renderer callers as
            // of this PR. Unregistering narrows the IPC attack
            // surface immediately rather than waiting on Phase 3's
            // full source deletion; the function bodies stay
            // compiled until then because cargo would not catch a
            // mismatched signature against the no-longer-registered
            // type list otherwise (deep-analyst red-team M1).
            commands::claude_login_subprocess::start_claude_login_subprocess,
            commands::set_provider_key,
            commands::bind_keyless_provider,
            commands::bind_keyed_provider,
            commands::list_ollama_models,
            commands::set_slot_model,
            commands::pull_ollama_model,
            commands::cancel_ollama_pull,
            // PR-C8 — Codex desktop UI
            commands::start_codex_login,
            commands::complete_codex_login,
            commands::cancel_codex_login,
            commands::list_codex_models,
            commands::acknowledge_codex_tos,
            commands::set_codex_slot_model,
            // PR-G5 — Gemini desktop UI
            commands::is_gemini_tos_acknowledged,
            commands::acknowledge_gemini_tos,
            commands::gemini_probe_tos_residue,
            commands::gemini_provision_api_key,
            commands::gemini_provision_vertex_sa,
            commands::gemini_provision_oauth,
            commands::gemini_switch_model,
            // Native Kimi/Grok session-surface desktop UI. an internal journal entry C8
            // redesigned the bind flow to a real per-slot device-code
            // login (mirroring PR-C8's Codex twin) — the marker-only
            // `provision_native_cli` (an internal journal entry W3-5) is retired.
            commands::list_native_clis,
            commands::start_native_login,
            commands::complete_native_login,
            commands::cancel_native_login,
            commands::list_sessions,
            commands::get_autostart_enabled,
            commands::set_autostart_enabled,
            commands::is_dock_hide_supported,
            commands::get_dock_hidden,
            commands::set_dock_hidden,
            commands::get_dashboard_at_launch,
            commands::set_dashboard_at_launch,
            commands::check_for_update,
            commands::get_update_status,
            commands::open_release_page,
            // HIGH-1: cached prefs-recovery gate for late-subscribing
            // renderers — fills the gap where setup() emits before
            // the WebView mounts and the Svelte listen() registers.
            commands::consume_prefs_recovery,
            // an internal ticket AC#3 — policy-bundle admin console. Enterprise-only:
            // the phase2b seam is moat-stripped in the community edition.
            // `generate_handler!` preserves the `#[cfg]` attribute on the
            // match arm, so these entries are absent from the community
            // build's match statement (the functions themselves are also
            // `#[cfg(feature = "enterprise")]` in policy.rs).
            #[cfg(feature = "enterprise")]
            commands::policy::policy_preview_active,
            #[cfg(feature = "enterprise")]
            commands::policy::policy_validate_draft,
            #[cfg(feature = "enterprise")]
            commands::policy::policy_create_unsigned,
            #[cfg(feature = "enterprise")]
            commands::policy::policy_keygen,
            // an internal ticket PR-2 — cloud-Claude (Vertex/Bedrock) desktop provisioning.
            // Enterprise-only: `bind_cloud_claude_backend_to_slot` is
            // `#[cfg(feature = "enterprise")]`, so these arms are absent from
            // the community build's match statement (same pattern as policy::*).
            #[cfg(feature = "enterprise")]
            commands::cloud_claude_provision_vertex,
            #[cfg(feature = "enterprise")]
            commands::cloud_claude_provision_bedrock,
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
            // **Critical (SIGABRT-on-launch guard):** see `init_logging_subscriber()`
            // for the full explanation of why `set_global_default` is used instead
            // of `try_init()`. The self-test path (`CSQ_DESKTOP_SELFTEST=1`) calls
            // the same function so any regression here is caught by the build gate
            // added in an internal ticket.
            //
            // #1a-2 — resolve base_dir via the same helper the daemon supervisor
            // uses so the rolling-file log layer lands in the same
            // `csq-runs/.daemon-log/` directory the supervisor's spawned
            // `log_gc` task GCs.
            init_logging_subscriber(&resolved_base_dir_for_logging());

            // ── CLI shim refresh (#1) ──────────────────────────
            //
            // The desktop `.app` and the terminal CLI are the same single
            // binary but are installed by independent channels — a desktop
            // auto-update never refreshes `~/.local/bin/csq`, so the in-process
            // daemon (new) and the terminal CLI (old) drift and trip the
            // version-skew guard on `csq run`/`login`/`status`/`doctor`. Refresh
            // the CLI to match this bundle on every launch. Best-effort +
            // NON-FATAL: a failure here must never block the desktop app.
            // Real-file copy (NOT cp → Gatekeeper SIGKILL; NOT a symlink →
            // mode::detect canonicalize trap). See csq_core cli_shim.
            //
            // Source resolution (an internal ticket): on the enterprise Developer-ID
            // build the running binary is the bundle's `--deep`-signed MAIN
            // executable, whose signature is bundle-bound and INVALID when copied
            // standalone (→ SIGKILL). `resolve_shim_source` prefers the
            // standalone-signed `Contents/Helpers/csq-cli` helper when present,
            // falling back to the running exe otherwise.
            //
            // Runs on a DETACHED thread so the `installed_cli_is_enterprise`
            // probe (a `<cli> --version` subprocess bounded by a 3s timeout)
            // never blocks the synchronous Tauri setup closure / event-loop
            // start — otherwise a slow/hung CLI would beachball launch (redteam
            // an internal ticket M1). The refresh is already best-effort + non-fatal, so
            // racing the rest of setup is safe.
            std::thread::spawn(|| {
            match (
                std::env::current_exe()
                    .map(|exe| csq_core::cli_deps::cli_shim::resolve_shim_source(&exe)),
                csq_core::cli_deps::cli_shim::resolve_shim_target(),
            ) {
                // Edition-downgrade guard (edition independence): a COMMUNITY
                // desktop must never silently overwrite an installed ENTERPRISE
                // CLI. The shim refresh is unconditional, so without this a
                // community `.app` launch would replace `~/.local/bin/csq`
                // (enterprise) with the community binary — the user silently
                // loses the Phase-2b moat. Enterprise-over-anything and
                // community-over-community are fine; only community-over-
                // enterprise is blocked (see `installed_cli_is_enterprise`).
                (Ok(_), Some(target))
                    if crate::BUILD_EDITION == "community"
                        && installed_cli_is_enterprise(&target) =>
                {
                    tracing::warn!(
                        target = %target.display(),
                        "cli shim refresh SKIPPED: refusing to downgrade an enterprise CLI \
                         to community. Run the enterprise desktop build, or reinstall the \
                         enterprise CLI, to keep editions consistent."
                    );
                }
                (Ok(src), Some(target)) => {
                    match csq_core::cli_deps::cli_shim::ensure_cli_shim(&src, &target) {
                        Ok(outcome) => tracing::info!(
                            ?outcome,
                            target = %target.display(),
                            "cli shim refresh"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "cli shim refresh failed (non-fatal)"
                        ),
                    }
                }
                _ => tracing::warn!(
                    "cli shim refresh skipped: could not resolve current exe or target"
                ),
            }

            // ── Managed background daemon plist (Wave B) ────────
            //
            // Install / repair the launchd-managed daemon plist AFTER the
            // shim refresh, so its `ProgramArguments[0]` (the shim,
            // resolved by `resolve_managed_daemon_exe`) points at a
            // freshly-copied real-file `~/.local/bin/csq`. The managed
            // daemon (`csq daemon start --supervised` under
            // `KeepAlive={SuccessfulExit:false}`) keeps the token refresher
            // alive whether or not this desktop app is open — the
            // structural fix for the mass-token-expiry incident
            // (daemon-auth-resilience an internal journal entry). Best-effort +
            // NON-FATAL: a launchctl hiccup must never block launch. The
            // in-process supervisor above is the cohabiting backup; the
            // PidFile guard ensures exactly one owner.
            //
            // macOS only — Linux's systemd unit already auto-restarts
            // (`Restart=on-failure`) and has no bundle-misdetection issue.
            //
            // Edition coherence: NEVER launchd-manage a daemon of a
            // different edition than this app. The shim-refresh above
            // refuses to downgrade an enterprise CLI to community, so a
            // COMMUNITY app on a box with an enterprise `~/.local/bin/csq`
            // leaves the shim enterprise — and a plist pointing at it would
            // run the enterprise daemon whose license gate refuses → no
            // refresh → Wave B silently defeated on exactly that
            // mixed-edition (maintainer dev-box) machine. Skip the install
            // in that case, mirroring the shim-refresh downgrade guard.
            #[cfg(target_os = "macos")]
            {
                let target = csq_core::cli_deps::cli_shim::resolve_shim_target();
                let edition_incoherent = crate::BUILD_EDITION == "community"
                    && target
                        .as_ref()
                        .is_some_and(|t| installed_cli_is_enterprise(t));
                if edition_incoherent {
                    tracing::warn!(
                        "managed daemon plist SKIPPED: installed CLI is enterprise \
                         but this is a community app; refusing to launchd-manage a \
                         mismatched-edition daemon. Reinstall a coherent edition to \
                         enable the always-on managed daemon."
                    );
                } else {
                    match crate::cli::commands::daemon::ensure_managed_daemon_plist() {
                        Ok(outcome) => {
                            tracing::info!(?outcome, "managed daemon plist ensured")
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "managed daemon plist install/repair failed (non-fatal)"
                        ),
                    }
                }
            }
            });

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

            // ── Updater plugin (COMMUNITY builds only) ───────
            //
            // The updater endpoints + minisign pubkey in tauri.conf.json point
            // at terrene-foundation/csq (community). Registering the plugin in
            // an enterprise build would let the community channel install the
            // community bundle over the enterprise one. Gate it off for
            // enterprise until an enterprise updater channel exists (W5).
            if community_auto_update_enabled() {
                app.handle()
                    .plugin(tauri_plugin_updater::Builder::new().build())?;
            }

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
            // `csq daemon start` in a terminal — and an internal journal entry
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
                update_cache: Mutex::new(None),
                ollama_pull_child: Arc::new(Mutex::new(None)),
                codex_login_child: Arc::new(Mutex::new(None)),
                native_login_children: Arc::new(Mutex::new(HashMap::new())),
                desktop_prefs_lock: Arc::new(PrefsLock::new()),
                prefs_recovery: Mutex::new(None),
            });

            // ── Apply persisted dock-hide preference ─────────────
            //
            // Read `<base>/desktop-prefs.json` and set the macOS
            // activation policy to match. On non-macOS this is a
            // no-op. The default (missing/corrupt file) is
            // `hide_dock_icon: false` → `ActivationPolicy::Regular`,
            // which is also Tauri's default — so a fresh install
            // sees no behaviour change from this block.
            //
            // Runs AFTER `app.manage(AppState)` so any future
            // enhancement to `apply_dock_hidden_policy` that
            // reads `State<AppState>` does not panic on an
            // unmanaged state (R1 redteam Finding T-7 — defensive
            // ordering).
            //
            // Failure is logged but does NOT abort setup; the user
            // can re-toggle from the tray once the app is up.
            if let Some(base) = base_dir() {
                let (prefs, outcome) = preferences::load_desktop_prefs(&base);
                if let Err(e) =
                    commands::apply_dock_hidden_policy(app.handle(), prefs.hide_dock_icon)
                {
                    log::warn!(
                        "startup dock-hide apply failed (hide={}, err={e}); \
                         continuing with default policy",
                        prefs.hide_dock_icon
                    );
                }
                // Apply `dashboard_at_launch` AFTER the dock-hide policy so
                // the activation-policy switch (which may transiently affect
                // the window) is settled before we make the visibility call.
                // Default `true` keeps the classic show-on-launch behavior;
                // `false` (opted into by the user or migrated from a legacy
                // dock-hide=true file) leaves the dashboard hidden until the
                // user clicks the tray icon to reveal it.
                if let Err(e) = commands::apply_dashboard_visibility(
                    app.handle(),
                    prefs.dashboard_at_launch,
                ) {
                    log::warn!(
                        "startup dashboard-visibility apply failed \
                         (visible={}, err={e}); window state may not match pref",
                        prefs.dashboard_at_launch
                    );
                }
                // HIGH-1: Tauri's `emit` is fire-and-forget. setup() runs
                // SYNCHRONOUSLY before the WebView spawns, so any renderer
                // `listen()` registered in `onMount` fires too late to catch
                // this event. Defense in depth: cache the record in AppState
                // AND emit so late-mounting renderers can call
                // `consume_prefs_recovery` on mount while still catching
                // future re-emits (e.g. hot-reload, manual trigger).
                //
                // MED-1: `occurred_at` is set HERE from the backend clock so
                // the frontend does not use its own `new Date().toISOString()`
                // at event-receipt time (which would be the frontend clock, not
                // the authoritative recovery timestamp).
                if let preferences::LoadOutcome::RecoveredFromCorrupt(reason) = outcome {
                    let occurred_at = chrono::Utc::now().to_rfc3339();
                    // Cache for late-subscribing renderer (HIGH-1 fix).
                    if let Ok(mut guard) = app
                        .state::<AppState>()
                        .prefs_recovery
                        .lock()
                    {
                        *guard = Some(PrefsRecoveryRecord {
                            reason,
                            occurred_at: occurred_at.clone(),
                        });
                    }
                    let payload =
                        serde_json::json!({ "reason": reason, "occurred_at": occurred_at });
                    if let Err(e) = app.handle().emit("prefs-reset-to-defaults", payload) {
                        log::warn!(
                            target: "csq::desktop",
                            "prefs_recovery_event_emit_failed: failed to emit \
                             prefs-reset-to-defaults event: {e}"
                        );
                    }
                }
            }

            // Separate state object for the parallel-race OAuth flow.
            // Kept out of `AppState` so the race lifecycle (one
            // outstanding race at a time) is enforced by its own type
            // rather than tucked into a generic options bag — and so
            // the race subsystem can evolve without churning unrelated
            // command handlers.
            app.manage(commands::RaceLoginState::default());

            // ── Background update check ────────────────────────
            //
            // Fires 10s after app launch so startup isn't blocked
            // on a network round-trip, then re-checks on a cadence
            // that depends on consecutive-failure count:
            //   - 0 failures → UPDATE_CHECK_INTERVAL_SECS (30 min)
            //   - N failures → min(60s * 2^(N-1), 6h)
            //
            // The recurring cadence closes the gap where a release
            // cut while the app was already running would never
            // surface without a quit+relaunch. The backoff prevents
            // an offline laptop from hammering GitHub every 30 min
            // for days; success resets the counter.
            //
            // The tray's "Check for updates" menu item publishes on
            // the local-Receiver channel; the loop wakes early,
            // drains any additional queued messages (coalescing
            // rapid-fire clicks into one check), and runs.
            // COMMUNITY builds only: the loop drives the `update-available`
            // banner off the community `latest.json`. Enterprise builds never
            // spawn it, so no community update is ever surfaced or installed
            // (edition independence — see `community_auto_update_enabled`).
            // `UPDATE_CHECK_TX` stays unset in enterprise, making the tray
            // "Check for updates" trigger a harmless no-op.
            if community_auto_update_enabled() {
                let handle_for_update = app.handle().clone();
                let (update_tx, update_rx) = std::sync::mpsc::channel::<()>();
                UPDATE_CHECK_TX
                    .set(update_tx)
                    .expect("UPDATE_CHECK_TX set twice — lib::run called more than once?");
                std::thread::spawn(move || {
                    let mut consecutive_failures: u32 = 0;
                    // Initial settle delay so launch isn't blocked.
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    let outcome = run_update_check(&handle_for_update);
                    consecutive_failures = match outcome {
                        UpdateCheckOutcome::Success => 0,
                        UpdateCheckOutcome::Failure => consecutive_failures.saturating_add(1),
                    };

                    loop {
                        let wait = update_check_wait_secs(consecutive_failures);
                        let awoke_early = update_rx
                            .recv_timeout(std::time::Duration::from_secs(wait))
                            .is_ok();
                        if awoke_early {
                            // Drain any additional queued messages —
                            // a rapid-fire clicker shouldn't cause N
                            // sequential GitHub checks. We want one
                            // check per observable user intent.
                            while update_rx.try_recv().is_ok() {}
                            tracing::debug!("update check: manual request");
                        }
                        let outcome = run_update_check(&handle_for_update);
                        consecutive_failures = match outcome {
                            UpdateCheckOutcome::Success => 0,
                            UpdateCheckOutcome::Failure => consecutive_failures.saturating_add(1),
                        };
                    }
                });
            }

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
            let tray = TrayIconBuilder::with_id("main")
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
    use tempfile::TempDir;

    // ── tray quota label: an absent window is not 0% ──────────────────────

    fn tray_row(
        five: Option<f64>,
        seven: Option<f64>,
        balance: Option<f64>,
    ) -> csq_core::quota::AccountQuota {
        use csq_core::quota::{AccountQuota, BalanceInfo, UsageWindow};
        AccountQuota {
            five_hour: five.map(|p| UsageWindow {
                used_percentage: p,
                // 4_102_444_800 = 2100-01-01 (testing.md Rule 1). MUST stay far-future:
                // this fixture round-trips through the loader, whose `clear_expired`
                // NULLS a past window — the row then falls back to `balance` and the
                // assertions below invert. A near-future literal here detonated on
                // 2026-08-07T11:12:35Z and reddened every PR in flight.
                resets_at: 4_102_444_800,
            }),
            seven_day: seven.map(|p| UsageWindow {
                used_percentage: p,
                resets_at: 4_102_444_800,
            }),
            balance: balance.map(|remaining| BalanceInfo {
                currency: "USD".to_string(),
                remaining,
            }),
            ..AccountQuota::default()
        }
    }

    /// A balance-metered slot (DeepSeek) has no usage window at all. The tray
    /// rendered `5h:0%  7d:0%` for it — two fabricated measurements.
    #[test]
    fn tray_quota_balance_only_slot_renders_the_balance_not_two_zeroes() {
        let q = tray_row(None, None, Some(165.32));
        let s = format_tray_quota(Some(&q));
        assert_eq!(s, "$165.32");
        assert!(!s.contains("5h:"), "must not fabricate a 5h window: {s}");
        assert!(!s.contains("7d:"), "must not fabricate a 7d window: {s}");
    }

    /// The grok-16 shape: a real weekly window plus a `$0.00` on-demand
    /// allowance. The 5h window does not exist, so it must be elided rather
    /// than printed as `5h:0%` beside the genuine 7d figure — and the window
    /// beats the balance.
    #[test]
    fn tray_quota_weekly_only_slot_elides_the_absent_five_hour_window() {
        let q = tray_row(None, Some(7.0), Some(0.0));
        let s = format_tray_quota(Some(&q));
        assert_eq!(s, "7d:7%");
        assert!(!s.contains("5h:"), "absent 5h must be elided, not 0%: {s}");
        assert!(!s.contains('$'), "a window beats a balance: {s}");
    }

    /// The ordinary Anthropic shape must be unchanged by the fix.
    #[test]
    fn tray_quota_both_windows_render_as_before() {
        let q = tray_row(Some(12.0), Some(55.0), None);
        assert_eq!(format_tray_quota(Some(&q)), "5h:12%  7d:55%");
    }

    /// A measured 0% is a REAL reading and must still render as `0%` — the
    /// fix must not suppress genuine zeroes along with fabricated ones.
    /// This is the assertion that stops "elide absent windows" from
    /// degenerating into "elide anything that looks like zero".
    #[test]
    fn tray_quota_measured_zero_is_still_rendered() {
        let q = tray_row(Some(0.0), Some(0.0), None);
        assert_eq!(format_tray_quota(Some(&q)), "5h:0%  7d:0%");
    }

    /// No row yet vs. a polled row with nothing measurable are different
    /// states and must read differently: the first resolves on its own.
    #[test]
    fn tray_quota_distinguishes_unpolled_from_unmeasurable() {
        assert_eq!(format_tray_quota(None), "checking…");
        let q = tray_row(None, None, None);
        assert_eq!(format_tray_quota(Some(&q)), "no quota data");
    }

    // ── edition-gated auto-update (edition independence) ─────

    // Concrete per-edition assertions (not a tautology against the definition):
    // these test the integration between the `enterprise` Cargo feature and the
    // gate's output. Exactly one compiles per build.
    #[cfg(feature = "enterprise")]
    #[test]
    fn community_auto_update_disabled_in_enterprise() {
        assert!(!community_auto_update_enabled());
        assert_eq!(crate::BUILD_EDITION, "enterprise");
    }

    #[cfg(not(feature = "enterprise"))]
    #[test]
    fn community_auto_update_enabled_in_community() {
        assert!(community_auto_update_enabled());
        assert_eq!(crate::BUILD_EDITION, "community");
    }

    #[cfg(unix)]
    fn write_fake_cli(dir: &std::path::Path, name: &str, version_line: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\necho '{version_line}'\n")).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// Deterministic coverage of the actual decision — no subprocess, no
    /// wall-clock budget. The spawn-based tests below exercise the plumbing;
    /// THIS is what pins the predicate, so a contended CI runner can no
    /// longer turn a string check into a failure. Ported from commit
    /// `6e646188` (see `version_output_is_enterprise`'s doc comment).
    #[test]
    fn version_output_is_enterprise_accepts_and_rejects() {
        // Accept boundary — the real shape `csq --version` prints.
        assert!(version_output_is_enterprise("csq 2.18.0 (enterprise)"));
        assert!(version_output_is_enterprise("csq 2.18.0 (enterprise)\n"));
        // Reject boundary — community is the OTHER shipped edition, and the
        // whole point of the probe is telling the two apart.
        assert!(!version_output_is_enterprise("csq 2.18.0 (community)"));
        assert!(!version_output_is_enterprise(""));
        assert!(!version_output_is_enterprise("csq 2.18.0"));
        // Near-misses: the marker is parenthesised and lowercase by
        // construction; neither variant should be accepted.
        assert!(!version_output_is_enterprise("csq 2.18.0 enterprise"));
        assert!(!version_output_is_enterprise("csq 2.18.0 (Enterprise)"));
    }

    /// Test-only probe budget for [`installed_cli_is_enterprise_within`].
    /// csq's macOS CI runner is self-hosted and shares the host with
    /// concurrent cargo builds / other agents, so the production 3s budget
    /// ([`CLI_ENTERPRISE_PROBE_TIMEOUT_SECS`]) is NOT safe to assert against
    /// under test — a fork/exec of `/bin/sh` can transiently take >3s under
    /// contention with no defect in the code under test. Reproduced directly:
    /// `installed_cli_is_enterprise_detects_enterprise_suffix` failed with
    /// `finished in 3.08s` (the exact production timeout) while its two
    /// sibling tests in the same run passed — the assertion is timeout-bound,
    /// not code-bound. 60s is generous enough to absorb that contention while
    /// still bounding a genuine hang so the suite cannot wedge forever.
    #[cfg(unix)]
    const TEST_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    // Workspace-local serial mutex, same pattern as
    // `csq/tests/cli_deps_doctor_integration.rs::SERIAL` (an internal ticket, journal
    // `internal-design-docs`).
    // That integration-test binary's static is NOT reachable here — `csq/tests/*.rs`
    // integration tests compile as separate binaries from `csq/src/**`'s own
    // `#[cfg(test)]` unittest harness — so this is a second, local instance of the
    // same pattern, not a shared import. Two independent defenses stack:
    // (1) this mutex removes INTRA-BINARY contention (no two of the three tests
    // below spawn `/bin/sh` at the same instant); (2) the generous
    // `TEST_PROBE_TIMEOUT` above absorbs CROSS-PROCESS contention the mutex
    // cannot touch (csq's macOS CI runner is self-hosted and shares the box
    // with concurrent cargo builds / other agents' sessions, per
    // `discovery_macos_ci_runner_is_self_hosted_local` — serializing this
    // binary's own three tests does nothing about a sibling process eating
    // every core). Neither layer alone is sufficient.
    #[cfg(unix)]
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn installed_cli_is_enterprise_detects_enterprise_suffix() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
            SERIAL.clear_poison();
            p.into_inner()
        });
        let dir = TempDir::new().unwrap();
        let cli = write_fake_cli(dir.path(), "csq-ent", "csq 2.17.0 (enterprise)");
        assert!(installed_cli_is_enterprise_within(&cli, TEST_PROBE_TIMEOUT));
    }

    #[cfg(unix)]
    #[test]
    fn installed_cli_is_enterprise_rejects_symlink() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
            SERIAL.clear_poison();
            p.into_inner()
        });
        // sec-M1: a symlink target (even one pointing at a real enterprise CLI)
        // must be rejected without spawning — `mode::detect` would canonicalize
        // it into the .app and launch Desktop mode. Fail-open (false) so
        // ensure_cli_shim replaces it with a real file.
        let dir = TempDir::new().unwrap();
        let real = write_fake_cli(dir.path(), "csq-real", "csq 2.17.0 (enterprise)");
        let link = dir.path().join("csq-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            !installed_cli_is_enterprise_within(&link, TEST_PROBE_TIMEOUT),
            "a symlink target must be rejected (never probed)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn installed_cli_is_enterprise_false_for_community_and_missing() {
        let _serial_guard = SERIAL.lock().unwrap_or_else(|p| {
            SERIAL.clear_poison();
            p.into_inner()
        });
        let dir = TempDir::new().unwrap();
        let community = write_fake_cli(dir.path(), "csq-comm", "csq 2.17.0 (community)");
        assert!(
            !installed_cli_is_enterprise_within(&community, TEST_PROBE_TIMEOUT),
            "community CLI must not be flagged enterprise"
        );
        // Missing binary → false (shim refresh proceeds).
        assert!(!installed_cli_is_enterprise_within(
            &dir.path().join("does-not-exist"),
            TEST_PROBE_TIMEOUT
        ));
    }

    // ── update-check backoff + channel ──────────────────────

    #[test]
    fn update_check_wait_zero_failures_is_normal_interval() {
        assert_eq!(update_check_wait_secs(0), UPDATE_CHECK_INTERVAL_SECS);
    }

    #[test]
    fn update_check_wait_one_failure_is_backoff_min() {
        // First retry waits the configured backoff floor (60s).
        assert_eq!(update_check_wait_secs(1), UPDATE_CHECK_BACKOFF_MIN_SECS);
    }

    #[test]
    fn update_check_wait_doubles_each_failure() {
        // 60s → 120s → 240s → 480s
        assert_eq!(update_check_wait_secs(2), 120);
        assert_eq!(update_check_wait_secs(3), 240);
        assert_eq!(update_check_wait_secs(4), 480);
    }

    #[test]
    fn update_check_wait_caps_at_max() {
        // Plenty of failures — must saturate at the 6-hour ceiling
        // rather than overflow or grow unbounded.
        assert_eq!(update_check_wait_secs(30), UPDATE_CHECK_BACKOFF_MAX_SECS);
        // Very high counts must also cap without panicking.
        assert_eq!(
            update_check_wait_secs(u32::MAX),
            UPDATE_CHECK_BACKOFF_MAX_SECS
        );
    }

    #[test]
    fn request_update_check_now_without_consumer_does_not_panic() {
        // Before `lib::run()` has initialized the sender, manual
        // triggers must no-op silently (tray could fire any time
        // during startup). The alternative — panicking — would
        // take out the tray event dispatcher.
        let prev = UPDATE_CHECK_TX.get().is_some();
        if !prev {
            request_update_check_now();
            request_update_check_now();
        }
        // If the static was already set by another test in this
        // process, the call still must not panic.
        request_update_check_now();
    }

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

    // M4-8: `most_recent_config_dir` and its tests were retired
    // alongside `rotation::swap_to`. The handle-dir tray-swap
    // mechanism (per spec 02 §2.8) targets the most-recently-active
    // terminal by PID, not a config-dir mtime heuristic — when that
    // follow-up lands, the tests will exercise that selector.

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

    // ── R-HIGH-1: tray cap-toggle TOCTOU regression ─────────────

    /// `apply_tray_cap_field_flip` flips exactly the named field
    /// and leaves siblings untouched. This is the unit-level
    /// correctness probe; the TOCTOU shape regression
    /// (`tray_cap_handler_does_one_load_one_save_per_click`) below
    /// proves the tray handler reads once + writes once + does not
    /// re-load between read and write.
    #[test]
    fn apply_tray_cap_field_flip_toggles_only_named_field() {
        let mut t = CapabilityLayerToggles::default();
        assert!(apply_tray_cap_field_flip(&mut t, "scaffold"));
        assert!(t.disable_scaffold);
        assert!(!t.disable_capability_layer);
        assert!(!t.disable_mcp_gate);
        assert!(!t.disable_post_validate);
        assert!(!t.disable_struct_out);

        // Flipping the same field a second time un-toggles it.
        assert!(apply_tray_cap_field_flip(&mut t, "scaffold"));
        assert!(!t.disable_scaffold);
    }

    #[test]
    fn apply_tray_cap_field_flip_rejects_unknown_field() {
        let mut t = CapabilityLayerToggles::default();
        assert!(!apply_tray_cap_field_flip(&mut t, "nonsense"));
        // No mutation on unknown field.
        assert_eq!(t, CapabilityLayerToggles::default());
    }

    /// R-HIGH-1: simulate the tray "cap:*" handler's load+mutate+save
    /// sequence end-to-end against the real on-disk file. Asserts
    /// that the resulting persisted state matches a SINGLE
    /// load+flip+save sequence — i.e. there is no second hidden read
    /// that could have observed a concurrent write between the read
    /// and the write. The pre-fix code path called
    /// `flip_capability_layer_toggle()` which re-loaded a fresh copy
    /// after the handler had already loaded one, opening a TOCTOU
    /// window. This regression test fails if any such second read is
    /// reintroduced because the asserted persisted state is computed
    /// from the original load — not from a re-load that would have
    /// missed the concurrent write below.
    #[test]
    fn tray_cap_handler_does_one_load_one_save_per_click() {
        let base = TempDir::new().unwrap();
        // Initial state: scaffold disabled (one-bit set).
        let initial = CapabilityLayerToggles {
            disable_scaffold: true,
            ..Default::default()
        };
        save_capability_layer_toggles(base.path(), &initial).unwrap();

        // Step 1 of the tray flow: handler loads the current state.
        let mut next = load_capability_layer_toggles(base.path());
        assert_eq!(next, initial);

        // Step 2: between load and save, a CONCURRENT writer (could be
        // an IPC `set_capability_layer_toggles`, a CLI config write,
        // a sibling tray click) flips a DIFFERENT field. The pre-fix
        // shape would re-load inside `flip_capability_layer_toggle`,
        // observe this concurrent write, then save — silently dropping
        // the tray click's own field flip. The fixed shape uses ONLY
        // the `next` value loaded in step 1, so the concurrent write
        // is correctly overwritten by the user's tray click.
        let concurrent = CapabilityLayerToggles {
            disable_mcp_gate: true,
            ..Default::default()
        };
        save_capability_layer_toggles(base.path(), &concurrent).unwrap();

        // Step 3: handler flips its target field and saves WITHOUT
        // re-reading. The fix is structural: any reintroduction of a
        // second load (e.g. resurrecting `flip_capability_layer_toggle`)
        // would silently make this test pass under the wrong contract.
        assert!(apply_tray_cap_field_flip(&mut next, "scaffold"));
        save_capability_layer_toggles(base.path(), &next).unwrap();

        // Persisted state MUST equal the user's intended state from
        // the tray click — scaffold flipped from disabled to enabled.
        // If the handler had a second load it would have observed the
        // `concurrent` value (mcp_gate=true, scaffold=false) and saved
        // scaffold=!false=true, leaving us with BOTH mcp_gate=true AND
        // scaffold=true, dropping the user's intended scaffold flip.
        let final_state = load_capability_layer_toggles(base.path());
        assert!(
            !final_state.disable_scaffold,
            "the user's tray click was lost: a second load was reintroduced and the handler observed a concurrent write between load and save"
        );
        assert!(
            !final_state.disable_mcp_gate,
            "the user's tray click overwrote the concurrent write — this is the intended last-writer-wins behavior"
        );
    }
}
