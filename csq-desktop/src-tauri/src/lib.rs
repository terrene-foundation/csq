mod commands;

use csq_core::accounts::{discovery, markers, AccountInfo};
use csq_core::broker::fanout;
use csq_core::rotation;
use csq_core::types::AccountNum;
use std::path::PathBuf;
use tauri::menu::{Menu, MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager};

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

/// Discovers accounts and finds the currently active one (if any).
///
/// Active detection scans config-* dirs for a `.csq-account` marker
/// that matches the current `CLAUDE_CONFIG_DIR`. Returns `(accounts,
/// active_id)`.
fn discover_for_tray(base: &std::path::Path) -> (Vec<AccountInfo>, Option<u16>) {
    let accounts = discovery::discover_anthropic(base);

    // The desktop app has no CLAUDE_CONFIG_DIR of its own. We show
    // an active checkmark only if the user has a session live in
    // some config-* dir that matches one of the accounts. Best-
    // effort — returns None if no active config can be determined.
    let active = std::env::var("CLAUDE_CONFIG_DIR")
        .ok()
        .and_then(|p| markers::read_current_account(std::path::Path::new(&p)))
        .map(|a| a.get());

    (accounts, active)
}

/// Builds the tray menu from the current account list.
///
/// Menu layout:
///   * #{id} {label}  ← one row per account, checkmark on active
///   ---
///   Open Dashboard
///   Hide Dashboard
///   ---
///   Quit Claude Squad
fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let mut builder = MenuBuilder::new(app);

    if let Some(base) = base_dir() {
        if base.is_dir() {
            let (accounts, active) = discover_for_tray(&base);
            for a in &accounts {
                if !a.has_credentials {
                    continue;
                }
                let marker = if Some(a.id) == active { "● " } else { "  " };
                let label = format!("{}#{} {}", marker, a.id, a.label);
                let id = format!("acct:{}", a.id);
                let item = MenuItemBuilder::with_id(id, label).build(app)?;
                builder = builder.item(&item);
            }
            if !accounts.is_empty() {
                builder = builder.item(&PredefinedMenuItem::separator(app)?);
            }
        }
    }

    let open_dashboard = MenuItemBuilder::with_id("open", "Open Dashboard").build(app)?;
    let hide_dashboard = MenuItemBuilder::with_id("hide", "Hide Dashboard").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit Claude Squad").build(app)?;

    builder
        .item(&open_dashboard)
        .item(&hide_dashboard)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&quit)
        .build()
}

/// Handles a tray menu click.
///
/// Account rows carry an `acct:{id}` identifier — on click we run
/// `rotation::swap_to` for that account in every live config dir.
/// Fire-and-forget: errors are logged but not surfaced to the user
/// (the tray menu will refresh and show the new active account).
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
            if let Some(num_str) = s.strip_prefix("acct:") {
                if let Ok(n) = num_str.parse::<u16>() {
                    if let Ok(account) = AccountNum::try_from(n) {
                        if let Some(base) = base_dir() {
                            let config_dirs = fanout::scan_config_dirs(&base, account);
                            for config_dir in &config_dirs {
                                let _ = rotation::swap_to(&base, config_dir, account);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Rebuilds and reattaches the tray menu.
///
/// Called on a 30s interval so the tray reflects account additions,
/// deletions, and active-session changes made from the CLI or other
/// processes.
fn refresh_tray_menu(app: &AppHandle, tray: &TrayIcon) {
    if let Ok(menu) = build_tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_accounts,
            commands::swap_account,
            commands::get_rotation_config,
            commands::set_rotation_enabled,
            commands::get_daemon_status,
            commands::start_login,
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // ── Auto-updater ─────────────────────────────────
            // Registers the updater plugin. Actual update checks require
            // a signed update manifest at the configured endpoint.
            // Signing keys and update server are configured in M11.
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;

            // ── System tray ──────────────────────────────────
            let menu = build_tray_menu(app.handle())?;
            let tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Claude Squad")
                .on_menu_event(move |app, event| {
                    handle_tray_event(app, event.id().as_ref());
                })
                .build(app)?;

            // Refresh the tray menu every 30s so account changes
            // made from the CLI show up without restarting the app.
            let app_handle = app.handle().clone();
            let tray_handle = tray.clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                // First tick fires immediately; skip it since we
                // just built the menu above.
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
