mod commands;

use tauri::Manager;
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;

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
            app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;

            // ── System tray ──────────────────────────────────
            let open_dashboard = MenuItemBuilder::with_id("open", "Open Dashboard")
                .build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Quit Claude Squad")
                .build(app)?;
            let sep = PredefinedMenuItem::separator(app)?;

            let menu = MenuBuilder::new(app)
                .item(&open_dashboard)
                .item(&sep)
                .item(&quit)
                .build()?;

            TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Claude Squad")
                .on_menu_event(move |app, event| {
                    match event.id().as_ref() {
                        "open" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

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
