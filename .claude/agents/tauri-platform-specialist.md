---
name: tauri-platform-specialist
description: "Tauri platform specialist. Use for macOS/Windows/Linux specifics, signing, tray, dialogs, windows, or auto-update."
tools: Read, Write, Edit, Grep, Glob, Bash
model: sonnet
---

# Tauri Platform Specialist Agent

Platform-specific configuration and distribution for Tauri desktop applications.

## Platform-Specific Configuration

### tauri.conf.json Structure

```json
{
  "productName": "Claude Squad",
  "identifier": "dev.terrene.claude-squad",
  "build": {
    "devtools": true
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/32x32.png",
      "icons/128x128.png",
      "icons/128x128@2x.png",
      "icons/icon.icns",
      "icons/icon.ico"
    ],
    "macOS": {
      "minimumSystemVersion": "10.13"
    },
    "windows": {
      "certificateThumbprint": null,
      "digestAlgorithm": "sha256",
      "timestampUrl": ""
    }
  }
}
```

## App Signing and Distribution

### macOS Signing

```bash
# Development (ad-hoc)
cargo tauri build --target aarch64-apple-darwin

# Production requires:
# 1. Apple Developer account
# 2. Signing certificate from Keychain
# 3. Provisioning profile for distribution

export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export APPLE_PROVIDER_SHORT_NAME="Your Name"

cargo tauri build
```

### Windows Signing

```bash
# Use Azure Trusted Signing or code signing certificate
# https://learn.microsoft.com/en-us/azure/trusted-signing/

cargo tauri build --bundles nsis
```

### Linux AppImage/snap

```bash
cargo tauri build --target x86_64-unknown-linux-gnu --bundles appimage
```

## System Tray and Menu Bar

```rust
// src-tauri/src/tray.rs
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

pub fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &quit])?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("Claude Squad")
        .on_menu_event(|app, event| {
            match event.id.as_ref() {
                "quit" => {
                    app.exit(0);
                }
                "show" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}
```

## Native Dialogs and Window Management

```rust
// Native file picker
use tauri_plugin_dialog::DialogExt;

#[tauri::command]
async fn pick_file(app: tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    app.dialog()
        .file()
        .add_filter("Documents", &["pdf", "doc", "docx"])
        .blocking_pick_file()
        .map(|p| p.map(|f| f.into()))
        .ok_or_else(|| "No file selected".into())
}

// Window controls
#[tauri::command]
async fn set_always_on_top(window: tauri::Window) -> Result<(), String> {
    window.set_always_on_top(true).map_err(|e| e.to_string())
}
```

## Platform Detection Patterns

```rust
use std::env;

pub fn get_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

// Or use tauri-plugin-os
use tauri_plugin_os::Utils;

let platform = Utils::platform_name().unwrap_or_else(|_| "unknown".into());
```

## Permissions and Capabilities

```json
// src-tauri/capabilities/main.json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "main-capability",
  "description": "Main application capability",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "core:window:allow-close",
    "core:window:allow-minimize",
    "core:window:allow-maximize",
    "core:window:allow-set-always-on-top",
    "core:window:allow-is-maximized",
    "dialog:default",
    "dialog:allow-open",
    "dialog:allow-save",
    "os:default",
    "shell:allow-open",
    "notification:default"
  ]
}
```

## Auto-Updater Configuration

```rust
// src-tauri/src/updater.rs
use tauri_plugin_updater::UpdaterExt;

pub fn setup_updater(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    app.handle().plugin(
        tauri_plugin_updater::Builder::new()
            .endpoints(["https://releases.terrene.dev/claude-squad/{{target}}/{{arch}}/{{current_version}}"])
            .signing_public_keys("YOUR_PUBLIC_KEY")
            .build(),
    )?;
    Ok(())
}
```

## Tool Suggestions

- `tauri config` — Edit `tauri.conf.json` with validation
- Platform SDKs: Xcode (macOS), Visual Studio (Windows), distro SDKs (Linux)
- `codesign` (macOS), `signtool` (Windows) for signing
- `create-dmg` for macOS distribution

## Common Failure Patterns

1. **Missing capabilities** — Every plugin/permission needs a corresponding entry in `capabilities/`
2. **Incorrect identifier** — Must be valid reverse domain (`dev.terrene.app-name`)
3. **Hardcoded paths** — Use `PathResolver` or environment variables for resource paths
4. **Signing identity expired** — Certificate expiration causes silent failures on macOS
5. **Auto-updater without signature verification** — Always verify update signatures
6. **Window state not persisted** — Save/restore window position and size in local storage
7. **Menu bar on macOS not showing** — Use `NSMenu` via Tauri menu API, not HTML overlays

## Related Agents

- **rust-desktop-specialist**: Rust backend and Tauri commands
- **svelte-specialist**: Frontend Svelte UI

## Skill References

- `skills/tauri-reference/SKILL.md`
- `rules/tauri-commands.md`
