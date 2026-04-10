---
name: tauri-reference
description: "Tauri 2.x + Rust backend patterns for desktop applications. Use when writing Tauri commands, managing Rust app state, handling IPC between Svelte and Rust, error handling in Rust, or configuring Cargo dependencies for a Tauri app."
---

# Tauri Reference

Tauri 2.x with Rust backend for desktop account management. Covers command patterns, state management, IPC, error handling, and Tauri configuration.

## Tauri Commands

```rust
use tauri::command;

#[command]
pub fn list_accounts(state: State<AppState>) -> Result<Vec<Account>, String> {
    state.accounts.lock().unwrap().clone().ok_or("No accounts".into())
}

#[command]
pub async fn swap_to_account(index: usize, state: State<'_, AppState>) -> Result<(), String> {
    let mut accounts = state.accounts.lock().unwrap();
    // swap logic
    Ok(())
}
```

## App State

```rust
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub accounts: Mutex<Option<Vec<Account>>>,
    pub active_index: Mutex<usize>,
    pub credentials_path: PathBuf,
}

impl AppState {
    pub fn new(credentials_path: PathBuf) -> Self {
        Self {
            accounts: Mutex::new(None),
            active_index: Mutex::new(0),
            credentials_path,
        }
    }
}
```

## Error Handling

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OAuth error: {0}")]
    OAuth(String),
    #[error("No active account")]
    NoActiveAccount,
}

// Implement serialization for Tauri
impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
```

## IPC with Svelte

```rust
// src-tauri/src/main.rs
fn main() {
    tauri::Builder::default()
        .manage(AppState::new(config_dir()))
        .invoke_handler(tauri::generate_handler![
            list_accounts,
            swap_to_account,
            get_quota,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

## OAuth Token Management

```rust
pub struct OAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

impl OAuthToken {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.expires_at - 60 // 60s buffer
    }

    pub async fn refresh(&mut self, client_id: &str) -> Result<(), AppError> {
        // POST to platform.claude.com/oauth/token
        // Update access_token and refresh_token
        Ok(())
    }
}
```

## Cargo Dependencies (Tauri 2.x)

```toml
[dependencies]
tauri = { version = "2", features = ["devtools"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
chrono = "0.4"
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
```

## Plugin System

Tauri plugins are reusable modules that expose commands and manage state. Each plugin lives in `src-tauri/src/plugins/<name>/` and registers via `plugin::Builder::new()`.

```rust
// plugins/keychain/src/lib.rs
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Runtime, Manager};

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("keychain")
        .invoke_handler(tauri::generate_handler![
            get_credential,
            set_credential,
            delete_credential,
        ])
        .setup(|app, _api| {
            // Plugin startup work
            Ok(())
        })
        .build()
}

#[tauri::command]
async fn get_credential(service: String, account: String) -> Result<String, String> {
    // Keychain read
    Ok(String::new())
}
```

Register the plugin in `lib.rs`:

```rust
tauri::Builder::default()
    .plugin(keychain::init())
    .plugin(tauri_plugin_dialog::init())  // official plugin
    .run(tauri::generate_context!())?;
```

**Official plugins to know:** `tauri-plugin-dialog` (native dialogs), `tauri-plugin-fs` (filesystem), `tauri-plugin-shell` (spawn processes), `tauri-plugin-notification` (native toasts), `tauri-plugin-store` (key-value persistence), `tauri-plugin-updater` (auto-update).

## Multi-Window Management

Tauri lets you open multiple windows, each with its own Svelte context, permissions, and lifecycle.

```rust
use tauri::WebviewWindowBuilder;

#[tauri::command]
async fn open_settings(app: tauri::AppHandle) -> Result<(), String> {
    WebviewWindowBuilder::new(
        &app,
        "settings",  // unique label
        tauri::WebviewUrl::App("settings.html".into())
    )
    .title("Settings")
    .inner_size(600.0, 400.0)
    .resizable(true)
    .center()
    .build()
    .map_err(|e| e.to_string())?;
    Ok(())
}
```

**Targeting a specific window:**

```rust
use tauri::Manager;

#[tauri::command]
fn notify_main(app: tauri::AppHandle, message: String) -> Result<(), String> {
    app.get_webview_window("main")
        .ok_or("main window not found")?
        .emit("notification", message)
        .map_err(|e| e.to_string())
}
```

**Capabilities per window** — each window can have its own permission scope in `src-tauri/capabilities/`:

```json
// capabilities/settings.json
{
  "identifier": "settings-window",
  "windows": ["settings"],
  "permissions": ["core:default", "dialog:allow-open"]
}
```

The settings window cannot invoke commands outside its granted permissions — main-window-only commands are blocked automatically.

## Tauri Configuration (tauri.conf.json)

```json
{
  "productName": "Claude Squad",
  "identifier": "foundation.terrene.claude-squad",
  "build": {
    "devtools": true
  },
  "app": {
    "windows": [{ "title": "Claude Squad", "width": 800, "height": 600 }],
    "security": {
      "csp": null
    }
  }
}
```

## CRITICAL Gotchas

| Rule                                              | Why                                                     |
| ------------------------------------------------- | ------------------------------------------------------- |
| Return `Result<T, String>` from all commands      | `String` maps to JS `Error`; custom types need Serialize |
| Use `State<T>` for shared mutable state           | Plain static globals don't work with Tauri's lifecycle |
| Mark `async` commands with `.await` in Rust       | Deadlocks if you `.lock()` inside async                 |
| Set `devtools: true` in tauri.conf.json build    | Required for `/analyze` hooks in dev                   |
| Handle token expiration before every API call      | Desktop app runs long sessions; tokens expire            |
