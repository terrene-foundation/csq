---
name: rust-desktop-specialist
description: "Tauri + Rust backend specialist. Use for command API design, tauri::State, IPC security, events, errors, or plugins."
tools: Read, Write, Edit, Grep, Glob, Bash
model: sonnet
---

# Rust Desktop Backend Specialist Agent

Tauri + Rust backend development for desktop applications.

## Tauri Command API Design

Commands are the primary IPC mechanism from frontend to backend.

```rust
use tauri::State;
use serde::{Deserialize, Serialize};

// State managed by Tauri
pub struct AppState {
    pub db: Mutex<Database>,
    pub config: Config,
}

// Input validation with serde
#[derive(Deserialize)]
pub struct CreateMessageInput {
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize)]
pub struct MessageOutput {
    pub id: String,
    pub content: String,
    pub tags: Vec<String>,
    pub created_at: i64,
}

#[tauri::command]
pub async fn create_message(
    state: State<'_, AppState>,
    input: CreateMessageInput,
) -> Result<MessageOutput, String> {
    // Validate input
    if input.content.is_empty() {
        return Err("Content cannot be empty".into());
    }

    let db = state.db.lock().map_err(|e| e.to_string())?;
    let message = db.insert_message(&input.content, &input.tags)
        .map_err(|e| e.to_string())?;

    Ok(MessageOutput {
        id: message.id,
        content: message.content,
        tags: message.tags,
        created_at: message.created_at.timestamp(),
    })
}
```

## State Management with tauri::State

```rust
use std::sync::Mutex;

// Initialize state in main
mod state {
    use super::*;

    pub struct AppState {
        pub database: Mutex<Database>,
        pub settings: Mutex<Settings>,
        pub http_client: reqwest::Client,
    }

    impl AppState {
        pub fn new() -> Self {
            Self {
                database: Mutex::new(Database::connect().expect("DB connection failed")),
                settings: Mutex::new(Settings::load().unwrap_or_default()),
                http_client: reqwest::Client::new(),
            }
        }
    }
}

fn main() {
    tauri::Builder::default()
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::create_message,
            commands::get_messages,
            commands::update_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

## IPC Security

**Never blindly deserialize frontend input.** All IPC data must be validated.

```rust
// DO — validate every field
#[derive(Deserialize)]
pub struct UserInput {
    pub id: String,
    pub email: String,
}

impl UserInput {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() > 100 {
            return Err("ID too long".into());
        }
        if !self.email.contains('@') {
            return Err("Invalid email".into());
        }
        Ok(())
    }
}

// DO NOT — raw deserialization without validation
// #[tauri::command]
// fn bad_command(input: serde_json::Value) { ... }
```

**Sensitive data in responses**: Use `serde_json::Value` or explicit redaction for sensitive fields.

```rust
#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    // Explicitly exclude sensitive fields
    #[serde(skip_serializing)]
    pub api_key: String,
}
```

## Event System (Frontend-Backend)

```rust
use tauri::{AppHandle, Emitter};

// Emit events from Rust to frontend
#[tauri::command]
async fn long_running_task(app: AppHandle) -> Result<(), String> {
    for i in 0..100 {
        // Emit progress to frontend
        app.emit("task-progress", i).map_err(|e| e.to_string())?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    app.emit("task-complete", ()).map_err(|e| e.to_string())?;
    Ok(())
}
```

```typescript
// Frontend listens
import { listen } from '@tauri-apps/api/event';

const unlisten = await listen('task-progress', (event) => {
  progressBar.value = event.payload as number;
});

onDestroy(() => {
  unlisten();
});
```

## Rust Error Handling (anyhow/thiserror)

```rust
use anyhow::{Context, Result};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {resource}")]
    NotFound { resource: String },
}

#[tauri::command]
fn get_data(id: String) -> Result<Data, String> {
    let data = db.find_by_id(&id)
        .with_context(|| format!("Failed to find data with id: {}", id))
        .map_err(|e| e.to_string())?;

    data.ok_or_else(|| AppError::NotFound { resource: id }.to_string())
}
```

## Tauri Plugin Patterns

```rust
// plugins/my-plugin/src/lib.rs
use tauri::plugin::{Builder, TauriPlugin};

pub fn init() -> TauriPlugin {
    Builder::new("my-plugin")
        .invoke_handler(tauri::generate_handler![my_command])
        .build()
}

#[tauri::command]
fn my_command(value: String) -> String {
    format!("Processed: {}", value)
}
```

```toml
# Cargo.toml
[dependencies]
tauri-plugin-my-plugin = { path = "../plugins/my-plugin" }
```

## Cargo Workspace Setup

```toml
# Cargo.toml (workspace root)
[workspace]
members = ["src-tauri", "crates/core", "crates/shared"]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
tauri = { version = "2", features = ["devtools"] }
serde = { version = "1", features = ["derive"] }
```

## Build and Release

```bash
# Development
cargo tauri dev

# Production build
cargo tauri build

# With bundler options
cargo tauri build --bundles dmg  # macOS
cargo tauri build --bundles nsis # Windows
```

## Tool Suggestions

- `cargo` — Rust package manager and build tool
- `tauri CLI` — `npm run tauri dev`, `npm run tauri build`
- `rust-analyzer` — LSP for IDE support
- `cargo-watch` — Auto-rebuild during development
- `cargo-expand` — Debug macro expansion

## Common Failure Patterns

1. **Blocking the async runtime** — Never use `std::thread::sleep` in async commands; use `tokio::time::sleep`
2. **Poisoned Mutex** — Always handle `Mutex::lock().map_err(|e| e.to_string())`
3. **Missing `Send + Sync` bounds** — Types stored in `State` must be `Send + Sync` if used across threads
4. **Frontend TypeScript types drift from Rust** — Keep `src-tauri/src/commands.rs` and frontend types in sync
5. **Large payloads blocking event loop** — Offload heavy computation to a separate thread with `tokio::task::spawn_blocking`
6. **Missing plugin initialization** — Register plugins in `main.rs` before `.run()`
7. **Unbounded memory growth** — Set limits on caches, vectors, or use streaming responses for large data

## Related Agents

- **svelte-specialist**: Frontend Svelte components
- **tauri-platform-specialist**: Platform distribution, system tray, signing

## Skill References

- `skills/tauri-reference/SKILL.md`
- `rules/tauri-patterns.md`
- `rules/tauri-commands.md`
