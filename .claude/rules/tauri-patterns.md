---
name: tauri-patterns
description: Tauri 2.x + Rust backend patterns for desktop apps. Applies to Rust backend code and Tauri command handlers.
triggers:
  - "writing or reviewing Rust backend code in a Tauri app"
  - "creating Tauri command handlers"
  - "designing IPC between frontend and backend"
  - "Rust file touched in src-tauri/"
paths:
  - "src-tauri/**/*.rs"
  - "**/*.rs" (Tauri context)
---

# Rust Desktop Patterns

Applies to all Rust code in `src-tauri/`. Covers Tauri state, IPC, error handling, and plugin patterns.

## Command Handlers

Commands register via `#[tauri::command]` in `src-tauri/src/lib.rs`. Keep them small — they are the frontend/backend boundary. Move logic into pure Rust functions.

```rust
#[tauri::command]
pub async fn get_config(path: String) -> Result<Config, String> {
    Config::load(&path).map_err(|e| e.to_string())
}
```

Validate every argument inside the handler before passing to internal functions:

```rust
#[tauri::command]
fn update_account(account_id: String, name: String) -> Result<(), String> {
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    if name.len() > 256 {
        return Err("name exceeds 256 characters".into());
    }
    internal_update(account_id, name)
}
```

## Shared State

Use `tauri::State` for resources shared across commands. `RwLock` for read-heavy, `Mutex` when write ordering matters.

```rust
pub struct AppState {
    pub config: RwLock<Option<Config>>,
    pub http: Client,
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    state.config.read().unwrap().clone().ok_or_else(|| "not configured".into())
}
```

**Never hold a lock across an `await` point.** Async blocks can switch threads, causing deadlocks:

```rust
// DO — release before await
{
    let mut guard = state.config.write().unwrap();
    *guard = Some(new_config);
}
// guard dropped before any async work

// DO NOT — lock held across await
let mut guard = state.config.write().unwrap();
save_to_disk(&guard).await; // deadlock risk
```

## IPC and Serialization

All IPC uses serde. IPC types are a contract with the frontend — keep them minimal and never include sensitive fields on serializable structs.

```rust
// BAD — secret leaks to frontend via IPC
#[derive(Serialize)]
pub struct Account { pub name: String, pub api_key: String }

// GOOD — public view only
#[derive(Serialize)]
pub struct AccountPublic { pub name: String, pub key_id: String }
```

## Events

Use `app.emit()` to push events from Rust to the frontend:

```rust
app.emit("query-progress", QueryProgress { percent: 50 }).unwrap();
```

Svelte side:

```typescript
import { listen } from '@tauri-apps/api/event';
listen<QueryProgress>("query-progress", (event) => {
  progress = event.payload.percent;
});
```

Every event payload needs `#[derive(Serialize)]`.

## Error Handling

Use `thiserror` at the command boundary for typed variants the frontend can handle. Use `anyhow` for internal propagation.

```rust
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("config not found at {path}")]
    ConfigMissing { path: String },
    #[error("invalid account id: {0}")]
    InvalidAccount(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```

## Plugins

Each plugin lives in `src-tauri/src/plugins/<name>/` and exposes commands via `plugin::Builder::new()`:

```rust
pub fn init() -> impl Plugin {
    Builder::new()
        .invoke_handler(tauri::generate_handler![query])
        .build()
}
```

Plugins needing runtime config receive it through their own struct parsed from `tauri.conf.json`. Never hardcode plugin settings.

## Testing

Unit tests live in the same file behind `#[cfg(test)]`. Integration tests use `#[tokio::test]` with a harness that starts the app.

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn config_loads_valid_file() {
        let cfg = Config::load("testdata/valid.toml").unwrap();
        assert_eq!(cfg.accounts.len(), 2);
    }
}
```

## MUST Rules

### 1. Every command returns `Result` or `Option`, never panics

Return `Result<T, String>` and map errors explicitly.

**Why:** Panics cross the IPC boundary as opaque 500 errors that the frontend cannot meaningfully handle or recover from.

### 2. Async commands do not block the main thread

Use `tokio::spawn_blocking` for CPU-heavy work.

**Why:** Blocking the Tauri event loop freezes window rendering and tray updates; users see a beachball and force-quit the app.

### 3. Shared state is `Send + Sync`

Wrap shared data in `RwLock` or `Mutex` from std or `parking_lot`.

**Why:** Non-thread-safe state in `tauri::State` produces data races that silently corrupt memory, with symptoms appearing hours after the race.

### 4. Validate all string inputs at the command boundary

**Why:** Assuming IPC payloads are well-formed turns every command into an attack surface; validation at the boundary is the only guarantee that downstream code sees safe data.

## Anti-Patterns

```rust
// BAD — lock held across await
let _guard = state.lock().unwrap();
some_async_op().await;
// GOOD — clone out, then await
let data = { state.lock().unwrap().clone() };
some_async_op(data).await;

// BAD — panic instead of Result
let val = map.get("key").unwrap();
// GOOD — propagate
let val = map.get("key").ok_or_else(|| "key not found")?;
```

## Cross-References

- `tauri-commands.md` — command API design rules
- `svelte-patterns.md` — frontend consumption
- `security.md` — credential and keychain handling
