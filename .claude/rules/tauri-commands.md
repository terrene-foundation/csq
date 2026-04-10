---
name: tauri-commands
description: Tauri command API design, naming conventions, argument validation, and error handling. Applies to Tauri command handler functions.
triggers:
  - "creating a new Tauri command"
  - "designing the API between frontend and Rust backend"
  - "returning errors from a Tauri command"
paths:
  - "src-tauri/**/*.rs" (command handlers)
---

# Tauri Commands API Design

Applies to all `#[tauri::command]` definitions in `src-tauri/`. Covers naming, validation, error mapping, permissions, and multi-window patterns.

## Naming

Commands are public API visible to the frontend. Name them as imperative verbs:

```
get_config       — returns a value
set_account      — sets state
rotate_key       — performs an action with side effects
query_search     — long-running query operation
```

Avoid generic names like `do_it` or `update`. Use `#[tauri::command(skip)]` to exclude internal handlers from IPC.

## Argument Validation

The command handler is the last line of defense before data reaches core logic. Validate every argument before calling any internal function.

```rust
#[tauri::command]
fn create_index(name: String, model: String) -> Result<Index, String> {
    if !is_valid_name(&name) {
        return Err(format!("invalid index name: {name}"));
    }
    if model.is_empty() {
        return Err("model must not be empty".into());
    }
    Index::create(&name, &model).map_err(|e| e.to_string())
}

fn is_valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}
```

Validation errors MUST be descriptive — include the field and the actual value:

```
BAD:  Err("invalid input".into())
GOOD: Err("account_id must be 1-999, got 'abc'".into())
```

## Error Mapping

Map Rust errors to a typed code the frontend can handle. Use `thiserror` for cross-boundary errors, `anyhow` for internal propagation.

```rust
#[derive(Clone)]
pub enum CommandError {
    NotFound,
    InvalidInput(String),
    PermissionDenied,
    Internal(String),
}

impl From<CommandError> for String {
    fn from(e: CommandError) -> String {
        match e {
            CommandError::NotFound => "NOT_FOUND".into(),
            CommandError::InvalidInput(msg) => format!("INVALID_INPUT: {msg}"),
            CommandError::PermissionDenied => "PERMISSION_DENIED".into(),
            CommandError::Internal(msg) => format!("INTERNAL_ERROR: {msg}"),
        }
    }
}
```

## Async Commands

Use async for anything that might wait — file I/O, network, DB queries. For long-running work (>1s), emit progress events instead of blocking:

```rust
#[tauri::command]
async fn bulk_import(paths: Vec<String>, app: AppHandle) -> Result<ImportSummary, String> {
    let total = paths.len();
    for (i, path) in paths.iter().enumerate() {
        import_single(path).map_err(|e| e.to_string())?;
        let _ = app.emit("import-progress", Progress { completed: i + 1, total });
    }
    Ok(ImportSummary { total })
}
```

## Return Types

Return types MUST implement `serde::Serialize`. Keep shapes flat:

```rust
#[derive(Serialize)]
pub struct AccountView {  // never expose secrets
    pub id: u32,
    pub label: String,
}
```

## Permissions

Tauri uses capability-based security. Scope commands per-window, not globally:

```json
// src-tauri/capabilities/main.json
{
  "identifier": "main-window",
  "windows": ["main"],
  "permissions": ["core:default", "query:allow-get-config"]
}
```

Assume renderer code is potentially adversarial — never expose admin commands to the renderer unless explicitly granted.

## Multi-Window

Target specific windows explicitly via `AppHandle::emit_to`:

```rust
#[tauri::command]
fn notify_progress(app: AppHandle, window: String, percent: u8) -> Result<(), String> {
    app.emit_to(&window, "progress", percent).map_err(|e| e.to_string())
}
```

Commands that modify window state (size, position, focus) MUST validate bounds. Reject zero or negative dimensions.

## MUST Rules

### 1. Every command returns Result or Option

Never let a command panic into the frontend.

**Why:** A panic from an unwrap becomes an opaque 500 error with no useful body, leaving the frontend unable to recover or show a meaningful message.

### 2. Validate all string and numeric arguments at the handler

**Why:** Bad data that slips past the handler reaches deeper code that trusts its inputs, turning a validation miss into a logic bug or injection vector.

### 3. Sensitive data MUST NOT appear in return types

Audit every field on every `#[derive(Serialize)]` struct. Credentials, tokens, and keys belong in the keychain, not IPC payloads.

**Why:** Tauri IPC payloads are serialized to the renderer and can be captured by devtools or logged by any listening window — one leaked token compromises every session.

### 4. Long-running commands MUST emit progress events

Emit at least every 100ms during bulk operations.

**Why:** A user waiting more than one second without feedback assumes the app is frozen and force-quits, losing unsaved work.

### 5. Commands MUST be idempotent or clearly documented

If calling a command twice has different effects, document it in the handler docstring.

**Why:** Non-idempotent commands that aren't documented cause retry logic in the frontend to double-apply side effects, corrupting state.

## MUST NOT Rules

### 1. No sensitive data in event payloads

Events can be listened to by any window.

**Why:** `app.emit()` broadcasts to every window in the app; one leaked credential in a progress event is visible to every listening renderer.

### 2. No `unwrap()` or `expect()` in command handlers

Use `?` to propagate as Result.

**Why:** `unwrap()` panics on `None` or `Err`, crashing the handler with no Result to return — the frontend sees an opaque error it cannot handle.

### 3. No blocking the main thread

CPU-heavy work runs in `tokio::spawn_blocking`.

**Why:** Blocking the main loop freezes the entire desktop app, including window rendering and tray menu updates — users see a beachball and assume a crash.

### 4. No global mutable state without synchronization

Protect every cross-command global with `Mutex` or `RwLock`.

**Why:** Data races in desktop apps corrupt memory silently; the symptom appears as "random" state drift hours after the race happened.

### 5. No state-modifying command without validation

Validate the requester's permissions, not just data format.

**Why:** Format-only validation passes malicious but well-formed requests; the permission check is the actual security boundary.

## Anti-Patterns

```rust
// BAD — leaks internal paths
return Err(format!("failed to open DB at {:?}: {}", db_path, e));
// GOOD — sanitized
return Err("database unavailable".into());

// BAD — unbounded input
fn process_files(paths: Vec<String>) { ... }
// GOOD — bounded at boundary
if paths.len() > 1000 {
    return Err("too many files: maximum 1000".into());
}
```

## Cross-References

- `tauri-patterns.md` — backend implementation patterns
- `svelte-patterns.md` — frontend consumption of commands
- `security.md` — credential and keychain handling
