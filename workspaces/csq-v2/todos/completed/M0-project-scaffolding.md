# M0: Project Scaffolding

Priority: P0 (Launch Blocker)
Effort: 1 autonomous session
Dependencies: None — this is the starting point
Phase: 0

---

## M0-01: Initialize Cargo workspace

Create root `Cargo.toml` with three workspace members: `csq-core` (library), `csq-cli` (binary), `src-tauri/` (Tauri binary). Use workspace dependencies per GAP-5 resolution. `cargo build` must succeed with empty crates.

- Scope: GAP-5
- Complexity: Moderate
- Acceptance:
  - [x] `cargo build` succeeds
  - [x] `cargo build -p csq-core` produces library
  - [x] `cargo build -p csq-cli` produces `csq` binary
  - [x] Workspace deps shared (serde, tokio, thiserror, anyhow)

## M0-02: Initialize Tauri project skeleton

Create `src-tauri/` with `tauri.conf.json`, `capabilities/main.json`, and minimal `src/main.rs`. Create Svelte frontend in `src/` with `App.svelte` and `main.ts`. `cargo tauri dev` must launch a blank window.

- Scope: ADR-002
- Complexity: Moderate
- Depends: M0-01
- Acceptance:
  - [x] `cargo tauri dev` launches window on macOS
  - [x] Svelte frontend renders "csq v2.0" placeholder
  - [x] `tauri.conf.json` has correct bundle identifier

## M0-03: Set up CI pipeline

GitHub Actions workflow: `cargo check` + `cargo test` + `cargo clippy` on push. `cargo tauri build` for release tags. Matrix: macOS-arm64, macOS-x86_64, Linux-x86_64, Windows-x86_64.

- Scope: Phase 0 deliverable
- Complexity: Complex
- Depends: M0-01, M0-02
- Acceptance:
  - [ ] CI green on all four matrix targets
  - [ ] Clippy passes with zero warnings (pedantic)
  - [ ] `cargo tauri build` produces platform installers on tag push

## M0-04: Configure linting and formatting

Enable `clippy::pedantic`. Configure `rustfmt.toml`. Add `cargo deny` for license and vulnerability audit. Create `justfile` with recipes: `build`, `test`, `lint`, `dev`, `release`.

- Scope: Phase 0 deliverable
- Complexity: Trivial
- Depends: M0-01
- Acceptance:
  - [x] `just lint` runs clippy + rustfmt check
  - [x] `just test` runs cargo test
  - [x] `cargo deny check` passes

## M0-05: Define cross-cutting types

Create `AccountNum` newtype (validated 1..MAX_ACCOUNTS via `TryFrom<u16>`). Create `AccessToken` and `RefreshToken` secret newtypes with masked `Display` (shows `sk-ant-...xxxx`). Place in `csq-core/src/types.rs`.

- Scope: Phase 0 deliverable
- Complexity: Moderate
- Depends: M0-01
- Acceptance:
  - [x] `AccountNum::try_from(0)` returns `Err`
  - [x] `AccountNum::try_from(1)` returns `Ok`
  - [x] `format!("{}", access_token)` shows `sk-ant-oat01-...xxxx`
  - [x] `AccessToken` does not implement `Serialize` (prevents accidental IPC leak)
  - [x] Token types use `secrecy::Secret<String>` with zeroize-on-drop (security finding S10)

## M0-06: Set up error handling and logging

Create `csq-core/src/error.rs` with `CsqError` hierarchy per GAP-4 resolution. Set up `tracing` with `CSQ_LOG` env filter. Add `tracing-subscriber` in `csq-cli/src/main.rs`.

- Scope: GAP-4
- Complexity: Moderate
- Depends: M0-01
- Acceptance:
  - [x] `CsqError` compiles with all module error variants
  - [x] `CSQ_LOG=debug csq` shows trace output
  - [x] Each error variant produces a readable `Display` message

## M0-07: Harden .gitignore

Ensure `.gitignore` includes: `config-*/`, `.credentials.json`, `.env`, `credentials/`, `.csq-account`, `.current-account`, `.live-pid`, `.quota-cursor`. Security finding H1.

- Scope: Security analysis H1
- Complexity: Trivial
- Acceptance:
  - [x] All credential-bearing paths listed in .gitignore
  - [x] `git status` does not show credential files
