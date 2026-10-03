//! Test-only utilities for csq-core.
//!
//! Gated by `#[cfg(any(test, feature = "test-utils"))]` so this module
//! compiles into:
//!
//! - The crate's own `cargo test` runs (via `cfg(test)`).
//! - External test consumers that enable `csq-core/test-utils`
//!   (integration tests, `coc-eval`, M1-4 acceptance tests).
//!
//! It MUST NOT be compiled into production binaries. The `test-utils` feature
//! in `csq-core/Cargo.toml` is `test-utils = ["dep:tempfile"]`; the `tempfile`
//! crate is an optional regular dependency gated by that feature, not a
//! dev-dependency. This is the canonical pattern established by
//! `discovery_test_utils_feature_gate_pattern`.

pub mod identity_fixtures;

/// Serialises every test in this crate that installs a scoped tracing
/// dispatcher (`tracing::subscriber::with_default`) to capture events.
///
/// `with_default` is thread-local, but entering and leaving it also updates
/// tracing's process-global max-level filter, which `warn!` consults before
/// dispatching. Two captures running concurrently can transiently lower that
/// filter while the other thread's event is evaluated, so the capture sees
/// nothing: a false RED for "event emitted" and a false GREEN for "no event".
/// One lock shared by every capturing test closes that window. A test that
/// reaches a captured callsite WITHOUT capturing it takes the lock too: its
/// first hit can cache the callsite as disabled mid-capture.
pub static TRACING_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
