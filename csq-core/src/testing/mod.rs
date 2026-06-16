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
