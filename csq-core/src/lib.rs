pub mod accounts;
pub mod audit;
pub mod capability_layer;
pub mod cli_deps;
pub mod coc;
pub mod credentials;
pub mod daemon;
pub mod env;
pub mod error;
pub mod http;
pub mod oauth;
// Phase-2b direct-API provider client infrastructure (enterprise edition only).
// Compiled only when the `enterprise` feature is active.  Community builds
// (`cargo build -p csq-core`) MUST NOT depend on this module or any type it
// exports.  Gate verification: `cargo build -p csq-core` (no --features) must
// succeed with this declaration present.
#[cfg(feature = "enterprise")]
pub mod phase2b;
pub mod platform;
pub mod probe;
pub mod providers;
pub mod quota;
pub mod refresh;
pub mod rotation;
pub mod session;
pub mod sessions;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
pub mod types;
pub mod update;
pub mod usage;
