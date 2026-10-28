pub mod accounts;
#[cfg(all(test, unix))]
mod ascii_probe;
// Crate-internal `declare_all_enum!` macro (never cross-crate-exported — see
// its own doc for why). Declared early so every module below can `use
// crate::all_enum::declare_all_enum;`.
mod all_enum;
pub mod audit;
pub mod capability_layer;
pub mod chat_sessions;
pub mod cli_deps;
pub mod coc;
pub mod credentials;
pub mod daemon;
pub mod env;
pub mod error;
pub mod gate;
pub mod http;
pub mod messaging;
pub mod oauth;
pub mod platform;
pub mod pool;
pub mod probe;
pub mod providers;
pub mod quota;
pub mod refresh;
pub mod relay;
pub mod rotation;
pub mod sdk;
pub mod session;
pub mod sessions;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
pub mod types;
pub mod update;
pub mod usage;

// Test-only harness (Unix): a forked child parked on a pipe holds its
// inherited descriptors without exec'ing, so a lock's Drop can be asserted
// to be the release point. Not part of any production build.
#[cfg(all(test, unix))]
pub(crate) mod fork_harness;
