//! Storage foundation; JSON records and the request ledger remain authoritative.
//! These values and guards do not select a backend or route a foreground operation.

pub mod legacy_guard;
pub mod secure;
pub mod values;
