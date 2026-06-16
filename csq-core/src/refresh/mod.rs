//! Per-slot OAuth refresh + broker-failed sentinel API + canonical/live
//! credential synchronization.
//!
//! Renamed from `broker` (Phase 4 M4-6, issue #292) — `fan_out_credentials`
//! is retired (M3-7) and the surviving responsibility is per-slot refresh
//! coordination plus the sentinel flags used by the dashboard.

pub mod check;
pub mod sentinel;
pub mod sync;
