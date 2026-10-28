//! E2E test harness module re-exports.
//!
//! Each submodule below is included by the `oauth_e2e.rs` integration
//! test entry point. Splitting the harness from the canned-response
//! fixtures and the fake-browser helper keeps each piece small enough
//! to read on one screen.

pub mod canned_responses;
pub mod fake_browser;
pub mod fake_transport;
pub mod harness;
