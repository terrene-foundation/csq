//! Owner bridge over Telegram — the local, credential-bearing half.
//!
//! The bridge lets the machine's owner send a message to their own Telegram bot
//! and have it delivered to a csq session. Only the pinned owner is accepted;
//! every inbound update is validated, attested and (in the daemon layer) audited.
//!
//! A message that passes this chain is the owner typing: there is no second
//! factor and no extra approval gate on top of it.
//!
//! Module map:
//!
//! * [`config`](crate::bridge::config) — `<base_dir>/telegram-bridge.json`
//!   (owner ids, enabled flag, allowed action classes), the poll cursor and the
//!   kill-switch marker.
//! * [`secrets`](crate::bridge::secrets) — vault-backed bot token and
//!   attestation origin key.
//! * [`validator`](crate::bridge::validator) — the pure, table-tested
//!   inbound-update screen.
//! * [`attestation`](crate::bridge::attestation) — the HMAC-SHA256 owner-origin
//!   proof. `mint` is `pub(crate)` so the separate `csq` CLI crate has no path
//!   to forge an origin.
//! * [`enroll`](crate::bridge::enroll) — the owner-enrolment handshake
//!   (`csq telegram pair`). The pairing code exists only in process memory.
//! * [`telegram_api`](crate::bridge::telegram_api) — the minimal Bot API
//!   transport (`getUpdates`, `sendMessage`) behind an injectable trait.
//! * [`notify`](crate::bridge::notify) — the outbound owner ping
//!   (`csq notify-owner`): the pinned destination, the kill switch, the
//!   persisted rate limit, the disclosure scrub and the signed-chain audit
//!   pair.
//!
//! Neither the bot token nor the origin key may appear in a log, an error
//! message, `Debug` output or argv (`security.md` MUST-2). Every error that can
//! arise next to one of them maps to a fixed `error_kind` tag.

pub mod attestation;
pub mod config;
pub mod enroll;
pub mod notify;
pub mod secrets;
pub mod telegram_api;
pub mod validator;

pub use attestation::OwnerAttestation;
pub use config::{BridgeConfig, BridgeConfigError};
pub use validator::{validate_update, RawUpdate, Reject, ValidatedUpdate};
