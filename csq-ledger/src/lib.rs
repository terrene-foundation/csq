//! csq-ledger — Foundation-owned transparency-log server (M10).
//!
//! A self-hostable HTTP/JSON transparency log built on a native RFC 6962
//! Merkle tree (no the enterprise edition / eatp dependency — correction 2) and csq's
//! existing crypto primitives (`ed25519-dalek` + `sha2`).
//!
//! # Architecture
//!
//! - [`merkle`] — native RFC 6962 Merkle tree: leaf/interior domain
//!   separation, inclusion proofs, consistency proofs (with test vectors).
//! - [`storage`] — append-only segment-file store; fsync before any ack; NO
//!   delete/truncate/compact/vacuum/wipe/prune/gc (PRIMARY DIRECTIVE 1 + 2 + 6).
//! - [`signing`] — server-side checkpoint signing key; first-boot auto-gen at
//!   0o600 + persistent WARN (decision 2).
//! - [`checkpoint`] — signed tree head with deterministic pre-image + the
//!   `anchored_to` field.
//! - [`anchor`] — `--anchor-to-sink` strengthening, consuming csq-core's M07
//!   `LedgerSink` trait (PRIMARY DIRECTIVE 3 — no new sink trait here).
//! - [`server`] — axum HTTP/JSON routes (PRIMARY DIRECTIVE 5 — axum, not tonic).
//! - [`config`] — CLI configuration parsing.
//!
//! The full protocol is specified in `specs/17-csq-ledger-protocol.md`.

pub mod anchor;
pub mod anchor_verdict;
pub mod checkpoint;
pub mod config;
pub mod merkle;
pub mod server;
pub mod signing;
pub mod storage;
