//! Cross-CLI session messaging store (spec 32 §3, §7, §8).
//!
//! A sibling of the spec 31 directive store: messages live one-per-file under
//! `<accounts>/messages/` and reuse the directive store's public/`pub(crate)` primitives
//! (`FsOps`, the atomic write pipeline, the lock, the bounded no-follow reader, the
//! sanitiser) rather than a second copy. This module never writes quota or credentials
//! (`account-terminal-separation.md`).
//!
//! * [`model`] — the `csq.message.v1` record, lifecycle status and receipt.
//! * [`limits`] — csq-authoritative caps and the pure checks (body, rate, pending, eviction).
//! * [`frame`] — the untrusted-data frame every rendering of a body passes through.
//! * [`hook`] — the Claude Code per-turn surfacing hook output (spec 32 §5.2).
//! * [`store`] — the locked, atomic, fail-closed store operations.
//! * [`mcp`] — the `csq mcp-messaging` stdio MCP server (spec 32 §4.2).
//! * [`register`] — per-terminal registration of that server and the hooks (spec 32 §6).

pub mod deferred;
pub mod fleet_directory;
pub mod frame;
pub mod hook;
mod image_build_grammar;
pub mod image_report;
pub mod limits;
pub mod mcp;
pub mod model;
pub mod register;
pub mod registry;
pub mod request;
pub mod request_retry;
pub mod storage;
pub mod store;
pub mod wake;

pub use model::{
    Message, MessageView, Receipt, Recipient, Sender, Status, Surface, VerifiedSession,
};
