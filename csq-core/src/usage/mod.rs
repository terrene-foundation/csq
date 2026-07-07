//! Phase B' billing ledger — per-slot usage telemetry for pay-per-token slots.
//!
//! Per an internal journal entry (an internal workspace workspace). Reads CC's `~/.claude/usage-data/
//! session-meta/<session-id>.json` files which CC already writes per session,
//! attributes them to slots via the csq launch log (post-hoc time correlation
//! per D2), estimates cost from a static per-model rate table (D3), and
//! persists to `accounts/usage-{account_id}.ndjson` (D4 — account_id chokepoint
//! migrates trivially when an internal ticket / Option A++ ships).
//!
//! ## Module layout
//!
//! - [`launch_log`] — append/read `~/.claude/accounts/.csq-launch.log`. Written
//!   by `csq run` and `csq swap`; read by the aggregator to attribute sessions
//!   to slots.
//! - [`cost_rates`] — static per-model `input_per_1m_usd` + `output_per_1m_usd`
//!   table covering Anthropic, OpenAI, Gemini, DeepSeek, MiniMax, Z.AI.
//! - [`ledger`] — NDJSON read/write for the per-account ledger; aggregation
//!   over rolling time windows (Total / 30d / 7d / 5d / Today).
//! - [`account_id`] — `resolve_account_id` chokepoint matching A++ migration
//!   story exactly. Today returns slot # as string; post-A++ returns UUID.
//!
//! The daemon-side aggregator that scans session-meta + writes the ledger
//! lives at `crate::daemon::usage_aggregator` (separate module — depends on
//! daemon-only types).
//!
//! ## Privacy invariant (D6)
//!
//! All deserialization structs in this module ONLY include metadata fields
//! (model, tokens, timestamps, cost). Conversation content from
//! `~/.claude/projects/<cwd>/<session-id>.jsonl` is NEVER read or persisted.

pub mod account_id;
pub mod aggregator;
pub mod cost_rates;
pub mod launch_log;
pub mod ledger;
