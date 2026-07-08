//! Phase B' billing ledger — per-slot usage telemetry for pay-per-token slots.
//!
//! Per an internal journal entry (an internal workspace workspace). Reads CC's per-session transcripts
//! at `~/.claude/projects/<encoded-cwd>/<session-id>.jsonl` (an internal ticket — the
//! original `~/.claude/usage-data/session-meta/` source was never written by
//! CC, so the ledger was empty for every slot), attributes them to slots via
//! the csq launch log (post-hoc time correlation per D2), estimates cost from
//! a static per-model rate table (D3), and persists to the per-account ledger
//! (D4): `identities/<UUID>/usage.ndjson` once `profiles.json` `by_slot` is
//! populated (A++ / an internal ticket has shipped), else the legacy
//! `accounts/usage-{slot}.ndjson`.
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
//! - [`account_id`] — `resolve_account_id` chokepoint: returns the account's
//!   permanent UUID when `by_slot` maps the slot (A++ / an internal ticket), else the
//!   slot number as a string (legacy fallback).
//!
//! ## Privacy invariant (D6)
//!
//! All deserialization structs in this module ONLY include metadata fields
//! (model, token counts, timestamps, cost). The transcript scanner
//! ([`aggregator`]) line-streams `~/.claude/projects/<cwd>/<session-id>.jsonl`
//! through content-free deser structs: conversation content is never
//! *retained* or *persisted* — only token/cwd/timestamp/model metadata is
//! extracted in-memory (serde drops the absent content fields). See
//! [`aggregator`]'s module docs for the exact contract.

pub mod account_id;
pub mod aggregator;
pub mod cost_rates;
pub mod launch_log;
pub mod ledger;
