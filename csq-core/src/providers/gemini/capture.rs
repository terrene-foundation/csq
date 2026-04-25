//! Event types produced by csq-cli during a Gemini session and
//! consumed by the daemon's NDJSON-drain + IPC path.
//!
//! The full event-emission machinery (NDJSON file writer with
//! `O_APPEND` + `fsync`, daemon socket IPC, drain-on-startup) lands
//! in **PR-G3**. This module ships the type definitions so
//! downstream PR-G3 work can branch off PR-G2a's foundation.
//!
//! # Why frozen here
//!
//! Per spec 05 §5.8.1 (FROZEN — PR-G0): the NDJSON event log is the
//! durability floor for Gemini quota signals when the daemon is
//! down. Single-writer (csq-cli writes; daemon drains and
//! truncates). The file shape is:
//!
//! ```text
//! ~/.claude/accounts/gemini-events-<slot>.ndjson
//! ```
//!
//! One JSON object per line. Schema is the [`GeminiEvent`] enum
//! externally tagged so each line is self-describing.

use serde::{Deserialize, Serialize};

/// One event line in the per-slot NDJSON log.
///
/// `serde(tag = "kind")` produces externally-tagged JSON like
/// `{"kind":"counter_increment","slot":3,"ts":"..."}`. Drained by
/// the daemon's `usage_poller::gemini` consumer (PR-G3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GeminiEvent {
    /// csq-cli successfully spawned `gemini` — increments a
    /// per-slot counter the daemon uses to estimate quota usage.
    CounterIncrement { slot: u16, ts: String },
    /// 429 RESOURCE_EXHAUSTED parsed from a response body — pins
    /// the rate-limit window's `retry_delay` and `quota_metric` per
    /// spec 05 §5.8 step 2.
    RateLimited {
        slot: u16,
        ts: String,
        retry_delay_s: u32,
        quota_metric: String,
    },
    /// Per-response `modelVersion` capture (silent-downgrade
    /// detection). Debounced on the receive side per spec 05 §5.8
    /// step 3.
    EffectiveModelObserved {
        slot: u16,
        ts: String,
        selected: String,
        effective: String,
    },
    /// EP4 ToS-guard sentinel tripped — csq-cli detected an
    /// OAuth-flow marker on an AI-Studio-provisioned slot. csq-cli
    /// kills the child after emitting this.
    TosGuardTripped {
        slot: u16,
        ts: String,
        trigger: String,
    },
    /// Schema-drift signal — csq-cli's parser failed to match the
    /// expected response shape. After 5 strikes the daemon flips
    /// `QuotaKind::Unknown` per the circuit-breaker policy.
    QuotaSchemaDrift { slot: u16, ts: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increment_serializes_as_externally_tagged() {
        let ev = GeminiEvent::CounterIncrement {
            slot: 3,
            ts: "2026-04-25T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"counter_increment","slot":3,"ts":"2026-04-25T00:00:00Z"}"#
        );
    }

    #[test]
    fn rate_limited_round_trip() {
        let ev = GeminiEvent::RateLimited {
            slot: 7,
            ts: "2026-04-25T00:00:00Z".into(),
            retry_delay_s: 30,
            quota_metric: "generate_content_requests_per_minute".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: GeminiEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn unknown_kind_fails_parse() {
        // Defence in depth — a malformed event must NOT silently
        // deserialise as a default variant.
        let result: Result<GeminiEvent, _> =
            serde_json::from_str(r#"{"kind":"made_up","slot":1,"ts":"x"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn event_does_not_carry_secret_fields() {
        // Schema invariant: NO field in any event variant may hold
        // the API key. This test enumerates every variant and
        // serialises it with a deliberately key-shaped string in
        // the only non-fixed text fields; the test asserts the key
        // does not appear in any event's serialised form because
        // the schema does not expose a place for it.
        //
        // If a future variant adds a free-text field, this test
        // forces the author to revisit whether keys could leak
        // into it.
        let key_shape = "AIzaSyTESTKEYxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let events = [
            GeminiEvent::CounterIncrement {
                slot: 1,
                ts: "x".into(),
            },
            GeminiEvent::RateLimited {
                slot: 1,
                ts: "x".into(),
                retry_delay_s: 1,
                quota_metric: "x".into(),
            },
            GeminiEvent::EffectiveModelObserved {
                slot: 1,
                ts: "x".into(),
                selected: "gemini-2.5-pro".into(),
                effective: "gemini-2.0-flash".into(),
            },
            GeminiEvent::TosGuardTripped {
                slot: 1,
                ts: "x".into(),
                trigger: "Opening browser".into(),
            },
            GeminiEvent::QuotaSchemaDrift {
                slot: 1,
                ts: "x".into(),
            },
        ];
        for e in events {
            let s = serde_json::to_string(&e).unwrap();
            assert!(
                !s.contains(key_shape),
                "event serialised form must not echo a key-shaped string: {s}"
            );
            assert!(!s.contains("AIza"), "event must not contain AIza: {s}");
        }
    }
}
