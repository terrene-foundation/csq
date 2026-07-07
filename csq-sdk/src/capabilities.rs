//! `csq.capabilities.v1` — the op-discovery payload DTO.
//!
//! A consumer calls `csq sdk capabilities --json` to learn which ops this binary
//! implements BEFORE invoking one, instead of discovering an unsupported op by hitting
//! a non-enveloped clap error. The `edition` field lets the consumer distinguish an op
//! that is absent-because-community from one that is absent-because-unimplemented.
//!
//! This crate holds only the wire SHAPE. The app (`csq-core::sdk::capabilities::build`)
//! supplies the op list it actually implements and its `EDITION` — the SDK never
//! feature-gates edition.

use serde::Serialize;

/// The `csq.capabilities.v1` payload: the ops a build implements + its edition.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesPayload {
    /// Short op identifiers (`"exec.v1"`, …) — the `.vN`-suffixed op names, without
    /// the `csq.` prefix carried by the envelope `schema` field.
    pub ops: Vec<&'static str>,
    /// This build's edition (`"community"` | `"enterprise"`), supplied by the app.
    pub edition: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, SCHEMA_CAPABILITIES_V1};

    #[test]
    fn capabilities_payload_serializes_ops_and_edition() {
        // The SDK owns the SHAPE; construct it directly (the app owns the values).
        let env = Envelope::success(
            SCHEMA_CAPABILITIES_V1,
            None,
            CapabilitiesPayload {
                ops: vec!["exec.v1", "capabilities.v1", "verify.v1"],
                edition: "community",
            },
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.capabilities.v1");
        assert_eq!(v["ok"], true);
        assert_eq!(v["edition"], "community");
        let ops: Vec<&str> = v["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(ops.contains(&"exec.v1"));
        assert!(ops.contains(&"verify.v1"));
    }
}
