//! `csq.capabilities.v1` builder — the app-side op list + `EDITION`.
//!
//! The payload SHAPE ([`CapabilitiesPayload`](super::CapabilitiesPayload)) lives in the
//! public `csq-sdk` crate; this builder supplies the ops THIS build actually implements
//! and the [`EDITION`](super::EDITION) discriminant. A consumer calls
//! `csq sdk capabilities --json` to learn which ops the binary implements BEFORE invoking
//! one, instead of discovering an unsupported op via a non-enveloped clap error.

use super::{CapabilitiesPayload, Envelope, EDITION, SCHEMA_CAPABILITIES_V1};

/// The ops actually IMPLEMENTED in this build.
///
/// Per `rules/spec-accuracy.md`, this advertises only what ships today. `eval.v1`
/// is enterprise-only (an internal ticket S2); community builds do not advertise it.
#[must_use]
pub fn implemented_ops() -> Vec<&'static str> {
    // S1: exec + capabilities. S2: verify. Community ops; enterprise extends below.
    #[allow(unused_mut)]
    let mut ops = vec!["exec.v1", "capabilities.v1", "verify.v1"];
    #[cfg(feature = "enterprise")]
    ops.push("eval.v1");
    ops
}

/// Build the `csq.capabilities.v1` success envelope for this build.
#[must_use]
pub fn build() -> Envelope<CapabilitiesPayload> {
    Envelope::success(
        SCHEMA_CAPABILITIES_V1,
        None,
        CapabilitiesPayload {
            ops: implemented_ops(),
            edition: EDITION,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_envelope_advertises_implemented_ops_and_edition() {
        let env = build();
        let v: serde_json::Value = serde_json::from_str(&env.to_line().unwrap()).unwrap();
        assert_eq!(v["schema"], "csq.capabilities.v1");
        assert_eq!(v["ok"], true);
        let ops: Vec<&str> = v["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(
            ops.contains(&"exec.v1"),
            "exec.v1 is implemented in this build"
        );
        assert!(ops.contains(&"capabilities.v1"));
        assert!(ops.contains(&"verify.v1"), "verify.v1 is implemented in S2");
        // eval.v1 ships in S2, enterprise-only.
        #[cfg(feature = "enterprise")]
        assert!(
            ops.contains(&"eval.v1"),
            "eval.v1 must be advertised in enterprise builds"
        );
        #[cfg(not(feature = "enterprise"))]
        assert!(
            !ops.contains(&"eval.v1"),
            "eval.v1 must NOT be advertised in community builds"
        );
    }

    #[test]
    fn edition_matches_build_feature() {
        let expected = if cfg!(feature = "enterprise") {
            "enterprise"
        } else {
            "community"
        };
        assert_eq!(EDITION, expected);
    }
}
