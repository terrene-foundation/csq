//! M12 — Operation classes subject to authority-registry membership enforcement.
//!
//! Three `EventKind` values are "guarded" — their multi-sig authorizations
//! must come from roster-enrolled keys (post-activation, enterprise edition).
//! All other event kinds are "unguarded" — they pass through with M11 behavior
//! (inner-sig validity only, no membership check).

use serde::{Deserialize, Serialize};

use crate::audit::types::EventKind;

/// The three guarded operation classes.
///
/// Roster membership is enforced for these op classes when the enterprise
/// registry is active and `record.seq >= roster_activation_seq`.
///
/// All other `EventKind` values are **unguarded**: M11 inner-sig validity is
/// sufficient; no membership check is applied. See the `unguarded_kinds_return_none`
/// test for the canonical enumeration of all non-guarded `EventKind` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpClass {
    /// A signing key was rotated (`EventKind::KeyRotate`).
    KeyRotate,
    /// An identity record was minted (`EventKind::IdentityMint`).
    IdentityMint,
    /// A release artifact was authorized (`EventKind::ReleaseAuth`).
    ReleaseAuth,
}

impl OpClass {
    /// Map an `EventKind` to its `OpClass`, if any.
    ///
    /// Returns `Some(OpClass)` for the three guarded kinds; `None` for all
    /// unguarded kinds (membership check skipped → pure M11 behavior).
    pub fn from_event_kind(k: &EventKind) -> Option<Self> {
        match k {
            EventKind::KeyRotate => Some(Self::KeyRotate),
            EventKind::IdentityMint => Some(Self::IdentityMint),
            EventKind::ReleaseAuth => Some(Self::ReleaseAuth),
            // All other event kinds are unguarded.
            EventKind::CsqRun
            | EventKind::OAuthRefresh
            | EventKind::ArtifactLoad
            | EventKind::ModelInvoke
            | EventKind::OutputCapture
            | EventKind::AccountSwap
            | EventKind::ReplicationAck
            | EventKind::ReplicationFailed
            | EventKind::ChainContinuation
            | EventKind::ChainReGenesis
            | EventKind::SinkDriftDetected
            | EventKind::AccountLogout
            | EventKind::AccountMove
            // M18 seam events are unguarded: their authenticity comes from the
            // per-developer authorship attestation (M17) in the actor/trust
            // slots, NOT from the M12 multi-sig roster. The seam is a new
            // PRODUCER into the existing pipeline, not an own-ops governance op.
            | EventKind::SeamEventRejected
            | EventKind::ProvenanceAnchored
            // M19 capture-matrix is a state-observation record (daemon self-reporting).
            // No multi-sig required — same rationale as SeamEventRejected.
            | EventKind::ProvenanceCaptureMatrix
            // M20 duplicate-suppression is a custody/observation record (the
            // daemon noting a replayed event was dropped). Unguarded — same
            // rationale as SeamEventRejected.
            | EventKind::SeamDuplicateSuppressed
            // #784 per-turn governance attestation is a passive observation of a
            // turn the live session already governed — single-sig chain-signed,
            // not an own-ops decision requiring the M12 multi-sig roster.
            | EventKind::GovernanceTurn
            // M3 §10.5 W2b EATP attestation records live on the EATP chain, not
            // the op-chain; the EATP chain has its own born-canonical genesis guard.
            // Unguarded for op-class purposes (no multi-sig roster role).
            | EventKind::EatpAttestation
            // M6 T6.2 Shard 4 MCP gate decision is a passive observation of a
            // spawn-boundary tool-call the proxy already gated — single-sig
            // chain-signed, not an own-ops decision requiring the M12 multi-sig
            // roster (same rationale as GovernanceTurn).
            | EventKind::McpGateDecision
            // #787 b2b policy-bundle install is a passive own-op observation:
            // the bundle's own detached signature (verified against the
            // out-of-band --pubkey) IS its authority, so the record is
            // single-sig chain-signed, not an M12 multi-sig-roster decision
            // (same rationale as GovernanceTurn).
            | EventKind::PolicyBundleInstall
            // M-DEK T-DEK.2 org-root ceremony is a passive custody observation:
            // the ceremony record is signed by a designated ceremony key and the
            // ≥2-participant 4-eyes property is enforced structurally in the
            // ceremony logic (`key_hierarchy::ceremony`), not by the M12 op-class
            // multi-sig roster (same rationale as GovernanceTurn/PolicyBundleInstall).
            | EventKind::OrgRootCeremony
            // M-DEK T-DEK.4 seat-key reanchor already runs the M11 authorize_op
            // threshold gate (over the audit signing key, mirroring KeyRotate's
            // own ordering) and the OUTGOING seat DEK's succession endorsement is
            // verified independently by `verify_seat_reanchor_chain` — the M12
            // op-class ROSTER-MEMBERSHIP check is a distinct, later-milestone
            // enforcement layer with no seat-hierarchy integration yet. Unguarded
            // for op-class purposes today; a future milestone MAY promote this to
            // a guarded class once seat ids participate in the M12 roster.
            | EventKind::SeatKeyReanchor => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_kinds_map_to_op_class() {
        assert_eq!(
            OpClass::from_event_kind(&EventKind::KeyRotate),
            Some(OpClass::KeyRotate)
        );
        assert_eq!(
            OpClass::from_event_kind(&EventKind::IdentityMint),
            Some(OpClass::IdentityMint)
        );
        assert_eq!(
            OpClass::from_event_kind(&EventKind::ReleaseAuth),
            Some(OpClass::ReleaseAuth)
        );
    }

    #[test]
    fn unguarded_kinds_return_none() {
        // All non-guarded EventKind values — every value whose OpClass is None.
        // Update this list whenever a new EventKind is added that should NOT
        // require an OpClass gate (i.e., it represents a passive observation or
        // custody record rather than an authorized decision).
        for kind in [
            EventKind::CsqRun,
            EventKind::OAuthRefresh,
            EventKind::ArtifactLoad,
            EventKind::ModelInvoke,
            EventKind::OutputCapture,
            EventKind::AccountSwap,
            EventKind::ReplicationAck,
            EventKind::ReplicationFailed,
            EventKind::ChainContinuation,
            EventKind::ChainReGenesis,
            EventKind::SinkDriftDetected,
            EventKind::AccountLogout,
            EventKind::AccountMove,
            EventKind::SeamEventRejected,
            EventKind::ProvenanceAnchored,
            EventKind::ProvenanceCaptureMatrix,
            EventKind::SeamDuplicateSuppressed,
            EventKind::GovernanceTurn,
            EventKind::EatpAttestation,
            EventKind::McpGateDecision,
            EventKind::PolicyBundleInstall,
            EventKind::OrgRootCeremony,
            EventKind::SeatKeyReanchor,
        ] {
            assert!(
                OpClass::from_event_kind(&kind).is_none(),
                "{kind:?} should be unguarded (return None)"
            );
        }
    }

    #[test]
    fn all_event_kinds_are_classified() {
        // Exhaustiveness check: every EventKind in EventKind::ALL must be
        // handled by from_event_kind without panicking.
        for kind in EventKind::ALL {
            let _ = OpClass::from_event_kind(&kind);
        }
    }
}
