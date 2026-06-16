//! M11 — Edition and policy resolution for multi-sig authorization.
//!
//! # Edition model
//!
//! Two editions govern the multi-sig threshold:
//!
//! - `Community`: the default. Single-operator installs self-authorize with a
//!   1-of-1 threshold (the operator's own key). No additional ceremony required
//!   for solo installs (`independence.md` Rule 5 — the tool stays usable solo).
//! - `Enterprise`: default threshold N=2 (2-of-M). Suitable for multi-developer
//!   teams where a single operator SHOULD NOT unilaterally authorize high-impact
//!   operations.
//!
//! Architecture note: this is the **placeholder** edition mechanism for M11.
//! M12's `AuthorityRegistry` will supersede it with a registry-backed roster
//! lookup. Until then, the edition + threshold is resolved from environment
//! variables (config-file-free; no new runtime dependency).
//!
//! # Reconciliation note (architecture B.1 vs milestone text)
//!
//! Architecture B.1 marks community multi-sig "Optional"; the milestone text
//! says "community is 1-of-1 self-authorize". Reconciled as: Community default
//! threshold = 1 (the operator's own key auto-satisfies it; no new ceremony for
//! solo installs). Enterprise default = 2.
//!
//! # Environment variables
//!
//! | Variable                       | Values                            | Effect                                     |
//! |-------------------------------|-----------------------------------|--------------------------------------------|
//! | `CSQ_AUDIT_EDITION`           | `"community"` (default) / `"enterprise"` | Select edition                    |
//! | `CSQ_AUDIT_MULTISIG_THRESHOLD` | unsigned integer                  | Override threshold for both editions; wins over default |
//!
//! If `CSQ_AUDIT_MULTISIG_THRESHOLD` is set to `0`, it is ignored (treated as
//! absent) to avoid creating an always-pass gate.

/// The deployment edition governing multi-sig policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edition {
    /// Single-operator install. Default threshold: 1 (1-of-1 self-authorize).
    Community,
    /// Multi-developer team install. Default threshold: 2 (N-of-M).
    Enterprise,
}

impl Edition {
    /// Default threshold for this edition.
    ///
    /// Community: 1 (self-authorize)
    /// Enterprise: 2 (requires a second signer)
    pub fn default_threshold(self) -> usize {
        match self {
            Edition::Community => 1,
            Edition::Enterprise => 2,
        }
    }
}

/// The resolved multi-sig policy: threshold N required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiSigPolicy {
    /// Number of valid signatures required for authorization to succeed.
    pub threshold: usize,
}

/// Resolve the active `Edition` from the environment.
///
/// Reads `CSQ_AUDIT_EDITION` (`"community"` | `"enterprise"`; default:
/// `"community"`). Unrecognised values are treated as Community with a
/// `tracing::warn`.
pub fn resolve_edition() -> Edition {
    match std::env::var("CSQ_AUDIT_EDITION")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "enterprise" => Edition::Enterprise,
        "" | "community" => Edition::Community,
        other => {
            tracing::warn!(
                error_kind = "unknown_audit_edition",
                value = other,
                "CSQ_AUDIT_EDITION has unknown value; defaulting to Community"
            );
            Edition::Community
        }
    }
}

/// Resolve the active `MultiSigPolicy` from the environment.
///
/// Resolution order (highest priority first):
/// 1. `CSQ_AUDIT_MULTISIG_THRESHOLD` if set and parses to a non-zero `usize`.
/// 2. `Edition::default_threshold()` for the resolved edition.
pub fn resolve_policy() -> MultiSigPolicy {
    let edition = resolve_edition();
    let threshold = if let Ok(raw) = std::env::var("CSQ_AUDIT_MULTISIG_THRESHOLD") {
        match raw.trim().parse::<usize>() {
            Ok(0) => {
                tracing::warn!(
                    error_kind = "invalid_multisig_threshold",
                    "CSQ_AUDIT_MULTISIG_THRESHOLD=0 is not valid; using edition default"
                );
                edition.default_threshold()
            }
            Ok(n) => n,
            Err(_) => {
                tracing::warn!(
                    error_kind = "invalid_multisig_threshold",
                    value = %raw,
                    "CSQ_AUDIT_MULTISIG_THRESHOLD is not a valid unsigned integer; \
                     using edition default"
                );
                edition.default_threshold()
            }
        }
    } else {
        edition.default_threshold()
    };
    MultiSigPolicy { threshold }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_env;

    #[test]
    fn test_community_default_threshold_is_one() {
        assert_eq!(Edition::Community.default_threshold(), 1);
    }

    #[test]
    fn test_enterprise_default_threshold_is_two() {
        assert_eq!(Edition::Enterprise.default_threshold(), 2);
    }

    #[test]
    fn test_resolve_edition_defaults_to_community() {
        let _guard = test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        assert_eq!(resolve_edition(), Edition::Community);
    }

    #[test]
    fn test_resolve_edition_enterprise() {
        let _guard = test_env::lock();
        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        let e = resolve_edition();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        assert_eq!(e, Edition::Enterprise);
    }

    #[test]
    fn test_resolve_edition_community_explicit() {
        let _guard = test_env::lock();
        std::env::set_var("CSQ_AUDIT_EDITION", "community");
        let e = resolve_edition();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        assert_eq!(e, Edition::Community);
    }

    #[test]
    fn test_resolve_policy_threshold_override() {
        let _guard = test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::set_var("CSQ_AUDIT_MULTISIG_THRESHOLD", "3");
        let p = resolve_policy();
        std::env::remove_var("CSQ_AUDIT_MULTISIG_THRESHOLD");
        assert_eq!(p.threshold, 3);
    }

    #[test]
    fn test_resolve_policy_threshold_zero_ignored() {
        let _guard = test_env::lock();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        std::env::set_var("CSQ_AUDIT_MULTISIG_THRESHOLD", "0");
        let p = resolve_policy();
        std::env::remove_var("CSQ_AUDIT_MULTISIG_THRESHOLD");
        // 0 is invalid; falls back to Community default = 1.
        assert_eq!(p.threshold, 1);
    }

    #[test]
    fn test_resolve_policy_enterprise_default() {
        let _guard = test_env::lock();
        std::env::set_var("CSQ_AUDIT_EDITION", "enterprise");
        std::env::remove_var("CSQ_AUDIT_MULTISIG_THRESHOLD");
        let p = resolve_policy();
        std::env::remove_var("CSQ_AUDIT_EDITION");
        assert_eq!(p.threshold, 2, "enterprise default threshold must be 2");
    }
}
