//! `coc.version` envelope handling per spec 09 §9.5.
//!
//! csq carries a hard-coded `MAX_KNOWN_COC_MAJOR` constant. Artifacts whose
//! `coc.version` major exceeds that constant are refused with an actionable
//! upgrade message. Within `MAX_KNOWN_COC_MAJOR`, the soft window tolerates
//! up to `current_minor + 2` (forward-compat unknown fields).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Highest `coc.version` major that this csq build understands.
///
/// Bump in a deliberate commit when csq learns a new format major. The
/// matching `min_csq_for_coc_major` mapping below is the actionable upgrade
/// message csq emits when refusing a too-new artifact.
pub const MAX_KNOWN_COC_MAJOR: u32 = 1;

/// csq's current `(minor, patch)` for the highest known major. Forward-compat
/// soft window per spec 09 §9.5 §9.9.2 tolerates `(current_minor + 2)`.
pub const CURRENT_COC_MINOR: u32 = 0;

/// Map from `coc.version` major to the minimum csq version that supports it.
/// Used to render the actionable upgrade message in `RefuseTooNew`.
pub fn min_csq_for_coc_major(major: u32) -> Option<&'static str> {
    match major {
        1 => Some("2.4.0"),
        // Future entries land here when csq learns a new major.
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CocVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl CocVersion {
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        patch: 0,
    };

    /// Parse a `<major>.<minor>.<patch>` string. Pre-release suffixes (e.g.
    /// `1.0.0-alpha`) are NOT accepted in v1 (spec 09 §9.5 says semver but
    /// reserves prerelease for a future revision).
    pub fn parse(input: &str) -> Result<Self, VersionParseError> {
        let mut parts = input.split('.');
        let major = parts
            .next()
            .ok_or_else(|| VersionParseError::missing(input, "major"))?;
        let minor = parts
            .next()
            .ok_or_else(|| VersionParseError::missing(input, "minor"))?;
        let patch = parts
            .next()
            .ok_or_else(|| VersionParseError::missing(input, "patch"))?;
        if parts.next().is_some() {
            return Err(VersionParseError::extra(input));
        }
        let major: u32 = major
            .parse()
            .map_err(|e: std::num::ParseIntError| VersionParseError::invalid(input, "major", e))?;
        let minor: u32 = minor
            .parse()
            .map_err(|e: std::num::ParseIntError| VersionParseError::invalid(input, "minor", e))?;
        let patch: u32 = patch
            .parse()
            .map_err(|e: std::num::ParseIntError| VersionParseError::invalid(input, "patch", e))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }

    /// Per spec 09 §9.5: refuse newer-than-known major; soft-window older
    /// minors; load known versions cleanly.
    pub fn check(&self) -> CompatVerdict {
        if self.major == 0 {
            // Experimental schema — load with warning.
            return CompatVerdict::Experimental;
        }
        if self.major > MAX_KNOWN_COC_MAJOR {
            let required = min_csq_for_coc_major(self.major)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "a newer csq".into());
            return CompatVerdict::RefuseTooNew {
                observed: *self,
                max_known_major: MAX_KNOWN_COC_MAJOR,
                required_csq: required,
            };
        }
        if self.major == MAX_KNOWN_COC_MAJOR && self.minor > CURRENT_COC_MINOR + 2 {
            return CompatVerdict::ForwardCompatBeyondWindow {
                observed: *self,
                window_max_minor: CURRENT_COC_MINOR + 2,
            };
        }
        if self.major == MAX_KNOWN_COC_MAJOR && self.minor > CURRENT_COC_MINOR {
            return CompatVerdict::ForwardCompatSoft { observed: *self };
        }
        CompatVerdict::Ok
    }
}

impl CompatVerdict {
    /// M6 PR-CA13: if `self` is `RefuseTooNew`, consult the grace
    /// state and promote to `GraceWindowDegraded` when the soft
    /// window has not yet expired. Other variants pass through
    /// unchanged AND DO NOT MUTATE `state` — only `RefuseTooNew`
    /// triggers an `upsert`. Callers MAY persist the returned state
    /// after every call; the persistent write is a no-op when the
    /// verdict was not `RefuseTooNew`. Returns the (possibly
    /// updated) state so the caller can persist it back to disk.
    ///
    /// `now_unix` is the current Unix timestamp; injectable so
    /// tests can simulate elapsed days without sleeping.
    ///
    /// Spec 09 §9.5.3 (Drift posture, M6 PR-CA13).
    pub fn apply_grace(
        self,
        state: &mut crate::coc::version_grace::GraceState,
        now_unix: i64,
    ) -> Self {
        match self {
            Self::RefuseTooNew {
                observed,
                max_known_major,
                required_csq,
            } => {
                let first_seen = state.upsert(&observed.to_string(), now_unix);
                let remaining =
                    crate::coc::version_grace::GraceState::days_remaining_at(first_seen, now_unix);
                if remaining < 0 {
                    // Grace expired → revert to hard refuse.
                    Self::RefuseTooNew {
                        observed,
                        max_known_major,
                        required_csq,
                    }
                } else {
                    Self::GraceWindowDegraded {
                        observed,
                        max_known_major,
                        required_csq,
                        days_remaining: remaining,
                    }
                }
            }
            other => other,
        }
    }
}

impl fmt::Display for CocVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatVerdict {
    Ok,
    Experimental,
    ForwardCompatSoft {
        observed: CocVersion,
    },
    ForwardCompatBeyondWindow {
        observed: CocVersion,
        window_max_minor: u32,
    },
    RefuseTooNew {
        observed: CocVersion,
        max_known_major: u32,
        required_csq: String,
    },
    /// M6 PR-CA13: csq encountered a `coc.version` whose major exceeds
    /// [`MAX_KNOWN_COC_MAJOR`], BUT the soft-grace window
    /// (`crate::coc::version_grace::SOFT_GRACE_DAYS`) has not yet
    /// expired since first observation. csq loads in degraded
    /// passthrough mode + surfaces a `csq update needed` banner.
    /// The `days_remaining` field is the number of days until the
    /// grace expires and the verdict flips to [`Self::RefuseTooNew`].
    GraceWindowDegraded {
        observed: CocVersion,
        max_known_major: u32,
        required_csq: String,
        /// Days left in the grace window. `0` means today is the
        /// last day; `1` means one full day remaining; etc. Always
        /// `>= 0` while in this variant — once it would be negative
        /// the verdict becomes [`Self::RefuseTooNew`].
        days_remaining: i64,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VersionParseError {
    #[error("coc.version `{input}` missing {component}")]
    Missing {
        input: String,
        component: &'static str,
    },
    #[error("coc.version `{input}` has too many components")]
    Extra { input: String },
    #[error("coc.version `{input}` component {component}: {reason}")]
    Invalid {
        input: String,
        component: &'static str,
        reason: String,
    },
}

impl VersionParseError {
    fn missing(input: &str, component: &'static str) -> Self {
        Self::Missing {
            input: input.into(),
            component,
        }
    }
    fn extra(input: &str) -> Self {
        Self::Extra {
            input: input.into(),
        }
    }
    fn invalid(input: &str, component: &'static str, e: std::num::ParseIntError) -> Self {
        Self::Invalid {
            input: input.into(),
            component,
            reason: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_semver() {
        let v = CocVersion::parse("1.2.3").unwrap();
        assert_eq!(
            v,
            CocVersion {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
    }

    #[test]
    fn rejects_partial_versions() {
        assert!(CocVersion::parse("1.2").is_err());
        assert!(CocVersion::parse("1").is_err());
        assert!(CocVersion::parse("").is_err());
    }

    #[test]
    fn rejects_extra_components() {
        assert!(CocVersion::parse("1.2.3.4").is_err());
    }

    #[test]
    fn rejects_prerelease_in_v1() {
        // Pre-release strings should fail; the integer parse on "0-alpha" fails.
        assert!(CocVersion::parse("1.0.0-alpha").is_err());
    }

    #[test]
    fn check_known_major_minor_zero_is_ok() {
        let v = CocVersion::parse("1.0.0").unwrap();
        assert_eq!(v.check(), CompatVerdict::Ok);
    }

    #[test]
    fn check_too_new_major_refuses_with_actionable_message() {
        let v = CocVersion::parse("2.0.0").unwrap();
        let verdict = v.check();
        match verdict {
            CompatVerdict::RefuseTooNew {
                observed,
                max_known_major,
                required_csq: _,
            } => {
                assert_eq!(observed, v);
                assert_eq!(max_known_major, MAX_KNOWN_COC_MAJOR);
            }
            other => panic!("expected RefuseTooNew, got {other:?}"),
        }
    }

    #[test]
    fn check_experimental_zero_major() {
        let v = CocVersion::parse("0.1.0").unwrap();
        assert_eq!(v.check(), CompatVerdict::Experimental);
    }

    #[test]
    fn check_minor_above_current_below_window_is_soft() {
        // CURRENT_COC_MINOR = 0, so minor=1 is within the +2 window
        let v = CocVersion::parse("1.1.0").unwrap();
        match v.check() {
            CompatVerdict::ForwardCompatSoft { .. } => (),
            other => panic!("expected ForwardCompatSoft, got {other:?}"),
        }
    }

    #[test]
    fn check_minor_beyond_window() {
        // current+3 is beyond the +2 window
        let v = CocVersion::parse("1.99.0").unwrap();
        match v.check() {
            CompatVerdict::ForwardCompatBeyondWindow { .. } => (),
            other => panic!("expected ForwardCompatBeyondWindow, got {other:?}"),
        }
    }

    /// M6 PR-CA13: a fresh observation of a too-new major lands in
    /// the grace window. Verdict promotes from RefuseTooNew to
    /// GraceWindowDegraded with `days_remaining == SOFT_GRACE_DAYS`.
    #[test]
    fn apply_grace_fresh_observation_yields_grace_window_degraded() {
        let v = CocVersion::parse("2.0.0").unwrap();
        let raw = v.check();
        assert!(matches!(raw, CompatVerdict::RefuseTooNew { .. }));

        let mut state = crate::coc::version_grace::GraceState::default();
        let now_unix = 1_700_000_000;
        let promoted = raw.apply_grace(&mut state, now_unix);

        match promoted {
            CompatVerdict::GraceWindowDegraded {
                observed,
                days_remaining,
                ..
            } => {
                assert_eq!(observed, v);
                assert_eq!(
                    days_remaining,
                    crate::coc::version_grace::SOFT_GRACE_DAYS as i64
                );
            }
            other => panic!("expected GraceWindowDegraded, got {other:?}"),
        }
        // The state now has a record for "2.0.0".
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.records[0].observed_version, "2.0.0");
    }

    /// M6 PR-CA13: an observation 29 days into the grace window
    /// still loads in degraded mode (1 day remaining).
    #[test]
    fn apply_grace_29_days_in_still_degraded() {
        let v = CocVersion::parse("2.0.0").unwrap();
        let mut state = crate::coc::version_grace::GraceState::default();
        // Seed the record at day 0.
        state.upsert("2.0.0", 1_700_000_000);
        // Now query at day 29.
        let now_unix = 1_700_000_000 + 29 * 86400;
        let promoted = v.check().apply_grace(&mut state, now_unix);
        match promoted {
            CompatVerdict::GraceWindowDegraded { days_remaining, .. } => {
                assert_eq!(days_remaining, 1);
            }
            other => panic!("expected GraceWindowDegraded, got {other:?}"),
        }
    }

    /// M6 PR-CA13: an observation 31 days after first observation
    /// has the grace expired — verdict stays RefuseTooNew (hard fail).
    #[test]
    fn apply_grace_31_days_in_reverts_to_refuse_too_new() {
        let v = CocVersion::parse("2.0.0").unwrap();
        let mut state = crate::coc::version_grace::GraceState::default();
        state.upsert("2.0.0", 1_700_000_000);
        let now_unix = 1_700_000_000 + 31 * 86400;
        let promoted = v.check().apply_grace(&mut state, now_unix);
        assert!(matches!(promoted, CompatVerdict::RefuseTooNew { .. }));
    }

    /// M6 PR-CA13: an Ok verdict passes through apply_grace unchanged.
    /// The grace path is only for too-new majors.
    #[test]
    fn apply_grace_passes_through_ok_verdict() {
        let v = CocVersion::parse("1.0.0").unwrap();
        let mut state = crate::coc::version_grace::GraceState::default();
        let promoted = v.check().apply_grace(&mut state, 1_700_000_000);
        assert_eq!(promoted, CompatVerdict::Ok);
        // No new records — Ok doesn't touch the grace state.
        assert!(state.records.is_empty());
    }
}
