//! EP4 ToS-guard — versioned response-body sentinel.
//!
//! Google's published ToS at `google-gemini/gemini-cli/docs/
//! resources/tos-privacy.md` prohibits third-party software from
//! accessing Gemini CLI backend services via subscription OAuth
//! (gemini-cli #20632, #22970 document active enforcement: 403 ban,
//! Form-based reinstatement on first offense, permanent ban on
//! second). csq ships API-key only and actively defends against
//! OAuth fall-through.
//!
//! EP4 is the runtime sentinel: scan gemini-cli's stderr for
//! OAuth-flow markers AT RUN TIME on an AI-Studio-provisioned slot.
//! If a marker fires, csq emits a [`TosGuardTripped`] event and
//! kills the child.
//!
//! # Versioned whitelist (C-CR1: NO disable knob)
//!
//! The marker strings are pinned to a specific `gemini-cli` minor
//! release. Per C-CR1 there is no disable knob — if Google ships a
//! patch that breaks the markers, csq either updates the whitelist
//! or rejects the new version (version-mismatch dialog from PR-G3).
//! "EP4 is advisory" reclassification is the documented escape
//! hatch (Risk #1 in the implementation plan), not a runtime knob.

use super::PINNED_GEMINI_CLI_VERSION;

/// Substrings whose presence in gemini-cli stderr signals an
/// OAuth-execution code path on an AI-Studio-provisioned slot.
/// Pinned to gemini-cli `0.38.x` per OPEN-G02 live-capture
/// (journal 0004) and observed in #20632 / #22970 traces.
///
/// Match is substring + case-sensitive — these strings appear
/// verbatim in gemini-cli's output and a case-insensitive match
/// would create false positives in user log lines.
pub const OAUTH_MARKERS: &[&str] = &[
    "Opening browser",
    "oauth2.googleapis.com",
    "cloudcode-pa.googleapis.com",
];

/// Result of one [`scan_stderr`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SentinelOutcome {
    /// No marker present — gemini-cli is on the API-key code path.
    Clean,
    /// One marker fired. The caller MUST emit a
    /// `TosGuardTripped` event and kill the child.
    Tripped {
        /// The marker substring that matched.
        trigger: String,
    },
}

/// Scans `stderr_chunk` for any marker in [`OAUTH_MARKERS`].
/// Returns the FIRST matching marker. The caller pipes
/// gemini-cli's stderr through this on each line received.
///
/// Cheap substring scan — N markers × line length. The markers are
/// short and few; this runs on the hot path of every gemini-cli
/// stderr line and MUST stay sub-microsecond.
pub fn scan_stderr(stderr_chunk: &str) -> SentinelOutcome {
    for marker in OAUTH_MARKERS {
        if stderr_chunk.contains(marker) {
            return SentinelOutcome::Tripped {
                trigger: marker.to_string(),
            };
        }
    }
    SentinelOutcome::Clean
}

/// Returns the gemini-cli minor version this whitelist is pinned
/// to. The version-mismatch dialog (PR-G3) compares this against
/// the running binary's `--version` output; mismatch prompts an
/// auto-update of the whitelist OR rejects the new version per
/// C-CR1.
pub fn pinned_cli_version() -> &'static str {
    PINNED_GEMINI_CLI_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_clean_on_empty() {
        assert_eq!(scan_stderr(""), SentinelOutcome::Clean);
    }

    #[test]
    fn scan_clean_on_unrelated_stderr() {
        let s = "DEBUG: loading model gemini-2.5-pro\nINFO: ready";
        assert_eq!(scan_stderr(s), SentinelOutcome::Clean);
    }

    #[test]
    fn scan_trips_on_opening_browser() {
        let s = "Opening browser to authenticate...";
        match scan_stderr(s) {
            SentinelOutcome::Tripped { trigger } => assert_eq!(trigger, "Opening browser"),
            other => panic!("expected Tripped, got {other:?}"),
        }
    }

    #[test]
    fn scan_trips_on_oauth_endpoint() {
        let s = "POST https://oauth2.googleapis.com/token";
        assert!(matches!(scan_stderr(s), SentinelOutcome::Tripped { .. }));
    }

    #[test]
    fn scan_trips_on_cloudcode_endpoint() {
        let s = "calling cloudcode-pa.googleapis.com/v1/projects";
        assert!(matches!(scan_stderr(s), SentinelOutcome::Tripped { .. }));
    }

    #[test]
    fn scan_returns_first_marker_on_multiple() {
        // Multiple markers in one chunk — return the first
        // (deterministic). Order matches OAUTH_MARKERS array.
        let s = "Opening browser; will hit oauth2.googleapis.com next";
        match scan_stderr(s) {
            SentinelOutcome::Tripped { trigger } => assert_eq!(trigger, "Opening browser"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn scan_is_case_sensitive() {
        // Lowercase variant must NOT match — case-insensitive
        // would create false positives in user log lines.
        let s = "opening browser failed";
        assert_eq!(scan_stderr(s), SentinelOutcome::Clean);
    }

    #[test]
    fn pinned_cli_version_is_the_module_constant() {
        assert_eq!(pinned_cli_version(), PINNED_GEMINI_CLI_VERSION);
    }

    #[test]
    fn marker_list_is_non_empty() {
        // Defence in depth — a future commit that empties the
        // whitelist (e.g. by accident) would silently disable EP4.
        // Per C-CR1 there is NO disable knob — emptying the array
        // is functionally equivalent and must fail the test.
        assert!(!OAUTH_MARKERS.is_empty());
    }
}
