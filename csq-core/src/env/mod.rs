//! Host-environment heuristics — detection of production-shaped secrets
//! used by the spec 08 MED-03 host-isolation warning surfacing
//! (PR-CA8 commit 1b — promoted from `csq-core/src/coc/translate/gemini.rs`
//! per round-2 R2-M6 architectural cleanup).
//!
//! # What this module owns
//!
//! - `looks_like_production_secret(name: &str) -> bool` — name-shape
//!   heuristic, errs toward warning per the spec 08 MED-03 doctrine.
//! - `first_exemplar(detected: &BTreeSet<String>) -> Option<&str>` —
//!   priority-list-first selection of a representative detected name
//!   for the operator-facing stderr line per round-3 R3-L2 / R3-H7
//!   resolution.
//!
//! # Why not in `coc/translate/gemini.rs`?
//!
//! Round-2 R2-M6: the function is host-environment scope, not
//! gemini-translator scope. Translators consume `&CocSet` and emit
//! per-Surface payloads — they should not own host-detection logic.
//! The new module is the right home; gemini's `HostContext` (also
//! moved to `coc/translate/types.rs::HostContext` in this commit per
//! R2-H4 sum-type promotion) is the wire-up surface that consumes
//! this module's output.
//!
//! Backwards compatibility: `coc::translate::gemini::looks_like_production_secret`
//! re-exports from here for any existing callers.

use std::collections::BTreeSet;

/// Suffix patterns that flag an env-var name as production-shaped.
/// Heuristic intentionally tightened in PR-CA8 round-2 R2-M2 and
/// re-tuned in round-3 R3-M1 / R4-M1: dropped bare `_KEY` / `_PASS`
/// (high false-positive cost — `XKB_DEFAULT_LAYOUT_KEY`,
/// `MY_DOG_NAME_PASS`); kept `_TOKEN` (broad coverage of
/// `*_TOKEN` env shapes — `GITLAB_TOKEN`, `JIRA_API_TOKEN`).
const SUFFIXES: &[&str] = &[
    "_API_KEY",
    "_SECRET_KEY",
    "_ACCESS_KEY",
    "_PASSWORD",
    "_CREDENTIALS",
    "_TOKEN",
];

/// Exact-match list — known-real production secrets that don't follow
/// the suffix pattern (e.g. `AWS_ACCESS_KEY_ID` matches via suffix
/// `_ACCESS_KEY` but the full name is also exact-listed for clarity).
/// EXACT_PRIORITY is used by [`first_exemplar`] for the operator-
/// facing warning so we surface a known-real secret name (e.g.
/// `ANTHROPIC_API_KEY`) instead of a lex-first false positive.
const EXACT: &[&str] = &[
    // Anthropic / OpenAI / Google
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    // AWS
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    // Source-control + CI
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "CIRCLECI_TOKEN",
    // SaaS
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "NPM_TOKEN",
    "OPSGENIE_API_KEY",
    "PAGERDUTY_API_KEY",
    "DATADOG_API_KEY",
    "LINEAR_API_KEY",
    "JIRA_API_TOKEN",
];

/// Heuristic — does an env-var name look like it carries a production
/// secret? Pure function; safe to apply on every `std::env::vars()`
/// entry. Names are case-insensitive.
///
/// Per spec 08 MED-03 doctrine, the heuristic errs toward warning.
/// False-positives (a benign `MY_TOKEN` env) are acceptable; false-
/// negatives (a real key not flagged) are not.
///
/// Round-3 R3-M1 + round-4 R4-M1 trimmed the suffix list to remove
/// bare `_KEY` / `_PASS` (high false-positive rate) while keeping
/// `_TOKEN` for broad coverage. EXACT-match list expanded with known
/// SaaS shapes.
pub fn looks_like_production_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if EXACT.contains(&upper.as_str()) {
        return true;
    }
    SUFFIXES.iter().any(|s| upper.ends_with(s))
}

/// Pick a single representative detected name for the operator-facing
/// stderr line per round-3 R3-H7. Priority order:
///
/// 1. EXACT-match list entries (in declaration order — known-real
///    secrets surface first).
/// 2. Lex-first fallback (when no EXACT entry matches; preserves the
///    deterministic-output property of `BTreeSet::iter().next()`).
///
/// Rationale: a workstation with `{AAA_API_KEY, GITHUB_TOKEN}` should
/// surface `GITHUB_TOKEN` (real) as the exemplar, not `AAA_API_KEY`
/// (lex-first benign-pattern false positive). The priority list lets
/// the operator confirm the detection is real without listing the
/// full inventory (round-2 R2-H3 disclosure-minimization).
pub fn first_exemplar(detected: &BTreeSet<String>) -> Option<&str> {
    // Priority pass — EXACT entries surface first.
    for known in EXACT {
        if detected.iter().any(|d| d.as_str() == *known) {
            return Some(*known);
        }
    }
    // Fallback — lex-first.
    detected.iter().next().map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // looks_like_production_secret heuristic
    // ============================================================

    #[test]
    fn looks_like_production_secret_accepts_anthropic_api_key() {
        assert!(looks_like_production_secret("ANTHROPIC_API_KEY"));
        assert!(looks_like_production_secret("anthropic_api_key")); // case-insensitive
    }

    #[test]
    fn looks_like_production_secret_accepts_aws_secret_access_key() {
        assert!(looks_like_production_secret("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn looks_like_production_secret_accepts_github_token() {
        assert!(looks_like_production_secret("GITHUB_TOKEN"));
    }

    #[test]
    fn looks_like_production_secret_accepts_gitlab_token() {
        // R2-M1 regression: bare _TOKEN suffix matches even without
        // EXACT-list coverage.
        assert!(looks_like_production_secret("GITLAB_TOKEN"));
    }

    #[test]
    fn looks_like_production_secret_accepts_stripe_secret_key() {
        // R2-M2 EXACT-list expansion.
        assert!(looks_like_production_secret("STRIPE_SECRET_KEY"));
    }

    #[test]
    fn looks_like_production_secret_accepts_slack_bot_token() {
        assert!(looks_like_production_secret("SLACK_BOT_TOKEN"));
    }

    #[test]
    fn looks_like_production_secret_accepts_arbitrary_api_key_suffix() {
        // Generic `*_API_KEY` shape that's not in EXACT.
        assert!(looks_like_production_secret("MY_API_KEY"));
        assert!(looks_like_production_secret("PARTNER_API_KEY"));
    }

    #[test]
    fn looks_like_production_secret_rejects_my_dog_name_pass() {
        // R2-M2 false-positive control: bare _PASS dropped from
        // SUFFIXES means `MY_DOG_NAME_PASS` is no longer flagged.
        assert!(!looks_like_production_secret("MY_DOG_NAME_PASS"));
    }

    #[test]
    fn looks_like_production_secret_rejects_jwt_public_key() {
        // R2-M2 false-positive control: bare _KEY dropped from
        // SUFFIXES means `JWT_PUBLIC_KEY` (a public cert, not a
        // secret) is no longer flagged.
        assert!(!looks_like_production_secret("JWT_PUBLIC_KEY"));
    }

    #[test]
    fn looks_like_production_secret_rejects_xkb_default_layout_key() {
        // R2-M2 false-positive control: Linux XKB env var.
        assert!(!looks_like_production_secret("XKB_DEFAULT_LAYOUT_KEY"));
    }

    #[test]
    fn looks_like_production_secret_rejects_safe_names() {
        assert!(!looks_like_production_secret("PATH"));
        assert!(!looks_like_production_secret("HOME"));
        assert!(!looks_like_production_secret("TERM"));
        assert!(!looks_like_production_secret("USER"));
        assert!(!looks_like_production_secret("CARGO_TARGET_DIR"));
    }

    // ============================================================
    // first_exemplar priority selection
    // ============================================================

    #[test]
    fn host_isolation_exemplar_prefers_well_known_github_token_over_lex_first_aaa_api_key() {
        // R3-L2: rename + clarify R2-H7 test. Lex-first → AAA_API_KEY
        // (false positive); priority → GITHUB_TOKEN (real).
        let mut detected = BTreeSet::new();
        detected.insert("AAA_API_KEY".to_string());
        detected.insert("GITHUB_TOKEN".to_string());
        assert_eq!(first_exemplar(&detected), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn host_isolation_exemplar_prefers_anthropic_api_key_over_other_exact_matches() {
        // ANTHROPIC_API_KEY is first in EXACT — surfaces over
        // GITHUB_TOKEN (also EXACT but later in the list).
        let mut detected = BTreeSet::new();
        detected.insert("GITHUB_TOKEN".to_string());
        detected.insert("ANTHROPIC_API_KEY".to_string());
        assert_eq!(first_exemplar(&detected), Some("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn host_isolation_exemplar_falls_back_to_lex_first_when_no_exact_match() {
        // {ZZZ_API_KEY, MMM_API_KEY} — both suffix-only matches; no
        // EXACT entry. Fallback to lex-first → MMM_API_KEY.
        let mut detected = BTreeSet::new();
        detected.insert("ZZZ_API_KEY".to_string());
        detected.insert("MMM_API_KEY".to_string());
        assert_eq!(first_exemplar(&detected), Some("MMM_API_KEY"));
    }

    #[test]
    fn host_isolation_exemplar_returns_none_for_empty_set() {
        let detected: BTreeSet<String> = BTreeSet::new();
        assert_eq!(first_exemplar(&detected), None);
    }
}
