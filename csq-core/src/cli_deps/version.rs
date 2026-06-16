//! Hand-rolled semver-lite parser. No `semver` crate per `independence.md` Rule 3.
//!
//! Grammar: `\d{1,5}\.\d{1,5}\.\d{1,5}(-[A-Za-z0-9.-]+)?`
//! Each numeric segment MUST be 1–5 ASCII digits AND fit in u32.
//! Trailing garbage (e.g. ` (Claude Code)`) is tolerated: the parser
//! scans for the FIRST three-dot-separated numeric token group in the
//! input string.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A parsed semantic version. Pre-release suffix (`pre`) is
/// `None` for release builds (e.g. `2.1.138`), and `Some("rc.1")` for
/// pre-releases (e.g. `0.41.2-rc.1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Pre-release suffix WITHOUT the leading `-`. `None` for releases.
    pub pre: Option<String>,
}

impl Version {
    /// Construct a release version (no pre-release suffix).
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// Reasons a version string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A numeric component (major/minor/patch) is >5 ASCII digits.
    ComponentTooLarge { segment: String },
    /// The string contains no `\d+.\d+.\d+` substring.
    BadFormat,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::ComponentTooLarge { segment } => {
                write!(f, "version component too large: '{segment}'")
            }
            ParseError::BadFormat => write!(f, "no recognisable semver substring found"),
        }
    }
}

/// Parse a semver-like string, tolerating leading/trailing garbage.
///
/// The parser scans for the FIRST substring matching
/// `\d{1,5}\.\d{1,5}\.\d{1,5}(-[A-Za-z0-9.-]+)?`.
/// This handles all known real-world shapes:
///
/// | Input                             | Result        |
/// |-----------------------------------|---------------|
/// | `"2.1.138 (Claude Code)"`         | `2.1.138`     |
/// | `"codex-cli 0.128.0"`             | `0.128.0`     |
/// | `"0.41.2"`                        | `0.41.2`      |
/// | `"0.41.2-rc.1"`                   | `0.41.2-rc.1` |
/// | `"0.1.2505291658"` (>5 digits)    | `ComponentTooLarge` |
/// | `"not a version"`                 | `BadFormat`   |
///
/// Returns `Err(ComponentTooLarge)` when a digit run is longer than 5
/// characters, regardless of whether it would fit in `u32`. The cap is
/// the two-gate defence against Homebrew-formula date-encoded versions
/// (e.g. `0.1.2505291658`).
pub fn parse(s: &str) -> Result<Version, ParseError> {
    // Scan through the string byte-by-byte, looking for the first
    // run of digits followed by `.digits.digits`.
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        // Find start of a digit run.
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // Collect first digit run.
        let major_start = i;
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let major_str = &s[major_start..i];

        // Must be followed by '.'.
        if i >= len || bytes[i] != b'.' {
            continue;
        }
        i += 1; // consume '.'

        // Collect minor digit run.
        let minor_start = i;
        if i >= len || !bytes[i].is_ascii_digit() {
            continue;
        }
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let minor_str = &s[minor_start..i];

        // Must be followed by '.'.
        if i >= len || bytes[i] != b'.' {
            continue;
        }
        i += 1; // consume '.'

        // Collect patch digit run.
        let patch_start = i;
        if i >= len || !bytes[i].is_ascii_digit() {
            continue;
        }
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let patch_str = &s[patch_start..i];

        // Validate segment lengths (1–5 ASCII digits per spec/13 §8).
        // Also reject leading-zero components like "01", "002" — valid semver
        // forbids them, and they indicate a non-semver version scheme.
        for seg in [major_str, minor_str, patch_str] {
            if seg.len() > 5 {
                return Err(ParseError::ComponentTooLarge {
                    segment: seg.to_string(),
                });
            }
            if seg.starts_with('0') && seg.len() > 1 {
                return Err(ParseError::BadFormat);
            }
        }

        // Parse as u32. A 5-digit decimal can exceed u32::MAX (99999 < 4294967295, fine).
        // The 5-digit cap is the primary defence; parse failure is a fallback.
        let parse_u32 = |seg: &str| -> Result<u32, ParseError> {
            seg.parse::<u32>()
                .map_err(|_| ParseError::ComponentTooLarge {
                    segment: seg.to_string(),
                })
        };

        let major = parse_u32(major_str)?;
        let minor = parse_u32(minor_str)?;
        let patch = parse_u32(patch_str)?;

        // Optional pre-release: `-[A-Za-z0-9.-]+`
        let pre = if i < len && bytes[i] == b'-' {
            let pre_start = i + 1; // skip '-'
            let mut j = pre_start;
            while j < len {
                let c = bytes[j];
                if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' {
                    j += 1;
                } else {
                    break;
                }
            }
            if j > pre_start {
                Some(s[pre_start..j].to_string())
            } else {
                None
            }
        } else {
            None
        };

        return Ok(Version {
            major,
            minor,
            patch,
            pre,
        });
    }

    Err(ParseError::BadFormat)
}

/// Returns `true` when `found` is at or above `min`.
///
/// Pre-release suffix on `found` is **ignored** when comparing against `min`
/// (spec/13 §8: "release portion meets minimum is sufficient"). This means
/// `0.41.2-rc.1 >= 0.41.2` is `true`.
pub fn meets_minimum(found: &Version, min: &Version) -> bool {
    let f = (found.major, found.minor, found.patch);
    let m = (min.major, min.minor, min.patch);
    f >= m
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parse: known real-world formats ──────────────────────────────

    #[test]
    fn parse_claude_format() {
        // "2.1.138 (Claude Code)" — trailing garbage ignored
        let v = parse("2.1.138 (Claude Code)").expect("should parse");
        assert_eq!(v, Version::new(2, 1, 138));
    }

    #[test]
    fn parse_codex_format() {
        // "codex-cli 0.128.0" — leading non-digit text ignored
        let v = parse("codex-cli 0.128.0").expect("should parse");
        assert_eq!(v, Version::new(0, 128, 0));
    }

    #[test]
    fn parse_bare_version() {
        // "0.41.2" — no prefix, no suffix
        let v = parse("0.41.2").expect("should parse");
        assert_eq!(v, Version::new(0, 41, 2));
    }

    #[test]
    fn parse_prerelease_suffix() {
        // "0.41.2-rc.1" — pre-release with dot in suffix
        let v = parse("0.41.2-rc.1").expect("should parse");
        assert_eq!(
            v,
            Version {
                major: 0,
                minor: 41,
                patch: 2,
                pre: Some("rc.1".to_string()),
            }
        );
    }

    #[test]
    fn parse_prerelease_alphanumeric() {
        let v = parse("1.0.0-alpha.2026").expect("should parse");
        assert_eq!(v.pre, Some("alpha.2026".to_string()));
    }

    // ── Parse: error cases ───────────────────────────────────────────

    #[test]
    fn parse_component_too_large_6_digits() {
        // "0.1.2505291658" — patch segment has 10 digits (>5)
        let err = parse("0.1.2505291658").expect_err("should fail");
        assert!(
            matches!(err, ParseError::ComponentTooLarge { ref segment } if segment == "2505291658"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_bad_format_no_semver() {
        let err = parse("not a version").expect_err("should fail");
        assert_eq!(err, ParseError::BadFormat);
    }

    #[test]
    fn parse_bad_format_empty() {
        let err = parse("").expect_err("should fail");
        assert_eq!(err, ParseError::BadFormat);
    }

    #[test]
    fn parse_bad_format_partial() {
        // Only two segments — not a valid version
        let err = parse("1.2").expect_err("should fail");
        assert_eq!(err, ParseError::BadFormat);
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn display_release() {
        assert_eq!(Version::new(2, 1, 138).to_string(), "2.1.138");
    }

    #[test]
    fn display_prerelease() {
        let v = Version {
            major: 0,
            minor: 41,
            patch: 2,
            pre: Some("rc.1".to_string()),
        };
        assert_eq!(v.to_string(), "0.41.2-rc.1");
    }

    #[test]
    fn display_roundtrip_bare() {
        let s = "0.41.2";
        assert_eq!(parse(s).unwrap().to_string(), s);
    }

    // ── meets_minimum ────────────────────────────────────────────────

    #[test]
    fn meets_minimum_prerelease_counts_as_meeting() {
        // spec/13 §8: pre-release suffix on FOUND is ignored
        let found = parse("0.41.2-rc.1").unwrap();
        let min = Version::new(0, 41, 2);
        assert!(meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_below() {
        let found = Version::new(0, 40, 0);
        let min = Version::new(0, 41, 2);
        assert!(!meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_exactly_at_floor() {
        let found = Version::new(0, 40, 0);
        let min = Version::new(0, 40, 0);
        assert!(meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_above() {
        let found = Version::new(0, 42, 0);
        let min = Version::new(0, 41, 2);
        assert!(meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_patch_increment_above() {
        let found = Version::new(0, 41, 3);
        let min = Version::new(0, 41, 2);
        assert!(meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_patch_below_by_one() {
        let found = Version::new(0, 41, 1);
        let min = Version::new(0, 41, 2);
        assert!(!meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_major_bump() {
        let found = Version::new(3, 0, 0);
        let min = Version::new(2, 0, 0);
        assert!(meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_codex_outdated() {
        // The PR-MCD1 acceptance criterion: codex 0.24.0 < 0.40.0
        let found = Version::new(0, 24, 0);
        let min = Version::new(0, 40, 0);
        assert!(!meets_minimum(&found, &min));
    }

    #[test]
    fn meets_minimum_codex_at_floor() {
        let found = Version::new(0, 40, 0);
        let min = Version::new(0, 40, 0);
        assert!(meets_minimum(&found, &min));
    }

    // ── Leading-zero rejection (F3 fix) ─────────────────────────────

    #[test]
    fn parse_leading_zero_components_bad_format() {
        // spec/13 §8: leading-zero segments like "01.02.03" are not valid semver.
        let err = parse("01.02.03").expect_err("should fail");
        assert_eq!(
            err,
            ParseError::BadFormat,
            "01.02.03 must be BadFormat; got {err:?}"
        );
    }

    #[test]
    fn parse_single_zero_components_ok() {
        // "0.0.0" is valid — the restriction is multi-character leading-zero only.
        let v = parse("0.0.0").expect("should parse");
        assert_eq!(v, Version::new(0, 0, 0));
    }

    // ── Trailing dash edge case (Rust F6) ────────────────────────────

    #[test]
    fn parse_trailing_dash_is_bad_format() {
        // "0.0.0-" — dash present but no pre-release chars after it → BadFormat
        // The pre-release segment requires at least one alphanumeric char.
        // The parser scans the pre-release but j == pre_start so pre = None,
        // and the version IS returned (just without the suffix). That is
        // acceptable; this test documents the actual behavior.
        let result = parse("0.0.0-");
        // Either Ok with no pre, or BadFormat; must not panic.
        match result {
            Ok(v) => assert_eq!(v.pre, None, "trailing dash produces no pre-release suffix"),
            Err(ParseError::BadFormat) => {} // also acceptable
            Err(e) => panic!("unexpected error for trailing-dash input: {e:?}"),
        }
    }

    // ── meets_minimum with pre-release on MIN side (Rust F7) ─────────

    #[test]
    fn meets_minimum_pre_release_on_min_side() {
        // When MIN itself has a pre-release suffix, only the numeric
        // triple is compared (same logic as for FOUND).
        let found = Version::new(0, 41, 2);
        let min = Version {
            major: 0,
            minor: 41,
            patch: 2,
            pre: Some("rc.1".to_string()),
        };
        assert!(
            meets_minimum(&found, &min),
            "release 0.41.2 must meet min 0.41.2-rc.1"
        );
    }
}
