//! `csq --build-info`: the Cargo features this binary was COMPILED with
//! (an internal ticket R3 N-2).
//!
//! The deny gates' exceptions are justified by "native-harness does not ship".
//! A build-line scan can only read what a script SAYS it builds; this is what
//! the binary IS. `csq/build.rs` turns cargo's `CARGO_FEATURE_<NAME>` variables
//! for this crate into `CSQ_BUILD_FEATURES` (sorted, comma-joined, `default`
//! dropped), and `scripts/verify/built-binary-features.sh` runs the built
//! binary before signing and refuses native-harness (csq's or csq-core's) or
//! an unlisted set.

/// The csq crate's compiled features, e.g. `cli,desktop,enterprise`.
pub(crate) const BUILD_FEATURES: &str = env!("CSQ_BUILD_FEATURES");

/// The same feature list plus csq-core's OWN native-harness state
/// (`csq_core::BUILD_NATIVE_HARNESS`; csq's features alone cannot show it,
/// because Cargo unifies features and a sibling workspace crate can enable
/// csq-core/native-harness while csq's `native-harness` stays off, an internal ticket FIX5
/// P-1; the verifier refuses `=1` and a csq set that disagrees with it), embedded as one contiguous
/// byte marker so a verifier can read it from a binary it cannot RUN (a
/// cross-built artifact, e.g. the x86_64-apple-darwin CLI on an arm64 runner)
/// without executing it or relying on `strings`:
/// scripts/verify/built-binary-features.sh scans the file bytes for
/// `CSQ-BUILD-FEATURES[<set>;csq-core-native-harness=<0|1>]` (an internal ticket).
/// `#[used]` keeps it in the binary. The `if` is a const condition; if both
/// literals ever reached the binary, the verifier would see two distinct
/// markers and refuse (UNDETERMINED), so that failure is closed, never open.
#[used]
pub(crate) static BUILD_FEATURES_MARKER: &str = if csq_core::BUILD_NATIVE_HARNESS {
    concat!(
        "CSQ-BUILD-FEATURES[",
        env!("CSQ_BUILD_FEATURES"),
        ";csq-core-native-harness=1]"
    )
} else {
    concat!(
        "CSQ-BUILD-FEATURES[",
        env!("CSQ_BUILD_FEATURES"),
        ";csq-core-native-harness=0]"
    )
};

/// The one line `csq --build-info` prints. The verifier matches it exactly.
/// Printed FROM the embedded marker, so the run-time answer and the bytes a
/// cross-arch verifier reads are one value, never two that could drift.
pub(crate) fn line() -> String {
    let body = BUILD_FEATURES_MARKER
        .strip_prefix("CSQ-BUILD-FEATURES[")
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(BUILD_FEATURES);
    format!("csq-build-features: {body}")
}

/// True when argv is exactly `csq --build-info` (the flag is honoured only as
/// the sole argument, like `--self-test`).
pub(crate) fn requested(argv: &[std::ffi::OsString]) -> bool {
    argv.len() == 2 && argv[1] == "--build-info"
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_NH_KEY: &str = ";csq-core-native-harness=";

    fn has(name: &str) -> bool {
        BUILD_FEATURES.split(',').any(|f| f == name)
    }

    // The const reflects exactly what was compiled: each feature that gates
    // the boundary is listed iff `cfg!(feature = ..)` is true for this build.
    #[test]
    fn build_features_match_the_compiled_cfg() {
        assert_eq!(has("cli"), cfg!(feature = "cli"), "{BUILD_FEATURES}");
        assert_eq!(
            has("desktop"),
            cfg!(feature = "desktop"),
            "{BUILD_FEATURES}"
        );
        assert_eq!(
            has("enterprise"),
            cfg!(feature = "enterprise"),
            "{BUILD_FEATURES}"
        );
        assert_eq!(
            has("native-harness"),
            cfg!(feature = "native-harness"),
            "{BUILD_FEATURES}"
        );
        assert_eq!(
            has("test-utils"),
            cfg!(feature = "test-utils"),
            "{BUILD_FEATURES}"
        );
        assert!(!has("default"), "{BUILD_FEATURES}");
    }

    #[test]
    fn build_features_are_sorted_hyphenated_names() {
        let names: Vec<&str> = BUILD_FEATURES
            .split(',')
            .filter(|f| !f.is_empty())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert!(names.iter().all(|f| f
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')));
    }

    fn core_nh() -> &'static str {
        if csq_core::BUILD_NATIVE_HARNESS {
            "1"
        } else {
            "0"
        }
    }

    #[test]
    fn embedded_marker_carries_the_same_set_and_core_state() {
        assert_eq!(
            BUILD_FEATURES_MARKER,
            format!(
                "CSQ-BUILD-FEATURES[{BUILD_FEATURES}{CORE_NH_KEY}{}]",
                core_nh()
            )
        );
    }

    // csq's native-harness forwards csq-core/native-harness, so with csq's
    // feature on, csq-core's must be on too (the converse is what the
    // verifier refuses in a shipped binary).
    #[test]
    fn csq_native_harness_implies_core_native_harness() {
        assert!(
            !has("native-harness")
                || BUILD_FEATURES_MARKER.ends_with(";csq-core-native-harness=1]"),
            "{BUILD_FEATURES_MARKER}"
        );
    }

    #[test]
    fn line_and_flag_shape() {
        assert_eq!(
            line(),
            format!(
                "csq-build-features: {BUILD_FEATURES}{CORE_NH_KEY}{}",
                core_nh()
            )
        );
        let argv = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(requested(&argv(&["csq", "--build-info"])));
        assert!(!requested(&argv(&["csq"])));
        assert!(!requested(&argv(&["csq", "--build-info", "x"])));
        assert!(!requested(&argv(&["csq", "status"])));
    }
}
