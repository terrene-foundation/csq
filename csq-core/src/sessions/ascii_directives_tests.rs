//! Actual predicate calls; counters observe existing category-library call sites.
use super::*;
use crate::ascii_probe::observe;

#[test]
fn accepted_ascii_predicates_perform_zero_category_lookups() {
    const N: usize = 256;
    let (_, count) = observe("op_unicode_category", || {
        for _ in 0..N {
            assert!(!is_forbidden_char('a'));
        }
    });
    assert_eq!(
        count, 0,
        "ASCII category lookups were not eliminated; omitted guard produces N"
    );
}

#[test]
fn ascii_load_predicate_performs_zero_category_lookups() {
    const N: usize = 256;
    let (_, count) = observe("op_unicode_category", || {
        for _ in 0..N {
            assert!(!hidden_char('a'));
        }
    });
    assert_eq!(
        count, 0,
        "ASCII load category lookups were not eliminated; omitted path produces N"
    );
}

#[test]
fn all_ascii_controls_and_body_newline_policy_match_original_predicates() {
    for byte in 0..=127_u8 {
        let c = char::from(byte);
        let old_hidden = c.is_control()
            || c == BRAILLE_BLANK
            || default_ignorable(c)
            || matches!(
                get_general_category(c),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
                    | GeneralCategory::PrivateUse
                    | GeneralCategory::Surrogate
            );
        let old_forbidden = old_hidden || get_general_category(c) == GeneralCategory::Unassigned;
        assert_eq!(hidden_char(c), old_hidden, "hidden U+{:04X}", u32::from(c));
        assert_eq!(
            is_forbidden_char(c),
            old_forbidden,
            "forbidden U+{:04X}",
            u32::from(c)
        );
        let body = format!("a{c}b");
        assert_eq!(
            crate::messaging::limits::check_body(&body).is_err(),
            c.is_control() && c != '\n'
        );
    }
    assert!(crate::messaging::limits::check_body("line\nline").is_ok());
    assert!(crate::messaging::limits::check_note("line\nline").is_err());
}

#[test]
fn non_ascii_category_paths_and_hidden_unassigned_distinction_are_preserved() {
    for c in ['é', '中', '\u{0301}', '\u{0378}'] {
        let (forbidden, count) = observe("op_unicode_category", || is_forbidden_char(c));
        assert_eq!(count, 2, "non-ASCII category path changed");
        assert_eq!(forbidden, c == '\u{0378}');
    }
    assert!(
        !hidden_char('\u{0378}'),
        "Cn remains loadable in legacy directive text"
    );
    assert!(is_display_unsafe('\u{0301}'));
    for c in ['\u{200b}', '\u{202e}', '\u{2800}', '\u{e000}', '\u{feff}'] {
        assert!(hidden_char(c));
        assert!(is_forbidden_char(c));
        assert!(crate::messaging::limits::check_body(&format!("a{c}b")).is_err());
    }
}
