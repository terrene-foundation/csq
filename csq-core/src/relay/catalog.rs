//! Compiled, non-authoritative evidence matching. Production entries are empty.

use super::evidence::{extract_retained, EvidenceError};
use super::{types::CliKind, SlashCmd};
use crate::sdk::SdkErrorCode;

struct ReviewedEntry {
    raw: &'static [u8],
    length: usize,
    digest: [u8; 32],
    records: &'static [&'static [&'static str]],
}

impl ReviewedEntry {
    fn validate(&self, raw: &[u8]) -> Result<(), EvidenceError> {
        let evidence = extract_retained(raw)?;
        evidence.check_integrity(self.length, &self.digest)?;
        evidence.matches_fields(self.records)
    }
}

struct ProductionEntry {
    cli: CliKind,
    command: SlashCmd,
    evidence: ReviewedEntry,
}

const PRODUCTION_ENTRIES: &[ProductionEntry] = &[];

/// This availability result supplies neither a slash cell nor launch authority.
pub(super) fn production_available(cli: CliKind, command: SlashCmd) -> Result<(), SdkErrorCode> {
    let entry = PRODUCTION_ENTRIES
        .iter()
        .find(|entry| entry.cli == cli && entry.command == command)
        .ok_or(SdkErrorCode::CliUnmeasured)?;
    entry
        .evidence
        .validate(entry.evidence.raw)
        .map_err(|_| SdkErrorCode::CliUnmeasured)
}

// Linux recorder artifacts admitted by the distinct A0 fixture review.
// Literal expectations below are source data, never derived during validation.
#[cfg(test)]
mod fixture_data {
    use super::*;
    const SUBJECT: &[&str] = &["subject", "relay-evidence-v1", "ownedfake-recorder-v1", "relay-extractor-v1", "ownedfake-v1", "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f", "9348e82a6032fb4f6db9a5cbe9c125565c81adea1cb3f65bab02c4753bc5ad25", "2efcb5f8f2c284d78c76dbcde62fdbdc6cf4a6444fab18630c4b4a2180cb2f29", "Linux-x86_64", "5b222f7573722f62696e2f707974686f6e332e3132222c222d49222c222d53222c2266616b655f636c692e7079222c222d2d7374617465222c2273746174652e62696e222c222d2d636f6e666967222c22636f6e6669672e747874222c222d2d6265686176696f72222c226e6f726d616c225d", "0"];
    const CLEAR: ReviewedEntry = ReviewedEntry {
        raw: include_bytes!("fixtures/a0/clear.raw"),
        length: 677,
        digest: [
            36, 31, 116, 90, 14, 103, 78, 50, 175, 173, 150, 68, 74, 89, 6, 61, 242, 93, 232, 231,
            128, 61, 224, 118, 236, 31, 146, 195, 221, 25, 1, 193,
        ],
        records: &[
            SUBJECT,
            &["input", "clear", "2f636c6561720d", "-", "-", "0d"],
            &["effect", "616c7068610a626574610a", "636c65617265640a"],
            &[
                "completion",
                "636c65617265640a",
                "6f776e656466616b652d72656164790a",
                "exit0-pty-eof",
            ],
        ],
    };
    const COMPACT: ReviewedEntry = ReviewedEntry {
        raw: include_bytes!("fixtures/a0/compact.raw"),
        length: 727,
        digest: [
            155, 70, 87, 2, 184, 171, 101, 242, 19, 19, 121, 90, 132, 103, 167, 154, 165, 211, 48,
            32, 138, 195, 29, 150, 154, 184, 206, 228, 43, 70, 180, 123,
        ],
        records: &[
            SUBJECT,
            &["input", "compact", "2f636f6d706163740d", "-", "-", "0d"],
            &[
                "effect",
                "616c7068610a626574610a",
                "73756d6d6172793a616c7068612b626574610a",
            ],
            &[
                "completion",
                "73756d6d6172793a616c7068612b626574610a",
                "6f776e656466616b652d72656164790a",
                "exit0-pty-eof",
            ],
        ],
    };
    pub(super) fn entry(command: SlashCmd) -> &'static ReviewedEntry {
        match command {
            SlashCmd::Clear => &CLEAR,
            SlashCmd::Compact => &COMPACT,
        }
    }
}

#[cfg(test)]
pub(super) fn validate_fixture(command: SlashCmd) -> Result<(), EvidenceError> {
    let entry = fixture_data::entry(command);
    entry.validate(entry.raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::evidence::MAX_RAW_BYTES;

    fn rows() -> Vec<Vec<String>> {
        std::str::from_utf8(fixture_data::entry(SlashCmd::Clear).raw)
            .unwrap()
            .split_terminator('\n')
            .map(|line| line.split('\t').map(str::to_owned).collect())
            .collect()
    }

    fn encode(rows: &[Vec<String>]) -> Vec<u8> {
        (rows
            .iter()
            .map(|row| row.join("\t"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n")
            .into_bytes()
    }

    fn changed(row: usize, column: usize, value: &str) -> Vec<u8> {
        let mut rows = rows();
        rows[row][column] = value.to_owned();
        encode(&rows)
    }

    #[test]
    fn both_ownedfake_commands_match_reviewed_catalog() {
        for command in [SlashCmd::Clear, SlashCmd::Compact] {
            assert_eq!(validate_fixture(command), Ok(()), "A0_POSITIVE_BOTH");
        }
    }

    #[test]
    fn valid_oversize_capture_refuses_directly() {
        let raw = changed(0, 8, &"x".repeat(MAX_RAW_BYTES));
        assert!(extract_retained(&raw).is_err(), "A0_CAUSAL_BOUND");
    }

    #[test]
    fn platform_control_bytes_refuse_directly() {
        for value in ["Linux x86_64", "Linux\rx86_64", "Linux\0x86_64"] {
            assert!(
                extract_retained(&changed(0, 8, value)).is_err(),
                "A0_CAUSAL_ALPHABET"
            );
        }
    }

    #[test]
    fn otherwise_valid_truncated_capture_refuses_directly() {
        let mut raw = fixture_data::entry(SlashCmd::Clear).raw.to_vec();
        raw.pop();
        assert!(extract_retained(&raw).is_err(), "A0_CAUSAL_TERMINATOR");
    }

    #[test]
    fn missing_required_record_refuses_directly() {
        let mut rows = rows();
        rows.pop();
        assert!(
            extract_retained(&encode(&rows)).is_err(),
            "A0_CAUSAL_REQUIRED_SET"
        );
    }

    #[test]
    fn extra_nonempty_field_refuses_directly() {
        let mut rows = rows();
        rows[2].push("extra".to_owned());
        assert!(
            extract_retained(&encode(&rows)).is_err(),
            "A0_CAUSAL_RECORD_SHAPE"
        );
    }

    #[test]
    fn empty_platform_refuses_directly() {
        assert!(
            extract_retained(&changed(0, 8, "")).is_err(),
            "A0_CAUSAL_NONEMPTY"
        );
    }

    #[test]
    fn future_schema_refuses_directly() {
        assert!(
            extract_retained(&changed(0, 1, "relay-evidence-v2")).is_err(),
            "A0_CAUSAL_VOCABULARY"
        );
    }

    #[test]
    fn odd_input_hex_refuses_directly() {
        assert!(
            extract_retained(&changed(1, 2, "0")).is_err(),
            "A0_CAUSAL_HEX"
        );
    }

    #[test]
    fn short_subject_hash_refuses_directly() {
        assert!(
            extract_retained(&changed(0, 5, &"ab".repeat(31))).is_err(),
            "A0_CAUSAL_HASH_WIDTH"
        );
    }

    #[test]
    fn noncanonical_exit_refuses_directly() {
        assert!(
            extract_retained(&changed(0, 10, "00")).is_err(),
            "A0_CAUSAL_EXIT"
        );
    }

    #[test]
    fn literal_length_is_checked_independently() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        let evidence = extract_retained(entry.raw).unwrap();
        assert!(
            evidence
                .check_integrity(entry.length + 1, &entry.digest)
                .is_err(),
            "A0_CAUSAL_LENGTH"
        );
    }

    #[test]
    fn literal_digest_is_checked_without_field_masking() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        let evidence = extract_retained(&changed(0, 8, "linux-x86_64")).unwrap();
        assert!(
            evidence
                .check_integrity(entry.length, &entry.digest)
                .is_err(),
            "A0_CAUSAL_DIGEST"
        );
    }

    #[test]
    fn old_catalog_digest_rejects_one_byte_mutation() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        assert_eq!(
            entry.validate(&changed(0, 8, "linux-x86_64")),
            Err(EvidenceError::Digest)
        );
    }

    #[test]
    fn every_catalog_field_mismatch_refuses_without_digest_masking() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        let evidence = extract_retained(entry.raw).unwrap();
        for (row, fields) in entry.records.iter().enumerate() {
            for column in 0..fields.len() {
                let mut expected = rows();
                expected[row][column].push('x');
                let refs: Vec<Vec<&str>> = expected
                    .iter()
                    .map(|r| r.iter().map(String::as_str).collect())
                    .collect();
                let refs: Vec<&[&str]> = refs.iter().map(Vec::as_slice).collect();
                assert!(
                    evidence.matches_fields(&refs).is_err(),
                    "A0_CAUSAL_EXACT_FIELDS row {row} column {column}"
                );
            }
        }
    }

    #[test]
    fn each_changed_observation_refuses_without_digest_masking() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        for (row, fields) in entry.records.iter().enumerate() {
            for (column, value) in fields.iter().enumerate() {
                let replacement = if *value == "clear" {
                    "compact".to_owned()
                } else if *value == "0" {
                    "1".to_owned()
                } else if *value == "-" {
                    "00".to_owned()
                } else if value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let mut bytes = value.as_bytes().to_vec();
                    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
                    String::from_utf8(bytes).unwrap()
                } else {
                    format!("{value}x")
                };
                let raw = changed(row, column, &replacement);
                let result = extract_retained(&raw)
                    .and_then(|evidence| evidence.matches_fields(entry.records));
                assert!(result.is_err(), "observation row {row} column {column}");
            }
        }
    }

    #[test]
    fn unknown_duplicate_conflicting_and_missing_records_refuse_directly() {
        let original = rows();
        for row in 0..original.len() {
            let mut missing = original.clone();
            missing.remove(row);
            assert!(extract_retained(&encode(&missing)).is_err());
            let mut duplicate = original.clone();
            duplicate.push(original[row].clone());
            assert!(extract_retained(&encode(&duplicate)).is_err());
            assert!(extract_retained(&changed(row, 0, "unknown")).is_err());
        }
        let mut conflict = original;
        conflict[2] = conflict[1].clone();
        conflict[2][1] = "compact".to_owned();
        assert!(extract_retained(&encode(&conflict)).is_err());
    }

    #[test]
    fn noncanonical_fields_and_missing_values_refuse_directly() {
        for (row, columns) in [
            (0, vec![5, 6, 7, 9]),
            (1, vec![2, 3, 4, 5]),
            (2, vec![1, 2]),
            (3, vec![1, 2]),
        ] {
            for column in columns {
                for value in ["0", "AB", "--", "gg"] {
                    assert!(extract_retained(&changed(row, column, value)).is_err());
                }
            }
        }
        for (row, fields) in rows().iter().enumerate() {
            for column in 0..fields.len() {
                assert!(extract_retained(&changed(row, column, "")).is_err());
            }
        }
        for exit in ["256", "-1", "+0", "00", "0x00"] {
            assert!(extract_retained(&changed(0, 10, exit)).is_err());
        }
        for (row, column, value) in [(0, 4, "vendor-v1"), (1, 1, "other"), (3, 3, "quiet")] {
            assert!(extract_retained(&changed(row, column, value)).is_err());
        }
    }

    #[test]
    fn retention_owns_the_hashed_and_parsed_buffer() {
        let entry = fixture_data::entry(SlashCmd::Clear);
        let mut raw = entry.raw.to_vec();
        let evidence = extract_retained(&raw).unwrap();
        raw.fill(b'x');
        assert_eq!(
            evidence.check_integrity(entry.length, &entry.digest),
            Ok(())
        );
        assert_eq!(evidence.matches_fields(entry.records), Ok(()));
    }
}
