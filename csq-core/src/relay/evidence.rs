//! Bounded owned-fake recorder evidence; extraction grants no relay authority.

use sha2::{Digest, Sha256};

pub(super) const MAX_RAW_BYTES: usize = 8192;
// Frozen independently of the captured artifacts (A0 interface v1).
const REQUIRED_RECORDS: [(&str, usize); 4] = [
    ("subject", 11),
    ("input", 6),
    ("effect", 3),
    ("completion", 4),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvidenceError {
    Bounds,
    Grammar,
    RecordSet,
    Field,
    Length,
    Digest,
    Mismatch,
}

/// Recorder observations only: no constructor, policy, cell, or writable bytes.
pub(super) struct ExtractedEvidence {
    retained: Box<[u8]>,
    digest: [u8; 32],
    records: Vec<Vec<String>>,
}

fn lower_hex(value: &str) -> bool {
    value == "-"
        || (!value.is_empty()
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

pub(super) fn extract_retained(raw: &[u8]) -> Result<ExtractedEvidence, EvidenceError> {
    // A0_GUARD bounded_retention: refuse before allocating the retained copy.
    if raw.is_empty() || raw.len() > MAX_RAW_BYTES {
        return Err(EvidenceError::Bounds);
    }
    let retained: Box<[u8]> = raw.into();
    let digest = Sha256::digest(&retained).into();
    // Hash and parse this same immutable owned buffer, never reopen a path.
    // A0_GUARD raw_alphabet
    if retained
        .iter()
        .any(|&b| !matches!(b, b'\t' | b'\n' | b'!'..=b'~'))
    {
        return Err(EvidenceError::Grammar);
    }
    // A0_GUARD terminated_capture
    if retained.last() != Some(&b'\n') {
        return Err(EvidenceError::Grammar);
    }
    let text = std::str::from_utf8(&retained).map_err(|_| EvidenceError::Grammar)?;
    let lines: Vec<_> = text.split_terminator('\n').collect();
    // A0_GUARD required_record_set: the sole completeness check, before zip.
    if lines.len() != REQUIRED_RECORDS.len() {
        return Err(EvidenceError::RecordSet);
    }
    let mut records = Vec::new();
    for (line, (tag, count)) in lines.iter().zip(REQUIRED_RECORDS) {
        let fields: Vec<_> = line.split('\t').collect();
        // A0_GUARD exact_record_shape
        if fields.len() != count || fields[0] != tag {
            return Err(EvidenceError::RecordSet);
        }
        // A0_GUARD nonempty_fields
        if fields.iter().any(|field| field.is_empty()) {
            return Err(EvidenceError::Field);
        }
        let vocabulary_ok = match tag {
            "subject" => fields[1] == "relay-evidence-v1" && fields[4] == "ownedfake-v1",
            "input" => matches!(fields[1], "clear" | "compact"),
            "completion" => fields[3] == "exit0-pty-eof",
            _ => true,
        };
        // A0_GUARD closed_vocabulary
        if !vocabulary_ok {
            return Err(EvidenceError::Field);
        }
        let hex_fields: &[usize] = match tag {
            "subject" => &[5, 6, 7, 9],
            "input" => &[2, 3, 4, 5],
            "effect" => &[1, 2],
            "completion" => &[1, 2],
            _ => unreachable!("required tag checked above"),
        };
        // A0_GUARD canonical_hex
        if hex_fields.iter().any(|&i| !lower_hex(fields[i])) {
            return Err(EvidenceError::Field);
        }
        if tag == "subject" {
            // A0_GUARD hash_width
            if [5, 6, 7].iter().any(|&i| fields[i].len() != 64) {
                return Err(EvidenceError::Field);
            }
            // A0_GUARD canonical_exit
            let exit = fields[10].parse::<u8>().map_err(|_| EvidenceError::Field)?;
            if exit.to_string() != fields[10] {
                return Err(EvidenceError::Field);
            }
        }
        records.push(fields.into_iter().map(str::to_owned).collect());
    }
    Ok(ExtractedEvidence {
        retained,
        digest,
        records,
    })
}

impl ExtractedEvidence {
    pub(super) fn check_integrity(
        &self,
        length: usize,
        digest: &[u8; 32],
    ) -> Result<(), EvidenceError> {
        // A0_GUARD retained_length
        if self.retained.len() != length {
            return Err(EvidenceError::Length);
        }
        // A0_GUARD retained_digest
        if &self.digest != digest {
            return Err(EvidenceError::Digest);
        }
        Ok(())
    }

    pub(super) fn matches_fields(&self, expected: &[&[&str]]) -> Result<(), EvidenceError> {
        // A0_GUARD exact_catalog_fields
        if self
            .records
            .iter()
            .map(|r| r.iter().map(String::as_str).collect::<Vec<_>>())
            .ne(expected.iter().map(|r| r.to_vec()))
        {
            return Err(EvidenceError::Mismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_oversize_capture_refuse_before_retention() {
        assert!(matches!(extract_retained(b""), Err(EvidenceError::Bounds)));
        assert!(matches!(
            extract_retained(&vec![b'x'; MAX_RAW_BYTES + 1]),
            Err(EvidenceError::Bounds)
        ));
    }

    #[test]
    fn capture_rejects_non_graphic_ascii_and_non_ascii() {
        for byte in [0, b'\r', b' ', 0x1b, 0x7f, 0x80, 0xff] {
            assert!(
                matches!(
                    extract_retained(&[byte, b'\n']),
                    Err(EvidenceError::Grammar)
                ),
                "byte {byte}"
            );
        }
    }

    #[test]
    fn truncated_capture_refuses() {
        assert!(matches!(
            extract_retained(b"subject"),
            Err(EvidenceError::Grammar)
        ));
    }
}
