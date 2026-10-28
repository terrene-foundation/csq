//! Pure classification of a mandatory-label SID's integrity level. Kept free of
//! Win32 calls so it is unit-tested on every platform; `fs_windows_acl` is its only
//! non-test consumer.
#![cfg_attr(not(any(windows, test)), allow(dead_code))]

/// `SECURITY_MANDATORY_MEDIUM_RID`: Untrusted is 0x0000, Low 0x1000, Medium 0x2000,
/// High 0x3000, System 0x4000.
pub(crate) const MEDIUM_RID: u32 = 0x2000;

/// The RID of a mandatory-label SID `S-1-16-<rid>` given its 12 bytes (revision 1,
/// one sub-authority, identifier authority {0,0,0,0,0,16}, then the RID), or `None`
/// when the bytes are any other shape.
pub(crate) fn label_rid(sid: &[u8]) -> Option<u32> {
    if sid.len() != 12 || sid[..8] != [1, 1, 0, 0, 0, 0, 0, 16] {
        return None;
    }
    Some(u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]))
}

/// Whether an INHERITED label ACE of this level may count as "no csq label" (and be
/// replaced by the explicit protected Medium one): ONLY exactly Medium. Below Medium
/// (Untrusted, Low) the object is Low-writable and a Low planter can give it the exact
/// owner and DACL; above Medium (High, System) stamping would LOWER the level, which
/// contradicts "it only tightens". A malformed or unknown level (`None`) is refused.
pub(crate) fn inherited_level_counts_as_absent(rid: Option<u32>) -> bool {
    rid == Some(MEDIUM_RID)
}

/// The policy bits an inherited label ACE must carry to sit beside csq's: no-write-up
/// (`SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`, 0x1) AND no-read-up (`..._NO_READ_UP`, 0x2).
pub(crate) const INHERITED_POLICY_MASK: u32 = 0x1 | 0x2;

/// Whether an INHERITED label ACE (its level SID's `rid` and its policy `mask`) may sit
/// beside csq's explicit one: exactly Medium AND the full NW|NR policy. A mask short of
/// either bit is refused: an NR-only label would leave the object writable up from Low,
/// an NW-only one (the default `icacls /setintegritylevel (OI)(CI)M`) readable up, and
/// which label ACE the kernel evaluates when several apply is not something csq
/// verifies, so only a label identical to ours in effect is accepted.
pub(crate) fn inherited_label_may_sit_beside(rid: Option<u32>, mask: u32) -> bool {
    inherited_level_counts_as_absent(rid) && mask & INHERITED_POLICY_MASK == INHERITED_POLICY_MASK
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sid(rid: u32) -> Vec<u8> {
        let mut bytes = vec![1, 1, 0, 0, 0, 0, 0, 16];
        bytes.extend(rid.to_le_bytes());
        bytes
    }

    // Reds if the gate accepted Untrusted/Low (the W11 regression: an inherited Low
    // label counted as absent and was stamped), High/System (stamping would lower them)
    // or refused exactly Medium.
    #[test]
    fn only_an_exactly_medium_inherited_label_may_count_as_absent() {
        for (name, rid, ok) in [
            ("untrusted", 0x0000, false),
            ("low", 0x1000, false),
            ("just below medium", 0x1fff, false),
            ("medium", 0x2000, true),
            ("medium plus", 0x2100, false),
            ("high", 0x3000, false),
            ("system", 0x4000, false),
        ] {
            assert_eq!(
                inherited_level_counts_as_absent(label_rid(&sid(rid))),
                ok,
                "{name}"
            );
        }
    }

    // A malformed or unknown level SID is refused.
    #[test]
    fn a_malformed_level_sid_is_refused() {
        let mut wrong_authority = sid(0x2000);
        wrong_authority[7] = 5;
        let mut two_subauthorities = sid(0x2000);
        two_subauthorities[1] = 2;
        let mut wrong_revision = sid(0x2000);
        wrong_revision[0] = 2;
        for (name, bytes) in [
            ("wrong authority", wrong_authority),
            ("two subauthorities", two_subauthorities),
            ("wrong revision", wrong_revision),
            ("short", vec![1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20]),
            ("long", [sid(0x2000), vec![0]].concat()),
            ("empty", Vec::new()),
        ] {
            assert_eq!(label_rid(&bytes), None, "{name}");
            assert!(
                !inherited_level_counts_as_absent(label_rid(&bytes)),
                "{name}"
            );
        }
        assert_eq!(label_rid(&sid(0x2000)), Some(MEDIUM_RID));
    }

    // An inherited Medium label counts as harmless only with BOTH policy bits. Reds with
    // the old NR-only test (mask 0x2 would pass) or a level-only test (0x0, 0x1 pass).
    #[test]
    fn an_inherited_medium_label_needs_the_full_nw_nr_mask() {
        let medium = label_rid(&sid(0x2000));
        for (name, mask, ok) in [
            ("no policy", 0x0, false),
            ("nw only", 0x1, false),
            ("nr only", 0x2, false),
            ("nw and nr", 0x3, true),
            ("nw nr plus an unknown bit", 0x7, true),
        ] {
            assert_eq!(inherited_label_may_sit_beside(medium, mask), ok, "{name}");
        }
        // The level gate still applies with the full mask.
        for rid in [0x1000, 0x3000, 0x2100] {
            assert!(!inherited_label_may_sit_beside(label_rid(&sid(rid)), 0x3));
        }
        assert!(!inherited_label_may_sit_beside(None, 0x3));
    }
}
