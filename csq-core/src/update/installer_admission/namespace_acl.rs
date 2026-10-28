//! Admission ancestry may use inherited ACLs, but foreign principals must not
//! be able to replace its dedicated secret directory between gate calls.
const DELETE: u32 = 0x0001_0000;
const DELETE_CHILD: u32 = 0x40;
const ADD_SUBDIRECTORY: u32 = 0x04;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const WRITE_DATA: u32 = 0x02;
const WRITE_ATTRIBUTES: u32 = 0x100;
const DANGEROUS: u32 = DELETE
    | DELETE_CHILD
    | ADD_SUBDIRECTORY
    | WRITE_DAC
    | WRITE_OWNER
    | WRITE_DATA
    | WRITE_ATTRIBUTES;
fn sid_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8
        || bytes[0] != 1
        || bytes[1] > 15
        || bytes.len() != 8 + usize::from(bytes[1]) * 4
    {
        return None;
    }
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let mut text = format!("S-1-{authority}");
    for part in bytes[8..].as_chunks::<4>().0 {
        text.push_str(&format!("-{}", u32::from_le_bytes(*part)));
    }
    Some(text)
}
fn trusted(sid: &str, current: &str) -> bool {
    sid == current || sid == "S-1-5-18" || sid == "S-1-5-32-544"
}
fn file_mask(mask: u32) -> u32 {
    let mut mapped = mask & !0xf000_0000;
    if mask & 0x1000_0000 != 0 {
        mapped |= 0x001f_01ff;
    } // GENERIC_ALL
    if mask & 0x4000_0000 != 0 {
        mapped |= 0x0012_0116;
    } // GENERIC_WRITE
    if mask & 0x8000_0000 != 0 {
        mapped |= 0x0012_0089;
    } // GENERIC_READ
    if mask & 0x2000_0000 != 0 {
        mapped |= 0x0012_00a0;
    } // GENERIC_EXECUTE
    mapped
}
/// Consumed by the Win32 retained-handle reader for BOTH profile and .csq.
/// NULL/absent DACL is None; empty DACL permits nobody and is safe here.
/// Denies do not cancel dangerous grants: conservative refusal avoids reasoning
/// about group membership and ACL order. Unknown ACE layouts always refuse.
pub(super) fn parent_acl_safe(owner: &[u8], current: &str, dacl: Option<&[u8]>) -> bool {
    let Some(owner) = sid_text(owner) else {
        return false;
    };
    if !trusted(&owner, current) {
        return false;
    }
    let Some(acl) = dacl else {
        return false;
    };
    if acl.len() < 8 || !matches!(acl[0], 2 | 4) {
        return false;
    }
    let size = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
    let count = u16::from_le_bytes([acl[4], acl[5]]);
    if size != acl.len() || size < 8 {
        return false;
    }
    let mut offset = 8usize;
    for _ in 0..count {
        let Some(header) = acl.get(offset..offset + 4) else {
            return false;
        };
        let kind = header[0];
        let flags = header[1];
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if !matches!(kind, 0 | 1) || flags & !0x1f != 0 || length < 16 || length % 4 != 0 {
            return false;
        }
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        let Some(ace) = acl.get(offset..end) else {
            return false;
        };
        let Some(sid) = sid_text(&ace[8..]) else {
            return false;
        };
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        if kind == 0
            && flags & 0x08 == 0
            && sid != "S-1-3-0"
            && !trusted(&sid, current)
            && file_mask(mask) & DANGEROUS != 0
        {
            return false;
        }
        offset = end;
    }
    // ACL allocation may include unused capacity after the last declared ACE.
    offset <= size
}

#[cfg(test)]
mod tests {
    use super::*;
    const USER: &str = "S-1-5-21-42";
    fn sid(authority: u8, parts: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, authority];
        for value in parts {
            bytes.extend(value.to_le_bytes());
        }
        bytes
    }
    fn acl(entries: &[(u8, u8, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![2, 0, 0, 0, 0, 0, 0, 0];
        for (kind, flags, mask, sid) in entries {
            bytes.extend([*kind, *flags]);
            bytes.extend(((8 + sid.len()) as u16).to_le_bytes());
            bytes.extend(mask.to_le_bytes());
            bytes.extend(sid);
        }
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_le_bytes());
        bytes[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes
    }
    #[test]
    fn trusted_owners_and_inherited_nonmutating_foreign_grants_pass() {
        let user = sid(5, &[21, 42]);
        let sys = sid(5, &[18]);
        let admin = sid(5, &[32, 544]);
        let grants = acl(&[
            (0, 0x13, 0x001f_01ff, user.clone()),
            (0, 0x13, 0x001f_01ff, sys.clone()),
            (0, 0x13, 0x001f_01ff, admin.clone()),
            (0, 0x10, 0xa000_0000, sid(1, &[0])),
        ]);
        for owner in [user, sys, admin] {
            assert!(parent_acl_safe(&owner, USER, Some(&grants)));
        }
    }
    #[test]
    fn every_foreign_mutation_bit_and_generic_grant_refuses() {
        let owner = sid(5, &[21, 42]);
        // Literal Win32 rights are independent of the production bit constants.
        for mask in [
            0x0001_0000,
            0x40,
            0x04,
            0x02,
            0x100,
            0x0004_0000,
            0x0008_0000,
            0x4000_0000,
            0x1000_0000,
        ] {
            let grants = acl(&[(0, 0, mask, sid(1, &[0]))]);
            assert!(
                !parent_acl_safe(&owner, USER, Some(&grants)),
                "mask={mask:08x}"
            );
        }
    }
    #[test]
    fn null_absent_foreign_owner_malformed_and_unknown_aces_refuse() {
        let owner = sid(5, &[21, 42]);
        assert!(!parent_acl_safe(&owner, USER, None));
        let empty = acl(&[]);
        assert!(!parent_acl_safe(&sid(5, &[21, 99]), USER, Some(&empty)));
        for kind in [2, 5, 9, 255] {
            assert!(!parent_acl_safe(
                &owner,
                USER,
                Some(&acl(&[(kind, 0, 0, owner.clone())]))
            ));
            assert!(!parent_acl_safe(
                &owner,
                USER,
                Some(&acl(&[(kind, 8, 0, owner.clone())]))
            ));
        }
        let good = acl(&[(0, 0, 0x001f_01ff, owner.clone())]);
        for end in 0..good.len() {
            assert!(!parent_acl_safe(&owner, USER, Some(&good[..end])));
        }
        let mut bad_sid = good.clone();
        bad_sid[16] = 2;
        assert!(!parent_acl_safe(&owner, USER, Some(&bad_sid)));
        let mut bad_count = good;
        bad_count[4] = 2;
        assert!(!parent_acl_safe(&owner, USER, Some(&bad_count)));
    }
    #[test]
    fn inherit_only_creator_owner_and_denies_do_not_grant_mutation() {
        let owner = sid(5, &[21, 42]);
        let grants = acl(&[
            (0, 0x0b, 0x1000_0000, sid(1, &[0])),
            (0, 0, 0x1000_0000, sid(3, &[0])),
            (1, 0, 0x1000_0000, sid(1, &[0])),
        ]);
        assert!(parent_acl_safe(&owner, USER, Some(&grants)));
        let denies_then_grant = acl(&[(1, 0, 0x40, sid(1, &[0])), (0, 0, 0x40, sid(1, &[0]))]);
        assert!(!parent_acl_safe(&owner, USER, Some(&denies_then_grant)));
    }
}
