//! UUIDv7 generation for the Gemini NDJSON event log.
//!
//! Per spec 05 §5.8.1, each NDJSON event line carries a 26-char base32
//! UUIDv7 in its `id` field. The daemon uses this ID for deduplication
//! across the dual-path (live IPC + NDJSON drain) so the same event
//! never applies twice to `quota.json`.
//!
//! # Why UUIDv7
//!
//! UUIDv7 is timestamp-prefixed (48 bits Unix-millis at the high end)
//! plus 80 bits of random. The timestamp prefix gives k-sortability
//! — events ordered by ID also order by emission time (modulo 1ms
//! resolution) — which makes the daemon's bounded LRU dedup set
//! correct under "drain old log first, then accept newer events" flow.
//!
//! Spec wording: "26-char base32 UUIDv7". 128 bits in base32 (5 bits
//! per char) needs 26 chars. We use the RFC 4648 base32 alphabet
//! (uppercase A-Z 2-7) without padding.
//!
//! # Why hand-rolled (no uuid crate)
//!
//! csq-core already depends on `getrandom` for the RustCrypto AEAD
//! path. UUIDv7 layout is ~30 lines of arithmetic. The `uuid` crate
//! would add an unnecessary build-graph hop for code that never
//! changes. The bit layout below is from RFC 9562 §5.7.

use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 4648 base32 alphabet (uppercase). 26 chars encode 128 bits with
/// 2 bits unused at the tail (we set them to 0 — the daemon dedup set
/// keys on the full 26-char string, so the unused bits are irrelevant
/// for collision risk).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Number of base32 characters needed to encode 128 bits (5 bits per
/// char): `ceil(128 / 5) = 26`.
const ID_CHAR_COUNT: usize = 26;

/// Generates a fresh UUIDv7 encoded as a 26-char base32 string.
///
/// Layout per RFC 9562 §5.7:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       unix_ts_ms (48)                         |
/// |       unix_ts_ms (cont.)      | ver |        rand_a (12)      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |var|                   rand_b (62)                             |
/// |                       rand_b (cont.)                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// `ver` = 0b0111 (= 7), `var` = 0b10. The remaining 74 bits are
/// random from `getrandom`.
///
/// # Panics
///
/// `getrandom::getrandom` may fail on a system without an entropy
/// source — but every platform csq targets (macOS, Linux, Windows)
/// provides one unconditionally. The panic message is fixed
/// vocabulary so the OS error does not leak into the panic payload.
pub fn new_uuidv7() -> String {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut rand_bytes = [0u8; 10];
    getrandom::getrandom(&mut rand_bytes).expect("getrandom failed for UUIDv7 entropy");
    let bytes = pack_uuidv7_bytes(unix_ms, rand_bytes);
    encode_base32(&bytes)
}

/// Internal helper: packs the 16-byte UUIDv7 layout from a `unix_ms`
/// timestamp and 10 bytes of random data. Exposed for unit testing
/// the bit layout independently of the entropy source.
pub(crate) fn pack_uuidv7_bytes(unix_ms: u64, rand_bytes: [u8; 10]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // Bytes 0-5: 48 bits of unix_ms (big-endian, top byte first).
    bytes[0] = ((unix_ms >> 40) & 0xFF) as u8;
    bytes[1] = ((unix_ms >> 32) & 0xFF) as u8;
    bytes[2] = ((unix_ms >> 24) & 0xFF) as u8;
    bytes[3] = ((unix_ms >> 16) & 0xFF) as u8;
    bytes[4] = ((unix_ms >> 8) & 0xFF) as u8;
    bytes[5] = (unix_ms & 0xFF) as u8;
    // Byte 6: high nibble = version (7), low nibble = high 4 bits of rand_a.
    bytes[6] = 0x70 | (rand_bytes[0] & 0x0F);
    // Byte 7: low 8 bits of rand_a.
    bytes[7] = rand_bytes[1];
    // Byte 8: top 2 bits = variant (0b10), low 6 bits = high 6 bits of rand_b.
    bytes[8] = 0x80 | (rand_bytes[2] & 0x3F);
    // Bytes 9-15: remaining 56 bits of rand_b.
    bytes[9..16].copy_from_slice(&rand_bytes[3..10]);
    bytes
}

/// Internal helper: encodes 16 bytes as 26 base32 characters
/// (RFC 4648 alphabet, no padding). 128 bits / 5 bits-per-char =
/// 25.6 → 26 chars (last char carries 3 data bits + 2 zero pad).
pub(crate) fn encode_base32(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(ID_CHAR_COUNT);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = ((buffer >> bits_in_buffer) & 0b11111) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits_in_buffer > 0 {
        // 3 leftover data bits — left-shift to occupy high positions
        // of a 5-bit chunk; low 2 bits remain zero pad.
        let idx = ((buffer << (5 - bits_in_buffer)) & 0b11111) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    debug_assert_eq!(out.len(), ID_CHAR_COUNT);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn id_is_26_chars() {
        let id = new_uuidv7();
        assert_eq!(id.len(), ID_CHAR_COUNT);
    }

    #[test]
    fn id_uses_rfc4648_alphabet() {
        let id = new_uuidv7();
        for c in id.chars() {
            assert!(
                BASE32_ALPHABET.contains(&(c as u8)),
                "char {c} not in RFC 4648 base32 alphabet"
            );
        }
    }

    #[test]
    fn version_nibble_is_seven() {
        // Byte 6 bits 4-7 must be 0b0111 per RFC 9562 §5.7.
        let bytes = pack_uuidv7_bytes(0xDEAD_BEEF_CAFE, [0xAA; 10]);
        assert_eq!(
            bytes[6] >> 4,
            0x07,
            "version nibble must be 7, got {:#x}",
            bytes[6] >> 4
        );
    }

    #[test]
    fn variant_bits_are_ten() {
        // Byte 8 top 2 bits must be 0b10 per RFC 9562 §5.7.
        let bytes = pack_uuidv7_bytes(0xDEAD_BEEF_CAFE, [0xAA; 10]);
        assert_eq!(
            bytes[8] >> 6,
            0b10,
            "variant bits must be 10, got {:#b}",
            bytes[8] >> 6
        );
    }

    #[test]
    fn timestamp_high_bits_preserved() {
        // The first 6 bytes encode the 48-bit timestamp big-endian.
        let ts = 0x0123_4567_89AB_u64;
        let bytes = pack_uuidv7_bytes(ts, [0; 10]);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x23);
        assert_eq!(bytes[2], 0x45);
        assert_eq!(bytes[3], 0x67);
        assert_eq!(bytes[4], 0x89);
        assert_eq!(bytes[5], 0xAB);
    }

    #[test]
    fn ids_are_unique_across_burst() {
        // 10k samples. UUIDv7's 80 bits of random give ~80-bit collision
        // resistance per millisecond — at this sample size collisions are
        // astronomically unlikely on a non-broken entropy source. A
        // duplicate here is a regression in the random path or in
        // pack_uuidv7_bytes.
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(new_uuidv7()), "UUIDv7 collision in burst");
        }
    }

    #[test]
    fn ids_with_higher_timestamp_sort_after_earlier_ones() {
        // K-sortability is the whole point of v7 vs v4. Test the
        // property deterministically via `pack_uuidv7_bytes` rather
        // than via `new_uuidv7` + sleep — Windows's SystemTime is
        // 15.6ms granular by default, so a 5ms sleep occasionally
        // lands in the same millisecond and the test flakes
        // (observed on windows-latest CI 2026-04-25). Using fixed
        // timestamps tests the layout invariant directly with the
        // same-prefix random payload so any difference comes from
        // the timestamp bytes.
        let rand = [0xAA; 10];
        let earlier_bytes = pack_uuidv7_bytes(1_000_000_000_000, rand);
        let later_bytes = pack_uuidv7_bytes(1_000_000_000_001, rand);
        let earlier = encode_base32(&earlier_bytes);
        let later = encode_base32(&later_bytes);
        assert!(
            later > earlier,
            "later id ({later}) must sort after earlier id ({earlier})"
        );
    }

    #[test]
    fn encode_base32_known_vector() {
        // 16 zero bytes encode to 26 'A's (every 5-bit chunk = 0 = 'A').
        let id = encode_base32(&[0u8; 16]);
        assert_eq!(id, "A".repeat(26));
        // 16 0xFF bytes: every 5-bit chunk except the last has all bits
        // set (= 0b11111 = '7'); the last char carries 3 data bits + 2
        // zero pad → 0b11100 = 28 = '4'.
        let id = encode_base32(&[0xFFu8; 16]);
        let expected: String = "7".repeat(25) + "4";
        assert_eq!(id, expected);
    }
}
