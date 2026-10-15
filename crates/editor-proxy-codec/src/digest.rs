//! The INBOUND compare-only digest (DESIGN v2 (1)).

/// A 32-byte digest DECODED from a proxy ADMIT. Only the trusted decoder constructs one (its
/// constructor is crate-private); its one observation is [`CompareOnlyDigest::matches_stored_hex`],
/// a constant-time comparison with a stored lowercase hex hash. No `Clone`/`Copy`, no
/// `Debug`/`Display`, no serialization, no byte view, no raw conversion and no production
/// re-encoder. Callers may move or store the opaque value.
///
/// Public trusted decoding ([`crate::decode_p2d`]) necessarily lets a caller obtain these values
/// from arbitrary well-formed wire bytes; the claim is restricted USE after trusted decoding, not
/// remote hash provenance.
pub struct CompareOnlyDigest([u8; 32]);

impl CompareOnlyDigest {
    /// The decoder's constructor (crate-private: cf17 pins that it is not callable outside).
    pub(crate) fn from_wire(bytes: [u8; 32]) -> CompareOnlyDigest {
        CompareOnlyDigest(bytes)
    }

    /// True iff `stored` is exactly 64 lowercase hexadecimal ASCII bytes encoding these 32 bytes.
    /// The stored text is decoded into a fixed stack array without data-dependent branches, all 32
    /// bytes are compared in constant time, and malformed stored configuration (wrong length,
    /// uppercase, any non-hex byte) returns false.
    pub fn matches_stored_hex(&self, stored: &str) -> bool {
        let text = stored.as_bytes();
        if text.len() != 64 {
            return false;
        }
        let mut decoded = [0u8; 32];
        let mut bad = 0u8;
        let mut i = 0;
        while i < 32 {
            let (hi, hi_bad) = nibble(text[2 * i]);
            let (lo, lo_bad) = nibble(text[2 * i + 1]);
            decoded[i] = (hi << 4) | lo;
            bad |= hi_bad | lo_bad;
            i += 1;
        }
        let mut diff = 0u8;
        let mut j = 0;
        while j < 32 {
            diff |= decoded[j] ^ self.0[j];
            j += 1;
        }
        (diff | bad) == 0
    }

    /// The test-only canonical encoder's view (unit tests only: absent from every shipped build).
    #[cfg(test)]
    pub(crate) fn test_only_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 0xff if `a < b`, else 0, without a branch.
const fn ct_lt(a: u8, b: u8) -> u8 {
    ((a as u16).wrapping_sub(b as u16) >> 8) as u8
}

/// A lowercase hex digit's value and a bad flag (1 if `c` is not `0-9a-f`), without a branch.
const fn nibble(c: u8) -> (u8, u8) {
    let d = c.wrapping_sub(b'0');
    let l = c.wrapping_sub(b'a');
    let is_d = ct_lt(d, 10);
    let is_l = ct_lt(l, 6);
    let value = (d & is_d) | (l.wrapping_add(10) & is_l);
    let bad = !(is_d | is_l) & 1;
    (value, bad)
}
