//! The OUTBOUND proxy digest (BUILD-DELTA #85, DESIGN v2 (1)): a SHA-256 digest whose ONLY
//! constructor hashes bytes.
//!
//! The editor/preview proxy is its own OS process. It tells the daemon which lease tokens a
//! browser presented by their SHA-256 digests, never by the tokens. [`Sha256Digest`] is that
//! outbound value: its field is private and its one constructor, [`Sha256Digest::of`], hashes.
//! There is no raw-array constructor, no `From`/`TryFrom`/`Default`/`FromStr`, no serde, no
//! mutable view, no `Deref`, no exported constructing macro and no public constant carrying
//! caller-chosen bytes, and no `Debug`/`Display` (a digest has no place in a log). `Copy`/`Clone`
//! only duplicate a hash already obtained by hashing.
//!
//! The claim is narrow: honest LOCAL hash construction. It is not remote hash provenance (the
//! daemon cannot prove a remote sender hashed anything), and the inbound value the daemon decodes
//! is a different, compare-only type in the trusted codec (`ioi-editor-proxy-ipc`).
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use sha2::{Digest, Sha256};

/// A SHA-256 digest. Its ONLY constructor hashes bytes.
#[derive(Clone, Copy)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The SHA-256 of `bytes`: the only way to make a `Sha256Digest`.
    pub fn of(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest(Sha256::digest(bytes).into())
    }

    /// The digest's 32 bytes, read-only (the outbound encoder writes them into a frame).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256Digest;

    /// FIPS 180-2 one-block vector: SHA-256("abc").
    const ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    /// SHA-256 of the empty string.
    const EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    /// FIPS 180-2 two-block vector: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").
    const TWO_BLOCK: [u8; 32] = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60,
        0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb,
        0x06, 0xc1,
    ];

    #[test]
    fn t_digest_of_is_sha256_on_the_known_answer_vectors() {
        assert_eq!(Sha256Digest::of(b"abc").as_bytes(), &ABC);
        assert_eq!(Sha256Digest::of(b"").as_bytes(), &EMPTY);
        assert_eq!(
            Sha256Digest::of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
                .as_bytes(),
            &TWO_BLOCK
        );
    }

    #[test]
    fn t_digest_copies_keep_the_hash_and_different_inputs_differ() {
        let a = Sha256Digest::of(b"lease-token");
        let b = a;
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(
            Sha256Digest::of(b"lease-token").as_bytes(),
            Sha256Digest::of(b"lease-tokeN").as_bytes()
        );
    }
}
