//! T-DIGEST, the inbound half: the compare-only digest's one observation.

use super::support::*;
use crate::{decode_p2d, CompareOnlyDigest, InboundP2d, Sha256Digest};
use std::string::String;
use std::vec::Vec;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| std::format!("{:02x}", b)).collect()
}

/// A compare-only digest of SHA-256(`input`), decoded from a real ADMIT frame.
fn decoded(input: &[u8]) -> (CompareOnlyDigest, [u8; 32]) {
    let bytes = *Sha256Digest::of(input).as_bytes();
    match decode_p2d(&admit_bytes(1, 1, &[bytes])) {
        Ok(InboundP2d::Admit(crate::InboundAdmit {
            digests: [first, ..],
            ..
        })) => (first, bytes),
        _ => panic!("a valid ADMIT"),
    }
}

#[test]
fn t_digest_compare_only_matches_its_own_lowercase_hex() {
    let (digest, bytes) = decoded(b"abc");
    assert_eq!(
        hex(&bytes),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "the FIPS 180-2 vector"
    );
    assert!(
        digest.matches_stored_hex(&hex(&bytes)),
        "its own lowercase hex matches"
    );
}

#[test]
fn t_digest_compare_only_refuses_malformed_stored_configuration() {
    let (digest, bytes) = decoded(b"lease-token");
    let good = hex(&bytes);
    assert!(digest.matches_stored_hex(&good));
    assert!(
        !digest.matches_stored_hex(&good.to_uppercase()),
        "uppercase is malformed"
    );
    assert!(!digest.matches_stored_hex(&good[..63]), "63 bytes");
    assert!(
        !digest.matches_stored_hex(&std::format!("{}0", good)),
        "65 bytes"
    );
    assert!(!digest.matches_stored_hex(""), "empty");
    for (i, bad) in [b'g', b'G', b' ', b'-', 0u8, 0xff].iter().enumerate() {
        let mut text = good.clone().into_bytes();
        text[i * 7] = *bad;
        let text = String::from_utf8_lossy(&text).into_owned();
        assert!(
            !digest.matches_stored_hex(&text),
            "a non-hex byte {:#x}",
            bad
        );
    }
}

#[test]
fn t_digest_compare_only_refuses_every_single_nibble_difference() {
    let (digest, bytes) = decoded(b"x");
    let good = hex(&bytes);
    for position in 0..64 {
        let mut text = good.clone().into_bytes();
        text[position] = if text[position] == b'0' { b'1' } else { b'0' };
        let text = String::from_utf8(text).expect("ascii");
        assert!(
            !digest.matches_stored_hex(&text),
            "nibble {} differs",
            position
        );
    }
}

#[test]
fn t_digest_any_match_compares_every_presented_digest() {
    let stored = hex(Sha256Digest::of(b"valid").as_bytes());
    let blocks: Vec<[u8; 32]> = [&b"a"[..], b"b", b"valid"]
        .iter()
        .map(|t| *Sha256Digest::of(t).as_bytes())
        .collect();
    let frame = admit_bytes(1, 1, &blocks);
    match decode_p2d(&frame) {
        Ok(InboundP2d::Admit(admit)) => {
            assert_eq!(admit.presented().len(), 3);
            assert!(
                admit.any_matches_stored_hex(&stored),
                "the valid bearer last still matches"
            );
            assert!(
                !admit.any_matches_stored_hex(&hex(&[0u8; 32])),
                "no presented digest matches"
            );
        }
        _ => panic!("a valid ADMIT"),
    }
    for order in [[&b"valid"[..], b"a", b"b"], [&b"a"[..], b"valid", b"b"]] {
        let blocks: Vec<[u8; 32]> = order
            .iter()
            .map(|t| *Sha256Digest::of(t).as_bytes())
            .collect();
        match decode_p2d(&admit_bytes(3, 1, &blocks)) {
            Ok(InboundP2d::Admit(admit)) => assert!(
                admit.any_matches_stored_hex(&stored),
                "any position matches, not only the last"
            ),
            _ => panic!("a valid ADMIT"),
        }
    }
    let empty = admit_bytes(2, 1, &[]);
    match decode_p2d(&empty) {
        Ok(InboundP2d::Admit(admit)) => {
            assert!(
                !admit.any_matches_stored_hex(&stored),
                "n = 0 cannot authenticate"
            );
        }
        _ => panic!("a valid empty ADMIT"),
    }
}
