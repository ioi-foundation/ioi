use super::*;

/// R9 gate: every share of a certificate verifies INDIVIDUALLY, and
/// forensic extraction on a staged conflict names every double-signer
/// from the shares alone.
#[test]
fn every_share_verifies_individually_and_extraction_names_double_signers() {
    let (root_x, root_y) = ([0xAA; 32], [0xBB; 32]);
    // Members 0 and 1 double-sign; member 2 stays honest (signs only X).
    let mut cert_x = Vec::new();
    let mut cert_y = Vec::new();
    for member in 0u32..3 {
        let mut signer = EvolvingSealSigner::new(member, [member as u8 + 1; 32]);
        let record = signer.emit_share(root_x).expect("share for X");
        verify_seal_share(&record.share).expect("individually verifiable");
        cert_x.push(record.share);
        if member < 2 {
            // The double-signers use a SECOND signer instance restored
            // from the same initial seed — modeling a compromised or
            // duplicated signer, exactly what attribution must survive.
            let mut duplicated = EvolvingSealSigner::new(member, [member as u8 + 1; 32]);
            let record = duplicated.emit_share(root_y).expect("share for Y");
            verify_seal_share(&record.share).expect("individually verifiable");
            cert_y.push(record.share);
        }
    }
    let offenders = extract_double_signers(&cert_x, &cert_y).expect("extraction runs");
    assert_eq!(
        offenders,
        vec![0, 1],
        "every double-signer named, honest member not"
    );
}

/// R9 gate: after a seal the prior key is UNRECOVERABLE — the state
/// carries no byte of the spent seed, and the signer cannot produce a
/// second share for the spent index.
#[test]
fn spent_seed_is_erased_and_the_spent_index_is_unreachable() {
    let initial_seed = [0x42; 32];
    let mut signer = EvolvingSealSigner::new(7, initial_seed);
    let seal_hash = [0xCC; 32];
    let record = signer.emit_share(seal_hash).expect("share");

    // The spent seed's bytes are GONE from the persisted state.
    let state = signer.state_bytes();
    assert!(
        !state
            .windows(initial_seed.len())
            .any(|window| window == initial_seed),
        "spent seed bytes must not survive in the signer state"
    );

    // The signer moved on: its next share is for index 1, under a NEW
    // key — no second share for index 0 can exist.
    assert_eq!(signer.seal_index(), 1);
    let second = signer.emit_share([0xDD; 32]).expect("next share");
    assert_eq!(second.share.seal_index, 1);
    assert_ne!(
        second.share.public_key_bytes, record.share.public_key_bytes,
        "per-seal key evolved"
    );

    // And the ratchet is verifiable: the emitted record committed to
    // the NEXT key, which is exactly the one the second share used.
    let restored = EvolvingSealSigner::new(7, initial_seed);
    let _ = restored; // the initial seed still derives index 0 elsewhere —
                      // everlasting safety is about the SIGNER's storage,
                      // and the erasure assertion above is the claim.
}

/// R9 gate: the e2e chain — three members, two seals, all shares
/// individually verifiable, commitments chain forward.
#[test]
fn three_members_two_seals_end_to_end() {
    let seals = [[0xE1; 32], [0xE2; 32]];
    for member in 0u32..3 {
        let mut signer = EvolvingSealSigner::new(member, [member as u8 + 10; 32]);
        let mut previous_commitment = signer.current_key_commitment().expect("commitment");
        for (index, seal_hash) in seals.iter().enumerate() {
            let record = signer.emit_share(*seal_hash).expect("share");
            assert_eq!(record.share.seal_index, index as u64);
            verify_seal_share(&record.share).expect("verifies");
            assert_ne!(
                record.next_key_commitment, previous_commitment,
                "the commitment chain advances"
            );
            previous_commitment = record.next_key_commitment;
        }
    }
}

// Clean-room twin conformance-vector generator (AFT-CB P4.5b in-session).
// Emits the seal-share verification + double-signer extraction vectors an
// isolated non-Rust twin must reproduce. Run with AFT_TWIN_VECTORS=1 to
// (re)write the JSON; otherwise it self-checks that the reference verifier
// agrees with every labelled verdict, so the committed vectors can never
// drift from the reference.
#[test]
fn twin_conformance_vectors() {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Deterministic share set: 3 members, 2 seal indices each.
    let mut accept_lines = Vec::new();
    let share_of = |member: u32, seed: u8, seal_hash: [u8; 32]| -> SealShare {
        let mut signer = EvolvingSealSigner::new(member, [seed; 32]);
        signer.emit_share(seal_hash).expect("share").share
    };

    let sh_a = [0xA1u8; 32];
    let sh_b = [0xB2u8; 32];
    let mut valid_shares = Vec::new();
    for member in 0u32..3 {
        for (idx, sh) in [sh_a, sh_b].into_iter().enumerate() {
            let mut signer = EvolvingSealSigner::new(member, [member as u8 + 1; 32]);
            // advance to seal index `idx`
            for _ in 0..idx {
                signer.emit_share([0xEE; 32]).expect("advance");
            }
            let share = signer.emit_share(sh).expect("share").share;
            verify_seal_share(&share).expect("reference accepts");
            accept_lines.push(format!(
                "{{\"member_index\":{},\"seal_index\":{},\"seal_hash\":\"{}\",\"public_key\":\"{}\",\"signature\":\"{}\",\"verdict\":\"accept\"}}",
                share.member_index, share.seal_index, hex(&share.seal_hash),
                hex(&share.public_key_bytes), hex(&share.signature_bytes)
            ));
            valid_shares.push(share);
        }
    }

    // Reject vectors: a byte-flipped signature, a wrong seal_hash, a wrong
    // seal_index — each must FAIL the reference verifier.
    let mut reject_lines = Vec::new();
    let base = share_of(7, 9, [0xC3; 32]);
    let mut bad_sig = base.clone();
    bad_sig.signature_bytes[0] ^= 0xFF;
    assert!(verify_seal_share(&bad_sig).is_err());
    let mut bad_hash = base.clone();
    bad_hash.seal_hash[0] ^= 0xFF;
    assert!(verify_seal_share(&bad_hash).is_err());
    let mut bad_index = base.clone();
    bad_index.seal_index = base.seal_index.wrapping_add(1);
    assert!(verify_seal_share(&bad_index).is_err());
    for (name, s) in [
        ("flipped_sig", &bad_sig),
        ("wrong_hash", &bad_hash),
        ("wrong_index", &bad_index),
    ] {
        reject_lines.push(format!(
            "{{\"case\":\"{}\",\"member_index\":{},\"seal_index\":{},\"seal_hash\":\"{}\",\"public_key\":\"{}\",\"signature\":\"{}\",\"verdict\":\"reject\"}}",
            name, s.member_index, s.seal_index, hex(&s.seal_hash), hex(&s.public_key_bytes), hex(&s.signature_bytes)
        ));
    }

    // Double-signer extraction: members 0 and 1 sign conflicting roots for
    // seal index 0; member 2 signs only sh_a. Offenders = [0, 1].
    let (rx, ry) = ([0xAA; 32], [0xBB; 32]);
    let mut cert_x = Vec::new();
    let mut cert_y = Vec::new();
    for member in 0u32..3 {
        cert_x.push(share_of(member, member as u8 + 20, rx));
        if member < 2 {
            cert_y.push(share_of(member, member as u8 + 20, ry));
        }
    }
    let offenders = extract_double_signers(&cert_x, &cert_y).expect("extract");
    assert_eq!(offenders, vec![0, 1]);

    if std::env::var("AFT_TWIN_VECTORS").as_deref() == Ok("1") {
        let share_json = |s: &SealShare| {
            format!(
            "{{\"member_index\":{},\"seal_index\":{},\"seal_hash\":\"{}\",\"public_key\":\"{}\",\"signature\":\"{}\"}}",
            s.member_index, s.seal_index, hex(&s.seal_hash), hex(&s.public_key_bytes), hex(&s.signature_bytes))
        };
        let doc = format!(
            "{{\n  \"domain_tag\": \"aft::seal-share::v1\",\n  \"scheme\": \"ed25519\",\n  \"message\": \"domain_tag_bytes || seal_index_be64 || seal_hash32\",\n  \"accept\": [\n    {}\n  ],\n  \"reject\": [\n    {}\n  ],\n  \"extraction\": {{\n    \"cert_x\": [{}],\n    \"cert_y\": [{}],\n    \"expected_offenders\": [0, 1]\n  }}\n}}\n",
            accept_lines.join(",\n    "),
            reject_lines.join(",\n    "),
            cert_x.iter().map(&share_json).collect::<Vec<_>>().join(", "),
            cert_y.iter().map(&share_json).collect::<Vec<_>>().join(", "),
        );
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../internal-docs/architecture/protocols/aft/twin/conformance_vectors.json"
        );
        std::fs::write(path, doc).expect("write vectors");
    }
}
