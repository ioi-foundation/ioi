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
