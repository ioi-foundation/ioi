#[test]
fn recoverable_slot_payload_hash_changes_with_transaction_hashes() {
    let certificate = CanonicalOrderCertificate {
        height: 11,
        bulletin_commitment: BulletinCommitment {
            height: 11,
            cutoff_timestamp_ms: 1_750_002_222_000,
            bulletin_root: [31u8; 32],
            entry_count: 2,
        },
        bulletin_availability_certificate: BulletinAvailabilityCertificate {
            height: 11,
            bulletin_commitment_hash: [32u8; 32],
            recoverability_root: [33u8; 32],
        },
        randomness_beacon: [34u8; 32],
        ordered_transactions_root_hash: [35u8; 32],
        resulting_state_root_hash: [36u8; 32],
        proof: Default::default(),
        omission_proofs: Vec::new(),
    };
    let mut payload = RecoverableSlotPayloadV1 {
        height: 11,
        view: 4,
        producer_account_id: AccountId([37u8; 32]),
        block_commitment_hash: [38u8; 32],
        canonical_order_certificate: certificate,
        ordered_transaction_hashes: vec![[39u8; 32], [40u8; 32]],
    };

    let original = canonical_recoverable_slot_payload_hash(&payload).expect("payload hash");
    payload.ordered_transaction_hashes[1][0] ^= 0xFF;
    let updated = canonical_recoverable_slot_payload_hash(&payload).expect("updated payload hash");
    assert_ne!(original, updated);
}

#[test]
fn recoverable_slot_payload_v2_hash_changes_with_transaction_bytes() {
    let certificate = CanonicalOrderCertificate {
        height: 12,
        bulletin_commitment: BulletinCommitment {
            height: 12,
            cutoff_timestamp_ms: 1_750_003_333_000,
            bulletin_root: [41u8; 32],
            entry_count: 2,
        },
        bulletin_availability_certificate: BulletinAvailabilityCertificate {
            height: 12,
            bulletin_commitment_hash: [42u8; 32],
            recoverability_root: [43u8; 32],
        },
        randomness_beacon: [44u8; 32],
        ordered_transactions_root_hash: [45u8; 32],
        resulting_state_root_hash: [46u8; 32],
        proof: Default::default(),
        omission_proofs: Vec::new(),
    };
    let mut payload = RecoverableSlotPayloadV2 {
        height: 12,
        view: 5,
        producer_account_id: AccountId([47u8; 32]),
        block_commitment_hash: [48u8; 32],
        canonical_order_certificate: certificate,
        ordered_transaction_bytes: vec![vec![49u8, 50u8], vec![51u8, 52u8]],
    };

    let original = canonical_recoverable_slot_payload_v2_hash(&payload).expect("payload v2 hash");
    payload.ordered_transaction_bytes[1][1] ^= 0xFF;
    let updated =
        canonical_recoverable_slot_payload_v2_hash(&payload).expect("updated payload v2 hash");
    assert_ne!(original, updated);
}

#[test]
fn recoverable_slot_payload_v3_hash_changes_with_publication_bundle_bytes() {
    let certificate = CanonicalOrderCertificate {
        height: 13,
        bulletin_commitment: BulletinCommitment {
            height: 13,
            cutoff_timestamp_ms: 1_750_004_444_000,
            bulletin_root: [51u8; 32],
            entry_count: 2,
        },
        bulletin_availability_certificate: BulletinAvailabilityCertificate {
            height: 13,
            bulletin_commitment_hash: [52u8; 32],
            recoverability_root: [53u8; 32],
        },
        randomness_beacon: [54u8; 32],
        ordered_transactions_root_hash: [55u8; 32],
        resulting_state_root_hash: [56u8; 32],
        proof: Default::default(),
        omission_proofs: Vec::new(),
    };
    let mut payload = RecoverableSlotPayloadV3 {
        height: 13,
        view: 6,
        producer_account_id: AccountId([57u8; 32]),
        block_commitment_hash: [58u8; 32],
        parent_block_hash: [57u8; 32],
        canonical_order_certificate: certificate,
        ordered_transaction_bytes: vec![vec![59u8, 60u8], vec![61u8, 62u8]],
        canonical_order_publication_bundle_bytes: vec![63u8, 64u8, 65u8],
    };

    let original = canonical_recoverable_slot_payload_v3_hash(&payload).expect("payload v3 hash");
    payload.canonical_order_publication_bundle_bytes[2] ^= 0xFF;
    let updated =
        canonical_recoverable_slot_payload_v3_hash(&payload).expect("updated payload v3 hash");
    assert_ne!(original, updated);
}

#[test]
fn recoverable_slot_payload_v4_hash_changes_with_bulletin_close_bytes() {
    let (mut payload, _, _) = build_sample_recoverable_slot_payload_v4(13, 6, 57);
    let original = canonical_recoverable_slot_payload_v4_hash(&payload).expect("payload v4 hash");
    payload.canonical_bulletin_close_bytes[0] ^= 0xFF;
    let updated =
        canonical_recoverable_slot_payload_v4_hash(&payload).expect("updated payload v4 hash");
    assert_ne!(original, updated);
}

#[test]
fn recoverable_slot_payload_v5_hash_changes_with_bulletin_surface_entries() {
    let (mut payload, _, _, _) = build_sample_recoverable_slot_payload_v5(14, 7, 63);
    let original = canonical_recoverable_slot_payload_v5_hash(&payload).expect("payload v5 hash");
    payload.bulletin_surface_entries[0].tx_hash[0] ^= 0xFF;
    let updated =
        canonical_recoverable_slot_payload_v5_hash(&payload).expect("updated payload v5 hash");
    assert_ne!(original, updated);
}

#[test]
fn recovered_publication_bundle_hash_changes_with_supporting_witnesses() {
    let recovered = RecoveredPublicationBundle {
        height: 14,
        block_commitment_hash: [66u8; 32],
        parent_block_commitment_hash: [65u8; 32],
        coding: xor_recovery_coding(3, 2),
        supporting_witness_manifest_hashes: vec![[67u8; 32], [68u8; 32]],
        recoverable_slot_payload_hash: [69u8; 32],
        recoverable_full_surface_hash: [70u8; 32],
        canonical_order_publication_bundle_hash: [71u8; 32],
        canonical_bulletin_close_hash: [72u8; 32],
    };
    let original = canonical_recovered_publication_bundle_hash(&recovered).expect("recovered hash");
    let mut updated = recovered.clone();
    updated.supporting_witness_manifest_hashes.swap(0, 1);
    let reordered = canonical_recovered_publication_bundle_hash(&updated).expect("reordered hash");
    assert_ne!(original, reordered);

    let normalized = normalize_recovered_publication_bundle_supporting_witnesses(
        &updated.supporting_witness_manifest_hashes,
    )
    .expect("normalize supporting witnesses");
    assert_eq!(normalized, vec![[67u8; 32], [68u8; 32]]);
}

