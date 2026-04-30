#[test]
fn recoverable_slot_payload_v3_reconstructs_from_two_systematic_xor_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(15, 7, 71);
    let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 2);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [72u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: xor_recovery_coding(3, 2),
            share_index: 0,
            share_commitment_hash: [73u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [74u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: xor_recovery_coding(3, 2),
            share_index: 2,
            share_commitment_hash: [75u8; 32],
            material_bytes: shards[2].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from two systematic xor shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
    assert_eq!(
        canonical_order_publication_bundle_hash(&recovered_bundle)
            .expect("publication bundle hash"),
        canonical_order_publication_bundle_hash(&bundle).expect("expected bundle hash")
    );
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_three_of_four_systematic_xor_parity_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(16, 8, 76);
    let shards = encode_systematic_xor_k_of_k_plus_1_shards(&payload, 3);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [77u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: xor_recovery_coding(4, 3),
            share_index: 0,
            share_commitment_hash: [78u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [79u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: xor_recovery_coding(4, 3),
            share_index: 2,
            share_commitment_hash: [80u8; 32],
            material_bytes: shards[2].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [81u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: xor_recovery_coding(4, 3),
            share_index: 3,
            share_commitment_hash: [82u8; 32],
            material_bytes: shards[3].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect(
            "recoverable slot payload should reconstruct from three of four parity-family shares",
        );
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_two_of_four_systematic_gf256_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(17, 9, 83);
    let shards = encode_systematic_gf256_2_of_4_shards(&payload);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [84u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(4, 2),
            share_index: 1,
            share_commitment_hash: [85u8; 32],
            material_bytes: shards[1].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [86u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(4, 2),
            share_index: 3,
            share_commitment_hash: [87u8; 32],
            material_bytes: shards[3].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from two of four gf256 shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_three_of_five_systematic_gf256_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(18, 10, 88);
    let shards = encode_systematic_gf256_3_of_5_shards(&payload);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [89u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(5, 3),
            share_index: 0,
            share_commitment_hash: [90u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [91u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(5, 3),
            share_index: 3,
            share_commitment_hash: [92u8; 32],
            material_bytes: shards[3].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [93u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(5, 3),
            share_index: 4,
            share_commitment_hash: [94u8; 32],
            material_bytes: shards[4].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from three of five gf256 shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_three_of_seven_systematic_gf256_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(19, 11, 95);
    let shards = encode_systematic_gf256_3_of_7_shards(&payload);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [96u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 3),
            share_index: 0,
            share_commitment_hash: [97u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [98u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 3),
            share_index: 3,
            share_commitment_hash: [99u8; 32],
            material_bytes: shards[3].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [100u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 3),
            share_index: 6,
            share_commitment_hash: [101u8; 32],
            material_bytes: shards[6].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from three of seven gf256 shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_four_of_six_systematic_gf256_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(20, 12, 102);
    let shards = encode_systematic_gf256_4_of_6_shards(&payload);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [103u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(6, 4),
            share_index: 0,
            share_commitment_hash: [104u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [105u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(6, 4),
            share_index: 2,
            share_commitment_hash: [106u8; 32],
            material_bytes: shards[2].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [107u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(6, 4),
            share_index: 4,
            share_commitment_hash: [108u8; 32],
            material_bytes: shards[4].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [109u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(6, 4),
            share_index: 5,
            share_commitment_hash: [110u8; 32],
            material_bytes: shards[5].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from four of six gf256 shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn recoverable_slot_payload_v3_reconstructs_from_four_of_seven_systematic_gf256_shares() {
    let (payload, bundle) = build_sample_recoverable_slot_payload_v3(21, 13, 111);
    let shards = encode_systematic_gf256_4_of_7_shards(&payload);
    let materials = vec![
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [112u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 4),
            share_index: 0,
            share_commitment_hash: [113u8; 32],
            material_bytes: shards[0].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [114u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 4),
            share_index: 2,
            share_commitment_hash: [115u8; 32],
            material_bytes: shards[2].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [116u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 4),
            share_index: 4,
            share_commitment_hash: [117u8; 32],
            material_bytes: shards[4].clone(),
        },
        RecoveryShareMaterial {
            height: payload.height,
            witness_manifest_hash: [118u8; 32],
            block_commitment_hash: payload.block_commitment_hash,
            coding: gf256_recovery_coding(7, 4),
            share_index: 6,
            share_commitment_hash: [119u8; 32],
            material_bytes: shards[6].clone(),
        },
    ];

    let reconstructed = recover_recoverable_slot_payload_v3_from_share_materials(&materials)
        .expect("recoverable slot payload should reconstruct from four of seven gf256 shares");
    assert_eq!(reconstructed, payload);

    let (recovered_payload, recovered_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("publication bundle should reconstruct");
    assert_eq!(recovered_payload, payload);
    assert_eq!(recovered_bundle, bundle);
}

#[test]
fn coded_recovery_family_contract_conformance_holds_across_supported_families() {
    for (height, view, seed, coding) in [
        (30, 14, 0x41, xor_recovery_coding(3, 2)),
        (31, 15, 0x47, xor_recovery_coding(4, 3)),
        (32, 16, 0x53, gf256_recovery_coding(4, 2)),
        (33, 17, 0x59, gf256_recovery_coding(5, 3)),
        (34, 18, 0x61, gf256_recovery_coding(7, 3)),
        (35, 19, 0x67, gf256_recovery_coding(7, 4)),
    ] {
        assert_coded_recovery_family_contract_conformance_case(height, view, seed, coding);
    }
}

