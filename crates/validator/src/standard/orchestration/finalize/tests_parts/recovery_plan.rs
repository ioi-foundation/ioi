#[test]
fn experimental_recovery_scaffold_changes_with_witness_manifest() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let scaffold_a = build_experimental_recovery_scaffold_artifacts(&header, &[], [0x41u8; 32], 0)
        .expect("scaffold a");
    let scaffold_b = build_experimental_recovery_scaffold_artifacts(&header, &[], [0x42u8; 32], 0)
        .expect("scaffold b");

    assert_eq!(
        scaffold_a.capsule.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        scaffold_b.capsule.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_ne!(scaffold_a.capsule, scaffold_b.capsule);
    assert_ne!(
        scaffold_a.capsule.coding_root_hash,
        scaffold_b.capsule.coding_root_hash
    );
    assert_ne!(
        scaffold_a.share_commitment_hash,
        scaffold_b.share_commitment_hash
    );
    assert_eq!(
        scaffold_a.capsule.coding.family,
        RecoveryCodingFamily::DeterministicScaffoldV1
    );
    assert_eq!(scaffold_a.capsule.coding.recovery_threshold, 1);
}

#[test]
fn experimental_multi_witness_recovery_plan_changes_with_membership() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let plan_a = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]]),
        0,
        3,
        2,
    )
    .expect("plan a");
    let plan_b = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &sample_guardian_witness_set(vec![[0x31u8; 32], [0x32u8; 32], [0x34u8; 32]]),
        0,
        3,
        2,
    )
    .expect("plan b");

    assert_eq!(
        plan_a.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        plan_a.payload_commitment_hash,
        plan_b.payload_commitment_hash
    );
    assert_ne!(
        plan_a.recovery_committee_root_hash,
        plan_b.recovery_committee_root_hash
    );
    assert_ne!(plan_a.coding_root_hash, plan_b.coding_root_hash);
    assert_ne!(
        plan_a
            .shares
            .iter()
            .map(|share| share.assignment.manifest_hash)
            .collect::<Vec<_>>(),
        plan_b
            .shares
            .iter()
            .map(|share| share.assignment.manifest_hash)
            .collect::<Vec<_>>()
    );
}

#[test]
fn experimental_multi_witness_recovery_plan_changes_with_threshold() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let certificate = build_committed_surface_canonical_order_certificate(&header, &[])
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x41u8; 32], [0x42u8; 32], [0x43u8; 32], [0x44u8; 32]]);
    let threshold_two = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("threshold two plan");
    let threshold_three = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("threshold three plan");

    assert_eq!(
        threshold_two.payload_commitment_hash,
        certificate
            .bulletin_availability_certificate
            .recoverability_root
    );
    assert_eq!(
        threshold_two.payload_commitment_hash,
        threshold_three.payload_commitment_hash
    );
    assert_eq!(threshold_two.share_count, threshold_three.share_count);
    assert_eq!(
        threshold_two.coding,
        gf256_recovery_coding(
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
    );
    assert_eq!(
        threshold_three.coding,
        xor_recovery_coding(
            sample_parity_family_share_count(),
            sample_parity_family_recovery_threshold(),
        )
    );
    assert_ne!(
        threshold_two.recovery_threshold,
        threshold_three.recovery_threshold
    );
    assert_ne!(
        threshold_two.coding_root_hash,
        threshold_three.coding_root_hash
    );
    assert_ne!(
        threshold_two
            .shares
            .iter()
            .map(|share| share.share_commitment_hash)
            .collect::<Vec<_>>(),
        threshold_three
            .shares
            .iter()
            .map(|share| share.share_commitment_hash)
            .collect::<Vec<_>>()
    );
}

#[test]
fn experimental_multi_witness_recovery_plan_rejects_threshold_one() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let error = build_experimental_multi_witness_recovery_plan(
        &header,
        &[],
        &sample_guardian_witness_seed(),
        &sample_guardian_witness_set(vec![[0x51u8; 32], [0x52u8; 32]]),
        0,
        2,
        1,
    )
    .expect_err("threshold-one plan should be rejected");

    assert!(
        error
            .to_string()
            .contains("requires threshold at least two"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x51);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x61u8; 32], [0x62u8; 32], [0x63u8; 32], [0x64u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_2_of_4_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_2_of_4_share_count(),
                sample_gf256_2_of_4_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_three_of_five_gf256()
{
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5b);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x91u8; 32],
        [0x92u8; 32],
        [0x93u8; 32],
        [0x94u8; 32],
        [0x95u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_5_share_count(),
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_3_of_5_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_3_of_5_share_count(),
                sample_gf256_3_of_5_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_six_gf256() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xc1u8; 32],
        [0xc2u8; 32],
        [0xc3u8; 32],
        [0xc4u8; 32],
        [0xc5u8; 32],
        [0xc6u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_6_share_count(),
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_4_of_6_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_6_share_count(),
                sample_gf256_4_of_6_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_builds_and_verifies_for_four_of_seven_gf256()
{
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x61);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xf1u8; 32],
        [0xf2u8; 32],
        [0xf3u8; 32],
        [0xf4u8; 32],
        [0xf5u8; 32],
        [0xf6u8; 32],
        [0xf7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_7_share_count(),
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("share materials");

    assert_eq!(
        materials.len(),
        usize::from(sample_gf256_4_of_7_share_count())
    );
    let expected_block_commitment_hash =
        canonical_block_commitment_hash(&header).expect("block commitment hash");
    for (expected_index, material) in materials.iter().enumerate() {
        assert_eq!(material.height, header.height);
        assert_eq!(
            material.block_commitment_hash,
            expected_block_commitment_hash
        );
        assert_eq!(
            material.coding,
            gf256_recovery_coding(
                sample_gf256_4_of_7_share_count(),
                sample_gf256_4_of_7_recovery_threshold(),
            )
        );
        assert_eq!(usize::from(material.share_index), expected_index);
        assert!(!material.material_bytes.is_empty());

        let receipt = verify_experimental_multi_witness_recovery_share_material(
            &header,
            &transactions,
            &witness_seed,
            &witness_set,
            0,
            material,
        )
        .expect("share material should verify");
        assert_eq!(receipt, material.to_recovery_share_receipt());
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_four_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x52);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x64u8; 32], [0x65u8; 32], [0x66u8; 32], [0x67u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_parity_family_share_count(),
        sample_parity_family_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[3].clone(),
    ])
    .expect("payload should reconstruct from three of four parity-family shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_two_of_four_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5a);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x71u8; 32], [0x72u8; 32], [0x73u8; 32], [0x74u8; 32]]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[1].clone(),
        materials[3].clone(),
    ])
    .expect("payload should reconstruct from two of four gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_five_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5c);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xa1u8; 32],
        [0xa2u8; 32],
        [0xa3u8; 32],
        [0xa4u8; 32],
        [0xa5u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_5_share_count(),
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[3].clone(),
        materials[4].clone(),
    ])
    .expect("payload should reconstruct from three of five gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_three_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xb1u8; 32],
        [0xb2u8; 32],
        [0xb3u8; 32],
        [0xb4u8; 32],
        [0xb5u8; 32],
        [0xb6u8; 32],
        [0xb7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[3].clone(),
        materials[6].clone(),
    ])
    .expect("payload should reconstruct from three of seven gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_full_positive_close_surface_from_three_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5e);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xc1u8; 32],
        [0xc2u8; 32],
        [0xc3u8; 32],
        [0xc4u8; 32],
        [0xc5u8; 32],
        [0xc6u8; 32],
        [0xc7u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let support_materials = [
        materials[0].clone(),
        materials[3].clone(),
        materials[6].clone(),
    ];
    let (recovered_payload, recovered_bundle, recovered_close) =
        recover_canonical_order_artifact_surface_from_share_materials(&support_materials).expect(
            "full positive close surface should reconstruct from three of seven gf256 shards",
        );
    let (recovered_full_surface, _, _, recovered_surface_entries) =
        recover_full_canonical_order_surface_from_share_materials(&support_materials).expect(
            "full extractable bulletin surface should reconstruct from three of seven gf256 shards",
        );
    let expected_payload = build_recoverable_slot_payload_v4(&header, &transactions, &certificate)
        .expect("recoverable payload v4");
    let expected_full_surface =
        build_recoverable_slot_payload_v5(&header, &transactions, &certificate)
            .expect("recoverable payload v5");
    let expected_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&expected_payload.canonical_order_publication_bundle_bytes)
            .expect("decode expected publication bundle");
    let expected_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&expected_bundle)
            .expect("verify expected publication bundle");
    let expected_surface = expected_bundle.bulletin_entries.clone();
    let recovered_object = build_recovered_publication_bundle(&support_materials)
        .expect("recovered publication bundle object");

    assert_eq!(recovered_payload, expected_payload);
    assert_eq!(recovered_full_surface, expected_full_surface);
    assert_eq!(recovered_bundle, expected_bundle);
    assert_eq!(recovered_close, expected_close);
    assert_eq!(recovered_surface_entries, expected_surface);
    assert_eq!(
        recovered_object.recoverable_slot_payload_hash,
        canonical_recoverable_slot_payload_v4_hash(&expected_payload)
            .expect("recoverable payload v4 hash")
    );
    assert_eq!(
        recovered_object.recoverable_full_surface_hash,
        canonical_recoverable_slot_payload_v5_hash(&expected_full_surface)
            .expect("recoverable payload v5 hash")
    );
    assert_eq!(
        recovered_object.canonical_bulletin_close_hash,
        canonical_bulletin_close_hash(&expected_close).expect("canonical bulletin close hash")
    );
}

#[test]
fn experimental_multi_witness_recovery_recovered_surfaces_chain_publication_frontiers_across_two_slots(
) {
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xe1u8; 32],
        [0xe2u8; 32],
        [0xe3u8; 32],
        [0xe4u8; 32],
        [0xe5u8; 32],
        [0xe6u8; 32],
        [0xe7u8; 32],
    ]);

    let mut base_header_a = sample_block_header();
    base_header_a.height = 1;
    base_header_a.timestamp += 1;
    base_header_a.timestamp_ms += 1_000;
    let (header_a, transactions_a) =
        sample_block_header_with_ordered_transactions_from_header(base_header_a, 0x64);
    let materials_a = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("slot-a share materials");
    let support_a = [
        materials_a[0].clone(),
        materials_a[3].clone(),
        materials_a[6].clone(),
    ];
    let (recovered_surface_a, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_a)
            .expect("slot-a recovered full extractable surface");
    let recovered_header_a = recovered_publication_frontier_header(&recovered_surface_a);
    let frontier_a = build_publication_frontier(&recovered_header_a, None)
        .expect("slot-a recovered publication frontier");
    ioi_types::app::verify_publication_frontier(&recovered_header_a, &frontier_a, None)
        .expect("slot-a recovered publication frontier should verify");

    let mut base_header_b = sample_block_header();
    base_header_b.height = header_a.height + 1;
    base_header_b.view = header_a.view + 1;
    base_header_b.parent_hash =
        canonical_block_commitment_hash(&header_a).expect("slot-a block commitment hash");
    base_header_b.parent_state_root = header_a.state_root.clone();
    base_header_b.timestamp = header_a.timestamp + 1;
    base_header_b.timestamp_ms = header_a.timestamp_ms + 1_000;
    base_header_b.parent_qc.height = header_a.height;
    base_header_b.parent_qc.view = header_a.view;
    base_header_b.parent_qc.block_hash = base_header_b.parent_hash;
    let (header_b, transactions_b) =
        sample_block_header_with_ordered_transactions_from_header(base_header_b, 0x65);
    let materials_b = build_experimental_multi_witness_recovery_share_materials(
        &header_b,
        &transactions_b,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_3_of_7_share_count(),
        sample_gf256_3_of_7_recovery_threshold(),
    )
    .expect("slot-b share materials");
    let support_b = [
        materials_b[0].clone(),
        materials_b[3].clone(),
        materials_b[6].clone(),
    ];
    let (recovered_surface_b, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&support_b)
            .expect("slot-b recovered full extractable surface");
    let recovered_header_b = recovered_publication_frontier_header(&recovered_surface_b);
    let frontier_b = build_publication_frontier(&recovered_header_b, Some(&frontier_a))
        .expect("slot-b recovered publication frontier");
    ioi_types::app::verify_publication_frontier(
        &recovered_header_b,
        &frontier_b,
        Some(&frontier_a),
    )
    .expect("slot-b recovered publication frontier should verify");

    assert_eq!(frontier_a.height, 1);
    assert_eq!(frontier_a.parent_frontier_hash, [0u8; 32]);
    assert_eq!(frontier_b.height, 2);
    assert_eq!(frontier_b.counter, frontier_a.counter + 1);
    assert_eq!(
        frontier_b.parent_frontier_hash,
        ioi_types::app::canonical_publication_frontier_hash(&frontier_a)
            .expect("slot-a publication frontier hash")
    );
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_six_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5f);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xd1u8; 32],
        [0xd2u8; 32],
        [0xd3u8; 32],
        [0xd4u8; 32],
        [0xd5u8; 32],
        [0xd6u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_6_share_count(),
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[4].clone(),
        materials[5].clone(),
    ])
    .expect("payload should reconstruct from four of six gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_reconstructs_publication_bundle_payload_from_four_of_seven_gf256_shards(
) {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x62);
    let certificate = build_committed_surface_canonical_order_certificate(&header, &transactions)
        .expect("canonical order certificate");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x11u8; 32],
        [0x12u8; 32],
        [0x13u8; 32],
        [0x14u8; 32],
        [0x15u8; 32],
        [0x16u8; 32],
        [0x17u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &transactions,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_4_of_7_share_count(),
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("share materials");

    let recovered = recover_recoverable_slot_payload_v3_from_share_materials(&[
        materials[0].clone(),
        materials[2].clone(),
        materials[4].clone(),
        materials[6].clone(),
    ])
    .expect("payload should reconstruct from four of seven gf256 shards");
    let expected_payload = build_recoverable_slot_payload_v3(&header, &transactions, &certificate)
        .expect("recoverable payload");
    let expected_transaction_bytes = transactions
        .iter()
        .map(|transaction| codec::to_bytes_canonical(transaction).expect("transaction bytes"))
        .collect::<Vec<_>>();
    let recovered_bundle: CanonicalOrderPublicationBundle =
        codec::from_bytes_canonical(&recovered.canonical_order_publication_bundle_bytes)
            .expect("decode recovered publication bundle");
    let rebuilt_close =
        ioi_types::app::verify_canonical_order_publication_bundle(&recovered_bundle)
            .expect("verify recovered publication bundle");

    assert_eq!(recovered.height, header.height);
    assert_eq!(recovered.view, header.view);
    assert_eq!(recovered.producer_account_id, header.producer_account_id);
    assert_eq!(
        recovered.block_commitment_hash,
        canonical_block_commitment_hash(&header).expect("block commitment hash")
    );
    assert_eq!(recovered.canonical_order_certificate, certificate);
    assert_eq!(
        recovered.ordered_transaction_bytes,
        expected_transaction_bytes
    );
    assert_eq!(
        recovered.canonical_order_publication_bundle_bytes,
        expected_payload.canonical_order_publication_bundle_bytes
    );
    assert_eq!(
        recovered_bundle.canonical_order_certificate,
        expected_payload.canonical_order_certificate
    );
    assert_eq!(rebuilt_close.height, header.height);
}

#[test]
fn experimental_multi_witness_recovery_share_material_commitments_change_with_transaction_bytes() {
    let (header_a, transactions_a) = sample_block_header_with_ordered_transactions(0x53);
    let (header_b, transactions_b) = sample_block_header_with_ordered_transactions(0x54);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x68u8; 32], [0x69u8; 32], [0x6au8; 32], [0x6bu8; 32]]);
    let materials_a = build_experimental_multi_witness_recovery_share_materials(
        &header_a,
        &transactions_a,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials a");
    let materials_b = build_experimental_multi_witness_recovery_share_materials(
        &header_b,
        &transactions_b,
        &witness_seed,
        &witness_set,
        0,
        sample_gf256_2_of_4_share_count(),
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("share materials b");

    let commitments_a = materials_a
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let commitments_b = materials_b
        .iter()
        .map(|material| material.share_commitment_hash)
        .collect::<Vec<_>>();
    let shard_bytes_a = materials_a
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();
    let shard_bytes_b = materials_b
        .iter()
        .map(|material| material.material_bytes.clone())
        .collect::<Vec<_>>();

    assert_ne!(commitments_a, commitments_b);
    assert_ne!(shard_bytes_a, shard_bytes_b);
}

