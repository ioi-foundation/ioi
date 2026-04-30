#[test]
fn experimental_multi_witness_recovery_share_material_coded_family_subset_conformance_holds_across_bounded_geometries(
) {
    for (transaction_seed, manifest_seed, share_count, recovery_threshold) in [
        (0x57, 0x63, 3, 2),
        (0x59, 0x69, 4, 3),
        (0x5a, 0x71, 4, 2),
        (0x5c, 0xa1, 5, 3),
        (0x5d, 0xb1, 7, 3),
        (0x5f, 0xd1, 6, 4),
        (0x62, 0x11, 7, 4),
    ] {
        assert_coded_recovery_family_subset_conformance_case(
            transaction_seed,
            manifest_seed,
            share_count,
            recovery_threshold,
        );
    }
}

#[test]
fn experimental_multi_witness_recovery_share_material_coded_family_commitments_are_deterministic_and_input_sensitive(
) {
    for (
        transaction_seed,
        manifest_seed,
        alternate_manifest_seed,
        share_count,
        recovery_threshold,
    ) in [
        (0x49, 0x52, 0x62, 3, 2),
        (0x4d, 0x56, 0x66, 4, 3),
        (0x53, 0x68, 0x78, 4, 2),
        (0x5d, 0xb1, 0xc1, 7, 3),
        (0x62, 0x11, 0x21, 7, 4),
    ] {
        assert_coded_recovery_family_commitment_determinism_case(
            transaction_seed,
            manifest_seed,
            alternate_manifest_seed,
            share_count,
            recovery_threshold,
        );
    }
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x58);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set =
        sample_guardian_witness_set(vec![[0x81u8; 32], [0x82u8; 32], [0x83u8; 32], [0x84u8; 32]]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_2_of_4_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_2_of_4_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_2_of_4_share_count(),
            sample_gf256_2_of_4_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_2_of_4_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_2_of_4_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_three_of_five_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x5d);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xb1u8; 32],
        [0xb2u8; 32],
        [0xb3u8; 32],
        [0xb4u8; 32],
        [0xb5u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_3_of_5_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_3_of_5_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_3_of_5_share_count(),
            sample_gf256_3_of_5_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_3_of_5_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_3_of_5_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_six_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x60);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0xe1u8; 32],
        [0xe2u8; 32],
        [0xe3u8; 32],
        [0xe4u8; 32],
        [0xe5u8; 32],
        [0xe6u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_4_of_6_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_4_of_6_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_4_of_6_share_count(),
            sample_gf256_4_of_6_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_4_of_6_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_4_of_6_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_binding_assignments_build_for_four_of_seven_gf256_shape() {
    let (header, transactions) = sample_block_header_with_ordered_transactions(0x63);
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x21u8; 32],
        [0x22u8; 32],
        [0x23u8; 32],
        [0x24u8; 32],
        [0x25u8; 32],
        [0x26u8; 32],
        [0x27u8; 32],
    ]);
    let assignments = derive_guardian_witness_assignments(
        &witness_seed,
        &witness_set,
        header.producer_account_id,
        header.height,
        header.view,
        0,
        sample_gf256_4_of_7_share_count(),
    )
    .expect("derive witness assignments");
    let plan = build_experimental_multi_witness_recovery_plan_from_assignments(
        &header,
        &transactions,
        witness_seed.epoch,
        assignments,
        0,
        sample_gf256_4_of_7_recovery_threshold(),
    )
    .expect("build multi-witness recovery plan");
    let (capsule, binding_assignments) =
        build_experimental_multi_witness_recovery_binding_assignments(header.height, &plan)
            .expect("build multi-witness recovery bindings");
    let recovery_capsule_hash =
        canonical_recovery_capsule_hash(&capsule).expect("recovery capsule hash");
    let distinct_manifests = binding_assignments
        .iter()
        .map(|assignment| assignment.witness_manifest_hash)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_share_commitments = binding_assignments
        .iter()
        .map(|assignment| assignment.recovery_binding.share_commitment_hash)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        capsule.coding,
        gf256_recovery_coding(
            sample_gf256_4_of_7_share_count(),
            sample_gf256_4_of_7_recovery_threshold(),
        )
    );
    assert_eq!(
        capsule.coding.recovery_threshold,
        sample_gf256_4_of_7_recovery_threshold()
    );
    assert_eq!(
        binding_assignments.len(),
        usize::from(sample_gf256_4_of_7_share_count())
    );
    assert_eq!(distinct_manifests.len(), binding_assignments.len());
    assert_eq!(distinct_share_commitments.len(), binding_assignments.len());
    assert!(binding_assignments.iter().all(|assignment| {
        assignment.recovery_binding.recovery_capsule_hash == recovery_capsule_hash
    }));
}

#[test]
fn experimental_multi_witness_recovery_share_material_stays_transparent_outside_coded_shapes() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![
        [0x81u8; 32],
        [0x82u8; 32],
        [0x83u8; 32],
        [0x84u8; 32],
        [0x85u8; 32],
    ]);
    let materials = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        5,
        5,
    )
    .expect("share materials");

    assert_eq!(materials.len(), 5);
    assert!(materials.iter().all(|material| {
        material.coding.family == RecoveryCodingFamily::TransparentCommittedSurfaceV1
    }));
}

#[test]
fn experimental_multi_witness_recovery_share_material_rejects_tampered_material_bytes() {
    let mut header = sample_block_header();
    header.transactions_root =
        ioi_types::app::canonical_transaction_root_from_hashes(&[]).expect("transactions root");
    let witness_seed = sample_guardian_witness_seed();
    let witness_set = sample_guardian_witness_set(vec![[0x71u8; 32], [0x72u8; 32], [0x73u8; 32]]);
    let mut material = build_experimental_multi_witness_recovery_share_materials(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        3,
        2,
    )
    .expect("share materials")
    .into_iter()
    .next()
    .expect("first share material");
    material.material_bytes[0] ^= 0xFF;

    let error = verify_experimental_multi_witness_recovery_share_material(
        &header,
        &[],
        &witness_seed,
        &witness_set,
        0,
        &material,
    )
    .expect_err("tampered share material should fail verification");

    assert!(
        error
            .to_string()
            .contains("deterministic committed-surface materialization"),
        "unexpected error: {error:#}"
    );
}

