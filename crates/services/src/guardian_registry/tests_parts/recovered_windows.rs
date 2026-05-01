#[test]
fn publishing_recovery_share_material_round_trips_after_matching_receipt() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(71);
    let witness_manifest_hash = [17u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [18u8; 32]);
    let material = RecoveryShareMaterial {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [19u8; 32],
        coding: xor_recovery_coding(3, 2),
        share_index: 0,
        share_commitment_hash: certificate.share_commitment_hash,
        material_bytes: vec![0xaa, 0xbb, 0xcc],
    };
    let receipt = material.to_recovery_share_receipt();

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt).unwrap(),
            ),
            (
                "publish_aft_recovery_share_material@v1",
                codec::to_bytes_canonical(&material).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_share_materials(
            &state,
            capsule.height,
            &witness_manifest_hash,
        )
        .unwrap(),
        vec![material.clone()]
    );
    assert!(state
        .get(&aft_recovery_share_material_key(
            capsule.height,
            &witness_manifest_hash,
            &material.block_commitment_hash,
        ))
        .unwrap()
        .is_some());
}

#[test]
fn publishing_recovered_publication_bundle_round_trips_after_two_public_reveals() {
    let registry = production_registry();
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture(80, 90);
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let (expected_full_surface, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials)
            .expect("reconstruct recovered full extractable surface");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x97);
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&capsule).unwrap(),
            ctx,
        ))
        .unwrap();
        for certificate in &certificates {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_witness_certificate@v1",
                &codec::to_bytes_canonical(certificate).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for material in &materials {
            let receipt = material.to_recovery_share_receipt();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_receipt@v1",
                &codec::to_bytes_canonical(&receipt).unwrap(),
                ctx,
            ))
            .unwrap();
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovery_share_material@v1",
                &codec::to_bytes_canonical(material).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovered_publication_bundle@v1",
            &codec::to_bytes_canonical(&recovered).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_eq!(
        GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
        Some(expected_bundle.bulletin_commitment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height).unwrap(),
        Some(expected_bundle.bulletin_availability_certificate.clone())
    );
    assert_eq!(
        GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
        Some(expected_close)
    );
    assert_eq!(
        recovered.canonical_bulletin_close_hash,
        canonical_bulletin_close_hash(
            &GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
                .unwrap()
                .expect("persisted bulletin close"),
        )
        .expect("persisted bulletin close hash")
    );
    assert_eq!(
        recovered.recoverable_full_surface_hash,
        canonical_recoverable_slot_payload_v5_hash(&expected_full_surface)
            .expect("recoverable payload v5 hash")
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
        Some(expected_surface)
    );
    assert_eq!(
        GuardianRegistry::load_recovered_publication_bundles(
            &state,
            recovered.height,
            &recovered.block_commitment_hash,
        )
        .unwrap(),
        vec![recovered.clone()]
    );
    assert!(state
        .get(
            &aft_recovered_publication_bundle_key(
                recovered.height,
                &recovered.block_commitment_hash,
                &recovered.supporting_witness_manifest_hashes,
            )
            .unwrap(),
        )
        .unwrap()
        .is_some());
}

#[test]
fn publishing_recovered_publication_bundles_for_two_consecutive_slots_supports_recovered_only_frontier_chain(
) {
    let registry = production_registry();
    let (capsule_a, certificates_a, materials_a, recovered_a) =
        sample_recovered_publication_bundle_fixture_3_of_7(1, 0xa1);
    let (capsule_b, certificates_b, materials_b, recovered_b) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
            2,
            0xa2,
            recovered_a.block_commitment_hash,
        );
    let (full_surface_a, _, _, surface_a) =
        recover_full_canonical_order_surface_from_share_materials(&materials_a)
            .expect("slot-a recovered full surface");
    let (full_surface_b, _, _, surface_b) =
        recover_full_canonical_order_surface_from_share_materials(&materials_b)
            .expect("slot-b recovered full surface");
    let header_a = recovered_publication_frontier_header(&full_surface_a);
    let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
        .expect("slot-a recovered frontier");
    let header_b = recovered_publication_frontier_header(&full_surface_b);
    let frontier_b = ioi_types::app::build_publication_frontier(&header_b, Some(&frontier_a))
        .expect("slot-b recovered frontier");

    let mut state = MockState::default();
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_a,
        &certificates_a,
        &materials_a,
        &recovered_a,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_b,
        &certificates_b,
        &materials_b,
        &recovered_b,
    );
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&frontier_a).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&frontier_b).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    ioi_types::app::verify_publication_frontier(&header_a, &frontier_a, None)
        .expect("slot-a recovered frontier should verify");
    ioi_types::app::verify_publication_frontier(&header_b, &frontier_b, Some(&frontier_a))
        .expect("slot-b recovered frontier should verify");
    assert_eq!(
        frontier_b.parent_frontier_hash,
        ioi_types::app::canonical_publication_frontier_hash(&frontier_a)
            .expect("slot-a frontier hash")
    );
    assert_eq!(
        GuardianRegistry::load_publication_frontier(&state, 1).unwrap(),
        Some(frontier_a)
    );
    assert_eq!(
        GuardianRegistry::load_publication_frontier(&state, 2).unwrap(),
        Some(frontier_b)
    );
    assert!(
        GuardianRegistry::load_publication_frontier_contradiction(&state, 1)
            .unwrap()
            .is_none()
    );
    assert!(
        GuardianRegistry::load_publication_frontier_contradiction(&state, 2)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, 1).unwrap(),
        Some(surface_a)
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, 2).unwrap(),
        Some(surface_b)
    );
}

#[test]
fn publishing_recovered_publication_window_with_middle_omission_abort_supports_recovered_only_bulletin_sequence(
) {
    let registry = production_registry_without_accountable_membership_updates();
    let offender = AccountId([0x91u8; 32]);
    let omission_tx_hash = [0xa7u8; 32];
    let (capsule_a, certificates_a, materials_a, recovered_a) =
        sample_recovered_publication_bundle_fixture_3_of_7(1, 0xb1);
    let (capsule_b, certificates_b, materials_b, recovered_b) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
            2,
            0xb2,
            recovered_a.block_commitment_hash,
            offender,
            omission_tx_hash,
        );
    let (capsule_c, certificates_c, materials_c, recovered_c) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
            3,
            0xb3,
            recovered_b.block_commitment_hash,
        );
    let (full_surface_a, _, _, surface_a) =
        recover_full_canonical_order_surface_from_share_materials(&materials_a)
            .expect("slot-a recovered full surface");
    let (full_surface_b, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_b)
            .expect("slot-b recovered full surface");
    let (full_surface_c, _, _, surface_c) =
        recover_full_canonical_order_surface_from_share_materials(&materials_c)
            .expect("slot-c recovered full surface");
    let (_, recovered_bundle_b) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials_b)
            .expect("slot-b recovered publication bundle");
    let omission_b = recovered_bundle_b
        .canonical_order_certificate
        .omission_proofs
        .first()
        .cloned()
        .expect("slot-b recovered omission proof");
    let mut surface_b = recovered_bundle_b.bulletin_entries.clone();
    surface_b.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));
    let header_a = recovered_publication_frontier_header(&full_surface_a);
    let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
        .expect("slot-a recovered frontier");
    let header_c = recovered_publication_frontier_header(&full_surface_c);
    let frontier_c = ioi_types::app::build_publication_frontier(&header_c, Some(&frontier_a))
        .expect("slot-c recovered frontier");
    let close_a = canonical_bulletin_close_from_recovered_surface(&full_surface_a);
    let close_b = canonical_bulletin_close_from_recovered_surface(&full_surface_b);
    let close_c = canonical_bulletin_close_from_recovered_surface(&full_surface_c);
    let expected_collapse_a =
        derive_canonical_collapse_object_from_recovered_surface(&full_surface_a, &close_a, None)
            .expect("slot-a recovered collapse");
    let expected_collapse_b = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_b,
        &close_b,
        Some(&expected_collapse_a),
    )
    .expect("slot-b recovered collapse");
    let expected_collapse_c = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_c,
        &close_c,
        Some(&expected_collapse_b),
    )
    .expect("slot-c recovered collapse");

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_a,
        &certificates_a,
        &materials_a,
        &recovered_a,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_b,
        &certificates_b,
        &materials_b,
        &recovered_b,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_c,
        &certificates_c,
        &materials_c,
        &recovered_c,
    );
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&frontier_a).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_publication_frontier@v1",
            &codec::to_bytes_canonical(&frontier_c).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    ioi_types::app::verify_publication_frontier(&header_a, &frontier_a, None)
        .expect("slot-a recovered frontier should verify");

    let slot_b_abort = GuardianRegistry::load_canonical_order_abort(&state, 2)
        .unwrap()
        .expect("slot-b recovered omission should materialize an abort");
    assert_eq!(
        slot_b_abort.reason,
        CanonicalOrderAbortReason::OmissionDominated
    );
    assert_eq!(
        GuardianRegistry::load_canonical_bulletin_close(&state, 1).unwrap(),
        Some(close_a.clone())
    );
    assert_eq!(
        GuardianRegistry::load_canonical_bulletin_close(&state, 2).unwrap(),
        None
    );
    assert_eq!(
        GuardianRegistry::load_canonical_bulletin_close(&state, 3).unwrap(),
        Some(close_c.clone())
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, 1).unwrap(),
        Some(surface_a)
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, 2).unwrap(),
        None
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, 3).unwrap(),
        Some(surface_c)
    );
    assert_eq!(
        GuardianRegistry::load_bulletin_surface_entries(&state, 2).unwrap(),
        surface_b
    );
    let stored_omission: OmissionProof = codec::from_bytes_canonical(
        &state
            .get(&aft_omission_proof_key(
                omission_b.height,
                &omission_b.tx_hash,
            ))
            .unwrap()
            .expect("slot-b omission proof stored"),
    )
    .unwrap();
    assert_eq!(stored_omission, omission_b);
    assert_eq!(
        GuardianRegistry::load_publication_frontier(&state, 1).unwrap(),
        Some(frontier_a.clone())
    );
    assert_eq!(
        GuardianRegistry::load_publication_frontier(&state, 2).unwrap(),
        None
    );
    assert_eq!(
        GuardianRegistry::load_publication_frontier(&state, 3).unwrap(),
        Some(frontier_c.clone())
    );
    assert_eq!(
        GuardianRegistry::load_canonical_collapse_object(&state, 1).unwrap(),
        Some(expected_collapse_a.clone())
    );
    assert_eq!(
        GuardianRegistry::load_canonical_collapse_object(&state, 2).unwrap(),
        Some(expected_collapse_b.clone())
    );
    assert_eq!(
        GuardianRegistry::load_canonical_collapse_object(&state, 3).unwrap(),
        Some(expected_collapse_c.clone())
    );
    assert_eq!(
        expected_collapse_b.previous_canonical_collapse_commitment_hash,
        ioi_types::app::canonical_collapse_commitment_hash_from_object(&expected_collapse_a)
            .expect("slot-a canonical collapse commitment")
    );
    assert_eq!(
        expected_collapse_c.previous_canonical_collapse_commitment_hash,
        ioi_types::app::canonical_collapse_commitment_hash_from_object(&expected_collapse_b)
            .expect("slot-b canonical collapse commitment")
    );
    assert_eq!(
        frontier_c.parent_frontier_hash,
        canonical_publication_frontier_hash(&frontier_a).expect("slot-a publication frontier hash")
    );
    assert!(
        GuardianRegistry::load_publication_frontier_contradiction(&state, 1)
            .unwrap()
            .is_none()
    );
    assert!(
        GuardianRegistry::load_publication_frontier_contradiction(&state, 2)
            .unwrap()
            .is_none()
    );
    assert!(
        GuardianRegistry::load_publication_frontier_contradiction(&state, 3)
            .unwrap()
            .is_none()
    );
}

#[test]
fn extracting_recovered_only_replay_prefix_matches_durable_mixed_window_surface() {
    let registry = production_registry_without_accountable_membership_updates();
    let offender = AccountId([0x81u8; 32]);
    let omission_tx_hash = [0xc7u8; 32];
    let (capsule_a, certificates_a, materials_a, recovered_a) =
        sample_recovered_publication_bundle_fixture_3_of_7(1, 0xc1);
    let (capsule_b, certificates_b, materials_b, recovered_b) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent_and_omission(
            2,
            0xc2,
            recovered_a.block_commitment_hash,
            offender,
            omission_tx_hash,
        );
    let (capsule_c, certificates_c, materials_c, recovered_c) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
            3,
            0xc3,
            recovered_b.block_commitment_hash,
        );
    let (capsule_d, certificates_d, materials_d, recovered_d) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
            4,
            0xc4,
            recovered_c.block_commitment_hash,
        );
    let (capsule_e, certificates_e, materials_e, recovered_e) =
        sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
            5,
            0xc5,
            recovered_d.block_commitment_hash,
        );
    let (full_surface_a, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_a)
            .expect("slot-a recovered full surface");
    let (full_surface_b, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_b)
            .expect("slot-b recovered full surface");
    let (full_surface_c, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_c)
            .expect("slot-c recovered full surface");
    let (full_surface_d, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_d)
            .expect("slot-d recovered full surface");
    let (full_surface_e, _, _, _) =
        recover_full_canonical_order_surface_from_share_materials(&materials_e)
            .expect("slot-e recovered full surface");
    let header_a = recovered_publication_frontier_header(&full_surface_a);
    let frontier_a = ioi_types::app::build_publication_frontier(&header_a, None)
        .expect("slot-a recovered frontier");
    let header_c = recovered_publication_frontier_header(&full_surface_c);
    let frontier_c = ioi_types::app::build_publication_frontier(&header_c, Some(&frontier_a))
        .expect("slot-c recovered frontier");
    let header_d = recovered_publication_frontier_header(&full_surface_d);
    let frontier_d = ioi_types::app::build_publication_frontier(&header_d, Some(&frontier_c))
        .expect("slot-d recovered frontier");
    let header_e = recovered_publication_frontier_header(&full_surface_e);
    let frontier_e = ioi_types::app::build_publication_frontier(&header_e, Some(&frontier_d))
        .expect("slot-e recovered frontier");
    let close_a = canonical_bulletin_close_from_recovered_surface(&full_surface_a);
    let close_b = canonical_bulletin_close_from_recovered_surface(&full_surface_b);
    let close_c = canonical_bulletin_close_from_recovered_surface(&full_surface_c);
    let close_d = canonical_bulletin_close_from_recovered_surface(&full_surface_d);
    let close_e = canonical_bulletin_close_from_recovered_surface(&full_surface_e);
    let expected_collapse_a =
        derive_canonical_collapse_object_from_recovered_surface(&full_surface_a, &close_a, None)
            .expect("slot-a recovered collapse");
    let expected_collapse_b = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_b,
        &close_b,
        Some(&expected_collapse_a),
    )
    .expect("slot-b recovered collapse");
    let expected_collapse_c = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_c,
        &close_c,
        Some(&expected_collapse_b),
    )
    .expect("slot-c recovered collapse");
    let expected_collapse_d = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_d,
        &close_d,
        Some(&expected_collapse_c),
    )
    .expect("slot-d recovered collapse");
    let expected_collapse_e = derive_canonical_collapse_object_from_recovered_surface(
        &full_surface_e,
        &close_e,
        Some(&expected_collapse_d),
    )
    .expect("slot-e recovered collapse");

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_a,
        &certificates_a,
        &materials_a,
        &recovered_a,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_b,
        &certificates_b,
        &materials_b,
        &recovered_b,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_c,
        &certificates_c,
        &materials_c,
        &recovered_c,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_d,
        &certificates_d,
        &materials_d,
        &recovered_d,
    );
    publish_recovered_publication_fixture(
        &registry,
        &mut state,
        &capsule_e,
        &certificates_e,
        &materials_e,
        &recovered_e,
    );
    with_ctx(|ctx| {
        for frontier in [&frontier_a, &frontier_c, &frontier_d, &frontier_e] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_publication_frontier@v1",
                &codec::to_bytes_canonical(frontier).unwrap(),
                ctx,
            ))
            .unwrap();
        }
    });

    let slot_b_abort = GuardianRegistry::load_canonical_order_abort(&state, 2)
        .unwrap()
        .expect("slot-b omission should materialize an abort");
    let replay_prefix = GuardianRegistry::extract_canonical_replay_prefix(&state, 1, 5)
        .expect("extract canonical replay prefix");
    let expected_prefix = vec![
        canonical_replay_prefix_entry(
            &expected_collapse_a,
            Some(recovered_a.block_commitment_hash),
            Some(recovered_a.parent_block_commitment_hash),
            canonical_bulletin_close_hash(&close_a).expect("slot-a close hash"),
            Some(
                canonical_publication_frontier_hash(&frontier_a)
                    .expect("slot-a publication frontier hash"),
            ),
            true,
        )
        .expect("slot-a replay prefix entry"),
        canonical_replay_prefix_entry(
            &expected_collapse_b,
            Some(recovered_b.block_commitment_hash),
            Some(recovered_b.parent_block_commitment_hash),
            canonical_order_abort_hash(&slot_b_abort).expect("slot-b abort hash"),
            None,
            false,
        )
        .expect("slot-b replay prefix entry"),
        canonical_replay_prefix_entry(
            &expected_collapse_c,
            Some(recovered_c.block_commitment_hash),
            Some(recovered_c.parent_block_commitment_hash),
            canonical_bulletin_close_hash(&close_c).expect("slot-c close hash"),
            Some(
                canonical_publication_frontier_hash(&frontier_c)
                    .expect("slot-c publication frontier hash"),
            ),
            true,
        )
        .expect("slot-c replay prefix entry"),
        canonical_replay_prefix_entry(
            &expected_collapse_d,
            Some(recovered_d.block_commitment_hash),
            Some(recovered_d.parent_block_commitment_hash),
            canonical_bulletin_close_hash(&close_d).expect("slot-d close hash"),
            Some(
                canonical_publication_frontier_hash(&frontier_d)
                    .expect("slot-d publication frontier hash"),
            ),
            true,
        )
        .expect("slot-d replay prefix entry"),
        canonical_replay_prefix_entry(
            &expected_collapse_e,
            Some(recovered_e.block_commitment_hash),
            Some(recovered_e.parent_block_commitment_hash),
            canonical_bulletin_close_hash(&close_e).expect("slot-e close hash"),
            Some(
                canonical_publication_frontier_hash(&frontier_e)
                    .expect("slot-e publication frontier hash"),
            ),
            true,
        )
        .expect("slot-e replay prefix entry"),
    ];

    assert_eq!(replay_prefix, expected_prefix);
    assert_eq!(
        replay_prefix[0].resulting_state_root_hash,
        expected_collapse_a.resulting_state_root_hash
    );
    assert_eq!(
        replay_prefix[1].resulting_state_root_hash,
        expected_collapse_b.resulting_state_root_hash
    );
    assert_eq!(
        replay_prefix[2].resulting_state_root_hash,
        expected_collapse_c.resulting_state_root_hash
    );
    assert_eq!(
        replay_prefix[3].resulting_state_root_hash,
        expected_collapse_d.resulting_state_root_hash
    );
    assert_eq!(
        replay_prefix[4].resulting_state_root_hash,
        expected_collapse_e.resulting_state_root_hash
    );
    assert!(!replay_prefix[1].extracted_bulletin_surface_present);
    assert!(replay_prefix[0].extracted_bulletin_surface_present);
    assert!(replay_prefix[2].extracted_bulletin_surface_present);
    assert!(replay_prefix[3].extracted_bulletin_surface_present);
    assert!(replay_prefix[4].extracted_bulletin_surface_present);
    assert_eq!(
        replay_prefix[1].previous_canonical_collapse_commitment_hash,
        replay_prefix[0].canonical_collapse_commitment_hash
    );
    assert_eq!(
        replay_prefix[2].previous_canonical_collapse_commitment_hash,
        replay_prefix[1].canonical_collapse_commitment_hash
    );
    assert_eq!(
        replay_prefix[3].previous_canonical_collapse_commitment_hash,
        replay_prefix[2].canonical_collapse_commitment_hash
    );
    assert_eq!(
        replay_prefix[4].previous_canonical_collapse_commitment_hash,
        replay_prefix[3].canonical_collapse_commitment_hash
    );
    assert_eq!(
        replay_prefix[1].parent_block_commitment_hash,
        replay_prefix[0].canonical_block_commitment_hash
    );
    assert_eq!(
        replay_prefix[2].parent_block_commitment_hash,
        replay_prefix[1].canonical_block_commitment_hash
    );
    assert_eq!(
        replay_prefix[3].parent_block_commitment_hash,
        replay_prefix[2].canonical_block_commitment_hash
    );
    assert_eq!(
        replay_prefix[4].parent_block_commitment_hash,
        replay_prefix[3].canonical_block_commitment_hash
    );

    let recovered_header_prefix =
        GuardianRegistry::extract_recovered_canonical_header_prefix(&state, 1, 5)
            .expect("extract recovered canonical header prefix");
    let expected_header_prefix = vec![
        recovered_canonical_header_entry(&expected_collapse_a, &full_surface_a)
            .expect("slot-a recovered header entry"),
        recovered_canonical_header_entry(&expected_collapse_b, &full_surface_b)
            .expect("slot-b recovered header entry"),
        recovered_canonical_header_entry(&expected_collapse_c, &full_surface_c)
            .expect("slot-c recovered header entry"),
        recovered_canonical_header_entry(&expected_collapse_d, &full_surface_d)
            .expect("slot-d recovered header entry"),
        recovered_canonical_header_entry(&expected_collapse_e, &full_surface_e)
            .expect("slot-e recovered header entry"),
    ];

    assert_eq!(recovered_header_prefix, expected_header_prefix);
    assert_eq!(
        recovered_header_prefix[1].parent_block_commitment_hash,
        recovered_header_prefix[0].canonical_block_commitment_hash
    );
    assert_eq!(
        recovered_header_prefix[2].parent_block_commitment_hash,
        recovered_header_prefix[1].canonical_block_commitment_hash
    );
    assert_eq!(
        recovered_header_prefix[3].parent_block_commitment_hash,
        recovered_header_prefix[2].canonical_block_commitment_hash
    );
    assert_eq!(
        recovered_header_prefix[4].parent_block_commitment_hash,
        recovered_header_prefix[3].canonical_block_commitment_hash
    );

    let recovered_certified_prefix =
        GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, 5)
            .expect("extract recovered certified header prefix");
    let expected_certified_prefix =
        recovered_certified_header_prefix(None, &expected_header_prefix)
            .expect("expected recovered certified header prefix");
    assert_eq!(recovered_certified_prefix, expected_certified_prefix);
    assert_eq!(
        recovered_certified_prefix[1]
            .certified_parent_quorum_certificate
            .block_hash,
        recovered_header_prefix[0].canonical_block_commitment_hash
    );
    assert_eq!(
        recovered_certified_prefix[2].certified_parent_resulting_state_root_hash,
        recovered_header_prefix[1].resulting_state_root_hash
    );
    assert_eq!(
        recovered_certified_prefix[4]
            .certified_parent_quorum_certificate
            .block_hash,
        recovered_header_prefix[3].canonical_block_commitment_hash
    );
    assert_eq!(
        recovered_certified_prefix[4].certified_parent_resulting_state_root_hash,
        recovered_header_prefix[3].resulting_state_root_hash
    );

    let recovered_restart_prefix =
        GuardianRegistry::extract_recovered_restart_block_header_prefix(&state, 1, 5)
            .expect("extract recovered restart block-header prefix");
    let expected_restart_prefix = expected_certified_prefix
        .iter()
        .zip([
            &full_surface_a,
            &full_surface_b,
            &full_surface_c,
            &full_surface_d,
            &full_surface_e,
        ])
        .map(|(certified, full_surface)| {
            recovered_restart_block_header_entry(full_surface, certified)
                .expect("expected recovered restart block-header entry")
        })
        .collect::<Vec<_>>();
    assert_eq!(recovered_restart_prefix, expected_restart_prefix);
    assert_eq!(
        recovered_restart_prefix[1].header.parent_qc,
        recovered_certified_prefix[1].certified_parent_quorum_certificate
    );
    assert_eq!(
        recovered_restart_prefix[2].header.parent_state_root.0,
        recovered_certified_prefix[2]
            .certified_parent_resulting_state_root_hash
            .to_vec()
    );
    assert_eq!(
        recovered_restart_prefix[3].header.parent_qc,
        recovered_restart_prefix[2].certified_quorum_certificate()
    );
    assert_eq!(
        recovered_restart_prefix[3].header.parent_state_root.0,
        recovered_certified_prefix[3]
            .certified_parent_resulting_state_root_hash
            .to_vec()
    );
    assert_eq!(
        recovered_restart_prefix[4].header.parent_qc,
        recovered_restart_prefix[3].certified_quorum_certificate()
    );
    assert_eq!(
        recovered_restart_prefix[4].header.parent_state_root.0,
        recovered_certified_prefix[4]
            .certified_parent_resulting_state_root_hash
            .to_vec()
    );

    let aft_recovered_state = GuardianRegistry::extract_aft_recovered_state_surface(&state, 1, 5)
        .expect("extract aft recovered state surface");
    assert_eq!(aft_recovered_state.replay_prefix, expected_prefix);
    assert_eq!(
        aft_recovered_state.consensus_headers,
        expected_header_prefix
    );
    assert_eq!(
        aft_recovered_state.certified_headers,
        expected_certified_prefix
    );
    assert_eq!(aft_recovered_state.restart_headers, expected_restart_prefix);
}
