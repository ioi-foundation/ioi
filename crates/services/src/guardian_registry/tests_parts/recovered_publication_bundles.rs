#[test]
fn publishing_recovered_publication_bundle_rejects_tampered_full_surface_hash() {
    let registry = production_registry();
    let (capsule, certificates, materials, mut recovered) =
        sample_recovered_publication_bundle_fixture(80, 91);
    recovered.recoverable_full_surface_hash[0] ^= 0xFF;

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x91);
    let mut publish_error = None;
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
        publish_error = Some(
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_recovered_publication_bundle@v1",
                &codec::to_bytes_canonical(&recovered).unwrap(),
                ctx,
            ))
            .unwrap_err(),
        );
    });
    let error = publish_error.expect("tampered recovered publication bundle should fail");

    assert!(
        error.to_string().contains("full extractable surface hash"),
        "unexpected error: {error}"
    );
}

#[test]
fn publishing_recovered_publication_bundle_round_trips_after_three_public_reveals() {
    let registry = production_registry();
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_3_of_5(80, 120);
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x92);
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
fn publishing_recovered_publication_bundle_round_trips_after_three_of_seven_public_reveals() {
    let registry = production_registry();
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_3_of_7(80, 130);
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x93);
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
fn publishing_recovered_publication_bundle_round_trips_after_four_public_reveals() {
    let registry = production_registry();
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_4_of_6(80, 140);
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x94);
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
fn publishing_recovered_publication_bundle_round_trips_after_four_of_seven_public_reveals() {
    let registry = production_registry();
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_4_of_7(81, 150);
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x95);
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

    let close = GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height)
        .expect("load canonical bulletin close")
        .expect("canonical bulletin close should exist");
    let surface = GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height)
        .expect("load bulletin surface")
        .expect("bulletin surface should exist");

    assert_eq!(close, expected_close);
    assert_eq!(surface, expected_surface);
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
fn publishing_recovered_publication_bundle_with_omission_proof_materializes_abort_without_membership_updates(
) {
    let registry = production_registry_without_accountable_membership_updates();
    let offender = AccountId([0x91u8; 32]);
    let omission_tx_hash = [0xa7u8; 32];
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_3_of_5_with_omission(
            82,
            160,
            offender,
            omission_tx_hash,
        );
    let (_, expected_bundle) =
        recover_canonical_order_publication_bundle_from_share_materials(&materials)
            .expect("reconstruct recovered publication bundle");
    let expected_close = verified_canonical_bulletin_close_for_bundle(&expected_bundle);
    let omission = expected_bundle
        .canonical_order_certificate
        .omission_proofs
        .first()
        .cloned()
        .expect("recovered omission proof");
    let mut expected_surface = expected_bundle.bulletin_entries.clone();
    expected_surface.sort_unstable_by(|left, right| left.tx_hash.cmp(&right.tx_hash));

    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();
    seed_previous_canonical_collapse_placeholder_if_absent(&mut state, recovered.height, 0x96);

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

    let stored_abort: CanonicalOrderAbort = codec::from_bytes_canonical(
        &state
            .get(&aft_canonical_order_abort_key(recovered.height))
            .unwrap()
            .expect("order abort stored"),
    )
    .unwrap();
    assert_eq!(
        stored_abort.reason,
        CanonicalOrderAbortReason::OmissionDominated
    );
    assert_eq!(
        stored_abort.canonical_order_certificate_hash,
        canonical_order_certificate_hash(&expected_bundle.canonical_order_certificate)
            .expect("canonical order certificate hash")
    );
    assert_eq!(
        stored_abort.bulletin_close_hash,
        canonical_bulletin_close_hash(&expected_close).expect("canonical bulletin close hash")
    );
    assert_eq!(
        GuardianRegistry::load_bulletin_commitment(&state, recovered.height).unwrap(),
        Some(expected_bundle.bulletin_commitment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_bulletin_surface_entries(&state, recovered.height).unwrap(),
        expected_surface
    );
    assert_eq!(
        GuardianRegistry::extract_published_bulletin_surface(&state, recovered.height).unwrap(),
        None
    );
    assert_eq!(
        GuardianRegistry::load_bulletin_availability_certificate(&state, recovered.height).unwrap(),
        None
    );
    assert_eq!(
        GuardianRegistry::load_canonical_bulletin_close(&state, recovered.height).unwrap(),
        None
    );
    assert!(state
        .get(&aft_order_certificate_key(recovered.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_bulletin_availability_certificate_key(recovered.height))
        .unwrap()
        .is_none());
    assert!(state
        .get(&aft_canonical_bulletin_close_key(recovered.height))
        .unwrap()
        .is_none());

    let stored_omission: OmissionProof = codec::from_bytes_canonical(
        &state
            .get(&aft_omission_proof_key(omission.height, &omission.tx_hash))
            .unwrap()
            .expect("omission proof stored"),
    )
    .unwrap();
    assert_eq!(stored_omission, omission);
    assert_eq!(
        GuardianRegistry::load_recovered_publication_bundles(
            &state,
            recovered.height,
            &recovered.block_commitment_hash,
        )
        .unwrap(),
        vec![recovered.clone()]
    );
    assert!(state.get(QUARANTINED_VALIDATORS_KEY).unwrap().is_none());

    let stored_sets = read_validator_sets(
        &state
            .get(VALIDATOR_SET_KEY)
            .unwrap()
            .expect("validator sets stored"),
    )
    .unwrap();
    assert!(stored_sets.next.is_none());
    assert!(stored_sets
        .current
        .validators
        .iter()
        .any(|validator| validator.account_id == offender));

    let evidence_registry: BTreeSet<[u8; 32]> = codec::from_bytes_canonical(
        &state
            .get(EVIDENCE_REGISTRY_KEY)
            .unwrap()
            .expect("evidence registry stored"),
    )
    .unwrap();
    assert_eq!(evidence_registry.len(), 1);
}

#[test]
fn publishing_recovered_publication_bundle_requires_sorted_supporting_witnesses() {
    let registry = production_registry();
    let (capsule, certificates, materials, mut recovered) =
        sample_recovered_publication_bundle_fixture(81, 100);
    recovered.supporting_witness_manifest_hashes.swap(0, 1);

    let mut state = MockState::default();
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
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovered_publication_bundle@v1",
            &codec::to_bytes_canonical(&recovered).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("canonical sorted supporting witness manifests"));
    });
}

#[test]
fn publishing_conflicting_recovered_publication_bundles_materializes_abort() {
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture(82, 110);
    let (_, _, conflicting_materials_template, conflicting_recovered_template) =
        sample_recovered_publication_bundle_fixture(82, 111);
    let conflicting_witnesses = [[201u8; 32], [202u8; 32]];
    let conflicting_share_commitments = [[203u8; 32], [204u8; 32]];
    let conflicting_certificates = conflicting_witnesses
        .iter()
        .zip(conflicting_share_commitments.iter())
        .map(|(witness_manifest_hash, share_commitment_hash)| {
            sample_recovery_witness_certificate(
                &capsule,
                *witness_manifest_hash,
                *share_commitment_hash,
            )
        })
        .collect::<Vec<_>>();
    let conflicting_materials = conflicting_materials_template
        .iter()
        .zip(conflicting_witnesses.iter())
        .zip(conflicting_share_commitments.iter())
        .map(
            |((material, witness_manifest_hash), share_commitment_hash)| RecoveryShareMaterial {
                witness_manifest_hash: *witness_manifest_hash,
                share_commitment_hash: *share_commitment_hash,
                ..material.clone()
            },
        )
        .collect::<Vec<_>>();
    let conflicting_recovered = RecoveredPublicationBundle {
        supporting_witness_manifest_hashes: conflicting_witnesses.to_vec(),
        ..conflicting_recovered_template
    };

    assert_conflicting_recovered_publication_bundles_materialize_abort(
        capsule,
        certificates,
        materials,
        recovered,
        conflicting_certificates,
        conflicting_materials,
        conflicting_recovered,
    );
}

#[test]
fn publishing_conflicting_recovered_publication_bundles_materializes_abort_for_three_of_seven_non_overlap(
) {
    let coding = gf256_recovery_coding(7, 3);
    let (capsule, certificates, materials, recovered) =
        sample_recovered_publication_bundle_fixture_with_scheme(83, 120, coding, &[0, 1, 2]);
    let (_, _, conflicting_materials_template, conflicting_recovered_template) =
        sample_recovered_publication_bundle_fixture_with_scheme(83, 121, coding, &[3, 4, 5]);
    let conflicting_witnesses = [[211u8; 32], [212u8; 32], [213u8; 32]];
    let conflicting_share_commitments = [[214u8; 32], [215u8; 32], [216u8; 32]];
    let conflicting_certificates = conflicting_witnesses
        .iter()
        .zip(conflicting_share_commitments.iter())
        .map(|(witness_manifest_hash, share_commitment_hash)| {
            sample_recovery_witness_certificate(
                &capsule,
                *witness_manifest_hash,
                *share_commitment_hash,
            )
        })
        .collect::<Vec<_>>();
    let conflicting_materials = conflicting_materials_template
        .iter()
        .zip(conflicting_witnesses.iter())
        .zip(conflicting_share_commitments.iter())
        .map(
            |((material, witness_manifest_hash), share_commitment_hash)| RecoveryShareMaterial {
                witness_manifest_hash: *witness_manifest_hash,
                share_commitment_hash: *share_commitment_hash,
                ..material.clone()
            },
        )
        .collect::<Vec<_>>();
    let conflicting_recovered = RecoveredPublicationBundle {
        supporting_witness_manifest_hashes: conflicting_witnesses.to_vec(),
        ..conflicting_recovered_template
    };

    assert_conflicting_recovered_publication_bundles_materialize_abort(
        capsule,
        certificates,
        materials,
        recovered,
        conflicting_certificates,
        conflicting_materials,
        conflicting_recovered,
    );
}

#[test]
fn publishing_conflicting_recovery_capsule_is_rejected() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(79);
    let conflicting = RecoveryCapsule {
        payload_commitment_hash: [0x61u8; 32],
        ..capsule.clone()
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&capsule).unwrap(),
            ctx,
        ))
        .expect("first capsule publish succeeds");

        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&conflicting).unwrap(),
            ctx,
        ))
        .expect_err("conflicting capsule must be rejected");
        assert!(err
            .to_string()
            .contains("conflicting aft recovery capsule already published"));
    });
}

#[test]
fn publishing_recovery_share_receipt_requires_matching_witness_certificate() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(72);
    let witness_manifest_hash = [21u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [22u8; 32]);
    let bad_receipt = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [23u8; 32],
        share_commitment_hash: [24u8; 32],
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&capsule).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_witness_certificate@v1",
            &codec::to_bytes_canonical(&certificate).unwrap(),
            ctx,
        ))
        .unwrap();
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_share_receipt@v1",
            &codec::to_bytes_canonical(&bad_receipt).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must match the witness certificate share commitment"));
    });

    assert!(state
        .get(&aft_recovery_share_receipt_key(
            capsule.height,
            &witness_manifest_hash,
            &bad_receipt.block_commitment_hash,
        ))
        .unwrap()
        .is_none());
}

#[test]
fn publishing_recovery_share_material_requires_matching_receipt() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(72);
    let witness_manifest_hash = [21u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [22u8; 32]);
    let material = RecoveryShareMaterial {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [23u8; 32],
        coding: xor_recovery_coding(3, 2),
        share_index: 1,
        share_commitment_hash: certificate.share_commitment_hash,
        material_bytes: vec![0xdd, 0xee, 0xff],
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_capsule@v1",
            &codec::to_bytes_canonical(&capsule).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_witness_certificate@v1",
            &codec::to_bytes_canonical(&certificate).unwrap(),
            ctx,
        ))
        .unwrap();
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_recovery_share_material@v1",
            &codec::to_bytes_canonical(&material).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("requires a published matching recovery share receipt"));
    });

    assert!(state
        .get(&aft_recovery_share_material_key(
            capsule.height,
            &witness_manifest_hash,
            &material.block_commitment_hash,
        ))
        .unwrap()
        .is_none());
}

#[test]
fn publishing_missing_recovery_share_round_trips_without_receipts() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(73);
    let witness_manifest_hash = [25u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [26u8; 32]);
    let missing = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash,
        recovery_capsule_hash: certificate.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };

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
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_missing_recovery_share(
            &state,
            capsule.height,
            &witness_manifest_hash
        )
        .unwrap(),
        Some(missing.clone())
    );
    assert!(state
        .get(&aft_missing_recovery_share_key(
            capsule.height,
            &witness_manifest_hash,
        ))
        .unwrap()
        .is_some());
}

#[test]
fn publishing_missing_recovery_share_after_receipt_is_rejected() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(74);
    let witness_manifest_hash = [27u8; 32];
    let certificate =
        sample_recovery_witness_certificate(&capsule, witness_manifest_hash, [28u8; 32]);
    let receipt = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash,
        block_commitment_hash: [29u8; 32],
        share_commitment_hash: certificate.share_commitment_hash,
    };
    let missing = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash,
        recovery_capsule_hash: certificate.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };

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
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_missing_recovery_share@v1",
            &codec::to_bytes_canonical(&missing).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("after a recovery receipt already exists"));
    });

    assert!(state
        .get(&aft_missing_recovery_share_key(
            capsule.height,
            &witness_manifest_hash,
        ))
        .unwrap()
        .is_none());
}

#[test]
fn recovery_threshold_status_reports_recoverable_for_matching_receipts() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(75);
    let witness_a = [31u8; 32];
    let witness_b = [32u8; 32];
    let witness_c = [33u8; 32];
    let block_commitment_hash = [34u8; 32];
    let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [35u8; 32]);
    let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [36u8; 32]);
    let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [37u8; 32]);
    let receipt_a = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        block_commitment_hash,
        share_commitment_hash: certificate_a.share_commitment_hash,
    };
    let receipt_b = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_b,
        block_commitment_hash,
        share_commitment_hash: certificate_b.share_commitment_hash,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_a).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_b).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_c).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_a).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_b).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_threshold_status(
            &state,
            capsule.height,
            &[witness_a, witness_b, witness_c],
            2,
        )
        .unwrap(),
        RecoveryThresholdStatus::Recoverable(block_commitment_hash)
    );
}

#[test]
fn recovery_threshold_status_reports_pending_when_threshold_is_still_reachable() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(76);
    let witness_a = [41u8; 32];
    let witness_b = [42u8; 32];
    let witness_c = [43u8; 32];
    let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [44u8; 32]);
    let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [45u8; 32]);
    let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [46u8; 32]);
    let receipt_a = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        block_commitment_hash: [47u8; 32],
        share_commitment_hash: certificate_a.share_commitment_hash,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_a).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_b).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_c).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_a).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_threshold_status(
            &state,
            capsule.height,
            &[witness_a, witness_b, witness_c],
            2,
        )
        .unwrap(),
        RecoveryThresholdStatus::Pending
    );
}

#[test]
fn recovery_threshold_status_reports_impossible_when_missingness_exhausts_capacity() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(77);
    let witness_a = [51u8; 32];
    let witness_b = [52u8; 32];
    let witness_c = [53u8; 32];
    let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [54u8; 32]);
    let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [55u8; 32]);
    let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [56u8; 32]);
    let missing_a = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        recovery_capsule_hash: certificate_a.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };
    let missing_b = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash: witness_b,
        recovery_capsule_hash: certificate_b.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_a).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_b).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_c).unwrap(),
            ),
            (
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing_a).unwrap(),
            ),
            (
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing_b).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_threshold_status(
            &state,
            capsule.height,
            &[witness_a, witness_b, witness_c],
            2,
        )
        .unwrap(),
        RecoveryThresholdStatus::Impossible
    );
}

#[test]
fn publishing_missing_recovery_share_materializes_recovery_impossible_abort() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(77_001);
    let witness_a = [57u8; 32];
    let witness_b = [58u8; 32];
    let witness_c = [59u8; 32];
    let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [60u8; 32]);
    let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [61u8; 32]);
    let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [62u8; 32]);
    let missing_a = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        recovery_capsule_hash: certificate_a.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };
    let missing_b = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash: witness_b,
        recovery_capsule_hash: certificate_b.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_a).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_b).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_c).unwrap(),
            ),
            (
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing_a).unwrap(),
            ),
            (
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing_b).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    let abort = GuardianRegistry::load_canonical_order_abort(&state, capsule.height)
        .unwrap()
        .expect("recovery impossible state should materialize a canonical-order abort");
    assert_eq!(
        abort.reason,
        CanonicalOrderAbortReason::RecoveryThresholdImpossible
    );
    assert!(
        GuardianRegistry::load_canonical_bulletin_close(&state, capsule.height)
            .unwrap()
            .is_none()
    );
}

#[test]
fn recovery_threshold_status_excludes_conflicting_same_witness_receipts_from_support() {
    let registry = production_registry();
    let capsule = sample_recovery_capsule(78);
    let witness_a = [61u8; 32];
    let witness_b = [62u8; 32];
    let witness_c = [63u8; 32];
    let certificate_a = sample_recovery_witness_certificate(&capsule, witness_a, [64u8; 32]);
    let certificate_b = sample_recovery_witness_certificate(&capsule, witness_b, [65u8; 32]);
    let certificate_c = sample_recovery_witness_certificate(&capsule, witness_c, [66u8; 32]);
    let block_commitment_hash = [67u8; 32];
    let receipt_a_one = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        block_commitment_hash,
        share_commitment_hash: certificate_a.share_commitment_hash,
    };
    let receipt_a_two = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_a,
        block_commitment_hash: [68u8; 32],
        share_commitment_hash: certificate_a.share_commitment_hash,
    };
    let receipt_b = RecoveryShareReceipt {
        height: capsule.height,
        witness_manifest_hash: witness_b,
        block_commitment_hash,
        share_commitment_hash: certificate_b.share_commitment_hash,
    };
    let missing_c = MissingRecoveryShare {
        height: capsule.height,
        witness_manifest_hash: witness_c,
        recovery_capsule_hash: certificate_c.recovery_capsule_hash,
        recovery_window_close_ms: capsule.recovery_window_close_ms,
    };

    let mut state = MockState::default();
    with_ctx(|ctx| {
        for (method, params) in [
            (
                "publish_aft_recovery_capsule@v1",
                codec::to_bytes_canonical(&capsule).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_a).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_b).unwrap(),
            ),
            (
                "publish_aft_recovery_witness_certificate@v1",
                codec::to_bytes_canonical(&certificate_c).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_a_one).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_a_two).unwrap(),
            ),
            (
                "publish_aft_recovery_share_receipt@v1",
                codec::to_bytes_canonical(&receipt_b).unwrap(),
            ),
            (
                "publish_aft_missing_recovery_share@v1",
                codec::to_bytes_canonical(&missing_c).unwrap(),
            ),
        ] {
            run_async(registry.handle_service_call(&mut state, method, &params, ctx)).unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_recovery_threshold_status(
            &state,
            capsule.height,
            &[witness_a, witness_b, witness_c],
            2,
        )
        .unwrap(),
        RecoveryThresholdStatus::Impossible
    );
}
