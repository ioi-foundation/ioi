#[test]
fn publishing_archived_recovered_history_segments_persists_deterministic_chain_and_loads_by_start()
{
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(90, 0x31);
    let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(91, 0x32);

    let previous_segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_a),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("previous archived segment");
    let current_segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_b),
        Some(&previous_segment),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("current archived segment");

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&previous_segment).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&current_segment).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment(&state, 90, 90).unwrap(),
        Some(previous_segment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment(&state, 91, 91).unwrap(),
        Some(current_segment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segments_for_start(&state, 91).unwrap(),
        vec![current_segment.clone()]
    );
    let previous_hash = canonical_archived_recovered_history_segment_hash(&previous_segment)
        .expect("previous archived segment hash");
    let current_hash = canonical_archived_recovered_history_segment_hash(&current_segment)
        .expect("current archived segment hash");
    assert_eq!(
        current_segment.previous_archived_segment_hash,
        previous_hash
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment_by_hash(&state, &previous_hash,)
            .unwrap(),
        Some(previous_segment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment_by_hash(&state, &current_hash)
            .unwrap(),
        Some(current_segment.clone())
    );
    assert_eq!(
        GuardianRegistry::load_previous_archived_recovered_history_segment(
            &state,
            &current_segment,
        )
        .unwrap(),
        Some(previous_segment)
    );
    assert_eq!(
        state
            .get(&aft_archived_recovered_history_segment_hash_key(
                &current_hash
            ))
            .unwrap()
            .is_some(),
        true
    );
}

#[test]
fn publishing_conflicting_archived_recovered_history_segment_for_same_range_rejects_conflicting_overlap(
) {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(92, 0x41);
    let segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("archived segment");
    let mut conflicting_segment = segment.clone();
    conflicting_segment.overlap_start_height = conflicting_segment.start_height;
    conflicting_segment.overlap_end_height = conflicting_segment.end_height;
    conflicting_segment.overlap_root_hash = [0xAB; 32];

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&segment).unwrap(),
            ctx,
        ))
        .unwrap();
        let error = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&conflicting_segment).unwrap(),
            ctx,
        ))
        .expect_err("conflicting overlap on the same archived range should fail");
        assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history segment already published for the same covered range"));
    });

    let stored = state
        .get(&aft_archived_recovered_history_segment_key(92, 92))
        .unwrap()
        .expect("stored archived segment bytes");
    let stored: ArchivedRecoveredHistorySegment =
        codec::from_bytes_canonical(&stored).expect("decode stored archived segment");
    assert_eq!(stored, segment);
}

fn sample_archived_recovered_restart_page(
    segment: &ArchivedRecoveredHistorySegment,
    parent_block_hash: [u8; 32],
    parent_state_root_hash: [u8; 32],
    state_seed: u8,
) -> ArchivedRecoveredRestartPage {
    let restart_entry = RecoveredRestartBlockHeaderEntry {
        certified_header: RecoveredCertifiedHeaderEntry {
            header: RecoveredCanonicalHeaderEntry {
                height: segment.start_height,
                view: segment.start_height + 10,
                canonical_block_commitment_hash: [state_seed.wrapping_add(1); 32],
                parent_block_commitment_hash: parent_block_hash,
                transactions_root_hash: [state_seed.wrapping_add(2); 32],
                resulting_state_root_hash: [state_seed.wrapping_add(3); 32],
                previous_canonical_collapse_commitment_hash: [state_seed.wrapping_add(4); 32],
            },
            certified_parent_quorum_certificate: QuorumCertificate {
                height: segment.start_height.saturating_sub(1),
                view: segment.start_height + 9,
                block_hash: parent_block_hash,
                ..Default::default()
            },
            certified_parent_resulting_state_root_hash: parent_state_root_hash,
        },
        header: BlockHeader {
            height: segment.start_height,
            view: segment.start_height + 10,
            parent_hash: parent_block_hash,
            parent_state_root: StateRoot(parent_state_root_hash.to_vec()),
            state_root: StateRoot(vec![state_seed.wrapping_add(3); 32]),
            transactions_root: vec![state_seed.wrapping_add(2); 32],
            timestamp: 1_760_000_000 + segment.start_height,
            timestamp_ms: (1_760_000_000 + segment.start_height) * 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([state_seed.wrapping_add(5); 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [state_seed.wrapping_add(6); 32],
            producer_pubkey: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate {
                height: segment.start_height.saturating_sub(1),
                view: segment.start_height + 9,
                block_hash: parent_block_hash,
                ..Default::default()
            },
            previous_canonical_collapse_commitment_hash: [state_seed.wrapping_add(4); 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            signature: Vec::new(),
        },
    };
    build_archived_recovered_restart_page(segment, std::slice::from_ref(&restart_entry))
        .expect("archived recovered restart page")
}

fn sample_archived_recovered_history_checkpoint(
    segment: &ArchivedRecoveredHistorySegment,
    page: &ArchivedRecoveredRestartPage,
    previous: Option<&ArchivedRecoveredHistoryCheckpoint>,
) -> ArchivedRecoveredHistoryCheckpoint {
    build_archived_recovered_history_checkpoint(segment, page, previous)
        .expect("archived recovered history checkpoint")
}

fn sample_archived_recovered_history_retention_receipt(
    checkpoint: &ArchivedRecoveredHistoryCheckpoint,
    profile: &ArchivedRecoveredHistoryProfile,
    validator_sets: &ValidatorSetsV1,
) -> ArchivedRecoveredHistoryRetentionReceipt {
    let validator_set_commitment_hash =
        canonical_validator_sets_hash(validator_sets).expect("validator set commitment hash");
    build_archived_recovered_history_retention_receipt(
        checkpoint,
        validator_set_commitment_hash,
        archived_recovered_history_retained_through_height(checkpoint, profile)
            .expect("retained-through height"),
    )
    .expect("archived recovered history retention receipt")
}

fn sample_archived_recovered_history_profile() -> ArchivedRecoveredHistoryProfile {
    build_archived_recovered_history_profile(
        1024,
        1,
        0,
        1,
        1,
        ArchivedRecoveredHistoryCheckpointUpdateRule::EveryPublishedSegmentV1,
    )
    .expect("archived recovered-history profile")
}

fn sample_archived_recovered_history_profile_activation(
    profile: &ArchivedRecoveredHistoryProfile,
    previous_activation: Option<&ArchivedRecoveredHistoryProfileActivation>,
    activation_end_height: u64,
) -> ArchivedRecoveredHistoryProfileActivation {
    build_archived_recovered_history_profile_activation(
        profile,
        previous_activation,
        activation_end_height,
        None,
    )
    .expect("archived recovered-history profile activation")
}

fn sample_bootstrap_archived_recovered_history_profile_activation(
    profile: &ArchivedRecoveredHistoryProfile,
) -> ArchivedRecoveredHistoryProfileActivation {
    sample_archived_recovered_history_profile_activation(profile, None, 1)
}

fn seed_active_archived_recovered_history_profile(
    state: &mut MockState,
) -> ArchivedRecoveredHistoryProfile {
    let profile = sample_archived_recovered_history_profile();
    let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
        .expect("archived recovered-history profile hash");
    let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);
    let activation_hash = canonical_archived_recovered_history_profile_activation_hash(&activation)
        .expect("archived recovered-history profile activation hash");
    state
        .insert(
            AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY,
            &codec::to_bytes_canonical(&profile)
                .expect("encode active archived recovered-history profile"),
        )
        .expect("store active archived recovered-history profile");
    state
        .insert(
            &aft_archived_recovered_history_profile_hash_key(&profile_hash),
            &codec::to_bytes_canonical(&profile)
                .expect("encode archived recovered-history profile by hash"),
        )
        .expect("store archived recovered-history profile by hash");
    state
        .insert(
            &aft_archived_recovered_history_profile_activation_key(&profile_hash),
            &codec::to_bytes_canonical(&activation)
                .expect("encode archived recovered-history profile activation"),
        )
        .expect("store archived recovered-history profile activation by hash");
    state
        .insert(
            &aft_archived_recovered_history_profile_activation_height_key(1),
            &codec::to_bytes_canonical(&activation)
                .expect("encode archived recovered-history profile activation by height"),
        )
        .expect("store archived recovered-history profile activation by height");
    state
        .insert(
            &aft_archived_recovered_history_profile_activation_hash_key(&activation_hash),
            &codec::to_bytes_canonical(&activation)
                .expect("encode archived recovered-history profile activation by hash"),
        )
        .expect("store archived recovered-history profile activation by hash");
    state
        .insert(
            AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY,
            &codec::to_bytes_canonical(&activation)
                .expect("encode latest archived recovered-history profile activation"),
        )
        .expect("store latest archived recovered-history profile activation");
    profile
}

#[test]
fn archived_recovered_history_profile_activation_persists_active_profile_and_loads_by_hash() {
    let registry = production_registry();
    let mut state = MockState::default();
    let profile = sample_archived_recovered_history_profile();
    let profile_hash = canonical_archived_recovered_history_profile_hash(&profile)
        .expect("archived recovered-history profile hash");
    let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile@v1",
            &codec::to_bytes_canonical(&profile).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile_activation@v1",
            &codec::to_bytes_canonical(&activation).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    assert_eq!(
        GuardianRegistry::load_active_archived_recovered_history_profile(&state).unwrap(),
        Some(profile.clone())
    );
    assert_eq!(
        GuardianRegistry::load_latest_archived_recovered_history_profile_activation(&state)
            .unwrap(),
        Some(activation.clone())
    );
    assert_eq!(
            GuardianRegistry::load_archived_recovered_history_profile_activation(
                &state,
                &profile_hash,
            )
            .unwrap(),
            Some(activation.clone())
        );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_profile_by_hash(&state, &profile_hash,)
            .unwrap(),
        Some(profile.clone())
    );
    assert!(state
        .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
        .unwrap()
        .is_some());
    assert!(state
        .get(&aft_archived_recovered_history_profile_hash_key(
            &profile_hash
        ))
        .unwrap()
        .is_some());
}

#[test]
fn publishing_conflicting_archived_recovered_history_profile_activation_fails_closed() {
    let registry = production_registry();
    let mut state = MockState::default();
    let profile = sample_archived_recovered_history_profile();
    let activation = sample_archived_recovered_history_profile_activation(&profile, None, 1);
    let conflicting_profile = build_archived_recovered_history_profile(
        profile.retention_horizon + 1,
        profile.restart_page_window,
        profile.restart_page_overlap,
        profile.windows_per_segment,
        profile.segments_per_fold,
        profile.checkpoint_update_rule,
    )
    .expect("conflicting archived recovered-history profile");
    let conflicting_activation =
        sample_archived_recovered_history_profile_activation(&conflicting_profile, None, 1);

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile@v1",
            &codec::to_bytes_canonical(&profile).unwrap(),
            ctx,
        ))
        .unwrap();
        let _ = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile_activation@v1",
            &codec::to_bytes_canonical(&activation).unwrap(),
            ctx,
        ))
        .expect("bootstrap activation should publish");
        let _ = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile@v1",
            &codec::to_bytes_canonical(&conflicting_profile).unwrap(),
            ctx,
        ))
        .expect("conflicting profile object should persist by hash");
        let error = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_profile_activation@v1",
            &codec::to_bytes_canonical(&conflicting_activation).unwrap(),
            ctx,
        ))
        .expect_err("conflicting archived recovered-history profile activation must fail");
        assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history profile activation already published for the same activation end height"));
    });
}

#[test]
fn archived_recovered_history_segment_page_by_hash_follows_previous_links() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(100, 0x51);
    let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(101, 0x52);
    let (_, _, _, recovered_c) = sample_recovered_publication_bundle_fixture(102, 0x53);

    let segment_a = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_a),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment a");
    let segment_b = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_b),
        Some(&segment_a),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment b");
    let segment_c = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_c),
        Some(&segment_b),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment c");
    let segment_c_hash =
        canonical_archived_recovered_history_segment_hash(&segment_c).expect("segment c hash");

    with_ctx(|ctx| {
        for segment in [&segment_a, &segment_b, &segment_c] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(segment).unwrap(),
                ctx,
            ))
            .unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment_page(&state, &segment_c_hash, 2,)
            .unwrap(),
        vec![segment_b.clone(), segment_c.clone()]
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_segment_page(&state, &segment_c_hash, 3,)
            .unwrap(),
        vec![segment_a, segment_b, segment_c]
    );
}

#[test]
fn archived_recovered_history_segment_page_by_hash_rejects_missing_predecessor() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered) = sample_recovered_publication_bundle_fixture(103, 0x61);
    let mut segment = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("archived segment");
    segment.previous_archived_segment_hash = [0xCD; 32];
    let segment_hash =
        canonical_archived_recovered_history_segment_hash(&segment).expect("segment hash");

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&segment).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let error =
        GuardianRegistry::load_archived_recovered_history_segment_page(&state, &segment_hash, 2)
            .expect_err("missing predecessor should fail closed");
    assert!(error
        .to_string()
        .contains("predecessor hash is missing from state"));
}

#[test]
fn archived_recovered_history_segment_page_by_hash_rejects_invalid_overlap_anchor() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(104, 0x71);
    let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(105, 0x72);

    let previous = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_a),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("previous segment");
    let mut current = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_b),
        Some(&previous),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("current segment");
    current.overlap_start_height = current.start_height;
    current.overlap_end_height = current.end_height;
    current.overlap_root_hash = current.segment_root_hash;
    let current_hash =
        canonical_archived_recovered_history_segment_hash(&current).expect("current hash");

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&previous).unwrap(),
            ctx,
        ))
        .unwrap();
        run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_segment@v1",
            &codec::to_bytes_canonical(&current).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    let error =
        GuardianRegistry::load_archived_recovered_history_segment_page(&state, &current_hash, 2)
            .expect_err("invalid overlap anchor should fail closed");
    assert!(error
        .to_string()
        .contains("does not cover the declared overlap anchor"));
}

#[test]
fn archived_recovered_restart_pages_follow_segment_hash_chain() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(106, 0x81);
    let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(107, 0x82);
    let segment_a = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_a),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment a");
    let segment_b = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_b),
        Some(&segment_a),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment b");
    let page_a = sample_archived_recovered_restart_page(&segment_a, [0x11; 32], [0x12; 32], 0x13);
    let page_b = sample_archived_recovered_restart_page(
        &segment_b,
        page_a.restart_headers[0]
            .certified_header
            .header
            .canonical_block_commitment_hash,
        page_a.restart_headers[0]
            .certified_header
            .header
            .resulting_state_root_hash,
        0x21,
    );
    let segment_b_hash =
        canonical_archived_recovered_history_segment_hash(&segment_b).expect("segment b hash");

    with_ctx(|ctx| {
        for segment in [&segment_a, &segment_b] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(segment).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for page in [&page_a, &page_b] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(page).unwrap(),
                ctx,
            ))
            .unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_archived_recovered_restart_page(&state, &page_b.segment_hash)
            .unwrap(),
        Some(page_b.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_restart_page_for_range(
            &state,
            segment_b.start_height,
            segment_b.end_height,
        )
        .unwrap(),
        Some(page_b.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_restart_page_chain(&state, &segment_b_hash, 2)
            .unwrap(),
        vec![page_a, page_b]
    );
    assert!(state
        .get(&aft_archived_recovered_restart_page_key(&segment_b_hash))
        .unwrap()
        .is_some());
}

#[test]
fn archived_recovered_history_checkpoints_persist_latest_tip_and_load_by_hash() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_a) = sample_recovered_publication_bundle_fixture(108, 0x91);
    let (_, _, _, recovered_b) = sample_recovered_publication_bundle_fixture(109, 0x92);
    let segment_a = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_a),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment a");
    let segment_b = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_b),
        Some(&segment_a),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("segment b");
    let page_a = sample_archived_recovered_restart_page(&segment_a, [0x31; 32], [0x32; 32], 0x33);
    let page_b = sample_archived_recovered_restart_page(
        &segment_b,
        page_a.restart_headers[0]
            .certified_header
            .header
            .canonical_block_commitment_hash,
        page_a.restart_headers[0]
            .certified_header
            .header
            .resulting_state_root_hash,
        0x34,
    );
    let checkpoint_a = sample_archived_recovered_history_checkpoint(&segment_a, &page_a, None);
    let checkpoint_b =
        sample_archived_recovered_history_checkpoint(&segment_b, &page_b, Some(&checkpoint_a));
    let checkpoint_b_hash = canonical_archived_recovered_history_checkpoint_hash(&checkpoint_b)
        .expect("checkpoint b hash");

    with_ctx(|ctx| {
        for segment in [&segment_a, &segment_b] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(segment).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for page in [&page_a, &page_b] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(page).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for checkpoint in [&checkpoint_a, &checkpoint_b] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(checkpoint).unwrap(),
                ctx,
            ))
            .unwrap();
        }
    });

    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_checkpoint(
            &state,
            checkpoint_b.covered_start_height,
            checkpoint_b.covered_end_height,
        )
        .unwrap(),
        Some(checkpoint_b.clone())
    );
    assert_eq!(
        GuardianRegistry::load_archived_recovered_history_checkpoint_by_hash(
            &state,
            &checkpoint_b_hash,
        )
        .unwrap(),
        Some(checkpoint_b.clone())
    );
    assert_eq!(
        GuardianRegistry::load_latest_archived_recovered_history_checkpoint(&state).unwrap(),
        Some(checkpoint_b.clone())
    );
    assert!(state
        .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
        .unwrap()
        .is_some());
    assert!(state
        .get(&aft_archived_recovered_history_checkpoint_hash_key(
            &checkpoint_b_hash,
        ))
        .unwrap()
        .is_some());
}

#[test]
fn publishing_conflicting_archived_recovered_history_checkpoint_for_same_range_fails_closed() {
    let registry = production_registry();
    let mut state = MockState::default();
    let _profile = seed_active_archived_recovered_history_profile(&mut state);
    let (_, _, _, recovered_prev_alt) = sample_recovered_publication_bundle_fixture(205, 0xA1);
    let (_, _, _, recovered_prev) = sample_recovered_publication_bundle_fixture(206, 0xA2);
    let (_, _, _, recovered_current) = sample_recovered_publication_bundle_fixture(207, 0xA3);
    let segment_prev_alt = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_prev_alt),
        None,
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("previous alt segment");
    let segment_prev = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_prev),
        Some(&segment_prev_alt),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("previous segment");
    let segment_current = build_archived_recovered_history_segment(
        std::slice::from_ref(&recovered_current),
        Some(&segment_prev),
        None,
        &sample_archived_recovered_history_profile(),
        &sample_bootstrap_archived_recovered_history_profile_activation(
            &sample_archived_recovered_history_profile(),
        ),
    )
    .expect("current segment");
    let page_prev_alt =
        sample_archived_recovered_restart_page(&segment_prev_alt, [0x41; 32], [0x42; 32], 0x43);
    let page_prev = sample_archived_recovered_restart_page(
        &segment_prev,
        page_prev_alt.restart_headers[0]
            .certified_header
            .header
            .canonical_block_commitment_hash,
        page_prev_alt.restart_headers[0]
            .certified_header
            .header
            .resulting_state_root_hash,
        0x44,
    );
    let page_current = sample_archived_recovered_restart_page(
        &segment_current,
        page_prev.restart_headers[0]
            .certified_header
            .header
            .canonical_block_commitment_hash,
        page_prev.restart_headers[0]
            .certified_header
            .header
            .resulting_state_root_hash,
        0x45,
    );
    let checkpoint_prev_alt =
        sample_archived_recovered_history_checkpoint(&segment_prev_alt, &page_prev_alt, None);
    let checkpoint_prev = sample_archived_recovered_history_checkpoint(
        &segment_prev,
        &page_prev,
        Some(&checkpoint_prev_alt),
    );
    let checkpoint_current = sample_archived_recovered_history_checkpoint(
        &segment_current,
        &page_current,
        Some(&checkpoint_prev),
    );
    let conflicting_checkpoint_current = sample_archived_recovered_history_checkpoint(
        &segment_current,
        &page_current,
        Some(&checkpoint_prev_alt),
    );

    with_ctx(|ctx| {
        for segment in [&segment_prev_alt, &segment_prev, &segment_current] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_segment@v1",
                &codec::to_bytes_canonical(segment).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for page in [&page_prev_alt, &page_prev, &page_current] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_restart_page@v1",
                &codec::to_bytes_canonical(page).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        for checkpoint in [&checkpoint_prev_alt, &checkpoint_prev, &checkpoint_current] {
            run_async(registry.handle_service_call(
                &mut state,
                "publish_aft_archived_recovered_history_checkpoint@v1",
                &codec::to_bytes_canonical(checkpoint).unwrap(),
                ctx,
            ))
            .unwrap();
        }
        let error = run_async(registry.handle_service_call(
            &mut state,
            "publish_aft_archived_recovered_history_checkpoint@v1",
            &codec::to_bytes_canonical(&conflicting_checkpoint_current).unwrap(),
            ctx,
        ))
        .expect_err("conflicting archived checkpoint on the same covered range should fail");
        assert!(error
                .to_string()
                .contains("conflicting aft archived recovered-history checkpoint already published for the same covered range"));
    });
}

