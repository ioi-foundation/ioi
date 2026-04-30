#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_archived_profile_activation_predecessor_history(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x80,
        );
    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let conflicting_profile = build_archived_recovered_history_profile(
        active_profile.retention_horizon + 1,
        active_profile.restart_page_window,
        active_profile.restart_page_overlap,
        active_profile.windows_per_segment,
        active_profile.segments_per_fold,
        active_profile.checkpoint_update_rule,
    )
    .expect("conflicting archived recovered-history profile");
    let conflicting_profile_hash =
        canonical_archived_recovered_history_profile_hash(&conflicting_profile)
            .expect("conflicting archived recovered-history profile hash");
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height,
        None,
    )
    .expect("conflicting archived recovered-history profile activation");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by height"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode latest conflicting archived profile activation"),
    );
    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting active archived profile"),
    );

    let mut conflicting_checkpoint = latest_checkpoint.clone();
    conflicting_checkpoint.archived_profile_hash = conflicting_profile_hash;
    let conflicting_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&conflicting_checkpoint)
            .expect("conflicting archived checkpoint hash");
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_key(
            conflicting_checkpoint.covered_start_height,
            conflicting_checkpoint.covered_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_checkpoint_hash_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode conflicting archived checkpoint by hash"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_checkpoint)
            .expect("encode latest conflicting archived checkpoint"),
    );

    let validator_sets = read_validator_sets(
        client
            .raw_state
            .get(VALIDATOR_SET_KEY)
            .expect("active validator set")
            .as_slice(),
    )
    .expect("decode validator set");
    let validator_set_commitment_hash =
        canonical_validator_sets_hash(&validator_sets).expect("validator set commitment hash");
    let conflicting_receipt = build_archived_recovered_history_retention_receipt(
        &conflicting_checkpoint,
        validator_set_commitment_hash,
        archived_recovered_history_retained_through_height(
            &conflicting_checkpoint,
            &conflicting_profile,
        )
        .expect("conflicting retained-through height"),
    )
    .expect("conflicting archived retention receipt");

    let collapse_key = aft_canonical_collapse_object_key(expected_end_height);
    let mut retained_tip: CanonicalCollapseObject = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&collapse_key)
            .expect("retained canonical collapse tip")
            .clone(),
    )
    .expect("decode retained canonical collapse tip");
    let conflicting_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&conflicting_activation)
            .expect("conflicting archived profile activation hash");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(&conflicting_activation_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by hash"),
    );
    set_canonical_collapse_archived_recovered_history_anchor(
        &mut retained_tip,
        conflicting_checkpoint_hash,
        conflicting_activation_hash,
        canonical_archived_recovered_history_retention_receipt_hash(&conflicting_receipt)
            .expect("conflicting archived receipt hash"),
    )
    .expect("set conflicting canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip).expect(
            "encode retained canonical collapse tip with conflicting archived-history anchor",
        ),
    );
    client
        .raw_state
        .remove(&aft_archived_recovered_history_retention_receipt_key(
            &canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
                .expect("latest archived checkpoint hash"),
        ));
    client.raw_state.insert(
        aft_archived_recovered_history_retention_receipt_key(&conflicting_checkpoint_hash),
        codec::to_bytes_canonical(&conflicting_receipt)
            .expect("encode conflicting archived retention receipt"),
    );

    let mut conflicting_predecessor = latest_activation.clone();
    conflicting_predecessor.activation_end_height = conflicting_activation.activation_end_height;
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(
            &conflicting_predecessor.archived_profile_hash,
        ),
        codec::to_bytes_canonical(&conflicting_predecessor)
            .expect("encode conflicting predecessor activation"),
    );

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let error = run_async_test(stream_recovered_ancestry_to_height(
        &client,
        &engine,
        target_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    ))
    .expect_err("conflicting archived activation predecessor history must fail closed");
    assert!(
        error
            .to_string()
            .contains("must advance to a strictly later archived tip height"),
        "unexpected archived activation predecessor conflict error: {error}"
    );
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_conflicting_late_page_overlap() {
    let expected_end_height = 233u64;
    let (mut client, _, _, _) = seed_recovered_workload_client(expected_end_height, 0x62);
    let mut recovered_headers = run_async_test(load_folded_recovered_consensus_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered headers");
    let mut recovered_certified = run_async_test(load_folded_recovered_certified_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered certified headers");
    let mut recovered_restart = run_async_test(load_folded_recovered_restart_block_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("initial folded recovered restart headers");
    let mut cursor = RecoveredSegmentFoldCursor::new(
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    for _ in 0..2 {
        let page = cursor
            .next_page()
            .expect("advance recovered segment-fold cursor")
            .expect("older recovered page");
        let loaded_page = run_async_test(load_recovered_segment_fold_page(&client, &page))
            .expect("load older recovered segment-fold page");
        recovered_headers = stitch_recovered_canonical_header_segments(&[
            loaded_page.consensus_headers.as_slice(),
            recovered_headers.as_slice(),
        ])
        .expect("stitch older recovered canonical-header page");
        recovered_certified = stitch_recovered_certified_header_segments(&[
            loaded_page.certified_headers.as_slice(),
            recovered_certified.as_slice(),
        ])
        .expect("stitch older recovered certified-header page");
        recovered_restart = stitch_recovered_restart_block_header_segments(&[
            loaded_page.restart_headers.as_slice(),
            recovered_restart.as_slice(),
        ])
        .expect("stitch older recovered restart page");
    }
    assert_eq!(
        loaded_recovered_ancestry_start_height(
            &recovered_headers,
            &recovered_certified,
            &recovered_restart,
        ),
        Some(73),
        "two older pages should extend the cached prefix down to height 73",
    );

    let key = aft_canonical_collapse_object_key(79);
    let mut collapse: CanonicalCollapseObject = codec::from_bytes_canonical(
        client
            .raw_state
            .get(&key)
            .expect("collapse bytes for late overlap height"),
    )
    .expect("decode canonical collapse object");
    collapse.previous_canonical_collapse_commitment_hash[0] ^= 0x5a;
    client.raw_state.insert(
        key,
        codec::to_bytes_canonical(&collapse).expect("encode conflicting collapse"),
    );

    let page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("late conflicting page");
    let loaded_page = run_async_test(load_recovered_segment_fold_page(&client, &page))
        .expect("load conflicting recovered segment-fold page");

    let error = stitch_recovered_canonical_header_segments(&[
        loaded_page.consensus_headers.as_slice(),
        recovered_headers.as_slice(),
    ])
    .expect_err("late conflicting overlap must fail");
    let message = error.to_string();
    assert!(
        message.contains("overlap mismatch at height 79"),
        "unexpected paged overlap error: {message}"
    );
}

#[test]
fn select_unique_recovered_publication_bundle_rejects_conflicting_surfaces() {
    let bundle_a = RecoveredPublicationBundle {
        height: 19,
        block_commitment_hash: [0x10; 32],
        parent_block_commitment_hash: [0x11; 32],
        coding: RecoveryCodingDescriptor {
            family: RecoveryCodingFamily::SystematicGf256KOfNV1,
            share_count: 7,
            recovery_threshold: 3,
        },
        supporting_witness_manifest_hashes: vec![[0x12; 32], [0x13; 32], [0x14; 32]],
        recoverable_slot_payload_hash: [0x15; 32],
        recoverable_full_surface_hash: [0x16; 32],
        canonical_order_publication_bundle_hash: [0x17; 32],
        canonical_bulletin_close_hash: [0x18; 32],
    };
    let mut bundle_b = bundle_a.clone();
    bundle_b.canonical_bulletin_close_hash = [0x19; 32];

    assert!(
            select_unique_recovered_publication_bundle(vec![bundle_a.clone(), bundle_b]).is_none(),
            "conflicting recovered surfaces should not collapse into a unique validator restart surface"
        );
    assert_eq!(
        select_unique_recovered_publication_bundle(vec![bundle_a.clone(), bundle_a.clone()]),
        Some(bundle_a)
    );
}
