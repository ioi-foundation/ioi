#[test]
fn stream_recovered_ancestry_to_height_matches_three_recurring_historical_continuation_cycles_on_runtime_side(
) {
    let cycles = [
        (1u64, 40u64, 31u64, 0x84u8),
        (2, 80, 71, 0x94),
        (3, 120, 111, 0xA4),
    ];

    for (cycle, expected_end_height, retained_start_height, seed_base) in cycles {
        let report = stream_recovered_historical_continuation_cycle_case(
            expected_end_height,
            retained_start_height,
            seed_base,
        );

        assert!(
            report.covered_target,
            "runtime recurring cycle {cycle} should cover genesis-facing target height"
        );
        assert!(
            !report.exhausted,
            "runtime recurring cycle {cycle} should not exhaust archived continuation"
        );
        assert!(
            !report.loaded_pages.is_empty(),
            "runtime recurring cycle {cycle} should page older historical retrievability ranges"
        );
        assert!(
            report.loaded_pages.iter().any(|page| page.0 == 1),
            "runtime recurring cycle {cycle} should reach a genesis-facing archived page: {:?}",
            report.loaded_pages
        );
    }
}

#[test]
fn stream_recovered_ancestry_to_height_matches_persistent_historical_continuation_churn_simulator()
{
    let target_height = 1u64;
    let cycles = [
        (1u64, 40u64, 31u64, 0x84u8),
        (2, 80, 71, 0x94),
        (3, 120, 111, 0xA4),
    ];
    let mut simulator = PersistentRecoveredHistoricalContinuationSimulator::new();

    for (cycle, expected_end_height, retained_start_height, seed_base) in cycles {
        simulator.append_through(expected_end_height, retained_start_height, seed_base);
        simulator.rotate_active_profile_and_remove_latest_side_indexes();
        let report = simulator.stream_to_target(retained_start_height, target_height);

        assert!(
            report.covered_target,
            "persistent runtime churn cycle {cycle} should cover genesis-facing target height"
        );
        assert!(
            !report.exhausted,
            "persistent runtime churn cycle {cycle} should not exhaust archived continuation"
        );
        assert!(
                !report.loaded_pages.is_empty(),
                "persistent runtime churn cycle {cycle} should page older historical retrievability ranges"
            );
        assert!(
                report.loaded_pages.iter().any(|page| page.0 == 1),
                "persistent runtime churn cycle {cycle} should still reach a genesis-facing archived page: {:?}",
                report.loaded_pages
            );
    }
}

#[test]
fn stream_recovered_ancestry_to_height_requires_referenced_archived_profile_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7E,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    client
        .raw_state
        .remove(&aft_archived_recovered_history_profile_hash_key(
            &latest_checkpoint.archived_profile_hash,
        ));

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
    .expect_err("missing referenced archived profile must fail closed");
    assert!(error
        .to_string()
        .contains("references a missing archived profile hash"));
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_mixed_profile_archived_chain() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7F,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
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
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile by hash"),
    );
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height + 1,
        None,
    )
    .expect("conflicting archived recovered-history profile activation");
    let conflicting_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&conflicting_activation)
            .expect("conflicting archived recovered-history profile activation hash");
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_hash_key(&conflicting_activation_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode conflicting archived profile activation by hash"),
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
            .expect("encode conflicting latest archived checkpoint"),
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
    .expect_err("mixed-profile archived chain must fail closed");
    assert!(
        error
            .to_string()
            .contains("predates the governing profile activation tip")
            || error
                .to_string()
                .contains("crosses the successor profile activation tip"),
        "unexpected mixed-profile archived chain error: {error}"
    );
}

