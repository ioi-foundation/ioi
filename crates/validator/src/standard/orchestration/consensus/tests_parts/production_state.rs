#[test]
fn stitch_recovered_restart_segment_folds_rejects_conflicting_middle_fold_overlap_in_three_fold_composition(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 610,
        state_root: vec![0x30; 32],
        block_hash: [0x40; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 611, 210, 125, 0x50);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        611,
        735,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    let first_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[0]);
    let mut second_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[1]);
    let third_fold = stitched_restart_segment_fold(&branch, 611, &segment_folds[2]);
    second_fold[40].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_fold.as_slice(),
        second_fold.as_slice(),
        third_fold.as_slice(),
    ])
    .expect_err("conflicting middle-fold overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn folded_recovered_loaders_match_expected_prefixes_across_fold_budgets() {
    let cases = [(1u64, 53u64, 0x21u8), (2, 89, 0x41), (3, 125, 0x51)];

    for (fold_budget, expected_end_height, seed_base) in cases {
        let (workload_client, expected_headers, expected_certified, expected_restart) =
            seed_recovered_workload_client(expected_end_height, seed_base);

        let loaded_headers = run_async_test(load_folded_recovered_consensus_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered canonical-header prefix");
        assert_eq!(
            loaded_headers, expected_headers,
            "fold budget {fold_budget} recovered canonical-header prefix mismatch"
        );

        let loaded_certified = run_async_test(load_folded_recovered_certified_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered certified-header prefix");
        assert_eq!(
            loaded_certified, expected_certified,
            "fold budget {fold_budget} recovered certified-header prefix mismatch"
        );

        let loaded_restart = run_async_test(load_folded_recovered_restart_block_headers(
            &workload_client,
            expected_end_height,
            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
            DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
            fold_budget,
        ))
        .expect("folded recovered restart block-header prefix");
        assert_eq!(
            loaded_restart, expected_restart,
            "fold budget {fold_budget} recovered restart block-header prefix mismatch"
        );
        assert_eq!(
            loaded_restart.len(),
            expected_end_height as usize,
            "fold budget {fold_budget} restart prefix length mismatch"
        );
        let tail_index = loaded_restart.len() - 1;
        assert_eq!(
            loaded_restart[tail_index].header.parent_qc,
            loaded_restart[tail_index - 1].certified_quorum_certificate(),
            "fold budget {fold_budget} restart tail parent QC mismatch"
        );
    }
}

#[test]
fn stitched_recovered_restart_carriers_reject_conflicting_overlap_across_fold_budgets() {
    let cases = [(1u64, 53usize, 0x22u8), (2, 89, 0x42), (3, 125, 0x52)];

    for (fold_budget, depth, seed_base) in cases {
        let current_anchor = RecoveredConsensusTipAnchor {
            height: 0,
            state_root: vec![seed_base; 32],
            block_hash: [seed_base.wrapping_add(1); 32],
        };
        let branch = sample_recovered_restart_branch(
            &current_anchor,
            1,
            300 + fold_budget,
            depth,
            seed_base.wrapping_add(0x10),
        );

        let error = match fold_budget {
            1 => {
                let segments = bounded_recovered_segment_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                );
                let first_segment = stitched_restart_segment(&branch, 1, &segments[0]);
                let second_segment = stitched_restart_segment(&branch, 1, &segments[1]);
                let mut third_segment = stitched_restart_segment(&branch, 1, &segments[2]);
                let fourth_segment = stitched_restart_segment(&branch, 1, &segments[3]);
                third_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_segment.as_slice(),
                    second_segment.as_slice(),
                    third_segment.as_slice(),
                    fourth_segment.as_slice(),
                ])
                .expect_err("conflicting interior segment overlap should be rejected")
            }
            2 => {
                let segment_folds = bounded_recovered_segment_fold_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
                );
                let first_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[0]);
                let mut second_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[1]);
                second_fold[8].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_fold.as_slice(),
                    second_fold.as_slice(),
                ])
                .expect_err("conflicting inter-fold overlap should be rejected")
            }
            3 => {
                let segment_folds = bounded_recovered_segment_fold_ranges(
                    1,
                    depth as u64,
                    AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                    AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
                    DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
                );
                let first_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[0]);
                let mut second_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[1]);
                let third_fold = stitched_restart_segment_fold(&branch, 1, &segment_folds[2]);
                second_fold[40].header.parent_qc.block_hash[0] ^= 0xFF;

                stitch_recovered_restart_block_header_segments(&[
                    first_fold.as_slice(),
                    second_fold.as_slice(),
                    third_fold.as_slice(),
                ])
                .expect_err("conflicting middle-fold overlap should be rejected")
            }
            _ => unreachable!("unsupported fold-budget conformance case"),
        };

        assert!(
            error.contains("overlap mismatch"),
            "fold budget {fold_budget} should reject conflicting overlap: {error}"
        );
    }
}

#[test]
fn paged_recovered_segment_fold_cursor_matches_direct_extract_for_two_hundred_thirty_three_step_branch(
) {
    let expected_end_height = 233u64;
    let (client, expected_headers, expected_certified, expected_restart) =
        seed_recovered_workload_client(expected_end_height, 0x61);

    let (loaded_headers, loaded_certified, loaded_restart) =
        load_paged_recovered_prefixes_to_height(&client, expected_end_height, 1)
            .expect("paged recovered ancestry");

    assert_eq!(loaded_headers.len(), expected_end_height as usize);
    assert_eq!(loaded_certified.len(), expected_end_height as usize);
    assert_eq!(loaded_restart.len(), expected_end_height as usize);
    assert_eq!(loaded_headers, expected_headers);
    assert_eq!(loaded_certified, expected_certified);
    assert_eq!(loaded_restart, expected_restart);
}

#[test]
fn paged_recovered_segment_fold_cursor_matches_direct_extract_across_page_depths() {
    for (index, expected_end_height) in [89u64, 125, 161, 197, 233].into_iter().enumerate() {
        let seed = 0x70u8.wrapping_add(index as u8);
        let (client, expected_headers, expected_certified, expected_restart) =
            seed_recovered_workload_client(expected_end_height, seed);

        let (loaded_headers, loaded_certified, loaded_restart) =
            load_paged_recovered_prefixes_to_height(&client, expected_end_height, 1)
                .expect("paged recovered ancestry");

        assert_eq!(
                loaded_headers, expected_headers,
                "paged recovered canonical-header ancestry mismatch at end height {expected_end_height}"
            );
        assert_eq!(
                loaded_certified, expected_certified,
                "paged recovered certified-header ancestry mismatch at end height {expected_end_height}"
            );
        assert_eq!(
            loaded_restart, expected_restart,
            "paged recovered restart ancestry mismatch at end height {expected_end_height}"
        );
    }
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_duplicate_page_ambiguity() {
    let mut cursor = RecoveredSegmentFoldCursor::new(
        233,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    let first_page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("older recovered page");
    let error = cursor
        .accept_page(&first_page)
        .expect_err("duplicate recovered page must be rejected");
    assert!(
        error.contains("expected page"),
        "unexpected duplicate-page error: {error}"
    );
}

#[test]
fn paged_recovered_segment_fold_cursor_rejects_missing_gap_page() {
    let expected_end_height = 233u64;
    let (mut client, _, _, _) = seed_recovered_workload_client(expected_end_height, 0x63);
    let mut cursor = RecoveredSegmentFoldCursor::new(
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    )
    .expect("recovered segment-fold cursor");

    let page = cursor
        .next_page()
        .expect("advance recovered segment-fold cursor")
        .expect("older recovered page");
    let gap_height = page.start_height + 7;
    let recovered_prefix = [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &gap_height.to_be_bytes(),
    ]
    .concat();
    client
        .raw_state
        .retain(|key, _| !key.starts_with(&recovered_prefix));

    let error = run_async_test(load_recovered_segment_fold_page(&client, &page))
        .expect_err("missing recovered page gap must fail");
    let message = error.to_string();
    assert!(
        (message.contains("expected") && message.contains("loaded"))
            || message.contains("must be consecutive"),
        "unexpected missing-page error: {message}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_pages_older_ranges_and_bounds_engine_cache() {
    let expected_end_height = 233u64;
    let target_height = 1u64;
    let (client, _all_headers, _all_certified, all_restart) =
        seed_recovered_workload_client(expected_end_height, 0x74);
    let recovered_headers = run_async_test(load_folded_recovered_consensus_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered consensus headers");
    let recovered_certified = run_async_test(load_folded_recovered_certified_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered certified headers");
    let recovered_restart = run_async_test(load_folded_recovered_restart_block_headers(
        &client,
        expected_end_height,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    ))
    .expect("bounded recovered restart block headers");
    let base_start_height = loaded_recovered_ancestry_start_height(
        &recovered_headers,
        &recovered_certified,
        &recovered_restart,
    )
    .expect("bounded recovered start height");
    let base_tail_entry = recovered_restart
        .last()
        .expect("bounded recovered restart tail")
        .clone();
    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
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
    .expect("stream recovered ancestry to target");

    assert!(report.covered_target, "target height must be covered");
    assert!(
        !report.exhausted,
        "stream should not exhaust before reaching genesis"
    );
    assert!(
        report.loaded_pages.len() > 1,
        "expected multiple paged recovered ranges: {:?}",
        report.loaded_pages
    );
    let final_page = report
        .loaded_pages
        .last()
        .copied()
        .expect("final streamed recovered page");
    assert_eq!(final_page.0, 1, "final streamed page must reach genesis");
    assert!(
        final_page.1 < base_start_height,
        "final streamed range should stay disjoint from the bounded base suffix"
    );

    let pruned_heights = report
        .loaded_pages
        .iter()
        .take(report.loaded_pages.len().saturating_sub(1))
        .map(|(start_height, _)| *start_height)
        .filter(|height| final_page.1 < *height && *height < base_start_height)
        .collect::<Vec<_>>();
    let target_entry = all_restart
        .iter()
        .find(|entry| entry.header.height == target_height)
        .expect("restart entry at target height")
        .clone();

    run_async_test(async {
        let engine = engine.lock().await;
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &target_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "streamed target height should remain available after paging"
            );
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &base_tail_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "bounded base suffix should remain retained after paging"
            );
        for pruned_height in pruned_heights {
            let pruned_entry = all_restart
                .iter()
                .find(|entry| entry.header.height == pruned_height)
                .expect("restart entry for pruned height");
            assert!(
                    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                        &*engine,
                        &pruned_entry.certified_quorum_certificate(),
                    )
                    .is_none(),
                    "intermediate streamed page at height {pruned_height} should be evicted once paging advances"
                );
        }
    });
}

#[test]
fn stream_recovered_ancestry_to_height_falls_back_to_archived_restart_pages() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7A,
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

    let report = run_async_test(stream_recovered_ancestry_to_height(
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
    .expect("stream recovered ancestry across archived fallback");

    assert!(
        report.covered_target,
        "archived fallback should cover the target"
    );
    assert!(
        !report.exhausted,
        "archived fallback should not exhaust before height 1"
    );
    assert!(
        report.loaded_pages.iter().any(|page| page.0 == 1),
        "archived fallback should reach an archived page whose start height reaches genesis"
    );

    let active_profile: ArchivedRecoveredHistoryProfile = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY)
            .expect("active archived profile")
            .clone(),
    )
    .expect("decode active archived profile");
    let (expected_archived_start_height, expected_archived_end_height) =
        archived_recovered_restart_page_range_for_profile(
            retained_start_height - 1,
            &active_profile,
        )
        .expect("expected archived recovered restart page range");
    let target_segment: ArchivedRecoveredHistorySegment = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&aft_archived_recovered_history_segment_key(
                expected_archived_start_height,
                expected_archived_end_height,
            ))
            .expect("archived segment covering the retained predecessor range")
            .clone(),
    )
    .expect("decode archived segment for the retained predecessor range");
    let target_segment_hash = canonical_archived_recovered_history_segment_hash(&target_segment)
        .expect("archived segment hash for the retained predecessor range");
    let target_page: ArchivedRecoveredRestartPage = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(&aft_archived_recovered_restart_page_key(
                &target_segment_hash,
            ))
            .expect("archived restart page for the retained predecessor range")
            .clone(),
    )
    .expect("decode archived restart page for the retained predecessor range");
    let target_entry = target_page
        .restart_headers
        .first()
        .expect("first archived restart entry in the retained predecessor range")
        .clone();

    run_async_test(async {
        let engine = engine.lock().await;
        assert!(
                <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::recovered_restart_block_header_for_quorum_certificate(
                    &*engine,
                    &target_entry.certified_quorum_certificate(),
                )
                .is_some(),
                "archived fallback target should be present in the engine cache"
            );
    });
}

#[test]
fn stream_recovered_ancestry_to_height_discovers_archived_fallback_from_canonical_collapse_anchor_without_latest_checkpoint_side_key(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7B,
        );
    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY);

    let engine = Arc::new(Mutex::new(GuardianMajorityEngine::new(
        AftSafetyMode::GuardianMajority,
    )));

    run_async_test(async {
        let mut engine = engine.lock().await;
        seed_recovered_consensus_headers_into_engine(&mut *engine, &recovered_headers);
        seed_recovered_certified_headers_into_engine(&mut *engine, &recovered_certified);
        seed_recovered_restart_block_headers_into_engine(&mut *engine, &recovered_restart);
    });

    let report = run_async_test(stream_recovered_ancestry_to_height(
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
    .expect("stream recovered ancestry without latest archived checkpoint tip");

    assert!(
            report.covered_target,
            "canonical collapse anchor should bootstrap archived fallback without the latest checkpoint side key"
        );
    assert!(
            !report.exhausted,
            "canonical collapse anchor should keep archived fallback live without the latest checkpoint side key"
        );
    assert!(
            report.loaded_pages.iter().any(|page| page.0 == 1),
            "canonical collapse anchor should still load archived pages to genesis-facing coverage: {:?}",
            report.loaded_pages
        );
}

#[test]
fn stream_recovered_ancestry_to_height_requires_canonical_collapse_archived_anchor_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x81,
        );
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
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
    )
    .expect("clear retained canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip without archived-history anchor"),
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

    let report = run_async_test(stream_recovered_ancestry_to_height(
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
    .expect("stream recovered ancestry without canonical collapse archived-history anchor");

    assert!(
            !report.covered_target,
            "missing canonical collapse archived-history anchor must not infer archived fallback coverage"
        );
    assert!(
            report.exhausted,
            "missing canonical collapse archived-history anchor must fail closed as exhausted recovered ancestry"
        );
    assert!(
        report.loaded_pages.is_empty(),
        "missing canonical collapse archived-history anchor must not load archived pages: {:?}",
        report.loaded_pages
    );
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_canonical_collapse_archived_anchor() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x82,
        );
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
        [0xC1; 32],
        [0xC2; 32],
        [0xC3; 32],
    )
    .expect("set conflicting retained canonical collapse archived-history anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip with conflicting anchor"),
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
    .expect_err("conflicting canonical collapse archived-history anchor must fail closed");
    assert!(
        error
            .to_string()
            .contains("checkpoint anchor is missing from state"),
        "unexpected conflicting canonical anchor error: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_requires_archived_retention_receipt_for_fallback() {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7C,
        );
    let latest_checkpoint: ArchivedRecoveredHistoryCheckpoint = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY)
            .expect("latest archived checkpoint")
            .clone(),
    )
    .expect("decode latest archived checkpoint");
    let latest_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
            .expect("latest archived checkpoint hash");
    client
        .raw_state
        .remove(&aft_archived_recovered_history_retention_receipt_key(
            &latest_checkpoint_hash,
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
    .expect_err("missing archived retention receipt must fail closed");
    assert!(
        error
            .to_string()
            .contains("retention receipt anchor is missing from state"),
        "unexpected error for missing archived retention receipt: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_rejects_conflicting_anchored_retention_receipt_hash() {
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
    let latest_checkpoint_hash =
        canonical_archived_recovered_history_checkpoint_hash(&latest_checkpoint)
            .expect("latest archived checkpoint hash");
    let latest_activation: ArchivedRecoveredHistoryProfileActivation = codec::from_bytes_canonical(
        &client
            .raw_state
            .get(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY)
            .expect("latest archived profile activation")
            .clone(),
    )
    .expect("decode latest archived profile activation");
    let latest_activation_hash =
        canonical_archived_recovered_history_profile_activation_hash(&latest_activation)
            .expect("latest archived profile activation hash");
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
        latest_checkpoint_hash,
        latest_activation_hash,
        [0xD7; 32],
    )
    .expect("set conflicting canonical collapse retention receipt anchor");
    client.raw_state.insert(
        collapse_key,
        codec::to_bytes_canonical(&retained_tip)
            .expect("encode retained canonical collapse tip with conflicting receipt hash"),
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
    .expect_err("conflicting canonical collapse receipt anchor must fail closed");
    assert!(
        error
            .to_string()
            .contains("retention receipt anchor does not match the published receipt"),
        "unexpected error for conflicting anchored receipt hash: {error}"
    );
}

#[test]
fn stream_recovered_ancestry_to_height_uses_historical_archived_profile_after_active_rotation_without_latest_activation_indexes(
) {
    let expected_end_height = 40u64;
    let retained_start_height = 31u64;
    let target_height = 1u64;
    let (mut client, recovered_headers, recovered_certified, recovered_restart) =
        seed_recovered_workload_client_with_archived_restart_pages(
            expected_end_height,
            retained_start_height,
            0x7D,
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
    .expect("rotated archived recovered-history profile");
    let conflicting_profile_hash =
        canonical_archived_recovered_history_profile_hash(&conflicting_profile)
            .expect("rotated archived recovered-history profile hash");
    let conflicting_activation = build_archived_recovered_history_profile_activation(
        &conflicting_profile,
        Some(&latest_activation),
        latest_checkpoint.covered_end_height + 1,
        None,
    )
    .expect("rotated archived recovered-history profile activation");
    client.raw_state.insert(
        AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode conflicting archived profile"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_hash_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_profile)
            .expect("encode rotated archived profile by hash"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_key(&conflicting_profile_hash),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode rotated archived profile activation"),
    );
    client.raw_state.insert(
        aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode rotated archived profile activation by height"),
    );
    client.raw_state.insert(
        AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY.to_vec(),
        codec::to_bytes_canonical(&conflicting_activation)
            .expect("encode latest rotated archived profile activation"),
    );
    client
        .raw_state
        .remove(AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY);
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            latest_activation.activation_end_height,
        ),
    );
    client.raw_state.remove(
        &aft_archived_recovered_history_profile_activation_height_key(
            conflicting_activation.activation_end_height,
        ),
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

    let report = run_async_test(stream_recovered_ancestry_to_height(
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
    .expect("historical archived profile should remain valid after active-profile rotation");
    assert!(report.covered_target);
    assert!(!report.exhausted);
    assert!(
        report.loaded_pages.iter().any(|page| page.0 == 1),
        "historical archived profile should still reach genesis-facing archived coverage"
    );
}

