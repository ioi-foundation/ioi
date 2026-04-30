#[test]
fn stitched_recovered_prefixes_match_direct_extract_for_overlapping_windows() {
    assert_stitched_recovered_prefixes_match_direct_extract(&[(1, 5), (4, 8)], 0x91, 8);
}

#[test]
fn stitched_recovered_prefixes_match_direct_extract_for_three_overlapping_windows() {
    assert_stitched_recovered_prefixes_match_direct_extract(&[(1, 5), (4, 8), (7, 11)], 0x71, 11);
}

#[test]
fn stitched_recovered_prefixes_match_direct_extract_for_four_overlapping_windows() {
    assert_stitched_recovered_prefixes_match_direct_extract(
        &[(1, 5), (4, 8), (7, 11), (10, 14)],
        0x51,
        14,
    );
}

#[test]
fn stitched_recovered_prefixes_match_direct_extract_for_five_overlapping_windows() {
    assert_stitched_recovered_prefixes_match_direct_extract(
        &[(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
        0x31,
        17,
    );
}

#[test]
fn aft_recovered_state_surface_matches_legacy_extractors_across_supported_coded_families() {
    for (coding, support_share_indices, seed_base) in [
        (xor_recovery_coding(3, 2), vec![0, 2], 0x31),
        (xor_recovery_coding(4, 3), vec![0, 2, 3], 0x41),
        (gf256_recovery_coding(4, 2), vec![1, 3], 0x51),
        (gf256_recovery_coding(7, 3), vec![0, 3, 6], 0x61),
        (gf256_recovery_coding(7, 4), vec![0, 2, 4, 6], 0x71),
    ] {
        assert_aft_recovered_state_surface_matches_legacy_extractors_for_coding(
            coding,
            &support_share_indices,
            seed_base,
        );
    }
}

#[test]
fn stitched_recovered_prefix_segments_match_direct_extract_for_two_overlapping_five_window_segments(
) {
    let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
    let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
    assert_segment_stitched_recovered_prefixes_match_direct_extract(
        &[first_segment.as_slice(), second_segment.as_slice()],
        0x11,
        29,
    );
}

#[test]
fn stitched_recovered_prefix_segments_match_direct_extract_for_three_overlapping_five_window_segments(
) {
    let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
    let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
    let third_segment = [(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)];
    assert_segment_stitched_recovered_prefixes_match_direct_extract(
        &[
            first_segment.as_slice(),
            second_segment.as_slice(),
            third_segment.as_slice(),
        ],
        0x01,
        41,
    );
}

#[test]
fn stitched_recovered_prefix_segments_match_direct_extract_for_four_overlapping_five_window_segments(
) {
    let first_segment = [(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)];
    let second_segment = [(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)];
    let third_segment = [(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)];
    let fourth_segment = [(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)];
    assert_segment_stitched_recovered_prefixes_match_direct_extract(
        &[
            first_segment.as_slice(),
            second_segment.as_slice(),
            third_segment.as_slice(),
            fourth_segment.as_slice(),
        ],
        0x21,
        53,
    );
}

#[test]
fn stitched_recovered_prefix_segment_folds_match_direct_extract_for_two_overlapping_four_segment_folds(
) {
    let first_fold = vec![
        vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
        vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
        vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
    ];
    let second_fold = vec![
        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
        vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
        vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
    ];
    assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
        &[first_fold, second_fold],
        0x41,
        89,
    );
}

#[test]
fn stitched_recovered_prefix_segment_folds_match_direct_extract_for_three_overlapping_four_segment_folds(
) {
    let first_fold = vec![
        vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
        vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
        vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
    ];
    let second_fold = vec![
        vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
        vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
        vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
    ];
    let third_fold = vec![
        vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
        vec![(85, 89), (88, 92), (91, 95), (94, 98), (97, 101)],
        vec![(97, 101), (100, 104), (103, 107), (106, 110), (109, 113)],
        vec![(109, 113), (112, 116), (115, 119), (118, 122), (121, 125)],
    ];
    assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
        &[first_fold, second_fold, third_fold],
        0x51,
        125,
    );
}

#[test]
fn stitched_recovered_prefix_segment_folds_match_direct_extract_across_fold_budgets() {
    let cases = [
        (
            vec![vec![
                vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
            ]],
            0x21,
            53u64,
        ),
        (
            vec![
                vec![
                    vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                    vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                    vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                    vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                ],
                vec![
                    vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                    vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
                    vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
                    vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                ],
            ],
            0x41,
            89u64,
        ),
        (
            vec![
                vec![
                    vec![(1, 5), (4, 8), (7, 11), (10, 14), (13, 17)],
                    vec![(13, 17), (16, 20), (19, 23), (22, 26), (25, 29)],
                    vec![(25, 29), (28, 32), (31, 35), (34, 38), (37, 41)],
                    vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                ],
                vec![
                    vec![(37, 41), (40, 44), (43, 47), (46, 50), (49, 53)],
                    vec![(49, 53), (52, 56), (55, 59), (58, 62), (61, 65)],
                    vec![(61, 65), (64, 68), (67, 71), (70, 74), (73, 77)],
                    vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                ],
                vec![
                    vec![(73, 77), (76, 80), (79, 83), (82, 86), (85, 89)],
                    vec![(85, 89), (88, 92), (91, 95), (94, 98), (97, 101)],
                    vec![(97, 101), (100, 104), (103, 107), (106, 110), (109, 113)],
                    vec![(109, 113), (112, 116), (115, 119), (118, 122), (121, 125)],
                ],
            ],
            0x51,
            125u64,
        ),
    ];

    for (segment_folds, seed_base, expected_end_height) in cases {
        assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
            &segment_folds,
            seed_base,
            expected_end_height,
        );
    }
}

#[test]
fn paged_recovered_prefixes_match_direct_extract_for_two_hundred_thirty_three_step_branch() {
    assert_paged_recovered_prefixes_match_direct_extract(0x61, 233);
}

#[test]
fn paged_recovered_prefixes_match_direct_extract_across_page_depths() {
    for (index, expected_end_height) in [89u64, 125, 161, 197, 233].into_iter().enumerate() {
        assert_paged_recovered_prefixes_match_direct_extract(
            0x70u8.wrapping_add(index as u8),
            expected_end_height,
        );
    }
}

#[test]
fn extract_recovered_prefix_page_rejects_missing_gap_page() {
    let (_registry, mut state) = build_recovered_registry_state(0x63, 233);
    let mut cursor =
        RecoveredSegmentFoldCursor::new(233, 5, 2, 5, 4, 2).expect("recovered segment-fold cursor");
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
    state
        .data
        .retain(|key, _| !key.starts_with(&recovered_prefix));

    let error = GuardianRegistry::extract_recovered_restart_block_header_page(&state, &page)
        .expect_err("missing recovered page gap must fail");
    let message = error.to_string();
    assert!(
        (message.contains("expected") && message.contains("loaded"))
            || message.contains("must be consecutive")
            || message.contains("requires a unique recovered publication bundle"),
        "unexpected missing-page error: {message}"
    );
}

fn bounded_recovered_window_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
) -> Vec<(u64, u64)> {
    if start_height == 0 || end_height == 0 || window == 0 || end_height < start_height {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let mut ranges = Vec::new();
    let step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let mut next_start = start_height;

    loop {
        let next_end = next_start
            .saturating_add(window.saturating_sub(1))
            .min(end_height);
        ranges.push((next_start, next_end));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(step);
    }

    ranges
}

fn bounded_recovered_segment_ranges(
    start_height: u64,
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
) -> Vec<Vec<(u64, u64)>> {
    if start_height == 0
        || end_height == 0
        || window == 0
        || windows_per_segment == 0
        || end_height < start_height
    {
        return Vec::new();
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let mut next_start = start_height;
    let mut segments = Vec::new();

    loop {
        let next_end = next_start
            .saturating_add(segment_span.saturating_sub(1))
            .min(end_height);
        segments.push(bounded_recovered_window_ranges(
            next_start, next_end, window, overlap,
        ));
        if next_end >= end_height {
            break;
        }
        next_start = next_start.saturating_add(segment_step);
    }

    segments
}

fn bounded_recovered_segment_fold_start_height(
    end_height: u64,
    window: u64,
    overlap: u64,
    windows_per_segment: u64,
    segments_per_fold: u64,
    fold_count: u64,
) -> u64 {
    if end_height == 0
        || window == 0
        || windows_per_segment == 0
        || segments_per_fold == 0
        || fold_count == 0
    {
        return 0;
    }

    let overlap = overlap.min(window.saturating_sub(1));
    let raw_step = if overlap < window {
        window - overlap
    } else {
        1
    };
    let segment_span =
        window.saturating_add(raw_step.saturating_mul(windows_per_segment.saturating_sub(1)));
    let segment_step = raw_step
        .saturating_mul(windows_per_segment.saturating_sub(1))
        .max(1);
    let fold_span = segment_span
        .saturating_add(segment_step.saturating_mul(segments_per_fold.saturating_sub(1)));
    let fold_step = segment_step
        .saturating_mul(segments_per_fold.saturating_sub(1))
        .max(1);
    let covered_span =
        fold_span.saturating_add(fold_step.saturating_mul(fold_count.saturating_sub(1)));
    end_height
        .saturating_sub(covered_span.saturating_sub(1))
        .max(1)
}

fn build_recovered_registry_state(
    seed_base: u8,
    expected_end_height: u64,
) -> (GuardianRegistry, MockState) {
    let registry = production_registry_without_accountable_membership_updates();
    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    let mut parent_block_hash = None;
    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (capsule, certificates, materials, recovered) =
            if let Some(parent_block_hash) = parent_block_hash {
                sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                    height,
                    seed,
                    parent_block_hash,
                )
            } else {
                sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
            };
        parent_block_hash = Some(recovered.block_commitment_hash);
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule,
            &certificates,
            &materials,
            &recovered,
        );
    }

    (registry, state)
}

fn assert_paged_recovered_prefixes_match_direct_extract(seed_base: u8, expected_end_height: u64) {
    let (_registry, state) = build_recovered_registry_state(seed_base, expected_end_height);
    let direct_certified =
        GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, expected_end_height)
            .expect("direct recovered certified-header prefix");
    let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
        &state,
        1,
        expected_end_height,
    )
    .expect("direct recovered restart block-header prefix");

    let start_height =
        bounded_recovered_segment_fold_start_height(expected_end_height, 5, 2, 5, 4, 2);
    let initial_segments =
        bounded_recovered_segment_ranges(start_height, expected_end_height, 5, 2, 5);
    let initial_segment_slices = initial_segments
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let mut stitched_certified =
        GuardianRegistry::extract_stitched_recovered_certified_header_segments(
            &state,
            &initial_segment_slices,
        )
        .expect("initial stitched recovered certified-header prefix");
    let mut stitched_restart =
        GuardianRegistry::extract_stitched_recovered_restart_block_header_segments(
            &state,
            &initial_segment_slices,
        )
        .expect("initial stitched recovered restart block-header prefix");
    let mut cursor = RecoveredSegmentFoldCursor::new(expected_end_height, 5, 2, 5, 4, 2)
        .expect("recovered segment-fold cursor");

    while stitched_restart
        .first()
        .map(|entry| entry.header.height)
        .unwrap_or(u64::MAX)
        > 1
    {
        let page = cursor
            .next_page()
            .expect("advance recovered segment-fold cursor")
            .expect("older recovered page");
        let page_certified =
            GuardianRegistry::extract_recovered_certified_header_page(&state, &page)
                .expect("paged recovered certified-header prefix");
        let page_restart =
            GuardianRegistry::extract_recovered_restart_block_header_page(&state, &page)
                .expect("paged recovered restart block-header prefix");
        stitched_certified = stitch_recovered_certified_header_segments(&[
            page_certified.as_slice(),
            stitched_certified.as_slice(),
        ])
        .expect("stitch paged recovered certified-header prefixes");
        stitched_restart = stitch_recovered_restart_block_header_segments(&[
            page_restart.as_slice(),
            stitched_restart.as_slice(),
        ])
        .expect("stitch paged recovered restart block-header prefixes");
    }

    assert_eq!(stitched_certified, direct_certified);
    assert_eq!(stitched_restart, direct_restart);
    assert_eq!(stitched_certified.len(), expected_end_height as usize);
    assert_eq!(stitched_restart.len(), expected_end_height as usize);
}

fn assert_stitched_recovered_prefixes_match_direct_extract(
    windows: &[(u64, u64)],
    seed_base: u8,
    expected_end_height: u64,
) {
    let registry = production_registry_without_accountable_membership_updates();
    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    let mut parent_block_hash = None;
    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (capsule, certificates, materials, recovered) =
            if let Some(parent_block_hash) = parent_block_hash {
                sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                    height,
                    seed,
                    parent_block_hash,
                )
            } else {
                sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
            };
        parent_block_hash = Some(recovered.block_commitment_hash);
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule,
            &certificates,
            &materials,
            &recovered,
        );
    }

    let direct_certified =
        GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, expected_end_height)
            .expect("direct recovered certified-header prefix");
    let stitched_certified =
        GuardianRegistry::extract_stitched_recovered_certified_header_prefix(&state, windows)
            .expect("stitched recovered certified-header prefix");
    assert_eq!(stitched_certified, direct_certified);
    assert_eq!(stitched_certified.len(), expected_end_height as usize);

    let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
        &state,
        1,
        expected_end_height,
    )
    .expect("direct recovered restart block-header prefix");
    let stitched_restart =
        GuardianRegistry::extract_stitched_recovered_restart_block_header_prefix(&state, windows)
            .expect("stitched recovered restart block-header prefix");
    assert_eq!(stitched_restart, direct_restart);
    assert_eq!(stitched_restart.len(), expected_end_height as usize);
    let tail_index = stitched_restart.len() - 1;
    assert_eq!(
        stitched_restart[tail_index].header.parent_qc,
        stitched_restart[tail_index - 1].certified_quorum_certificate()
    );
}

fn assert_aft_recovered_state_surface_matches_legacy_extractors_for_coding(
    coding: RecoveryCodingDescriptor,
    support_share_indices: &[u16],
    seed_base: u8,
) {
    let registry = production_registry_without_accountable_membership_updates();
    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    let (capsule_a, certificates_a, materials_a, recovered_a) =
        sample_recovered_publication_bundle_fixture_with_scheme(
            1,
            seed_base,
            coding,
            support_share_indices,
        );
    let (capsule_b, certificates_b, materials_b, recovered_b) =
        sample_recovered_publication_bundle_fixture_with_scheme_and_optional_omission(
            2,
            seed_base.wrapping_add(1),
            coding,
            support_share_indices,
            Some(recovered_a.block_commitment_hash),
            None,
        );
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

    let aft_state = GuardianRegistry::extract_aft_recovered_state_surface(&state, 1, 2)
        .expect("extract aft recovered state surface");
    assert_eq!(
        aft_state.replay_prefix,
        GuardianRegistry::extract_aft_recovered_replay_prefix(&state, 1, 2)
            .expect("extract replay prefix")
    );
    assert_eq!(
        aft_state.consensus_headers,
        GuardianRegistry::extract_aft_recovered_consensus_header_prefix(&state, 1, 2)
            .expect("extract consensus-header prefix")
    );
    assert_eq!(
        aft_state.certified_headers,
        GuardianRegistry::extract_aft_recovered_certified_header_prefix(&state, 1, 2)
            .expect("extract certified-header prefix")
    );
    assert_eq!(
        aft_state.restart_headers,
        GuardianRegistry::extract_aft_recovered_restart_header_prefix(&state, 1, 2)
            .expect("extract restart-header prefix")
    );
    assert_eq!(
        aft_state.restart_headers[1].header.parent_qc,
        aft_state.certified_headers[1].certified_parent_quorum_certificate
    );
}

fn assert_segment_stitched_recovered_prefixes_match_direct_extract(
    segments: &[&[(u64, u64)]],
    seed_base: u8,
    expected_end_height: u64,
) {
    let registry = production_registry_without_accountable_membership_updates();
    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    let mut parent_block_hash = None;
    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (capsule, certificates, materials, recovered) =
            if let Some(parent_block_hash) = parent_block_hash {
                sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                    height,
                    seed,
                    parent_block_hash,
                )
            } else {
                sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
            };
        parent_block_hash = Some(recovered.block_commitment_hash);
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule,
            &certificates,
            &materials,
            &recovered,
        );
    }

    let direct_certified =
        GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, expected_end_height)
            .expect("direct recovered certified-header prefix");
    let stitched_certified =
        GuardianRegistry::extract_stitched_recovered_certified_header_segments(&state, segments)
            .expect("segment-stitched recovered certified-header prefix");
    assert_eq!(stitched_certified, direct_certified);
    assert_eq!(stitched_certified.len(), expected_end_height as usize);

    let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
        &state,
        1,
        expected_end_height,
    )
    .expect("direct recovered restart block-header prefix");
    let stitched_restart =
        GuardianRegistry::extract_stitched_recovered_restart_block_header_segments(
            &state, segments,
        )
        .expect("segment-stitched recovered restart block-header prefix");
    assert_eq!(stitched_restart, direct_restart);
    assert_eq!(stitched_restart.len(), expected_end_height as usize);
    let tail_index = stitched_restart.len() - 1;
    assert_eq!(
        stitched_restart[tail_index].header.parent_qc,
        stitched_restart[tail_index - 1].certified_quorum_certificate()
    );
}

fn assert_segment_fold_stitched_recovered_prefixes_match_direct_extract(
    segment_folds: &[Vec<Vec<(u64, u64)>>],
    seed_base: u8,
    expected_end_height: u64,
) {
    let registry = production_registry_without_accountable_membership_updates();
    let mut state = MockState::default();
    state
        .insert(
            VALIDATOR_SET_KEY,
            &write_validator_sets(&validator_sets(&[(18, 1), (145, 1), (19, 1)])).unwrap(),
        )
        .unwrap();

    let mut parent_block_hash = None;
    for (offset, height) in (1u64..=expected_end_height).enumerate() {
        let seed = seed_base.wrapping_add(offset as u8);
        let (capsule, certificates, materials, recovered) =
            if let Some(parent_block_hash) = parent_block_hash {
                sample_recovered_publication_bundle_fixture_3_of_7_with_parent(
                    height,
                    seed,
                    parent_block_hash,
                )
            } else {
                sample_recovered_publication_bundle_fixture_3_of_7(height, seed)
            };
        parent_block_hash = Some(recovered.block_commitment_hash);
        publish_recovered_publication_fixture(
            &registry,
            &mut state,
            &capsule,
            &certificates,
            &materials,
            &recovered,
        );
    }

    let direct_certified =
        GuardianRegistry::extract_recovered_certified_header_prefix(&state, 1, expected_end_height)
            .expect("direct recovered certified-header prefix");
    let stitched_certified =
        GuardianRegistry::extract_stitched_recovered_certified_header_segment_folds(
            &state,
            segment_folds,
        )
        .expect("segment-fold-stitched recovered certified-header prefix");
    assert_eq!(stitched_certified, direct_certified);
    assert_eq!(stitched_certified.len(), expected_end_height as usize);

    let direct_restart = GuardianRegistry::extract_recovered_restart_block_header_prefix(
        &state,
        1,
        expected_end_height,
    )
    .expect("direct recovered restart block-header prefix");
    let stitched_restart =
        GuardianRegistry::extract_stitched_recovered_restart_block_header_segment_folds(
            &state,
            segment_folds,
        )
        .expect("segment-fold-stitched recovered restart block-header prefix");
    assert_eq!(stitched_restart, direct_restart);
    assert_eq!(stitched_restart.len(), expected_end_height as usize);
    let tail_index = stitched_restart.len() - 1;
    assert_eq!(
        stitched_restart[tail_index].header.parent_qc,
        stitched_restart[tail_index - 1].certified_quorum_certificate()
    );
}

