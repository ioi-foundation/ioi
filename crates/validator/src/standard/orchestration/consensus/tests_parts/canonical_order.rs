#[test]
fn advance_recovered_tip_anchor_along_stitched_restart_windows_accepts_overlapping_windows() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 120,
        state_root: vec![0xC1; 32],
        block_hash: [0xD1; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 121, 40, 8, 0xE1);
    let windows = bounded_recovered_window_ranges(
        current_anchor.height + 1,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(windows, vec![(121, 125), (124, 128)]);

    let windows = stitched_restart_windows(&branch, 121, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("stitched overlapping recovered windows should advance");

    assert_eq!(anchor.height, 128);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 130,
        state_root: vec![0xD1; 32],
        block_hash: [0xE1; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 131, 50, 8, 0xF1);
    let windows = bounded_recovered_window_ranges(
        131,
        138,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 131, &windows);
    let first_window = stitched_windows[0];
    let mut second_window = stitched_windows[1].to_vec();
    second_window[0].header.parent_qc.block_hash[0] ^= 0xFF;

    let error =
        stitch_recovered_restart_block_header_windows(&[first_window, second_window.as_slice()])
            .expect_err("conflicting overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_windows_accepts_recursive_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 220,
        state_root: vec![0x21; 32],
        block_hash: [0x31; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 221, 60, 11, 0x41);
    let windows = bounded_recovered_window_ranges(
        current_anchor.height + 1,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(windows, vec![(221, 225), (224, 228), (227, 231)]);

    let windows = stitched_restart_windows(&branch, 221, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("three stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched recovered windows should advance");

    assert_eq!(anchor.height, 231);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_middle_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 230,
        state_root: vec![0x22; 32],
        block_hash: [0x32; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 231, 70, 11, 0x42);
    let windows = bounded_recovered_window_ranges(
        231,
        241,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 231, &windows);
    let first_window = stitched_windows[0];
    let mut second_window = stitched_windows[1].to_vec();
    let third_window = stitched_windows[2];
    second_window[3].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window.as_slice(),
        third_window,
    ])
    .expect_err("conflicting middle overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_four_stitched_restart_windows_accepts_bounded_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 240,
        state_root: vec![0x23; 32],
        block_hash: [0x33; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 241, 80, 14, 0x43);
    let start_height = bounded_recovered_window_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        4,
    );
    assert_eq!(start_height, 241);
    let windows = bounded_recovered_window_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        windows,
        vec![(241, 245), (244, 248), (247, 251), (250, 254)]
    );

    let windows = stitched_restart_windows(&branch, 241, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("four stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("four stitched recovered windows should advance");

    assert_eq!(anchor.height, 254);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_fourth_window_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 250,
        state_root: vec![0x24; 32],
        block_hash: [0x34; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 251, 90, 14, 0x44);
    let windows = bounded_recovered_window_ranges(
        251,
        264,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let stitched_windows = stitched_restart_windows(&branch, 251, &windows);
    let first_window = stitched_windows[0];
    let second_window = stitched_windows[1];
    let third_window = stitched_windows[2];
    let mut fourth_window = stitched_windows[3].to_vec();
    fourth_window[0].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window,
        third_window,
        fourth_window.as_slice(),
    ])
    .expect_err("conflicting fourth-window overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_five_stitched_restart_windows_accepts_configured_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 270,
        state_root: vec![0x25; 32],
        block_hash: [0x35; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 271, 100, 17, 0x45);
    let start_height = bounded_recovered_window_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(start_height, 271);
    let windows = bounded_recovered_window_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        windows,
        vec![(271, 275), (274, 278), (277, 281), (280, 284), (283, 287)]
    );

    let windows = stitched_restart_windows(&branch, 271, &windows);
    let stitched = stitch_recovered_restart_block_header_windows(&windows)
        .expect("five stitched recovered restart windows");
    let parent_qc = stitched
        .last()
        .expect("stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("five stitched recovered windows should advance");

    assert_eq!(anchor.height, 287);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_windows_rejects_conflicting_interior_overlap_in_five_window_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 280,
        state_root: vec![0x26; 32],
        block_hash: [0x36; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 281, 110, 17, 0x46);
    let mut windows = bounded_stitched_restart_windows(
        &branch,
        281,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let first_window = windows.remove(0);
    let second_window = windows.remove(0);
    let mut third_window = windows.remove(0).to_vec();
    let fourth_window = windows.remove(0);
    let fifth_window = windows.remove(0);
    third_window[3].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_windows(&[
        first_window,
        second_window,
        third_window.as_slice(),
        fourth_window,
        fifth_window,
    ])
    .expect_err("conflicting interior overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_two_stitched_restart_segments_accepts_recursive_segment_composition(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 300,
        state_root: vec![0x27; 32],
        block_hash: [0x37; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 301, 120, 29, 0x47);
    let first_segment_windows = bounded_recovered_window_ranges(
        301,
        317,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let second_segment_windows = bounded_recovered_window_ranges(
        313,
        329,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    assert_eq!(
        first_segment_windows,
        vec![(301, 305), (304, 308), (307, 311), (310, 314), (313, 317)]
    );
    assert_eq!(
        second_segment_windows,
        vec![(313, 317), (316, 320), (319, 323), (322, 326), (325, 329)]
    );

    let first_segment = stitched_restart_segment(&branch, 301, &first_segment_windows);
    let second_segment = stitched_restart_segment(&branch, 301, &second_segment_windows);
    let stitched = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
    ])
    .expect("two stitched restart segments should compose");
    let parent_qc = stitched
        .last()
        .expect("segment-stitched branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("segment-stitched recovered restart branch should advance");

    assert_eq!(anchor.height, 329);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-stitched branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_segment_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 330,
        state_root: vec![0x28; 32],
        block_hash: [0x38; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 331, 130, 29, 0x48);
    let first_segment_windows = bounded_recovered_window_ranges(
        331,
        347,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );
    let second_segment_windows = bounded_recovered_window_ranges(
        343,
        359,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
    );

    let first_segment = stitched_restart_segment(&branch, 331, &first_segment_windows);
    let mut second_segment = stitched_restart_segment(&branch, 331, &second_segment_windows);
    second_segment[1].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
    ])
    .expect_err("conflicting segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_segments_accepts_recursive_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 360,
        state_root: vec![0x29; 32],
        block_hash: [0x39; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 361, 140, 41, 0x49);
    let segments = bounded_recovered_segment_ranges(
        361,
        401,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(
        segments,
        vec![
            vec![(361, 365), (364, 368), (367, 371), (370, 374), (373, 377)],
            vec![(373, 377), (376, 380), (379, 383), (382, 386), (385, 389)],
            vec![(385, 389), (388, 392), (391, 395), (394, 398), (397, 401)],
        ]
    );

    let stitched = stitched_restart_segment_fold(&branch, 361, &segments);
    let parent_qc = stitched
        .last()
        .expect("segment-fold branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched restart segments should advance");

    assert_eq!(anchor.height, 401);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_middle_segment_overlap_in_three_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 390,
        state_root: vec![0x2A; 32],
        block_hash: [0x3A; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 391, 150, 41, 0x4A);
    let segments = bounded_recovered_segment_ranges(
        391,
        431,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    let first_segment = stitched_restart_segment(&branch, 391, &segments[0]);
    let mut middle_segment = stitched_restart_segment(&branch, 391, &segments[1]);
    let third_segment = stitched_restart_segment(&branch, 391, &segments[2]);
    middle_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        middle_segment.as_slice(),
        third_segment.as_slice(),
    ])
    .expect_err("conflicting middle-segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_four_stitched_restart_segments_accepts_live_segment_fold() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 420,
        state_root: vec![0x2B; 32],
        block_hash: [0x3B; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 421, 160, 53, 0x4B);
    let start_height = bounded_recovered_segment_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(start_height, 421);
    let segments = bounded_recovered_segment_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    assert_eq!(
        segments,
        vec![
            vec![(421, 425), (424, 428), (427, 431), (430, 434), (433, 437)],
            vec![(433, 437), (436, 440), (439, 443), (442, 446), (445, 449)],
            vec![(445, 449), (448, 452), (451, 455), (454, 458), (457, 461)],
            vec![(457, 461), (460, 464), (463, 467), (466, 470), (469, 473)],
        ]
    );

    let stitched = stitched_restart_segment_fold(&branch, 421, &segments);
    let parent_qc = stitched
        .last()
        .expect("segment-fold branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("four stitched restart segments should advance");

    assert_eq!(anchor.height, 473);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segments_rejects_conflicting_interior_segment_overlap_in_four_segment_fold(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 450,
        state_root: vec![0x2C; 32],
        block_hash: [0x3C; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 451, 170, 53, 0x4C);
    let segments = bounded_recovered_segment_ranges(
        451,
        503,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
    );
    let first_segment = stitched_restart_segment(&branch, 451, &segments[0]);
    let second_segment = stitched_restart_segment(&branch, 451, &segments[1]);
    let mut third_segment = stitched_restart_segment(&branch, 451, &segments[2]);
    let fourth_segment = stitched_restart_segment(&branch, 451, &segments[3]);
    third_segment[12].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_segment.as_slice(),
        second_segment.as_slice(),
        third_segment.as_slice(),
        fourth_segment.as_slice(),
    ])
    .expect_err("conflicting interior segment overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_two_stitched_restart_segment_folds_accepts_recursive_fold_of_folds(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 480,
        state_root: vec![0x2D; 32],
        block_hash: [0x3D; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 481, 180, 89, 0x4D);
    let start_height = bounded_recovered_segment_fold_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET,
    );
    assert_eq!(start_height, 481);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(
        segment_folds,
        vec![
            vec![
                vec![(481, 485), (484, 488), (487, 491), (490, 494), (493, 497)],
                vec![(493, 497), (496, 500), (499, 503), (502, 506), (505, 509)],
                vec![(505, 509), (508, 512), (511, 515), (514, 518), (517, 521)],
                vec![(517, 521), (520, 524), (523, 527), (526, 530), (529, 533)],
            ],
            vec![
                vec![(517, 521), (520, 524), (523, 527), (526, 530), (529, 533)],
                vec![(529, 533), (532, 536), (535, 539), (538, 542), (541, 545)],
                vec![(541, 545), (544, 548), (547, 551), (550, 554), (553, 557)],
                vec![(553, 557), (556, 560), (559, 563), (562, 566), (565, 569)],
            ],
        ]
    );

    let stitched = stitched_restart_segment_fold_of_folds(&branch, 481, &segment_folds);
    let parent_qc = stitched
        .last()
        .expect("segment-fold-of-folds branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("two stitched restart segment folds should advance");

    assert_eq!(anchor.height, 569);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("segment-fold-of-folds branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn stitch_recovered_restart_segment_folds_rejects_conflicting_inter_fold_overlap() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 520,
        state_root: vec![0x2E; 32],
        block_hash: [0x3E; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 521, 190, 89, 0x4E);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        521,
        609,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    let first_fold = stitched_restart_segment_fold(&branch, 521, &segment_folds[0]);
    let mut second_fold = stitched_restart_segment_fold(&branch, 521, &segment_folds[1]);
    second_fold[8].header.parent_qc.block_hash[0] ^= 0xFF;

    let error = stitch_recovered_restart_block_header_segments(&[
        first_fold.as_slice(),
        second_fold.as_slice(),
    ])
    .expect_err("conflicting inter-fold overlap should be rejected");
    assert!(
        error.contains("overlap mismatch"),
        "unexpected stitch error: {error}"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_three_stitched_restart_segment_folds_accepts_recursive_fold_of_folds(
) {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 560,
        state_root: vec![0x2F; 32],
        block_hash: [0x3F; 32],
    };
    let branch = sample_recovered_restart_branch(&current_anchor, 561, 200, 125, 0x4F);
    let start_height = bounded_recovered_segment_fold_start_height(
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
        3,
    );
    assert_eq!(start_height, 561);
    let segment_folds = bounded_recovered_segment_fold_ranges(
        start_height,
        current_anchor.height + branch.len() as u64,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
        AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET,
        DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET,
    );
    assert_eq!(segment_folds.len(), 3);
    assert_eq!(
        segment_folds[0],
        vec![
            vec![(561, 565), (564, 568), (567, 571), (570, 574), (573, 577)],
            vec![(573, 577), (576, 580), (579, 583), (582, 586), (585, 589)],
            vec![(585, 589), (588, 592), (591, 595), (594, 598), (597, 601)],
            vec![(597, 601), (600, 604), (603, 607), (606, 610), (609, 613)],
        ]
    );
    assert_eq!(
        segment_folds[1],
        vec![
            vec![(597, 601), (600, 604), (603, 607), (606, 610), (609, 613)],
            vec![(609, 613), (612, 616), (615, 619), (618, 622), (621, 625)],
            vec![(621, 625), (624, 628), (627, 631), (630, 634), (633, 637)],
            vec![(633, 637), (636, 640), (639, 643), (642, 646), (645, 649)],
        ]
    );
    assert_eq!(
        segment_folds[2],
        vec![
            vec![(633, 637), (636, 640), (639, 643), (642, 646), (645, 649)],
            vec![(645, 649), (648, 652), (651, 655), (654, 658), (657, 661)],
            vec![(657, 661), (660, 664), (663, 667), (666, 670), (669, 673)],
            vec![(669, 673), (672, 676), (675, 679), (678, 682), (681, 685)],
        ]
    );

    let stitched = stitched_restart_segment_fold_of_folds(&branch, 561, &segment_folds);
    let parent_qc = stitched
        .last()
        .expect("three-fold segment composition branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &stitched)
            .expect("three stitched restart segment folds should advance");

    assert_eq!(anchor.height, 685);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        stitched
            .last()
            .expect("three-fold segment composition branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

