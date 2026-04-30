#[test]
fn parent_ref_from_last_committed_or_recovered_tip_prefers_committed_block() {
    let block = sample_block(11, 0x41);
    let recovered_tip = RecoveredConsensusTipAnchor {
        height: 11,
        state_root: vec![0x99; 32],
        block_hash: [0x55; 32],
    };

    let parent_ref =
        parent_ref_from_last_committed_or_recovered_tip(&Some(block.clone()), Some(&recovered_tip))
            .expect("parent ref")
            .expect("committed block parent ref");

    assert_eq!(parent_ref.height, block.header.height);
    assert_eq!(parent_ref.state_root, block.header.state_root.0);
    assert_eq!(
        parent_ref.block_hash,
        to_root_hash(&block.header.hash().expect("block hash"))
            .expect("state hash from committed block")
    );
}

#[test]
fn parent_ref_from_last_committed_or_recovered_tip_uses_recovered_tip_when_block_absent() {
    let recovered_tip = RecoveredConsensusTipAnchor {
        height: 13,
        state_root: vec![0x77; 32],
        block_hash: [0x88; 32],
    };

    let parent_ref = parent_ref_from_last_committed_or_recovered_tip(&None, Some(&recovered_tip))
        .expect("parent ref")
        .expect("recovered tip parent ref");

    assert_eq!(parent_ref.height, recovered_tip.height);
    assert_eq!(parent_ref.state_root, recovered_tip.state_root);
    assert_eq!(parent_ref.block_hash, recovered_tip.block_hash);
}

#[test]
fn recovered_consensus_tip_anchor_from_parts_requires_matching_header_height() {
    let collapse = CanonicalCollapseObject {
        height: 17,
        ordering: CanonicalOrderingCollapse {
            height: 17,
            kind: CanonicalCollapseKind::Close,
            ..Default::default()
        },
        resulting_state_root_hash: [0x33; 32],
        ..Default::default()
    };

    assert!(
        recovered_consensus_tip_anchor_from_parts(&collapse, &[]).is_none(),
        "missing recovered header should not produce a restart tip anchor"
    );

    let header = RecoveredCanonicalHeaderEntry {
        height: 17,
        canonical_block_commitment_hash: [0x44; 32],
        resulting_state_root_hash: collapse.resulting_state_root_hash,
        ..Default::default()
    };
    let anchor = recovered_consensus_tip_anchor_from_parts(&collapse, &[header.clone()])
        .expect("restart tip anchor");
    assert_eq!(anchor.height, collapse.height);
    assert_eq!(anchor.state_root, collapse.resulting_state_root_hash);
    assert_eq!(anchor.block_hash, header.canonical_block_commitment_hash);
}

#[test]
fn recovered_consensus_tip_anchor_from_header_uses_recovered_state_root() {
    let header = RecoveredCanonicalHeaderEntry {
        height: 21,
        canonical_block_commitment_hash: [0x71; 32],
        resulting_state_root_hash: [0x72; 32],
        ..Default::default()
    };

    let anchor = recovered_consensus_tip_anchor_from_header(&header);

    assert_eq!(anchor.height, header.height);
    assert_eq!(anchor.block_hash, header.canonical_block_commitment_hash);
    assert_eq!(anchor.state_root, header.resulting_state_root_hash);
}

#[test]
fn reconcile_recovered_tip_anchor_with_parent_qc_accepts_matching_recovered_branch() {
    let parent_ref = StateRef {
        height: 23,
        state_root: vec![0x83; 32],
        block_hash: [0x90; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 23,
        view: 9,
        block_hash: [0x91; 32],
        ..Default::default()
    };
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 23,
        view: 9,
        canonical_block_commitment_hash: [0x91; 32],
        resulting_state_root_hash: [0x83; 32],
        ..Default::default()
    };

    let anchor =
        reconcile_recovered_tip_anchor_with_parent_qc(&parent_ref, &parent_qc, &recovered_header)
            .expect("matching recovered branch should reconcile");

    assert_eq!(anchor.height, parent_ref.height);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, parent_ref.state_root);
}

#[test]
fn reconcile_recovered_tip_anchor_with_parent_qc_rejects_state_root_mismatch() {
    let parent_ref = StateRef {
        height: 24,
        state_root: vec![0x84; 32],
        block_hash: [0x90; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 24,
        view: 3,
        block_hash: [0x92; 32],
        ..Default::default()
    };
    let recovered_header = RecoveredCanonicalHeaderEntry {
        height: 24,
        view: 3,
        canonical_block_commitment_hash: [0x92; 32],
        resulting_state_root_hash: [0x99; 32],
        ..Default::default()
    };

    assert!(
        reconcile_recovered_tip_anchor_with_parent_qc(&parent_ref, &parent_qc, &recovered_header)
            .is_none(),
        "state-root mismatch should not reconcile a recovered restart branch"
    );
}

#[test]
fn advance_recovered_tip_anchor_with_certified_parent_qc_accepts_matching_recovered_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 24,
        state_root: vec![0x94; 32],
        block_hash: [0xa4; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 25,
        view: 6,
        block_hash: [0xa5; 32],
        ..Default::default()
    };
    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 25,
            view: 6,
            canonical_block_commitment_hash: [0xa5; 32],
            parent_block_commitment_hash: [0xa4; 32],
            resulting_state_root_hash: [0x95; 32],
            ..Default::default()
        },
        certified_parent_quorum_certificate: QuorumCertificate {
            height: 24,
            view: 5,
            block_hash: [0xa4; 32],
            ..Default::default()
        },
        certified_parent_resulting_state_root_hash: [0x94; 32],
    };

    let anchor = advance_recovered_tip_anchor_with_certified_parent_qc(
        &current_anchor,
        &parent_qc,
        &recovered_entry,
    )
    .expect("matching recovered certified branch should advance");

    assert_eq!(anchor.height, 25);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x95; 32]);
}

#[test]
fn advance_recovered_tip_anchor_with_certified_parent_qc_rejects_parent_root_mismatch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 24,
        state_root: vec![0x94; 32],
        block_hash: [0xa4; 32],
    };
    let parent_qc = QuorumCertificate {
        height: 25,
        view: 6,
        block_hash: [0xa5; 32],
        ..Default::default()
    };
    let recovered_entry = RecoveredCertifiedHeaderEntry {
        header: RecoveredCanonicalHeaderEntry {
            height: 25,
            view: 6,
            canonical_block_commitment_hash: [0xa5; 32],
            parent_block_commitment_hash: [0xa4; 32],
            resulting_state_root_hash: [0x95; 32],
            ..Default::default()
        },
        certified_parent_quorum_certificate: QuorumCertificate {
            height: 24,
            view: 5,
            block_hash: [0xa4; 32],
            ..Default::default()
        },
        certified_parent_resulting_state_root_hash: [0xff; 32],
    };

    assert!(
        advance_recovered_tip_anchor_with_certified_parent_qc(
            &current_anchor,
            &parent_qc,
            &recovered_entry
        )
        .is_none(),
        "parent state-root mismatch should not advance a recovered certified branch"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_two_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 30,
        state_root: vec![0x31; 32],
        block_hash: [0x41; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        31,
        7,
        0x51,
        0x61,
        0x71,
        0x81,
        0x91,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 32, 8, 0x52, 0x62, 0x72, 0x82, 0x92);
    let parent_qc = step_two.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one.clone(), step_two.clone()],
    )
    .expect("two-step recovered branch should advance");

    assert_eq!(anchor.height, 32);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x72; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 40,
        state_root: vec![0x41; 32],
        block_hash: [0x51; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        41,
        9,
        0x61,
        0x71,
        0x81,
        0x91,
        0xA1,
    );
    let mut step_two =
        sample_recovered_restart_step(None, Some(&step_one), 42, 10, 0x62, 0x72, 0x82, 0x92, 0xA2);
    step_two.header.parent_state_root = StateRoot(vec![0xFF; 32]);
    let parent_qc = step_two.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two],
        )
        .is_none(),
        "conflicting recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_three_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 50,
        state_root: vec![0x51; 32],
        block_hash: [0x61; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        51,
        11,
        0x71,
        0x81,
        0x91,
        0xA1,
        0xB1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 52, 12, 0x72, 0x82, 0x92, 0xA2, 0xB2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 53, 13, 0x73, 0x83, 0x93, 0xA3, 0xB3);
    let parent_qc = step_three.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one, step_two, step_three],
    )
    .expect("three-step recovered branch should advance");

    assert_eq!(anchor.height, 53);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0x93; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_third_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 60,
        state_root: vec![0x61; 32],
        block_hash: [0x71; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        61,
        14,
        0x81,
        0x91,
        0xA1,
        0xB1,
        0xC1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 62, 15, 0x82, 0x92, 0xA2, 0xB2, 0xC2);
    let mut step_three =
        sample_recovered_restart_step(None, Some(&step_two), 63, 16, 0x83, 0x93, 0xA3, 0xB3, 0xC3);
    step_three.header.parent_qc.block_hash[0] ^= 0xFF;
    let parent_qc = step_three.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two, step_three],
        )
        .is_none(),
        "conflicting third-step recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_four_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 70,
        state_root: vec![0x71; 32],
        block_hash: [0x81; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        71,
        17,
        0x91,
        0xA1,
        0xB1,
        0xC1,
        0xD1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 72, 18, 0x92, 0xA2, 0xB2, 0xC2, 0xD2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 73, 19, 0x93, 0xA3, 0xB3, 0xC3, 0xD3);
    let step_four = sample_recovered_restart_step(
        None,
        Some(&step_three),
        74,
        20,
        0x94,
        0xA4,
        0xB4,
        0xC4,
        0xD4,
    );
    let parent_qc = step_four.certified_quorum_certificate();

    let anchor = advance_recovered_tip_anchor_along_restart_headers(
        &current_anchor,
        &parent_qc,
        &[step_one, step_two, step_three, step_four],
    )
    .expect("four-step recovered branch should advance");

    assert_eq!(anchor.height, 74);
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(anchor.state_root, vec![0xB4; 32]);
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_fourth_step_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 80,
        state_root: vec![0x81; 32],
        block_hash: [0x91; 32],
    };
    let step_one = sample_recovered_restart_step(
        Some(&current_anchor),
        None,
        81,
        21,
        0xA1,
        0xB1,
        0xC1,
        0xD1,
        0xE1,
    );
    let step_two =
        sample_recovered_restart_step(None, Some(&step_one), 82, 22, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2);
    let step_three =
        sample_recovered_restart_step(None, Some(&step_two), 83, 23, 0xA3, 0xB3, 0xC3, 0xD3, 0xE3);
    let mut step_four = sample_recovered_restart_step(
        None,
        Some(&step_three),
        84,
        24,
        0xA4,
        0xB4,
        0xC4,
        0xD4,
        0xE4,
    );
    step_four.header.parent_qc.block_hash[0] ^= 0xFF;
    let parent_qc = step_four.certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(
            &current_anchor,
            &parent_qc,
            &[step_one, step_two, step_three, step_four],
        )
        .is_none(),
        "conflicting fourth-step recovered restart branch should be rejected"
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_accepts_configured_window_branch() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 90,
        state_root: vec![0x91; 32],
        block_hash: [0xA1; 32],
    };
    let branch = sample_recovered_restart_branch(
        &current_anchor,
        91,
        25,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW as usize,
        0xB1,
    );
    let parent_qc = branch
        .last()
        .expect("configured branch tail")
        .certified_quorum_certificate();

    let anchor =
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &branch)
            .expect("configured-window recovered branch should advance");

    assert_eq!(
        anchor.height,
        current_anchor.height + AFT_RECOVERED_CONSENSUS_HEADER_WINDOW
    );
    assert_eq!(anchor.block_hash, parent_qc.block_hash);
    assert_eq!(
        anchor.state_root,
        branch
            .last()
            .expect("configured branch tail")
            .certified_header
            .header
            .resulting_state_root_hash
            .to_vec()
    );
}

#[test]
fn advance_recovered_tip_anchor_along_restart_headers_rejects_conflicting_configured_window_tail() {
    let current_anchor = RecoveredConsensusTipAnchor {
        height: 100,
        state_root: vec![0xA1; 32],
        block_hash: [0xB1; 32],
    };
    let mut branch = sample_recovered_restart_branch(
        &current_anchor,
        101,
        30,
        AFT_RECOVERED_CONSENSUS_HEADER_WINDOW as usize,
        0xC1,
    );
    branch
        .last_mut()
        .expect("configured branch tail")
        .header
        .parent_qc
        .block_hash[0] ^= 0xFF;
    let parent_qc = branch
        .last()
        .expect("configured branch tail")
        .certified_quorum_certificate();

    assert!(
        advance_recovered_tip_anchor_along_restart_headers(&current_anchor, &parent_qc, &branch)
            .is_none(),
        "conflicting configured-window recovered restart branch should be rejected"
    );
}

