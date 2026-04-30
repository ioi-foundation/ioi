#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_local_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(1, 3);
    let qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [44u8; 32],
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, 0);
    assert!(
            <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::take_pending_quorum_certificates(
                &mut engine,
            )
            .is_empty()
        );
    assert!(engine.safety.next_ready_commit().is_none());
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_local_header() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(1, 3);
    let header = build_progress_parent_header(1, 0);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);
    let qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
    assert!(engine.safety.next_ready_commit().is_none());
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_previous_anchor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(2, 3);

    let previous_collapse = test_canonical_collapse_object(1, None, [60u8; 32], [61u8; 32]);
    let mut header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, 0);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_without_carried_previous_collapse_certificate(
) {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(2, 3);

    let previous_collapse = test_canonical_collapse_object(1, None, [70u8; 32], [71u8; 32]);
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    header.canonical_collapse_extension_certificate = None;
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 2);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_does_not_advance_with_mismatched_local_previous_collapse(
) {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [72u8; 32], [73u8; 32]);
    let previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [74u8; 32], [75u8; 32]);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let mut wrong_certificate =
        extension_certificate_from_predecessor(&previous_collapse, header.height);
    wrong_certificate.predecessor_recursive_proof_hash[0] ^= 0xFF;
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
    header.canonical_collapse_extension_certificate = Some(wrong_certificate);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 3);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_recursive_proof_backed_predecessor() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [76u8; 32], [77u8; 32]);
    let previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [78u8; 32], [79u8; 32]);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_collapse_chain(
        &mut header,
        &[previous_collapse.clone(), grandparent_collapse.clone()],
    );
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_advances_with_valid_succinct_predecessor_proof() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [80u8; 32], [81u8; 32]);
    let mut previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [82u8; 32], [83u8; 32]);
    bind_succinct_mock_continuity(&mut previous_collapse);
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    link_header_to_previous_collapse(&mut header, &previous_collapse);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc.clone(),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, qc.height);
    assert_eq!(engine.highest_qc.block_hash, qc.block_hash);
}

#[tokio::test]
async fn asymptote_handle_quorum_certificate_rejects_invalid_succinct_predecessor_proof() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    engine.remember_validator_count(3, 3);

    let grandparent_collapse = test_canonical_collapse_object(1, None, [84u8; 32], [85u8; 32]);
    let mut previous_collapse =
        test_canonical_collapse_object(2, Some(&grandparent_collapse), [86u8; 32], [87u8; 32]);
    bind_succinct_mock_continuity(&mut previous_collapse);
    previous_collapse
        .continuity_recursive_proof
        .proof_bytes
        .reverse();
    engine
        .committed_collapses
        .insert(grandparent_collapse.height, grandparent_collapse.clone());
    engine
        .committed_collapses
        .insert(previous_collapse.height, previous_collapse.clone());

    let mut header = build_progress_parent_header(3, 0);
    header.previous_canonical_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&previous_collapse).unwrap();
    header.canonical_collapse_extension_certificate = Some(CanonicalCollapseExtensionCertificate {
        predecessor_commitment: canonical_collapse_commitment(&previous_collapse),
        predecessor_recursive_proof_hash: canonical_collapse_recursive_proof_hash(
            &previous_collapse.continuity_recursive_proof,
        )
        .unwrap(),
    });
    header.parent_state_root = StateRoot(previous_collapse.resulting_state_root_hash.to_vec());
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);

    let qc = QuorumCertificate {
        height: 3,
        view: 0,
        block_hash,
        signatures: vec![
            (AccountId([1u8; 32]), vec![1u8]),
            (AccountId([2u8; 32]), vec![2u8]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        qc,
    )
    .await
    .unwrap();

    assert!(engine.highest_qc.height < 3);
}
