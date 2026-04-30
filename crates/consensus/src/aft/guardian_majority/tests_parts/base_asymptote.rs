#[test]
fn verify_canonical_collapse_backend_accepts_and_rejects_succinct_mock_proofs() {
    let engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    let mut collapse = test_canonical_collapse_object(1, None, [0x21u8; 32], [0x22u8; 32]);
    let proof = &mut collapse.continuity_recursive_proof;
    let public_inputs = canonical_collapse_continuity_public_inputs(
        &proof.commitment,
        proof.previous_canonical_collapse_commitment_hash,
        proof.payload_hash,
        proof.previous_recursive_proof_hash,
    );
    proof.proof_system = CanonicalCollapseContinuityProofSystem::SuccinctSp1V1;
    proof.proof_bytes = canonical_collapse_succinct_mock_proof_bytes(&public_inputs)
        .expect("succinct mock proof bytes");

    engine
        .verify_canonical_collapse_backend(&collapse)
        .expect("succinct backend proof should verify");

    let mut mutated = collapse.clone();
    mutated.continuity_recursive_proof.proof_bytes[0] ^= 0xFF;
    assert!(engine.verify_canonical_collapse_backend(&mutated).is_err());
}

#[test]
fn verifies_valid_guardian_certificate() {
    let (engine, header, manifest, preimage, _, _) = build_case(&[(0, 0), (1, 1)]);
    engine
        .verify_guardianized_certificate_against_manifest(&header, &preimage, &manifest)
        .unwrap();
}

#[tokio::test]
async fn local_timeout_does_not_enter_new_view_without_timeout_certificate() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::GuardianMajority, Duration::ZERO);

    let first: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[0], 1, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        first,
        ConsensusDecision::Timeout { view: 1, height: 1 }
    ));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);

    let second: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[0], 1, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(second, ConsensusDecision::WaitForBlock));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);
}

#[tokio::test]
async fn bootstrap_grace_pins_view_zero_without_blocking_leader_production() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine = GuardianMajorityEngine::with_view_timeout(
        AftSafetyMode::GuardianMajority,
        Duration::from_secs(5),
    );
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock { view: 0, .. }
    ));
    assert_eq!(engine.pacemaker.lock().await.current_view, 0);
}

#[tokio::test]
async fn asymptote_decide_times_out_when_parent_qc_is_not_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let parent_view = build_decide_parent_view(validators.clone());
    let known_peers = HashSet::from([PeerId::random()]);
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.highest_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [77u8; 32],
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::Timeout { view: 1, height: 2 }
    ));
}

#[tokio::test]
async fn asymptote_decide_produces_when_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
    let collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&collapse).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    engine.highest_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock {
            view: 0,
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            ..
        } if previous_canonical_collapse_commitment_hash == collapse_commitment_hash
            && canonical_collapse_extension_certificate.as_ref()
                == Some(&extension_certificate_from_predecessor(&collapse, 2))
    ));
}

#[tokio::test]
async fn asymptote_decide_produces_canonical_collapse_extension_certificate_when_available() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let grandparent_header = build_progress_parent_header(1, 0);
    let grandparent_collapse = derive_canonical_collapse_object(&grandparent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(grandparent_header.height),
        codec::to_bytes_canonical(&grandparent_collapse).unwrap(),
    );

    let mut parent_header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut parent_header, &grandparent_collapse);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let parent_collapse = derive_canonical_collapse_object_with_previous(
        &parent_header,
        &[],
        Some(&grandparent_collapse),
    )
    .unwrap();
    let parent_collapse_commitment_hash =
        canonical_collapse_commitment_hash_from_object(&parent_collapse).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&parent_collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header);
    engine.highest_qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[2], 3, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        decision,
        ConsensusDecision::ProduceBlock {
            view: 0,
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            ..
        } if previous_canonical_collapse_commitment_hash == parent_collapse_commitment_hash
            && canonical_collapse_extension_certificate.as_ref()
                == Some(&extension_certificate_from_predecessor(&parent_collapse, 3))
    ));
}

#[tokio::test]
async fn asymptote_decide_stalls_when_previous_collapse_is_missing_for_current_height() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let parent_of_parent_header = build_progress_parent_header(1, 0);
    let parent_of_parent_collapse =
        derive_canonical_collapse_object(&parent_of_parent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_of_parent_header.height),
        codec::to_bytes_canonical(&parent_of_parent_collapse).unwrap(),
    );

    let mut parent_header = build_progress_parent_header(2, 0);
    link_header_to_previous_collapse(&mut parent_header, &parent_of_parent_collapse);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    engine.highest_qc = QuorumCertificate {
        height: 2,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };

    let decision: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[2], 3, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(decision, ConsensusDecision::Stall));
}

#[tokio::test]
async fn asymptote_defers_ready_commit_until_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

    let parent_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: [77u8; 32],
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };
    engine.highest_qc = parent_qc.clone();
    assert!(engine.safety.update(
        &QuorumCertificate {
            height: 2,
            view: 1,
            block_hash: [90u8; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        },
        &parent_qc,
    ));

    let _: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(engine.safety.committed_qc.is_none());
    assert!(engine.safety.next_ready_commit().is_some());
}

#[tokio::test]
async fn asymptote_accepts_ready_commit_once_parent_is_collapse_backed() {
    let validators = vec![
        AccountId([1u8; 32]),
        AccountId([2u8; 32]),
        AccountId([3u8; 32]),
    ];
    let known_peers = HashSet::from([PeerId::random()]);
    let mut parent_view = build_decide_parent_view(validators.clone());
    let mut engine =
        GuardianMajorityEngine::with_view_timeout(AftSafetyMode::Asymptote, Duration::from_secs(5));
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::ZERO);

    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    let collapse = derive_canonical_collapse_object(&parent_header, &[]).unwrap();
    parent_view.state.insert(
        aft_canonical_collapse_object_key(parent_header.height),
        codec::to_bytes_canonical(&collapse).unwrap(),
    );
    engine
        .committed_headers
        .insert(parent_header.height, parent_header.clone());
    engine
        .seen_headers
        .entry((parent_header.height, parent_header.view))
        .or_default()
        .insert(parent_hash, parent_header.clone());
    let parent_qc = QuorumCertificate {
        height: 1,
        view: 0,
        block_hash: parent_hash,
        signatures: vec![
            (validators[0], vec![1u8; 64]),
            (validators[1], vec![2u8; 64]),
        ],
        aggregated_signature: vec![],
        signers_bitfield: vec![],
    };
    engine.highest_qc = parent_qc.clone();
    assert!(engine.safety.update(
        &QuorumCertificate {
            height: 2,
            view: 1,
            block_hash: [91u8; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        },
        &parent_qc,
    ));

    let _: ConsensusDecision<ChainTransaction> = engine
        .decide(&validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert_eq!(
        engine.safety.committed_qc.as_ref().map(|qc| qc.height),
        Some(1)
    );
    assert!(engine.safety.next_ready_commit().is_none());
}

