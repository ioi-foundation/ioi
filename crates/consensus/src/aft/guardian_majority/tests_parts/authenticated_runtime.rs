// Adversarial coverage for the authenticated vote/quorum path.
//
// Every test here builds a real Ed25519 membership via `AuthenticatedValidators`
// and then substitutes exactly one element of the evidence. The control case in
// each pair proves the engine still accepts genuine evidence, so a rejection can
// be attributed to the substitution rather than to a fixture that never
// verified in the first place.

/// The number of members whose ClassicBft threshold is 3 and whose honest
/// `n >= 3f + 1` tolerance is 1.
const BFT_MEMBERS: usize = 4;

fn classic_engine(validators: &AuthenticatedValidators, heights: &[u64]) -> GuardianMajorityEngine {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    for height in heights {
        validators.install(&mut engine, *height);
    }
    engine
}

/// Seeds the normal runtime shape: a header at height two, view zero whose
/// parent certificate sits at height one, view zero. Views are height-scoped;
/// direct ancestry is established by consecutive heights and the child's
/// embedded parent certificate.
fn seed_two_chain(
    engine: &mut GuardianMajorityEngine,
    validators: &AuthenticatedValidators,
) -> (QuorumCertificate, QuorumCertificate) {
    let parent_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);
    let mut header = build_progress_parent_header(2, 0);
    header.parent_qc = parent_qc.clone();
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((header.height, header.view))
        .or_default()
        .insert(block_hash, header);
    let child_qc = validators.signed_qc(&[0, 1, 2], 2, 0, block_hash);
    (parent_qc, child_qc)
}

// --- Loose vote ingress ---------------------------------------------------

#[tokio::test]
async fn genuine_view_change_vote_is_admitted_to_the_timeout_pool() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[5]);
    let vote = validators.signed_view_change(0, 5, 1);
    let source = validators.keypairs[0].public().to_peer_id();

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_view_change(
        &mut engine,
        source,
        &codec::to_bytes_canonical(&vote).unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(engine.view_votes[&5][&1].len(), 1);
}

#[tokio::test]
async fn forged_view_change_vote_never_reaches_the_timeout_pool() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[5]);
    let mut vote = validators.signed_view_change(0, 5, 1);
    vote.signature = vec![0xAA; 64];
    let source = validators.keypairs[0].public().to_peer_id();

    let result = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_view_change(
        &mut engine,
        source,
        &codec::to_bytes_canonical(&vote).unwrap(),
    )
    .await;

    assert!(result.is_err());
    assert!(engine.view_votes.is_empty());
}

#[test]
fn timeout_certificate_rejects_one_substituted_signature() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);
    let mut certificate = TimeoutCertificate {
        height: 5,
        view: 1,
        votes: (0..3)
            .map(|index| validators.signed_view_change(index, 5, 1))
            .collect(),
    };
    engine
        .verify_timeout_certificate(&certificate, &validators.sets)
        .unwrap();

    certificate.votes[1].signature = vec![0xBB; 64];
    assert!(engine
        .verify_timeout_certificate(&certificate, &validators.sets)
        .is_err());
}

#[tokio::test]
async fn genuine_vote_is_admitted_to_the_pool() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[5]);
    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(&mut engine, vote)
        .await
        .unwrap();

    assert_eq!(
        engine
            .vote_pool
            .get(&5)
            .unwrap()
            .get(&[7u8; 32])
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn same_validator_cannot_vote_for_two_hashes_in_one_height_and_view() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[5]);
    let first = validators.signed_vote(0, 5, 1, [7u8; 32]);
    let conflicting = validators.signed_vote(0, 5, 1, [8u8; 32]);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(&mut engine, first)
        .await
        .unwrap();
    let error = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
        &mut engine,
        conflicting,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, ConsensusError::BlockVerificationFailed(_)));
    assert!(!engine.vote_pool[&5].contains_key(&[8u8; 32]));
}

#[tokio::test]
async fn forged_vote_signature_never_reaches_the_pool() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[5]);
    let mut vote = validators.signed_vote(0, 5, 0, [7u8; 32]);
    vote.signature = vec![0xAAu8; 64];

    let error = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
        &mut engine,
        vote,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, ConsensusError::BlockVerificationFailed(_)));
    assert!(engine.vote_pool.is_empty());
}

#[tokio::test]
async fn vote_from_a_non_member_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let outsider = AuthenticatedValidators::new(1);
    let mut engine = classic_engine(&validators, &[5]);
    // Genuinely signed, just not by anyone the effective set names.
    let vote = outsider.signed_vote(0, 5, 0, [7u8; 32]);

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            vote
        )
        .await
        .is_err()
    );
    assert!(engine.vote_pool.is_empty());
}

#[tokio::test]
async fn vote_is_refused_when_no_raw_key_is_available() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    // Membership is known, but no peer has been authenticated, so the raw key
    // behind the account's key hash is still unavailable.
    validators.install_without_keys(&mut engine, 5);
    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            vote
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn vote_is_refused_when_no_validator_set_was_ever_observed() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            vote
        )
        .await
        .is_err()
    );
}

#[test]
fn vote_signed_over_different_coordinates_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);

    // A real signature over (5, 0, hash_a) replayed onto a vote claiming a
    // different block, view, and height in turn.
    let mut substituted_hash = validators.signed_vote(0, 5, 0, [7u8; 32]);
    substituted_hash.block_hash = [8u8; 32];
    assert!(engine.authenticated_vote(&substituted_hash).is_err());

    let mut substituted_view = validators.signed_vote(0, 5, 0, [7u8; 32]);
    substituted_view.view = 1;
    assert!(engine.authenticated_vote(&substituted_view).is_err());

    let mut substituted_height = validators.signed_vote(0, 5, 0, [7u8; 32]);
    substituted_height.height = 6;
    assert!(engine.authenticated_vote(&substituted_height).is_err());
}

#[test]
fn vote_below_the_key_activation_height_is_refused_as_stale() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    let mut sets = validators.sets.clone();
    for validator in &mut sets.current.validators {
        validator.consensus_key.since_height = 10;
    }
    engine.remember_validator_sets(5, &sets);
    engine.remember_validator_count(5, BFT_MEMBERS);
    for keypair in &validators.keypairs {
        engine.record_validator_public_key(&keypair.public().encode_protobuf());
    }

    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_err());
}

#[test]
fn a_key_substituted_under_another_members_account_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);

    // Member 1 signs genuinely, then the vote is relabelled as member 0. The
    // signature verifies under member 1's key but member 0's record binds a
    // different key hash, so the binding step refuses it.
    let mut vote = validators.signed_vote(1, 5, 0, [7u8; 32]);
    vote.voter = validators.account_id(0);

    assert!(engine.authenticated_vote(&vote).is_err());
}

#[test]
fn a_member_whose_record_binds_a_foreign_key_hash_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let foreign = AuthenticatedValidators::new(1);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);

    // The set keeps member 0's account id but binds a key hash it does not
    // hold. Even with both raw keys registered, no signature can satisfy it.
    let mut sets = validators.sets.clone();
    let target = validators.account_id(0);
    for validator in &mut sets.current.validators {
        if validator.account_id == target {
            validator.consensus_key.public_key_hash = foreign.account_id(0).0;
        }
    }
    engine.remember_validator_sets(5, &sets);
    engine.remember_validator_count(5, BFT_MEMBERS);
    for keypair in validators.keypairs.iter().chain(foreign.keypairs.iter()) {
        engine.record_validator_public_key(&keypair.public().encode_protobuf());
    }

    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_err());
}

// --- Quorum certificate ingress -------------------------------------------

#[test]
fn empty_certificate_is_refused_in_every_safety_mode() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    for mode in [
        AftSafetyMode::ClassicBft,
        AftSafetyMode::GuardianMajority,
        AftSafetyMode::Asymptote,
        AftSafetyMode::ExperimentalNestedGuardian,
    ] {
        let mut engine = GuardianMajorityEngine::new(mode);
        validators.install(&mut engine, 5);
        let empty = QuorumCertificate {
            height: 5,
            view: 0,
            block_hash: [7u8; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        };
        assert!(
            engine.authenticated_quorum(&empty).is_err(),
            "an empty certificate is not a quorum under {mode:?}"
        );
    }
}

#[test]
fn duplicate_signer_does_not_count_twice_toward_the_threshold() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);

    // Three signature entries but only two distinct members.
    let mut qc = validators.signed_qc(&[0, 1], 5, 0, [7u8; 32]);
    let repeated = qc.signatures.first().cloned().unwrap();
    qc.signatures.push(repeated);

    assert!(engine.authenticated_quorum(&qc).is_err());
}

#[test]
fn certificate_below_the_threshold_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);
    // ClassicBft over 4 members needs 3 distinct verified signers.
    let qc = validators.signed_qc(&[0, 1], 5, 0, [7u8; 32]);

    assert!(engine.authenticated_quorum(&qc).is_err());
    assert!(engine
        .authenticated_quorum(&validators.signed_qc(&[0, 1, 2], 5, 0, [7u8; 32]))
        .is_ok());
}

#[test]
fn certificate_carrying_one_forged_signature_is_refused_whole() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);
    let mut qc = validators.signed_qc(&[0, 1, 2], 5, 0, [7u8; 32]);
    if let Some(entry) = qc.signatures.last_mut() {
        entry.1 = vec![0xAAu8; 64];
    }

    assert!(engine.authenticated_quorum(&qc).is_err());
}

#[test]
fn certificate_replayed_onto_a_different_block_is_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let engine = classic_engine(&validators, &[5]);
    let mut qc = validators.signed_qc(&[0, 1, 2], 5, 0, [7u8; 32]);
    qc.block_hash = [8u8; 32];

    assert!(engine.authenticated_quorum(&qc).is_err());
}

#[tokio::test]
async fn received_certificate_that_does_not_verify_never_advances_highest_qc() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    let mut header = build_progress_parent_header(2, 1);
    header.parent_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((2, 1))
        .or_default()
        .insert(block_hash, header);

    let mut qc = validators.signed_qc(&[0, 1, 2], 2, 1, block_hash);
    if let Some(entry) = qc.signatures.first_mut() {
        entry.1 = vec![0xAAu8; 64];
    }

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await
        .is_err()
    );
    assert_eq!(engine.highest_qc.height, 0);
}

#[tokio::test]
async fn locally_assembled_certificate_from_pooled_votes_advances_highest_qc() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    let mut header = build_progress_parent_header(2, 1);
    header.parent_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((2, 1))
        .or_default()
        .insert(block_hash, header);

    // Three genuine votes reach the ClassicBft threshold, so the engine builds
    // its own certificate and must hold it to the same standard.
    for index in 0..3 {
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            validators.signed_vote(index, 2, 1, block_hash),
        )
        .await
        .unwrap();
    }

    assert_eq!(engine.highest_qc.height, 2);
    assert_eq!(engine.highest_qc.block_hash, block_hash);
}

#[tokio::test]
async fn later_view_certificate_at_same_height_replaces_classic_high_qc() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    let parent_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);

    let mut view_zero = build_progress_parent_header(2, 0);
    view_zero.parent_qc = parent_qc.clone();
    let view_zero_hash = to_root_hash(&view_zero.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((2, 0))
        .or_default()
        .insert(view_zero_hash, view_zero);

    let mut view_one = build_progress_parent_header(2, 1);
    view_one.parent_qc = parent_qc;
    let view_one_hash = to_root_hash(&view_one.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((2, 1))
        .or_default()
        .insert(view_one_hash, view_one);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        validators.signed_qc(&[0, 1, 2], 2, 0, view_zero_hash),
    )
    .await
    .unwrap();
    assert_eq!(engine.highest_qc.view, 0);
    assert_eq!(engine.highest_qc.block_hash, view_zero_hash);

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        validators.signed_qc(&[0, 1, 2], 2, 1, view_one_hash),
    )
    .await
    .unwrap();

    assert_eq!(engine.highest_qc.height, 2);
    assert_eq!(engine.highest_qc.view, 1);
    assert_eq!(engine.highest_qc.block_hash, view_one_hash);
}

#[tokio::test]
async fn conflicting_authenticated_certificates_in_one_classic_slot_are_refused() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    engine.highest_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x31u8; 32]);
    let first_hash = [0x41u8; 32];
    let conflicting_hash = [0x42u8; 32];

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        validators.signed_qc(&[0, 1, 2], 2, 1, first_hash),
    )
    .await
    .unwrap();

    let result =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            validators.signed_qc(&[0, 1, 2], 2, 1, conflicting_hash),
        )
        .await;

    assert!(result.is_err());
    assert_eq!(engine.highest_qc.block_hash, first_hash);
}

#[tokio::test]
async fn classic_bft_child_proposal_waits_for_exact_authenticated_parent_quorum() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let active_validators = validators
        .sets
        .current
        .validators
        .iter()
        .map(|validator| validator.account_id)
        .collect::<Vec<_>>();
    let mut parent_view = build_decide_parent_view(active_validators.clone());
    parent_view.state.insert(
        VALIDATOR_SET_KEY.to_vec(),
        write_validator_sets(&validators.sets).unwrap(),
    );
    let collapse_chain = test_canonical_collapse_chain_ending(1, [0x21u8; 32], [0x22u8; 32]);
    insert_published_collapse_chain(&mut parent_view, &collapse_chain);
    let known_peers = validators
        .keypairs
        .iter()
        .map(|keypair| PeerId::from_public_key(&keypair.public()))
        .collect::<HashSet<_>>();
    let mut engine = classic_engine(&validators, &[1, 2]);
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);

    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    engine.committed_headers.insert(1, parent_header);

    let without_quorum: ConsensusDecision<ChainTransaction> = engine
        .decide(&active_validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(without_quorum, ConsensusDecision::WaitForBlock));
    assert_eq!(engine.highest_qc.height, 0);

    engine.highest_qc = validators.signed_qc(&[0, 1, 2], 1, 0, parent_hash);
    let with_quorum: ConsensusDecision<ChainTransaction> = engine
        .decide(&active_validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(
        with_quorum,
        ConsensusDecision::ProduceBlock { view: 0, .. }
    ));
}

// --- BFT qualification ----------------------------------------------------

#[test]
fn only_classic_bft_marks_a_certificate_bft_qualified() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let qc = validators.signed_qc(&[0, 1, 2], 5, 0, [7u8; 32]);

    let classic = classic_engine(&validators, &[5]);
    let verified = classic.authenticated_quorum(&qc).unwrap();
    assert_eq!(verified.total_voting_members, 4);
    assert_eq!(verified.byzantine_fault_tolerance(), 1);
    assert_eq!(verified.distinct_member_signatures_verified(), 3);
    assert!(verified.qualifies_bft_consensus_aft_v1());

    // Same evidence, majority mode: the assumptions differ, so the classical
    // BFT label is not available no matter how many signatures verified.
    for mode in [
        AftSafetyMode::GuardianMajority,
        AftSafetyMode::Asymptote,
        AftSafetyMode::ExperimentalNestedGuardian,
    ] {
        let mut engine = GuardianMajorityEngine::new(mode);
        validators.install(&mut engine, 5);
        let verified = engine.authenticated_quorum(&qc).unwrap();
        assert!(
            !verified.qualifies_bft_consensus_aft_v1(),
            "{mode:?} must never be relabelled as 3f+1/2f+1"
        );
    }
}

#[test]
fn a_membership_tolerating_zero_faults_is_not_bft_qualified() {
    // n = 3 gives f = (3 - 1) / 3 = 0, which is single-authority under a BFT
    // label rather than a Byzantine quorum.
    let validators = AuthenticatedValidators::new(3);
    let engine = classic_engine(&validators, &[5]);
    let qc = validators.signed_qc(&[0, 1, 2], 5, 0, [7u8; 32]);

    let verified = engine.authenticated_quorum(&qc).unwrap();
    assert_eq!(verified.byzantine_fault_tolerance(), 0);
    assert!(!verified.qualifies_bft_consensus_aft_v1());
}

// --- Finalized evidence ---------------------------------------------------

#[tokio::test]
async fn no_finalized_event_before_the_two_chain_rule_fires() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    let view =
        build_decide_parent_view((0..BFT_MEMBERS).map(|i| validators.account_id(i)).collect());

    // A single certificate with no certified child commits
    // nothing, so nothing may be exported.
    let qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);
    let _ =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
            &mut engine,
            qc,
        )
        .await;

    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        2,
        0,
        &view,
        &HashSet::new(),
    )
    .await;

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine
        )
        .is_empty()
    );
}

#[tokio::test]
async fn no_finalized_event_while_the_commit_guard_is_still_running() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    // Leave the default guard duration in place so the commit stays pending.
    let (_parent_qc, child_qc) = seed_two_chain(&mut engine, &validators);
    let view =
        build_decide_parent_view((0..BFT_MEMBERS).map(|i| validators.account_id(i)).collect());

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        child_qc,
    )
    .await
    .unwrap();
    assert!(engine.safety.next_ready_commit().is_none());

    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        3,
        0,
        &view,
        &HashSet::new(),
    )
    .await;

    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine
        )
        .is_empty()
    );
}

#[tokio::test]
async fn finalized_event_carries_the_committed_certificate_and_drains_exactly_once() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine(&validators, &[1, 2]);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::from_millis(0));
    let (parent_qc, child_qc) = seed_two_chain(&mut engine, &validators);
    let view =
        build_decide_parent_view((0..BFT_MEMBERS).map(|i| validators.account_id(i)).collect());

    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        child_qc.clone(),
    )
    .await
    .unwrap();

    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        3,
        0,
        &view,
        &HashSet::new(),
    )
    .await;

    let events =
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine,
        );
    assert_eq!(events.len(), 1);
    let event = events.first().unwrap();

    // The finalized block's own certificate, never the child that triggered it.
    assert_eq!(event.quorum_certificate, parent_qc);
    assert_ne!(event.quorum_certificate, child_qc);
    assert_eq!(event.quorum_certificate.height, 1);

    // Raw key material the validator set only stores by hash.
    assert_eq!(event.signers.len(), 3);
    assert_eq!(event.distinct_member_signatures_verified, 3);
    for signer in &event.signers {
        assert_eq!(signer.public_key.len(), 32);
        assert_eq!(signer.suite, SignatureSuite::ED25519);
    }
    assert_eq!(event.total_voting_members, 4);
    assert_eq!(event.byzantine_fault_tolerance, 1);
    assert_eq!(event.quorum_threshold, 3);
    assert!(event.bft_consensus_aft_v1_qualified);

    // A second drain, and a second decide, must not re-release it.
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine
        )
        .is_empty()
    );
    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        3,
        0,
        &view,
        &HashSet::new(),
    )
    .await;
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine
        )
        .is_empty()
    );
}

#[tokio::test]
async fn asymptote_withholds_the_finalized_event_until_the_collapse_gate_passes() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::Asymptote);
    validators.install(&mut engine, 1);
    validators.install(&mut engine, 2);
    engine.safety = SafetyGadget::new().with_guard_duration(Duration::from_millis(0));

    let parent_qc = validators.signed_qc(&[0, 1, 2], 1, 0, [0x11u8; 32]);
    engine.safety.update(
        &validators.signed_qc(&[0, 1, 2], 2, 1, [0x22u8; 32]),
        &parent_qc,
    );
    let view =
        build_decide_parent_view((0..BFT_MEMBERS).map(|i| validators.account_id(i)).collect());

    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        3,
        0,
        &view,
        &HashSet::new(),
    )
    .await;

    // The commit is ready by the guard timer but has no canonical collapse
    // object behind it, so it is neither consumed nor exported.
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::drain_finalized_native_quorums(
            &mut engine
        )
        .is_empty()
    );
    assert!(engine.safety.next_ready_commit().is_some());
}

// --- Key discovery --------------------------------------------------------

#[test]
fn the_local_key_is_recorded_through_the_engine_trait_method() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    engine.remember_validator_sets(5, &validators.sets);
    engine.remember_validator_count(5, BFT_MEMBERS);

    let vote = validators.signed_vote(0, 5, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_err());

    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_validator_public_key(
        &mut engine,
        &validators.keypairs[0].public().encode_protobuf(),
    ));
    assert!(engine.authenticated_vote(&vote).is_ok());
}

#[test]
fn malformed_key_material_is_rejected_without_being_recorded() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    assert!(!<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_validator_public_key(
        &mut engine, &[0xFFu8; 8],
    ));
}

#[test]
fn lifecycle_membership_hydration_authenticates_height_one_before_decide() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    for keypair in &validators.keypairs {
        assert!(<GuardianMajorityEngine as ConsensusEngine<
            ChainTransaction,
        >>::observe_validator_public_key(
            &mut engine,
            &keypair.public().encode_protobuf(),
        ));
    }
    assert!(<GuardianMajorityEngine as ConsensusEngine<
        ChainTransaction,
    >>::observe_validator_sets(
        &mut engine, 1, &validators.sets,
    ));

    let vote = validators.signed_vote(2, 1, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_ok());
    let qc = validators.signed_qc(&[0, 1, 2], 1, 0, [7u8; 32]);
    assert!(engine.authenticated_quorum(&qc).is_ok());
}

#[tokio::test]
async fn peer_keys_are_learned_from_the_authenticated_peer_set() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    engine.remember_validator_sets(5, &validators.sets);
    engine.remember_validator_count(5, BFT_MEMBERS);

    let vote = validators.signed_vote(1, 5, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_err());

    // `decide` harvests keys inlined in already-authenticated peer identities.
    let peers: HashSet<PeerId> = validators
        .keypairs
        .iter()
        .map(|keypair| keypair.public().to_peer_id())
        .collect();
    let view =
        build_decide_parent_view((0..BFT_MEMBERS).map(|i| validators.account_id(i)).collect());
    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        5,
        0,
        &view,
        &peers,
    )
    .await;

    assert!(engine.authenticated_vote(&vote).is_ok());
}

#[tokio::test]
async fn relayed_vote_and_quorum_use_canonical_keys_without_direct_peer_adjacency() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    validators.install_without_keys(&mut engine, 5);

    let mut view = build_decide_parent_view(
        (0..BFT_MEMBERS)
            .map(|index| validators.account_id(index))
            .collect(),
    );
    for keypair in &validators.keypairs {
        let account_id = AccountId(
            ioi_types::app::account_id_from_key_material(
                SignatureSuite::ED25519,
                &keypair.public().encode_protobuf(),
            )
            .unwrap(),
        );
        view.state.insert(
            [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat(),
            keypair.public().encode_protobuf(),
        );
    }

    // Empty known_peers deliberately models an indirect leaf in a star: all
    // raw keys must come from the same anchored state as membership.
    let _ = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        5,
        0,
        &view,
        &HashSet::new(),
    )
    .await;

    let vote = validators.signed_vote(3, 5, 0, [7u8; 32]);
    assert!(engine.authenticated_vote(&vote).is_ok());
    let qc = validators.signed_qc(&[0, 1, 3], 5, 0, [7u8; 32]);
    assert!(engine.authenticated_quorum(&qc).is_ok());
}

#[tokio::test]
async fn canonical_key_substitution_stalls_and_cannot_authenticate_the_member() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    validators.install_without_keys(&mut engine, 5);
    let mut view = build_decide_parent_view(
        (0..BFT_MEMBERS)
            .map(|index| validators.account_id(index))
            .collect(),
    );
    let substituted = Keypair::generate_ed25519();
    for (index, keypair) in validators.keypairs.iter().enumerate() {
        let account_id = validators.account_id(index);
        let encoded = if index == 3 {
            substituted.public().encode_protobuf()
        } else {
            keypair.public().encode_protobuf()
        };
        view.state.insert(
            [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat(),
            encoded,
        );
    }

    let decision = <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::decide(
        &mut engine,
        &validators.account_id(0),
        5,
        0,
        &view,
        &HashSet::new(),
    )
    .await;
    assert!(matches!(decision, ConsensusDecision::Stall));
    assert!(engine
        .authenticated_vote(&validators.signed_vote(3, 5, 0, [7u8; 32]))
        .is_err());
}
