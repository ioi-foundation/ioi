// P7 STEP 1, REPRODUCTION at the trunk (build Ruling 12 and its amendments; NET's S-debug
// sequence: a leader's processing outlives its view, a TC moves the height to view v+1, and the
// stale view-v proposal still collects votes).
//
// Each test below RECORDS the trunk's vote-path behaviour at the engine level, in the safety
// modes the engine runs: Classic-BFT over the normative ML-DSA-44 membership (the only mode a
// node can boot at the trunk) and GuardianMajority over Ed25519 (the engine's non-classic path;
// Asymptote shares it, but cannot boot on the AFT engine at the trunk). They assert what the code
// does TODAY. The vote-safety commit that follows inverts each one into the rule it adopts, so the
// history shows red, then green.

/// The stale proposal's header, as the engine would hold it after verifying it: returns its hash.
fn seed_stale_proposal(engine: &mut GuardianMajorityEngine, height: u64, view: u64) -> [u8; 32] {
    let header = build_progress_parent_header(height, view);
    let block_hash = to_root_hash(&header.hash().unwrap()).unwrap();
    engine
        .seen_headers
        .entry((height, view))
        .or_default()
        .insert(block_hash, header);
    block_hash
}

/// The engine records its own timeout vote for (height, view + 1): it has timed out of `view`.
fn record_local_timeout(engine: &mut GuardianMajorityEngine, height: u64, view: u64) {
    engine
        .timeout_votes_sent
        .insert((height, view + 1), std::time::Instant::now());
}

#[tokio::test]
async fn reproduction_classic_bft_a_view_v_qc_and_a_view_v_plus_1_tc_coexist() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fallback.scale");
    let mut engine = pq_fallback_engine(&validators, 5, &path);

    // Validator 0 (this node) timed out of view 0 at height 5, and the TC for view 1 formed.
    record_local_timeout(&mut engine, 5, 0);
    assert!(engine
        .adopt_aft_timeout_certificate(validators.timeout_certificate(5, 1), true)
        .await
        .unwrap());
    assert!(engine.tc_formed.contains(&(5, 1)));

    // The stale view-0 proposal arrives. This node's own vote for it is accepted, and so are two
    // peers' votes: a view-0 QC forms beside the view-1 TC.
    let stale = seed_stale_proposal(&mut engine, 5, 0);
    for index in 0..3 {
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            validators.signed_vote(index, 5, 0, stale),
        )
        .await
        .expect("TRUNK: a vote in a timed-out view, after a higher-view TC, is accepted");
    }
    assert!(
        engine
            .qc_pool
            .get(&5)
            .is_some_and(|qcs| qcs.contains_key(&stale)),
        "TRUNK: the stale view-0 block is quorum-certified after the view-1 TC"
    );
    assert_eq!((engine.highest_qc.height, engine.highest_qc.view), (5, 0));
}

#[tokio::test]
async fn reproduction_guardian_majority_a_view_v_qc_and_a_view_v_plus_1_tc_coexist() {
    let validators = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    for height in [1, 5] {
        validators.install(&mut engine, height);
    }
    engine.pacemaker_height = 5;

    record_local_timeout(&mut engine, 5, 0);
    let certificate = TimeoutCertificate {
        height: 5,
        view: 1,
        votes: (0..3)
            .map(|index| validators.signed_view_change(index, 5, 1))
            .collect(),
    };
    assert!(engine
        .adopt_timeout_certificate(certificate, true)
        .await
        .unwrap());
    assert!(engine.tc_formed.contains(&(5, 1)));

    let stale = seed_stale_proposal(&mut engine, 5, 0);
    for index in 0..3 {
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            validators.signed_vote(index, 5, 0, stale),
        )
        .await
        .expect("TRUNK: a vote in a timed-out view, after a higher-view TC, is accepted");
    }
    assert!(
        engine
            .qc_pool
            .get(&5)
            .is_some_and(|qcs| qcs.contains_key(&stale)),
        "TRUNK: the stale view-0 block is quorum-certified after the view-1 TC"
    );
}

/// The lock never advances once views are height-scoped: every ordinary view is zero, and the
/// update compares views ACROSS heights (safety.rs `qc_parent.view > current_lock.view`).
#[test]
fn reproduction_the_lock_never_advances_past_the_first_parent() {
    let mut gadget = SafetyGadget::new().with_guard_duration(std::time::Duration::ZERO);
    let qc = |height: u64| QuorumCertificate {
        height,
        view: 0,
        block_hash: [height as u8; 32],
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    };
    for height in 2..=6 {
        gadget.update(&qc(height), &qc(height - 1));
    }
    assert_eq!(
        gadget.locked_qc.as_ref().map(|lock| lock.height),
        Some(1),
        "TRUNK: after the 2-chains (1,2) .. (5,6) the lock is still at height 1"
    );
    // `safe_to_vote` takes views only, so it cannot even name a parent below the lock: with every
    // view zero it answers yes for any parent at any height.
    assert!(gadget.safe_to_vote(0, 0));
}

/// `handle_vote` computes `safe_to_vote` with a HEIGHT as the parent view, and ignores the answer.
#[tokio::test]
async fn reproduction_handle_vote_ignores_safe_to_vote() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 5]);
    // A lock that makes `safe_to_vote(vote.view, vote.height - 1)` answer no for a (5, 0) vote:
    // 0 > 9 is false, and 4 >= 9 is false.
    engine.safety.locked_qc = Some(QuorumCertificate {
        height: 4,
        view: 9,
        block_hash: [0x44u8; 32],
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    });
    assert!(!engine.safety.safe_to_vote(0, 4));
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
        &mut engine,
        validators.signed_vote(0, 5, 0, [0x55u8; 32]),
    )
    .await
    .expect("TRUNK: the vote is pooled although safe_to_vote said no");
    assert_eq!(engine.vote_pool[&5][&[0x55u8; 32]].len(), 1);
}
