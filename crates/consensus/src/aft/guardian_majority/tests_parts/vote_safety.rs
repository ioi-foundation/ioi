// P7 vote safety (build Ruling 12 and its four amendments; vote_safety.rs, safety.rs). These
// tests are the inversion of the trunk reproduction (commit 0a37ab86a): each pins the rule this
// node now applies to its OWN votes and proposals. They close CONFORMANCE gaps; canon already
// refused a second commit per height locally.
//
// The lock order is LEXICOGRAPHIC by (height, view) (`safety::qc_rank`), with equal rank only
// for the locked block itself; bare views are never compared across heights.

fn qc_at(height: u64, view: u64, byte: u8) -> QuorumCertificate {
    QuorumCertificate {
        height,
        view,
        block_hash: [byte; 32],
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    }
}

/// A proposal header at (height, view) whose parent certificate is `parent_qc`.
fn proposal_with_parent(height: u64, view: u64, parent_qc: QuorumCertificate) -> BlockHeader {
    let mut header = build_progress_parent_header(height, view);
    header.parent_hash = parent_qc.block_hash;
    header.parent_qc = parent_qc;
    header
}

/// The engine records its own timeout vote for (height, view + 1): it has timed out of `view`.
fn record_local_timeout(engine: &mut GuardianMajorityEngine, height: u64, view: u64) {
    engine
        .timeout_votes_sent
        .insert((height, view + 1), std::time::Instant::now());
}

async fn admit(engine: &mut GuardianMajorityEngine, header: &BlockHeader) -> Result<(), ConsensusError> {
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::admit_local_vote(engine, header)
        .await
}

// --- The lock: lexicographic (height, view) order -------------------------------------------

#[test]
fn the_lock_advances_in_height_then_view_order() {
    let mut gadget = SafetyGadget::new().with_guard_duration(std::time::Duration::ZERO);
    for height in 2..=6u64 {
        gadget.update(&qc_at(height, 0, height as u8), &qc_at(height - 1, 0, height as u8 - 1));
    }
    // The trunk left the lock at height 1 (bare views compared across heights, all zero).
    assert_eq!(
        gadget.locked_qc.as_ref().map(|lock| (lock.height, lock.view)),
        Some((5, 0))
    );
    // A later view at the lock's height outranks it.
    gadget.update(&qc_at(6, 1, 0x61), &qc_at(5, 2, 0x52));
    assert_eq!(
        gadget.locked_qc.as_ref().map(|lock| (lock.height, lock.view)),
        Some((5, 2))
    );
    // A higher VIEW at a lower HEIGHT never does.
    gadget.update(&qc_at(5, 9, 0x59), &qc_at(4, 9, 0x49));
    assert_eq!(
        gadget.locked_qc.as_ref().map(|lock| (lock.height, lock.view)),
        Some((5, 2))
    );
}

#[test]
fn safe_to_vote_orders_by_height_then_view_never_by_bare_view() {
    let mut gadget = SafetyGadget::new();
    gadget.locked_qc = Some(qc_at(5, 1, 0xA5));
    // A later height outranks the lock even in a lower view (the trunk's bare-view test said no).
    assert!(gadget.safe_to_vote(&qc_at(6, 0, 0x60)));
    // A later view at the lock's height outranks it.
    assert!(gadget.safe_to_vote(&qc_at(5, 2, 0x52)));
    // The locked block itself: the proposal extends the lock directly.
    assert!(gadget.safe_to_vote(&qc_at(5, 1, 0xA5)));
    // The lock's rank with another block, an earlier view at the lock's height, and a higher
    // view at a lower height (the trunk's bare-view test said yes) are all below the lock.
    assert!(!gadget.safe_to_vote(&qc_at(5, 1, 0xB5)));
    assert!(!gadget.safe_to_vote(&qc_at(5, 0, 0xA5)));
    assert!(!gadget.safe_to_vote(&qc_at(4, 9, 0x49)));
    // No lock yet: every parent is safe.
    assert!(SafetyGadget::new().safe_to_vote(&qc_at(0, 0, 0)));
}

// --- THIS node's own vote ------------------------------------------------------------------

#[tokio::test]
async fn own_vote_in_a_timed_out_view_is_refused_in_both_modes() {
    let pq = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let ed = AuthenticatedValidators::new(BFT_MEMBERS);
    let mut classic = classic_engine_for_pq(&pq, &[1, 5]);
    let mut guardian = GuardianMajorityEngine::new(AftSafetyMode::GuardianMajority);
    ed.install(&mut guardian, 5);
    for engine in [&mut classic, &mut guardian] {
        record_local_timeout(engine, 5, 0);
        let stale = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
        let error = admit(engine, &stale).await.unwrap_err();
        assert!(error.to_string().contains("moved past view 0"), "{error}");
        // The view it moved to is still votable.
        admit(engine, &proposal_with_parent(5, 1, qc_at(4, 0, 0x40)))
            .await
            .expect("a vote in the view this node timed out INTO is admitted");
    }
}

#[tokio::test]
async fn own_vote_after_a_later_view_tc_is_refused() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fallback.scale");
    let mut engine = pq_fallback_engine(&validators, 5, &path);
    assert!(engine
        .adopt_aft_timeout_certificate(validators.timeout_certificate(5, 1), true)
        .await
        .unwrap());
    let error = admit(&mut engine, &proposal_with_parent(5, 0, qc_at(4, 0, 0x40)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("moved past view 0"), "{error}");
}

#[tokio::test]
async fn own_vote_below_the_lock_is_refused() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 5]);
    engine.safety.locked_qc = Some(qc_at(4, 1, 0xA4));
    let error = admit(&mut engine, &proposal_with_parent(5, 0, qc_at(4, 0, 0xB4)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("lock rule"), "{error}");
    admit(&mut engine, &proposal_with_parent(5, 0, qc_at(4, 1, 0xA4)))
        .await
        .expect("a proposal extending the locked block is admitted");
}

#[tokio::test]
async fn own_vote_is_one_block_per_slot_and_an_exact_replay_passes() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 5]);
    let first = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    admit(&mut engine, &first).await.unwrap();
    // A replay of the admitted vote passes, even after this node has moved on.
    record_local_timeout(&mut engine, 5, 0);
    admit(&mut engine, &first)
        .await
        .expect("an exact replay of an admitted vote is not a new vote");
    let mut other = first.clone();
    other.transactions_root = vec![0xEE; 32];
    let error = admit(&mut engine, &other).await.unwrap_err();
    assert!(error.to_string().contains("another block"), "{error}");
}

/// m2 (round 2): the fallback-start fence. A durable fallback start at H refuses this node's own
/// optimistic vote at H, and (m7) an exact replay of a vote admitted before the start.
#[tokio::test]
async fn own_vote_and_its_replay_are_refused_after_a_fallback_start() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let directory = tempfile::tempdir().unwrap();
    let mut engine = pq_fallback_engine(&validators, 5, &directory.path().join("fallback.scale"));
    let admitted = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    admit(&mut engine, &admitted).await.unwrap();
    // The canonical third timeout certificate starts the durable fallback at height 5.
    for view in 1..=AFT_FALLBACK_TRIGGER_VIEW_V1 {
        engine
            .adopt_aft_timeout_certificate(validators.timeout_certificate(5, view), true)
            .await
            .unwrap();
    }
    assert!(engine.fallback_starts.contains_key(&5), "the fallback started");
    let error = admit(&mut engine, &admitted).await.unwrap_err();
    assert!(error.to_string().contains("fenced by a fallback start"), "{error}");
    let fresh = proposal_with_parent(5, 1, qc_at(4, 0, 0x40));
    let error = admit(&mut engine, &fresh).await.unwrap_err();
    assert!(error.to_string().contains("fenced by a fallback start"), "{error}");
    // Another height is not fenced.
    let next = proposal_with_parent(6, 0, qc_at(5, 0, 0x50));
    admit(&mut engine, &next).await.unwrap();
}

/// NET's S-debug sequence at engine level, after the fix: this node timed out of view 0 at
/// height 5 and the view-1 TC formed; the stale view-0 proposal can no longer get THIS node's
/// vote, and is refused before execution. Peers' votes are still pooled: cross-view votes by
/// other validators are never refused, and a view-0 QC formed from votes cast BEFORE their
/// timeouts stays possible (the fourth amendment: the hygiene rule is not the safety argument).
#[tokio::test]
async fn sdebug_replay_this_node_never_votes_the_stale_view_but_peers_are_not_refused() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fallback.scale");
    let mut engine = pq_fallback_engine(&validators, 5, &path);
    record_local_timeout(&mut engine, 5, 0);
    assert!(engine
        .adopt_aft_timeout_certificate(validators.timeout_certificate(5, 1), true)
        .await
        .unwrap());

    let stale_header = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    assert!(admit(&mut engine, &stale_header).await.is_err());
    let stale_hash = to_root_hash(&stale_header.hash().unwrap()).unwrap();
    assert!(engine
        .refuse_stale_view_proposal(&stale_header, &stale_hash)
        .is_err());

    for index in 1..3 {
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            validators.signed_vote(index, 5, 0, stale_hash),
        )
        .await
        .expect("a peer's vote is that peer's decision; this node's rules never refuse it");
    }
    assert_eq!(engine.vote_pool[&5][&stale_hash].len(), 2);
}

/// `handle_vote` no longer consults this node's lock for a peer's vote (the trunk computed
/// `safe_to_vote` there for every vote and ignored it); the lock gates `admit_local_vote`.
#[tokio::test]
async fn a_peers_vote_is_pooled_whatever_this_nodes_lock_but_its_own_is_gated() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 5]);
    engine.safety.locked_qc = Some(qc_at(4, 9, 0x49));
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
        &mut engine,
        validators.signed_vote(1, 5, 0, [0x55u8; 32]),
    )
    .await
    .expect("a peer's vote is pooled");
    assert_eq!(engine.vote_pool[&5][&[0x55u8; 32]].len(), 1);
    assert!(admit(&mut engine, &proposal_with_parent(5, 0, qc_at(4, 0, 0x40)))
        .await
        .is_err());
}

// --- Proposals -----------------------------------------------------------------------------

#[test]
fn a_lower_view_proposal_after_a_tc_is_refused_unless_already_accepted() {
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    engine.tc_formed.insert((5, 1));
    let stale = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    let stale_hash = to_root_hash(&stale.hash().unwrap()).unwrap();
    let error = engine
        .refuse_stale_view_proposal(&stale, &stale_hash)
        .unwrap_err();
    assert!(error.to_string().contains("timeout certificate for view 1"), "{error}");
    // The TC's own view is not stale, nor is another height.
    let current = proposal_with_parent(5, 1, qc_at(4, 0, 0x40));
    let current_hash = to_root_hash(&current.hash().unwrap()).unwrap();
    engine
        .refuse_stale_view_proposal(&current, &current_hash)
        .unwrap();
    let next = proposal_with_parent(6, 0, qc_at(5, 1, 0x51));
    let next_hash = to_root_hash(&next.hash().unwrap()).unwrap();
    engine.refuse_stale_view_proposal(&next, &next_hash).unwrap();
    // A header merely SEEN (check_divergence records every authenticated arrival, including one
    // refused later) is not accepted.
    engine
        .seen_headers
        .entry((5, 0))
        .or_default()
        .insert(stale_hash, stale.clone());
    engine
        .refuse_stale_view_proposal(&stale, &stale_hash)
        .unwrap_err();
    // A block this node fully verified before the TC (a later enrichment of it) is not a new
    // proposal.
    engine.accepted_proposals.insert((5, 0, stale_hash));
    engine
        .refuse_stale_view_proposal(&stale, &stale_hash)
        .unwrap();
}

#[test]
fn a_proposal_must_extend_its_timeout_certificates_highest_qc() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let scope = validators.fallback_scope();
    let high = validators.signed_qc(4, 2, [0xB4u8; 32]);
    let certificate = validators.timeout_certificate_with_signers_and_safe_state(
        scope,
        5,
        1,
        &[0, 1, 2],
        high.clone(),
        QuorumCertificate::default(),
    );
    // Below the TC's highest QC: an earlier view at its height.
    let below = proposal_with_parent(5, 1, qc_at(4, 0, 0xA4));
    let error =
        GuardianMajorityEngine::refuse_proposal_below_tc_high_qc(&below, &certificate).unwrap_err();
    assert!(error.to_string().contains("highest QC"), "{error}");
    // The TC's highest QC's rank with another block.
    let conflicting = proposal_with_parent(5, 1, qc_at(4, 2, 0xC4));
    assert!(
        GuardianMajorityEngine::refuse_proposal_below_tc_high_qc(&conflicting, &certificate)
            .is_err()
    );
    // Extending it is admitted.
    let extending = proposal_with_parent(5, 1, high);
    GuardianMajorityEngine::refuse_proposal_below_tc_high_qc(&extending, &certificate).unwrap();
}

/// The leader withholds a proposal whose parent certificate is below its lock (decide's lock
/// check, the trunk's empty block at runtime.rs:724-730).
#[tokio::test]
async fn the_leader_withholds_a_proposal_below_its_lock() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
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
    let known_peers = HashSet::new();
    let mut engine = classic_engine_for_pq(&validators, &[1, 2]);
    engine.bootstrap_grace_until = Instant::now() + Duration::from_secs(60);
    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    engine.committed_headers.insert(1, parent_header);
    engine.highest_qc = validators.signed_qc(1, 0, parent_hash);

    // A lock at a later view of height 1, on another block: the parent (1, 0) is below it.
    engine.safety.locked_qc = Some(qc_at(1, 3, 0x13));
    let withheld: ConsensusDecision<ChainTransaction> = engine
        .decide(&active_validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(withheld, ConsensusDecision::WaitForBlock));

    // The lock on the parent itself: the leader proposes.
    engine.safety.locked_qc = Some(engine.highest_qc.clone());
    let produced: ConsensusDecision<ChainTransaction> = engine
        .decide(&active_validators[1], 2, 0, &parent_view, &known_peers)
        .await;
    assert!(matches!(produced, ConsensusDecision::ProduceBlock { view: 0, .. }));
}

/// What the scoped TC's timeout votes carry as their highest QC.
#[derive(Clone, Copy)]
enum TcHigh {
    /// The leader's own (1, 0) parent certificate.
    TheParent,
    /// A later view at height 1, on another block, signed by the same membership.
    LaterViewOtherBlock,
}

/// The view-1 leader's decision at height 2 after a scoped TC; its own parent certificate is the
/// authenticated (1, 0) parent.
async fn view_one_leader_decision(tc_high: TcHigh) -> ConsensusDecision<ChainTransaction> {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
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
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fallback.scale");
    let mut engine = pq_fallback_engine(&validators, 2, &path);
    // Past the bootstrap grace, so the view is not pinned to zero.
    engine.bootstrap_grace_until = Instant::now();
    let parent_header = build_progress_parent_header(1, 0);
    let parent_hash = to_root_hash(&parent_header.hash().unwrap()).unwrap();
    engine.committed_headers.insert(1, parent_header);
    engine.highest_qc = validators.signed_qc(1, 0, parent_hash);

    let carried = match tc_high {
        TcHigh::TheParent => engine.highest_qc.clone(),
        TcHigh::LaterViewOtherBlock => validators.signed_qc(1, 2, [0xB1u8; 32]),
    };
    let scope = validators.fallback_scope();
    for index in 0..3 {
        let vote = validators.signed_aft_timeout_with_safe_state(
            index,
            scope,
            2,
            1,
            carried.clone(),
            QuorumCertificate::default(),
        );
        engine
            .aft_timeout_votes
            .entry(2)
            .or_default()
            .entry(1)
            .or_default()
            .insert(vote.voter, vote);
    }
    // The (2, 1) leader: round index (2 - 1) + 1 = 2.
    engine
        .decide(&active_validators[2], 2, 0, &parent_view, &HashSet::new())
        .await
}

/// The next leader extends the TC's highest QC: with a higher QC in the TC than its own parent,
/// the view-1 leader withholds; with its own parent as the TC's highest QC, it proposes in view 1.
#[tokio::test]
async fn the_next_leader_withholds_unless_it_extends_the_tcs_highest_qc() {
    let withheld = view_one_leader_decision(TcHigh::LaterViewOtherBlock).await;
    assert!(
        matches!(withheld, ConsensusDecision::WaitForBlock),
        "a leader whose parent is below the TC's highest QC must not propose"
    );
    let extending = view_one_leader_decision(TcHigh::TheParent).await;
    assert!(matches!(extending, ConsensusDecision::ProduceBlock { view: 1, .. }));
}

/// A node that verified a later-view proposal (which moved its pacemaker) but neither timed out
/// itself nor adopted the TC separately still refuses its own vote for the earlier view.
#[tokio::test]
async fn own_vote_below_the_pacemakers_view_is_refused() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 5]);
    engine.pacemaker_height = 5;
    engine.pacemaker.lock().await.observe_progress(1);
    assert!(engine.superseding_view(5, 0).is_none());
    let error = admit(&mut engine, &proposal_with_parent(5, 0, qc_at(4, 0, 0x40)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("to view 1"), "{error}");
}

// --- G1: synced certificates verify against the view's membership ---------------------------

/// A view holding only the membership (no engine cache): the keys come from the engine registry
/// or the view, the sets from the view.
fn membership_view(sets: &ValidatorSetsV1) -> MockAnchoredView {
    let mut view = MockAnchoredView::default();
    view.state.insert(
        VALIDATOR_SET_KEY.to_vec(),
        write_validator_sets(sets).unwrap(),
    );
    view
}

#[tokio::test]
async fn a_synced_certificate_verifies_against_the_views_membership_only() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    // Raw keys known, but NO validator set cached: the membership must come from the view.
    for keypair in &validators.keypairs {
        assert!(engine.record_validator_public_key(&keypair.public_key().to_bytes()));
    }
    assert!(engine.validator_sets_by_height.is_empty());
    let view = membership_view(&validators.sets);
    let genuine = validators.signed_qc(4, 0, [0x44u8; 32]);
    engine
        .verify_certificate_against_view(&genuine, &view)
        .await
        .expect("an authentic 2f+1 certificate verifies against the view's membership");

    // Refuted (inputs fully held here), never "cannot evaluate".
    let refuted = |error: ConsensusError| !matches!(error, ConsensusError::DependencyNotFound(_));
    let mut forged = genuine.clone();
    forged.signatures[1].1 = vec![0xBB; forged.signatures[1].1.len()];
    assert!(refuted(
        engine
            .verify_certificate_against_view(&forged, &view)
            .await
            .unwrap_err()
    ));
    let mut replayed = genuine.clone();
    replayed.block_hash = [0x45u8; 32];
    assert!(refuted(
        engine
            .verify_certificate_against_view(&replayed, &view)
            .await
            .unwrap_err()
    ));
    // The genesis sentinel needs no signatures; any other height-zero certificate is refused.
    engine
        .verify_certificate_against_view(&QuorumCertificate::default(), &view)
        .await
        .unwrap();
    assert!(engine
        .verify_certificate_against_view(&qc_at(0, 1, 0x01), &view)
        .await
        .is_err());
    // A view without a membership cannot authenticate anything: a local "cannot evaluate".
    assert!(matches!(
        engine
            .verify_certificate_against_view(&genuine, &MockAnchoredView::default())
            .await
            .unwrap_err(),
        ConsensusError::DependencyNotFound(_)
    ));
}

/// M2 (round 2): a member key absent from the anchored view (and not otherwise held) leaves the
/// certificate unevaluable here: a local "cannot evaluate", never a refutation of its server.
#[tokio::test]
async fn a_certificate_naming_keys_absent_here_cannot_be_evaluated() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = GuardianMajorityEngine::new(AftSafetyMode::ClassicBft);
    // The view holds the membership but none of its keys, and the engine holds none either.
    let view = membership_view(&validators.sets);
    let genuine = validators.signed_qc(4, 0, [0x44u8; 32]);
    assert!(matches!(
        engine
            .verify_certificate_against_view(&genuine, &view)
            .await
            .unwrap_err(),
        ConsensusError::DependencyNotFound(_)
    ));
}
