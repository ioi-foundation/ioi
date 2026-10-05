// P7 round 2 (review round 1, B1 and M2): the vote-safety refusals pinned THROUGH the engine's
// real entry point `handle_block_proposal`, and the synced-certificate check's "cannot evaluate"
// outcome. Written RED against 98e89083d, before the fix, where marked.

/// A chain view whose every anchored view is the given membership view.
struct ProposalChainView {
    view: MockAnchoredView,
}

impl std::fmt::Debug for ProposalChainView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProposalChainView")
    }
}

#[async_trait]
impl ioi_api::chain::ChainView<
        ioi_state::primitives::hash::HashCommitmentScheme,
        ioi_state::tree::iavl::IAVLTree<ioi_state::primitives::hash::HashCommitmentScheme>,
    > for ProposalChainView
{
    async fn view_at(
        &self,
        _state_ref: &ioi_api::chain::StateRef,
    ) -> Result<std::sync::Arc<dyn AnchoredStateView>, ChainError> {
        Ok(std::sync::Arc::new(self.view.clone()))
    }
    fn get_penalty_mechanism(&self) -> Box<dyn crate::PenaltyMechanism + Send + Sync + '_> {
        unimplemented!("unused by the proposal tests")
    }
    fn consensus_type(&self) -> ioi_types::config::ConsensusType {
        ioi_types::config::ConsensusType::Aft
    }
    fn workload_container(
        &self,
    ) -> &ioi_api::validator::WorkloadContainer<
        ioi_state::tree::iavl::IAVLTree<ioi_state::primitives::hash::HashCommitmentScheme>,
    > {
        unimplemented!("unused by the proposal tests")
    }
}

async fn propose(
    engine: &mut GuardianMajorityEngine,
    chain: &ProposalChainView,
    header: BlockHeader,
) -> Result<(), ConsensusError> {
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_block_proposal(
        engine,
        Block {
            header,
            transactions: Vec::new(),
        },
        chain,
    )
    .await
}

/// B1 (RED before the round-2 fix). The ruled item "lower-view proposals are refused after a TC",
/// through `handle_block_proposal`: the TC for view 1 at height 5 has formed here, and a fresh,
/// authentic view-0 proposal at height 5 arrives. It is refused as stale (the typed error the
/// orchestration keeps it by), before anything executes or persists it. (At 98e89083d
/// `check_divergence` recorded the header first, so the refusal read it as "already accepted" and
/// never fired.) Round 3: the refusal runs after authentication, so the proposal here is the slot
/// leader's signed one (round 2 used an unsigned block, refused before any check).
#[tokio::test]
async fn b1_handle_block_proposal_refuses_a_stale_view_proposal_after_a_tc() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let stale = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let stale_hash = to_root_hash(&stale.hash().unwrap()).unwrap();
    let error = propose(&mut engine, &chain, stale.clone()).await.unwrap_err();
    assert!(
        matches!(
            error,
            ConsensusError::StaleViewProposal {
                height: 5,
                view: 0,
                superseding_view: 1
            }
        ),
        "{error:?}"
    );
    assert!(!engine.accepted_proposals.contains(&(5, 0, stale_hash)));
    // A second delivery of the same bytes is refused too.
    let error = propose(&mut engine, &chain, stale).await.unwrap_err();
    assert!(
        matches!(error, ConsensusError::StaleViewProposal { .. }),
        "{error:?}"
    );
}

/// B1, the deadlock guard (a pin): a stale-view block that a known certificate CERTIFIES (votes
/// cast before the timeouts) is not refused as stale: the next height may have to extend it.
#[tokio::test]
async fn b1_a_certified_stale_view_block_is_not_refused_as_stale() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let stale = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    let stale_hash = to_root_hash(&stale.hash().unwrap()).unwrap();
    engine.remember_qc(&validators.signed_qc(5, 0, stale_hash));
    let error = propose(&mut engine, &chain, stale).await.unwrap_err();
    assert!(
        !error.to_string().contains("stale proposal"),
        "a certified stale-view block was refused as stale: {error}"
    );
}

/// B1, the follower's TC-high check pinned at its call site (a pin: live before and after): a
/// view-1 proposal whose parent is below the highest QC its own timeout certificate carries is
/// refused by `handle_block_proposal` itself.
#[tokio::test]
async fn b1_handle_block_proposal_refuses_a_proposal_below_its_tcs_highest_qc() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    // The (5, 1) leader: round index (5 - 1) + 1 = 5, mod 4 = seat 1.
    let leader = validators.sets.current.validators[1].account_id;
    let leader_index = (0..BFT_MEMBERS)
        .find(|index| validators.account_id(*index) == leader)
        .unwrap();
    let high = validators.signed_qc(4, 2, [0xB4u8; 32]);
    let certificate = validators.timeout_certificate_with_signers_and_safe_state(
        validators.fallback_scope(),
        5,
        1,
        &[0, 1, 2],
        high,
        QuorumCertificate::default(),
    );
    let mut header = proposal_with_parent(5, 1, qc_at(4, 0, 0xA4));
    header.producer_account_id = leader;
    header.producer_key_suite = SignatureSuite::ML_DSA_44;
    header.producer_pubkey = validators.keypairs[leader_index].public_key().to_bytes();
    header.producer_pubkey_hash = leader.0;
    header.aft_timeout_certificate = Some(certificate);
    let error = propose(&mut engine, &chain, header).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not extend its timeout certificate's highest QC"),
        "{error}"
    );
}

/// M2 (RED before the fix). An honest asynchronous-parent reference (the canonical, signature-free
/// reference to a hash-fallback virtual block) cannot be evaluated by a node that does not hold
/// the asynchronous parent proof. That is a local "cannot evaluate" (`DependencyNotFound`), never
/// a refutation of the peer that served it.
#[tokio::test]
async fn m2_an_async_parent_reference_without_its_proof_cannot_be_evaluated_here() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    let virtual_block = proposal_with_parent(4, 4, qc_at(3, 0, 0x30));
    let reference = ioi_types::app::aft_async_canonical_parent_reference(&virtual_block).unwrap();
    assert!(reference.signatures.is_empty());
    let error = engine
        .verify_certificate_against_view(&reference, &membership_view(&validators.sets))
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConsensusError::DependencyNotFound(_)),
        "an unevaluable async reference was reported as refuted: {error:?}"
    );
}

/// A view-`view` proposal at `height`, signed by that slot's leader, whose parent certificate is
/// an authentic 2f+1 certificate for `parent`: one that `handle_block_proposal` fully verifies.
fn leader_signed_proposal(
    validators: &PqAuthenticatedValidators,
    height: u64,
    view: u64,
    parent: [u8; 32],
) -> BlockHeader {
    let members = &validators.sets.current.validators;
    let leader = members[((height - 1 + view) % members.len() as u64) as usize].account_id;
    let leader_index = (0..BFT_MEMBERS)
        .find(|index| validators.account_id(*index) == leader)
        .unwrap();
    let mut header = proposal_with_parent(height, view, validators.signed_qc(height - 1, 0, parent));
    header.producer_account_id = leader;
    header.producer_key_suite = SignatureSuite::ML_DSA_44;
    header.producer_pubkey = validators.keypairs[leader_index].public_key().to_bytes();
    header.producer_pubkey_hash = leader.0;
    header.oracle_counter = height;
    header.oracle_trace_hash = [0x5A; 32];
    let preimage = header.to_preimage_for_signing().unwrap();
    let mut payload = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap().to_vec();
    payload.extend_from_slice(&header.oracle_counter.to_be_bytes());
    payload.extend_from_slice(&header.oracle_trace_hash);
    header.signature = validators.keypairs[leader_index]
        .sign(&payload)
        .unwrap()
        .to_bytes();
    header
}

/// B1, the redelivery exemption at its call site (added with the round-2 fix): a proposal
/// `handle_block_proposal` fully verified BEFORE a later-view timeout certificate formed is not a
/// new proposal: its exact redelivery afterwards is not refused as stale. (A NEW proposal at
/// the stale view is refused: `b1_handle_block_proposal_refuses_a_stale_view_proposal_after_a_tc`.)
#[tokio::test]
async fn b1_a_verified_proposal_redelivered_after_a_tc_is_not_refused_as_stale() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let verified = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    propose(&mut engine, &chain, verified.clone())
        .await
        .expect("the leader's proposal fully verifies");
    engine.tc_formed.insert((5, 1));
    propose(&mut engine, &chain, verified)
        .await
        .expect("an exact redelivery of a verified proposal is not a new proposal");
}

/// A chain view whose parent state is unavailable (this node does not hold it yet).
struct UnavailableChainView;

impl std::fmt::Debug for UnavailableChainView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnavailableChainView")
    }
}

#[async_trait]
impl ioi_api::chain::ChainView<
        ioi_state::primitives::hash::HashCommitmentScheme,
        ioi_state::tree::iavl::IAVLTree<ioi_state::primitives::hash::HashCommitmentScheme>,
    > for UnavailableChainView
{
    async fn view_at(
        &self,
        state_ref: &ioi_api::chain::StateRef,
    ) -> Result<std::sync::Arc<dyn AnchoredStateView>, ChainError> {
        Err(ChainError::UnknownStateAnchor(hex::encode(&state_ref.state_root)))
    }
    fn get_penalty_mechanism(&self) -> Box<dyn crate::PenaltyMechanism + Send + Sync + '_> {
        unimplemented!("unused by the proposal tests")
    }
    fn consensus_type(&self) -> ioi_types::config::ConsensusType {
        ioi_types::config::ConsensusType::Aft
    }
    fn workload_container(
        &self,
    ) -> &ioi_api::validator::WorkloadContainer<
        ioi_state::tree::iavl::IAVLTree<ioi_state::primitives::hash::HashCommitmentScheme>,
    > {
        unimplemented!("unused by the proposal tests")
    }
}

/// B1, MUT-1 survivor C5 killed: a proposal is recorded as accepted only once it FULLY verified.
/// One that failed verification before a later-view timeout certificate formed is refused as
/// stale when it is redelivered after the TC; a record made on arrival would exempt it. Round 3:
/// the refusal now runs after authentication, so the first delivery fails for a reason that
/// clears later (its parent state is not held here yet), not for a bad signature (which fails
/// authentication on every delivery and never reaches the refusal).
#[tokio::test]
async fn b1_a_proposal_that_failed_verification_is_not_exempt_after_a_tc() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let proposal = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let error = propose_on(&mut engine, &UnavailableChainView, proposal.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConsensusError::StateAccess(_)),
        "the first delivery failed for its unavailable parent state: {error:?}"
    );
    engine.tc_formed.insert((5, 1));
    let error = propose(&mut engine, &chain, proposal).await.unwrap_err();
    assert!(
        matches!(error, ConsensusError::StaleViewProposal { .. }),
        "a proposal that failed verification was exempt after the TC: {error:?}"
    );
}

async fn propose_on(
    engine: &mut GuardianMajorityEngine,
    chain: &UnavailableChainView,
    header: BlockHeader,
) -> Result<(), ConsensusError> {
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_block_proposal(
        engine,
        Block {
            header,
            transactions: Vec::new(),
        },
        chain,
    )
    .await
}

/// N1 (round 3), the engine's half through its real entry points: a stale-view proposal refused
/// BEFORE its certificate is known; the certificate then arrives as a propagated QC
/// (`handle_quorum_certificate`). The engine reports the block certified
/// (`holds_certificate_for`, which the orchestration polls to offer its kept copy again), and the
/// kept copy, offered again, is accepted. Nothing was redelivered by the producer: the second
/// call carries the same bytes the orchestration kept.
#[tokio::test]
async fn n1_a_certificate_learned_after_the_refusal_makes_the_kept_proposal_acceptable() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let kept = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let kept_hash = to_root_hash(&kept.hash().unwrap()).unwrap();
    let error = propose(&mut engine, &chain, kept.clone()).await.unwrap_err();
    assert!(matches!(error, ConsensusError::StaleViewProposal { .. }), "{error:?}");
    assert!(!<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::holds_certificate_for(
        &engine, 5, &kept_hash
    ));
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_quorum_certificate(
        &mut engine,
        validators.signed_qc(5, 0, kept_hash),
    )
    .await
    .expect("the votes cast before the timeouts certify the block");
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::holds_certificate_for(
            &engine, 5, &kept_hash
        ),
        "the engine does not report the certificate it accepted"
    );
    propose(&mut engine, &chain, kept)
        .await
        .expect("the kept proposal, certified, is accepted when offered again");
    assert!(engine.accepted_proposals.contains(&(5, 0, kept_hash)));
}

/// N1 (P7 round 3; RED before the fix). A stale-view refusal is a statement about an AUTHENTIC
/// proposal: the orchestration keeps a proposal refused as stale (bounded, one per slot) so that
/// it can be applied once a certificate for it is known, without a redelivery by its producer.
/// An unauthenticated block at a superseded slot must therefore be refused for failing
/// authentication, never as stale (else anyone could fill that retention). Here the view-0 slot
/// at height 5 is superseded by TC(5, 1): a block not signed by the slot's leader is refused for
/// that; the leader's own signed proposal is refused as stale.
#[tokio::test]
async fn n1_only_an_authenticated_proposal_is_refused_as_stale() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let unauthenticated = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    let error = propose(&mut engine, &chain, unauthenticated)
        .await
        .unwrap_err();
    assert!(
        !error.to_string().contains("stale proposal"),
        "an unauthenticated block was refused as a stale proposal: {error}"
    );
    // A fresh engine (since B1-P7-DIV the unauthenticated block above leaves no record, so the
    // same engine would also do).
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let error = propose(&mut engine, &chain, authentic).await.unwrap_err();
    assert!(error.to_string().contains("stale proposal"), "{error}");
}

// B1-P7-DIV (build rulings, "P7 PART 1 REVIEW r2 NOT REGISTERABLE", ruling 2): `check_divergence`
// ran BEFORE authentication in `handle_block_proposal`. It recorded every arriving header, so an
// unauthenticated header gossiped first at a slot made this node refuse the slot leader's own
// proposal there as "divergence" (a liveness DoS from unauthenticated input), with "evidence"
// that names the honest leader and that Algorithm 2 (divergence.rs: both headers signed by the
// accused) would reject. Divergence evidence must consider only AUTHENTICATED headers. Written
// RED against the trunk before the fix.

/// RED before the fix. A header at (5, 0) that the slot's leader did not sign arrives first; the
/// leader's own signed proposal at (5, 0) must still be accepted.
#[tokio::test]
async fn div_an_unauthenticated_header_first_does_not_make_the_leaders_proposal_divergent() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let junk = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    let error = propose(&mut engine, &chain, junk).await.unwrap_err();
    assert!(
        !error.to_string().contains("HardwareDivergence"),
        "the junk header itself was treated as divergence: {error}"
    );
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let authentic_hash = to_root_hash(&authentic.hash().unwrap()).unwrap();
    propose(&mut engine, &chain, authentic)
        .await
        .expect("the slot leader's proposal was refused after an unauthenticated header");
    assert!(engine.accepted_proposals.contains(&(5, 0, authentic_hash)));
}

/// RED before the fix. An unauthenticated header leaves no trace in the headers the engine treats
/// as known (`seen_headers`: read by divergence, QC acceptance and the collapse paths).
#[tokio::test]
async fn div_an_unauthenticated_header_is_not_recorded_as_seen() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let junk = proposal_with_parent(5, 0, qc_at(4, 0, 0x40));
    let junk_hash = to_root_hash(&junk.hash().unwrap()).unwrap();
    assert!(propose(&mut engine, &chain, junk).await.is_err());
    assert!(
        !engine
            .seen_headers
            .get(&(5, 0))
            .is_some_and(|headers| headers.contains_key(&junk_hash)),
        "an unauthenticated header was recorded as seen"
    );
}

/// A pin (green before and after the fix): two AUTHENTIC proposals by the slot's leader at one
/// slot are still divergence: the second is refused.
#[tokio::test]
async fn div_two_authentic_proposals_at_one_slot_are_still_divergent() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let first = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    propose(&mut engine, &chain, first)
        .await
        .expect("the first authentic proposal is accepted");
    let second = leader_signed_proposal(&validators, 5, 0, [0x41; 32]);
    let error = propose(&mut engine, &chain, second).await.unwrap_err();
    assert!(error.to_string().contains("HardwareDivergence"), "{error}");
}

/// MUT-1 D6's kill (B1-P7-DIV): a vote pool holding FEWER votes than the threshold for an
/// authentic proposal's hash builds no certificate, so the proposal is accepted on its own checks.
#[tokio::test]
async fn div_a_sub_threshold_vote_pool_does_not_build_a_certificate_for_the_proposal() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let authentic_hash = to_root_hash(&authentic.hash().unwrap()).unwrap();
    <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
        &mut engine,
        validators.signed_vote(1, 5, 0, authentic_hash),
    )
    .await
    .expect("one peer's vote is pooled");
    assert_eq!(engine.vote_pool[&5][&authentic_hash].len(), 1);
    propose(&mut engine, &chain, authentic)
        .await
        .expect("a proposal with a sub-threshold vote pool is accepted on its own checks");
    assert!(
        !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::holds_certificate_for(
            &engine,
            5,
            &authentic_hash
        ),
        "a certificate was built from a sub-threshold vote pool"
    );
}

/// MUT-1 D3's kill (B1-P7-DIV): the divergence check has no height exemption; two authentic
/// proposals at the FIRST height's slot are divergent too.
#[tokio::test]
async fn div_two_authentic_proposals_at_the_first_height_are_still_divergent() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 1;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let first = leader_signed_proposal(&validators, 1, 0, [0x40; 32]);
    let _ = propose(&mut engine, &chain, first).await;
    let second = leader_signed_proposal(&validators, 1, 0, [0x41; 32]);
    let error = propose(&mut engine, &chain, second).await.unwrap_err();
    assert!(error.to_string().contains("HardwareDivergence"), "{error}");
}

// B1-P7-DIV, MUT-1 supplementary kills (records/build/p7/MUT-1-PREREG-P7-DIV.md, "AMENDMENT before
// the supplementary run"): D7 (TRUST-CLAIM), D8 and D9 (SPURIOUS-EFFECT, D9 = review r3's R3-m2),
// D10 and D11 (STALE).

/// MUT-1 D7's kill (TRUST-CLAIM). A header that copies the slot leader's identity and an
/// authentic parent certificate, but whose payload the leader did not sign, passes every
/// structural check and is refused at the SIGNATURE (`InvalidSignature`), leaving no record; the
/// leader's own proposal at that slot is then accepted. (The other unauthenticated-header tests use
/// a header naming the wrong producer, refused at the first structural check, so they cannot tell
/// a check placed after the signature from one placed only after the structural checks.)
#[tokio::test]
async fn div_a_header_forging_the_leaders_identity_is_refused_at_the_signature_and_not_recorded() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let authentic_hash = to_root_hash(&authentic.hash().unwrap()).unwrap();
    let mut forged = authentic.clone();
    forged.transactions_root = vec![0xEE; 32];
    let forged_hash = to_root_hash(&forged.hash().unwrap()).unwrap();
    assert_ne!(
        forged_hash, authentic_hash,
        "the forged header must be a different payload"
    );
    let error = propose(&mut engine, &chain, forged).await.unwrap_err();
    assert!(
        matches!(error, ConsensusError::InvalidSignature),
        "the forged header must reach, and fail, the leader's signature check: {error:?}"
    );
    assert!(
        !engine
            .seen_headers
            .get(&(5, 0))
            .is_some_and(|headers| headers.contains_key(&forged_hash)),
        "a header whose leader signature does not verify was recorded as seen"
    );
    propose(&mut engine, &chain, authentic)
        .await
        .expect("the slot leader's proposal was refused after a header forging its identity");
    assert!(engine.accepted_proposals.contains(&(5, 0, authentic_hash)));
}

/// A view-start time one second in the past, planted so that any pacemaker reset is visible.
async fn plant_view_start(engine: &GuardianMajorityEngine) -> std::time::Instant {
    let planted = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("a monotonic clock one second old");
    engine.pacemaker.lock().await.view_start_time = planted;
    planted
}

/// MUT-1 D8's kill (SPURIOUS-EFFECT). A proposal refused as divergent does not move the
/// pacemaker: a divergent leader must not reset this node's view timer (and so must not delay its
/// timeout out of that leader's view).
#[tokio::test]
async fn div_a_divergent_proposal_does_not_move_the_pacemaker() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let first = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    propose(&mut engine, &chain, first)
        .await
        .expect("the first authentic proposal is accepted");
    let planted = plant_view_start(&engine).await;
    let second = leader_signed_proposal(&validators, 5, 0, [0x41; 32]);
    let error = propose(&mut engine, &chain, second).await.unwrap_err();
    assert!(error.to_string().contains("HardwareDivergence"), "{error}");
    assert_eq!(
        engine.pacemaker.lock().await.view_start_time,
        planted,
        "a proposal refused as divergent reset the view timer"
    );
}

/// MUT-1 D9's kill (SPURIOUS-EFFECT; review r3's R3-m2, registered as a follow-up of P7 part 1).
/// A proposal refused as stale (a later-view TC has formed) does not move the pacemaker: a
/// replayed authentic stale proposal must not keep resetting the view timer.
#[tokio::test]
async fn n1_a_refused_stale_proposal_does_not_move_the_pacemaker() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let planted = plant_view_start(&engine).await;
    let stale = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let error = propose(&mut engine, &chain, stale).await.unwrap_err();
    assert!(
        matches!(error, ConsensusError::StaleViewProposal { .. }),
        "{error:?}"
    );
    assert_eq!(
        engine.pacemaker.lock().await.view_start_time,
        planted,
        "a proposal refused as stale reset the view timer"
    );
}

/// MUT-1 D10's and D11's kill (STALE). On a node whose highest certificate lags (a fresh engine:
/// height 0), a quorum of votes for the view-0 proposal at height 5 arrives BEFORE its header. The
/// pool's certificate cannot be accepted then: it jumps beyond the next height with no known
/// header (collapse_verification.rs, `accept_quorum_certificate`). A later-view TC then forms. When
/// the authentic proposal arrives, its parent certificate and its now-recorded header let the
/// pool's certificate be accepted BEFORE the stale-view decision, so the certified proposal is
/// exempt (vote_safety.rs) and accepted; it is not refused and left waiting for a vote or
/// certificate event that may never come (all the votes have already arrived).
#[tokio::test]
async fn div_a_stale_proposal_whose_votes_came_first_is_certified_by_the_pool_and_accepted() {
    let validators = PqAuthenticatedValidators::new(BFT_MEMBERS);
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    let chain = ProposalChainView {
        view: membership_view(&validators.sets),
    };
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let authentic_hash = to_root_hash(&authentic.hash().unwrap()).unwrap();
    for voter in 0..BFT_MEMBERS {
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::handle_vote(
            &mut engine,
            validators.signed_vote(voter, 5, 0, authentic_hash),
        )
        .await
        .expect("an authentic vote is pooled");
    }
    assert!(
        !<GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::holds_certificate_for(
            &engine,
            5,
            &authentic_hash
        ),
        "precondition: the pool's certificate is not accepted before the header is known"
    );
    engine.tc_formed.insert((5, 1));
    propose(&mut engine, &chain, authentic)
        .await
        .expect("a stale-view proposal the vote pool certifies is exempt and accepted");
    assert!(
        <GuardianMajorityEngine as ConsensusEngine<ChainTransaction>>::holds_certificate_for(
            &engine,
            5,
            &authentic_hash
        ),
        "the pool's certificate was accepted with the proposal"
    );
    assert!(engine.accepted_proposals.contains(&(5, 0, authentic_hash)));
}
