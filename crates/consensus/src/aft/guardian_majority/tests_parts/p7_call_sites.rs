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
    // A fresh engine: this one has now seen a header at the slot, and its divergence check
    // refuses any second header there.
    let mut engine = classic_engine_for_pq(&validators, &[1, 4, 5]);
    engine.pacemaker_height = 5;
    engine.tc_formed.insert((5, 1));
    let authentic = leader_signed_proposal(&validators, 5, 0, [0x40; 32]);
    let error = propose(&mut engine, &chain, authentic).await.unwrap_err();
    assert!(error.to_string().contains("stale proposal"), "{error}");
}
