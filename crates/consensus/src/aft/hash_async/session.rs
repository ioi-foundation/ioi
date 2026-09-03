use super::{
    verify_async_executed_block_certificate, verify_async_ordering_certificate,
    verify_async_proposal_availability_certificate, AsyncExecutedBlockVotePool,
    AsyncOrderingVotePool, AsyncProposalAvailabilityVotePool, CrossPathDecision,
    DurableAsyncProposalStore, DurableCrossPathSigningFence, DurableHashAsyncNode, HashAsyncAction,
};
use crate::aft::authenticated_quorum::{pq_optimistic_quorum_geometry, ValidatorKeyRegistry};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_types::app::{
    account_id_from_key_material, canonical_validator_set_hash, AccountId, AftAsyncBatchProposalV1,
    AftAsyncCarrierBodyV1, AftAsyncCarrierV1, AftAsyncDecisionVoteV1,
    AftAsyncExecutedBlockCertificateV1, AftAsyncExecutedBlockDecisionV1,
    AftAsyncExecutedBlockVoteV1, AftAsyncInstanceV1, AftAsyncOrderingCertificateV1,
    AftAsyncProposalAvailabilityCertificateV1, AftAsyncProposalAvailabilityVoteV1,
    AftAsyncProposalDescriptorV1, AftAsyncSelectedBatchWitnessV1,
    AftAsyncSelectedProposalWitnessV1, SignatureSuite, ValidatorSetV1,
    AFT_ASYNC_PROTOCOL_VERSION_V1, AFT_ASYNC_SCHEMA_VERSION_V1,
};
use ioi_types::error::ConsensusError;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Runtime-neutral effects produced by one integrated hash-only fallback
/// session. Validator orchestration maps these to strict-PQ swarm commands and
/// its sole finality admission path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashAsyncSessionAction {
    /// Send a public protocol artifact to every configured validator.
    Broadcast(AftAsyncCarrierV1),
    /// Send a private ASKS share to exactly one enrolled account.
    Send {
        /// Rooted destination account.
        recipient: AccountId,
        /// Instance-bound carrier.
        carrier: AftAsyncCarrierV1,
    },
    /// Fully rooted exact-q ordering evidence ready for finality admission.
    Finalized(AftAsyncOrderingCertificateV1),
    /// Fully rooted post-execution evidence ready for canonical block/finality
    /// admission, paired with the external payload witness it commits.
    ExecutedBlockFinalized {
        certificate: AftAsyncExecutedBlockCertificateV1,
        witness: AftAsyncSelectedBatchWitnessV1,
    },
}

/// Integrated per-height hash-only fallback session. It binds authenticated
/// accounts to member indices, refuses unverified proposal references, loops
/// back local broadcasts, and verifies exact-q evidence before exposing a
/// final ordering certificate.
pub struct HashAsyncSession {
    instance: AftAsyncInstanceV1,
    instance_hash: [u8; 32],
    local_index: u16,
    local_account: AccountId,
    signer: MldsaKeyPair,
    set: ValidatorSetV1,
    registry: ValidatorKeyRegistry,
    signing_fence: Arc<Mutex<DurableCrossPathSigningFence>>,
    node: DurableHashAsyncNode,
    proposals: DurableAsyncProposalStore,
    availability_pools: BTreeMap<[u8; 32], AsyncProposalAvailabilityVotePool>,
    local_availability_votes: BTreeMap<[u8; 32], AftAsyncProposalAvailabilityVoteV1>,
    availability_certificates: BTreeMap<[u8; 32], AftAsyncProposalAvailabilityCertificateV1>,
    pending_availability_certificates:
        BTreeMap<[u8; 32], AftAsyncProposalAvailabilityCertificateV1>,
    local_proposal: Option<AftAsyncProposalDescriptorV1>,
    started_proposal_binding: Option<[u8; 32]>,
    ordering_pool: Option<AsyncOrderingVotePool>,
    pending_decision_votes: BTreeMap<u16, AftAsyncDecisionVoteV1>,
    local_decision_vote: Option<AftAsyncDecisionVoteV1>,
    finalized: Option<AftAsyncOrderingCertificateV1>,
    executed_decision: Option<AftAsyncExecutedBlockDecisionV1>,
    executed_pool: Option<AsyncExecutedBlockVotePool>,
    pending_executed_votes: BTreeMap<u16, AftAsyncExecutedBlockVoteV1>,
    local_executed_vote: Option<AftAsyncExecutedBlockVoteV1>,
    executed_finalized: Option<AftAsyncExecutedBlockCertificateV1>,
}

impl std::fmt::Debug for HashAsyncSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HashAsyncSession")
            .field("instance_hash", &self.instance_hash)
            .field("local_index", &self.local_index)
            .field(
                "availability_certificates",
                &self.availability_certificates.len(),
            )
            .field("finalized", &self.finalized.is_some())
            .field("secret_state", &"<redacted>")
            .finish()
    }
}

impl HashAsyncSession {
    /// Opens an integrated session and deterministically replays its encrypted
    /// protocol journal. The external anchor must not share the node snapshot
    /// boundary with `node_journal` or `proposal_root`.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        instance: AftAsyncInstanceV1,
        local_account: AccountId,
        signer: MldsaKeyPair,
        set: ValidatorSetV1,
        registry: ValidatorKeyRegistry,
        signing_fence: Arc<Mutex<DurableCrossPathSigningFence>>,
        node_journal: &Path,
        external_anchor: &Path,
        proposal_root: &Path,
        custody_key: &[u8; 32],
        entropy_for_new: Option<[u8; 32]>,
    ) -> Result<(Self, Vec<HashAsyncSessionAction>), ConsensusError> {
        let instance_hash = instance
            .instance_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let rooted_geometry = pq_optimistic_quorum_geometry(&set)?;
        let configuration_hash =
            canonical_validator_set_hash(&set).map_err(ConsensusError::BlockVerificationFailed)?;
        if u32::from(instance.geometry.n) != rooted_geometry.n
            || u32::from(instance.geometry.f) != rooted_geometry.f
            || u32::from(instance.geometry.quorum) != rooted_geometry.q
            || instance.scope.configuration_hash != configuration_hash
            || instance.scope.epoch != set.effective_from_height
            || instance.height < set.effective_from_height
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "asynchronous session instance does not match rooted membership".into(),
            ));
        }
        let local_index = set
            .validators
            .iter()
            .position(|member| member.account_id == local_account)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "local asynchronous account is absent from rooted membership".into(),
                )
            })?;
        let local_member = set.validators.get(local_index as usize).ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "local asynchronous member index is out of range".into(),
            )
        })?;
        let raw_public = signer.public_key().to_bytes();
        let key_hash = account_id_from_key_material(SignatureSuite::ML_DSA_44, &raw_public)
            .map_err(|error| ConsensusError::BlockVerificationFailed(error.to_string()))?;
        if local_member.weight != 1
            || local_member.consensus_key.suite != SignatureSuite::ML_DSA_44
            || local_member.consensus_key.public_key_hash != key_hash
            || instance.height < local_member.consensus_key.since_height
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "local asynchronous signer does not match rooted membership".into(),
            ));
        }
        let (node, replay) = DurableHashAsyncNode::open(
            node_journal,
            external_anchor,
            instance.clone(),
            local_index,
            custody_key,
            entropy_for_new,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        let proposals = DurableAsyncProposalStore::open(proposal_root, instance.clone())
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let replayed_finalized = proposals
            .finalized_ordering_certificate()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if let Some(certificate) = replayed_finalized.as_ref() {
            verify_async_ordering_certificate(certificate, &set, &registry)?;
        }
        let replayed_started_binding = node
            .originated_proposal()
            .map(|proposal| proposal.proposal_hash);
        let replayed_local_proposal = proposals
            .local_descriptor()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let mut session = Self {
            instance,
            instance_hash,
            local_index,
            local_account,
            signer,
            set,
            registry,
            signing_fence,
            node,
            proposals,
            availability_pools: BTreeMap::new(),
            local_availability_votes: BTreeMap::new(),
            availability_certificates: BTreeMap::new(),
            pending_availability_certificates: BTreeMap::new(),
            local_proposal: replayed_local_proposal,
            started_proposal_binding: replayed_started_binding,
            ordering_pool: None,
            pending_decision_votes: BTreeMap::new(),
            local_decision_vote: None,
            finalized: replayed_finalized.clone(),
            executed_decision: None,
            executed_pool: None,
            pending_executed_votes: BTreeMap::new(),
            local_executed_vote: None,
            executed_finalized: None,
        };
        let mut actions = session.process_node_actions(replay)?;
        if let Some(certificate) = replayed_finalized {
            actions.push(HashAsyncSessionAction::Finalized(certificate));
        }
        actions.extend(session.restore_executed_round()?);
        Ok((session, actions))
    }

    /// Durably retains and disseminates a local proposal, then emits the
    /// local rooted validate-and-hold vote. Protocol RBC starts only after an
    /// exact-q availability certificate forms.
    pub fn propose(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let descriptor = self
            .proposals
            .retain_local(self.local_index, self.instance.locked_root, payload)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        match &self.local_proposal {
            Some(previous) if previous != &descriptor => {
                return Err(ConsensusError::BlockVerificationFailed(
                    "local asynchronous proposal is already frozen for this instance".into(),
                ));
            }
            Some(_) => {}
            None => self.local_proposal = Some(descriptor.clone()),
        }
        let mut actions = vec![self.broadcast(AftAsyncCarrierBodyV1::ProposalPayload {
            descriptor: descriptor.clone(),
            payload: payload.to_vec(),
        })];
        actions.extend(self.vote_for_retained(descriptor)?);
        Ok(actions)
    }

    /// Handles one carrier only after the strict-PQ channel authenticated its
    /// account. Direct payload and vote messages cannot be relayed under a
    /// different identity; completed certificates may be relayed.
    pub fn handle(
        &mut self,
        authenticated_account: AccountId,
        carrier: AftAsyncCarrierV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        carrier
            .validate_shape()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if carrier.instance_hash != self.instance_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "asynchronous carrier crossed the active instance".into(),
            ));
        }
        match carrier.body {
            AftAsyncCarrierBodyV1::ProposalPayload {
                ..
            } => Err(ConsensusError::BlockVerificationFailed(
                "proposal payload requires runtime semantic validation before availability voting"
                    .into(),
            )),
            AftAsyncCarrierBodyV1::ProposalAvailabilityVote { descriptor, vote } => {
                if vote.voter != authenticated_account {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "availability vote does not match its authenticated channel account".into(),
                    ));
                }
                self.insert_availability_vote(descriptor, vote)
            }
            AftAsyncCarrierBodyV1::ProposalAvailabilityCertificate(certificate) => {
                self.observe_availability_certificate(certificate)
            }
            AftAsyncCarrierBodyV1::Message(message) => {
                let sender = self.member_index(authenticated_account)?;
                if sender != message.sender {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "protocol message index does not match its authenticated account".into(),
                    ));
                }
                let actions = self
                    .node
                    .handle(sender, message)
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                self.process_node_actions(actions)
            }
            AftAsyncCarrierBodyV1::DecisionVote(vote) => {
                if vote.voter != authenticated_account {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "ordering vote does not match its authenticated channel account".into(),
                    ));
                }
                let sender = self.member_index(authenticated_account)?;
                if sender != vote.member_index {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "ordering vote index does not match its authenticated account".into(),
                    ));
                }
                if self.ordering_pool.is_none() {
                    match self.pending_decision_votes.get(&sender) {
                        Some(previous) if previous != &vote => {
                            return Err(ConsensusError::BlockVerificationFailed(
                                "pre-decision ordering vote attempted member rebinding".into(),
                            ));
                        }
                        Some(_) => return Ok(Vec::new()),
                        None => {
                            self.pending_decision_votes.insert(sender, vote);
                            return Ok(Vec::new());
                        }
                    }
                }
                self.insert_decision_vote(vote)
            }
            AftAsyncCarrierBodyV1::OrderingCertificate(certificate) => {
                verify_async_ordering_certificate(&certificate, &self.set, &self.registry)?;
                self.accept_finalized(certificate)
            }
            AftAsyncCarrierBodyV1::ExecutedBlockVote(vote) => {
                if vote.voter != authenticated_account
                    || self.member_index(authenticated_account)? != vote.member_index
                {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "executed-block vote does not match its authenticated channel account"
                            .into(),
                    ));
                }
                if self.executed_pool.is_none() {
                    match self.pending_executed_votes.get(&vote.member_index) {
                        Some(previous) if previous != &vote => {
                            return Err(ConsensusError::BlockVerificationFailed(
                                "pre-execution block vote attempted member rebinding".into(),
                            ));
                        }
                        Some(_) => return Ok(Vec::new()),
                        None => {
                            self.pending_executed_votes
                                .insert(vote.member_index, vote);
                            return Ok(Vec::new());
                        }
                    }
                }
                self.insert_executed_vote(vote)
            }
            AftAsyncCarrierBodyV1::ExecutedBlockCertificate(certificate) => {
                self.accept_executed_certificate(certificate)
            }
        }
    }

    /// Returns the final exact-q certificate, if one has been verified.
    pub fn finalized(&self) -> Option<&AftAsyncOrderingCertificateV1> {
        self.finalized.as_ref()
    }

    /// Returns the fully verified executed-block certificate, if this session
    /// completed the second exact-q round.
    pub fn executed_finalized(&self) -> Option<&AftAsyncExecutedBlockCertificateV1> {
        self.executed_finalized.as_ref()
    }

    /// Returns the exact instance commitment used for ingress routing.
    pub fn instance_hash(&self) -> [u8; 32] {
        self.instance_hash
    }

    /// Returns the fully verified fallback instance for typed payload checks.
    pub fn instance(&self) -> &AftAsyncInstanceV1 {
        &self.instance
    }

    /// Reports whether this instance already froze its local proposal.
    pub fn has_local_proposal(&self) -> bool {
        self.local_proposal.is_some()
    }

    /// Reloads every selected proposal only through its persisted,
    /// cryptographically verified availability certificate. Returned payloads
    /// follow the certificate's canonical proposer order.
    pub fn selected_payloads(
        &self,
        certificate: &AftAsyncOrderingCertificateV1,
    ) -> Result<Vec<Vec<u8>>, ConsensusError> {
        verify_async_ordering_certificate(certificate, &self.set, &self.registry)?;
        if !certificate
            .decision
            .instance
            .consensus_equivalent(&self.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "ordering certificate crossed its active asynchronous session".into(),
            ));
        }
        certificate
            .decision
            .selected
            .iter()
            .map(|reference| {
                let availability = self
                    .proposals
                    .load_availability_certificate(reference)
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                verify_async_proposal_availability_certificate(
                    &availability,
                    &self.instance,
                    &self.set,
                    &self.registry,
                )?;
                self.proposals
                    .load(&availability.descriptor)
                    .map_err(ConsensusError::BlockVerificationFailed)
            })
            .collect()
    }

    /// Builds the portable payload/availability witness consumed by the
    /// post-execution block certificate. All bytes and signatures are checked
    /// again while loading from durable custody.
    pub fn selected_batch_witness(
        &self,
        certificate: &AftAsyncOrderingCertificateV1,
    ) -> Result<AftAsyncSelectedBatchWitnessV1, ConsensusError> {
        let payloads = self.selected_payloads(certificate)?;
        let selected = certificate
            .decision
            .selected
            .iter()
            .zip(payloads)
            .map(|(reference, payload)| {
                let availability_certificate = self
                    .proposals
                    .load_availability_certificate(reference)
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                let proposal =
                    ioi_types::codec::from_bytes_canonical::<AftAsyncBatchProposalV1>(&payload)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                Ok(AftAsyncSelectedProposalWitnessV1 {
                    proposal,
                    availability_certificate,
                })
            })
            .collect::<Result<Vec<_>, ConsensusError>>()?;
        let witness = AftAsyncSelectedBatchWitnessV1 { selected };
        witness
            .canonical_transactions(certificate)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok(witness)
    }

    /// Starts the second exact-q round after the runtime independently
    /// executes the selected batch and derives its canonical block hash.
    pub fn begin_executed_block(
        &mut self,
        block_hash: [u8; 32],
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let ordering = self.finalized.clone().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "cannot certify an executed block before ordering finalizes".into(),
            )
        })?;
        let witness = self.selected_batch_witness(&ordering)?;
        let decision =
            AftAsyncExecutedBlockDecisionV1::new(ordering.clone(), witness.clone(), block_hash)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        if let Some(previous) = self.executed_decision.as_ref() {
            if previous
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
                != decision
                    .decision_hash()
                    .map_err(ConsensusError::BlockVerificationFailed)?
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "asynchronous session attempted to certify two executed blocks".into(),
                ));
            }
            return Ok(Vec::new());
        }
        self.proposals
            .retain_executed_decision(&decision, &ordering, &witness)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.signing_fence
            .lock()
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "cross-path signing-fence lock is poisoned".into(),
                )
            })?
            .authorize(
                self.instance.height,
                CrossPathDecision::HashAsync(block_hash),
            )
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let vote = self.sign_executed_vote(&decision)?;
        self.proposals
            .retain_local_executed_vote(&vote, &decision)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.executed_pool = Some(AsyncExecutedBlockVotePool::new(decision.clone(), ordering)?);
        self.executed_decision = Some(decision);
        self.local_executed_vote = Some(vote.clone());
        let mut actions =
            vec![self.broadcast(AftAsyncCarrierBodyV1::ExecutedBlockVote(vote.clone()))];
        actions.extend(self.insert_executed_vote(vote)?);
        let pending = std::mem::take(&mut self.pending_executed_votes);
        for vote in pending.into_values() {
            actions.extend(self.insert_executed_vote(vote)?);
        }
        Ok(actions)
    }

    /// Admits payload bytes only after the embedding runtime has checked its
    /// typed validity predicate (including transaction signatures). The
    /// authenticated proposer binding and durable validate-and-hold discipline
    /// remain enforced here.
    pub fn handle_validated_proposal_payload(
        &mut self,
        authenticated_account: AccountId,
        descriptor: AftAsyncProposalDescriptorV1,
        payload: Vec<u8>,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let sender = self.member_index(authenticated_account)?;
        if sender != descriptor.proposer {
            return Err(ConsensusError::BlockVerificationFailed(
                "proposal payload did not arrive from its rooted proposer".into(),
            ));
        }
        self.proposals
            .retain(&descriptor, &payload)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let mut actions = self.vote_for_retained(descriptor.clone())?;
        actions.extend(self.admit_pending_for(&descriptor)?);
        Ok(actions)
    }

    fn vote_for_retained(
        &mut self,
        descriptor: AftAsyncProposalDescriptorV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        self.proposals
            .load(&descriptor)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let binding = descriptor
            .binding_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let vote = if let Some(vote) = self.local_availability_votes.get(&binding) {
            vote.clone()
        } else {
            let preimage = AftAsyncProposalAvailabilityVoteV1::signing_bytes(
                &descriptor,
                self.local_index,
                self.local_account,
            )
            .map_err(ConsensusError::BlockVerificationFailed)?;
            let vote = AftAsyncProposalAvailabilityVoteV1 {
                proposal_binding_hash: binding,
                member_index: self.local_index,
                voter: self.local_account,
                signature_suite: SignatureSuite::ML_DSA_44,
                signature: self
                    .signer
                    .sign(&preimage)
                    .map_err(|error| {
                        ConsensusError::BlockVerificationFailed(format!(
                            "failed to sign asynchronous availability vote: {error}"
                        ))
                    })?
                    .to_bytes(),
            };
            self.local_availability_votes.insert(binding, vote.clone());
            vote
        };
        let mut actions = vec![
            self.broadcast(AftAsyncCarrierBodyV1::ProposalAvailabilityVote {
                descriptor: descriptor.clone(),
                vote: vote.clone(),
            }),
        ];
        actions.extend(self.insert_availability_vote(descriptor, vote)?);
        Ok(actions)
    }

    fn insert_availability_vote(
        &mut self,
        descriptor: AftAsyncProposalDescriptorV1,
        vote: AftAsyncProposalAvailabilityVoteV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let binding = descriptor
            .binding_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let pool = match self.availability_pools.entry(binding) {
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(
                AsyncProposalAvailabilityVotePool::new(self.instance.clone(), descriptor)?,
            ),
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        };
        match pool.insert(vote, &self.set, &self.registry)? {
            Some(certificate) => {
                let mut actions =
                    vec![
                        self.broadcast(AftAsyncCarrierBodyV1::ProposalAvailabilityCertificate(
                            certificate.clone(),
                        )),
                    ];
                actions.extend(self.observe_availability_certificate(certificate)?);
                Ok(actions)
            }
            None => Ok(Vec::new()),
        }
    }

    fn observe_availability_certificate(
        &mut self,
        certificate: AftAsyncProposalAvailabilityCertificateV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        verify_async_proposal_availability_certificate(
            &certificate,
            &self.instance,
            &self.set,
            &self.registry,
        )?;
        let binding = certificate
            .descriptor
            .binding_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if self.proposals.load(&certificate.descriptor).is_err() {
            self.pending_availability_certificates
                .insert(binding, certificate);
            return Ok(Vec::new());
        }
        self.admit_availability_certificate(certificate)
    }

    fn admit_pending_for(
        &mut self,
        descriptor: &AftAsyncProposalDescriptorV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let binding = descriptor
            .binding_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        match self.pending_availability_certificates.remove(&binding) {
            Some(certificate) => self.admit_availability_certificate(certificate),
            None => Ok(Vec::new()),
        }
    }

    fn admit_availability_certificate(
        &mut self,
        certificate: AftAsyncProposalAvailabilityCertificateV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let certificate_hash = certificate
            .certificate_hash(&self.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let persisted_hash = self
            .proposals
            .retain_verified_availability_certificate(&certificate)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if persisted_hash != certificate_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "persisted availability certificate changed its commitment".into(),
            ));
        }
        if let Some(previous) = self.availability_certificates.get(&certificate_hash) {
            if previous != &certificate {
                return Err(ConsensusError::BlockVerificationFailed(
                    "availability certificate hash was rebound".into(),
                ));
            }
            return Ok(Vec::new());
        }
        let proposal = certificate
            .proposal_ref(&self.instance)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.availability_certificates
            .insert(certificate_hash, certificate);
        let mut node_actions = self
            .node
            .admit_verified_proposal(proposal.clone())
            .map_err(ConsensusError::BlockVerificationFailed)?;
        if proposal.proposer == self.local_index {
            let binding = proposal.proposal_hash;
            match self.started_proposal_binding {
                Some(previous) if previous != binding => {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "local asynchronous proposer received certificates for conflicting payloads"
                            .into(),
                    ));
                }
                Some(_) => {}
                None => {
                    self.started_proposal_binding = Some(binding);
                    node_actions.extend(
                        self.node
                            .start(proposal)
                            .map_err(ConsensusError::BlockVerificationFailed)?,
                    );
                }
            }
        }
        self.process_node_actions(node_actions)
    }

    fn process_node_actions(
        &mut self,
        initial: Vec<HashAsyncAction>,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let mut pending = VecDeque::from(initial);
        let mut output = Vec::new();
        while let Some(action) = pending.pop_front() {
            match action {
                HashAsyncAction::Broadcast(message) => {
                    output.push(self.broadcast(AftAsyncCarrierBodyV1::Message(message.clone())));
                    let more = self
                        .node
                        .handle(self.local_index, message)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    pending.extend(more);
                }
                HashAsyncAction::Send { recipient, message } => {
                    if recipient == self.local_index {
                        let more = self
                            .node
                            .handle(self.local_index, message)
                            .map_err(ConsensusError::BlockVerificationFailed)?;
                        pending.extend(more);
                    } else {
                        output.push(HashAsyncSessionAction::Send {
                            recipient: self.member_account(recipient)?,
                            carrier: self.carrier(AftAsyncCarrierBodyV1::Message(message)),
                        });
                    }
                }
                HashAsyncAction::Decide {
                    decision,
                    transcript,
                } => {
                    let decision = *decision;
                    let transcript = *transcript;
                    if self.ordering_pool.is_some() {
                        if self
                            .local_decision_vote
                            .as_ref()
                            .map(|vote| vote.decision_hash)
                            != Some(
                                decision
                                    .decision_hash()
                                    .map_err(ConsensusError::BlockVerificationFailed)?,
                            )
                        {
                            return Err(ConsensusError::BlockVerificationFailed(
                                "local asynchronous session attempted to decide twice".into(),
                            ));
                        }
                        continue;
                    }
                    let preimage = AftAsyncDecisionVoteV1::signing_bytes(
                        &decision,
                        self.local_index,
                        self.local_account,
                    )
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                    let vote = AftAsyncDecisionVoteV1 {
                        decision_hash: decision
                            .decision_hash()
                            .map_err(ConsensusError::BlockVerificationFailed)?,
                        member_index: self.local_index,
                        voter: self.local_account,
                        signature_suite: SignatureSuite::ML_DSA_44,
                        signature: self
                            .signer
                            .sign(&preimage)
                            .map_err(|error| {
                                ConsensusError::BlockVerificationFailed(format!(
                                    "failed to sign asynchronous ordering vote: {error}"
                                ))
                            })?
                            .to_bytes(),
                    };
                    self.ordering_pool = Some(AsyncOrderingVotePool::new(decision, transcript)?);
                    self.local_decision_vote = Some(vote.clone());
                    output.push(self.broadcast(AftAsyncCarrierBodyV1::DecisionVote(vote.clone())));
                    output.extend(self.insert_decision_vote(vote)?);
                    let early = std::mem::take(&mut self.pending_decision_votes);
                    for (_, pending_vote) in early {
                        output.extend(self.insert_decision_vote(pending_vote)?);
                    }
                }
            }
        }
        if self.ordering_pool.is_some() {
            self.node
                .compact_terminal()
                .map_err(ConsensusError::BlockVerificationFailed)?;
        }
        Ok(output)
    }

    fn insert_decision_vote(
        &mut self,
        vote: AftAsyncDecisionVoteV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let pool = self.ordering_pool.as_mut().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "ordering vote arrived before this node converged on a decision".into(),
            )
        })?;
        match pool.insert(vote, &self.set, &self.registry)? {
            Some(certificate) => {
                let mut actions = vec![self.broadcast(AftAsyncCarrierBodyV1::OrderingCertificate(
                    certificate.clone(),
                ))];
                actions.extend(self.accept_finalized(certificate)?);
                Ok(actions)
            }
            None => Ok(Vec::new()),
        }
    }

    fn accept_finalized(
        &mut self,
        certificate: AftAsyncOrderingCertificateV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        verify_async_ordering_certificate(&certificate, &self.set, &self.registry)?;
        if let Some(previous) = &self.finalized {
            if previous
                .decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
                != certificate
                    .decision
                    .decision_hash()
                    .map_err(ConsensusError::BlockVerificationFailed)?
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "asynchronous session received conflicting exact-q certificates".into(),
                ));
            }
            return Ok(Vec::new());
        }
        self.proposals
            .retain_verified_ordering_certificate(&certificate)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.finalized = Some(certificate.clone());
        Ok(vec![HashAsyncSessionAction::Finalized(certificate)])
    }

    fn restore_executed_round(&mut self) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let Some(ordering) = self.finalized.clone() else {
            return Ok(Vec::new());
        };
        let witness = self.selected_batch_witness(&ordering)?;
        let Some(decision) = self
            .proposals
            .executed_decision(&ordering, &witness)
            .map_err(ConsensusError::BlockVerificationFailed)?
        else {
            return Ok(Vec::new());
        };
        self.signing_fence
            .lock()
            .map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "cross-path signing-fence lock is poisoned".into(),
                )
            })?
            .authorize(
                self.instance.height,
                CrossPathDecision::HashAsync(decision.block_hash),
            )
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let vote = match self
            .proposals
            .local_executed_vote(&decision)
            .map_err(ConsensusError::BlockVerificationFailed)?
        {
            Some(vote) => vote,
            None => {
                let vote = self.sign_executed_vote(&decision)?;
                self.proposals
                    .retain_local_executed_vote(&vote, &decision)
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                vote
            }
        };
        let mut pool = AsyncExecutedBlockVotePool::new(decision.clone(), ordering)?;
        pool.insert(vote.clone(), &self.set, &self.registry)?;
        self.executed_decision = Some(decision.clone());
        self.executed_pool = Some(pool);
        self.local_executed_vote = Some(vote.clone());
        if let Some(certificate) = self
            .proposals
            .finalized_executed_certificate(&witness)
            .map_err(ConsensusError::BlockVerificationFailed)?
        {
            verify_async_executed_block_certificate(
                &certificate,
                &witness,
                &self.set,
                &self.registry,
            )?;
            if certificate
                .decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
                != decision
                    .decision_hash()
                    .map_err(ConsensusError::BlockVerificationFailed)?
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "stored executed-block certificate conflicts with the frozen decision".into(),
                ));
            }
            self.executed_finalized = Some(certificate.clone());
            return Ok(vec![HashAsyncSessionAction::ExecutedBlockFinalized {
                certificate,
                witness,
            }]);
        }
        Ok(vec![
            self.broadcast(AftAsyncCarrierBodyV1::ExecutedBlockVote(vote))
        ])
    }

    fn sign_executed_vote(
        &self,
        decision: &AftAsyncExecutedBlockDecisionV1,
    ) -> Result<AftAsyncExecutedBlockVoteV1, ConsensusError> {
        let preimage = AftAsyncExecutedBlockVoteV1::signing_bytes(
            decision,
            self.local_index,
            self.local_account,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok(AftAsyncExecutedBlockVoteV1 {
            decision_hash: decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?,
            member_index: self.local_index,
            voter: self.local_account,
            signature_suite: SignatureSuite::ML_DSA_44,
            signature: self
                .signer
                .sign(&preimage)
                .map_err(|error| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "failed to sign asynchronous executed-block vote: {error}"
                    ))
                })?
                .to_bytes(),
        })
    }

    fn insert_executed_vote(
        &mut self,
        vote: AftAsyncExecutedBlockVoteV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let pool = self.executed_pool.as_mut().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "executed-block vote arrived before local deterministic execution".into(),
            )
        })?;
        match pool.insert(vote, &self.set, &self.registry)? {
            Some(certificate) => {
                let mut actions =
                    vec![
                        self.broadcast(AftAsyncCarrierBodyV1::ExecutedBlockCertificate(
                            certificate.clone(),
                        )),
                    ];
                actions.extend(self.accept_executed_certificate(certificate)?);
                Ok(actions)
            }
            None => Ok(Vec::new()),
        }
    }

    fn accept_executed_certificate(
        &mut self,
        certificate: AftAsyncExecutedBlockCertificateV1,
    ) -> Result<Vec<HashAsyncSessionAction>, ConsensusError> {
        let decision = self.executed_decision.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "executed-block certificate arrived before local deterministic execution".into(),
            )
        })?;
        if certificate
            .decision
            .decision_hash()
            .map_err(ConsensusError::BlockVerificationFailed)?
            != decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "executed-block certificate conflicts with the frozen local decision".into(),
            ));
        }
        if let Some(previous) = self.executed_finalized.as_ref() {
            if previous
                .decision
                .decision_hash()
                .map_err(ConsensusError::BlockVerificationFailed)?
                != certificate
                    .decision
                    .decision_hash()
                    .map_err(ConsensusError::BlockVerificationFailed)?
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "asynchronous session received conflicting executed-block certificates".into(),
                ));
            }
            return Ok(Vec::new());
        }
        let witness = self.selected_batch_witness(&certificate.ordering)?;
        verify_async_executed_block_certificate(&certificate, &witness, &self.set, &self.registry)?;
        self.proposals
            .retain_verified_executed_certificate(&certificate, &witness)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.executed_finalized = Some(certificate.clone());
        Ok(vec![HashAsyncSessionAction::ExecutedBlockFinalized {
            certificate,
            witness,
        }])
    }

    fn member_index(&self, account: AccountId) -> Result<u16, ConsensusError> {
        self.set
            .validators
            .iter()
            .position(|member| member.account_id == account)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "authenticated asynchronous account is not a rooted member".into(),
                )
            })
    }

    fn member_account(&self, index: u16) -> Result<AccountId, ConsensusError> {
        self.set
            .validators
            .get(index as usize)
            .map(|member| member.account_id)
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "asynchronous action names an out-of-range recipient".into(),
                )
            })
    }

    fn broadcast(&self, body: AftAsyncCarrierBodyV1) -> HashAsyncSessionAction {
        HashAsyncSessionAction::Broadcast(self.carrier(body))
    }

    fn carrier(&self, body: AftAsyncCarrierBodyV1) -> AftAsyncCarrierV1 {
        AftAsyncCarrierV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance_hash: self.instance_hash,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aft::hash_async::node::tests_support::test_instance;
    use ioi_crypto::security::SecurityLevel;
    use ioi_crypto::sign::dilithium::MldsaScheme;
    use ioi_types::app::{
        aft_async_canonical_qc_reference, canonical_transactions_root,
        canonical_validator_set_hash, ActiveKeyRecord, AftAsyncParentProofV1, BlockHeader,
        StateRoot, ValidatorV1,
    };

    fn rooted_fixture() -> (
        AftAsyncInstanceV1,
        ValidatorSetV1,
        ValidatorKeyRegistry,
        Vec<MldsaKeyPair>,
    ) {
        let mut keyed = (0..4)
            .map(|_| {
                let keypair = MldsaScheme::new(SecurityLevel::Level2)
                    .generate_keypair()
                    .unwrap();
                let raw = keypair.public_key().to_bytes();
                let account = AccountId(
                    account_id_from_key_material(SignatureSuite::ML_DSA_44, &raw).unwrap(),
                );
                (account, keypair, raw)
            })
            .collect::<Vec<_>>();
        keyed.sort_by_key(|(account, _, _)| *account);
        let set = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 4,
            validators: keyed
                .iter()
                .map(|(account, _, raw)| ValidatorV1 {
                    account_id: *account,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ML_DSA_44,
                        public_key_hash: account_id_from_key_material(
                            SignatureSuite::ML_DSA_44,
                            raw,
                        )
                        .unwrap(),
                        since_height: 1,
                    },
                })
                .collect(),
        };
        let mut instance = test_instance();
        let configuration_hash = canonical_validator_set_hash(&set).unwrap();
        instance.scope.configuration_hash = configuration_hash;
        instance.fallback_start.scope.configuration_hash = configuration_hash;
        for certificate in &mut instance
            .fallback_start
            .trigger_certificate
            .consecutive_timeout_certificates
        {
            certificate.scope.configuration_hash = configuration_hash;
            for vote in &mut certificate.votes {
                vote.scope.configuration_hash = configuration_hash;
            }
        }
        instance.fallback_instance_id =
            ioi_types::app::FallbackStartCertificateV1::derive_instance_id(
                instance.scope,
                instance.height,
            )
            .unwrap();
        instance.fallback_start.fallback_instance_id = instance.fallback_instance_id;
        instance.fallback_start_hash = instance.fallback_start.certificate_hash().unwrap();
        instance.validate().unwrap();
        let mut registry = ValidatorKeyRegistry::new();
        for (_, _, raw) in &keyed {
            registry
                .learn_raw_public_key(SignatureSuite::ML_DSA_44, raw)
                .unwrap();
        }
        (
            instance,
            set,
            registry,
            keyed.into_iter().map(|(_, keypair, _)| keypair).collect(),
        )
    }

    #[test]
    fn integrated_sessions_reach_rooted_exact_q_ordering() {
        let (instance, set, registry, keys) = rooted_fixture();
        let directory = tempfile::tempdir().unwrap();
        let mut sessions = keys
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, key)| {
                let base = directory.path().join(format!("node-{index}"));
                let custody_key = [index as u8 + 10; 32];
                let fence = DurableCrossPathSigningFence::open(
                    &base.join("signing-fence.scale"),
                    &directory
                        .path()
                        .join(format!("external-{index}/signing-fence.anchor")),
                    instance.scope,
                    set.validators[index].account_id,
                    &custody_key,
                )
                .unwrap();
                HashAsyncSession::open(
                    instance.clone(),
                    set.validators[index].account_id,
                    key,
                    set.clone(),
                    registry.clone(),
                    Arc::new(Mutex::new(fence)),
                    &base.join("journal.scale"),
                    &directory
                        .path()
                        .join(format!("external-{index}/anchor.scale")),
                    &base.join("proposals"),
                    &custody_key,
                    Some([index as u8 + 30; 32]),
                )
                .unwrap()
                .0
            })
            .collect::<Vec<_>>();
        let mut queue = VecDeque::new();
        for index in 0..sessions.len() {
            let proposal = AftAsyncBatchProposalV1::new(&instance, Vec::new()).unwrap();
            let payload = ioi_types::codec::to_bytes_canonical(&proposal).unwrap();
            let actions = sessions[index].propose(&payload).unwrap();
            queue.extend(actions.into_iter().map(|action| (index, action)));
        }

        let mut steps = 0usize;
        while sessions.iter().any(|session| session.finalized().is_none()) && steps < 2_000_000 {
            let (sender, action) = queue
                .pop_front()
                .unwrap_or_else(|| panic!("integrated session quiesced at step {steps}"));
            match action {
                HashAsyncSessionAction::Broadcast(carrier) => {
                    for recipient in 0..sessions.len() {
                        if recipient == sender {
                            continue;
                        }
                        let generated = match carrier.clone().body {
                            AftAsyncCarrierBodyV1::ProposalPayload {
                                descriptor,
                                payload,
                            } => sessions[recipient]
                                .handle_validated_proposal_payload(
                                    set.validators[sender].account_id,
                                    descriptor,
                                    payload,
                                )
                                .unwrap(),
                            _ => sessions[recipient]
                                .handle(set.validators[sender].account_id, carrier.clone())
                                .unwrap(),
                        };
                        queue.extend(generated.into_iter().map(|action| (recipient, action)));
                    }
                }
                HashAsyncSessionAction::Send { recipient, carrier } => {
                    let target = set
                        .validators
                        .iter()
                        .position(|member| member.account_id == recipient)
                        .unwrap();
                    let generated = sessions[target]
                        .handle(set.validators[sender].account_id, carrier)
                        .unwrap();
                    queue.extend(generated.into_iter().map(|action| (target, action)));
                }
                HashAsyncSessionAction::Finalized(_)
                | HashAsyncSessionAction::ExecutedBlockFinalized { .. } => {}
            }
            steps += 1;
        }
        assert!(steps < 2_000_000);
        let roots = sessions
            .iter()
            .map(|session| session.finalized().unwrap().decision.ordering_root)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(roots.len(), 1);
        for (index, session) in sessions.iter().enumerate() {
            verify_async_ordering_certificate(session.finalized().unwrap(), &set, &registry)
                .unwrap();
            assert!(session.node.terminal_checkpointed());
            assert!(
                std::fs::metadata(directory.path().join(format!("node-{index}/journal.scale")))
                    .unwrap()
                    .len()
                    < 1024 * 1024,
                "terminal hash-async journal was not compacted to a bounded checkpoint"
            );
            assert_eq!(
                session
                    .selected_payloads(session.finalized().unwrap())
                    .unwrap()
                    .len(),
                instance.geometry.quorum as usize
            );
        }

        let finalized_for_block = sessions[0].finalized().unwrap().clone();
        let witness_for_block = sessions[0]
            .selected_batch_witness(&finalized_for_block)
            .unwrap();
        let transactions = witness_for_block
            .canonical_transactions(&finalized_for_block)
            .unwrap();
        let virtual_member = &set.validators[0];
        let virtual_key = registry
            .get(&virtual_member.consensus_key.public_key_hash)
            .unwrap();
        let virtual_header = BlockHeader {
            height: instance.height,
            view: instance
                .fallback_start
                .trigger_certificate
                .consecutive_timeout_certificates
                .last()
                .unwrap()
                .view
                + 1,
            parent_hash: instance.fallback_start.highest_qc.block_hash,
            parent_state_root: StateRoot(vec![0x31; 32]),
            state_root: StateRoot(vec![0x32; 32]),
            transactions_root: canonical_transactions_root(&transactions).unwrap(),
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: set
                .validators
                .iter()
                .map(|member| member.account_id.0.to_vec())
                .collect(),
            producer_account_id: virtual_member.account_id,
            producer_key_suite: virtual_member.consensus_key.suite,
            producer_pubkey_hash: virtual_member.consensus_key.public_key_hash,
            producer_pubkey: virtual_key.raw().to_vec(),
            oracle_counter: 0,
            oracle_trace_hash: [0; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            parent_qc: aft_async_canonical_qc_reference(&instance.fallback_start.highest_qc),
            previous_canonical_collapse_commitment_hash: [0; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        };
        let block_hash = virtual_header
            .hash()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        for index in 0..sessions.len() {
            let actions = sessions[index].begin_executed_block(block_hash).unwrap();
            queue.extend(actions.into_iter().map(|action| (index, action)));
        }
        while sessions
            .iter()
            .any(|session| session.executed_finalized().is_none())
            && steps < 2_100_000
        {
            let (sender, action) = queue
                .pop_front()
                .unwrap_or_else(|| panic!("executed-block round quiesced at step {steps}"));
            match action {
                HashAsyncSessionAction::Broadcast(carrier) => {
                    for recipient in 0..sessions.len() {
                        if recipient == sender {
                            continue;
                        }
                        let generated = sessions[recipient]
                            .handle(set.validators[sender].account_id, carrier.clone())
                            .unwrap();
                        queue.extend(generated.into_iter().map(|action| (recipient, action)));
                    }
                }
                HashAsyncSessionAction::Send { recipient, carrier } => {
                    let target = set
                        .validators
                        .iter()
                        .position(|member| member.account_id == recipient)
                        .unwrap();
                    let generated = sessions[target]
                        .handle(set.validators[sender].account_id, carrier)
                        .unwrap();
                    queue.extend(generated.into_iter().map(|action| (target, action)));
                }
                HashAsyncSessionAction::Finalized(_)
                | HashAsyncSessionAction::ExecutedBlockFinalized { .. } => {}
            }
            steps += 1;
        }
        assert!(steps < 2_100_000);
        let executed = sessions[0].executed_finalized().unwrap().clone();
        for session in &sessions {
            let certificate = session.executed_finalized().unwrap();
            assert_eq!(certificate.decision, executed.decision);
            let witness = session
                .selected_batch_witness(&certificate.ordering)
                .unwrap();
            verify_async_executed_block_certificate(certificate, &witness, &set, &registry)
                .unwrap();
        }
        let semantic_parent_proof_hashes = sessions
            .iter()
            .map(|session| {
                let certificate = session.executed_finalized().unwrap().clone();
                let witness = session
                    .selected_batch_witness(&certificate.ordering)
                    .unwrap();
                AftAsyncParentProofV1::new(&virtual_header, certificate, witness)
                    .unwrap()
                    .proof_hash()
                    .unwrap()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(semantic_parent_proof_hashes.len(), 1);
        let proof =
            AftAsyncParentProofV1::new(&virtual_header, executed.clone(), witness_for_block)
                .unwrap();
        crate::aft::hash_async::verify_async_parent_proof(&proof, &set, &registry).unwrap();
        let mut mutated = proof.clone();
        mutated.executed_certificate.votes[0].signature[0] ^= 1;
        assert!(
            crate::aft::hash_async::verify_async_parent_proof(&mutated, &set, &registry).is_err()
        );
        let mut rebound = proof;
        rebound.parent_header_bytes[0] ^= 1;
        assert!(
            crate::aft::hash_async::verify_async_parent_proof(&rebound, &set, &registry).is_err()
        );

        let finalized = sessions[0].finalized().unwrap().clone();
        drop(sessions);
        let base = directory.path().join("node-0");
        let journal_path = base.join("journal.scale");
        let checkpoint_bytes = std::fs::read(&journal_path).unwrap();
        let mut corrupted_checkpoint = checkpoint_bytes.clone();
        let last = corrupted_checkpoint.len() - 1;
        corrupted_checkpoint[last] ^= 1;
        std::fs::write(&journal_path, corrupted_checkpoint).unwrap();
        assert!(HashAsyncSession::open(
            instance.clone(),
            set.validators[0].account_id,
            keys[0].clone(),
            set.clone(),
            registry.clone(),
            Arc::new(Mutex::new(
                DurableCrossPathSigningFence::open(
                    &base.join("signing-fence.scale"),
                    &directory.path().join("external-0/signing-fence.anchor"),
                    instance.scope,
                    set.validators[0].account_id,
                    &[10; 32],
                )
                .unwrap(),
            )),
            &journal_path,
            &directory.path().join("external-0/anchor.scale"),
            &base.join("proposals"),
            &[10; 32],
            None,
        )
        .is_err());
        std::fs::write(&journal_path, checkpoint_bytes).unwrap();
        let fence = DurableCrossPathSigningFence::open(
            &base.join("signing-fence.scale"),
            &directory.path().join("external-0/signing-fence.anchor"),
            instance.scope,
            set.validators[0].account_id,
            &[10; 32],
        )
        .unwrap();
        let (reopened, replay) = HashAsyncSession::open(
            instance,
            set.validators[0].account_id,
            keys[0].clone(),
            set.clone(),
            registry.clone(),
            Arc::new(Mutex::new(fence)),
            &journal_path,
            &directory.path().join("external-0/anchor.scale"),
            &base.join("proposals"),
            &[10; 32],
            None,
        )
        .unwrap();
        assert_eq!(reopened.finalized(), Some(&finalized));
        assert!(replay.iter().any(
            |action| matches!(action, HashAsyncSessionAction::Finalized(value) if value == &finalized)
        ));
        assert_eq!(reopened.executed_finalized(), Some(&executed));
        assert!(replay.iter().any(|action| matches!(
            action,
            HashAsyncSessionAction::ExecutedBlockFinalized { certificate, .. }
                if certificate == &executed
        )));
        assert_eq!(
            reopened.selected_payloads(&finalized).unwrap().len(),
            finalized.decision.instance.geometry.quorum as usize
        );
    }

    #[test]
    fn proposal_payload_refuses_authenticated_proposer_substitution() {
        let (instance, set, registry, keys) = rooted_fixture();
        let directory = tempfile::tempdir().unwrap();
        let proposer_fence = DurableCrossPathSigningFence::open(
            &directory.path().join("p/fence.scale"),
            &directory.path().join("external-p/fence.anchor"),
            instance.scope,
            set.validators[0].account_id,
            &[41; 32],
        )
        .unwrap();
        let (mut proposer, _) = HashAsyncSession::open(
            instance.clone(),
            set.validators[0].account_id,
            keys[0].clone(),
            set.clone(),
            registry.clone(),
            Arc::new(Mutex::new(proposer_fence)),
            &directory.path().join("p/journal.scale"),
            &directory.path().join("external-p/anchor.scale"),
            &directory.path().join("p/proposals"),
            &[41; 32],
            Some([42; 32]),
        )
        .unwrap();
        let receiver_fence = DurableCrossPathSigningFence::open(
            &directory.path().join("r/fence.scale"),
            &directory.path().join("external-r/fence.anchor"),
            instance.scope,
            set.validators[1].account_id,
            &[43; 32],
        )
        .unwrap();
        let (mut receiver, _) = HashAsyncSession::open(
            instance,
            set.validators[1].account_id,
            keys[1].clone(),
            set.clone(),
            registry,
            Arc::new(Mutex::new(receiver_fence)),
            &directory.path().join("r/journal.scale"),
            &directory.path().join("external-r/anchor.scale"),
            &directory.path().join("r/proposals"),
            &[43; 32],
            Some([44; 32]),
        )
        .unwrap();
        let payload_carrier = proposer
            .propose(b"origin-bound")
            .unwrap()
            .into_iter()
            .find_map(|action| match action {
                HashAsyncSessionAction::Broadcast(carrier)
                    if matches!(&carrier.body, AftAsyncCarrierBodyV1::ProposalPayload { .. }) =>
                {
                    Some(carrier)
                }
                _ => None,
            })
            .unwrap();
        let (descriptor, payload) = match payload_carrier.body {
            AftAsyncCarrierBodyV1::ProposalPayload {
                descriptor,
                payload,
            } => (descriptor, payload),
            _ => unreachable!(),
        };
        assert!(receiver
            .handle_validated_proposal_payload(set.validators[2].account_id, descriptor, payload,)
            .is_err());
    }
}
