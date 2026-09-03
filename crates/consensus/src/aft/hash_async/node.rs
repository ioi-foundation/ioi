use super::{
    AsksDealerMaterial, AsksParticipant, AsksReconstruction, HashAsyncOrderingAdapter,
    IndexCoverGatherAction, IndexCoverGatherState, RaAction, RbcAction, ReliableAgreementState,
    ReliableBroadcastState,
};
use ioi_types::app::{
    validate_index_set, AftAsyncAsksMessageV1, AftAsyncGatherMessageV1, AftAsyncInstanceV1,
    AftAsyncMessageBodyV1, AftAsyncMessageV1, AftAsyncOrderingDecisionV1, AftAsyncProposalRefV1,
    AftAsyncRaPhaseV1, AftAsyncRaPurposeV1, AftAsyncRbcPhaseV1, AftAsyncRbcPurposeV1,
    AftAsyncTranscriptSummaryV1, AFT_ASYNC_PROTOCOL_VERSION_V1, AFT_ASYNC_SCHEMA_VERSION_V1,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::Zeroize;

const MAX_VABA_VIEW_LEAD: u64 = 2;
const ENTROPY_DERIVATION_DOMAIN_V1: &[u8] = b"ioi/aft/async-asks-entropy/v1";
const RANK_DOMAIN_V1: &[u8] = b"ioi/aft/async-vaba-rank/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAsyncAction {
    Broadcast(AftAsyncMessageV1),
    Send {
        recipient: u16,
        message: AftAsyncMessageV1,
    },
    Decide {
        decision: Box<AftAsyncOrderingDecisionV1>,
        transcript: Box<AftAsyncTranscriptSummaryV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct VabaPrevoteV1 {
    pre: u16,
    shared_dealers: Vec<u16>,
    justify: Vec<(u16, u16)>,
}

#[derive(Debug, Clone)]
struct VabaViewState {
    pre: Option<u16>,
    justify: Vec<(u16, u16)>,
    shared: BTreeSet<u16>,
    prevote_sent: bool,
    prevotes: BTreeMap<u16, VabaPrevoteV1>,
    validated_prevotes: BTreeSet<u16>,
    icg: IndexCoverGatherState,
    icg_output: Option<Vec<u16>>,
    reconstruction_started: BTreeSet<u16>,
    secrets: BTreeMap<u16, [u8; 32]>,
    vote_sent: bool,
    votes: BTreeMap<u16, u16>,
    next_started: bool,
}

impl VabaViewState {
    fn new(
        geometry: ioi_types::app::AftAsyncGeometryV1,
        local: u16,
        view: u64,
        pre: Option<u16>,
        justify: Vec<(u16, u16)>,
    ) -> Result<Self, String> {
        Ok(Self {
            pre,
            justify,
            shared: BTreeSet::new(),
            prevote_sent: false,
            prevotes: BTreeMap::new(),
            validated_prevotes: BTreeSet::new(),
            icg: IndexCoverGatherState::new(geometry, local, view)?,
            icg_output: None,
            reconstruction_started: BTreeSet::new(),
            secrets: BTreeMap::new(),
            vote_sent: false,
            votes: BTreeMap::new(),
            next_started: false,
        })
    }
}

/// One event-driven participant in the complete hash-only message-ACS stack.
/// The caller supplies a 256-bit OS-random local entropy seed, transports all
/// actions over the strict PQ private authenticated channel, and durably logs
/// accepted messages before calling [`Self::handle`].
#[derive(Clone)]
pub struct HashAsyncNode {
    instance: AftAsyncInstanceV1,
    instance_hash: [u8; 32],
    local: u16,
    entropy_seed: [u8; 32],
    started: bool,
    originated_proposal: Option<AftAsyncProposalRefV1>,
    rbcs: BTreeMap<(AftAsyncRbcPurposeV1, u16), ReliableBroadcastState>,
    asks: BTreeMap<(u64, u16), AsksParticipant>,
    asks_ra: BTreeMap<(u64, u16), ReliableAgreementState>,
    asks_ra_input: BTreeSet<(u64, u16)>,
    admitted_proposals: BTreeMap<[u8; 32], AftAsyncProposalRefV1>,
    pending_proposals: BTreeMap<[u8; 32], AftAsyncProposalRefV1>,
    proposals: BTreeMap<u16, AftAsyncProposalRefV1>,
    acs_input_sent: bool,
    pending_acs_inputs: BTreeMap<u16, Vec<u16>>,
    acs_inputs: BTreeMap<u16, Vec<u16>>,
    vaba_valid: BTreeSet<u16>,
    first_vaba_valid: Option<u16>,
    views: BTreeMap<u64, VabaViewState>,
    current_view: u64,
    pending_view_messages: BTreeMap<u64, VecDeque<(u16, AftAsyncMessageBodyV1)>>,
    pending_reconstruction: BTreeMap<(u64, u16), BTreeMap<u16, [u8; 32]>>,
    pending_start_messages: VecDeque<(u16, AftAsyncMessageBodyV1)>,
    decision_ra: ReliableAgreementState,
    decision_ra_input: Option<u16>,
    output: Option<(AftAsyncOrderingDecisionV1, AftAsyncTranscriptSummaryV1)>,
}

impl std::fmt::Debug for HashAsyncNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HashAsyncNode")
            .field("instance_hash", &self.instance_hash)
            .field("local", &self.local)
            .field("current_view", &self.current_view)
            .field("started", &self.started)
            .field("output", &self.output.is_some())
            .field("secret_state", &"<redacted>")
            .finish()
    }
}

impl Drop for HashAsyncNode {
    fn drop(&mut self) {
        self.entropy_seed.zeroize();
        for view in self.views.values_mut() {
            for secret in view.secrets.values_mut() {
                secret.zeroize();
            }
        }
        for shares in self.pending_reconstruction.values_mut() {
            for share in shares.values_mut() {
                share.zeroize();
            }
        }
    }
}

impl HashAsyncNode {
    pub fn new(
        instance: AftAsyncInstanceV1,
        local: u16,
        entropy_seed: [u8; 32],
    ) -> Result<Self, String> {
        instance.validate()?;
        if !instance.geometry.contains(local) || entropy_seed == [0; 32] {
            return Err("hash-async node has an invalid local index or empty entropy".into());
        }
        let instance_hash = instance.instance_hash()?;
        let decision_ra =
            ReliableAgreementState::new(instance.geometry, AftAsyncRaPurposeV1::VabaDecision)?;
        Ok(Self {
            instance,
            instance_hash,
            local,
            entropy_seed,
            started: false,
            originated_proposal: None,
            rbcs: BTreeMap::new(),
            asks: BTreeMap::new(),
            asks_ra: BTreeMap::new(),
            asks_ra_input: BTreeSet::new(),
            admitted_proposals: BTreeMap::new(),
            pending_proposals: BTreeMap::new(),
            proposals: BTreeMap::new(),
            acs_input_sent: false,
            pending_acs_inputs: BTreeMap::new(),
            acs_inputs: BTreeMap::new(),
            vaba_valid: BTreeSet::new(),
            first_vaba_valid: None,
            views: BTreeMap::new(),
            current_view: 0,
            pending_view_messages: BTreeMap::new(),
            pending_reconstruction: BTreeMap::new(),
            pending_start_messages: VecDeque::new(),
            decision_ra,
            decision_ra_input: None,
            output: None,
        })
    }

    /// Restores the minimal terminal state retained by an encrypted journal
    /// checkpoint. Once ACS has decided, protocol messages can no longer
    /// change the output; retaining the decision, transcript, local proposal
    /// binding, instance and entropy is sufficient for exact replay.
    pub(super) fn from_terminal_checkpoint(
        instance: AftAsyncInstanceV1,
        local: u16,
        entropy_seed: [u8; 32],
        originated_proposal: Option<AftAsyncProposalRefV1>,
        decision: AftAsyncOrderingDecisionV1,
        transcript: AftAsyncTranscriptSummaryV1,
    ) -> Result<Self, String> {
        decision.validate()?;
        if !decision.instance.consensus_equivalent(&instance)? {
            return Err("hash-async checkpoint crossed its fallback instance".into());
        }
        transcript.validate(&instance)?;
        if decision.transcript_root != transcript.transcript_root(&instance)? {
            return Err("hash-async checkpoint decision/transcript binding is invalid".into());
        }
        let selected_by_proposer = decision
            .selected
            .iter()
            .map(|proposal| Ok((proposal.proposer, proposal.commitment()?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let transcript_selection = transcript
            .selected_indices
            .iter()
            .copied()
            .zip(transcript.proposal_commitments.iter().copied())
            .collect::<BTreeMap<_, _>>();
        if selected_by_proposer != transcript_selection {
            return Err("hash-async checkpoint transcript names a different selected set".into());
        }
        if let Some(proposal) = originated_proposal.as_ref() {
            proposal.validate_for(&instance)?;
            if proposal.proposer != local {
                return Err("hash-async checkpoint local proposal is rebound".into());
            }
        }
        let mut node = Self::new(instance, local, entropy_seed)?;
        node.started = true;
        node.originated_proposal = originated_proposal;
        node.output = Some((decision, transcript));
        Ok(node)
    }

    pub(super) fn is_terminal(&self) -> bool {
        self.output.is_some()
    }

    pub fn start(
        &mut self,
        proposal: AftAsyncProposalRefV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        proposal.validate_for(&self.instance)?;
        if proposal.proposer != self.local {
            return Err("hash-async node cannot originate another member's proposal".into());
        }
        let mut actions = self.admit_verified_proposal(proposal.clone())?;
        if self.started {
            return if self.originated_proposal.as_ref() == Some(&proposal) {
                Ok(Vec::new())
            } else {
                Err("hash-async node was restarted with a conflicting proposal".into())
            };
        }
        self.started = true;
        self.originated_proposal = Some(proposal.clone());
        actions.extend(self.start_rbc(
            AftAsyncRbcPurposeV1::Proposal,
            self.local,
            codec::to_bytes_canonical(&proposal)?,
        )?);
        actions.extend(self.start_view(0, None, Vec::new())?);
        let pending = std::mem::take(&mut self.pending_start_messages);
        for (authenticated_sender, body) in pending {
            actions.extend(self.dispatch_or_buffer_view(authenticated_sender, body)?);
        }
        Ok(actions)
    }

    /// Admits one proposal reference only after the caller has verified its
    /// rooted exact-q availability certificate. This event is journaled by
    /// [`DurableHashAsyncNode`] so proposal RBC delivery can safely precede
    /// availability-certificate delivery and survive restart.
    pub fn admit_verified_proposal(
        &mut self,
        proposal: AftAsyncProposalRefV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        proposal.validate_for(&self.instance)?;
        let key = proposal.availability_certificate_hash;
        match self.admitted_proposals.get(&key) {
            Some(previous) if previous != &proposal => {
                return Err("hash-async availability certificate hash was rebound".into());
            }
            Some(_) => return Ok(Vec::new()),
            None => {
                self.admitted_proposals.insert(key, proposal.clone());
            }
        }
        match self.pending_proposals.remove(&key) {
            Some(pending) if pending == proposal => self.accept_proposal(pending),
            Some(pending) => {
                self.pending_proposals.insert(key, pending);
                Err("hash-async pending proposal conflicts with verified availability".into())
            }
            None => Ok(Vec::new()),
        }
    }

    pub fn handle(
        &mut self,
        authenticated_sender: u16,
        message: AftAsyncMessageV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        message.validate_for(&self.instance)?;
        if authenticated_sender != message.sender {
            return Err("hash-async envelope sender does not match authenticated channel".into());
        }
        if self.output.is_some() {
            return Ok(Vec::new());
        }
        if !self.started {
            if self.pending_start_messages.len() >= 100_000 {
                return Err("hash-async pre-start message buffer is exhausted".into());
            }
            self.pending_start_messages
                .push_back((authenticated_sender, message.body));
            return Ok(Vec::new());
        }
        self.dispatch_or_buffer_view(authenticated_sender, message.body)
    }

    fn dispatch_or_buffer_view(
        &mut self,
        authenticated_sender: u16,
        body: AftAsyncMessageBodyV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if let Some(view) = message_body_view(&body) {
            self.validate_view_bound(Some(view))?;
            if !self.views.contains_key(&view) {
                self.pending_view_messages
                    .entry(view)
                    .or_default()
                    .push_back((authenticated_sender, body));
                return Ok(Vec::new());
            }
        }
        self.dispatch_body(authenticated_sender, body)
    }

    fn dispatch_body(
        &mut self,
        authenticated_sender: u16,
        body: AftAsyncMessageBodyV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match body {
            AftAsyncMessageBodyV1::Rbc {
                purpose,
                dealer,
                phase,
                value_hash,
                value,
            } => self.handle_rbc(
                authenticated_sender,
                purpose,
                dealer,
                phase,
                value_hash,
                value,
            ),
            AftAsyncMessageBodyV1::ReliableAgreement {
                purpose,
                phase,
                value_hash,
                value,
            } => self.handle_ra(authenticated_sender, purpose, phase, value_hash, value),
            AftAsyncMessageBodyV1::Asks(message) => self.handle_asks(authenticated_sender, message),
            AftAsyncMessageBodyV1::Gather { view, message } => {
                self.handle_gather(authenticated_sender, view, message)
            }
        }
    }

    pub fn output(&self) -> Option<&(AftAsyncOrderingDecisionV1, AftAsyncTranscriptSummaryV1)> {
        self.output.as_ref()
    }

    /// Highest VABA view entered by this participant. This is an observability
    /// surface only; callers cannot use it as authority or a synchrony oracle.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Returns the immutable local proposal after this node has started.
    pub fn originated_proposal(&self) -> Option<&AftAsyncProposalRefV1> {
        self.originated_proposal.as_ref()
    }

    fn envelope(&self, body: AftAsyncMessageBodyV1) -> AftAsyncMessageV1 {
        AftAsyncMessageV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance_hash: self.instance_hash,
            sender: self.local,
            body,
        }
    }

    fn start_rbc(
        &mut self,
        purpose: AftAsyncRbcPurposeV1,
        dealer: u16,
        value: Vec<u8>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if dealer != self.local {
            return Err("only the local dealer may start an RBC".into());
        }
        self.rbc_state(purpose.clone(), dealer)?;
        match ReliableBroadcastState::dealer_value(value)? {
            RbcAction::Broadcast {
                phase,
                value_hash,
                value,
            } => Ok(vec![HashAsyncAction::Broadcast(self.envelope(
                AftAsyncMessageBodyV1::Rbc {
                    purpose,
                    dealer,
                    phase,
                    value_hash,
                    value,
                },
            ))]),
            RbcAction::Deliver(_) => Err("dealer RBC unexpectedly delivered synchronously".into()),
        }
    }

    fn rbc_state(
        &mut self,
        purpose: AftAsyncRbcPurposeV1,
        dealer: u16,
    ) -> Result<&mut ReliableBroadcastState, String> {
        let key = (purpose.clone(), dealer);
        if !self.rbcs.contains_key(&key) {
            self.rbcs.insert(
                key.clone(),
                ReliableBroadcastState::new(self.instance.geometry, purpose, dealer)?,
            );
        }
        self.rbcs
            .get_mut(&key)
            .ok_or_else(|| "RBC state insertion failed".into())
    }

    fn handle_rbc(
        &mut self,
        sender: u16,
        purpose: AftAsyncRbcPurposeV1,
        dealer: u16,
        phase: AftAsyncRbcPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        self.validate_view_bound(rbc_view(&purpose))?;
        let actions = self
            .rbc_state(purpose.clone(), dealer)?
            .handle(sender, phase, value_hash, value)?;
        let mut output = Vec::new();
        for action in actions {
            match action {
                RbcAction::Broadcast {
                    phase,
                    value_hash,
                    value,
                } => output.push(HashAsyncAction::Broadcast(self.envelope(
                    AftAsyncMessageBodyV1::Rbc {
                        purpose: purpose.clone(),
                        dealer,
                        phase,
                        value_hash,
                        value,
                    },
                ))),
                RbcAction::Deliver(value) => {
                    output.extend(self.on_rbc_delivery(purpose.clone(), dealer, value)?);
                }
            }
        }
        Ok(output)
    }

    fn on_rbc_delivery(
        &mut self,
        purpose: AftAsyncRbcPurposeV1,
        dealer: u16,
        value: Vec<u8>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match purpose {
            AftAsyncRbcPurposeV1::Proposal => {
                let proposal = codec::from_bytes_canonical::<AftAsyncProposalRefV1>(&value)?;
                proposal.validate_for(&self.instance)?;
                if proposal.proposer != dealer {
                    return Err("proposal RBC dealer does not match proposal owner".into());
                }
                let availability_hash = proposal.availability_certificate_hash;
                if self.admitted_proposals.get(&availability_hash) == Some(&proposal) {
                    self.accept_proposal(proposal)
                } else {
                    match self
                        .pending_proposals
                        .insert(availability_hash, proposal.clone())
                    {
                        Some(previous) if previous != proposal => {
                            self.pending_proposals.insert(availability_hash, previous);
                            Err("proposal RBC rebound an availability certificate hash".into())
                        }
                        _ => Ok(Vec::new()),
                    }
                }
            }
            AftAsyncRbcPurposeV1::AcsInput => {
                let indices = codec::from_bytes_canonical::<Vec<u16>>(&value)?;
                validate_index_set(
                    &indices,
                    self.instance.geometry.n,
                    self.instance.geometry.quorum,
                )?;
                match self.pending_acs_inputs.insert(dealer, indices.clone()) {
                    Some(previous) if previous != indices => {
                        self.pending_acs_inputs.insert(dealer, previous);
                        Err("ACS input dealer rebound its delivered set".into())
                    }
                    _ => self.refresh_acs_inputs(),
                }
            }
            AftAsyncRbcPurposeV1::AsksCommitments {
                view,
                dealer: named,
            } => {
                if dealer != named {
                    return Err("ASKS commitment RBC dealer tag mismatch".into());
                }
                let commitments = codec::from_bytes_canonical::<Vec<[u8; 32]>>(&value)?;
                let valid = self
                    .asks_participant(view, dealer)?
                    .accept_commitments(commitments)?;
                self.maybe_start_asks_ra(view, dealer, valid)
            }
            AftAsyncRbcPurposeV1::VabaPrevote { view } => {
                let prevote = codec::from_bytes_canonical::<VabaPrevoteV1>(&value)?;
                let state = self.view_mut(view)?;
                match state.prevotes.insert(dealer, prevote.clone()) {
                    Some(previous) if previous != prevote => {
                        state.prevotes.insert(dealer, previous);
                        return Err("VABA prevote dealer rebound its delivered value".into());
                    }
                    _ => {}
                }
                self.try_validate_prevote(view, dealer)
            }
            AftAsyncRbcPurposeV1::VabaVote { view } => {
                let candidate = codec::from_bytes_canonical::<u16>(&value)?;
                self.accept_vote(view, dealer, candidate)
            }
        }
    }

    fn accept_proposal(
        &mut self,
        proposal: AftAsyncProposalRefV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match self.proposals.insert(proposal.proposer, proposal.clone()) {
            Some(previous) if previous != proposal => {
                self.proposals.insert(previous.proposer, previous);
                return Err("proposal owner rebound its availability-certified reference".into());
            }
            _ => {}
        }
        let mut actions = self.maybe_send_acs_input()?;
        actions.extend(self.refresh_acs_inputs()?);
        Ok(actions)
    }

    fn maybe_send_acs_input(&mut self) -> Result<Vec<HashAsyncAction>, String> {
        if self.acs_input_sent || self.proposals.len() < self.instance.geometry.quorum as usize {
            return Ok(Vec::new());
        }
        let indices = self
            .proposals
            .keys()
            .copied()
            .take(self.instance.geometry.quorum as usize)
            .collect::<Vec<_>>();
        self.acs_input_sent = true;
        self.start_rbc(
            AftAsyncRbcPurposeV1::AcsInput,
            self.local,
            codec::to_bytes_canonical(&indices)?,
        )
    }

    fn refresh_acs_inputs(&mut self) -> Result<Vec<HashAsyncAction>, String> {
        let ready = self
            .pending_acs_inputs
            .iter()
            .filter(|(dealer, indices)| {
                !self.acs_inputs.contains_key(dealer)
                    && indices
                        .iter()
                        .all(|index| self.proposals.contains_key(index))
            })
            .map(|(dealer, indices)| (*dealer, indices.clone()))
            .collect::<Vec<_>>();
        let mut actions = Vec::new();
        for (dealer, indices) in ready {
            self.acs_inputs.insert(dealer, indices);
            if self.vaba_valid.insert(dealer) {
                if self.first_vaba_valid.is_none() {
                    self.first_vaba_valid = Some(dealer);
                    if let Some(view) = self.views.get_mut(&0) {
                        view.pre = Some(dealer);
                    }
                }
                actions.extend(self.maybe_send_prevote(0)?);
                let views = self.views.keys().copied().collect::<Vec<_>>();
                for view in views {
                    actions.extend(self.revalidate_prevotes(view)?);
                }
            }
        }
        Ok(actions)
    }

    fn start_view(
        &mut self,
        view: u64,
        pre: Option<u16>,
        justify: Vec<(u16, u16)>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if self.views.contains_key(&view) {
            return Ok(Vec::new());
        }
        if view > 0 && pre.is_none() {
            return Err("nonzero VABA view requires a justified prevote".into());
        }
        self.current_view = self.current_view.max(view);
        self.views.insert(
            view,
            VabaViewState::new(self.instance.geometry, self.local, view, pre, justify)?,
        );
        let mut material = AsksDealerMaterial::derive(
            self.instance_hash,
            self.instance.geometry,
            view,
            self.local,
            self.view_entropy(view)?,
        )?;
        let mut actions = self.start_rbc(
            AftAsyncRbcPurposeV1::AsksCommitments {
                view,
                dealer: self.local,
            },
            self.local,
            codec::to_bytes_canonical(&material.commitments)?,
        )?;
        for (recipient, share) in std::mem::take(&mut material.shares).into_iter().enumerate() {
            let recipient = u16::try_from(recipient)
                .map_err(|_| "ASKS recipient index overflow".to_string())?;
            actions.push(HashAsyncAction::Send {
                recipient,
                message: self.envelope(AftAsyncMessageBodyV1::Asks(AftAsyncAsksMessageV1::Share {
                    view,
                    dealer: self.local,
                    recipient,
                    share,
                })),
            });
        }
        actions.extend(self.maybe_send_prevote(view)?);
        if let Some(mut pending) = self.pending_view_messages.remove(&view) {
            while let Some((sender, body)) = pending.pop_front() {
                actions.extend(self.dispatch_body(sender, body)?);
            }
        }
        Ok(actions)
    }

    fn view_entropy(&self, view: u64) -> Result<[u8; 32], String> {
        hash_encoded(&(
            ENTROPY_DERIVATION_DOMAIN_V1.to_vec(),
            self.instance_hash,
            self.local,
            view,
            self.entropy_seed,
        ))
    }

    fn asks_participant(&mut self, view: u64, dealer: u16) -> Result<&mut AsksParticipant, String> {
        self.validate_view_bound(Some(view))?;
        let key = (view, dealer);
        if !self.asks.contains_key(&key) {
            self.asks.insert(
                key,
                AsksParticipant::new(
                    self.instance_hash,
                    self.instance.geometry,
                    self.local,
                    view,
                    dealer,
                )?,
            );
        }
        self.asks
            .get_mut(&key)
            .ok_or_else(|| "ASKS participant insertion failed".into())
    }

    fn asks_ra_state(
        &mut self,
        view: u64,
        dealer: u16,
    ) -> Result<&mut ReliableAgreementState, String> {
        let key = (view, dealer);
        if !self.asks_ra.contains_key(&key) {
            self.asks_ra.insert(
                key,
                ReliableAgreementState::new(
                    self.instance.geometry,
                    AftAsyncRaPurposeV1::AsksSharing { view, dealer },
                )?,
            );
        }
        self.asks_ra
            .get_mut(&key)
            .ok_or_else(|| "ASKS RA insertion failed".into())
    }

    fn maybe_start_asks_ra(
        &mut self,
        view: u64,
        dealer: u16,
        local_share_valid: bool,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if !local_share_valid || !self.asks_ra_input.insert((view, dealer)) {
            return Ok(Vec::new());
        }
        let action = self.asks_ra_state(view, dealer)?.input(vec![1])?;
        self.map_ra_action(AftAsyncRaPurposeV1::AsksSharing { view, dealer }, action)
    }

    fn handle_asks(
        &mut self,
        sender: u16,
        message: AftAsyncAsksMessageV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match message {
            AftAsyncAsksMessageV1::Share {
                view,
                dealer,
                recipient,
                share,
            } => {
                if recipient != self.local {
                    return Err("ASKS private share was delivered to the wrong recipient".into());
                }
                let valid = self
                    .asks_participant(view, dealer)?
                    .accept_private_share(sender, share)?;
                self.maybe_start_asks_ra(view, dealer, valid)
            }
            AftAsyncAsksMessageV1::Reconstruct {
                view,
                dealer,
                owner,
                share,
            } => {
                if sender != owner {
                    return Err("ASKS reconstruction owner does not match channel sender".into());
                }
                if !self.view(view)?.reconstruction_started.contains(&dealer) {
                    let shares = self
                        .pending_reconstruction
                        .entry((view, dealer))
                        .or_default();
                    match shares.insert(owner, share) {
                        Some(previous) if previous != share => {
                            shares.insert(owner, previous);
                            return Err("ASKS reconstruction owner equivocated before start".into());
                        }
                        _ => return Ok(Vec::new()),
                    }
                }
                self.accept_reconstruction(view, dealer, owner, share)
            }
        }
    }

    fn accept_reconstruction(
        &mut self,
        view: u64,
        dealer: u16,
        owner: u16,
        share: [u8; 32],
    ) -> Result<Vec<HashAsyncAction>, String> {
        let output = self
            .asks_participant(view, dealer)?
            .accept_reconstruction_share(owner, share)?;
        if let Some(output) = output {
            let secret = match output {
                AsksReconstruction::Secret(secret)
                | AsksReconstruction::MalformedDealer(secret) => secret,
            };
            self.view_mut(view)?.secrets.insert(dealer, secret);
            self.maybe_send_vote(view)
        } else {
            Ok(Vec::new())
        }
    }

    fn handle_ra(
        &mut self,
        sender: u16,
        purpose: AftAsyncRaPurposeV1,
        phase: AftAsyncRaPhaseV1,
        value_hash: [u8; 32],
        value: Vec<u8>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match purpose.clone() {
            AftAsyncRaPurposeV1::AsksSharing { view, dealer } => {
                self.validate_view_bound(Some(view))?;
                if value != [1] {
                    return Err("ASKS sharing RA accepts only one".into());
                }
                let actions = self
                    .asks_ra_state(view, dealer)?
                    .handle(sender, phase, value_hash, value)?;
                let mut output = Vec::new();
                for action in actions {
                    match action {
                        RaAction::Output(value) => {
                            if value != [1] {
                                return Err("ASKS sharing RA output was not one".into());
                            }
                            self.asks_participant(view, dealer)?.finish_sharing()?;
                            self.view_mut(view)?.shared.insert(dealer);
                            output.extend(self.maybe_send_prevote(view)?);
                            output.extend(self.revalidate_prevotes(view)?);
                        }
                        other => output.extend(self.map_ra_action(purpose.clone(), other)?),
                    }
                }
                Ok(output)
            }
            AftAsyncRaPurposeV1::CoverValidation { view, candidate } => {
                self.validate_view_bound(Some(view))?;
                let actions = self
                    .view_mut(view)?
                    .icg
                    .handle_ra(sender, candidate, phase, value_hash, value)?;
                self.map_icg_actions(view, actions)
            }
            AftAsyncRaPurposeV1::VabaDecision => {
                let actions = self.decision_ra.handle(sender, phase, value_hash, value)?;
                let mut output = Vec::new();
                for action in actions {
                    match action {
                        RaAction::Output(value) => {
                            let winner = codec::from_bytes_canonical::<u16>(&value)?;
                            output.extend(self.finish_acs(winner)?);
                        }
                        other => output.extend(self.map_ra_action(purpose.clone(), other)?),
                    }
                }
                Ok(output)
            }
        }
    }

    fn map_ra_action(
        &self,
        purpose: AftAsyncRaPurposeV1,
        action: RaAction,
    ) -> Result<Vec<HashAsyncAction>, String> {
        match action {
            RaAction::Broadcast {
                phase,
                value_hash,
                value,
            } => Ok(vec![HashAsyncAction::Broadcast(self.envelope(
                AftAsyncMessageBodyV1::ReliableAgreement {
                    purpose,
                    phase,
                    value_hash,
                    value,
                },
            ))]),
            RaAction::Output(_) => Err("unhandled RA output action".into()),
        }
    }

    fn maybe_send_prevote(&mut self, view: u64) -> Result<Vec<HashAsyncAction>, String> {
        let threshold = self.instance.geometry.f as usize + 1;
        let (pre, justify, shared_dealers) = {
            let state = self.view_mut(view)?;
            if state.prevote_sent || state.pre.is_none() || state.shared.len() < threshold {
                return Ok(Vec::new());
            }
            let pre = state
                .pre
                .ok_or_else(|| "VABA prevote disappeared".to_string())?;
            let shared_dealers = state.shared.iter().copied().take(threshold).collect();
            state.prevote_sent = true;
            (pre, state.justify.clone(), shared_dealers)
        };
        self.start_rbc(
            AftAsyncRbcPurposeV1::VabaPrevote { view },
            self.local,
            codec::to_bytes_canonical(&VabaPrevoteV1 {
                pre,
                shared_dealers,
                justify,
            })?,
        )
    }

    fn try_validate_prevote(
        &mut self,
        view: u64,
        dealer: u16,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if self.view(view)?.validated_prevotes.contains(&dealer)
            || !self.prevote_is_valid(view, dealer)?
        {
            return Ok(Vec::new());
        }
        self.view_mut(view)?.validated_prevotes.insert(dealer);
        let actions = self.view_mut(view)?.icg.add_valid(dealer)?;
        self.map_icg_actions(view, actions)
    }

    fn revalidate_prevotes(&mut self, view: u64) -> Result<Vec<HashAsyncAction>, String> {
        let dealers = self
            .view(view)?
            .prevotes
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut actions = Vec::new();
        for dealer in dealers {
            actions.extend(self.try_validate_prevote(view, dealer)?);
        }
        Ok(actions)
    }

    fn prevote_is_valid(&self, view: u64, dealer: u16) -> Result<bool, String> {
        let state = self.view(view)?;
        let Some(prevote) = state.prevotes.get(&dealer) else {
            return Ok(false);
        };
        if !self.vaba_valid.contains(&prevote.pre)
            || prevote.shared_dealers.len() != self.instance.geometry.f as usize + 1
            || validate_index_set(
                &prevote.shared_dealers,
                self.instance.geometry.n,
                self.instance.geometry.f + 1,
            )
            .is_err()
            || !prevote
                .shared_dealers
                .iter()
                .all(|member| state.shared.contains(member))
        {
            return Ok(false);
        }
        if view == 0 {
            return Ok(prevote.justify.is_empty());
        }
        if prevote.justify.len() != self.instance.geometry.quorum as usize
            || !canonical_justification(&prevote.justify, self.instance.geometry.n)
        {
            return Ok(false);
        }
        let previous = self.view(view - 1)?;
        if !prevote
            .justify
            .iter()
            .all(|(voter, candidate)| previous.votes.get(voter) == Some(candidate))
        {
            return Ok(false);
        }
        Ok(most_frequent(&prevote.justify) == Some(prevote.pre))
    }

    fn handle_gather(
        &mut self,
        sender: u16,
        view: u64,
        message: AftAsyncGatherMessageV1,
    ) -> Result<Vec<HashAsyncAction>, String> {
        self.validate_view_bound(Some(view))?;
        let actions = self.view_mut(view)?.icg.handle_gather(sender, message)?;
        self.map_icg_actions(view, actions)
    }

    fn map_icg_actions(
        &mut self,
        view: u64,
        actions: Vec<IndexCoverGatherAction>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        let mut output = Vec::new();
        for action in actions {
            match action {
                IndexCoverGatherAction::RaBroadcast {
                    purpose,
                    phase,
                    value_hash,
                    value,
                } => output.push(HashAsyncAction::Broadcast(self.envelope(
                    AftAsyncMessageBodyV1::ReliableAgreement {
                        purpose,
                        phase,
                        value_hash,
                        value,
                    },
                ))),
                IndexCoverGatherAction::GatherBroadcast(message) => {
                    output.push(HashAsyncAction::Broadcast(
                        self.envelope(AftAsyncMessageBodyV1::Gather { view, message }),
                    ));
                }
                IndexCoverGatherAction::GatherSend { recipient, message } => {
                    output.push(HashAsyncAction::Send {
                        recipient,
                        message: self.envelope(AftAsyncMessageBodyV1::Gather { view, message }),
                    });
                }
                IndexCoverGatherAction::Output(indices) => {
                    output.extend(self.start_reconstruction(view, indices)?);
                }
            }
        }
        Ok(output)
    }

    fn start_reconstruction(
        &mut self,
        view: u64,
        indices: Vec<u16>,
    ) -> Result<Vec<HashAsyncAction>, String> {
        {
            let state = self.view_mut(view)?;
            if let Some(previous) = &state.icg_output {
                return if previous == &indices {
                    Ok(Vec::new())
                } else {
                    Err("ICG attempted to output conflicting sets".into())
                };
            }
            state.icg_output = Some(indices.clone());
        }
        let dealers = indices
            .iter()
            .flat_map(|index| {
                self.views
                    .get(&view)
                    .and_then(|state| state.prevotes.get(index))
                    .map(|prevote| prevote.shared_dealers.clone())
                    .unwrap_or_default()
            })
            .collect::<BTreeSet<_>>();
        let mut actions = Vec::new();
        for dealer in dealers {
            if !self.view_mut(view)?.reconstruction_started.insert(dealer) {
                continue;
            }
            if let Some(share) = self
                .asks_participant(view, dealer)?
                .start_reconstruction()?
            {
                actions.push(HashAsyncAction::Broadcast(self.envelope(
                    AftAsyncMessageBodyV1::Asks(AftAsyncAsksMessageV1::Reconstruct {
                        view,
                        dealer,
                        owner: self.local,
                        share,
                    }),
                )));
            }
            if let Some(pending) = self.pending_reconstruction.remove(&(view, dealer)) {
                for (owner, share) in pending {
                    actions.extend(self.accept_reconstruction(view, dealer, owner, share)?);
                }
            }
        }
        actions.extend(self.maybe_send_vote(view)?);
        Ok(actions)
    }

    fn maybe_send_vote(&mut self, view: u64) -> Result<Vec<HashAsyncAction>, String> {
        let state = self.view(view)?;
        if state.vote_sent {
            return Ok(Vec::new());
        }
        let Some(indices) = state.icg_output.clone() else {
            return Ok(Vec::new());
        };
        let mut ranked = Vec::new();
        for index in indices {
            let prevote = state
                .prevotes
                .get(&index)
                .ok_or_else(|| "ICG output lacks a delivered prevote".to_string())?;
            let mut rank = [0u8; 32];
            for dealer in &prevote.shared_dealers {
                let Some(secret) = state.secrets.get(dealer) else {
                    return Ok(Vec::new());
                };
                let component = hash_encoded(&(
                    RANK_DOMAIN_V1.to_vec(),
                    self.instance_hash,
                    view,
                    index,
                    dealer,
                    secret,
                ))?;
                add_rank(&mut rank, &component);
            }
            ranked.push((rank, std::cmp::Reverse(index), prevote.pre));
        }
        let (_, _, candidate) = ranked
            .into_iter()
            .max()
            .ok_or_else(|| "ICG output was empty".to_string())?;
        self.view_mut(view)?.vote_sent = true;
        self.start_rbc(
            AftAsyncRbcPurposeV1::VabaVote { view },
            self.local,
            codec::to_bytes_canonical(&candidate)?,
        )
    }

    fn accept_vote(
        &mut self,
        view: u64,
        dealer: u16,
        candidate: u16,
    ) -> Result<Vec<HashAsyncAction>, String> {
        if !self.vaba_valid.contains(&candidate) {
            return Err("VABA vote selects an unvalidated ACS input".into());
        }
        let state = self.view_mut(view)?;
        match state.votes.insert(dealer, candidate) {
            Some(previous) if previous != candidate => {
                state.votes.insert(dealer, previous);
                return Err("VABA vote RBC rebound its delivered candidate".into());
            }
            _ => {}
        }
        let votes = self.view(view)?.votes.clone();
        let mut actions = Vec::new();
        let mut counts = BTreeMap::<u16, usize>::new();
        for candidate in votes.values() {
            *counts.entry(*candidate).or_default() += 1;
        }
        if self.decision_ra_input.is_none() {
            if let Some(candidate) = counts
                .iter()
                .find(|(_, count)| **count >= self.instance.geometry.quorum as usize)
                .map(|(candidate, _)| *candidate)
            {
                self.decision_ra_input = Some(candidate);
                let action = self
                    .decision_ra
                    .input(codec::to_bytes_canonical(&candidate)?)?;
                actions.extend(self.map_ra_action(AftAsyncRaPurposeV1::VabaDecision, action)?);
            }
        }
        if votes.len() >= self.instance.geometry.quorum as usize && !self.view(view)?.next_started {
            let justify = votes
                .iter()
                .take(self.instance.geometry.quorum as usize)
                .map(|(voter, candidate)| (*voter, *candidate))
                .collect::<Vec<_>>();
            let pre = most_frequent(&justify)
                .ok_or_else(|| "VABA vote justification is empty".to_string())?;
            self.view_mut(view)?.next_started = true;
            actions.extend(self.start_view(view + 1, Some(pre), justify)?);
        }
        Ok(actions)
    }

    fn finish_acs(&mut self, winner: u16) -> Result<Vec<HashAsyncAction>, String> {
        if let Some((decision, transcript)) = &self.output {
            return Ok(vec![HashAsyncAction::Decide {
                decision: Box::new(decision.clone()),
                transcript: Box::new(transcript.clone()),
            }]);
        }
        let indices = self
            .acs_inputs
            .get(&winner)
            .ok_or_else(|| "VABA output lacks a validated ACS-input RBC".to_string())?
            .clone();
        let (decision, transcript) = HashAsyncOrderingAdapter::decide(
            self.instance.clone(),
            winner,
            &indices,
            &self.proposals,
        )?;
        self.output = Some((decision.clone(), transcript.clone()));
        Ok(vec![HashAsyncAction::Decide {
            decision: Box::new(decision),
            transcript: Box::new(transcript),
        }])
    }

    fn view(&self, view: u64) -> Result<&VabaViewState, String> {
        self.views
            .get(&view)
            .ok_or_else(|| format!("VABA view {view} has not started"))
    }

    fn view_mut(&mut self, view: u64) -> Result<&mut VabaViewState, String> {
        self.views
            .get_mut(&view)
            .ok_or_else(|| format!("VABA view {view} has not started"))
    }

    fn validate_view_bound(&self, view: Option<u64>) -> Result<(), String> {
        if view.is_some_and(|view| view > self.current_view.saturating_add(MAX_VABA_VIEW_LEAD)) {
            return Err("hash-async message is too far ahead of the local VABA view".into());
        }
        Ok(())
    }
}

fn rbc_view(purpose: &AftAsyncRbcPurposeV1) -> Option<u64> {
    match purpose {
        AftAsyncRbcPurposeV1::VabaPrevote { view }
        | AftAsyncRbcPurposeV1::VabaVote { view }
        | AftAsyncRbcPurposeV1::AsksCommitments { view, .. } => Some(*view),
        AftAsyncRbcPurposeV1::Proposal | AftAsyncRbcPurposeV1::AcsInput => None,
    }
}

fn message_body_view(body: &AftAsyncMessageBodyV1) -> Option<u64> {
    match body {
        AftAsyncMessageBodyV1::Rbc { purpose, .. } => rbc_view(purpose),
        AftAsyncMessageBodyV1::ReliableAgreement { purpose, .. } => match purpose {
            AftAsyncRaPurposeV1::AsksSharing { view, .. }
            | AftAsyncRaPurposeV1::CoverValidation { view, .. } => Some(*view),
            AftAsyncRaPurposeV1::VabaDecision => None,
        },
        AftAsyncMessageBodyV1::Asks(message) => match message {
            AftAsyncAsksMessageV1::Share { view, .. }
            | AftAsyncAsksMessageV1::Reconstruct { view, .. } => Some(*view),
        },
        AftAsyncMessageBodyV1::Gather { view, .. } => Some(*view),
    }
}

fn canonical_justification(justify: &[(u16, u16)], n: u16) -> bool {
    let mut previous = None;
    justify.iter().all(|(voter, candidate)| {
        let valid = *voter < n && *candidate < n && previous.map_or(true, |old| old < *voter);
        previous = Some(*voter);
        valid
    })
}

fn most_frequent(justify: &[(u16, u16)]) -> Option<u16> {
    let mut counts = BTreeMap::<u16, usize>::new();
    for (_, candidate) in justify {
        *counts.entry(*candidate).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(candidate, count)| (*count, std::cmp::Reverse(*candidate)))
        .map(|(candidate, _)| candidate)
}

fn add_rank(rank: &mut [u8; 32], component: &[u8; 32]) {
    let mut carry = 0u16;
    for (left, right) in rank.iter_mut().rev().zip(component.iter().rev()) {
        let sum = u16::from(*left) + u16::from(*right) + carry;
        *left = sum as u8;
        carry = sum >> 8;
    }
}

fn hash_encoded<T: Encode>(value: &T) -> Result<[u8; 32], String> {
    let bytes = codec::to_bytes_canonical(value)?;
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) mod tests_support {
    use ioi_types::app::{
        AccountId, AftAsyncGeometryV1, AftAsyncInstanceV1, AftAsyncProposalRefV1,
        AftFallbackScopeV1, AftFallbackTriggerCertificateV1, AftTimeoutCertificateV1,
        AftTimeoutVoteV1, FallbackStartCertificateV1, QuorumCertificate,
        AFT_TIMEOUT_PROTOCOL_VERSION_V1, AFT_TIMEOUT_SCHEMA_VERSION_V1,
    };

    pub(crate) fn test_instance() -> AftAsyncInstanceV1 {
        let scope = AftFallbackScopeV1 {
            network_id: [11; 32],
            configuration_hash: [12; 32],
            epoch: 1,
        };
        let tc = |view| AftTimeoutCertificateV1 {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height: 5,
            view,
            votes: vec![AftTimeoutVoteV1 {
                protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                scope,
                height: 5,
                view,
                highest_qc: QuorumCertificate::default(),
                highest_qc_async_parent_proof_hash: None,
                locked_qc: QuorumCertificate::default(),
                locked_qc_async_parent_proof_hash: None,
                voter: AccountId([view as u8; 32]),
                signature: vec![1],
            }],
        };
        let start = FallbackStartCertificateV1::new(
            scope,
            5,
            AftFallbackTriggerCertificateV1 {
                height: 5,
                consecutive_timeout_certificates: vec![tc(1), tc(2), tc(3)],
            },
        )
        .unwrap();
        AftAsyncInstanceV1::from_fallback_start(&start, AftAsyncGeometryV1::exact(4).unwrap())
            .unwrap()
    }

    pub(crate) fn proposal_for(
        instance: &AftAsyncInstanceV1,
        proposer: u16,
    ) -> AftAsyncProposalRefV1 {
        AftAsyncProposalRefV1 {
            proposer,
            proposal_hash: [proposer as u8 + 20; 32],
            payload_len: 100,
            availability_certificate_hash: [proposer as u8 + 40; 32],
            parent_root: instance.locked_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::proposal_for;
    use super::*;
    use ioi_types::app::{
        AccountId, AftAsyncGeometryV1, AftFallbackScopeV1, AftFallbackTriggerCertificateV1,
        AftTimeoutCertificateV1, AftTimeoutVoteV1, FallbackStartCertificateV1, QuorumCertificate,
        AFT_TIMEOUT_PROTOCOL_VERSION_V1, AFT_TIMEOUT_SCHEMA_VERSION_V1,
    };
    use std::collections::VecDeque;

    #[test]
    fn frequency_ties_choose_the_lowest_index() {
        assert_eq!(most_frequent(&[(0, 2), (1, 1), (2, 2), (3, 1)]), Some(1));
    }

    #[test]
    fn rank_addition_is_modulo_two_to_256() {
        let mut left = [0xff; 32];
        let mut right = [0; 32];
        right[31] = 1;
        add_rank(&mut left, &right);
        assert_eq!(left, [0; 32]);
    }

    #[test]
    fn prestart_messages_and_late_availability_are_buffered_without_authority() {
        let instance = test_instance();
        let mut sender = HashAsyncNode::new(instance.clone(), 0, [1; 32]).unwrap();
        let remote = proposal_for(&instance, 0);
        let first = sender
            .start(remote.clone())
            .unwrap()
            .into_iter()
            .find_map(|action| match action {
                HashAsyncAction::Broadcast(message) => Some(message),
                _ => None,
            })
            .unwrap();
        let mut receiver = HashAsyncNode::new(instance.clone(), 1, [2; 32]).unwrap();
        assert!(receiver.handle(0, first).unwrap().is_empty());
        assert_eq!(receiver.pending_start_messages.len(), 1);
        receiver.start(proposal_for(&instance, 1)).unwrap();
        assert!(receiver.pending_start_messages.is_empty());

        receiver
            .on_rbc_delivery(
                AftAsyncRbcPurposeV1::Proposal,
                0,
                codec::to_bytes_canonical(&remote).unwrap(),
            )
            .unwrap();
        assert!(!receiver.proposals.contains_key(&0));
        receiver.admit_verified_proposal(remote).unwrap();
        assert!(receiver.proposals.contains_key(&0));
    }

    #[test]
    fn terminal_checkpoint_refuses_a_transcript_for_a_different_selected_set() {
        let instance = test_instance();
        let available = (0..3)
            .map(|proposer| {
                let proposal = proposal_for(&instance, proposer);
                (proposer, proposal)
            })
            .collect::<BTreeMap<_, _>>();
        let (mut decision, mut transcript) =
            HashAsyncOrderingAdapter::decide(instance.clone(), 0, &[0, 1, 2], &available).unwrap();
        transcript.proposal_commitments[0] = [0xf1; 32];
        decision.transcript_root = transcript.transcript_root(&instance).unwrap();
        decision.validate().unwrap();

        assert!(HashAsyncNode::from_terminal_checkpoint(
            instance, 0, [9; 32], None, decision, transcript,
        )
        .is_err());
    }

    fn test_instance() -> AftAsyncInstanceV1 {
        let scope = AftFallbackScopeV1 {
            network_id: [11; 32],
            configuration_hash: [12; 32],
            epoch: 1,
        };
        let tc = |view| AftTimeoutCertificateV1 {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height: 5,
            view,
            votes: vec![AftTimeoutVoteV1 {
                protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                scope,
                height: 5,
                view,
                highest_qc: QuorumCertificate::default(),
                highest_qc_async_parent_proof_hash: None,
                locked_qc: QuorumCertificate::default(),
                locked_qc_async_parent_proof_hash: None,
                voter: AccountId([view as u8; 32]),
                signature: vec![1],
            }],
        };
        let start = FallbackStartCertificateV1::new(
            scope,
            5,
            AftFallbackTriggerCertificateV1 {
                height: 5,
                consecutive_timeout_certificates: vec![tc(1), tc(2), tc(3)],
            },
        )
        .unwrap();
        AftAsyncInstanceV1::from_fallback_start(&start, AftAsyncGeometryV1::exact(4).unwrap())
            .unwrap()
    }

    fn enqueue(
        queue: &mut VecDeque<(u16, AftAsyncMessageV1)>,
        actions: Vec<HashAsyncAction>,
        n: u16,
    ) {
        for action in actions {
            match action {
                HashAsyncAction::Broadcast(message) => {
                    for recipient in 0..n {
                        queue.push_back((recipient, message.clone()));
                    }
                }
                HashAsyncAction::Send { recipient, message } => {
                    queue.push_back((recipient, message));
                }
                HashAsyncAction::Decide { .. } => {}
            }
        }
    }

    fn enqueue_retried(
        queue: &mut VecDeque<(u16, AftAsyncMessageV1, u8)>,
        actions: Vec<HashAsyncAction>,
        n: u16,
    ) {
        for action in actions {
            let deliveries = match action {
                HashAsyncAction::Broadcast(message) => (0..n)
                    .map(|recipient| (recipient, message.clone()))
                    .collect::<Vec<_>>(),
                HashAsyncAction::Send { recipient, message } => vec![(recipient, message)],
                HashAsyncAction::Decide { .. } => Vec::new(),
            };
            for (recipient, message) in deliveries {
                // The first transmission is deliberately lost. Two subsequent
                // copies model reliable-channel retry and exercise idempotence.
                for attempt in 0..3 {
                    queue.push_back((recipient, message.clone(), attempt));
                }
            }
        }
    }

    fn xorshift64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn four_honest_nodes_complete_message_acs_without_a_clock_or_setup() {
        let instance = test_instance();
        let n = instance.geometry.n;
        let mut nodes = (0..n)
            .map(|local| {
                HashAsyncNode::new(instance.clone(), local, [local as u8 + 1; 32]).unwrap()
            })
            .collect::<Vec<_>>();
        let mut queue = VecDeque::new();
        let proposals = (0..n)
            .map(|local| AftAsyncProposalRefV1 {
                proposer: local,
                proposal_hash: [local as u8 + 20; 32],
                payload_len: 100,
                availability_certificate_hash: [local as u8 + 40; 32],
                parent_root: instance.locked_root,
            })
            .collect::<Vec<_>>();
        for node in &mut nodes {
            for proposal in &proposals {
                node.admit_verified_proposal(proposal.clone()).unwrap();
            }
        }
        for local in 0..n {
            let actions = nodes[local as usize]
                .start(proposals[local as usize].clone())
                .unwrap();
            enqueue(&mut queue, actions, n);
        }

        let mut deliveries = 0usize;
        while nodes.iter().any(|node| node.output().is_none()) && deliveries < 500_000 {
            let (recipient, message) = queue.pop_front().unwrap_or_else(|| {
                panic!("protocol quiesced before decision at delivery {deliveries}")
            });
            let sender = message.sender;
            let actions = nodes[recipient as usize].handle(sender, message).unwrap();
            enqueue(&mut queue, actions, n);
            deliveries += 1;
        }
        assert!(deliveries < 500_000, "protocol exceeded delivery bound");
        let roots = nodes
            .iter()
            .map(|node| node.output().unwrap().0.ordering_root)
            .collect::<BTreeSet<_>>();
        assert_eq!(roots.len(), 1, "honest nodes decided different order roots");
        for node in &nodes {
            let (decision, transcript) = node.output().unwrap();
            decision.validate().unwrap();
            transcript.validate(&instance).unwrap();
            assert_eq!(decision.selected.len(), 3);
        }
    }

    #[test]
    fn asynchronous_schedule_tolerates_one_silent_byzantine_loss_reordering_and_duplicates() {
        let instance = test_instance();
        let n = instance.geometry.n;
        let honest = 3u16;
        let mut nodes = (0..honest)
            .map(|local| {
                HashAsyncNode::new(instance.clone(), local, [local as u8 + 71; 32]).unwrap()
            })
            .collect::<Vec<_>>();
        let mut queue = VecDeque::new();
        let proposals = (0..honest)
            .map(|local| AftAsyncProposalRefV1 {
                proposer: local,
                proposal_hash: [local as u8 + 90; 32],
                payload_len: 512,
                availability_certificate_hash: [local as u8 + 110; 32],
                parent_root: instance.locked_root,
            })
            .collect::<Vec<_>>();
        for node in &mut nodes {
            for proposal in &proposals {
                node.admit_verified_proposal(proposal.clone()).unwrap();
            }
        }
        for local in 0..honest {
            let proposal = proposals[local as usize].clone();
            let actions = nodes[local as usize].start(proposal.clone()).unwrap();
            enqueue_retried(&mut queue, actions, n);
            assert!(nodes[local as usize].start(proposal).unwrap().is_empty());
        }

        let mut malformed = queue.front().unwrap().1.clone();
        malformed.instance_hash[0] ^= 1;
        assert!(nodes[0].handle(malformed.sender, malformed).is_err());

        let mut rng = 0xd1b5_4a32_d192_ed03u64;
        let mut deliveries = 0usize;
        let mut dropped = 0usize;
        let mut saw_future_buffer = false;
        let mut saw_reconstruction_buffer = false;
        while nodes.iter().any(|node| node.output().is_none()) && deliveries < 2_000_000 {
            let index = (xorshift64(&mut rng) as usize) % queue.len();
            let (recipient, message, attempt) = queue.remove(index).unwrap();
            if recipient >= honest || attempt == 0 {
                dropped += 1;
                continue;
            }
            let sender = message.sender;
            let actions = nodes[recipient as usize].handle(sender, message).unwrap();
            enqueue_retried(&mut queue, actions, n);
            saw_future_buffer |= !nodes[recipient as usize].pending_view_messages.is_empty();
            saw_reconstruction_buffer |=
                !nodes[recipient as usize].pending_reconstruction.is_empty();
            deliveries += 1;
        }

        assert!(deliveries < 2_000_000, "protocol exceeded delivery bound");
        assert!(dropped > 0, "scheduler did not exercise packet loss");
        assert!(
            saw_future_buffer || saw_reconstruction_buffer,
            "scheduler did not exercise an early asynchronous delivery"
        );
        let roots = nodes
            .iter()
            .map(|node| node.output().unwrap().0.ordering_root)
            .collect::<BTreeSet<_>>();
        assert_eq!(roots.len(), 1, "honest nodes decided different order roots");
        for node in &nodes {
            let (decision, transcript) = node.output().unwrap();
            decision.validate().unwrap();
            transcript.validate(&instance).unwrap();
            assert_eq!(decision.selected.len(), 3);
        }
    }
}
