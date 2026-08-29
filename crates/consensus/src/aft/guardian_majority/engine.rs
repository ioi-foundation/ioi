use super::*;

/// How many observed validator-set snapshots to retain.
///
/// Authentication only ever looks near the tip, so this bounds growth while
/// still covering votes that arrive for recent heights out of order.
const VALIDATOR_SET_CACHE_DEPTH: usize = 64;

impl GuardianMajorityEngine {
    pub(super) fn benchmark_trace_enabled() -> bool {
        std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
    }

    pub fn new(safety_mode: AftSafetyMode) -> Self {
        Self::with_view_timeout(safety_mode, Duration::from_secs(5))
    }

    pub fn with_view_timeout(safety_mode: AftSafetyMode, view_timeout: Duration) -> Self {
        let bootstrap_grace_secs = std::env::var("IOI_AFT_BOOTSTRAP_GRACE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(8);
        Self {
            safety_mode,
            continuity_verifier: SharedContinuityVerifier::default(),
            last_seen_counters: HashMap::new(),
            view_votes: HashMap::new(),
            tc_formed: HashSet::new(),
            timeout_votes_sent: HashSet::new(),
            seen_headers: HashMap::new(),
            vote_pool: HashMap::new(),
            validator_count_by_height: HashMap::new(),
            qc_pool: HashMap::new(),
            committed_headers: HashMap::new(),
            committed_collapses: HashMap::new(),
            recovered_headers: HashMap::new(),
            recovered_certified_headers: HashMap::new(),
            recovered_restart_headers: HashMap::new(),
            pending_qc_broadcasts: VecDeque::new(),
            announced_qcs: HashSet::new(),
            highest_qc: QuorumCertificate::default(),
            mirror_seed: [0u8; 32],
            echo_pool: HashMap::new(),
            voted_slots: HashSet::new(),
            pacemaker: Arc::new(Mutex::new(Pacemaker::new(view_timeout))),
            safety: SafetyGadget::new(),
            mirror_stats: MirrorStats::default(),
            cached_validator_count: 1,
            bootstrap_grace_until: Instant::now()
                .checked_add(Duration::from_secs(bootstrap_grace_secs))
                .unwrap_or_else(Instant::now),
            key_registry: ValidatorKeyRegistry::new(),
            validator_sets_by_height: BTreeMap::new(),
            finalized_quorum_events: VecDeque::new(),
            emitted_finalized_quorums: HashSet::new(),
        }
    }

    pub fn safety_mode(&self) -> AftSafetyMode {
        self.safety_mode
    }

    pub(super) fn verify_canonical_collapse_backend(
        &self,
        collapse: &CanonicalCollapseObject,
    ) -> Result<(), ConsensusError> {
        let proof = &collapse.continuity_recursive_proof;
        match proof.proof_system {
            CanonicalCollapseContinuityProofSystem::HashPcdV1 => Ok(()),
            CanonicalCollapseContinuityProofSystem::SuccinctSp1V1 => {
                let public_inputs = canonical_collapse_continuity_public_inputs(
                    &proof.commitment,
                    proof.previous_canonical_collapse_commitment_hash,
                    proof.payload_hash,
                    proof.previous_recursive_proof_hash,
                );
                self.continuity_verifier
                    .0
                    .verify_canonical_collapse_continuity(
                        proof.proof_system,
                        &proof.proof_bytes,
                        &public_inputs,
                    )
                    .map_err(|error| {
                        ConsensusError::BlockVerificationFailed(format!(
                            "canonical collapse continuity backend verification failed for height {}: {}",
                            collapse.height, error
                        ))
                    })
            }
        }
    }

    pub(super) fn verify_runtime_canonical_collapse_continuity(
        &self,
        collapse: &CanonicalCollapseObject,
        previous: Option<&CanonicalCollapseObject>,
    ) -> Result<(), ConsensusError> {
        verify_canonical_collapse_continuity(collapse, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.verify_canonical_collapse_backend(collapse)
    }

    pub(super) fn quorum_weight_threshold(&self, total_weight: u128) -> u128 {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => (total_weight * 2) / 3,
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => total_weight / 2,
        }
    }

    pub(super) fn quorum_count_threshold(&self, count: usize) -> usize {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => ((count * 2) / 3) + 1,
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => (count / 2) + 1,
        }
    }

    pub(super) fn remember_validator_count(&mut self, height: u64, count: usize) {
        let count = count.max(1);
        self.cached_validator_count = count;
        self.validator_count_by_height.insert(height, count);
    }

    pub(super) fn quorum_count_threshold_for_height(&self, height: u64) -> usize {
        let count = self
            .validator_count_by_height
            .get(&height)
            .copied()
            .unwrap_or(self.cached_validator_count)
            .max(1);
        self.quorum_count_threshold(count)
    }

    /// Records the validator sets exactly as read from an anchored state view.
    pub(super) fn remember_validator_sets(&mut self, height: u64, sets: &ValidatorSetsV1) {
        self.validator_sets_by_height.insert(height, sets.clone());
        while self.validator_sets_by_height.len() > VALIDATOR_SET_CACHE_DEPTH {
            let Some(oldest) = self.validator_sets_by_height.keys().next().copied() else {
                break;
            };
            self.validator_sets_by_height.remove(&oldest);
        }
    }

    /// The effective validator set to authenticate evidence for `height`.
    ///
    /// Uses the most recent sets observed at or **below** `height`. There is
    /// deliberately no fallback to a newer observation: a membership that took
    /// effect after the evidence was produced must never be used to authenticate
    /// it, or a rotated-in validator could retroactively validate history it was
    /// never part of.
    ///
    /// Returns `None` when nothing was observed at or below `height`, which
    /// makes every signature check fail closed rather than admit evidence
    /// against an assumed membership.
    pub(super) fn effective_validator_set_for(&self, height: u64) -> Option<ValidatorSetV1> {
        let sets = self
            .validator_sets_by_height
            .range(..=height)
            .next_back()
            .map(|(_, sets)| sets)?;
        Some(effective_set_for_height(sets, height).clone())
    }

    /// Learns the keys inlined in already-authenticated peer identities.
    ///
    /// The transport authenticated these peers, and an Ed25519 peer id carries
    /// its own public key, so this adds no trust: it only makes a key the node
    /// already holds usable for signature checks. A peer that is not a
    /// validator simply never matches a validator record.
    pub(super) fn learn_authenticated_peer_keys(&mut self, peers: &HashSet<PeerId>) {
        for peer in peers {
            let _ = self.key_registry.learn_peer_id(peer);
        }
    }

    /// Completes the raw-key registry from the same anchored state view that
    /// supplied the effective validator set.
    ///
    /// A star or relayed topology does not give every validator a direct
    /// transport identity for every other member. The canonical identity map
    /// does: each validator account indexes the exact raw key whose hash is
    /// bound by `ValidatorV1::consensus_key`. Existing transport-learned keys
    /// remain usable, but every missing member is resolved from rooted state
    /// and rebound before any relayed vote or certificate can count.
    pub(super) async fn hydrate_effective_validator_keys(
        &mut self,
        view: &dyn AnchoredStateView,
        set: &ValidatorSetV1,
    ) -> Result<bool, ConsensusError> {
        let mut complete = true;
        for validator in &set.validators {
            if self
                .key_registry
                .get(&validator.consensus_key.public_key_hash)
                .is_some()
            {
                continue;
            }
            if validator.consensus_key.suite != ioi_types::app::SignatureSuite::ED25519 {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "native AFT validator {} declares unsupported consensus suite {:?}",
                    hex::encode(validator.account_id.as_ref()),
                    validator.consensus_key.suite
                )));
            }
            let key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, validator.account_id.as_ref()].concat();
            let Some(encoded) = view.get(&key).await.map_err(|error| {
                ConsensusError::BlockVerificationFailed(format!(
                    "failed to read canonical consensus key for validator {}: {error}",
                    hex::encode(validator.account_id.as_ref())
                ))
            })?
            else {
                // Key unavailability is a liveness condition, not authority.
                // Continue the state machine, but any vote/QC naming this
                // member remains unverifiable and therefore cannot count.
                complete = false;
                continue;
            };
            let public_key = PublicKey::try_decode_protobuf(&encoded).map_err(|_| {
                ConsensusError::BlockVerificationFailed(format!(
                    "canonical consensus key is malformed for validator {}",
                    hex::encode(validator.account_id.as_ref())
                ))
            })?;
            let observed_hash = self.key_registry.learn_public_key(&public_key)?;
            if observed_hash != validator.consensus_key.public_key_hash {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "canonical consensus key substitution for validator {}: expected={} actual={}",
                    hex::encode(validator.account_id.as_ref()),
                    hex::encode(validator.consensus_key.public_key_hash),
                    hex::encode(observed_hash)
                )));
            }
        }
        Ok(complete)
    }

    /// Records a protobuf-encoded public key the node has authenticated.
    pub(super) fn record_validator_public_key(&mut self, protobuf_public_key: &[u8]) -> bool {
        let Ok(key) = PublicKey::try_decode_protobuf(protobuf_public_key) else {
            return false;
        };
        self.key_registry.learn_public_key(&key).is_ok()
    }

    /// Re-verifies a certificate against the effective set and known raw keys.
    ///
    /// Used for both received and locally assembled certificates so the two can
    /// never diverge: a certificate this node built from its own vote pool is
    /// held to exactly the standard a peer's certificate is.
    pub(super) fn authenticated_quorum(
        &self,
        qc: &QuorumCertificate,
    ) -> Result<authenticated_quorum::VerifiedQuorum, ConsensusError> {
        let set = self.effective_validator_set_for(qc.height).ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(format!(
                "no observed validator set to authenticate the quorum certificate for height {}",
                qc.height
            ))
        })?;
        authenticated_quorum::verify_quorum_certificate(
            qc,
            &set,
            &self.key_registry,
            self.safety_mode,
            self.quorum_count_threshold_for_height(qc.height),
        )
    }

    /// Verifies one loose vote before it may enter the vote pool.
    pub(super) fn authenticated_vote(
        &self,
        vote: &ConsensusVote,
    ) -> Result<authenticated_quorum::VerifiedSigner, ConsensusError> {
        let set = self
            .effective_validator_set_for(vote.height)
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "no observed validator set to authenticate a vote for height {}",
                    vote.height
                ))
            })?;
        authenticated_quorum::verify_consensus_vote(vote, &set, &self.key_registry)
    }

    /// Queues finalized-block evidence, exactly once per finalized block.
    ///
    /// Callers must already have passed the commit rule and every existing
    /// guard and collapse gate. The certificate re-verifies here rather than
    /// reusing an earlier verdict, so evidence is never emitted on the strength
    /// of a check that happened under a different membership.
    pub(super) fn queue_finalized_quorum_event(&mut self, qc: &QuorumCertificate) {
        // Genesis and the synthetic parent certificates the engine mints for
        // restart continuity carry no signatures by construction. They are
        // internal scaffolding for parent selection, never quorum evidence, so
        // they are never exported. `authenticated_quorum` would refuse them
        // anyway; refusing here keeps the intent explicit.
        if qc.height == 0 {
            return;
        }

        let dedup_key = (qc.height, qc.block_hash);
        if self.emitted_finalized_quorums.contains(&dedup_key) {
            return;
        }
        match self.authenticated_quorum(qc) {
            Ok(verified) => {
                self.emitted_finalized_quorums.insert(dedup_key);
                self.finalized_quorum_events
                    .push_back(AftFinalizedQuorumEvent::from_verified(verified));
            }
            Err(error) => {
                // Finality already happened internally; what is missing is the
                // key material to prove it to a third party. Emitting a
                // half-populated event would misreport that as a proven quorum.
                warn!(
                    target: "consensus",
                    height = qc.height,
                    view = qc.view,
                    error = %error,
                    "Committed block finalized without independently verifiable quorum evidence; emitting no finality event"
                );
            }
        }
    }

    /// Drains finalized-block evidence accumulated since the last call.
    pub(super) fn take_finalized_quorum_events(&mut self) -> Vec<AftFinalizedQuorumEvent> {
        self.finalized_quorum_events.drain(..).collect()
    }

    pub(super) fn remember_qc(&mut self, qc: &QuorumCertificate) {
        self.qc_pool
            .entry(qc.height)
            .or_default()
            .insert(qc.block_hash, qc.clone());
    }

    pub(super) fn local_recovered_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredCanonicalHeaderEntry> {
        let header = self.recovered_headers.get(&qc.height)?;
        (header.canonical_block_commitment_hash == qc.block_hash && header.view == qc.view)
            .then(|| header.clone())
    }

    pub(super) fn local_recovered_certified_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredCertifiedHeaderEntry> {
        let entry = self.recovered_certified_headers.get(&qc.height)?;
        let certified_qc = entry.certified_quorum_certificate();
        (certified_qc.block_hash == qc.block_hash && certified_qc.view == qc.view)
            .then(|| entry.clone())
    }

    pub(super) fn local_recovered_restart_header_for_qc(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<RecoveredRestartBlockHeaderEntry> {
        let entry = self.recovered_restart_headers.get(&qc.height)?;
        let certified_qc = entry.certified_quorum_certificate();
        (certified_qc.block_hash == qc.block_hash && certified_qc.view == qc.view)
            .then(|| entry.clone())
    }

    pub(super) fn local_recovered_qc_for_height(&self, height: u64) -> Option<QuorumCertificate> {
        self.recovered_headers
            .get(&height)
            .map(RecoveredCanonicalHeaderEntry::synthetic_quorum_certificate)
    }

    pub(super) fn qc_has_local_restart_context(&self, qc: &QuorumCertificate) -> bool {
        self.local_header_for_qc(qc).is_some()
            || self.local_recovered_header_for_qc(qc).is_some()
            || self.local_recovered_certified_header_for_qc(qc).is_some()
            || self.local_recovered_restart_header_for_qc(qc).is_some()
    }

    pub(super) fn queue_qc_broadcast(&mut self, qc: &QuorumCertificate) {
        let key = (qc.height, qc.block_hash);
        if self.announced_qcs.insert(key) {
            self.pending_qc_broadcasts.push_back(qc.clone());
        }
    }
}
