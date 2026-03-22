use super::*;

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
