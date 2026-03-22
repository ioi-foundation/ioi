use super::*;

impl GuardianMajorityEngine {
    pub(super) fn assign_mirror(&self, account: &AccountId) -> u8 {
        let mut mix = self.mirror_seed[0];
        mix ^= account.0[0];
        mix % 2
    }

    /// Checks for quorum on View Change.
    pub(super) fn check_quorum(
        &mut self,
        height: u64,
        view: u64,
        total_weight: u128,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Option<TimeoutCertificate> {
        let votes_map = self.view_votes.get(&height)?.get(&view)?;

        let mut accumulated_weight = 0u128;
        let active_set = effective_set_for_height(sets, height);

        let weights: HashMap<AccountId, u128> = active_set
            .validators
            .iter()
            .map(|v| (v.account_id, v.weight))
            .collect();

        let mut valid_votes = Vec::new();

        for (voter, vote) in votes_map {
            if let Some(w) = weights.get(voter) {
                accumulated_weight += w;
                valid_votes.push(vote.clone());
            }
        }

        // Aft deterministic Quorum: Simple Majority (> 50%)
        let threshold = self.quorum_weight_threshold(total_weight);

        if accumulated_weight > threshold {
            Some(TimeoutCertificate {
                height,
                view,
                votes: valid_votes,
            })
        } else {
            None
        }
    }

    /// Internal helper to detect divergence.
    pub(super) fn check_divergence(&mut self, header: &BlockHeader) -> Option<ProofOfDivergence> {
        let entry = self
            .seen_headers
            .entry((header.height, header.view))
            .or_default();

        let header_hash = match header.hash() {
            Ok(h) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            }
            Err(_) => return None,
        };

        if entry.is_empty() {
            entry.insert(header_hash, header.clone());
            return None;
        }

        if entry.contains_key(&header_hash) {
            return None;
        }

        // DIVERGENCE DETECTED
        let (existing_hash, existing_header) = entry.iter().next().unwrap();

        warn!(target: "consensus",
            "Aft deterministic DIVERGENCE DETECTED @ H{} V{}: {:?} vs {:?}",
            header.height, header.view, hex::encode(existing_hash), hex::encode(header_hash)
        );

        Some(ProofOfDivergence {
            offender: header.producer_account_id,
            evidence_a: existing_header.clone(),
            evidence_b: header.clone(),
            guardian_certificates: header
                .guardian_certificate
                .iter()
                .cloned()
                .chain(existing_header.guardian_certificate.iter().cloned())
                .collect(),
            log_checkpoints: header
                .guardian_certificate
                .iter()
                .filter_map(|cert| cert.log_checkpoint.clone())
                .chain(
                    existing_header
                        .guardian_certificate
                        .iter()
                        .filter_map(|cert| cert.log_checkpoint.clone()),
                )
                .collect(),
        })
    }

    /// Verifies a Quorum Certificate.
    pub(super) fn verify_qc(
        &self,
        qc: &QuorumCertificate,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            return Ok(());
        }

        if qc.signatures.is_empty() {
            return match self.safety_mode {
                AftSafetyMode::ClassicBft => Err(ConsensusError::BlockVerificationFailed(
                    "Classic BFT requires a validator quorum certificate".into(),
                )),
                AftSafetyMode::GuardianMajority
                | AftSafetyMode::Asymptote
                | AftSafetyMode::ExperimentalNestedGuardian => Ok(()),
            };
        }

        let active_set = effective_set_for_height(sets, qc.height);
        let total_weight = active_set.total_weight;
        let threshold = self.quorum_weight_threshold(total_weight);

        let mut voting_power = 0u128;
        let validators: HashMap<AccountId, &ioi_types::app::ValidatorV1> = active_set
            .validators
            .iter()
            .map(|v| (v.account_id, v))
            .collect();

        for (voter, _signature) in &qc.signatures {
            if let Some(validator) = validators.get(voter) {
                voting_power += validator.weight;
            }
        }

        if voting_power <= threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "QC has insufficient voting power: {} <= {}",
                voting_power, threshold
            )));
        }

        Ok(())
    }

    /// Processes an incoming Echo message.
    pub async fn handle_echo(
        &mut self,
        echo: EchoMessage,
    ) -> Result<ConsensusDecision<ChainTransaction>, ConsensusError> {
        let threshold = self.quorum_count_threshold_for_height(echo.height);
        let pool = self.echo_pool.entry((echo.height, echo.view)).or_default();
        if pool.iter().any(|e| e.sender_id == echo.sender_id) {
            return Ok(ConsensusDecision::WaitForBlock);
        }
        pool.push(echo.clone());
        let count = pool
            .iter()
            .filter(|e| e.block_hash == echo.block_hash)
            .count();

        if count >= threshold {
            if !self.voted_slots.contains(&(echo.height, echo.view)) {
                self.voted_slots.insert((echo.height, echo.view));
                return Ok(ConsensusDecision::Vote {
                    block_hash: echo.block_hash,
                    height: echo.height,
                    view: echo.view,
                });
            }
        }
        Ok(ConsensusDecision::WaitForBlock)
    }
}
