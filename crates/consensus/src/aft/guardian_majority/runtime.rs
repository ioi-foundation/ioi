use super::*;

impl ConsensusControl for GuardianMajorityEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }

    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl PenaltyMechanism for GuardianMajorityEngine {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        apply_quarantine_penalty(state, report).await
    }
}

impl PenaltyEngine for GuardianMajorityEngine {
    fn apply(
        &self,
        sys: &mut dyn SystemState,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        let sets = sys
            .validators()
            .current_sets()
            .map_err(TransactionError::State)?;
        let authorities: Vec<AccountId> = sets
            .current
            .validators
            .iter()
            .map(|v| v.account_id)
            .collect();
        let quarantined = sys
            .quarantine()
            .get_all()
            .map_err(TransactionError::State)?;
        let min_live = (authorities.len() / 2) + 1;

        if !authorities.contains(&report.offender) {
            return Err(TransactionError::Invalid(
                "Offender is not an authority".into(),
            ));
        }
        if quarantined.contains(&report.offender) {
            return Ok(());
        }
        let live_after = authorities
            .len()
            .saturating_sub(quarantined.len())
            .saturating_sub(1);
        if live_after < min_live {
            return Err(TransactionError::Invalid(
                "Quarantine jeopardizes liveness".into(),
            ));
        }
        sys.quarantine_mut()
            .insert(report.offender)
            .map_err(TransactionError::State)
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T>
    for GuardianMajorityEngine
{
    async fn decide(
        &mut self,
        our_account_id: &AccountId,
        height: u64,
        _view_arg: u64,
        parent_view: &dyn AnchoredStateView,
        known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // 1. Poll the Commit Guard
        // Ready commits only become internal finality once their committed slot is
        // also backed by the canonical collapse surface in Asymptote mode.
        loop {
            let Some(ready_commit) = self.safety.next_ready_commit() else {
                break;
            };
            let collapse_backed = if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                self.quorum_certificate_is_collapse_backed(&ready_commit, parent_view)
                    .await
                    .unwrap_or(false)
            } else {
                true
            };
            if !collapse_backed {
                debug!(
                    target: "consensus",
                    height = ready_commit.height,
                    view = ready_commit.view,
                    "Deferring ready commit until the corresponding canonical collapse object is available"
                );
                break;
            }
            if let Some(finalized_qc) = self.safety.accept_next_ready_commit() {
                info!(
                    target: "consensus",
                    "Safety Gadget: Finalized height {}",
                    finalized_qc.height
                );
            } else {
                break;
            }
        }

        info!(target: "consensus", "GuardianMajorityEngine::decide called for height {}", height);

        if Self::benchmark_trace_enabled() && height <= 3 {
            let root = parent_view.state_root();
            let root_prefix_len = root.len().min(4);
            eprintln!(
                "[BENCH-AFT-DECIDE] height={} parent_height={} parent_root_len={} parent_root={}",
                height,
                parent_view.height(),
                root.len(),
                hex::encode(&root[..root_prefix_len]),
            );
        }

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=stall reason=missing_validator_set",
                        height
                    );
                }
                return ConsensusDecision::Stall;
            }
            Err(error) => {
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=stall reason=validator_set_read_error error={}",
                        height,
                        error
                    );
                }
                return ConsensusDecision::Stall;
            }
        };
        let sets = match read_validator_sets(&vs_bytes) {
            Ok(s) => s,
            Err(error) => {
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=stall reason=validator_set_decode_error error={}",
                        height,
                        error
                    );
                }
                return ConsensusDecision::Stall;
            }
        };

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, height);
        let active_validators: Vec<AccountId> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();
        self.cached_validator_count = active_validators.len();

        if active_validators.is_empty() {
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=stall reason=no_active_validators",
                    height
                );
            }
            return ConsensusDecision::Stall;
        }
        self.remember_validator_count(height, active_validators.len());

        let mut current_view = { self.pacemaker.lock().await.current_view };
        let bootstrap_first_commit_pending =
            height == 1 && self.highest_qc.height == 0 && !self.committed_headers.contains_key(&1);
        let pin_bootstrap_view_zero = bootstrap_first_commit_pending
            || (height <= 3 && Instant::now() < self.bootstrap_grace_until);

        if pin_bootstrap_view_zero {
            if let Ok(mut pacemaker) = self.pacemaker.try_lock() {
                pacemaker.current_view = 0;
                pacemaker.view_start_time = Instant::now();
            }
            current_view = 0;
            if bootstrap_first_commit_pending {
                self.timeout_votes_sent
                    .retain(|(vote_height, _)| *vote_height != height);
                self.tc_formed.retain(|(tc_height, _)| *tc_height != height);
            }
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=pin_view0 reason={}",
                    height,
                    if bootstrap_first_commit_pending {
                        "bootstrap_first_commit_pending"
                    } else {
                        "bootstrap_grace"
                    }
                );
            }
            debug!(
                target: "consensus",
                height,
                bootstrap_first_commit_pending,
                "Pinning the bootstrap view to 0."
            );
        }

        if !bootstrap_first_commit_pending {
            let tc_views = self
                .view_votes
                .get(&height)
                .map(|view_map| view_map.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut newest_tc_view = current_view;
            for view in tc_views {
                if self.tc_formed.contains(&(height, view)) {
                    newest_tc_view = newest_tc_view.max(view);
                    continue;
                }
                if self
                    .check_quorum(height, view, vs.total_weight, &sets)
                    .is_some()
                {
                    info!(
                        target: "consensus",
                        height,
                        view,
                        "Majority quorum reached for view change. Advancing pacemaker."
                    );
                    self.tc_formed.insert((height, view));
                    newest_tc_view = newest_tc_view.max(view);
                }
            }
            if newest_tc_view > current_view {
                self.pacemaker.lock().await.advance_view(newest_tc_view);
                current_view = newest_tc_view;
            }

            let timed_out = { self.pacemaker.lock().await.check_timeout() };
            if timed_out {
                let next_view = current_view + 1;
                if self.timeout_votes_sent.insert((height, next_view)) {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=timeout current_view={} next_view={} reason=pacemaker_timed_out",
                            height,
                            current_view,
                            next_view
                        );
                    }
                    info!(
                        target: "consensus",
                        height,
                        current_view,
                        next_view,
                        "Pacemaker timed out. Emitting a view change vote and waiting for a timeout certificate."
                    );
                    return ConsensusDecision::Timeout {
                        view: next_view,
                        height,
                    };
                }
                debug!(
                    target: "consensus",
                    height,
                    current_view,
                    next_view,
                    "Timeout vote already emitted for the next view; waiting for a timeout certificate."
                );
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} next_view={} reason=timeout_vote_already_emitted",
                        height,
                        current_view,
                        next_view
                    );
                }
                return ConsensusDecision::WaitForBlock;
            }

            if current_view > 0 && !self.tc_formed.contains(&(height, current_view)) {
                if Self::benchmark_trace_enabled() {
                    eprintln!(
                        "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} reason=awaiting_timeout_certificate",
                        height,
                        current_view
                    );
                }
                debug!(
                    target: "consensus",
                    height,
                    current_view,
                    "Waiting for timeout certificate before entering the next view."
                );
                return ConsensusDecision::WaitForBlock;
            }
        }

        let parent_root = parent_view.state_root();
        self.mirror_seed = ioi_crypto::algorithms::hash::sha256(parent_root).unwrap_or([0u8; 32]);

        let n = active_validators.len() as u64;
        let round_index = height.saturating_sub(1).saturating_add(current_view);
        let leader_index = (round_index % n) as usize;
        let leader_id = active_validators[leader_index];
        if height == 1 {
            eprintln!(
                "[AFT-LEADER] local={} leader={} validator_count={} known_peer_count={}",
                hex::encode(&our_account_id.0[..4]),
                hex::encode(&leader_id.0[..4]),
                active_validators.len(),
                known_peers.len(),
            );
            info!(
                target: "consensus",
                height,
                current_view,
                local = %hex::encode(&our_account_id.0[..4]),
                leader = %hex::encode(&leader_id.0[..4]),
                validator_count = active_validators.len(),
                known_peer_count = known_peers.len(),
                "GuardianMajority leader selection for the first height."
            );
        }
        if known_peers.is_empty() && leader_id != *our_account_id {
            if Self::benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=no_peers_not_leader",
                    height,
                    current_view
                );
            }
            debug!(target: "consensus", "Stalling: No peers and not leader (Me: {:?}, Leader: {:?})", our_account_id, leader_id);
            return ConsensusDecision::Stall;
        }

        if leader_id == *our_account_id {
            let parent_qc = if height > 1 {
                let progress_parent_qc = if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                    self.collapse_backed_parent_qc_for_height(height, parent_view)
                        .await
                        .ok()
                        .flatten()
                } else {
                    self.synthetic_parent_qc_for_height(height)
                };
                if let Some(synthetic_parent_qc) = progress_parent_qc {
                    let highest_qc_at_parent_height = self.highest_qc.height == height - 1;
                    let highest_qc_has_local_header =
                        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                            highest_qc_at_parent_height
                                && self
                                    .quorum_certificate_is_collapse_backed(
                                        &self.highest_qc,
                                        parent_view,
                                    )
                                    .await
                                    .unwrap_or(false)
                        } else {
                            highest_qc_at_parent_height
                                && self.qc_has_local_restart_context(&self.highest_qc)
                        };

                    if self.highest_qc.height < height - 1
                        || (highest_qc_at_parent_height && !highest_qc_has_local_header)
                    {
                        if highest_qc_at_parent_height
                            && self.highest_qc.block_hash != synthetic_parent_qc.block_hash
                            && !highest_qc_has_local_header
                        {
                            info!(
                                target: "consensus",
                                height,
                                current_view,
                                highest_qc_height = self.highest_qc.height,
                                highest_qc_hash = %hex::encode(&self.highest_qc.block_hash[..4]),
                                synthetic_parent_hash = %hex::encode(&synthetic_parent_qc.block_hash[..4]),
                                "Replacing a headerless parent-height QC with the locally committed synthetic parent QC."
                            );
                        }
                        self.highest_qc = synthetic_parent_qc.clone();
                        synthetic_parent_qc
                    } else {
                        self.highest_qc.clone()
                    }
                } else if self.highest_qc.height < height - 1
                    || (matches!(self.safety_mode, AftSafetyMode::Asymptote)
                        && self.highest_qc.height == height - 1
                        && !self
                            .quorum_certificate_is_collapse_backed(&self.highest_qc, parent_view)
                            .await
                            .unwrap_or(false))
                {
                    let next_view = current_view + 1;
                    if self.timeout_votes_sent.insert((height, next_view)) {
                        if Self::benchmark_trace_enabled() {
                            eprintln!(
                                "[BENCH-AFT-DECIDE] height={} decision=timeout current_view={} next_view={} highest_qc_height={} reason=leader_missing_parent_qc",
                                height,
                                current_view,
                                next_view,
                                self.highest_qc.height
                            );
                        }
                        info!(
                            target: "consensus",
                            height,
                            current_view,
                            next_view,
                            highest_qc_height = self.highest_qc.height,
                            "Leader lacks a quorum certificate for the parent height. Emitting a view change vote."
                        );
                        return ConsensusDecision::Timeout {
                            view: next_view,
                            height,
                        };
                    }
                    debug!(
                        target: "consensus",
                        height,
                        current_view,
                        next_view,
                        highest_qc_height = self.highest_qc.height,
                        "Leader is still waiting for a timeout certificate after requesting a view change."
                    );
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=wait_for_block current_view={} next_view={} highest_qc_height={} reason=leader_waiting_after_parent_qc_timeout",
                            height,
                            current_view,
                            next_view,
                            self.highest_qc.height
                        );
                    }
                    return ConsensusDecision::WaitForBlock;
                } else {
                    self.highest_qc.clone()
                }
            } else {
                self.highest_qc.clone()
            };

            // Safety Check: Ensure we don't propose conflicting blocks
            // Use locked_qc from safety gadget to ensure we extend the correct chain
            if let Some(_locked) = &self.safety.locked_qc {
                // If we have a lock, we must extend it.
                // For simplified Aft deterministic, the highest_qc usually matches the lock or is newer.
                // The proposal construction in `create_block` uses `highest_qc` (via `parent_qc` logic).
            }

            let timing_params = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingParams>(&b).unwrap_or_default()
                }
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_timing_params",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };
            let timing_runtime = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
                Ok(Some(b)) => {
                    codec::from_bytes_canonical::<BlockTimingRuntime>(&b).unwrap_or_default()
                }
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_timing_runtime",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };
            let parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                Ok(None) if height == 1 => ChainStatus::default(),
                _ => {
                    if Self::benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-DECIDE] height={} decision=stall current_view={} reason=missing_parent_status",
                            height,
                            current_view
                        );
                    }
                    return ConsensusDecision::Stall;
                }
            };

            let expected_ts_ms = compute_next_timestamp_ms(
                &timing_params,
                &timing_runtime,
                height.saturating_sub(1),
                parent_status.latest_timestamp_ms_or_legacy(),
                0,
            )
            .unwrap_or_else(|| parent_status.latest_timestamp_ms_or_legacy());
            let expected_ts = timestamp_millis_to_legacy_seconds(expected_ts_ms);

            let timeout_certificate = if current_view > 0 {
                self.check_quorum(height, current_view, vs.total_weight, &sets)
            } else {
                None
            };

            let (
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
            ) = if height <= 1 {
                ([0u8; 32], None)
            } else {
                match self
                    .canonical_collapse_extension_certificate_for_height(height, parent_view)
                    .await
                {
                    Ok((hash, certificate)) => (hash, Some(certificate)),
                    Err(error) => {
                        debug!(
                            target: "consensus",
                            height,
                            current_view,
                            error = %error,
                            "Stalling block production until the canonical collapse extension certificate is available"
                        );
                        return ConsensusDecision::Stall;
                    }
                }
            };

            info!(target: "consensus", "I am leader for H={} V={}. Producing block.", height, current_view);

            ConsensusDecision::ProduceBlock {
                transactions: vec![],
                expected_timestamp_secs: expected_ts,
                expected_timestamp_ms: expected_ts_ms,
                view: current_view,
                parent_qc,
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
                timeout_certificate,
            }
        } else {
            ConsensusDecision::WaitForBlock
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        block: Block<T>,
        chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        if let Some(proof) = self.check_divergence(&block.header) {
            error!(target: "consensus", "CRITICAL: DIVERGENCE PROOF CONSTRUCTED: {:?}", proof);
            return Err(ConsensusError::BlockVerificationFailed(
                "Panic:HardwareDivergence".into(),
            ));
        }

        let header = &block.header;

        let parent_state_ref = StateRef {
            height: header.height - 1,
            state_root: header.parent_state_root.as_ref().to_vec(),
            block_hash: header.parent_hash,
        };
        let parent_view = chain_view
            .view_at(&parent_state_ref)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;

        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                error!(target: "consensus", "Validator set missing in parent state for H={}", header.height);
                return Err(ConsensusError::StateAccess(StateError::KeyNotFound));
            }
            Err(e) => {
                error!(target: "consensus", "State access error reading validator set: {}", e);
                return Err(ConsensusError::StateAccess(StateError::Backend(
                    e.to_string(),
                )));
            }
        };

        let sets = read_validator_sets(&vs_bytes).map_err(|e| {
            error!(target: "consensus", "Failed to decode validator set: {}", e);
            ConsensusError::BlockVerificationFailed("VS decode failed".into())
        })?;

        let quarantined: BTreeSet<AccountId> =
            match parent_view.get(QUARANTINED_VALIDATORS_KEY).await {
                Ok(Some(b)) => codec::from_bytes_canonical(&b).unwrap_or_default(),
                _ => BTreeSet::new(),
            };

        let vs = effective_set_for_height(&sets, header.height);
        let active_validators: Vec<AccountId> = vs
            .validators
            .iter()
            .map(|v| v.account_id)
            .filter(|id| !quarantined.contains(id))
            .collect();
        self.remember_validator_count(header.height, active_validators.len());

        let validator_count = active_validators.len() as u64;
        if validator_count == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "No active validators for proposal".into(),
            ));
        }
        let round_index = header.height.saturating_sub(1).saturating_add(header.view);
        let leader_index = (round_index % validator_count) as usize;
        let expected_leader = active_validators[leader_index];
        if header.producer_account_id != expected_leader {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Unexpected proposer for H={} V={}: expected {} got {}",
                header.height,
                header.view,
                hex::encode(expected_leader),
                hex::encode(header.producer_account_id)
            )));
        }
        if header.view == 0 {
            if header.timeout_certificate.is_some() {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "Unexpected timeout certificate on view-0 proposal H={}",
                    header.height
                )));
            }
        } else {
            let timeout_certificate = header.timeout_certificate.as_ref().ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "Missing timeout certificate for non-zero-view proposal H={} V={}",
                    header.height, header.view
                ))
            })?;
            self.verify_timeout_certificate(timeout_certificate, &sets)?;
        }

        let threshold = self.quorum_count_threshold_for_height(header.height);

        let block_hash_bytes = match header.hash() {
            Ok(h) => h,
            Err(_) => return Err(ConsensusError::BlockVerificationFailed("Hash fail".into())),
        };
        let block_hash = to_root_hash(&block_hash_bytes)
            .map_err(|_| ConsensusError::BlockVerificationFailed("Hash len".into()))?;
        // Check votes
        if let Some(votes) = self
            .vote_pool
            .get(&header.height)
            .and_then(|m| m.get(&block_hash))
        {
            if votes.len() >= threshold {
                let qc = QuorumCertificate {
                    height: header.height,
                    view: header.view,
                    block_hash,
                    signatures: votes
                        .iter()
                        .map(|v| (v.voter, v.signature.clone()))
                        .collect(),
                    aggregated_signature: vec![],
                    signers_bitfield: vec![],
                };
                self.accept_quorum_certificate(qc, true).await?;
            }
        }

        if header.height > 1 {
            let parent_qc = &header.parent_qc;
            if parent_qc.height != header.height - 1 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC height mismatch".into(),
                ));
            }
            if parent_qc.block_hash != header.parent_hash {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Parent QC hash mismatch".into(),
                ));
            }
            if let Err(e) = self.verify_qc(parent_qc, &sets) {
                error!(
                    target: "consensus",
                    "QC Verification Failed for block {}: {}",
                    header.height,
                    e
                );
                return Err(e);
            }
            if matches!(self.safety_mode, AftSafetyMode::Asymptote)
                && !self
                    .quorum_certificate_is_collapse_backed(parent_qc, &*parent_view)
                    .await?
            {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "Parent QC is not backed by a canonical collapse object for height {}",
                    parent_qc.height
                )));
            }
            self.remember_qc(parent_qc);
            if parent_qc.height > self.highest_qc.height {
                self.highest_qc = parent_qc.clone();
            }
        }

        {
            let mut pacemaker = self.pacemaker.lock().await;
            if header.view > pacemaker.current_view {
                pacemaker.advance_view(header.view);
            } else {
                pacemaker.view_start_time = Instant::now();
            }
        }

        let preimage = header
            .to_preimage_for_signing()
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        verify_guardian_signature(
            &preimage,
            &header.producer_pubkey,
            &header.signature,
            header.oracle_counter,
            &header.oracle_trace_hash,
        )?;
        self.verify_guardianized_certificate(header, &preimage, &*parent_view)
            .await?;
        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            self.canonical_collapse_from_header_surface_with_parent_view(header, &*parent_view)
                .await?;
            self.verify_published_canonical_collapse_object(header, &*parent_view)
                .await?;
        }

        if let Some(existing_header) = self
            .seen_headers
            .get(&(header.height, header.view))
            .and_then(|headers| headers.get(&block_hash))
            .cloned()
        {
            let same_slot_identity = existing_header.producer_account_id
                == header.producer_account_id
                && existing_header.oracle_counter == header.oracle_counter
                && existing_header.oracle_trace_hash == header.oracle_trace_hash;
            let richer_certification = existing_header.guardian_certificate
                != header.guardian_certificate
                || existing_header.sealed_finality_proof != header.sealed_finality_proof
                || existing_header.canonical_order_certificate
                    != header.canonical_order_certificate;
            if same_slot_identity && richer_certification {
                if let Some(headers) = self.seen_headers.get_mut(&(header.height, header.view)) {
                    headers.insert(block_hash, header.clone());
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Accepted sealed/header enrichment for an already verified block"
                );
                return Ok(());
            }
        }

        if let Some(&last_ctr) = self.last_seen_counters.get(&header.producer_account_id) {
            if header.oracle_counter <= last_ctr {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Guardian counter rollback".into(),
                ));
            }
        }
        self.last_seen_counters
            .insert(header.producer_account_id, header.oracle_counter);

        {
            let mut pacemaker = self.pacemaker.lock().await;
            pacemaker.observe_progress(header.view);
        }

        debug!(target: "consensus", "Aft deterministic: Block {} verified. Initiating ECHO phase.", header.height);
        Ok(())
    }

    async fn handle_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        // Safety Check: Don't process votes if not safe
        if !self.safety.safe_to_vote(vote.view, vote.height - 1) {
            // Logic for unsafe vote handling (optional)
        }

        let threshold = self.quorum_count_threshold_for_height(vote.height);
        let height_map = self.vote_pool.entry(vote.height).or_default();
        let votes = height_map.entry(vote.block_hash).or_default();

        if votes.iter().any(|v| v.voter == vote.voter) {
            return Ok(());
        }
        votes.push(vote.clone());

        if votes.len() >= threshold {
            let qc = QuorumCertificate {
                height: vote.height,
                view: vote.view,
                block_hash: vote.block_hash,
                signatures: votes
                    .iter()
                    .map(|v| (v.voter, v.signature.clone()))
                    .collect(),
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            };
            self.accept_quorum_certificate(qc, true).await?;
        }
        Ok(())
    }

    async fn handle_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
    ) -> Result<(), ConsensusError> {
        self.accept_quorum_certificate(qc, false).await
    }

    async fn handle_view_change(
        &mut self,
        from: PeerId,
        proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        let vote: ViewChangeVote =
            ioi_types::codec::from_bytes_canonical(proof_bytes).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid view vote: {}", e))
            })?;

        info!(target: "consensus", "ViewChange vote H={} V={} from {}", vote.height, vote.view, from);
        let height_map = self.view_votes.entry(vote.height).or_default();
        let view_map = height_map.entry(vote.view).or_default();
        view_map.insert(vote.voter, vote);
        Ok(())
    }

    fn reset(&mut self, height: u64) {
        self.reset_cache_for_height(height);
    }

    fn observe_committed_block(
        &mut self,
        header: &BlockHeader,
        collapse: Option<&CanonicalCollapseObject>,
    ) -> bool {
        self.record_committed_block(header, collapse)
    }

    fn observe_aft_recovered_consensus_header(
        &mut self,
        header: &AftRecoveredConsensusHeaderEntry,
    ) -> bool {
        self.store_aft_recovered_consensus_header(header)
    }

    fn observe_aft_recovered_certified_header(
        &mut self,
        entry: &AftRecoveredCertifiedHeaderEntry,
    ) -> bool {
        self.store_aft_recovered_certified_header(entry)
    }

    fn aft_recovered_consensus_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredConsensusHeaderEntry> {
        self.recovered_consensus_header_for_quorum_certificate(qc)
    }

    fn aft_recovered_certified_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredCertifiedHeaderEntry> {
        self.recovered_certified_header_for_quorum_certificate(qc)
    }

    fn observe_aft_recovered_restart_header(
        &mut self,
        entry: &AftRecoveredRestartHeaderEntry,
    ) -> bool {
        self.store_aft_recovered_restart_header(entry)
    }

    fn aft_recovered_restart_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredRestartHeaderEntry> {
        self.recovered_restart_header_for_quorum_certificate(qc)
    }

    fn retain_recovered_ancestry_ranges(&mut self, keep_ranges: &[(u64, u64)]) {
        self.retain_recovered_ancestry_cache_ranges(keep_ranges);
    }

    fn header_for_quorum_certificate(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        self.header_for_quorum_certificate_hint(qc)
    }

    fn take_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        self.drain_pending_quorum_certificates()
    }
}
