use super::*;

impl GuardianMajorityEngine {
    pub(super) fn canonical_ordering_collapse_from_header(
        header: &BlockHeader,
    ) -> Result<CanonicalOrderingCollapse, ConsensusError> {
        match header.canonical_order_certificate.as_ref() {
            Some(certificate) => {
                let bulletin_close = build_canonical_bulletin_close(
                    &certificate.bulletin_commitment,
                    &certificate.bulletin_availability_certificate,
                )
                .map_err(|error| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "failed to rebuild canonical bulletin close for collapse derivation: {}",
                        error
                    ))
                })?;
                Ok(CanonicalOrderingCollapse {
                    height: header.height,
                    kind: if certificate.omission_proofs.is_empty() {
                        CanonicalCollapseKind::Close
                    } else {
                        CanonicalCollapseKind::Abort
                    },
                    bulletin_commitment_hash: canonical_bulletin_commitment_hash(
                        &certificate.bulletin_commitment,
                    )
                    .map_err(ConsensusError::BlockVerificationFailed)?,
                    bulletin_availability_certificate_hash:
                        canonical_bulletin_availability_certificate_hash(
                            &certificate.bulletin_availability_certificate,
                        )
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                    bulletin_retrievability_profile_hash: [0u8; 32],
                    bulletin_shard_manifest_hash: [0u8; 32],
                    bulletin_custody_receipt_hash: [0u8; 32],
                    bulletin_close_hash: canonical_bulletin_close_hash(&bulletin_close)
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                    canonical_order_certificate_hash: canonical_order_certificate_hash(certificate)
                        .map_err(ConsensusError::BlockVerificationFailed)?,
                })
            }
            None => Ok(CanonicalOrderingCollapse {
                height: header.height,
                kind: CanonicalCollapseKind::Abort,
                bulletin_commitment_hash: [0u8; 32],
                bulletin_availability_certificate_hash: [0u8; 32],
                bulletin_retrievability_profile_hash: [0u8; 32],
                bulletin_shard_manifest_hash: [0u8; 32],
                bulletin_custody_receipt_hash: [0u8; 32],
                bulletin_close_hash: [0u8; 32],
                canonical_order_certificate_hash: [0u8; 32],
            }),
        }
    }

    pub(super) fn canonical_collapse_from_header_surface_with_previous(
        &self,
        header: &BlockHeader,
        previous: Option<&CanonicalCollapseObject>,
    ) -> Result<CanonicalCollapseObject, ConsensusError> {
        verify_block_header_canonical_collapse_evidence(header, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let ordering = Self::canonical_ordering_collapse_from_header(header)?;
        let sealing = header
            .sealed_finality_proof
            .as_ref()
            .map(derive_canonical_sealing_collapse)
            .transpose()
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let mut collapse = CanonicalCollapseObject {
            height: header.height,
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            continuity_accumulator_hash: [0u8; 32],
            continuity_recursive_proof: Default::default(),
            ordering,
            sealing,
            transactions_root_hash: to_root_hash(&header.transactions_root)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            resulting_state_root_hash: to_root_hash(&header.state_root.0)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            archived_recovered_history_checkpoint_hash: [0u8; 32],
            archived_recovered_history_profile_activation_hash: [0u8; 32],
            archived_recovered_history_retention_receipt_hash: [0u8; 32],
        };
        bind_canonical_collapse_continuity(&mut collapse, previous)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        self.verify_runtime_canonical_collapse_continuity(&collapse, previous)?;
        Ok(collapse)
    }

    pub(super) fn quorum_certificate_from_header(
        header: &BlockHeader,
    ) -> Result<QuorumCertificate, ConsensusError> {
        let block_hash = to_root_hash(
            &header
                .hash()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(QuorumCertificate {
            height: header.height,
            view: header.view,
            block_hash,
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        })
    }

    pub(super) fn verify_local_canonical_collapse_chain(
        &self,
        collapse: &CanonicalCollapseObject,
    ) -> Result<(), ConsensusError> {
        let mut chain = Vec::new();
        let mut current = collapse.clone();
        loop {
            chain.push(current.clone());
            if current.height <= 1 {
                break;
            }
            current = self
                .committed_collapses
                .get(&(current.height - 1))
                .cloned()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "missing locally committed canonical collapse object for height {}",
                        current.height - 1
                    ))
                })?;
        }
        chain.reverse();
        let mut previous: Option<&CanonicalCollapseObject> = None;
        for current in &chain {
            self.verify_runtime_canonical_collapse_continuity(current, previous)?;
            previous = Some(current);
        }
        Ok(())
    }

    pub(super) async fn load_published_canonical_collapse_object(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_canonical_collapse_object_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn canonical_collapse_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        if height == 0 {
            return Ok(None);
        }
        if let Some(collapse) = self.committed_collapses.get(&height) {
            self.verify_canonical_collapse_backend(collapse)?;
            return Ok(Some(collapse.clone()));
        }
        let collapse = self
            .load_published_canonical_collapse_object(height, parent_view)
            .await?;
        if let Some(collapse) = collapse.as_ref() {
            self.verify_canonical_collapse_backend(collapse)?;
        }
        Ok(collapse)
    }

    pub(super) async fn previous_canonical_collapse_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<CanonicalCollapseObject>, ConsensusError> {
        if height <= 1 {
            return Ok(None);
        }
        if let Some(previous) = self.committed_collapses.get(&(height - 1)) {
            self.verify_canonical_collapse_backend(previous)?;
            return Ok(Some(previous.clone()));
        }
        match self
            .load_published_canonical_collapse_object(height - 1, parent_view)
            .await?
        {
            Some(previous) => {
                self.verify_canonical_collapse_backend(&previous)?;
                Ok(Some(previous))
            }
            None => Err(ConsensusError::BlockVerificationFailed(format!(
                "missing previous canonical collapse object for height {}",
                height
            ))),
        }
    }

    pub(super) async fn verify_canonical_collapse_chain_with_parent_view(
        &self,
        collapse: &CanonicalCollapseObject,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let mut chain = Vec::new();
        let mut current = collapse.clone();
        loop {
            chain.push(current.clone());
            if current.height <= 1 {
                break;
            }
            current = self
                .canonical_collapse_for_height(current.height - 1, parent_view)
                .await?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "missing canonical collapse object for height {}",
                        current.height - 1
                    ))
                })?;
        }
        chain.reverse();
        let mut previous: Option<&CanonicalCollapseObject> = None;
        for current in &chain {
            self.verify_runtime_canonical_collapse_continuity(current, previous)?;
            previous = Some(current);
        }
        Ok(())
    }

    pub(super) async fn canonical_collapse_extension_certificate_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<([u8; 32], CanonicalCollapseExtensionCertificate), ConsensusError> {
        if height <= 1 {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "height {} does not admit a canonical collapse extension certificate",
                height
            )));
        }
        let Some(head) = self
            .previous_canonical_collapse_for_height(height, parent_view)
            .await?
        else {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "missing previous canonical collapse object for height {}",
                height
            )));
        };
        self.verify_canonical_collapse_chain_with_parent_view(&head, parent_view)
            .await?;
        let certificate = canonical_collapse_extension_certificate(height, &head)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        let hash = canonical_collapse_commitment_hash_from_object(&head)
            .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok((hash, certificate))
    }

    pub(super) async fn canonical_collapse_from_header_surface_with_parent_view(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<CanonicalCollapseObject, ConsensusError> {
        let previous = self
            .previous_canonical_collapse_for_height(header.height, parent_view)
            .await?;
        if let Some(previous) = previous.as_ref() {
            self.verify_canonical_collapse_chain_with_parent_view(previous, parent_view)
                .await?;
        }
        self.canonical_collapse_from_header_surface_with_previous(header, previous.as_ref())
    }

    pub(super) async fn header_is_collapse_backed(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<bool, ConsensusError> {
        let derived = self
            .canonical_collapse_from_header_surface_with_parent_view(header, parent_view)
            .await?;
        match self
            .load_published_canonical_collapse_object(header.height, parent_view)
            .await?
        {
            Some(published) => {
                self.verify_canonical_collapse_chain_with_parent_view(&published, parent_view)
                    .await?;
                Ok(published == derived)
            }
            None => Ok(true),
        }
    }

    pub(super) fn header_links_to_local_previous_collapse(
        &self,
        header: &BlockHeader,
    ) -> Result<bool, ConsensusError> {
        let previous = if header.height <= 1 {
            None
        } else {
            self.committed_collapses.get(&(header.height - 1))
        };
        if verify_block_header_canonical_collapse_evidence(header, previous).is_err() {
            return Ok(false);
        }
        if let Some(local) = previous {
            if self.verify_local_canonical_collapse_chain(local).is_err() {
                return Ok(false);
            }
            let Some(certificate) = header.canonical_collapse_extension_certificate.as_ref() else {
                return Ok(false);
            };
            if certificate.predecessor_commitment != canonical_collapse_commitment(local) {
                return Ok(false);
            }
            let expected_proof_hash = ioi_types::app::canonical_collapse_recursive_proof_hash(
                &local.continuity_recursive_proof,
            )
            .map_err(ConsensusError::BlockVerificationFailed)?;
            if certificate.predecessor_recursive_proof_hash != expected_proof_hash {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) async fn quorum_certificate_is_collapse_backed(
        &self,
        qc: &QuorumCertificate,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<bool, ConsensusError> {
        if qc.height == 0 {
            return Ok(true);
        }

        if let Some(header) = self.committed_headers.get(&qc.height) {
            let expected = Self::quorum_certificate_from_header(header)?;
            if expected.block_hash == qc.block_hash
                && expected.height == qc.height
                && expected.view == qc.view
            {
                return self.header_is_collapse_backed(header, parent_view).await;
            }
        }

        let header = self
            .seen_headers
            .iter()
            .filter(|((height, _), _)| *height == qc.height)
            .find_map(|(_, headers)| headers.get(&qc.block_hash).cloned());
        let Some(header) = header else {
            return Ok(false);
        };
        let expected = Self::quorum_certificate_from_header(&header)?;
        if expected.block_hash != qc.block_hash
            || expected.height != qc.height
            || expected.view != qc.view
        {
            return Ok(false);
        }
        self.header_is_collapse_backed(&header, parent_view).await
    }

    pub(super) async fn collapse_backed_parent_qc_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<QuorumCertificate>, ConsensusError> {
        let parent_height = match height.checked_sub(1) {
            Some(parent_height) => parent_height,
            None => return Ok(None),
        };
        if parent_height == 0 {
            return Ok(Some(QuorumCertificate::default()));
        }

        if let Some(header) = self.committed_headers.get(&parent_height) {
            if self.header_is_collapse_backed(header, parent_view).await? {
                return Ok(Some(Self::quorum_certificate_from_header(header)?));
            }
        }

        let mut candidates = self
            .seen_headers
            .iter()
            .filter(|((seen_height, _), _)| *seen_height == parent_height)
            .flat_map(|(_, headers)| headers.values().cloned())
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            a.view
                .cmp(&b.view)
                .then_with(|| a.producer_account_id.0.cmp(&b.producer_account_id.0))
        });
        candidates.reverse();

        for candidate in candidates {
            if self
                .header_is_collapse_backed(&candidate, parent_view)
                .await?
            {
                return Ok(Some(Self::quorum_certificate_from_header(&candidate)?));
            }
        }

        Ok(None)
    }

    pub(super) fn local_header_for_qc(&self, qc: &QuorumCertificate) -> Option<BlockHeader> {
        if qc.height == 0 {
            return None;
        }

        if let Some(header) = self.committed_headers.get(&qc.height) {
            let block_hash = to_root_hash(&header.hash().ok()?).ok()?;
            if block_hash == qc.block_hash {
                return Some(header.clone());
            }
        }

        self.seen_headers
            .iter()
            .filter(|((height, _), _)| *height == qc.height)
            .find_map(|(_, headers)| headers.get(&qc.block_hash).cloned())
    }

    pub(super) fn maybe_promote_committed_height_qc(&mut self, height: u64) {
        if height == 0 || self.highest_qc.height >= height {
            return;
        }

        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(header) = self.committed_headers.get(&height) else {
                return;
            };
            if !self.committed_collapses.contains_key(&height) {
                return;
            }
            let Ok(qc) = Self::quorum_certificate_from_header(header) else {
                return;
            };
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
            return;
        }

        if let Some(qc) = self.local_recovered_qc_for_height(height) {
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
            return;
        }

        if let Some(qc) = self.qc_pool.get(&height).and_then(|qcs| {
            (qcs.len() == 1)
                .then(|| qcs.values().next().cloned())
                .flatten()
        }) {
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
            return;
        }

        let threshold = self.quorum_count_threshold_for_height(height);
        let quorum_candidates = self
            .vote_pool
            .get(&height)
            .map(|votes_by_hash| {
                votes_by_hash
                    .iter()
                    .filter_map(|(block_hash, votes)| {
                        let unique_signers: HashSet<AccountId> =
                            votes.iter().map(|vote| vote.voter).collect();
                        if unique_signers.len() < threshold {
                            return None;
                        }

                        let view = votes.first().map(|vote| vote.view)?;
                        Some(QuorumCertificate {
                            height,
                            view,
                            block_hash: *block_hash,
                            signatures: votes
                                .iter()
                                .map(|vote| (vote.voter, vote.signature.clone()))
                                .collect(),
                            aggregated_signature: vec![],
                            signers_bitfield: vec![],
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if quorum_candidates.len() == 1 {
            let qc = quorum_candidates
                .into_iter()
                .next()
                .expect("exactly one QC candidate");
            self.remember_qc(&qc);
            self.highest_qc = qc.clone();
            self.queue_qc_broadcast(&qc);
        }
    }

    pub(super) fn synthetic_parent_qc_for_height(&self, height: u64) -> Option<QuorumCertificate> {
        let parent_height = height.checked_sub(1)?;
        if parent_height == 0 {
            return Some(QuorumCertificate::default());
        }

        if let Some(header) = self.committed_headers.get(&parent_height) {
            let block_hash = to_root_hash(&header.hash().ok()?).ok()?;
            return Some(QuorumCertificate {
                height: parent_height,
                view: header.view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        if let Some(qc) = self.local_recovered_qc_for_height(parent_height) {
            return Some(qc);
        }

        if let Some(qc) = self.qc_pool.get(&parent_height).and_then(|qcs| {
            (qcs.len() == 1)
                .then(|| qcs.values().next().cloned())
                .flatten()
        }) {
            return Some(qc);
        }

        if let Some((block_hash, votes)) =
            self.vote_pool
                .get(&parent_height)
                .and_then(|votes_by_hash| {
                    (votes_by_hash.len() == 1)
                        .then(|| {
                            votes_by_hash
                                .iter()
                                .next()
                                .map(|(hash, votes)| (*hash, votes))
                        })
                        .flatten()
                })
        {
            let view = votes.first().map(|vote| vote.view)?;
            return Some(QuorumCertificate {
                height: parent_height,
                view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        let mut candidates = self
            .seen_headers
            .iter()
            .filter(|((seen_height, _), _)| *seen_height == parent_height)
            .flat_map(|((_, view), headers)| headers.keys().copied().map(|hash| (*view, hash)))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates.dedup();
        if candidates.len() == 1 {
            let (view, block_hash) = candidates[0];
            return Some(QuorumCertificate {
                height: parent_height,
                view,
                block_hash,
                signatures: vec![],
                aggregated_signature: vec![],
                signers_bitfield: vec![],
            });
        }

        None
    }

    pub(super) async fn refresh_liveness_after_qc(&mut self, qc_height: u64) {
        let next_height = qc_height.saturating_add(1);
        self.timeout_votes_sent
            .retain(|(height, _)| *height != next_height);
        let mut pacemaker = self.pacemaker.lock().await;
        pacemaker.view_start_time = std::time::Instant::now();
    }

    pub(super) async fn accept_quorum_certificate(
        &mut self,
        qc: QuorumCertificate,
        queue_for_broadcast: bool,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            return Ok(());
        }

        let unique_signers: HashSet<AccountId> =
            qc.signatures.iter().map(|(voter, _)| *voter).collect();
        let threshold = self.quorum_count_threshold_for_height(qc.height);
        if unique_signers.len() < threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "QC below quorum threshold for height {}",
                qc.height
            )));
        }

        let header = self.local_header_for_qc(&qc);
        let recovered_header = self.local_recovered_header_for_qc(&qc);
        if header.is_none()
            && recovered_header.is_none()
            && qc.height > self.highest_qc.height.saturating_add(1)
        {
            debug!(
                target: "consensus",
                height = qc.height,
                view = qc.view,
                block = %hex::encode(&qc.block_hash[..4]),
                highest_qc_height = self.highest_qc.height,
                "Ignoring QC that jumps beyond the next expected height without a known header"
            );
            return Ok(());
        }

        self.remember_qc(&qc);
        if qc.height <= self.highest_qc.height {
            return Ok(());
        }

        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(header) = header.as_ref() else {
                debug!(
                    target: "consensus",
                    height = qc.height,
                    view = qc.view,
                    block = %hex::encode(&qc.block_hash[..4]),
                    "Ignoring QC without a locally known collapse-derivable header in Asymptote"
                );
                return Ok(());
            };
            if !self.header_links_to_local_previous_collapse(header)? {
                debug!(
                    target: "consensus",
                    height = qc.height,
                    view = qc.view,
                    block = %hex::encode(&qc.block_hash[..4]),
                    "Ignoring QC whose locally known header is not linked to the previous canonical collapse object"
                );
                return Ok(());
            }
        }

        info!(
            target: "consensus",
            height = qc.height,
            view = qc.view,
            block = %hex::encode(&qc.block_hash[..4]),
            "Accepted quorum certificate and advanced highest_qc"
        );
        self.highest_qc = qc.clone();
        self.refresh_liveness_after_qc(qc.height).await;
        if queue_for_broadcast {
            self.queue_qc_broadcast(&qc);
        }

        if let Some(header) = header {
            if self.safety.update(&qc, &header.parent_qc) {
                info!(
                    target: "consensus",
                    "Safety Gadget: Queued commit for height {}",
                    header.parent_qc.height
                );
            }
        } else {
            debug!(
                target: "consensus",
                height = qc.height,
                view = qc.view,
                block = %hex::encode(&qc.block_hash[..4]),
                "Advanced highest_qc without a locally stored header; skipping safety update"
            );
        }

        Ok(())
    }

    pub(super) fn verify_timeout_certificate(
        &self,
        timeout_certificate: &TimeoutCertificate,
        sets: &ioi_types::app::ValidatorSetsV1,
    ) -> Result<(), ConsensusError> {
        let active_set = effective_set_for_height(sets, timeout_certificate.height);
        let weights: HashMap<AccountId, u128> = active_set
            .validators
            .iter()
            .map(|validator| (validator.account_id, validator.weight))
            .collect();

        let mut accumulated_weight = 0u128;
        let mut seen = HashSet::new();
        for vote in &timeout_certificate.votes {
            if vote.height != timeout_certificate.height || vote.view != timeout_certificate.view {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Timeout certificate vote does not match certificate height/view".into(),
                ));
            }
            if !seen.insert(vote.voter) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "Timeout certificate contains duplicate voters".into(),
                ));
            }
            let weight = weights.get(&vote.voter).ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "Timeout certificate contains non-validator voter".into(),
                )
            })?;
            accumulated_weight = accumulated_weight.saturating_add(*weight);
        }

        let threshold = self.quorum_weight_threshold(active_set.total_weight);
        if accumulated_weight <= threshold {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "Timeout certificate weight {} does not exceed threshold {}",
                accumulated_weight, threshold
            )));
        }

        Ok(())
    }

    pub(super) fn verify_guardianized_certificate_against_manifest(
        &self,
        header: &BlockHeader,
        preimage: &[u8],
        manifest: &GuardianCommitteeManifest,
    ) -> Result<(), ConsensusError> {
        let cert = header.guardian_certificate.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "guardianized mode requires guardian_certificate".into(),
            )
        })?;
        if manifest.validator_account_id != header.producer_account_id {
            return Err(ConsensusError::BlockVerificationFailed(
                "guardian committee manifest validator mismatch".into(),
            ));
        }
        if cert.counter != header.oracle_counter || cert.trace_hash != header.oracle_trace_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "guardian_certificate counter/trace mismatch".into(),
            ));
        }

        let decision = Self::guardian_decision_from_header(header, preimage, manifest, cert)?;
        verify_quorum_certificate(manifest, &decision, cert)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) fn guardian_decision_from_header(
        header: &BlockHeader,
        preimage: &[u8],
        manifest: &GuardianCommitteeManifest,
        cert: &GuardianQuorumCertificate,
    ) -> Result<GuardianDecision, ConsensusError> {
        let payload_hash = ioi_crypto::algorithms::hash::sha256(preimage)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(GuardianDecision {
            domain: GuardianDecisionDomain::ConsensusSlot as u8,
            subject: header.producer_account_id.0.to_vec(),
            payload_hash,
            counter: cert.counter,
            trace_hash: cert.trace_hash,
            measurement_root: cert.measurement_root,
            policy_hash: manifest.policy_hash,
        })
    }

    pub(super) fn guardian_checkpoint_entry_bytes(
        decision: &GuardianDecision,
        certificate: &GuardianQuorumCertificate,
    ) -> Result<Vec<u8>, ConsensusError> {
        let mut checkpoint_certificate = certificate.clone();
        checkpoint_certificate.log_checkpoint = None;
        checkpoint_certificate.experimental_witness_certificate = None;
        codec::to_bytes_canonical(&(decision, checkpoint_certificate))
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) fn experimental_witness_statement(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
    ) -> GuardianWitnessStatement {
        guardian_witness_statement_for_header(header, certificate)
    }

    pub(super) fn asymptote_observer_statement(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        observer_certificate: &AsymptoteObserverCertificate,
    ) -> Result<AsymptoteObserverStatement, ConsensusError> {
        let block_hash = ioi_crypto::algorithms::hash::sha256(
            &header
                .to_preimage_for_signing()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(AsymptoteObserverStatement {
            epoch: observer_certificate.assignment.epoch,
            assignment: observer_certificate.assignment.clone(),
            block_hash,
            guardian_manifest_hash: certificate.manifest_hash,
            guardian_decision_hash: certificate.decision_hash,
            guardian_counter: certificate.counter,
            guardian_trace_hash: certificate.trace_hash,
            guardian_measurement_root: certificate.measurement_root,
            guardian_checkpoint_root: certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
            verdict: observer_certificate.verdict,
            veto_kind: observer_certificate.veto_kind,
            evidence_hash: observer_certificate.evidence_hash,
        })
    }

    pub(super) fn asymptote_observer_observation_request(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        assignment: &AsymptoteObserverAssignment,
    ) -> Result<AsymptoteObserverObservationRequest, ConsensusError> {
        let block_hash = ioi_crypto::algorithms::hash::sha256(
            &header
                .to_preimage_for_signing()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(AsymptoteObserverObservationRequest {
            epoch: assignment.epoch,
            assignment: assignment.clone(),
            block_hash,
            guardian_manifest_hash: certificate.manifest_hash,
            guardian_decision_hash: certificate.decision_hash,
            guardian_counter: certificate.counter,
            guardian_trace_hash: certificate.trace_hash,
            guardian_measurement_root: certificate.measurement_root,
            guardian_checkpoint_root: certificate
                .log_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.root_hash)
                .unwrap_or([0u8; 32]),
        })
    }

    pub(super) fn asymptote_observer_decision(
        statement: &AsymptoteObserverStatement,
        manifest: &GuardianCommitteeManifest,
        certificate: &GuardianQuorumCertificate,
    ) -> Result<GuardianDecision, ConsensusError> {
        let payload_hash = ioi_crypto::algorithms::hash::sha256(
            &codec::to_bytes_canonical(statement)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        Ok(GuardianDecision {
            domain: GuardianDecisionDomain::AsymptoteObserve as u8,
            subject: statement.assignment.observer_account_id.0.to_vec(),
            payload_hash,
            counter: certificate.counter,
            trace_hash: certificate.trace_hash,
            measurement_root: certificate.measurement_root,
            policy_hash: manifest.policy_hash,
        })
    }

    pub(super) async fn verify_asymptote_observer_certificate(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        observer_certificate: &AsymptoteObserverCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let statement =
            self.asymptote_observer_statement(header, certificate, observer_certificate)?;
        self.verify_asymptote_observer_statement_certificate(
            &statement,
            &observer_certificate.guardian_certificate,
            parent_view,
            current_epoch,
        )
        .await
    }

    pub(super) async fn verify_asymptote_observer_statement_certificate(
        &self,
        statement: &AsymptoteObserverStatement,
        observer_guardian: &GuardianQuorumCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        if observer_guardian.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer certificate epoch does not match current epoch".into(),
            ));
        }

        let manifest_bytes = parent_view
            .get(&guardian_registry_committee_key(
                &observer_guardian.manifest_hash,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "observer guardian manifest is not registered on-chain".into(),
                )
            })?;
        let observer_manifest: GuardianCommitteeManifest =
            codec::from_bytes_canonical(&manifest_bytes)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if observer_manifest.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer guardian manifest epoch does not match current epoch".into(),
            ));
        }
        if observer_manifest.validator_account_id != statement.assignment.observer_account_id {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer certificate manifest does not belong to the assigned observer".into(),
            ));
        }
        let decision =
            Self::asymptote_observer_decision(statement, &observer_manifest, observer_guardian)?;
        let checkpoint = observer_guardian.log_checkpoint.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(
                "observer guardian certificate is missing a checkpoint".into(),
            )
        })?;
        let descriptor =
            Self::load_log_descriptor(parent_view, &observer_manifest.transparency_log_id).await?;
        let checkpoint_entry = Self::guardian_checkpoint_entry_bytes(&decision, observer_guardian)?;
        let leaf_hash = canonical_log_leaf_hash(&checkpoint_entry)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let anchored_checkpoint =
            Self::load_anchored_checkpoint(parent_view, &observer_manifest.transparency_log_id)
                .await?;
        Self::verify_checkpoint_against_anchor(
            &descriptor,
            checkpoint,
            &observer_manifest.transparency_log_id,
            anchored_checkpoint.as_ref(),
            leaf_hash,
            "asymptote observer certificate",
        )?;
        verify_quorum_certificate(&observer_manifest, &decision, observer_guardian)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn verify_asymptote_observer_transcript(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        transcript: &AsymptoteObserverTranscript,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let observer_certificate = AsymptoteObserverCertificate {
            assignment: transcript.statement.assignment.clone(),
            verdict: transcript.statement.verdict,
            veto_kind: transcript.statement.veto_kind,
            evidence_hash: transcript.statement.evidence_hash,
            guardian_certificate: transcript.guardian_certificate.clone(),
        };
        let expected_statement =
            self.asymptote_observer_statement(header, certificate, &observer_certificate)?;
        if transcript.statement != expected_statement {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript statement does not match the canonical slot binding".into(),
            ));
        }
        self.verify_asymptote_observer_statement_certificate(
            &transcript.statement,
            &transcript.guardian_certificate,
            parent_view,
            current_epoch,
        )
        .await
    }

    pub(super) async fn derive_expected_asymptote_observer_assignments(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
        witness_seed: &GuardianWitnessEpochSeed,
        policy: &AsymptotePolicy,
    ) -> Result<Vec<AsymptoteObserverAssignment>, ConsensusError> {
        let validator_set_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "observer-backed asymptote proof requires an active validator set".into(),
                )
            })?;
        let validator_sets =
            read_validator_sets(&validator_set_bytes).map_err(ConsensusError::StateAccess)?;
        let active_set = effective_set_for_height(&validator_sets, header.height);
        let mut observer_manifests = std::collections::BTreeMap::new();
        for validator in &active_set.validators {
            if validator.account_id == header.producer_account_id {
                continue;
            }
            let manifest_hash_bytes = parent_view
                .get(&guardian_registry_committee_account_key(
                    &validator.account_id,
                ))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(format!(
                        "observer guardian manifest index missing for {}",
                        hex::encode(validator.account_id)
                    ))
                })?;
            let manifest_hash: [u8; 32] =
                manifest_hash_bytes.as_slice().try_into().map_err(|_| {
                    ConsensusError::BlockVerificationFailed(
                        "observer manifest hash must be 32 bytes".into(),
                    )
                })?;
            let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_committee_key(&manifest_hash))
                    .await
                    .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                    .ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(format!(
                            "observer guardian manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        ))
                    })?,
            )
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            observer_manifests.insert(validator.account_id, manifest);
        }
        let expected_plan = derive_asymptote_observer_plan_entries(
            witness_seed,
            active_set,
            &observer_manifests,
            header.producer_account_id,
            header.height,
            header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
            &policy.observer_correlation_budget,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        Ok(expected_plan
            .into_iter()
            .map(|entry| entry.assignment)
            .collect())
    }

    pub(super) async fn verify_asymptote_canonical_observer_sealed_finality(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
        proof: &ioi_types::app::SealedFinalityProof,
        policy: &AsymptotePolicy,
        witness_seed: &GuardianWitnessEpochSeed,
    ) -> Result<(), ConsensusError> {
        if policy.observer_rounds == 0 || policy.observer_committee_size == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing requires observer policy to be configured".into(),
            ));
        }
        if policy.observer_challenge_window_ms == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing requires a non-zero challenge window".into(),
            ));
        }
        if !proof.witness_certificates.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing may not mix witness certificates with observer transcripts"
                    .into(),
            ));
        }
        if !proof.observer_certificates.is_empty()
            || !proof.veto_proofs.is_empty()
            || proof.observer_close_certificate.is_some()
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing may not mix sampled observer certificates, veto proofs, or legacy close certificates".into(),
            ));
        }
        if !proof.divergence_signals.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing proof may not contain divergence signals".into(),
            ));
        }

        let transcript_commitment =
            proof
                .observer_transcript_commitment
                .as_ref()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "canonical observer sealing proof is missing a transcript commitment"
                            .into(),
                    )
                })?;
        let challenge_commitment =
            proof
                .observer_challenge_commitment
                .as_ref()
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "canonical observer sealing proof is missing a challenge commitment".into(),
                    )
                })?;
        if proof.observer_canonical_close.is_some() == proof.observer_canonical_abort.is_some() {
            return Err(ConsensusError::BlockVerificationFailed(
                "canonical observer sealing proof must carry exactly one of canonical close or canonical abort".into(),
            ));
        }
        let canonical_close = proof.observer_canonical_close.as_ref();
        let canonical_abort = proof.observer_canonical_abort.as_ref();

        let expected_assignments = self
            .derive_expected_asymptote_observer_assignments(
                header,
                parent_view,
                witness_seed,
                policy,
            )
            .await?;
        let expected_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&expected_assignments)
                .map_err(ConsensusError::BlockVerificationFailed)?;

        let expected_transcript_count =
            u16::try_from(expected_assignments.len()).map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "deterministic observer transcript surface exceeds u16 capacity".into(),
                )
            })?;
        let expected_challenge_root =
            canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        let expected_transcript_root =
            canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)
                .map_err(ConsensusError::BlockVerificationFailed)?;

        if transcript_commitment.epoch != current_epoch
            || transcript_commitment.height != header.height
            || transcript_commitment.view != header.view
            || transcript_commitment.assignments_hash != expected_assignments_hash
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript commitment does not match the canonical slot assignment surface".into(),
            ));
        }
        if challenge_commitment.epoch != current_epoch
            || challenge_commitment.height != header.height
            || challenge_commitment.view != header.view
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge commitment does not match the sealed slot".into(),
            ));
        }
        if let Some(canonical_close) = canonical_close {
            if canonical_close.epoch != current_epoch
                || canonical_close.height != header.height
                || canonical_close.view != header.view
                || canonical_close.assignments_hash != expected_assignments_hash
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close does not match the canonical slot assignment surface"
                        .into(),
                ));
            }
            if canonical_close.challenge_cutoff_timestamp_ms == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close must carry a non-zero challenge cutoff".into(),
                ));
            }
        }
        if let Some(canonical_abort) = canonical_abort {
            if canonical_abort.epoch != current_epoch
                || canonical_abort.height != header.height
                || canonical_abort.view != header.view
                || canonical_abort.assignments_hash != expected_assignments_hash
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort does not match the canonical slot assignment surface"
                        .into(),
                ));
            }
            if canonical_abort.challenge_cutoff_timestamp_ms == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort must carry a non-zero challenge cutoff".into(),
                ));
            }
        }

        let stored_transcript_commitment = parent_view
            .get(&guardian_registry_observer_transcript_commitment_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_transcript_commitment) = stored_transcript_commitment {
            let stored_transcript_commitment: ioi_types::app::AsymptoteObserverTranscriptCommitment =
                codec::from_bytes_canonical(&stored_transcript_commitment)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if &stored_transcript_commitment != transcript_commitment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript commitment does not match the on-chain registry copy"
                        .into(),
                ));
            }
        }

        let stored_challenge_commitment = parent_view
            .get(&guardian_registry_observer_challenge_commitment_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_challenge_commitment) = stored_challenge_commitment {
            let stored_challenge_commitment: ioi_types::app::AsymptoteObserverChallengeCommitment =
                codec::from_bytes_canonical(&stored_challenge_commitment)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if &stored_challenge_commitment != challenge_commitment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge commitment does not match the on-chain registry copy"
                        .into(),
                ));
            }
        }

        let stored_canonical_close = parent_view
            .get(&guardian_registry_observer_canonical_close_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_canonical_close) = stored_canonical_close {
            let stored_canonical_close: AsymptoteObserverCanonicalClose =
                codec::from_bytes_canonical(&stored_canonical_close)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if Some(&stored_canonical_close) != canonical_close {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical close does not match the on-chain registry copy".into(),
                ));
            }
        }
        let stored_canonical_abort = parent_view
            .get(&guardian_registry_observer_canonical_abort_key(
                current_epoch,
                header.height,
                header.view,
            ))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?;
        if let Some(stored_canonical_abort) = stored_canonical_abort {
            let stored_canonical_abort: AsymptoteObserverCanonicalAbort =
                codec::from_bytes_canonical(&stored_canonical_abort)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if Some(&stored_canonical_abort) != canonical_abort {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer canonical abort does not match the on-chain registry copy".into(),
                ));
            }
        }

        if transcript_commitment.transcripts_root != expected_transcript_root
            || canonical_close
                .map(|close| close.transcripts_root != expected_transcript_root)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.transcripts_root != expected_transcript_root)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript surface root does not match the proof-carried transcripts"
                    .into(),
            ));
        }
        if canonical_close
            .map(|close| {
                transcript_commitment.transcript_count != expected_transcript_count
                    || close.transcript_count != expected_transcript_count
            })
            .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer transcript counts do not match the deterministic assignment surface"
                    .into(),
            ));
        }
        if challenge_commitment.challenges_root != expected_challenge_root
            || canonical_close
                .map(|close| close.challenges_root != expected_challenge_root)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.challenges_root != expected_challenge_root)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge surface root does not match the proof-carried challenges"
                    .into(),
            ));
        }
        let proof_challenge_count =
            u16::try_from(proof.observer_challenges.len()).map_err(|_| {
                ConsensusError::BlockVerificationFailed(
                    "deterministic observer challenge surface exceeds u16 capacity".into(),
                )
            })?;
        if challenge_commitment.challenge_count != proof_challenge_count
            || canonical_close
                .map(|close| close.challenge_count != challenge_commitment.challenge_count)
                .unwrap_or(false)
            || canonical_abort
                .map(|abort| abort.challenge_count != challenge_commitment.challenge_count)
                .unwrap_or(false)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer challenge counts do not match the proof-carried challenge surface".into(),
            ));
        }

        let expected = expected_assignments
            .into_iter()
            .map(|assignment| {
                (
                    (assignment.round, assignment.observer_account_id),
                    assignment,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::new();
        for transcript in &proof.observer_transcripts {
            let key = (
                transcript.statement.assignment.round,
                transcript.statement.assignment.observer_account_id,
            );
            let Some(expected_assignment) = expected.get(&key) else {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface includes an unexpected assignment".into(),
                ));
            };
            if !seen.insert(key) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface contains duplicate assignments".into(),
                ));
            }
            if transcript.statement.assignment != *expected_assignment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript assignment does not match the deterministic sample".into(),
                ));
            }
            self.verify_asymptote_observer_transcript(
                header,
                certificate,
                transcript,
                parent_view,
                current_epoch,
            )
            .await?;
        }

        let mut challenged_assignments = HashSet::new();
        for challenge in &proof.observer_challenges {
            if challenge.epoch != current_epoch
                || challenge.height != header.height
                || challenge.view != header.view
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge does not match the sealed slot".into(),
                ));
            }
            let mut normalized_challenge = challenge.clone();
            normalized_challenge.challenge_id = [0u8; 32];
            let expected_challenge_id = ioi_crypto::algorithms::hash::sha256(
                &codec::to_bytes_canonical(&normalized_challenge)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
            )
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if challenge.challenge_id != expected_challenge_id {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge id does not match its canonical payload".into(),
                ));
            }
            match challenge.kind {
                AsymptoteObserverChallengeKind::MissingTranscript => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry a transcript".into(),
                        ));
                    }
                    if challenge.canonical_close.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge may not carry a canonical close".into(),
                        ));
                    }
                    let assignment_hash = canonical_asymptote_observer_assignment_hash(assignment)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != assignment_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "missing-transcript challenge evidence hash does not match the assignment".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::TranscriptMismatch => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge must be assignment scoped".into(),
                        )
                    })?;
                    let request = challenge.observation_request.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge must carry the offending observation request".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge may not carry a transcript".into(),
                        ));
                    }
                    let expected_request = self.asymptote_observer_observation_request(
                        header,
                        certificate,
                        assignment,
                    )?;
                    let request_hash =
                        canonical_asymptote_observer_observation_request_hash(request)
                            .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != request_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge evidence hash does not match the offending request".into(),
                        ));
                    }
                    if request == &expected_request {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "transcript-mismatch challenge does not contain an objective mismatch"
                                .into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::VetoTranscriptPresent => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge must carry the offending transcript".into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge references an unexpected assignment".into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge may not carry an observation request".into(),
                        ));
                    }
                    if transcript.statement.assignment != *assignment {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge transcript does not match its assignment"
                                .into(),
                        ));
                    }
                    let transcript_hash = canonical_asymptote_observer_transcript_hash(transcript)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != transcript_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge evidence hash does not match the offending transcript".into(),
                        ));
                    }
                    let observer_certificate = AsymptoteObserverCertificate {
                        assignment: transcript.statement.assignment.clone(),
                        verdict: transcript.statement.verdict,
                        veto_kind: transcript.statement.veto_kind,
                        evidence_hash: transcript.statement.evidence_hash,
                        guardian_certificate: transcript.guardian_certificate.clone(),
                    };
                    let expected_statement = self.asymptote_observer_statement(
                        header,
                        certificate,
                        &observer_certificate,
                    )?;
                    if transcript.statement != expected_statement {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge does not bind the canonical slot surface"
                                .into(),
                        ));
                    }
                    self.verify_asymptote_observer_statement_certificate(
                        &transcript.statement,
                        &transcript.guardian_certificate,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    if transcript.statement.verdict == AsymptoteObserverVerdict::Ok
                        && transcript.statement.veto_kind.is_none()
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "veto-transcript challenge does not carry an admissible veto".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::ConflictingTranscript => {
                    let assignment = challenge.assignment.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge must be assignment scoped".into(),
                        )
                    })?;
                    let transcript = challenge.transcript.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge must carry the offending transcript"
                                .into(),
                        )
                    })?;
                    let key = (assignment.round, assignment.observer_account_id);
                    if expected.get(&key) != Some(assignment) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge references an unexpected assignment"
                                .into(),
                        ));
                    }
                    if seen.contains(&key) {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge references an assignment that already has a transcript".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    let transcript_hash = canonical_asymptote_observer_transcript_hash(transcript)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != transcript_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge evidence hash does not match the offending transcript".into(),
                        ));
                    }
                    self.verify_asymptote_observer_statement_certificate(
                        &transcript.statement,
                        &transcript.guardian_certificate,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    let observer_certificate = AsymptoteObserverCertificate {
                        assignment: assignment.clone(),
                        verdict: transcript.statement.verdict,
                        veto_kind: transcript.statement.veto_kind,
                        evidence_hash: transcript.statement.evidence_hash,
                        guardian_certificate: transcript.guardian_certificate.clone(),
                    };
                    let expected_statement = self.asymptote_observer_statement(
                        header,
                        certificate,
                        &observer_certificate,
                    )?;
                    if transcript.statement.assignment == *assignment
                        && transcript.statement == expected_statement
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "conflicting-transcript challenge does not contain a conflicting transcript".into(),
                        ));
                    }
                    challenged_assignments.insert(key);
                }
                AsymptoteObserverChallengeKind::InvalidCanonicalClose => {
                    let close = challenge.canonical_close.as_ref().ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge must carry the offending canonical close".into(),
                        )
                    })?;
                    if challenge.assignment.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not be assignment scoped".into(),
                        ));
                    }
                    if challenge.observation_request.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not carry an observation request"
                                .into(),
                        ));
                    }
                    if challenge.transcript.is_some() {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge may not carry a transcript".into(),
                        ));
                    }
                    let close_hash = canonical_asymptote_observer_canonical_close_hash(close)
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    if challenge.evidence_hash != close_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge evidence hash does not match the offending close".into(),
                        ));
                    }
                    let empty_challenges_root = canonical_asymptote_observer_challenges_hash(&[])
                        .map_err(ConsensusError::BlockVerificationFailed)?;
                    let transcripts_are_all_ok =
                        proof.observer_transcripts.iter().all(|transcript| {
                            transcript.statement.verdict == AsymptoteObserverVerdict::Ok
                                && transcript.statement.veto_kind.is_none()
                        });
                    let close_is_valid = close.epoch == current_epoch
                        && close.height == header.height
                        && close.view == header.view
                        && close.assignments_hash == expected_assignments_hash
                        && close.transcripts_root == expected_transcript_root
                        && close.transcript_count == proof.observer_transcripts.len() as u16
                        && close.challenges_root == empty_challenges_root
                        && close.challenge_count == 0
                        && close.challenge_cutoff_timestamp_ms != 0
                        && seen.len() == expected.len()
                        && transcripts_are_all_ok;
                    if close_is_valid {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "invalid-canonical-close challenge does not contain an objectively invalid close".into(),
                        ));
                    }
                }
            }
        }

        if let Some(canonical_close) = canonical_close {
            if proof.finality_tier != FinalityTier::SealedFinal
                || proof.collapse_state != CollapseState::SealedFinal
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer close must appear only in a SealedFinal proof".into(),
                ));
            }
            if !proof.observer_challenges.is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer challenge surface is non-empty; canonical close is challenge-dominated".into(),
                ));
            }
            if canonical_close.challenge_count != 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer close may not carry dominant challenges".into(),
                ));
            }
            if seen.len() != expected.len() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer transcript surface does not cover every deterministic assignment"
                        .into(),
                ));
            }
            for transcript in &proof.observer_transcripts {
                if transcript.statement.verdict != AsymptoteObserverVerdict::Ok
                    || transcript.statement.veto_kind.is_some()
                {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "observer transcript surface contains a non-OK verdict; SealedFinal is dominated".into(),
                    ));
                }
            }
        }
        if let Some(canonical_abort) = canonical_abort {
            if proof.finality_tier != FinalityTier::BaseFinal
                || proof.collapse_state != CollapseState::Abort
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort must appear only in an Abort proof".into(),
                ));
            }
            if proof.observer_challenges.is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort requires at least one dominant challenge".into(),
                ));
            }
            if canonical_abort.challenge_count == 0 {
                return Err(ConsensusError::BlockVerificationFailed(
                    "canonical observer abort must bind a non-empty challenge surface".into(),
                ));
            }
            for assignment in expected.values() {
                let key = (assignment.round, assignment.observer_account_id);
                if !seen.contains(&key) && !challenged_assignments.contains(&key) {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "canonical observer abort does not account for every deterministic assignment".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub(super) async fn verify_asymptote_observer_sealed_finality(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
        proof: &ioi_types::app::SealedFinalityProof,
        policy: &AsymptotePolicy,
        witness_seed: &GuardianWitnessEpochSeed,
    ) -> Result<(), ConsensusError> {
        if policy.observer_rounds == 0 || policy.observer_committee_size == 0 {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed asymptote proof requires observer policy to be configured".into(),
            ));
        }
        if proof.finality_tier != FinalityTier::SealedFinal
            || proof.collapse_state != CollapseState::SealedFinal
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof is not in the SealedFinal state".into(),
            ));
        }
        if !proof.witness_certificates.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof may not mix witness certificates with equal-authority observer certificates".into(),
            ));
        }
        if !proof.divergence_signals.is_empty() {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof may not contain divergence signals".into(),
            ));
        }

        let expected_assignments = self
            .derive_expected_asymptote_observer_assignments(
                header,
                parent_view,
                witness_seed,
                policy,
            )
            .await?;

        if proof.observer_certificates.len() != expected_assignments.len() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "sealed finality proof has {} observer certificates but expected {} equal-authority assignments",
                proof.observer_certificates.len(),
                expected_assignments.len()
            )));
        }
        let Some(observer_close_certificate) = proof.observer_close_certificate.as_ref() else {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer-backed sealed finality proof is missing an observer close certificate"
                    .into(),
            ));
        };
        let expected_assignments_hash =
            canonical_asymptote_observer_assignments_hash(&expected_assignments)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        if observer_close_certificate.epoch != current_epoch
            || observer_close_certificate.height != header.height
            || observer_close_certificate.view != header.view
            || observer_close_certificate.assignments_hash != expected_assignments_hash
            || observer_close_certificate.expected_assignments != expected_assignments.len() as u16
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer close certificate does not match the deterministic observer sample"
                    .into(),
            ));
        }
        if observer_close_certificate.ok_count != proof.observer_certificates.len() as u16
            || observer_close_certificate.veto_count != proof.veto_proofs.len() as u16
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "observer close certificate does not match attached observer verdict counts".into(),
            ));
        }

        let expected = expected_assignments
            .into_iter()
            .map(|assignment| {
                (
                    (assignment.round, assignment.observer_account_id),
                    assignment,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut seen = HashSet::new();
        for observer_certificate in &proof.observer_certificates {
            let key = (
                observer_certificate.assignment.round,
                observer_certificate.assignment.observer_account_id,
            );
            let Some(expected_assignment) = expected.get(&key) else {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof includes an unexpected observer assignment".into(),
                ));
            };
            if !seen.insert(key) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate observer assignments".into(),
                ));
            }
            if observer_certificate.assignment != *expected_assignment {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof observer assignment does not match the deterministic sample".into(),
                ));
            }
            if observer_certificate.verdict != AsymptoteObserverVerdict::Ok
                || observer_certificate.veto_kind.is_some()
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains a non-OK observer certificate".into(),
                ));
            }
            self.verify_asymptote_observer_certificate(
                header,
                certificate,
                observer_certificate,
                parent_view,
                current_epoch,
            )
            .await?;
        }

        for veto_proof in &proof.veto_proofs {
            let observer_certificate = &veto_proof.observer_certificate;
            if observer_certificate.verdict != AsymptoteObserverVerdict::Veto
                || observer_certificate.veto_kind.is_none()
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "observer veto proof does not contain a veto verdict".into(),
                ));
            }
            self.verify_asymptote_observer_certificate(
                header,
                certificate,
                observer_certificate,
                parent_view,
                current_epoch,
            )
            .await?;
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "valid equal-authority observer veto proof aborts sealed finality: {}",
                veto_proof.details
            )));
        }

        Ok(())
    }

    pub(super) fn verify_experimental_witness_certificate_against_manifest(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        manifest: &GuardianWitnessCommitteeManifest,
    ) -> Result<(), ConsensusError> {
        let witness_certificate = certificate
            .experimental_witness_certificate
            .as_ref()
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "experimental nested guardian mode requires witness certificate".into(),
                )
            })?;
        let statement = self.experimental_witness_statement(header, certificate);
        verify_witness_certificate(manifest, &statement, witness_certificate)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) fn witness_checkpoint_entry_bytes(
        statement: &GuardianWitnessStatement,
        certificate: &ioi_types::app::GuardianWitnessCertificate,
    ) -> Result<Vec<u8>, ConsensusError> {
        let mut checkpoint_certificate = certificate.clone();
        checkpoint_certificate.log_checkpoint = None;
        codec::to_bytes_canonical(&(statement, checkpoint_certificate))
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn verify_asymptote_sealed_finality(
        &self,
        header: &BlockHeader,
        certificate: &GuardianQuorumCertificate,
        manifest: &GuardianCommitteeManifest,
        parent_view: &dyn AnchoredStateView,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let Some(proof) = header.sealed_finality_proof.as_ref() else {
            return Ok(());
        };

        let policy_bytes = parent_view
            .get(&guardian_registry_asymptote_policy_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "asymptote mode requires an epoch-scoped asymptote policy".into(),
                )
            })?;
        let policy: AsymptotePolicy = codec::from_bytes_canonical(&policy_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if policy.epoch != current_epoch || proof.epoch != current_epoch {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof epoch does not match current epoch".into(),
            ));
        }
        verify_sealed_finality_proof_signature(header, proof)?;
        if proof.guardian_manifest_hash != certificate.manifest_hash
            || proof.guardian_decision_hash != certificate.decision_hash
            || proof.guardian_counter != certificate.counter
            || proof.guardian_trace_hash != certificate.trace_hash
            || proof.guardian_measurement_root != certificate.measurement_root
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof is not bound to the guardian certificate".into(),
            ));
        }
        if proof.policy_hash != manifest.policy_hash {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality policy hash does not match guardian manifest policy".into(),
            ));
        }
        let witness_seed_bytes = parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "witness assignment seed is not registered on-chain".into(),
                )
            })?;
        let witness_seed: GuardianWitnessEpochSeed =
            codec::from_bytes_canonical(&witness_seed_bytes)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        if policy.observer_sealing_mode == AsymptoteObserverSealingMode::CanonicalChallengeV1
            || !proof.observer_transcripts.is_empty()
            || !proof.observer_challenges.is_empty()
            || proof.observer_transcript_commitment.is_some()
            || proof.observer_challenge_commitment.is_some()
            || proof.observer_canonical_close.is_some()
        {
            return self
                .verify_asymptote_canonical_observer_sealed_finality(
                    header,
                    certificate,
                    parent_view,
                    current_epoch,
                    proof,
                    &policy,
                    &witness_seed,
                )
                .await;
        }
        if !proof.observer_certificates.is_empty() || !proof.veto_proofs.is_empty() {
            return self
                .verify_asymptote_observer_sealed_finality(
                    header,
                    certificate,
                    parent_view,
                    current_epoch,
                    proof,
                    &policy,
                    &witness_seed,
                )
                .await;
        }
        if proof.finality_tier != FinalityTier::SealedFinal
            || proof.collapse_state != CollapseState::SealedFinal
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "witness-backed sealed finality proof is not in the SealedFinal state".into(),
            ));
        }
        let required_strata = if proof.divergence_signals.is_empty() {
            &policy.required_witness_strata
        } else {
            &policy.escalation_witness_strata
        };
        if proof.witness_certificates.len() != required_strata.len() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "sealed finality proof has {} witness certificates but policy requires exactly {} strata",
                proof.witness_certificates.len(),
                required_strata.len()
            )));
        }

        let witness_set_bytes = parent_view
            .get(&guardian_registry_witness_set_key(current_epoch))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(
                    "active witness set is not registered on-chain".into(),
                )
            })?;
        let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(&witness_set_bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        let reassignment_depth = proof
            .witness_certificates
            .first()
            .map(|certificate| certificate.reassignment_depth)
            .unwrap_or_default();
        if proof
            .witness_certificates
            .iter()
            .any(|certificate| certificate.reassignment_depth != reassignment_depth)
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "sealed finality proof mixes witness reassignment depths".into(),
            ));
        }
        let mut active_witness_manifests = Vec::with_capacity(witness_set.manifest_hashes.len());
        for manifest_hash in &witness_set.manifest_hashes {
            let witness_bytes = parent_view
                .get(&guardian_registry_witness_key(manifest_hash))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "active witness manifest is not registered on-chain".into(),
                    )
                })?;
            let witness_manifest: GuardianWitnessCommitteeManifest =
                codec::from_bytes_canonical(&witness_bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if witness_manifest.epoch != current_epoch {
                return Err(ConsensusError::BlockVerificationFailed(
                    "active witness manifest epoch does not match current epoch".into(),
                ));
            }
            active_witness_manifests.push(witness_manifest);
        }

        let expected_assignments = derive_guardian_witness_assignments_for_strata(
            &witness_seed,
            &witness_set,
            &active_witness_manifests,
            header.producer_account_id,
            header.height,
            header.view,
            reassignment_depth,
            required_strata,
        )
        .map_err(ConsensusError::BlockVerificationFailed)?;
        let expected_manifest_hashes = expected_assignments
            .iter()
            .map(|assignment| assignment.manifest_hash)
            .collect::<BTreeSet<_>>();
        let expected_strata = expected_assignments
            .iter()
            .map(|assignment| assignment.stratum_id.clone())
            .collect::<BTreeSet<_>>();
        let mut seen_manifests = BTreeSet::new();
        let mut seen_strata = BTreeSet::new();
        for witness_certificate in &proof.witness_certificates {
            if !seen_manifests.insert(witness_certificate.manifest_hash) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate witness committees".into(),
                ));
            }
            if witness_certificate.stratum_id.trim().is_empty() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains a witness certificate without a stratum".into(),
                ));
            }
            if !expected_manifest_hashes.contains(&witness_certificate.manifest_hash) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof includes a witness committee outside the deterministic stratum assignment".into(),
                ));
            }
            if !witness_set
                .manifest_hashes
                .contains(&witness_certificate.manifest_hash)
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof references a committee outside the active witness set"
                        .into(),
                ));
            }

            let witness_bytes = parent_view
                .get(&guardian_registry_witness_key(
                    &witness_certificate.manifest_hash,
                ))
                .await
                .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                .ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "sealed finality witness manifest is not registered on-chain".into(),
                    )
                })?;
            let witness_manifest: GuardianWitnessCommitteeManifest =
                codec::from_bytes_canonical(&witness_bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            if witness_manifest.epoch != current_epoch || witness_certificate.epoch != current_epoch
            {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness epoch does not match current epoch".into(),
                ));
            }
            if witness_manifest.stratum_id != witness_certificate.stratum_id {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness certificate stratum does not match the registered witness manifest".into(),
                ));
            }
            if !expected_strata.contains(&witness_certificate.stratum_id) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality witness certificate satisfies an unexpected stratum".into(),
                ));
            }
            if !seen_strata.insert(witness_certificate.stratum_id.clone()) {
                return Err(ConsensusError::BlockVerificationFailed(
                    "sealed finality proof contains duplicate witness strata".into(),
                ));
            }
            let witness_checkpoint =
                witness_certificate.log_checkpoint.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "sealed finality witness certificate is missing a checkpoint".into(),
                    )
                })?;
            let statement = guardian_witness_statement_for_header_with_recovery_binding(
                header,
                certificate,
                witness_certificate.recovery_binding.clone(),
            );
            let witness_descriptor =
                Self::load_log_descriptor(parent_view, &witness_manifest.transparency_log_id)
                    .await?;
            let witness_checkpoint_entry =
                Self::witness_checkpoint_entry_bytes(&statement, witness_certificate)?;
            let witness_leaf_hash = canonical_log_leaf_hash(&witness_checkpoint_entry)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
            let anchored_witness_checkpoint =
                Self::load_anchored_checkpoint(parent_view, &witness_manifest.transparency_log_id)
                    .await?;
            Self::verify_checkpoint_against_anchor(
                &witness_descriptor,
                witness_checkpoint,
                &witness_manifest.transparency_log_id,
                anchored_witness_checkpoint.as_ref(),
                witness_leaf_hash,
                "sealed witness certificate",
            )?;
            verify_witness_certificate(&witness_manifest, &statement, witness_certificate)
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
        }

        Ok(())
    }

    pub(super) async fn verify_canonical_order_enrichment(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let published_order_abort = parent_view
            .get(&aft_canonical_order_abort_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<CanonicalOrderAbort>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let published_bulletin_availability = parent_view
            .get(&aft_bulletin_availability_certificate_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<BulletinAvailabilityCertificate>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let published_bulletin_close = parent_view
            .get(&aft_canonical_bulletin_close_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<CanonicalBulletinClose>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            if published_order_abort.is_some() {
                if published_bulletin_availability.is_some() || published_bulletin_close.is_some() {
                    return Err(ConsensusError::BlockVerificationFailed(format!(
                        "parent state for slot {} is inconsistent: canonical order abort coexists with positive published ordering artifacts",
                        header.height
                    )));
                }
                return Ok(());
            }
            return Ok(());
        };
        if let Some(order_abort) = published_order_abort.as_ref() {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "canonical order abort already dominates slot {}: {}",
                header.height, order_abort.details
            )));
        }
        let published_bulletin = parent_view
            .get(&aft_bulletin_commitment_key(header.height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .map(|bytes| {
                codec::from_bytes_canonical::<BulletinCommitment>(&bytes)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
            })
            .transpose()?;
        verify_canonical_order_certificate(
            header,
            certificate,
            published_bulletin.as_ref(),
            published_bulletin_availability.as_ref(),
            published_bulletin_close.as_ref(),
        )
        .map_err(ConsensusError::BlockVerificationFailed)
    }

    pub(super) async fn load_published_publication_frontier(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontier>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_publication_frontier_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn load_published_publication_frontier_contradiction(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontierContradiction>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&aft_publication_frontier_contradiction_key(height))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn previous_publication_frontier_for_height(
        &self,
        height: u64,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<Option<PublicationFrontier>, ConsensusError> {
        if height <= 1 {
            return Ok(None);
        }
        if let Some(local) = self
            .committed_headers
            .get(&(height - 1))
            .and_then(|header| header.publication_frontier.clone())
        {
            return Ok(Some(local));
        }
        self.load_published_publication_frontier(height - 1, parent_view)
            .await
    }

    pub(super) async fn verify_publication_frontier_enrichment(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        if let Some(contradiction) = self
            .load_published_publication_frontier_contradiction(header.height, parent_view)
            .await?
        {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "publication frontier contradiction already dominates slot {}: {}",
                header.height,
                hex::encode(
                    canonical_publication_frontier_hash(&contradiction.candidate_frontier)
                        .map_err(ConsensusError::BlockVerificationFailed)?
                ),
            )));
        }

        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            if header.publication_frontier.is_some() {
                return Err(ConsensusError::BlockVerificationFailed(
                    "publication frontier requires a canonical-order certificate".into(),
                ));
            }
            return Ok(());
        };

        let frontier = header.publication_frontier.as_ref().ok_or_else(|| {
            ConsensusError::BlockVerificationFailed(format!(
                "canonical-order certificate for slot {} requires a publication frontier",
                header.height
            ))
        })?;

        verify_publication_frontier_binding(header, frontier)
            .map_err(ConsensusError::BlockVerificationFailed)?;

        if let Some(previous) = self
            .previous_publication_frontier_for_height(header.height, parent_view)
            .await?
            .as_ref()
        {
            verify_publication_frontier_chain(frontier, previous)
                .map_err(ConsensusError::BlockVerificationFailed)?;
        }

        if frontier.bulletin_commitment_hash
            != canonical_bulletin_commitment_hash(&certificate.bulletin_commitment)
                .map_err(ConsensusError::BlockVerificationFailed)?
        {
            return Err(ConsensusError::BlockVerificationFailed(
                "publication frontier does not match the canonical-order bulletin commitment"
                    .into(),
            ));
        }

        if let Some(published) = self
            .load_published_publication_frontier(header.height, parent_view)
            .await?
        {
            if published != *frontier {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "publication frontier for slot {} conflicts with the published same-slot frontier",
                    header.height
                )));
            }
        }

        Ok(())
    }

    pub(super) async fn verify_published_canonical_collapse_object(
        &self,
        header: &BlockHeader,
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        let Some(published) = self
            .load_published_canonical_collapse_object(header.height, parent_view)
            .await?
        else {
            return Ok(());
        };
        let derived = self
            .canonical_collapse_from_header_surface_with_parent_view(header, parent_view)
            .await?;
        if published != derived {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "published canonical collapse object does not match the proof-carried surface for slot {}",
                header.height
            )));
        }
        self.verify_canonical_collapse_chain_with_parent_view(&published, parent_view)
            .await?;
        Ok(())
    }

    pub(super) async fn load_anchored_checkpoint(
        parent_view: &dyn AnchoredStateView,
        log_id: &str,
    ) -> Result<Option<GuardianLogCheckpoint>, ConsensusError> {
        let Some(bytes) = parent_view
            .get(&guardian_registry_checkpoint_key(log_id))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
        else {
            return Ok(None);
        };

        codec::from_bytes_canonical(&bytes)
            .map(Some)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) async fn load_log_descriptor(
        parent_view: &dyn AnchoredStateView,
        log_id: &str,
    ) -> Result<GuardianTransparencyLogDescriptor, ConsensusError> {
        let bytes = parent_view
            .get(&guardian_registry_log_key(log_id))
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or_else(|| {
                ConsensusError::BlockVerificationFailed(format!(
                    "guardian transparency log '{}' is not registered on-chain",
                    log_id
                ))
            })?;

        codec::from_bytes_canonical(&bytes)
            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))
    }

    pub(super) fn verify_checkpoint_against_anchor(
        descriptor: &GuardianTransparencyLogDescriptor,
        checkpoint: &GuardianLogCheckpoint,
        expected_log_id: &str,
        anchored_checkpoint: Option<&GuardianLogCheckpoint>,
        expected_leaf_hash: [u8; 32],
        certificate_label: &str,
    ) -> Result<(), ConsensusError> {
        if checkpoint.log_id != expected_log_id {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint log id does not match registered transparency log"
            )));
        }
        if checkpoint.tree_size == 0 {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint tree size must be non-zero"
            )));
        }

        verify_checkpoint_signature(descriptor, checkpoint).map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!(
                "{certificate_label} checkpoint signature verification failed: {e}"
            ))
        })?;
        verify_checkpoint_proof(checkpoint, anchored_checkpoint, expected_leaf_hash).map_err(
            |e| {
                ConsensusError::BlockVerificationFailed(format!(
                    "{certificate_label} checkpoint append-only proof failed: {e}"
                ))
            },
        )?;

        Ok(())
    }

    pub(super) async fn verify_guardianized_certificate(
        &self,
        header: &BlockHeader,
        preimage: &[u8],
        parent_view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        match self.safety_mode {
            AftSafetyMode::ClassicBft => Ok(()),
            AftSafetyMode::GuardianMajority
            | AftSafetyMode::Asymptote
            | AftSafetyMode::ExperimentalNestedGuardian => {
                let cert = header.guardian_certificate.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "guardianized mode requires guardian_certificate".into(),
                    )
                })?;
                let manifest_bytes = parent_view
                    .get(&guardian_registry_committee_key(&cert.manifest_hash))
                    .await
                    .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
                    .ok_or_else(|| {
                        ConsensusError::BlockVerificationFailed(
                            "guardianized manifest is not registered on-chain".into(),
                        )
                    })?;
                let manifest: GuardianCommitteeManifest =
                    codec::from_bytes_canonical(&manifest_bytes)
                        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                let current_epoch =
                    match parent_view.get(CURRENT_EPOCH_KEY).await.map_err(|e| {
                        ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                    })? {
                        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
                        None => 1,
                    };
                if manifest.epoch != current_epoch || cert.epoch != current_epoch {
                    return Err(ConsensusError::BlockVerificationFailed(
                        "guardian certificate epoch does not match current epoch".into(),
                    ));
                }
                let guardian_descriptor =
                    Self::load_log_descriptor(parent_view, &manifest.transparency_log_id).await?;
                let guardian_checkpoint = cert.log_checkpoint.as_ref().ok_or_else(|| {
                    ConsensusError::BlockVerificationFailed(
                        "guardianized mode requires a guardian log checkpoint".into(),
                    )
                })?;
                let decision =
                    Self::guardian_decision_from_header(header, preimage, &manifest, cert)?;
                let guardian_checkpoint_entry =
                    Self::guardian_checkpoint_entry_bytes(&decision, cert)?;
                let guardian_leaf_hash = canonical_log_leaf_hash(&guardian_checkpoint_entry)
                    .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                let anchored_guardian_checkpoint =
                    Self::load_anchored_checkpoint(parent_view, &manifest.transparency_log_id)
                        .await?;
                Self::verify_checkpoint_against_anchor(
                    &guardian_descriptor,
                    guardian_checkpoint,
                    &manifest.transparency_log_id,
                    anchored_guardian_checkpoint.as_ref(),
                    guardian_leaf_hash,
                    "guardian certificate",
                )?;
                self.verify_guardianized_certificate_against_manifest(header, preimage, &manifest)?;
                if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
                    self.verify_asymptote_sealed_finality(
                        header,
                        cert,
                        &manifest,
                        parent_view,
                        current_epoch,
                    )
                    .await?;
                    self.verify_canonical_order_enrichment(header, parent_view)
                        .await?;
                    self.verify_publication_frontier_enrichment(header, parent_view)
                        .await?;
                }
                if matches!(self.safety_mode, AftSafetyMode::ExperimentalNestedGuardian) {
                    let witness_certificate = cert
                        .experimental_witness_certificate
                        .as_ref()
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "experimental nested guardian mode requires witness certificate"
                                    .into(),
                            )
                        })?;
                    let witness_bytes = parent_view
                        .get(&guardian_registry_witness_key(
                            &witness_certificate.manifest_hash,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "experimental witness manifest is not registered on-chain".into(),
                            )
                        })?;
                    let witness_manifest: GuardianWitnessCommitteeManifest =
                        codec::from_bytes_canonical(&witness_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let active_witness_set_bytes = parent_view
                        .get(&guardian_registry_witness_set_key(
                            witness_certificate.epoch,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "active witness set is not registered on-chain".into(),
                            )
                        })?;
                    let active_witness_set: GuardianWitnessSet =
                        codec::from_bytes_canonical(&active_witness_set_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let witness_seed_bytes = parent_view
                        .get(&guardian_registry_witness_seed_key(
                            witness_certificate.epoch,
                        ))
                        .await
                        .map_err(|e| {
                            ConsensusError::StateAccess(StateError::Backend(e.to_string()))
                        })?
                        .ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "witness assignment seed is not registered on-chain".into(),
                            )
                        })?;
                    let witness_seed: GuardianWitnessEpochSeed =
                        codec::from_bytes_canonical(&witness_seed_bytes)
                            .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    if witness_manifest.epoch != current_epoch
                        || witness_certificate.epoch != current_epoch
                        || active_witness_set.epoch != current_epoch
                        || witness_seed.epoch != current_epoch
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate epoch does not match current epoch".into(),
                        ));
                    }
                    let expected_assignment = derive_guardian_witness_assignment(
                        &witness_seed,
                        &active_witness_set,
                        header.producer_account_id,
                        header.height,
                        header.view,
                        witness_certificate.reassignment_depth,
                    )
                    .map_err(ConsensusError::BlockVerificationFailed)?;
                    if expected_assignment.manifest_hash != witness_certificate.manifest_hash {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate does not match deterministic assignment".into(),
                        ));
                    }
                    if !active_witness_set
                        .manifest_hashes
                        .contains(&witness_certificate.manifest_hash)
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate references a committee outside the active witness set"
                                .into(),
                        ));
                    }
                    if expected_assignment.checkpoint_interval_blocks > 0
                        && witness_certificate.log_checkpoint.is_none()
                    {
                        return Err(ConsensusError::BlockVerificationFailed(
                            "witness certificate is missing a required checkpoint".into(),
                        ));
                    }
                    let witness_checkpoint =
                        witness_certificate.log_checkpoint.as_ref().ok_or_else(|| {
                            ConsensusError::BlockVerificationFailed(
                                "nested guardian mode requires a witness log checkpoint".into(),
                            )
                        })?;
                    let witness_descriptor = Self::load_log_descriptor(
                        parent_view,
                        &witness_manifest.transparency_log_id,
                    )
                    .await?;
                    let witness_statement = self.experimental_witness_statement(header, cert);
                    let witness_checkpoint_entry = Self::witness_checkpoint_entry_bytes(
                        &witness_statement,
                        witness_certificate,
                    )?;
                    let witness_leaf_hash = canonical_log_leaf_hash(&witness_checkpoint_entry)
                        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
                    let anchored_witness_checkpoint = Self::load_anchored_checkpoint(
                        parent_view,
                        &witness_manifest.transparency_log_id,
                    )
                    .await?;
                    Self::verify_checkpoint_against_anchor(
                        &witness_descriptor,
                        witness_checkpoint,
                        &witness_manifest.transparency_log_id,
                        anchored_witness_checkpoint.as_ref(),
                        witness_leaf_hash,
                        "witness certificate",
                    )?;
                    self.verify_experimental_witness_certificate_against_manifest(
                        header,
                        cert,
                        &witness_manifest,
                    )?;
                }
                Ok(())
            }
        }
    }

}
