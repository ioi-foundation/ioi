use super::*;

impl GuardianMajorityEngine {
    pub(super) fn reset_cache_for_height(&mut self, height: u64) {
        self.maybe_promote_committed_height_qc(height);
        self.view_votes.retain(|h, _| *h >= height);
        self.tc_formed.retain(|(h, _)| *h >= height);
        self.timeout_votes_sent.retain(|(h, _)| *h >= height);
        self.seen_headers.retain(|(h, _), _| *h >= height);
        self.vote_pool.retain(|h, _| *h >= height);
        self.validator_count_by_height.retain(|h, _| *h >= height);
        self.qc_pool.retain(|h, _| *h + 2 >= height);
        self.committed_headers.retain(|h, _| *h + 2 >= height);
        if !matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            self.committed_collapses.retain(|h, _| *h + 2 >= height);
        }
        self.recovered_headers.retain(|h, _| *h + 2 >= height);
        self.recovered_certified_headers
            .retain(|h, _| *h + 2 >= height);
        self.recovered_restart_headers
            .retain(|h, _| *h + 2 >= height);
        self.pending_qc_broadcasts
            .retain(|qc| qc.height + 2 >= height);
        self.announced_qcs
            .retain(|(qc_height, _)| *qc_height + 2 >= height);
        self.echo_pool.retain(|(h, _), _| *h >= height);
        self.voted_slots.retain(|(h, _)| *h >= height);

        if let Ok(mut pm) = self.pacemaker.try_lock() {
            pm.current_view = 0;
            pm.view_start_time = std::time::Instant::now();
        }
    }

    pub(super) fn record_committed_block(
        &mut self,
        header: &BlockHeader,
        collapse: Option<&CanonicalCollapseObject>,
    ) -> bool {
        if matches!(self.safety_mode, AftSafetyMode::Asymptote) {
            let Some(expected_collapse) = collapse else {
                if header.height <= 2 {
                    warn!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        reason = "missing_expected_collapse",
                        "Rejecting committed header hint in Asymptote."
                    );
                }
                if header.height <= 2 {
                    eprintln!(
                        "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=missing_expected_collapse",
                        header.height, header.view
                    );
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint without a verified canonical collapse object in Asymptote"
                );
                return false;
            };
            let previous = if header.height <= 1 {
                None
            } else {
                let Some(previous) = self.committed_collapses.get(&(header.height - 1)) else {
                    if header.height <= 2 {
                        warn!(
                            target: "consensus",
                            height = header.height,
                            view = header.view,
                            reason = "missing_previous_local_collapse",
                            "Rejecting committed header hint in Asymptote."
                        );
                    }
                    if header.height <= 2 {
                        eprintln!(
                            "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=missing_previous_local_collapse",
                            header.height, header.view
                        );
                    }
                    debug!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        "Ignoring committed header hint because the previous canonical collapse object is not locally known"
                    );
                    return false;
                };
                if let Err(error) = self.verify_local_canonical_collapse_chain(previous) {
                    if header.height <= 2 {
                        warn!(
                            target: "consensus",
                            height = header.height,
                            view = header.view,
                            reason = "invalid_previous_local_chain",
                            error = %error,
                            "Rejecting committed header hint in Asymptote."
                        );
                    }
                    if header.height <= 2 {
                        eprintln!(
                            "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=invalid_previous_local_chain error={}",
                            header.height, header.view, error
                        );
                    }
                    debug!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        "Ignoring committed header hint because the local predecessor collapse chain failed recursive continuity verification: {}",
                        error
                    );
                    return false;
                }
                Some(previous)
            };
            let Ok(derived) =
                self.canonical_collapse_from_header_surface_with_previous(header, previous)
            else {
                if header.height <= 2 {
                    warn!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        reason = "header_surface_derivation_failed",
                        "Rejecting committed header hint in Asymptote."
                    );
                }
                if header.height <= 2 {
                    eprintln!(
                        "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=header_surface_derivation_failed",
                        header.height, header.view
                    );
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the canonical collapse surface could not be derived"
                );
                return false;
            };
            if !canonical_collapse_eq_on_header_surface(&derived, expected_collapse) {
                if header.height <= 2 {
                    warn!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        reason = "header_surface_mismatch",
                        prev_hash_match = derived.previous_canonical_collapse_commitment_hash
                            == expected_collapse.previous_canonical_collapse_commitment_hash,
                        ordering_height_match = derived.ordering.height
                            == expected_collapse.ordering.height,
                        ordering_kind_match = derived.ordering.kind
                            == expected_collapse.ordering.kind,
                        commitment_match = derived.ordering.bulletin_commitment_hash
                            == expected_collapse.ordering.bulletin_commitment_hash,
                        availability_match = derived.ordering.bulletin_availability_certificate_hash
                            == expected_collapse.ordering.bulletin_availability_certificate_hash,
                        close_match = derived.ordering.bulletin_close_hash
                            == expected_collapse.ordering.bulletin_close_hash,
                        order_cert_match = derived.ordering.canonical_order_certificate_hash
                            == expected_collapse.ordering.canonical_order_certificate_hash,
                        sealing_match = derived.sealing == expected_collapse.sealing,
                        tx_root_match = derived.transactions_root_hash
                            == expected_collapse.transactions_root_hash,
                        state_root_match = derived.resulting_state_root_hash
                            == expected_collapse.resulting_state_root_hash,
                        "Rejecting committed header hint in Asymptote."
                    );
                }
                if header.height <= 2 {
                    eprintln!(
                        "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=header_surface_mismatch prev_hash={} ordering_height={} ordering_kind={} commitment={} availability={} close={} order_cert={} sealing={} tx_root={} state_root={}",
                        header.height,
                        header.view,
                        derived.previous_canonical_collapse_commitment_hash
                            == expected_collapse.previous_canonical_collapse_commitment_hash,
                        derived.ordering.height == expected_collapse.ordering.height,
                        derived.ordering.kind == expected_collapse.ordering.kind,
                        derived.ordering.bulletin_commitment_hash
                            == expected_collapse.ordering.bulletin_commitment_hash,
                        derived.ordering.bulletin_availability_certificate_hash
                            == expected_collapse.ordering.bulletin_availability_certificate_hash,
                        derived.ordering.bulletin_close_hash
                            == expected_collapse.ordering.bulletin_close_hash,
                        derived.ordering.canonical_order_certificate_hash
                            == expected_collapse.ordering.canonical_order_certificate_hash,
                        derived.sealing == expected_collapse.sealing,
                        derived.transactions_root_hash == expected_collapse.transactions_root_hash,
                        derived.resulting_state_root_hash
                            == expected_collapse.resulting_state_root_hash,
                    );
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the supplied canonical collapse object does not match the header surface"
                );
                return false;
            }
            if let Err(error) =
                self.verify_runtime_canonical_collapse_continuity(expected_collapse, previous)
            {
                if header.height <= 2 {
                    warn!(
                        target: "consensus",
                        height = header.height,
                        view = header.view,
                        reason = "expected_collapse_backend_failed",
                        error = %error,
                        "Rejecting committed header hint in Asymptote."
                    );
                }
                if header.height <= 2 {
                    eprintln!(
                        "[BENCH-AFT-COMMIT-HINT-REJECT] height={} view={} reason=expected_collapse_backend_failed error={}",
                        header.height, header.view, error
                    );
                }
                debug!(
                    target: "consensus",
                    height = header.height,
                    view = header.view,
                    "Ignoring committed header hint because the canonical collapse object failed backend verification: {}",
                    error
                );
                return false;
            }
        }

        let Ok(hash) = header.hash() else {
            return false;
        };
        let Ok(block_hash) = to_root_hash(&hash) else {
            return false;
        };
        self.committed_headers.insert(header.height, header.clone());
        if let Some(collapse) = collapse {
            self.committed_collapses
                .insert(header.height, collapse.clone());
        }
        self.seen_headers
            .entry((header.height, header.view))
            .or_default()
            .insert(block_hash, header.clone());
        if Self::benchmark_trace_enabled() && header.height <= 2 {
            eprintln!(
                "[BENCH-AFT-COMMIT-HINT] height={} view={} hash={} collapse={}",
                header.height,
                header.view,
                hex::encode(&block_hash[..4]),
                collapse.is_some()
            );
        }
        true
    }

    pub(super) fn store_aft_recovered_consensus_header(
        &mut self,
        header: &AftRecoveredConsensusHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_headers.get(&header.height) {
            return existing == header;
        }

        if header.height > 1 {
            if let Some(previous) = self.recovered_headers.get(&(header.height - 1)) {
                if previous.canonical_block_commitment_hash != header.parent_block_commitment_hash {
                    return false;
                }
            } else if let Some(previous) = self.committed_headers.get(&(header.height - 1)) {
                let Ok(previous_hash) = previous.hash() else {
                    return false;
                };
                let Ok(previous_hash) = to_root_hash(&previous_hash) else {
                    return false;
                };
                if previous_hash != header.parent_block_commitment_hash {
                    return false;
                }
            }
        }

        self.recovered_headers.insert(header.height, header.clone());
        true
    }

    pub(super) fn store_aft_recovered_certified_header(
        &mut self,
        entry: &AftRecoveredCertifiedHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_certified_headers.get(&entry.header.height) {
            return existing == entry;
        }

        let certified_qc = entry.certified_quorum_certificate();
        if certified_qc.height != entry.header.height
            || certified_qc.view != entry.header.view
            || certified_qc.block_hash != entry.header.canonical_block_commitment_hash
        {
            return false;
        }

        if entry.header.height > 1 {
            if entry.certified_parent_quorum_certificate.height + 1 != entry.header.height
                || entry.certified_parent_quorum_certificate.block_hash
                    != entry.header.parent_block_commitment_hash
            {
                return false;
            }

            if let Some(previous) = self
                .recovered_certified_headers
                .get(&(entry.header.height - 1))
            {
                if previous.certified_quorum_certificate()
                    != entry.certified_parent_quorum_certificate
                    || previous.header.resulting_state_root_hash
                        != entry.certified_parent_resulting_state_root_hash
                {
                    return false;
                }
            } else if let Some(previous) = self.recovered_headers.get(&(entry.header.height - 1)) {
                if previous.synthetic_quorum_certificate()
                    != entry.certified_parent_quorum_certificate
                    || previous.resulting_state_root_hash
                        != entry.certified_parent_resulting_state_root_hash
                {
                    return false;
                }
            } else if let Some(previous) = self.committed_headers.get(&(entry.header.height - 1)) {
                let Ok(previous_hash) = previous.hash() else {
                    return false;
                };
                let Ok(previous_hash) = to_root_hash(&previous_hash) else {
                    return false;
                };
                if previous.height != entry.certified_parent_quorum_certificate.height
                    || previous.view != entry.certified_parent_quorum_certificate.view
                    || previous_hash != entry.certified_parent_quorum_certificate.block_hash
                    || previous.state_root.as_ref()
                        != entry.certified_parent_resulting_state_root_hash.as_slice()
                {
                    return false;
                }
            }
        } else if entry.certified_parent_quorum_certificate != QuorumCertificate::default()
            || entry.certified_parent_resulting_state_root_hash != [0u8; 32]
        {
            return false;
        }

        if !self.store_aft_recovered_consensus_header(&entry.header) {
            return false;
        }

        self.recovered_certified_headers
            .insert(entry.header.height, entry.clone());
        true
    }

    pub(super) fn recovered_consensus_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredConsensusHeaderEntry> {
        self.local_recovered_header_for_qc(qc)
    }

    pub(super) fn recovered_certified_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredCertifiedHeaderEntry> {
        self.local_recovered_certified_header_for_qc(qc)
    }

    pub(super) fn store_aft_recovered_restart_header(
        &mut self,
        entry: &AftRecoveredRestartHeaderEntry,
    ) -> bool {
        if let Some(existing) = self.recovered_restart_headers.get(&entry.header.height) {
            return existing == entry;
        }

        if !self.store_aft_recovered_certified_header(&entry.certified_header) {
            return false;
        }

        let certified = &entry.certified_header;
        let header = &entry.header;
        if header.height != certified.header.height
            || header.view != certified.header.view
            || header.parent_hash != certified.header.parent_block_commitment_hash
            || header.transactions_root != certified.header.transactions_root_hash.to_vec()
            || header.state_root.0 != certified.header.resulting_state_root_hash.to_vec()
            || header.parent_qc != certified.certified_parent_quorum_certificate
            || header.previous_canonical_collapse_commitment_hash
                != certified.header.previous_canonical_collapse_commitment_hash
        {
            return false;
        }

        let expected_parent_state_root = if header.height <= 1 {
            vec![0u8; 32]
        } else {
            certified
                .certified_parent_resulting_state_root_hash
                .to_vec()
        };
        if header.parent_state_root.0 != expected_parent_state_root {
            return false;
        }

        let Some(certificate) = header.canonical_order_certificate.as_ref() else {
            return false;
        };
        if certificate.height != header.height
            || certificate.ordered_transactions_root_hash != certified.header.transactions_root_hash
            || certificate.resulting_state_root_hash != certified.header.resulting_state_root_hash
            || header.timestamp_ms != certificate.bulletin_commitment.cutoff_timestamp_ms
            || header.timestamp
                != timestamp_millis_to_legacy_seconds(
                    certificate.bulletin_commitment.cutoff_timestamp_ms,
                )
        {
            return false;
        }

        self.recovered_restart_headers
            .insert(entry.header.height, entry.clone());
        true
    }

    pub(super) fn recovered_restart_header_for_quorum_certificate(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<AftRecoveredRestartHeaderEntry> {
        self.local_recovered_restart_header_for_qc(qc)
    }

    pub(super) fn retain_recovered_ancestry_cache_ranges(&mut self, keep_ranges: &[(u64, u64)]) {
        let keep_height = |height: u64| {
            keep_ranges
                .iter()
                .any(|(start, end)| *start <= height && height <= *end)
        };

        self.recovered_headers
            .retain(|height, _| keep_height(*height));
        self.recovered_certified_headers
            .retain(|height, _| keep_height(*height));
        self.recovered_restart_headers
            .retain(|height, _| keep_height(*height));
    }

    pub(super) fn header_for_quorum_certificate_hint(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<BlockHeader> {
        self.local_header_for_qc(qc).or_else(|| {
            self.local_recovered_restart_header_for_qc(qc)
                .map(|entry| entry.header)
        })
    }

    pub(super) fn drain_pending_quorum_certificates(&mut self) -> Vec<QuorumCertificate> {
        self.pending_qc_broadcasts.drain(..).collect()
    }
}
