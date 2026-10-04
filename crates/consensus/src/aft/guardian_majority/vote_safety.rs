// Path: crates/consensus/src/aft/guardian_majority/vote_safety.rs
//! The vote rules THIS node applies to its own votes and proposals (P7, build Ruling 12 and
//! its four amendments). They close CONFORMANCE gaps: canon already refuses a second commit per
//! height locally (`safety.rs`, the commit queue) and requires authenticated parent QCs, so the
//! trunk's gaps never showed two authoritative commits; they left the cross-view argument
//! (timeout votes carry the voter's highest QC, the next leader extends the TC's highest QC, and
//! the lock rule) unenforced in code.
//!
//! - **The lock rule** ([`SafetyGadget::safe_to_vote`]): this node votes only for a proposal
//!   whose parent certificate ranks at or above its lock in the LEXICOGRAPHIC (height, view)
//!   order of [`qc_rank`] (equal rank only for the locked block itself). It never compares bare
//!   views across heights: views are height-scoped, as `safety.rs`'s height-scoped 2-chain is.
//! - **The next leader extends the TC's highest QC** ([`extends`]): a proposal in a non-zero
//!   view carries the timeout certificate that opened it; its parent certificate must rank at or
//!   above the highest QC any of that certificate's timeout votes carries. The normative PQ
//!   timeout vote carries the voter's highest and locked QCs (`AftTimeoutVoteV1`); the legacy
//!   `ViewChangeVote` signs only (height, view) and carries none, so the check applies to the
//!   scoped certificate only.
//! - **No vote in a view this node has timed out of** ([`GuardianMajorityEngine::superseding_view`]):
//!   HYGIENE, not the safety argument (a validator can vote in v and THEN time out, so a view-v
//!   QC and a view-(v+1) TC can both form without anyone breaking it). It forbids exactly the
//!   votes NET's S-debug run observed. It is our ADOPTED rule (the spec is silent).
//! - **No lower-view proposal after a timeout certificate**
//!   ([`GuardianMajorityEngine::superseding_tc_view`]): once a TC for a later view at a height
//!   has formed here, a proposal of an earlier view at that height is refused before it is
//!   executed or persisted, unless this node already accepted that exact block earlier.
//! - **One block per slot for this node** (`local_votes`): a second block in one (height, view)
//!   is refused; an exact replay of an admitted vote is let through.
//!
//! Cross-view votes by OTHER validators are never refused here: after a failed view a validator
//! must be able to vote for the next leader's proposal at the same height (NET's warning; canon's
//! same-view-only equivocation check in `handle_vote` stays as it is).

use super::safety::qc_rank;
use super::*;

/// Whether `parent` ranks at or above `bound` in the (height, view) order, equal rank only for
/// the same block: the parent extends the bound's block directly, or is justified by a newer
/// certificate.
pub(super) fn extends(parent: &QuorumCertificate, bound: &QuorumCertificate) -> bool {
    qc_rank(parent) > qc_rank(bound)
        || (qc_rank(parent) == qc_rank(bound) && parent.block_hash == bound.block_hash)
}

/// The highest QC (by [`qc_rank`]) the timeout votes of a scoped certificate carry.
pub(super) fn timeout_certificate_high_qc(
    certificate: &AftTimeoutCertificateV1,
) -> Option<&QuorumCertificate> {
    certificate
        .votes
        .iter()
        .map(|vote| &vote.highest_qc)
        .max_by_key(|qc| qc_rank(qc))
}

impl GuardianMajorityEngine {
    /// The latest view past `view` at `height` that this node has moved to, if any: it emitted a
    /// timeout vote for a later view at that height (it timed out of `view`), or a timeout
    /// certificate for a later view at that height formed here.
    pub(super) fn superseding_view(&self, height: u64, view: u64) -> Option<u64> {
        let timed_out = self
            .timeout_votes_sent
            .keys()
            .filter(|(h, v)| *h == height && *v > view)
            .map(|(_, v)| *v);
        timed_out
            .chain(self.superseding_tc_view(height, view))
            .max()
    }

    /// The latest view past `view` at `height` for which a timeout certificate formed here.
    pub(super) fn superseding_tc_view(&self, height: u64, view: u64) -> Option<u64> {
        self.tc_formed
            .iter()
            .filter(|(h, v)| *h == height && *v > view)
            .map(|(_, v)| *v)
            .max()
    }

    /// Refuses a proposal of an earlier view at a height where a timeout certificate for a later
    /// view has formed, unless this node already accepted that exact block (a later enrichment
    /// of an accepted block is not a new proposal).
    pub(super) fn refuse_stale_view_proposal(
        &self,
        header: &BlockHeader,
        block_hash: &[u8; 32],
    ) -> Result<(), ConsensusError> {
        let Some(tc_view) = self.superseding_tc_view(header.height, header.view) else {
            return Ok(());
        };
        let already_accepted = self
            .seen_headers
            .get(&(header.height, header.view))
            .is_some_and(|headers| headers.contains_key(block_hash));
        if already_accepted {
            return Ok(());
        }
        Err(ConsensusError::BlockVerificationFailed(format!(
            "stale proposal at H={} V={}: a timeout certificate for view {} has formed at this height",
            header.height, header.view, tc_view
        )))
    }

    /// Refuses a non-zero-view proposal whose parent certificate does not extend the highest QC
    /// its scoped timeout certificate carries.
    pub(super) fn refuse_proposal_below_tc_high_qc(
        header: &BlockHeader,
        certificate: &AftTimeoutCertificateV1,
    ) -> Result<(), ConsensusError> {
        if let Some(high) = timeout_certificate_high_qc(certificate) {
            if !extends(&header.parent_qc, high) {
                return Err(ConsensusError::BlockVerificationFailed(format!(
                    "proposal at H={} V={} does not extend its timeout certificate's highest QC: parent (H={} V={}) is below (H={} V={})",
                    header.height,
                    header.view,
                    header.parent_qc.height,
                    header.parent_qc.view,
                    high.height,
                    high.view
                )));
            }
        }
        Ok(())
    }

    /// Admits THIS node's own vote for `header`, or refuses it. Every local vote path calls this
    /// before signing. On admission the vote is recorded for its slot.
    pub(super) async fn admit_own_vote(
        &mut self,
        header: &BlockHeader,
    ) -> Result<(), ConsensusError> {
        let (height, view) = (header.height, header.view);
        let block_hash = to_root_hash(
            &header
                .hash()
                .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?,
        )
        .map_err(|_| ConsensusError::BlockVerificationFailed("block hash length".into()))?;
        if let Some(prior) = self.local_votes.get(&(height, view)) {
            if *prior == block_hash {
                // An exact replay of a vote already admitted in this slot.
                return Ok(());
            }
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "own vote refused: this node already voted for another block at H={height} V={view}"
            )));
        }
        if self.fallback_starts.contains_key(&height) {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "own vote refused: the optimistic path at H={height} is fenced by a fallback start"
            )));
        }
        let mut superseded = self.superseding_view(height, view);
        if self.pacemaker_height == height {
            let current = self.pacemaker.lock().await.current_view;
            if current > view {
                superseded = superseded.max(Some(current));
            }
        }
        if let Some(later) = superseded {
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "own vote refused: this node has moved past view {view} at H={height} (to view {later})"
            )));
        }
        if height > 1 && !self.safety.safe_to_vote(&header.parent_qc) {
            let lock = self.safety.locked_qc.clone().unwrap_or_default();
            return Err(ConsensusError::BlockVerificationFailed(format!(
                "own vote refused by the lock rule: parent (H={} V={}) is below the lock (H={} V={})",
                header.parent_qc.height, header.parent_qc.view, lock.height, lock.view
            )));
        }
        self.local_votes.insert((height, view), block_hash);
        Ok(())
    }
}

impl GuardianMajorityEngine {
    /// Verifies `qc` as a certificate for the block it names, against the validator membership
    /// read from `view` (the anchored state of the certified block's parent, or an earlier
    /// ancestor whose sets cover `qc.height`). P7 G1: sync verifies every synced block's parent
    /// certificate before applying it, and a replacement block's own certificate before replacing.
    ///
    /// The membership is taken from the view itself, never from the engine's bounded cache, so a
    /// node catching up far behind its live height still authenticates against the membership
    /// that was in force. The genesis sentinel (height 0) needs no signatures. Classic-BFT accepts
    /// an authenticated 2f+1 certificate or a separately verified async-parent proof; the other
    /// modes use their own QC rule (and Asymptote its collapse backing).
    pub(super) async fn verify_certificate_against_view(
        &mut self,
        qc: &QuorumCertificate,
        view: &dyn AnchoredStateView,
    ) -> Result<(), ConsensusError> {
        if qc.height == 0 {
            return if *qc == QuorumCertificate::default() {
                Ok(())
            } else {
                Err(ConsensusError::BlockVerificationFailed(
                    "a height-zero certificate must be the canonical genesis sentinel".into(),
                ))
            };
        }
        let encoded = view
            .get(VALIDATOR_SET_KEY)
            .await
            .map_err(|e| ConsensusError::StateAccess(StateError::Backend(e.to_string())))?
            .ok_or(ConsensusError::StateAccess(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&encoded).map_err(|e| {
            ConsensusError::BlockVerificationFailed(format!("VS decode failed: {e}"))
        })?;
        let set = effective_set_for_height(&sets, qc.height).clone();
        self.hydrate_effective_validator_keys(view, &set).await?;
        match self.safety_mode {
            AftSafetyMode::ClassicBft => {
                if self.has_async_parent_proof(qc) {
                    return Ok(());
                }
                let threshold = if set
                    .validators
                    .iter()
                    .all(|validator| validator.consensus_key.suite == SignatureSuite::ML_DSA_44)
                {
                    authenticated_quorum::pq_optimistic_quorum_geometry(&set)?.q as usize
                } else {
                    self.quorum_count_threshold(set.validators.len())
                };
                authenticated_quorum::verify_quorum_certificate(
                    qc,
                    &set,
                    &self.key_registry,
                    self.safety_mode,
                    threshold,
                )
                .map(|_| ())
            }
            AftSafetyMode::Asymptote => {
                self.verify_qc(qc, &sets)?;
                if self.quorum_certificate_is_collapse_backed(qc, view).await? {
                    Ok(())
                } else {
                    Err(ConsensusError::BlockVerificationFailed(format!(
                        "certificate for height {} is not backed by a canonical collapse object",
                        qc.height
                    )))
                }
            }
            _ => self.verify_qc(qc, &sets),
        }
    }
}
