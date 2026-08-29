// Path: crates/consensus/src/aft/guardian_majority/safety.rs

//! Implements the Safety Rules (Commit Logic) for Aft Fault Tolerance.
//!
//! This module defines the `SafetyGadget`, which enforces the 2-chain commit rule
//! used in the Aft deterministic consensus engine.
//!
//! [UPDATED] Implements Corollary 3.2 (Commit Guard).
//! Finalization is delayed by `guard_duration` to allow a Panic message (Proof of Divergence)
//! to propagate and freeze the network before a conflicting block becomes durable.

use ioi_types::app::QuorumCertificate;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// A commit that satisfies the 2-Chain rule but is waiting for the
/// Panic Propagation Window ($\Delta_{guard}$) to elapse.
#[derive(Debug, Clone)]
struct PendingCommit {
    qc: QuorumCertificate,
    can_commit_at: Instant,
}

/// The Safety Gadget tracks the chain of Quorum Certificates to determine finality.
#[derive(Debug, Clone)]
pub struct SafetyGadget {
    /// The QC for the highest block known to be committed.
    /// Used to prune the block tree.
    pub committed_qc: Option<QuorumCertificate>,

    /// The QC representing the "Lock".
    /// A validator cannot vote for a proposal that conflicts with this lock.
    pub locked_qc: Option<QuorumCertificate>,

    /// Queue of blocks waiting for the Commit Guard timer.
    pending_commits: VecDeque<PendingCommit>,

    /// Highest finality height already admitted by the canonical Agentgres
    /// runtime spine. After restart this floor is known before the native
    /// certificate that originally established it has been reconstructed.
    admitted_finality_height: u64,

    /// The guard duration ($d \cdot \Delta$).
    /// Corresponds to Corollary 3.2 in the paper.
    guard_duration: Duration,
}

impl Default for SafetyGadget {
    fn default() -> Self {
        Self {
            committed_qc: None,
            locked_qc: None,
            pending_commits: VecDeque::new(),
            admitted_finality_height: 0,
            // Default 500ms guard (Typical network latency bounds)
            guard_duration: Duration::from_millis(500),
        }
    }
}

impl SafetyGadget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_guard_duration(mut self, duration: Duration) -> Self {
        self.guard_duration = duration;
        self
    }

    /// Updates the safety state based on a newly verified QC.
    ///
    /// Instead of returning the committed height immediately, this method queues
    /// the commit if the rule is met. Finality is extracted by polling
    /// `next_ready_commit` and then explicitly consuming it with
    /// `accept_next_ready_commit` once any external gating conditions have
    /// passed.
    ///
    /// Returns `true` if a new block was queued for commit.
    pub fn update(&mut self, qc_high: &QuorumCertificate, qc_parent: &QuorumCertificate) -> bool {
        // 1. Update Lock (Liveness)
        // We lock immediately upon seeing the QC to prevent voting on forks.
        if let Some(current_lock) = &self.locked_qc {
            if qc_parent.view > current_lock.view {
                self.locked_qc = Some(qc_parent.clone());
            }
        } else {
            self.locked_qc = Some(qc_parent.clone());
        }

        // 2. Check 2-Chain Commit Rule (Invariant 2.6).
        //
        // AFT views are scoped to a block height: the ordinary successful
        // path is view zero at every height, while a timeout raises the view
        // only for that height.  Direct ancestry is therefore expressed by
        // consecutive *heights*, not by numerically consecutive views.  The
        // caller supplies the parent certificate embedded in the locally
        // verified child header, so this height check completes the direct
        // parent relation without silently requiring every new height to
        // suffer a view change before it can finalize.
        if qc_high.height == qc_parent.height.saturating_add(1) {
            let commit_height = qc_parent.height;

            // Certificates and proposals are delivered independently. A
            // follower can therefore learn H+2 before H+1. Keep every
            // authenticated candidate above the Agentgres-admitted floor and
            // order the queue by height; a later predecessor must not be
            // discarded merely because a higher candidate arrived first.
            let already_committed = self
                .committed_qc
                .as_ref()
                .map_or(self.admitted_finality_height, |qc| {
                    qc.height.max(self.admitted_finality_height)
                });
            if commit_height <= already_committed
                || self
                    .pending_commits
                    .iter()
                    .any(|pending| pending.qc.height == commit_height)
            {
                return false;
            }

            let pending = PendingCommit {
                qc: qc_parent.clone(),
                can_commit_at: Instant::now() + self.guard_duration,
            };
            let insert_at = self
                .pending_commits
                .iter()
                .position(|existing| existing.qc.height > commit_height)
                .unwrap_or(self.pending_commits.len());
            self.pending_commits.insert(insert_at, pending);
            return true;
        }

        false
    }

    /// Returns the next ready commit without consuming it.
    ///
    /// The caller can use this to gate finalization on additional protocol
    /// conditions, such as the presence of a canonical collapse object.
    pub fn next_ready_commit(&self) -> Option<QuorumCertificate> {
        let now = Instant::now();
        let admitted_height = self
            .committed_qc
            .as_ref()
            .map_or(self.admitted_finality_height, |qc| {
                qc.height.max(self.admitted_finality_height)
            });
        self.pending_commits.front().and_then(|pending| {
            (pending.qc.height == admitted_height.saturating_add(1) && now >= pending.can_commit_at)
                .then(|| pending.qc.clone())
        })
    }

    /// Consumes the next ready commit and records it as committed.
    ///
    /// Callers should only invoke this after any external gating conditions have
    /// passed for the ready commit returned by `next_ready_commit`.
    pub fn accept_next_ready_commit(&mut self) -> Option<QuorumCertificate> {
        let now = Instant::now();
        let Some(pending) = self.pending_commits.front() else {
            return None;
        };
        let admitted_height = self
            .committed_qc
            .as_ref()
            .map_or(self.admitted_finality_height, |qc| {
                qc.height.max(self.admitted_finality_height)
            });
        if pending.qc.height != admitted_height.saturating_add(1) || now < pending.can_commit_at {
            return None;
        }

        let committed = self.pending_commits.pop_front()?.qc;
        self.admitted_finality_height = committed.height;
        self.committed_qc = Some(committed.clone());
        Some(committed)
    }

    /// Advances the floor from the canonical Agentgres-admitted runtime head.
    /// Pending certificates at or below the floor are stale evidence and can
    /// never be emitted again after restart or a profile transition.
    pub fn observe_admitted_finality_height(&mut self, height: u64) -> bool {
        if height < self.admitted_finality_height {
            return false;
        }
        self.admitted_finality_height = height;
        self.pending_commits
            .retain(|pending| pending.qc.height > height);
        true
    }

    /// Checks if it is safe to vote for a proposal.
    pub fn safe_to_vote(&self, proposal_view: u64, parent_view: u64) -> bool {
        if let Some(locked) = &self.locked_qc {
            // Liveness condition: view is higher than lock
            if proposal_view > locked.view {
                return true;
            }
            // Safety condition: proposal extends the locked block
            if parent_view >= locked.view {
                return true;
            }
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qc(height: u64, byte: u8) -> QuorumCertificate {
        QuorumCertificate {
            height,
            view: 0,
            block_hash: [byte; 32],
            signatures: Vec::new(),
            aggregated_signature: Vec::new(),
            signers_bitfield: Vec::new(),
        }
    }

    #[test]
    fn reordered_candidates_wait_for_and_emit_the_missing_predecessor() {
        let mut gadget = SafetyGadget::new().with_guard_duration(Duration::ZERO);
        let one = qc(1, 1);
        let two = qc(2, 2);
        let three = qc(3, 3);

        assert!(gadget.update(&three, &two));
        assert!(gadget.next_ready_commit().is_none());
        assert!(gadget.update(&two, &one));
        assert_eq!(gadget.accept_next_ready_commit(), Some(one));
        assert_eq!(gadget.accept_next_ready_commit(), Some(two));
    }

    #[test]
    fn agentgres_floor_prevents_restart_reemission() {
        let mut gadget = SafetyGadget::new().with_guard_duration(Duration::ZERO);
        assert!(gadget.observe_admitted_finality_height(100));
        let hundred = qc(100, 100);
        let hundred_one = qc(101, 101);
        let hundred_two = qc(102, 102);

        assert!(!gadget.update(&hundred_one, &hundred));
        assert!(gadget.update(&hundred_two, &hundred_one));
        assert_eq!(gadget.accept_next_ready_commit(), Some(hundred_one));
    }
}
