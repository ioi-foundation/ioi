// Path: crates/consensus/src/admft/safety.rs

//! Implements the Safety Rules (Commit Logic) for LFT.
//!
//! This module defines the `SafetyGadget`, which enforces the 2-chain commit rule
//! used in the A-DMFT consensus engine.
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
    /// the commit if the rule is met. Finality is extracted via `drain_ready_commits`.
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

        // 2. Check 2-Chain Commit Rule (Invariant 2.6)
        // If Child references Parent directly (consecutive view).
        if qc_high.view == qc_parent.view + 1 {
            let commit_height = qc_parent.height;
            
            // Check against currently committed to avoid re-queuing
            let already_committed = self.committed_qc.as_ref().map_or(0, |qc| qc.height);
            let pending_max = self.pending_commits.back().map_or(0, |p| p.qc.height);
            let max_seen = std::cmp::max(already_committed, pending_max);

            if commit_height > max_seen {
                // Queue the commit. This enforces the "No-Panic Window".
                self.pending_commits.push_back(PendingCommit {
                    qc: qc_parent.clone(),
                    can_commit_at: Instant::now() + self.guard_duration,
                });
                return true;
            }
        }
        
        false
    }

    /// Checks if any pending commits have passed the guard duration.
    ///
    /// This should be called by the consensus loop on every tick.
    /// If a Panic occurs, the engine should stop calling this method,
    /// effectively orphaning the pending commits (Safety Condition).
    pub fn drain_ready_commits(&mut self) -> Option<u64> {
        let now = Instant::now();
        let mut highest_ready: Option<QuorumCertificate> = None;

        // Drain all commits where T_now >= T_queued + Delta_guard
        while let Some(pending) = self.pending_commits.front() {
            if now >= pending.can_commit_at {
                let p = self.pending_commits.pop_front().unwrap();
                highest_ready = Some(p.qc);
            } else {
                break;
            }
        }

        if let Some(new_commit) = highest_ready {
            self.committed_qc = Some(new_commit.clone());
            return Some(new_commit.height);
        }

        None
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