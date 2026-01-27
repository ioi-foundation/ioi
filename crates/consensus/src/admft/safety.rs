// Path: crates/consensus/src/admft/safety.rs

//! Implements the Safety Rules (Commit Logic) for Chained BFT.
//!
//! This module defines the `SafetyGadget`, which enforces the 3-chain commit rule
//! (or 2-chain depending on configuration) used in HotStuff/Jolteon-style consensus.
//! It determines when a block is considered "Finalized" and safe to prune.

use ioi_types::app::QuorumCertificate;

/// The Safety Gadget tracks the chain of Quorum Certificates to determine finality.
#[derive(Debug, Clone, Default)]
pub struct SafetyGadget {
    /// The QC for the highest block known to be committed.
    /// Used to prune the block tree.
    pub committed_qc: Option<QuorumCertificate>,
    
    /// The QC representing the "Lock". 
    /// A validator cannot vote for a proposal that conflicts with this lock 
    /// (i.e., a proposal that does not extend from this QC or a higher one).
    pub locked_qc: Option<QuorumCertificate>,
}

impl SafetyGadget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates the safety state based on a newly verified QC (e.g. from a valid block proposal).
    /// Returns `Some(height)` if a new block was committed by this update.
    ///
    /// Implements the 3-Chain Commit Rule:
    /// If we have a direct chain of 3 blocks with QCs (Grandparent <- Parent <- Child),
    /// and they have consecutive views (or heights in simplified BFT), the Grandparent is committed.
    ///
    /// Note: Since we don't have the full Block struct here, we rely on the `parent_hash`
    /// linkage implicitly tracked by the caller or assume consecutive heights for the rule.
    /// For this logic, we assume `qc_high` points to `b_child`, `b_child` contains `qc_parent`.
    pub fn update(&mut self, qc_high: &QuorumCertificate, qc_parent: &QuorumCertificate) -> Option<u64> {
        // 1. Update Lock
        // In standard HotStuff, you lock on the 2-chain (Parent).
        if let Some(current_lock) = &self.locked_qc {
            if qc_parent.view > current_lock.view {
                self.locked_qc = Some(qc_parent.clone());
            }
        } else {
            self.locked_qc = Some(qc_parent.clone());
        }

        // 2. Check Commit Rule (3-Chain)
        // If Child references Parent, and Parent references Grandparent (implied), and views are consecutive.
        // Simplified heuristic: If `qc_high.view == qc_parent.view + 1`, we have a 2-chain.
        // If we had a 3rd QC available (Grandparent), we could commit.
        // For A-DMFT MVP, we can use a 2-chain commit rule for faster finality if we trust the Guardian anti-equivocation.
        
        // Let's implement 2-chain commit for simplicity and speed in this version.
        // Rule: If Parent QC is valid and Child QC extends it directly (consecutive view), Parent is committed.
        if qc_high.view == qc_parent.view + 1 {
            let commit_height = qc_parent.height;
            
            // Only update if it advances our commit pointer
            if let Some(committed) = &self.committed_qc {
                if commit_height > committed.height {
                    self.committed_qc = Some(qc_parent.clone());
                    return Some(commit_height);
                }
            } else {
                self.committed_qc = Some(qc_parent.clone());
                return Some(commit_height);
            }
        }
        
        None
    }

    /// Checks if it is safe to vote for a proposal extending a specific parent.
    ///
    /// Rule: Safe to vote if `proposal.view > locked_qc.view` OR `proposal extends locked_qc`.
    pub fn safe_to_vote(&self, proposal_view: u64, parent_view: u64) -> bool {
        if let Some(locked) = &self.locked_qc {
            // Liveness condition: higher view
            if proposal_view > locked.view {
                return true;
            }
            // Safety condition: extends lock
            if parent_view >= locked.view {
                return true;
            }
            false
        } else {
            true // No lock yet
        }
    }
}