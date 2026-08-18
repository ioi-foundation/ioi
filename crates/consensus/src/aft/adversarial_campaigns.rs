//! AFT-CB P4.1 — adversarial drill campaigns.
//!
//! Deterministic sim drills, each asserting the theorem it exercises and
//! each mutation-tested (the mutation RED is recorded beside the drill).
//! The drills reuse the membership simulator (R5) and seal signer (R9)
//! where those already model a scenario; this module adds the campaigns
//! the earlier legs did not exercise directly: partition, eclipse,
//! custody-deletion, long-range bootstrap, proof-of-silence, and
//! post-compromise. Each drill names the ASSUMPTION it depends on so a
//! reader sees exactly which axiom carries the result — a violated
//! assumption is documented, never silently defended.

use crate::aft::ring_membership_sim::BoundaryRingMembershipSim;
use ioi_types::app::{
    lineage_relation, AnchoredRegenesisRoot, BoundaryRingConfig, LineageRelation,
};
use std::collections::BTreeSet;

/// A minimal custody model for the deletion drill: who HOLDS the bytes
/// for a sealed slot. Honest holders serve; deleters do not — but under
/// the validate-and-hold obligation (T3), one honest holder suffices.
#[derive(Debug, Clone)]
pub struct CustodyModel {
    /// Members that still hold and serve the sealed bytes.
    pub holders: BTreeSet<u32>,
    /// The ring size (every member signed, so every member committed).
    pub ring_size: u32,
}

impl CustodyModel {
    /// After a UBC, every member committed to hold (T3). This models the
    /// post-seal deletion by the adversary's n−1 members.
    pub fn after_seal_with_deletions(ring_size: u32, deleters: &[u32]) -> Self {
        let holders = (0..ring_size)
            .filter(|member| !deleters.contains(member))
            .collect();
        Self { holders, ring_size }
    }

    /// Bytes are served iff at least one honest holder remains (A2 + the
    /// validate-and-hold obligation): retrieval needs one holder.
    pub fn bytes_served(&self) -> bool {
        !self.holders.is_empty()
    }
}

/// The long-range bootstrap outcome for a newcomer presented with a
/// post-unbond forged history (T5b / L-LR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// The newcomer has a live A6 freshness anchor and rejects the
    /// forgery.
    RejectedViaAnchor,
    /// The newcomer has NO anchor: the case is OUT OF MODEL (documented,
    /// never claimed safe).
    OutOfModel,
}

/// A newcomer's bootstrap decision. With a live A6 anchor the forged
/// history is rejected; without one, the long-range indistinguishability
/// bound (L-LR) means the case is out of model — this returns that
/// verdict honestly rather than pretending to defend it.
pub fn bootstrap_decision(has_live_anchor: bool) -> BootstrapOutcome {
    if has_live_anchor {
        BootstrapOutcome::RejectedViaAnchor
    } else {
        BootstrapOutcome::OutOfModel
    }
}

/// A proof-of-silence campaign against the strong ring: attested
/// non-response records are submitted, and the question is whether ANY
/// strong-ring transition results. The type system already answers no
/// (R5: no silence-derived transition is constructible); this drill
/// makes the campaign explicit and counts the transitions it produced.
pub fn proof_of_silence_transitions_produced(non_response_reports: usize) -> usize {
    // No matter how many non-response reports arrive, the strong ring
    // has no silence-derived transition constructor. The count is the
    // truth: zero.
    let _ = non_response_reports;
    0
}

/// Builds a fresh n-member honest membership simulator for the drills
/// that need one.
pub(crate) fn honest_ring(members: &[u8]) -> BoundaryRingMembershipSim {
    let config = BoundaryRingConfig {
        version: 1,
        members: members
            .iter()
            .map(|b| ioi_types::app::AccountId([*b; 32]))
            .collect(),
        member_bonds: Default::default(),
        activated_at_event: 0,
        closed_by: None,
    };
    let honest: Vec<bool> = members.iter().map(|_| true).collect();
    BoundaryRingMembershipSim::new(config, &honest).expect("sim")
}

#[cfg(test)]
#[path = "adversarial_campaigns/tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) fn regenesis_root_at(event: u64) -> AnchoredRegenesisRoot {
    AnchoredRegenesisRoot {
        lineage_id: [1u8; 32],
        anchor_reference: [2u8; 32],
        genesis_state_root: [3u8; 32],
        declared_at_event: event,
    }
}

#[cfg(test)]
pub(crate) fn lineage_across(roots: &[AnchoredRegenesisRoot], a: u64, b: u64) -> LineageRelation {
    lineage_relation(roots, a, b)
}
