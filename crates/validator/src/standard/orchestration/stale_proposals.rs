// Path: crates/validator/src/standard/orchestration/stale_proposals.rs
//! Stale-view proposals kept for a certificate that arrives late (P7 round 3, review round 2's
//! N1).
//!
//! The engine refuses an AUTHENTIC proposal of an earlier view at a height where a timeout
//! certificate for a later view has formed (`ConsensusError::StaleViewProposal`), unless a quorum
//! certificate it holds already certifies the block. Votes cast before the timeouts can still
//! certify that block AFTER the refusal (NET's S-debug order), and the next height must then
//! extend it. Nothing else redelivers it: its producer rebroadcasts only while the block is its
//! own unadmitted tip (and may have crashed), and sync serves only admitted blocks. So the gossip
//! path keeps each block refused this way and offers it again, through the same gossip path, once
//! the engine holds a certificate for it (`ConsensusEngine::holds_certificate_for`).
//!
//! Bounds: only the engine's typed stale-view refusal is kept, which the engine returns only
//! after the slot leader's signature and the proposal's certificates verify, so a peer cannot
//! fill the store with blocks it made up. One block per slot (height, view): the engine's
//! divergence check refuses any second distinct header it sees at a slot before this. At most [`STALE_PROPOSAL_CAPACITY`] blocks; when full, a new one is not kept (the
//! earliest refusals are the ones a late certificate is for). A block at or below the
//! Agentgres-admitted height can never be applied and is dropped.

use ioi_types::app::{Block, ChainTransaction};
use libp2p::PeerId;
use std::collections::BTreeMap;

/// The most stale-view proposals kept at once. The gossip path verifies proposals only at the
/// executed height and the one above it, and each kept block is one superseded view there.
pub(crate) const STALE_PROPOSAL_CAPACITY: usize = 16;

/// A stale-view proposal kept for a late certificate, with where it came from.
#[derive(Debug, Clone)]
pub(crate) struct KeptProposal {
    pub(crate) block: Block<ChainTransaction>,
    pub(crate) block_hash: [u8; 32],
    pub(crate) mirror_id: u8,
    pub(crate) source_peer: PeerId,
}

/// The kept stale-view proposals, by slot (height, view).
#[derive(Debug, Default)]
pub(crate) struct StaleProposalStore {
    kept: BTreeMap<(u64, u64), KeptProposal>,
}

impl StaleProposalStore {
    /// Keeps `proposal`, refused as a stale-view proposal, unless its slot already holds one, the
    /// store is full, or it is at or below `admitted_height`. Returns whether it was kept.
    pub(crate) fn keep(&mut self, proposal: KeptProposal, admitted_height: u64) -> bool {
        self.prune_at_or_below(admitted_height);
        let slot = (proposal.block.header.height, proposal.block.header.view);
        if slot.0 <= admitted_height
            || self.kept.contains_key(&slot)
            || self.kept.len() >= STALE_PROPOSAL_CAPACITY
        {
            return false;
        }
        self.kept.insert(slot, proposal);
        true
    }

    /// Removes and returns every kept proposal that `certified(height, block_hash)` reports a
    /// held certificate for, lowest slot first.
    pub(crate) fn take_certified(
        &mut self,
        certified: impl Fn(u64, &[u8; 32]) -> bool,
    ) -> Vec<KeptProposal> {
        let slots: Vec<(u64, u64)> = self
            .kept
            .iter()
            .filter(|(slot, kept)| certified(slot.0, &kept.block_hash))
            .map(|(slot, _)| *slot)
            .collect();
        slots
            .into_iter()
            .filter_map(|slot| self.kept.remove(&slot))
            .collect()
    }

    /// Drops every kept proposal at or below `admitted_height`: it can never be applied.
    pub(crate) fn prune_at_or_below(&mut self, admitted_height: u64) {
        self.kept.retain(|(height, _), _| *height > admitted_height);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.kept.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard::orchestration::sync_harness::{harness_block, harness_hash};

    fn kept(height: u64, view: u64, salt: u8) -> KeptProposal {
        let mut block = harness_block([height as u8; 32], height, salt);
        block.header.view = view;
        KeptProposal {
            block_hash: harness_hash(&block),
            block,
            mirror_id: 0,
            source_peer: PeerId::random(),
        }
    }

    #[test]
    fn one_proposal_per_slot_is_kept_and_the_first_wins() {
        let mut store = StaleProposalStore::default();
        let first = kept(5, 0, 1);
        let first_hash = first.block_hash;
        assert!(store.keep(first, 3));
        assert!(
            !store.keep(kept(5, 0, 2), 3),
            "a second block at one slot was kept"
        );
        assert!(store.keep(kept(5, 1, 3), 3), "another view is another slot");
        let taken = store.take_certified(|_, hash| *hash == first_hash);
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].block_hash, first_hash);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn only_certified_proposals_are_taken() {
        let mut store = StaleProposalStore::default();
        assert!(store.keep(kept(5, 0, 1), 3));
        assert!(store.take_certified(|_, _| false).is_empty());
        assert_eq!(store.len(), 1, "an uncertified proposal was dropped");
        assert_eq!(store.take_certified(|height, _| height == 5).len(), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn the_store_is_bounded_and_keeps_the_earliest() {
        let mut store = StaleProposalStore::default();
        for view in 0..STALE_PROPOSAL_CAPACITY as u64 {
            assert!(store.keep(kept(5, view, 1), 3));
        }
        assert!(!store.keep(kept(5, 99, 1), 3), "the bound was exceeded");
        assert_eq!(store.len(), STALE_PROPOSAL_CAPACITY);
        assert_eq!(
            store
                .take_certified(|_, _| true)
                .first()
                .map(|kept| kept.block.header.view),
            Some(0),
            "the earliest refusal was evicted"
        );
    }

    #[test]
    fn a_proposal_at_or_below_the_admitted_height_is_never_kept_and_is_pruned() {
        let mut store = StaleProposalStore::default();
        assert!(
            !store.keep(kept(3, 0, 1), 3),
            "a block at the admitted height was kept"
        );
        assert!(store.keep(kept(4, 0, 1), 3));
        assert!(store.keep(kept(5, 0, 1), 3));
        assert!(
            store.keep(kept(6, 0, 1), 4),
            "keeping prunes height 4 first"
        );
        assert_eq!(store.len(), 2);
        store.prune_at_or_below(6);
        assert!(store.is_empty());
    }
}
