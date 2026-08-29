// Path: crates/state/src/tree/iavl/indices.rs

use super::node::IAVLNode;
use ioi_types::app::{RootHash, StateRoot};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub(super) struct Indices {
    pub(super) versions_by_height: BTreeMap<u64, RootHash>,
    pub(super) root_refcount: HashMap<RootHash, u32>,
    pub(super) roots: HashMap<RootHash, Option<Arc<IAVLNode>>>,
    /// Exact reverse index for the public `StateRoot::to_anchor` identity.
    /// A 32-byte IAVL root is still SHA-256 hashed when exported as a
    /// StateAnchor, so treating the anchor bytes as the root loses historical
    /// lookup as soon as the live root advances.
    pub(super) roots_by_anchor: HashMap<[u8; 32], RootHash>,
}

impl Indices {
    pub(super) fn index_root_anchor(&mut self, root_hash: RootHash) {
        if let Ok(anchor) = StateRoot(root_hash.to_vec()).to_anchor() {
            self.roots_by_anchor.insert(anchor.0, root_hash);
        }
    }

    pub(super) fn decrement_refcount(&mut self, root_hash: RootHash) {
        if let Some(c) = self.root_refcount.get_mut(&root_hash) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.root_refcount.remove(&root_hash);
                self.roots.remove(&root_hash);
                if let Ok(anchor) = StateRoot(root_hash.to_vec()).to_anchor() {
                    self.roots_by_anchor.remove(&anchor.0);
                }
            }
        }
    }
}
