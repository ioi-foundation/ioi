// Path: crates/state/src/tree/iavl/indices.rs

use super::node::IAVLNode;
use ioi_types::app::RootHash;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub(super) struct Indices {
    pub(super) versions_by_height: BTreeMap<u64, RootHash>,
    pub(super) root_refcount: HashMap<RootHash, u32>,
    pub(super) roots: HashMap<RootHash, Option<Arc<IAVLNode>>>,
}

impl Indices {
    pub(super) fn decrement_refcount(&mut self, root_hash: RootHash) {
        if let Some(c) = self.root_refcount.get_mut(&root_hash) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.root_refcount.remove(&root_hash);
                self.roots.remove(&root_hash);
            }
        }
    }
}