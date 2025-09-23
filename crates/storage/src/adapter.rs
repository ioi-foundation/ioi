// Path: crates/storage/src/adapter.rs

// Glue from your StateManager trees to NodeStore::commit_block().
// Provides a DeltaAccumulator and a thin commit_and_persist() wrapper.

use ahash::{AHashMap, AHashSet};
use depin_sdk_api::storage::{
    CommitInput, NodeHash as StoreNodeHash, NodeStore, RootHash as StoreRootHash, StorageError,
};

// FIX: Add Debug and Clone traits.
#[derive(Default, Debug, Clone)]
pub struct DeltaAccumulator {
    /// Set of nodes referenced at this height (CHANGES; unique per height)
    touched: AHashSet<[u8; 32]>,
    /// Bytes for nodes first seen in the *tip epoch* (store will dedup, but we pass bytes)
    new_nodes: AHashMap<[u8; 32], Vec<u8>>,
}

impl DeltaAccumulator {
    #[inline]
    pub fn record_touch(&mut self, node_hash: [u8; 32]) {
        self.touched.insert(node_hash);
    }
    #[inline]
    pub fn record_new(&mut self, node_hash: [u8; 32], bytes: Vec<u8>) {
        self.touched.insert(node_hash);
        // If the node already exists in-epoch, NodeStore will dedup;
        // keeping the first bytes here is OK (idempotent).
        self.new_nodes.entry(node_hash).or_insert(bytes);
    }

    pub fn build<'a>(&'a self) -> (Vec<StoreNodeHash>, Vec<(StoreNodeHash, &'a [u8])>) {
        // CHANGES: unique_nodes_for_height
        let mut uniq: Vec<StoreNodeHash> = self.touched.iter().map(|h| StoreNodeHash(*h)).collect();
        // (optional) stable order
        uniq.sort_by(|a, b| a.0.cmp(&b.0));

        // NEW nodes: node bytes (borrow as &[u8])
        let mut news: Vec<(StoreNodeHash, &'a [u8])> = Vec::with_capacity(self.new_nodes.len());
        for (h, bytes) in &self.new_nodes {
            news.push((StoreNodeHash(*h), bytes.as_slice()));
        }
        (uniq, news)
    }

    pub fn clear(&mut self) {
        self.touched.clear();
        self.new_nodes.clear();
    }
}

/// Call this *inside* your StateManager::commit_version(height) flow,
/// after the in-memory tree has its final root at `height`.
///
/// - `root_hash32` is the 32-byte state root
/// - `delta` is the per-height accumulator you just filled
pub fn commit_and_persist<S: NodeStore + ?Sized>(
    store: &S,
    height: u64,
    root_hash32: [u8; 32],
    delta: &DeltaAccumulator,
) -> Result<(), StorageError> {
    let (unique, newv) = delta.build();
    let input = CommitInput {
        height,
        root: StoreRootHash(root_hash32),
        unique_nodes_for_height: &unique,
        new_nodes: &newv,
    };
    store.commit_block(&input)
}
