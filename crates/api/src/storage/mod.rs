// Path: crates/api/src/storage.rs

//! API for a durable, epoch-sharded, content-addressed node store.

use thiserror::Error;

/// A type alias for an epoch identifier, typically derived from block height.
pub type Epoch = u64;
/// A type alias for a block height.
pub type Height = u64;

/// A 32-byte state root hash, representing a commitment to a specific version of the state tree.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootHash(pub [u8; 32]);

impl std::fmt::Debug for RootHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RootHash({})", hex::encode(self.0))
    }
}

/// A 32-byte content-addressed hash of a state tree node's canonical representation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeHash(pub [u8; 32]);

impl std::fmt::Debug for NodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeHash({})", hex::encode(self.0))
    }
}

/// Encodes a u64 into a big-endian byte array, suitable for ordered key scans.
#[inline]
pub fn be64(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}
/// Encodes a u32 into a big-endian byte array.
#[inline]
pub fn be32(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// Represents errors that can occur within the durable storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A generic error originating from the underlying key-value store backend (e.g., redb).
    #[error("backend error: {0}")]
    Backend(String),
    /// An error occurred while serializing data for storage.
    #[error("encode error: {0}")]
    Encode(String),
    /// An error occurred while deserializing data from storage.
    #[error("decode error: {0}")]
    Decode(String),
    /// The requested key or item was not found in the store.
    #[error("not found")]
    NotFound,
}

/// Minimal input required to atomically commit a block's state delta to the store.
pub struct CommitInput<'a> {
    /// The block height being committed.
    pub height: Height,
    /// The state root hash for this height.
    pub root: RootHash,
    /// A comprehensive list of every unique node hash referenced by the state at this height.
    pub unique_nodes_for_height: &'a [NodeHash],
    /// The full byte representation of nodes that are being introduced to this epoch for the first time.
    pub new_nodes: &'a [(NodeHash, &'a [u8])],
}

/// Contains statistics about a completed pruning operation.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneStats {
    /// The number of distinct block heights that were successfully pruned.
    pub heights_pruned: usize,
    /// The number of unique state tree nodes that were garbage collected as a result of pruning.
    pub nodes_deleted: usize,
}

/// The primary trait defining the API for a durable, epoch-sharded, content-addressed node store.
///
/// This interface abstracts the underlying storage backend (like `redb`) and provides
/// crash-safe methods for committing and pruning versioned state tree data.
pub trait NodeStore: Send + Sync {
    /// The size of a state history epoch in blocks, which is constant for the lifetime of the store.
    fn epoch_size(&self) -> u64;

    /// Computes the epoch identifier for a given block height.
    fn epoch_of(&self, height: Height) -> Epoch {
        let sz = self.epoch_size();
        if sz == 0 {
            0
        } else {
            height / sz
        }
    }

    /// Returns the current head of the chain (latest committed height and its epoch).
    fn head(&self) -> Result<(Height, Epoch), StorageError>;

    /// Returns the canonical block height for a given state root hash, if it exists.
    fn height_for_root(&self, root: RootHash) -> Result<Option<Height>, StorageError>;

    /// Returns the canonical state root hash for a given block height, if it has been committed.
    fn root_for_height(&self, height: Height) -> Result<Option<RootHash>, StorageError>;

    /// Marks an epoch as sealed, preventing any further writes to it.
    /// This is typically called at an epoch rollover.
    fn seal_epoch(&self, epoch: Epoch) -> Result<(), StorageError>;

    /// Checks if a given epoch has been sealed and is now considered immutable.
    fn is_sealed(&self, epoch: Epoch) -> Result<bool, StorageError>;

    /// Atomically commits all state changes for a single block.
    /// This operation is designed to be crash-safe.
    fn commit_block(&self, input: &CommitInput<'_>) -> Result<(), StorageError>;

    /// Prunes a limited number of historical state versions according to a `PrunePlan`.
    ///
    /// # Arguments
    /// * `cutoff_height` - The upper bound (exclusive) for pruning. Any height less than this is a candidate.
    /// * `excluded_heights` - A list of heights to explicitly skip, even if they are below the cutoff.
    /// * `limit` - The maximum number of heights to prune in this single call.
    ///
    /// # Returns
    /// `PruneStats` indicating the work done. If `stats.heights_pruned < limit`, the caller
    /// can assume there is nothing more to prune in the current cycle.
    fn prune_batch(
        &self,
        cutoff_height: Height,
        excluded_heights: &[Height],
        limit: usize,
    ) -> Result<PruneStats, StorageError>;

    /// Atomically drops an entire sealed epoch from the database.
    /// This is an efficient, O(1)-style operation for compliant backends.
    fn drop_sealed_epoch(&self, epoch: Epoch) -> Result<(), StorageError>;
}
