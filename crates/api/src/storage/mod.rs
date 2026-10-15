// Path: crates/api/src/storage/mod.rs

//! API for a durable, epoch-sharded, content-addressed node store.

use crate::app::{Block, ChainTransaction};
use async_trait::async_trait;
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

/// The node's Agentgres-admitted tip: the highest block the orchestration's Agentgres admission
/// has recorded as committed (FU-N11-DURABLE-STATUS-1 D2a). It is the source of every
/// "committed" read (IBC latest height, licence expiry, a trusted state root), never the
/// workload's durable status, which counts signed but uncommitted blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedTip {
    /// The admitted block's height.
    pub height: Height,
    /// The admitted (certified) block hash. It may differ from the stored header's hash when a
    /// view-change winner names a different parent; the execution surface is what must match.
    pub block_hash: [u8; 32],
    /// The admitted block's post-state root.
    pub state_root: Vec<u8>,
}

/// One row of the workload's ADMITTED INDEX (FU-N11-DURABLE-STATUS-1 D2a RED-4 scaffold; the index
/// replaces the admission-floor fence at GREEN-4): what the Agentgres admission publication
/// recorded for `height`. Every committed read (the by-height record, the IBC explicit and latest
/// heights, licence expiry, a trusted root) is served from ONE such record and nothing else. The
/// index is written once per height, only by the publication; its max entry is the committed tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRecord {
    /// The admitted block's height.
    pub height: Height,
    /// The admitted (certified) block hash.
    pub block_hash: [u8; 32],
    /// The admitted block's post-state root.
    pub state_root: Vec<u8>,
    /// The admitted header's timestamp (seconds), carried by the record and never re-read from a
    /// stored block.
    pub timestamp: u64,
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
#[derive(Debug, Clone)]
pub struct CommitInput {
    /// The block height being committed.
    pub height: Height,
    /// The state root hash for this height.
    pub root: RootHash,
    /// A comprehensive list of every unique node hash referenced by the state at this height.
    pub unique_nodes_for_height: Vec<NodeHash>,
    /// The full byte representation of nodes that are being introduced to this epoch for the first time.
    pub new_nodes: Vec<(NodeHash, Vec<u8>)>,
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
#[async_trait]
pub trait NodeStore: Send + Sync {
    /// The size of a state history epoch in blocks, which is constant for the lifetime of the store.
    fn epoch_size(&self) -> u64;

    /// Returns the epoch id that contains this height (usually height / epoch_size).
    fn epoch_of(&self, height: u64) -> u64;

    /// Returns the raw, canonical bytes of a node by hash in a specific epoch.
    fn get_node(&self, epoch: u64, node: NodeHash) -> Result<Option<Vec<u8>>, StorageError>;

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
    ///
    /// This is async to allow for backpressure handling from the persistence layer.
    async fn commit_block(&self, input: CommitInput) -> Result<(), StorageError>;

    /// Atomically commits all state changes for a single block and persists the full block bytes.
    ///
    /// Backends can override this to persist both artifacts in one durable operation. The default
    /// implementation preserves existing semantics by performing the operations sequentially.
    async fn commit_block_with_payload(
        &self,
        input: CommitInput,
        block_bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.commit_block(input.clone()).await?;
        self.put_block(input.height, block_bytes).await
    }

    /// Prunes a limited number of historical state versions according to a `PrunePlan`.
    fn prune_batch(
        &self,
        cutoff_height: Height,
        excluded_heights: &[Height],
        limit: usize,
    ) -> Result<PruneStats, StorageError>;

    /// Atomically drops an entire sealed epoch from the database.
    fn drop_sealed_epoch(&self, epoch: Epoch) -> Result<(), StorageError>;

    /// Stores the full, serialized bytes of a block at its height.
    /// This is async to allow offloading large writes to the background worker.
    async fn put_block(&self, height: u64, block_bytes: &[u8]) -> Result<(), StorageError>;

    /// Retrieves a single block by its height from the durable store.
    fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>, StorageError>;

    /// Retrieves a range of blocks starting from a given height.
    fn get_blocks_range(
        &self,
        start: u64,
        limit: u32,
        max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>, StorageError>;

    /// The persisted Agentgres-admitted tip marker, or `None` before the first admission.
    fn get_admitted_tip(&self) -> Result<Option<AdmittedTip>, StorageError> {
        Ok(None)
    }

    /// Persists the Agentgres-admitted tip marker. Monotone: a lower height, or the same height
    /// with a different block hash or state root, is refused and leaves the marker unchanged.
    /// The record is checked against the block the store holds at the tip's height (same height
    /// and state root) in the same write as the marker, so a block write cannot interleave into a
    /// marker over a different block (FU-N11-DURABLE-STATUS-1 D2a round 2). Backends without a
    /// marker refuse every record.
    ///
    /// THE ADMISSION FLOOR: once a marker exists, every block or state-version write at a height
    /// at or below it (`put_block`, `commit_block`, `commit_block_with_payload`) is refused unless
    /// it keeps the committed block: the same identity hash, execution surface and transactions,
    /// no stripped evidence (signature, sealed finality proof, guardian certificate) and unchanged
    /// committee certificates; a state version keeps its root. A refusal leaves the store as it
    /// was.
    fn put_admitted_tip(&self, _tip: &AdmittedTip) -> Result<(), StorageError> {
        Err(StorageError::Backend(
            "this node store keeps no admitted-tip marker".into(),
        ))
    }

    /// The ADMITTED INDEX row for `height` (FU-N11-DURABLE-STATUS-1 D2a RED-4 scaffold): what the
    /// admission publication recorded there, or `None` (not admitted, or above the max entry): a
    /// committed read then refuses, never falls back to a stored block. The default keeps no
    /// index and returns `None`, as every store does before GREEN-4.
    fn get_admitted_record(&self, _height: Height) -> Result<Option<AdmittedRecord>, StorageError> {
        Ok(None)
    }

    /// The ADMITTED INDEX's own writer (FU-N11-DURABLE-STATUS-1 D2a RED-4 scaffold): writes one row,
    /// once per height. A different record at an existing height is refused and the row stays as
    /// it was; the identical record is an idempotent no-op; no prune or epoch drop removes a row.
    /// The default keeps no index and refuses every write.
    fn put_admitted_record(&self, _record: &AdmittedRecord) -> Result<(), StorageError> {
        Err(StorageError::Backend(
            "this node store keeps no admitted index".into(),
        ))
    }
}
