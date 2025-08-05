// Path: crates/network/src/traits.rs
//! Trait definitions for networking, including block synchronization and mempool gossip.

use async_trait::async_trait;
use depin_sdk_types::app::{Block, ChainTransaction};
use libp2p::PeerId;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// An error type for sync operations.
#[derive(thiserror::Error, Debug)]
pub enum SyncError {
    #[error("network error: {0}")]
    Network(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Represents the high-level state of the node's synchronization process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    Initializing,
    Syncing,
    Synced,
}

/// A trait for a standalone, pluggable block synchronization engine.
#[async_trait]
pub trait BlockSync: Send + Sync {
    /// Starts the background tasks for handling sync requests, etc.
    async fn start(&self) -> Result<(), SyncError>;

    /// Stops all background networking tasks.
    async fn stop(&self) -> Result<(), SyncError>;

    /// Publishes a block produced by the local node to the network.
    async fn publish_block(&self, block: &Block<ChainTransaction>) -> Result<(), SyncError>;

    /// Retrieves the current synchronization state of the node.
    fn get_node_state(&self) -> Arc<Mutex<NodeState>>;

    /// Retrieves the libp2p PeerId of the local node.
    fn get_local_peer_id(&self) -> PeerId;

    /// Retrieves the set of currently known (and likely connected) peers.
    fn get_known_peers(&self) -> Arc<Mutex<HashSet<PeerId>>>;
}

/// A trait for gossiping transactions to the mempool of other nodes.
#[async_trait]
pub trait MempoolGossip: Send + Sync {
    /// Publishes a transaction to the network's shared mempool.
    async fn publish_transaction(&self, tx: &ChainTransaction) -> Result<(), SyncError>;
}
