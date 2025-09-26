// Path: crates/storage/src/lib.rs

//! Pure-Rust persistent storage (redb + epoch sharding) for StateManager backends.
//! This module provides a NodeStore abstraction and a redb-based EpochStore
//! that implements the layout described in Phase 4 (ROOT_INDEX, HEAD, EPOCH_MANIFEST,
//! and epoch-sharded VERSIONS/CHANGES/NODES/REFS realized via prefix-encoded keys).

pub mod adapter;
pub mod metrics;
pub mod redb_epoch_store;

pub use redb_epoch_store::RedbEpochStore;