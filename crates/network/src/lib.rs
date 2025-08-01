// Path: crates/network/src/lib.rs

//! # DePIN SDK Network
//!
//! This crate provides traits and implementations for block synchronization
//! and network communication logic.

// The libp2p implementation is now a module with sub-modules.
pub mod libp2p;
pub mod traits;

// Re-export the public interface for consumers of the crate.
pub use self::libp2p::Libp2pSync;
pub use traits::{BlockSync, MempoolGossip, SyncError};