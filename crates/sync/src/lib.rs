//! # DePIN SDK Sync
//!
//! This crate provides traits and implementations for block synchronization
//! and network communication logic.

pub mod libp2p;
pub mod traits;

pub use traits::{BlockSync, SyncError};