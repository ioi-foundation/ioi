// Path: crates/networking/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

//! # IOI Kernel Network
//!
//! This crate provides traits and implementations for block synchronization
//! and network communication logic.

pub mod libp2p;
pub mod metrics;
pub mod noop;
pub mod traits; // [NEW] Export noop module

// Re-export the public interface for consumers of the crate.
pub use self::libp2p::Libp2pSync;
pub use noop::NoOpBlockSync;
pub use traits::{BlockSync, MempoolGossip, SyncError}; // [NEW] Re-export NoOpBlockSync
