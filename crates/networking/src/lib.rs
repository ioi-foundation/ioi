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
pub mod traits;
pub mod noop; // [NEW] Export noop module

// Re-export the public interface for consumers of the crate.
pub use self::libp2p::Libp2pSync;
pub use traits::{BlockSync, MempoolGossip, SyncError};
pub use noop::NoOpBlockSync; // [NEW] Re-export NoOpBlockSync