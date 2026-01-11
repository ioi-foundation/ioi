// Path: crates/client/src/lib.rs
//! # IOI Kernel Client Crate Lints
//!
//! This crate enforces a strict set of lints to ensure high-quality,
//! panic-free, and well-documented code. Panics are disallowed in non-test
//! code to promote robust error handling.
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

//! # IOI Kernel Client
//!
//! Provides client-side logic for interacting with validator containers via IPC.

pub mod security;
pub mod shmem;
pub mod slicing; // [NEW]
pub mod workload_client;

// Re-export for convenience
pub use slicing::{SlicePackager, SlicerConfig};
pub use workload_client::WorkloadClient;
