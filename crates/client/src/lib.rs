// Path: crates/client/src/lib.rs
#![forbid(unsafe_code)]

//! # DePIN SDK Client
//!
//! Provides client-side logic for interacting with validator containers via IPC.

pub mod ipc;
pub mod security;
pub mod workload_client;

// Re-export for convenience
pub use workload_client::WorkloadClient;
