// Path: crates/ipc/src/lib.rs
//! # IOI SDK IPC Protocol Crate Lints
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

pub mod jsonrpc;

/// Identifies the type of client connecting via the secure IPC channel.
///
/// This enum replaces magic numbers used in the mTLS handshake to route
/// connections within the Guardian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcClientType {
    /// The Orchestration container, responsible for consensus and networking.
    Orchestrator = 1,
    /// The Workload container, responsible for transaction execution and state management.
    Workload = 2,
}

impl TryFrom<u8> for IpcClientType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Orchestrator),
            2 => Ok(Self::Workload),
            _ => Err(value),
        }
    }
}