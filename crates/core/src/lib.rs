// Path: crates/core/src/lib.rs
//! # DePIN SDK Core
//!
//! Core traits and interfaces for the DePIN SDK.

pub mod app;
pub mod chain;
pub mod commitment;
pub mod component;
pub mod config;
pub mod crypto;
pub mod error;
pub mod homomorphic;
pub mod ibc;
pub mod services;
pub mod state;
pub mod transaction;
pub mod types;
pub mod validator;
pub mod vm;

#[cfg(test)]
pub mod test_utils;

// Re-export key traits and types for convenience
pub use app::*;
pub use chain::*;
pub use commitment::*;
pub use component::*;
pub use config::*;
pub use crypto::*;
pub use error::*;
pub use homomorphic::*;
pub use ibc::*;
pub use services::*;
pub use state::*;
pub use transaction::*;
pub use validator::{Container, GuardianContainer, TransactionExecutor, WorkloadContainer};
pub use vm::{ExecutionContext, ExecutionOutput, VirtualMachine};