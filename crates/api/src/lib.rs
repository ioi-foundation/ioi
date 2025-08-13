// Path: crates/api/src/lib.rs
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # DePIN SDK API
//!
//! Core traits and interfaces for the DePIN SDK. This crate defines the
//! stable contract for all modular components.

/// Core application-level data structures like Blocks and Transactions.
pub mod app;
pub mod chain;
pub mod commitment;
pub mod component;
pub mod crypto;
pub mod homomorphic;
pub mod ibc;
pub mod services;
pub mod state;
pub mod transaction;
pub mod validator;
pub mod vm;

/// A curated set of the most commonly used traits and types.
pub mod prelude {
    pub use crate::chain::AppChain;
    pub use crate::commitment::{CommitmentScheme, HomomorphicCommitmentScheme};
    // No change needed for consensus as it's not part of the API crate.
    pub use crate::services::{BlockchainService, UpgradableService};
    pub use crate::state::{StateCommitment, StateManager};
    pub use crate::transaction::TransactionModel;
    // FIX: Corrected the paths for validator traits.
    pub use crate::validator::container::{Container, GuardianContainer};
    pub use crate::validator::TransactionExecutor;
    pub use crate::vm::VirtualMachine;
}
