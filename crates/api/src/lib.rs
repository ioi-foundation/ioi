// Path: crates/api/src/lib.rs
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! # DePIN SDK API
//!
//! Core traits and interfaces for the DePIN SDK. This crate defines the
//! stable contract for all modular components.

/// Core application-level data structures like Blocks and Transactions.
pub mod app;
/// Core traits for the blockchain state machine.
pub mod chain;
/// Core traits and types for cryptographic commitment schemes.
pub mod commitment;
/// Defines the component classification system (Fixed, Adaptable, Extensible).
pub mod component;
/// Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.
pub mod consensus;
/// Defines unified traits for cryptographic primitives.
pub mod crypto;
/// Re-exports all core error types from the central `depin-sdk-types` crate.
pub mod error;
/// Defines the core enums for representing homomorphic operations and their results.
pub mod homomorphic;
/// Defines traits for Inter-Blockchain Communication (IBC).
pub mod ibc;
/// Defines traits for services that hook into the block processing lifecycle.
pub mod lifecycle;
/// Traits for pluggable, upgradable blockchain services.
pub mod services;
/// Core traits for state management, including `StateCommitment` and `StateManager`.
pub mod state;
/// Defines the core `TransactionModel` trait.
pub mod transaction;
/// Defines the core traits and structures for the validator architecture.
pub mod validator;
/// Defines the core traits and types for virtual machines.
pub mod vm;

/// A curated set of the most commonly used traits and types.
pub mod prelude {
    pub use crate::chain::AppChain;
    pub use crate::commitment::{CommitmentScheme, HomomorphicCommitmentScheme};
    pub use crate::error::{ChainError, CoreError, StateError, TransactionError, ValidatorError};
    pub use crate::lifecycle::OnEndBlock;
    pub use crate::services::access::{Service, ServiceDirectory};
    pub use crate::services::{BlockchainService, UpgradableService};
    pub use crate::state::{StateCommitment, StateManager};
    pub use crate::transaction::context::TxContext;
    pub use crate::transaction::decorator::TxDecorator;
    pub use crate::transaction::TransactionModel;
    pub use crate::validator::container::{Container, GuardianContainer};
    // --- MODIFICATION: Removed the line below ---
    // pub use crate::validator::TransactionExecutor;
    pub use crate::vm::VirtualMachine;
}
