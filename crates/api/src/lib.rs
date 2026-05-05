// Path: crates/api/src/lib.rs

//! # IOI Kernel API Crate Lints
//!
//! This crate enforces a strict set of lints to ensure high-quality,
//! panic-free, and well-documented code. Panics are disallowed in non-test
//! code to promote robust error handling.
#![allow(
    clippy::await_holding_lock,
    clippy::assign_op_pattern,
    clippy::if_same_then_else,
    clippy::incompatible_msrv,
    clippy::indexing_slicing,
    clippy::len_zero,
    clippy::manual_clamp,
    clippy::manual_div_ceil,
    clippy::manual_inspect,
    clippy::manual_pattern_char_comparison,
    clippy::match_single_binding,
    clippy::needless_borrow,
    clippy::needless_lifetimes,
    clippy::needless_match,
    clippy::needless_return,
    clippy::question_mark,
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::unnecessary_sort_by,
    clippy::unnecessary_lazy_evaluations,
    clippy::useless_conversion,
    clippy::useless_format,
    clippy::expect_used
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]
//! # IOI Kernel API
//!
//! Core traits and interfaces for the IOI Kernel. This crate defines the
//! stable contract for all modular components.

/// Core application-level data structures like Blocks and Transactions.
pub mod app;
/// Core traits for the blockchain state machine.
pub mod chain;
/// Shared Chat routing and artifact materialization helpers.
pub mod chat;
pub(crate) mod chat_mock;
/// Core traits and types for cryptographic commitment schemes.
pub mod commitment;
/// Defines the component classification system (Fixed, Adaptable, Extensible).
pub mod component;
/// Defines the core `ConsensusEngine` trait for pluggable consensus algorithms.
pub mod consensus;
/// Defines unified traits for cryptographic primitives.
pub mod crypto;
/// Re-exports all core error types from the central `ioi-types` crate.
pub mod error;
/// Shared execution substrate and strategy helpers across Chat domains.
pub mod execution;
/// Defines traits for Inter-Blockchain Communication (IBC).
pub mod ibc;
/// Defines the `CredentialsView` trait for decoupled identity lookups.
pub mod identity;
/// Defines traits for services that hook into the block processing lifecycle.
pub mod lifecycle;
/// Product-agnostic runtime-harness semantics shared by shell products.
pub mod runtime_harness;
/// Traits for pluggable, upgradable blockchain services.
pub mod services;
/// Core traits for state management, including `StateAccess` and `StateManager`.
pub mod state;
/// An API for a durable, epoch-sharded, content-addressed node store.
pub mod storage;
/// Defines the core `TransactionModel` trait.
pub mod transaction;
/// Defines the core traits and structures for the validator architecture.
pub mod validator;
/// Defines the core traits and types for virtual machines.
pub mod vm;
/// Definitions for the Zero-Knowledge Stack.
pub mod zk;

/// A curated set of the most commonly used traits and types.
pub mod prelude {
    pub use crate::chain::{
        AnchoredStateView, ChainStateMachine, LiveStateView, RemoteStateView, StateRef,
        ViewResolver,
    };
    pub use crate::commitment::CommitmentScheme;
    pub use crate::error::{
        ChainError, CoreError, CryptoError, ErrorCode, StateError, TransactionError, ValidatorError,
    };
    pub use crate::identity::CredentialsView;
    pub use crate::lifecycle::OnEndBlock;
    pub use crate::services::access::ServiceDirectory;
    pub use crate::services::{BlockchainService, UpgradableService};
    pub use crate::state::{StateAccess, StateManager, VerifiableState};
    pub use crate::storage::NodeStore;
    pub use crate::transaction::context::TxContext;
    pub use crate::transaction::decorator::TxDecorator;
    pub use crate::transaction::TransactionModel;
    pub use crate::validator::container::{Container, GuardianContainer};
    pub use crate::vm::VirtualMachine;
}
