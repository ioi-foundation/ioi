// Path: crates/execution/src/lib.rs
//! # IOI SDK Execution Crate Lints
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
//! # IOI SDK Execution
//!
//! This crate provides the implementation logic for the `ChainStateMachine` state machine.

pub mod app;
// [NEW] Export parallel execution components
pub mod mv_memory;
pub mod scheduler;

pub mod runtime_service;
pub mod upgrade_manager;
pub mod util;

pub use crate::app::ExecutionMachine;
pub use upgrade_manager::ServiceUpgradeManager;
