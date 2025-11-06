// Path: crates/chain/src/lib.rs
//! # DePIN SDK Chain Crate Lints
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
//! # DePIN SDK Chain
//!
//! This crate provides the implementation logic for the `AppChain` state machine.

pub mod app;
pub mod runtime_service;
pub mod upgrade_manager;
pub mod util;
pub mod wasm_loader;

pub use crate::app::Chain;
pub use upgrade_manager::ModuleUpgradeManager;
