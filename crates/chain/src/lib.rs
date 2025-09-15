// Path: crates/chain/src/lib.rs
#![forbid(unsafe_code)]
//! # DePIN SDK Chain
//!
//! This crate provides the implementation logic for the `AppChain` state machine.

pub mod app;
pub mod upgrade_manager;
pub mod util;
pub mod wasm_loader;

pub use crate::app::Chain;
pub use upgrade_manager::ModuleUpgradeManager;
