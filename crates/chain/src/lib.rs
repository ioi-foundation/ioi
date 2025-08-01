//! # DePIN SDK Chain
//!
//! This crate provides the implementation logic for the `AppChain` state machine.

mod app;
pub mod upgrade_manager;

// FIX: Corrected the path to Chain, removing the non-existent 'logic' module.
pub use app::Chain;
pub use upgrade_manager::ModuleUpgradeManager;