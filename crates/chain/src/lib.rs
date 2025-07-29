//! # DePIN SDK Chain
//!
//! This crate provides the implementation logic for the `SovereignAppChain` state machine.

mod app;
pub mod upgrade_manager;
pub mod traits;

// FIX: Corrected the path to ChainLogic, removing the non-existent 'logic' module.
pub use app::ChainLogic;
pub use upgrade_manager::ModuleUpgradeManager;