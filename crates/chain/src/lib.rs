//! # DePIN SDK Chain
//!
//! Chain implementation components for the DePIN SDK.

pub mod app;
pub mod upgrade_manager;

// Re-export for convenience
pub use upgrade_manager::ModuleUpgradeManager;

// Re-export consensus from its crate
pub use depin_sdk_consensus as consensus;

// TODO: Add governance crate when it's implemented
// pub use depin_sdk_governance as governance;