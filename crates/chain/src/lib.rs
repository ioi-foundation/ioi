//! # DePIN SDK Chain
//!
//! Chain implementation components for the DePIN SDK.

pub mod app;

// Re-export governance and consensus from their respective crates
pub use depin_sdk_consensus as consensus;
pub use depin_sdk_governance as governance;
