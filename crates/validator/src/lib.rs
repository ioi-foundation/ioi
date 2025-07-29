//! # DePIN SDK Validator
//!
//! Validator implementation with container architecture for the DePIN SDK.

pub mod config;
pub mod common;
pub mod standard;
pub mod hybrid;
// NEW: Public traits for this crate are defined here.
pub mod traits;

// Re-export the new public trait.
pub use traits::WorkloadLogic;