//! # DePIN SDK Core
//!
//! Core traits and interfaces for the DePIN SDK.

pub mod component;
pub mod crypto;
pub mod error;
pub mod homomorphic;
pub mod services;
pub mod commitment;
pub mod state;
pub mod types;
pub mod ibc;
pub mod transaction;
pub mod validator;

// Only include test utilities when running tests
#[cfg(test)]
pub mod test_utils;

// Re-export key traits and types for convenience
pub use commitment::*;
pub use component::*;
pub use crypto::*;
pub use error::*;
pub use homomorphic::*;
pub use ibc::*;
pub use services::*;
pub use state::*;
pub use transaction::*;
pub use validator::*;