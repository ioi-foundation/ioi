//! # DePIN SDK Transaction Models
//!
//! Implementations of various transaction models for the DePIN SDK.
//!
//! This crate provides concrete implementations of the transaction model
//! interfaces defined in the `depin_sdk_core` crate.
//!
//! ## Usage
//!
//! Each transaction model is implemented in its own module.
//! Applications should import the specific model types they wish to use.
//!
//! ```rust
//! // Example: Using the UTXO model
//! use transaction_models::utxo::{UTXOModel, UTXOProof, UTXOTransaction};
//!
//! // Example: Using the account model
//! use transaction_models::account::{AccountModel, AccountProof, AccountTransaction};
//! ```

// Modules for each transaction model
pub mod account;
pub mod hybrid;
pub mod utxo;

// Re-export operation traits for convenience
pub use account::AccountOperations;
pub use hybrid::HybridOperations;
pub use utxo::UTXOOperations;
