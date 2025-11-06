// Path: crates/transaction_models/src/lib.rs
//! # IOI SDK Transaction Models Crate Lints
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

pub mod account;
pub mod hybrid;
pub mod system; // Add this module
pub mod unified;
pub mod utxo;

pub use account::{AccountConfig, AccountModel, AccountTransaction};
pub use hybrid::{HybridConfig, HybridModel, HybridTransaction};
pub use unified::UnifiedTransactionModel;
pub use utxo::{UTXOConfig, UTXOModel, UTXOTransaction};