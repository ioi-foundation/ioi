//! # DePIN SDK Transaction Models
//!
//! Implementations of various transaction models for the DePIN SDK.

pub mod utxo;
pub mod account;
pub mod hybrid;

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
