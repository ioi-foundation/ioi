//! # DePIN SDK Homomorphic Operations
//!
//! Implementation of homomorphic operations on commitments for the DePIN SDK.

pub mod operations;
pub mod computation;
pub mod pedersen;

use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use depin_sdk_core::commitment::{CommitmentScheme, HomomorphicCommitmentScheme};
