//! # DePIN SDK State Trees
//!
//! Implementations of various state tree structures for the DePIN SDK.

pub mod verkle;
pub mod sparse_merkle;
pub mod iavl_plus;
pub mod generic;

use std::any::Any;
use depin-sdk-core::state::StateTree;
use depin-sdk-core::commitment::CommitmentScheme;
