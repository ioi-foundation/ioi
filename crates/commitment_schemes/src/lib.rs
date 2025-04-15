//! # DePIN SDK Commitment Schemes
//!
//! Implementations of various commitment schemes for the DePIN SDK.

pub mod merkle;
pub mod pedersen;
pub mod kzg;
pub mod lattice;
pub mod iavl;
pub mod universal;

use depin-sdk-core::commitment::{CommitmentScheme, HomomorphicCommitmentScheme, SchemeIdentifier};
