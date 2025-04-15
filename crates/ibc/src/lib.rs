//! # DePIN SDK IBC
//!
//! Inter-Blockchain Communication implementation for the DePIN SDK.

pub mod proof;
pub mod translation;
pub mod light_client;
pub mod verification;

use depin_sdk_core::ibc::{ProofTranslator, UniversalProofFormat};
use depin_sdk_core::commitment::{CommitmentScheme, SchemeIdentifier};
