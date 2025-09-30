// Path: crates/services/src/ibc/src/lib.rs
//! # DePIN SDK IBC Crate Lints
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
        clippy::indexing_slicing
    )
)]

//! # DePIN SDK IBC
//!
//! Inter-Blockchain Communication implementation for the DePIN SDK.

pub mod conversion;
pub mod endpoints;
pub mod light_client;
pub mod proof;
pub mod translation;
pub mod verification;

use depin_sdk_api::commitment::{CommitmentScheme, SchemeIdentifier};
use depin_sdk_api::ibc::{ProofTranslator, UniversalProofFormat};
