// Path: crates/commitment_schemes/src/lib.rs
#![forbid(unsafe_code)]
//! # DePIN SDK Commitment Schemes
//!
//! Implementations of various commitment schemes for the DePIN SDK.

pub mod elliptic_curve;
pub mod hash;
pub mod kzg;
pub mod lattice; // Renamed from module_lwe
