// Path: crates/validator/src/common/mod.rs

//! Common validator components shared by all types

pub mod attestation;
pub mod guardian; // FIX: Make the module public
pub mod ipc;
pub mod security;

#[cfg(test)]
mod tests;

pub use guardian::*;
pub use security::*;
