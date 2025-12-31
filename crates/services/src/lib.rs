// Path: crates/services/src/lib.rs
#![forbid(unsafe_code)]

pub mod agentic;
pub mod governance;
#[cfg(feature = "ibc-deps")]
pub mod ibc;
pub mod identity;
pub mod provider_registry; // Replaced 'oracle'
