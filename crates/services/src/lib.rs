// Path: crates/services/src/lib.rs
#![forbid(unsafe_code)]

pub mod agentic;
pub mod external_data;
pub mod gas_escrow;
pub mod governance;
#[cfg(feature = "svc-ibc")]
pub mod ibc;
pub mod identity;