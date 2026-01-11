// Path: crates/validator/src/standard/workload/drivers/mod.rs

//! Workload runtime and hardware drivers.

/// Verified HTTP driver for secure egress via the Guardian.
pub mod verified_http;

/// CPU-based hardware driver (Candle).
pub mod cpu;
