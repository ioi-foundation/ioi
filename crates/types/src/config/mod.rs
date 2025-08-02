// Path: crates/core/src/config/mod.rs
//! Shared configuration structures for core DePIN SDK components.

use serde::Deserialize;

/// Configuration for the Workload container (`workload.toml`).
/// This is defined in `core` because it's part of the public `WorkloadContainer` struct.
#[derive(Debug, Deserialize, Clone)]
pub struct WorkloadConfig {
    /// A list of VM identifiers that are enabled.
    pub enabled_vms: Vec<String>,
}