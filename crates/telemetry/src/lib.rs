// Path: crates/telemetry/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

//! # IOI Kernel Telemetry
//!
//! This crate provides the observability infrastructure for the IOI Kernel,
//! including structured logging initialization, a Prometheus metrics endpoint,
//! and abstract sinks for decoupling metric instrumentation from the backend.

/// A lightweight HTTP server for exposing `/metrics`, `/healthz`, and `/readyz` endpoints.
pub mod http;
/// The initialization routine for global structured logging.
pub mod init;
/// The concrete implementation of metrics sinks using the `prometheus` crate.
pub mod prometheus;
/// Abstract traits (`*MetricsSink`) that define the contract for metrics reporting.
pub mod sinks;
/// A simple RAII timer for measuring the duration of a scope.
pub mod time;

// Re-export the public helper functions for easy access to the global sinks.
pub use sinks::{error_metrics, service_metrics};
