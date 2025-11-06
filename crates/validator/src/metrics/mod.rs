// Path: crates/validator/src/metrics/mod.rs
//! Static accessors for validator-specific metrics sinks.
//!
//! This module provides globally accessible, lazily-initialized static references
//! to metrics sinks for different validator domains (Consensus, RPC). This allows
//! any part of the validator codebase to record metrics without needing to pass
//! a metrics object through the entire call stack.

use ioi_telemetry::sinks::{ConsensusMetricsSink, NopSink, RpcMetricsSink};
use once_cell::sync::OnceCell;

static NOP_SINK: NopSink = NopSink;
/// A lazily-initialized static reference to the global consensus metrics sink.
pub static CONSENSUS_SINK: OnceCell<&'static dyn ConsensusMetricsSink> = OnceCell::new();
/// A lazily-initialized static reference to the global RPC metrics sink.
pub static RPC_SINK: OnceCell<&'static dyn RpcMetricsSink> = OnceCell::new();

/// Returns a static reference to the configured consensus metrics sink.
/// If the sink has not been initialized (e.g., in a test), it returns a no-op sink.
pub fn consensus_metrics() -> &'static dyn ConsensusMetricsSink {
    CONSENSUS_SINK.get().copied().unwrap_or(&NOP_SINK)
}

/// Returns a static reference to the configured RPC metrics sink.
/// If the sink has not been initialized, it returns a no-op sink.
pub fn rpc_metrics() -> &'static dyn RpcMetricsSink {
    RPC_SINK.get().copied().unwrap_or(&NOP_SINK)
}
