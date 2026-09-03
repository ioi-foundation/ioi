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

#[cfg(test)]
mod tests {
    use super::{consensus_metrics, CONSENSUS_SINK};
    use ioi_telemetry::sinks::ConsensusMetricsSink;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    struct ConsensusProbe {
        async_stage_observations: AtomicU64,
    }

    impl ConsensusMetricsSink for ConsensusProbe {
        fn inc_blocks_produced(&self) {}
        fn inc_view_changes_proposed(&self) {}
        fn observe_tick_duration(&self, _duration_secs: f64) {}
        fn observe_aft_hash_async_message(&self, _direction: &str, _class: &str, _bytes: u64) {}
        fn observe_aft_hash_async_stage_duration(&self, _stage: &str, _duration_secs: f64) {
            self.async_stage_observations.fetch_add(1, Ordering::SeqCst);
        }
        fn set_aft_hash_async_active_sessions(&self, _count: u64) {}
    }

    static PROBE: ConsensusProbe = ConsensusProbe {
        async_stage_observations: AtomicU64::new(0),
    };

    #[test]
    fn configured_consensus_accessor_routes_hash_async_observations() {
        let _ = CONSENSUS_SINK.set(&PROBE);
        let before = PROBE.async_stage_observations.load(Ordering::SeqCst);
        consensus_metrics().observe_aft_hash_async_stage_duration("execution_prepare", 0.25);
        assert_eq!(
            PROBE.async_stage_observations.load(Ordering::SeqCst),
            before + 1
        );
    }
}
