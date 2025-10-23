// Path: crates/telemetry/src/sinks.rs
//! Defines abstract traits for metrics reporting, decoupling core logic from the backend.

use once_cell::sync::OnceCell;

// --- Static Sink Access ---

/// A no-op sink for use in tests or when telemetry is disabled.
#[derive(Debug, Clone, Copy)]
pub struct NopSink;

/// A lazily-initialized static reference to the global `MetricsSink` implementation.
pub static SINK: OnceCell<&'static dyn MetricsSink> = OnceCell::new();
static NOP_SINK: NopSink = NopSink;

/// Returns a static reference to the configured error metrics sink.
/// If no sink has been initialized, it returns a no-op sink.
pub fn error_metrics() -> &'static dyn ErrorMetricsSink {
    SINK.get().copied().unwrap_or(&NOP_SINK)
}

/// Returns a static reference to the configured service metrics sink.
/// If no sink has been initialized, it returns a no-op sink.
pub fn service_metrics() -> &'static dyn ServiceMetricsSink {
    SINK.get().copied().unwrap_or(&NOP_SINK)
}

// --- Trait Definitions ---

/// A sink for metrics related to the persistent storage layer.
pub trait StorageMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments the total number of sealed epochs dropped by the garbage collector.
    fn inc_epochs_dropped(&self, count: u64);
    /// Increments the total number of state tree nodes deleted by the garbage collector.
    fn inc_nodes_deleted(&self, count: u64);
    /// Increments the total number of bytes written to the storage backend for new nodes.
    fn inc_bytes_written_total(&self, bytes: u64);
    /// Sets the gauge for the estimated total disk usage of the storage backend.
    fn set_disk_usage_bytes(&self, bytes: u64);
    /// Sets the gauge for the total number of reference counts being tracked for garbage collection.
    fn set_total_ref_counts(&self, count: u64);
}
impl StorageMetricsSink for NopSink {
    fn inc_epochs_dropped(&self, _count: u64) {}
    fn inc_nodes_deleted(&self, _count: u64) {}
    fn inc_bytes_written_total(&self, _bytes: u64) {}
    fn set_disk_usage_bytes(&self, _bytes: u64) {}
    fn set_total_ref_counts(&self, _count: u64) {}
}

/// A sink for metrics related to the networking layer (libp2p).
pub trait NetworkMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments a counter for gossip messages received, labeled by topic.
    fn inc_gossip_messages_received(&self, topic: &str);
    /// Increments a counter for RPC requests received, labeled by method. (Deprecated)
    fn inc_rpc_requests_received(&self, method: &str);
    /// Increments the gauge for the current number of connected peers.
    fn inc_connected_peers(&self);
    /// Decrements the gauge for the current number of connected peers.
    fn dec_connected_peers(&self);
    /// Sets a gauge vector to indicate the current synchronization state of the node.
    fn set_node_state(&self, state_name: &str);
}
impl NetworkMetricsSink for NopSink {
    fn inc_gossip_messages_received(&self, _topic: &str) {}
    fn inc_rpc_requests_received(&self, _method: &str) {}
    fn inc_connected_peers(&self) {}
    fn dec_connected_peers(&self) {}
    fn set_node_state(&self, _state_name: &str) {}
}

/// A sink for metrics related to the consensus engine.
pub trait ConsensusMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments the counter for blocks produced by this node.
    fn inc_blocks_produced(&self);
    /// Increments the counter for view changes proposed by this node.
    fn inc_view_changes_proposed(&self);
    /// Observes the duration of a single consensus tick.
    fn observe_tick_duration(&self, duration_secs: f64);
}
impl ConsensusMetricsSink for NopSink {
    fn inc_blocks_produced(&self) {}
    fn inc_view_changes_proposed(&self) {}
    fn observe_tick_duration(&self, _duration_secs: f64) {}
}

/// A sink for metrics related to the public RPC server.
pub trait RpcMetricsSink: Send + Sync + std::fmt::Debug {
    /// Observes the latency of an RPC request, labeled by route.
    fn observe_request_duration(&self, route: &str, duration_secs: f64);
    /// Increments a counter for total RPC requests, labeled by route and status code.
    fn inc_requests_total(&self, route: &str, status_code: u16);
    /// Increments a counter for transactions added to the mempool via RPC.
    fn inc_mempool_transactions_added(&self);
    /// Sets the gauge for the current number of transactions in the mempool.
    fn set_mempool_size(&self, size: f64);
}
impl RpcMetricsSink for NopSink {
    fn observe_request_duration(&self, _route: &str, _duration_secs: f64) {}
    fn inc_requests_total(&self, _route: &str, _status_code: u16) {}
    fn inc_mempool_transactions_added(&self) {}
    fn set_mempool_size(&self, _size: f64) {}
}

/// A sink for recording structured error metrics.
pub trait ErrorMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments a counter for a specific error, categorized by its kind and variant.
    fn inc_error(&self, kind: &'static str, variant: &'static str);
}
impl ErrorMetricsSink for NopSink {
    fn inc_error(&self, _kind: &'static str, _variant: &'static str) {}
}

/// A sink for service-level metrics related to the generic dispatch mechanism.
pub trait ServiceMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments a counter when a required service capability cannot be found. (Deprecated)
    fn inc_capability_resolve_fail(&self, capability: &str);
    /// Observes the latency of a dispatched `handle_service_call`, labeled by service and method.
    fn observe_service_dispatch_latency(&self, service_id: &str, method: &str, duration_secs: f64);
    /// Increments a counter for errors returned from `handle_service_call`, labeled by reason.
    fn inc_dispatch_error(&self, service_id: &str, method: &str, reason: &'static str);
}
impl ServiceMetricsSink for NopSink {
    fn inc_capability_resolve_fail(&self, _capability: &str) {}
    fn observe_service_dispatch_latency(
        &self,
        _service_id: &str,
        _method: &str,
        _duration_secs: f64,
    ) {
    }
    fn inc_dispatch_error(&self, _service_id: &str, _method: &str, _reason: &'static str) {}
}

/// A unified sink that implements all domain-specific traits, providing a single
/// point of implementation for metrics backends like Prometheus.
pub trait MetricsSink:
    StorageMetricsSink
    + NetworkMetricsSink
    + ConsensusMetricsSink
    + RpcMetricsSink
    + ErrorMetricsSink
    + ServiceMetricsSink
{
}

// Blanket implementation to allow any type that implements all sub-traits
// to be used as a `MetricsSink`.
impl<T> MetricsSink for T where
    T: StorageMetricsSink
        + NetworkMetricsSink
        + ConsensusMetricsSink
        + RpcMetricsSink
        + ErrorMetricsSink
        + ServiceMetricsSink
{
}
