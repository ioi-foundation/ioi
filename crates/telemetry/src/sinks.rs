// Path: crates/telemetry/src/sinks.rs
//! Defines abstract traits for metrics reporting, decoupling core logic from the backend.

/// A no-op sink for use in tests where metrics are not needed.
#[derive(Debug, Clone, Copy)]
pub struct NopSink;

// --- Trait Definitions ---

pub trait StorageMetricsSink: Send + Sync + std::fmt::Debug {
    fn inc_epochs_dropped(&self, count: u64);
    fn inc_nodes_deleted(&self, count: u64);
    fn inc_bytes_written_total(&self, bytes: u64);
    fn set_disk_usage_bytes(&self, bytes: u64);
    fn set_total_ref_counts(&self, count: u64);
}
impl StorageMetricsSink for NopSink {
    fn inc_epochs_dropped(&self, _count: u64) {}
    fn inc_nodes_deleted(&self, _count: u64) {}
    fn inc_bytes_written_total(&self, _bytes: u64) {}
    fn set_disk_usage_bytes(&self, _bytes: u64) {}
    fn set_total_ref_counts(&self, _count: u64) {}
}

pub trait NetworkMetricsSink: Send + Sync + std::fmt::Debug {
    fn inc_gossip_messages_received(&self, topic: &str);
    fn inc_rpc_requests_received(&self, method: &str);
    fn inc_connected_peers(&self);
    fn dec_connected_peers(&self);
    fn set_node_state(&self, state_name: &str);
}
impl NetworkMetricsSink for NopSink {
    fn inc_gossip_messages_received(&self, _topic: &str) {}
    fn inc_rpc_requests_received(&self, _method: &str) {}
    fn inc_connected_peers(&self) {}
    fn dec_connected_peers(&self) {}
    fn set_node_state(&self, _state_name: &str) {}
}

pub trait ConsensusMetricsSink: Send + Sync + std::fmt::Debug {
    fn inc_blocks_produced(&self);
    fn inc_view_changes_proposed(&self);
    fn observe_tick_duration(&self, duration_secs: f64);
}
impl ConsensusMetricsSink for NopSink {
    fn inc_blocks_produced(&self) {}
    fn inc_view_changes_proposed(&self) {}
    fn observe_tick_duration(&self, _duration_secs: f64) {}
}

pub trait RpcMetricsSink: Send + Sync + std::fmt::Debug {
    fn observe_request_duration(&self, method: &str, duration_secs: f64);
    fn inc_requests_total(&self, method: &str, status_code: u16);
    fn inc_mempool_transactions_added(&self);
    fn set_mempool_size(&self, size: f64);
}
impl RpcMetricsSink for NopSink {
    fn observe_request_duration(&self, _method: &str, _duration_secs: f64) {}
    fn inc_requests_total(&self, _method: &str, _status_code: u16) {}
    fn inc_mempool_transactions_added(&self) {}
    fn set_mempool_size(&self, _size: f64) {}
}

/// A sink for recording error metrics.
pub trait ErrorMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments a counter for a specific error.
    fn inc_error(&self, kind: &'static str, variant: &'static str);
}
impl ErrorMetricsSink for NopSink {
    fn inc_error(&self, _kind: &'static str, _variant: &'static str) {}
}

/// A sink for service-level metrics.
pub trait ServiceMetricsSink: Send + Sync + std::fmt::Debug {
    /// Increments a counter when a required service capability cannot be found.
    fn inc_capability_resolve_fail(&self, capability: &'static str);
    /// Observes the latency of a dispatched service call.
    fn observe_service_dispatch_latency(&self, service_id: &'static str, duration_secs: f64);
}
impl ServiceMetricsSink for NopSink {
    fn inc_capability_resolve_fail(&self, _capability: &'static str) {}
    fn observe_service_dispatch_latency(&self, _service_id: &'static str, _duration_secs: f64) {}
}

// A unified sink that implements all domain-specific traits
pub trait MetricsSink:
    StorageMetricsSink
    + NetworkMetricsSink
    + ConsensusMetricsSink
    + RpcMetricsSink
    + ErrorMetricsSink
    + ServiceMetricsSink
{
}

// Blanket implementation
impl<T> MetricsSink for T where
    T: StorageMetricsSink
        + NetworkMetricsSink
        + ConsensusMetricsSink
        + RpcMetricsSink
        + ErrorMetricsSink
        + ServiceMetricsSink
{
}