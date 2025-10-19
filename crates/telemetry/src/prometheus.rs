// Path: crates/telemetry/src/prometheus.rs
//! A concrete implementation of the metrics sinks using the Prometheus crate.

use crate::sinks::*;
use once_cell::sync::OnceCell;
use prometheus::{
    exponential_buckets, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, register_int_counter, register_int_counter_vec, Gauge, GaugeVec,
    Histogram, HistogramVec, IntCounter, IntCounterVec,
};

// --- Metric Statics ---
// We now use OnceCell to hold the metric collectors. They will be initialized
// exactly once by the `install` function.

static NETWORK_CONNECTED_PEERS: OnceCell<Gauge> = OnceCell::new();
static MEMPOOL_SIZE: OnceCell<Gauge> = OnceCell::new();
static STORAGE_DISK_USAGE_BYTES: OnceCell<Gauge> = OnceCell::new();
static STORAGE_REF_COUNTS: OnceCell<Gauge> = OnceCell::new();
static NETWORK_NODE_STATE: OnceCell<GaugeVec> = OnceCell::new();
static STORAGE_EPOCHS_DROPPED_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static STORAGE_NODES_DELETED_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static STORAGE_BYTES_WRITTEN_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static CONSENSUS_BLOCKS_PRODUCED_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static MEMPOOL_TRANSACTIONS_ADDED_TOTAL: OnceCell<IntCounter> = OnceCell::new();
static GOSSIP_MESSAGES_RECEIVED_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
static RPC_REQUESTS_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
static CONSENSUS_TICK_DURATION_SECONDS: OnceCell<Histogram> = OnceCell::new();
static RPC_REQUEST_DURATION_SECONDS: OnceCell<HistogramVec> = OnceCell::new();
static ERRORS_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();

// --- NEW METRICS FOR PHASE 2 ---
static SVC_CAPABILITY_RESOLVE_FAIL_TOTAL: OnceCell<IntCounterVec> = OnceCell::new();
static SVC_DISPATCH_LATENCY_SECONDS: OnceCell<HistogramVec> = OnceCell::new();
// NOTE: `ibc_dispatch_errors_total` is better handled by the generic `ERRORS_TOTAL` counter.

#[derive(Debug, Clone, Copy)]
pub struct PrometheusSink;

// Helper macro to reduce boilerplate for getting a metric from OnceCell.
// This will panic if `install()` has not been called, which is intentional
// as it indicates a critical application setup error.
macro_rules! get_metric {
    ($metric:ident) => {
        $metric
            .get()
            .expect("Prometheus sink not initialized. Call telemetry::prometheus::install() first.")
    };
}

impl StorageMetricsSink for PrometheusSink {
    fn inc_epochs_dropped(&self, count: u64) {
        get_metric!(STORAGE_EPOCHS_DROPPED_TOTAL).inc_by(count);
    }
    fn inc_nodes_deleted(&self, count: u64) {
        get_metric!(STORAGE_NODES_DELETED_TOTAL).inc_by(count);
    }
    fn inc_bytes_written_total(&self, bytes: u64) {
        get_metric!(STORAGE_BYTES_WRITTEN_TOTAL).inc_by(bytes);
    }
    fn set_disk_usage_bytes(&self, bytes: u64) {
        get_metric!(STORAGE_DISK_USAGE_BYTES).set(bytes as f64);
    }
    fn set_total_ref_counts(&self, count: u64) {
        get_metric!(STORAGE_REF_COUNTS).set(count as f64);
    }
}
impl NetworkMetricsSink for PrometheusSink {
    fn inc_connected_peers(&self) {
        get_metric!(NETWORK_CONNECTED_PEERS).inc();
    }
    fn dec_connected_peers(&self) {
        get_metric!(NETWORK_CONNECTED_PEERS).dec();
    }
    fn inc_gossip_messages_received(&self, topic: &str) {
        get_metric!(GOSSIP_MESSAGES_RECEIVED_TOTAL)
            .with_label_values(&[topic])
            .inc();
    }
    fn inc_rpc_requests_received(&self, _method: &str) {} // Deprecated, use RPC_REQUESTS_TOTAL
    fn set_node_state(&self, state_name: &str) {
        for state in &["Initializing", "Syncing", "Synced"] {
            get_metric!(NETWORK_NODE_STATE)
                .with_label_values(&[state])
                .set(if *state == state_name { 1.0 } else { 0.0 });
        }
    }
}
impl ConsensusMetricsSink for PrometheusSink {
    fn inc_blocks_produced(&self) {
        get_metric!(CONSENSUS_BLOCKS_PRODUCED_TOTAL).inc();
    }
    fn inc_view_changes_proposed(&self) {
        get_metric!(CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL).inc();
    }
    fn observe_tick_duration(&self, duration_secs: f64) {
        get_metric!(CONSENSUS_TICK_DURATION_SECONDS).observe(duration_secs);
    }
}
impl RpcMetricsSink for PrometheusSink {
    fn observe_request_duration(&self, route: &str, duration_secs: f64) {
        get_metric!(RPC_REQUEST_DURATION_SECONDS)
            .with_label_values(&[route])
            .observe(duration_secs);
    }
    fn inc_requests_total(&self, route: &str, status_code: u16) {
        get_metric!(RPC_REQUESTS_TOTAL)
            .with_label_values(&[route, &status_code.to_string()])
            .inc();
    }
    fn set_mempool_size(&self, size: f64) {
        get_metric!(MEMPOOL_SIZE).set(size);
    }
    fn inc_mempool_transactions_added(&self) {
        get_metric!(MEMPOOL_TRANSACTIONS_ADDED_TOTAL).inc();
    }
}

impl ErrorMetricsSink for PrometheusSink {
    fn inc_error(&self, kind: &'static str, variant: &'static str) {
        get_metric!(ERRORS_TOTAL)
            .with_label_values(&[kind, variant])
            .inc();
    }
}

impl ServiceMetricsSink for PrometheusSink {
    fn inc_capability_resolve_fail(&self, capability: &'static str) {
        get_metric!(SVC_CAPABILITY_RESOLVE_FAIL_TOTAL)
            .with_label_values(&[capability])
            .inc();
    }
    fn observe_service_dispatch_latency(&self, service_id: &'static str, duration_secs: f64) {
        get_metric!(SVC_DISPATCH_LATENCY_SECONDS)
            .with_label_values(&[service_id])
            .observe(duration_secs);
    }
}

/// Initializes all Prometheus metrics collectors and returns a static reference to the sink.
/// This function must be called only once at application startup.
#[allow(clippy::expect_used)]
pub fn install() -> Result<&'static dyn MetricsSink, prometheus::Error> {
    // This is the single point where registration can fail. We propagate the error.
    NETWORK_CONNECTED_PEERS
        .set(register_gauge!(
            "depin_sdk_network_connected_peers",
            "Current number of connected libp2p peers."
        )?)
        .expect("NETWORK_CONNECTED_PEERS static already initialized");
    MEMPOOL_SIZE
        .set(register_gauge!(
            "depin_sdk_mempool_size",
            "Current number of transactions in the mempool."
        )?)
        .expect("MEMPOOL_SIZE static already initialized");
    STORAGE_DISK_USAGE_BYTES
        .set(register_gauge!(
            "depin_sdk_storage_disk_usage_bytes",
            "Estimated total disk usage for the storage backend."
        )?)
        .expect("STORAGE_DISK_USAGE_BYTES static already initialized");
    STORAGE_REF_COUNTS
        .set(register_gauge!(
            "depin_sdk_storage_ref_counts",
            "Total number of reference counts tracked for GC."
        )?)
        .expect("STORAGE_REF_COUNTS static already initialized");
    NETWORK_NODE_STATE
        .set(register_gauge_vec!(
            "depin_sdk_network_node_state",
            "Current synchronization state of the node (1 if active, 0 otherwise).",
            &["state"]
        )?)
        .expect("NETWORK_NODE_STATE static already initialized");
    STORAGE_EPOCHS_DROPPED_TOTAL
        .set(register_int_counter!(
            "depin_sdk_storage_epochs_dropped_total",
            "Total number of sealed epochs dropped by GC."
        )?)
        .expect("STORAGE_EPOCHS_DROPPED_TOTAL static already initialized");
    STORAGE_NODES_DELETED_TOTAL
        .set(register_int_counter!(
            "depin_sdk_storage_nodes_deleted_total",
            "Total number of state tree nodes deleted by GC."
        )?)
        .expect("STORAGE_NODES_DELETED_TOTAL static already initialized");
    STORAGE_BYTES_WRITTEN_TOTAL
        .set(register_int_counter!(
            "depin_sdk_storage_bytes_written_total",
            "Total bytes written to the storage backend for new nodes."
        )?)
        .expect("STORAGE_BYTES_WRITTEN_TOTAL static already initialized");
    CONSENSUS_BLOCKS_PRODUCED_TOTAL
        .set(register_int_counter!(
            "depin_sdk_consensus_blocks_produced_total",
            "Total number of blocks produced by this node."
        )?)
        .expect("CONSENSUS_BLOCKS_PRODUCED_TOTAL static already initialized");
    CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL
        .set(register_int_counter!(
            "depin_sdk_consensus_view_changes_proposed_total",
            "Total number of view changes proposed by this node."
        )?)
        .expect("CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL static already initialized");
    MEMPOOL_TRANSACTIONS_ADDED_TOTAL
        .set(register_int_counter!(
            "depin_sdk_mempool_transactions_added_total",
            "Total transactions added to the mempool via RPC."
        )?)
        .expect("MEMPOOL_TRANSACTIONS_ADDED_TOTAL static already initialized");
    GOSSIP_MESSAGES_RECEIVED_TOTAL
        .set(register_int_counter_vec!(
            "depin_sdk_network_gossip_messages_received_total",
            "Total gossip messages received.",
            &["topic"]
        )?)
        .expect("GOSSIP_MESSAGES_RECEIVED_TOTAL static already initialized");
    RPC_REQUESTS_TOTAL
        .set(register_int_counter_vec!(
            "depin_sdk_rpc_requests_total",
            "Total RPC requests.",
            &["route", "status"]
        )?)
        .expect("RPC_REQUESTS_TOTAL static already initialized");
    CONSENSUS_TICK_DURATION_SECONDS
        .set(register_histogram!(
            "depin_sdk_consensus_tick_duration_seconds",
            "Latency of a single consensus tick.",
            exponential_buckets(0.002, 2.0, 15)?
        )?)
        .expect("CONSENSUS_TICK_DURATION_SECONDS static already initialized");
    RPC_REQUEST_DURATION_SECONDS
        .set(register_histogram_vec!(
            "depin_sdk_rpc_request_duration_seconds",
            "Latency of RPC requests.",
            &["route"],
            exponential_buckets(0.001, 2.0, 15)?
        )?)
        .expect("RPC_REQUEST_DURATION_SECONDS static already initialized");

    ERRORS_TOTAL
        .set(register_int_counter_vec!(
            "depin_sdk_errors_total",
            "Total number of errors, categorized by type and variant.",
            &["kind", "variant"]
        )?)
        .expect("ERRORS_TOTAL static already initialized");

    SVC_CAPABILITY_RESOLVE_FAIL_TOTAL
        .set(register_int_counter_vec!(
            "depin_sdk_svc_capability_resolve_fail_total",
            "Total failures to resolve a required service capability.",
            &["capability"]
        )?)
        .expect("SVC_CAPABILITY_RESOLVE_FAIL_TOTAL static already initialized");

    SVC_DISPATCH_LATENCY_SECONDS
        .set(register_histogram_vec!(
            "depin_sdk_service_dispatch_latency_seconds",
            "Latency of dispatched calls to on-chain services.",
            &["service_id"],
            exponential_buckets(0.0001, 2.0, 16)? // Start finer for service calls
        )?)
        .expect("SVC_DISPATCH_LATENCY_SECONDS static already initialized");

    static SINK: PrometheusSink = PrometheusSink;
    Ok(&SINK)
}