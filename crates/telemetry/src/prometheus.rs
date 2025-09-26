// Path: crates/telemetry/src/prometheus.rs
//! A concrete implementation of the metrics sinks using the Prometheus crate.

use crate::sinks::*;
use once_cell::sync::Lazy;
use prometheus::{
    exponential_buckets, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, register_int_counter, register_int_counter_vec, Gauge, GaugeVec,
    Histogram, HistogramVec, IntCounter, IntCounterVec,
};

// --- Metric Definitions ---

// GAUGE (no _total suffix)
static NETWORK_CONNECTED_PEERS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "depin_sdk_network_connected_peers",
        "Current number of connected libp2p peers."
    )
    .unwrap()
});
static MEMPOOL_SIZE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "depin_sdk_mempool_size",
        "Current number of transactions in the mempool."
    )
    .unwrap()
});
static STORAGE_DISK_USAGE_BYTES: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "depin_sdk_storage_disk_usage_bytes",
        "Estimated total disk usage for the storage backend."
    )
    .unwrap()
});
static STORAGE_REF_COUNTS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "depin_sdk_storage_ref_counts",
        "Total number of reference counts tracked for GC."
    )
    .unwrap()
});
static NETWORK_NODE_STATE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "depin_sdk_network_node_state",
        "Current synchronization state of the node (1 if active, 0 otherwise).",
        &["state"]
    )
    .unwrap()
});

// COUNTER (correctly uses _total suffix)
static STORAGE_EPOCHS_DROPPED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_storage_epochs_dropped_total",
        "Total number of sealed epochs dropped by GC."
    )
    .unwrap()
});
static STORAGE_NODES_DELETED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_storage_nodes_deleted_total",
        "Total number of state tree nodes deleted by GC."
    )
    .unwrap()
});
static STORAGE_BYTES_WRITTEN_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_storage_bytes_written_total",
        "Total bytes written to the storage backend for new nodes."
    )
    .unwrap()
});
static CONSENSUS_BLOCKS_PRODUCED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_consensus_blocks_produced_total",
        "Total number of blocks produced by this node."
    )
    .unwrap()
});
static CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_consensus_view_changes_proposed_total",
        "Total number of view changes proposed by this node."
    )
    .unwrap()
});
static MEMPOOL_TRANSACTIONS_ADDED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "depin_sdk_mempool_transactions_added_total",
        "Total transactions added to the mempool via RPC."
    )
    .unwrap()
});
static GOSSIP_MESSAGES_RECEIVED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "depin_sdk_network_gossip_messages_received_total",
        "Total gossip messages received.",
        &["topic"]
    )
    .unwrap()
});
static RPC_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "depin_sdk_rpc_requests_total",
        "Total RPC requests.",
        &["route", "status"]
    )
    .unwrap()
});

// HISTOGRAM (uses unit suffix like _seconds)
static CONSENSUS_TICK_DURATION_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "depin_sdk_consensus_tick_duration_seconds",
        "Latency of a single consensus tick.",
        exponential_buckets(0.002, 2.0, 15).unwrap()
    )
    .unwrap()
});
static RPC_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "depin_sdk_rpc_request_duration_seconds",
        "Latency of RPC requests.",
        &["route"],
        exponential_buckets(0.001, 2.0, 15).unwrap()
    )
    .unwrap()
});

#[derive(Debug, Clone, Copy)]
pub struct PrometheusSink;

impl StorageMetricsSink for PrometheusSink {
    fn inc_epochs_dropped(&self, count: u64) {
        STORAGE_EPOCHS_DROPPED_TOTAL.inc_by(count);
    }
    fn inc_nodes_deleted(&self, count: u64) {
        STORAGE_NODES_DELETED_TOTAL.inc_by(count);
    }
    fn inc_bytes_written_total(&self, bytes: u64) {
        STORAGE_BYTES_WRITTEN_TOTAL.inc_by(bytes);
    }
    fn set_disk_usage_bytes(&self, bytes: u64) {
        STORAGE_DISK_USAGE_BYTES.set(bytes as f64);
    }
    fn set_total_ref_counts(&self, count: u64) {
        STORAGE_REF_COUNTS.set(count as f64);
    }
}
impl NetworkMetricsSink for PrometheusSink {
    fn inc_connected_peers(&self) {
        NETWORK_CONNECTED_PEERS.inc();
    }
    fn dec_connected_peers(&self) {
        NETWORK_CONNECTED_PEERS.dec();
    }
    fn inc_gossip_messages_received(&self, topic: &str) {
        GOSSIP_MESSAGES_RECEIVED_TOTAL
            .with_label_values(&[topic])
            .inc();
    }
    fn inc_rpc_requests_received(&self, _method: &str) {} // Deprecated, use RPC_REQUESTS_TOTAL
    fn set_node_state(&self, state_name: &str) {
        for state in &["Initializing", "Syncing", "Synced"] {
            NETWORK_NODE_STATE
                .with_label_values(&[state])
                .set(if *state == state_name { 1.0 } else { 0.0 });
        }
    }
}
impl ConsensusMetricsSink for PrometheusSink {
    fn inc_blocks_produced(&self) {
        CONSENSUS_BLOCKS_PRODUCED_TOTAL.inc();
    }
    fn inc_view_changes_proposed(&self) {
        CONSENSUS_VIEW_CHANGES_PROPOSED_TOTAL.inc();
    }
    fn observe_tick_duration(&self, duration_secs: f64) {
        CONSENSUS_TICK_DURATION_SECONDS.observe(duration_secs);
    }
}
impl RpcMetricsSink for PrometheusSink {
    fn observe_request_duration(&self, route: &str, duration_secs: f64) {
        RPC_REQUEST_DURATION_SECONDS
            .with_label_values(&[route])
            .observe(duration_secs);
    }
    fn inc_requests_total(&self, route: &str, status_code: u16) {
        RPC_REQUESTS_TOTAL
            .with_label_values(&[route, &status_code.to_string()])
            .inc();
    }
    fn set_mempool_size(&self, size: f64) {
        MEMPOOL_SIZE.set(size);
    }
    fn inc_mempool_transactions_added(&self) {
        MEMPOOL_TRANSACTIONS_ADDED_TOTAL.inc();
    }
}

pub fn install() -> &'static dyn MetricsSink {
    static SINK: PrometheusSink = PrometheusSink;
    &SINK
}
