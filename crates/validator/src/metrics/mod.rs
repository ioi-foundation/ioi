// Path: crates/validator/src/metrics/mod.rs
use depin_sdk_telemetry::sinks::{ConsensusMetricsSink, NopSink, RpcMetricsSink};
use once_cell::sync::OnceCell;

static NOP_SINK: NopSink = NopSink;
pub static CONSENSUS_SINK: OnceCell<&'static dyn ConsensusMetricsSink> = OnceCell::new();
pub static RPC_SINK: OnceCell<&'static dyn RpcMetricsSink> = OnceCell::new();

pub fn consensus_metrics() -> &'static dyn ConsensusMetricsSink {
    CONSENSUS_SINK.get().copied().unwrap_or(&NOP_SINK)
}

pub fn rpc_metrics() -> &'static dyn RpcMetricsSink {
    RPC_SINK.get().copied().unwrap_or(&NOP_SINK)
}
