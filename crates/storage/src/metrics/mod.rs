// Path: crates/storage/src/metrics.rs
use depin_sdk_telemetry::sinks::{NopSink, StorageMetricsSink};
use once_cell::sync::OnceCell;

static NOP_SINK: NopSink = NopSink;
pub static SINK: OnceCell<&'static dyn StorageMetricsSink> = OnceCell::new();

pub fn metrics() -> &'static dyn StorageMetricsSink {
    SINK.get().copied().unwrap_or(&NOP_SINK)
}