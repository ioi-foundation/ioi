// Path: crates/network/src/metrics/mod.rs
use ioi_telemetry::sinks::{NetworkMetricsSink, NopSink};
use once_cell::sync::OnceCell;

static NOP_SINK: NopSink = NopSink;
pub static SINK: OnceCell<&'static dyn NetworkMetricsSink> = OnceCell::new();

pub fn metrics() -> &'static dyn NetworkMetricsSink {
    SINK.get().copied().unwrap_or(&NOP_SINK)
}
