// Path: crates/telemetry/src/time.rs
use crate::sinks::ConsensusMetricsSink;
use std::time::Instant;

pub struct Timer<'a> {
    sink: &'a dyn ConsensusMetricsSink,
    start: Instant,
}

impl<'a> Timer<'a> {
    pub fn new(sink: &'a dyn ConsensusMetricsSink) -> Self {
        Self {
            sink,
            start: Instant::now(),
        }
    }
}

impl Drop for Timer<'_> {
    fn drop(&mut self) {
        self.sink
            .observe_tick_duration(self.start.elapsed().as_secs_f64());
    }
}
