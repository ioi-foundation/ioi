// Path: crates/services/src/agentic/desktop/service/step/queue.rs

#[path = "queue/processing.rs"]
mod processing;
#[path = "queue/support.rs"]
mod support;

pub use processing::{process_queue_item, resolve_queue_routing_context};
pub use support::queue_action_request_to_tool;

#[cfg(test)]
#[path = "queue/tests.rs"]
mod tests;
