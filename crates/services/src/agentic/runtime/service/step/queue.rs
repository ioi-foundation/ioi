// Path: crates/services/src/agentic/runtime/service/step/queue.rs

#[path = "queue/envelope.rs"]
mod envelope;
#[path = "queue/processing/mod.rs"]
mod processing;
#[path = "queue/support/mod.rs"]
mod support;
#[path = "queue/web_pipeline.rs"]
pub(crate) mod web_pipeline;

pub(crate) use processing::handle_web_search_result;
pub use processing::{process_queue_item, resolve_queue_routing_context};
pub(crate) use support::emit_final_web_completion_contract_receipts;
pub use support::queue_action_request_to_tool;

#[cfg(test)]
#[path = "queue/tests/mod.rs"]
mod tests;
