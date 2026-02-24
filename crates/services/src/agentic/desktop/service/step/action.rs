// Path: crates/services/src/agentic/desktop/service/step/action.rs

#[path = "action/probe.rs"]
mod probe;
#[path = "action/processing/mod.rs"]
mod processing;
#[path = "action/refusal_eval.rs"]
mod refusal_eval;
#[path = "action/resume.rs"]
mod resume;
#[path = "action/search.rs"]
mod search;
#[path = "action/support.rs"]
mod support;

pub use probe::{
    is_command_probe_intent, is_system_clock_read_intent, summarize_command_probe_output,
    summarize_system_clock_output,
};
pub use processing::{process_tool_output, resolve_action_routing_context};
pub use resume::resume_pending_action;
pub(crate) use search::{is_search_results_url, search_query_from_url};
pub use support::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    has_execution_postcondition, has_execution_receipt, is_action_fingerprint_executed,
    mark_action_fingerprint_executed, mark_execution_postcondition, mark_execution_receipt,
    postcondition_marker, receipt_marker,
};
