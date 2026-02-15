// Path: crates/services/src/agentic/desktop/service/step/action.rs

#[path = "action/processing.rs"]
mod processing;
#[path = "action/refusal_eval.rs"]
mod refusal_eval;
#[path = "action/resume.rs"]
mod resume;
#[path = "action/search.rs"]
mod search;
#[path = "action/support.rs"]
mod support;

pub use processing::{process_tool_output, resolve_action_routing_context};
pub use resume::resume_pending_action;
pub use support::{canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity};
