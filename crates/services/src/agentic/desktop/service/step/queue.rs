// Path: crates/services/src/agentic/desktop/service/step/queue.rs

#[path = "queue/processing.rs"]
mod processing;
#[path = "queue/support.rs"]
mod support;

pub use processing::{process_queue_item, resolve_queue_routing_context};
pub use support::queue_action_request_to_tool;
pub(crate) use support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    candidate_source_hints_from_bundle, candidate_urls_from_bundle, is_human_challenge_error,
    mark_pending_web_attempted, mark_pending_web_blocked, next_pending_web_candidate,
    parse_web_evidence_bundle, queue_web_read_from_pipeline, remaining_pending_web_candidates,
    render_mailbox_access_limited_reply, synthesize_web_pipeline_reply,
    synthesize_web_pipeline_reply_hybrid, web_pipeline_completion_reason, web_pipeline_now_ms,
    WebPipelineCompletionReason, WEB_PIPELINE_BUDGET_MS, WEB_PIPELINE_DEFAULT_MIN_SOURCES,
    WEB_PIPELINE_SEARCH_LIMIT,
};

#[cfg(test)]
#[path = "queue/tests.rs"]
mod tests;
