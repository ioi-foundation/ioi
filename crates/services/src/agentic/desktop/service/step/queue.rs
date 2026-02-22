// Path: crates/services/src/agentic/desktop/service/step/queue.rs

#[path = "queue/envelope.rs"]
mod envelope;
#[path = "queue/processing.rs"]
mod processing;
#[path = "queue/support.rs"]
mod support;

pub use processing::{process_queue_item, resolve_queue_routing_context};
pub use support::queue_action_request_to_tool;
pub(crate) use support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    constraint_grounded_probe_query_with_hints, constraint_grounded_search_limit,
    constraint_grounded_search_query, constraint_grounded_search_query_with_hints,
    is_human_challenge_error, mark_pending_web_attempted, mark_pending_web_blocked,
    merge_pending_search_completion, next_pending_web_candidate, parse_web_evidence_bundle,
    pre_read_candidate_plan_from_bundle, query_requires_runtime_locality_scope,
    queue_web_read_from_pipeline, queue_web_search_from_pipeline, remaining_pending_web_candidates,
    render_mailbox_access_limited_reply, synthesize_web_pipeline_reply,
    synthesize_web_pipeline_reply_hybrid, web_pipeline_can_queue_initial_read_latency_aware,
    web_pipeline_can_queue_probe_search_latency_aware, web_pipeline_completion_reason,
    web_pipeline_latency_pressure_label, web_pipeline_min_sources, web_pipeline_now_ms,
    web_pipeline_remaining_budget_ms, web_pipeline_required_probe_budget_ms,
    web_pipeline_required_read_budget_ms, web_pipeline_requires_metric_probe_followup,
    WebPipelineCompletionReason, WEB_PIPELINE_BUDGET_MS, WEB_PIPELINE_SEARCH_LIMIT,
};

#[cfg(test)]
#[path = "queue/tests.rs"]
mod tests;
