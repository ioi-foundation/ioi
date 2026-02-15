// Path: crates/services/src/agentic/desktop/service/step/anti_loop.rs

#[path = "anti_loop/attempts.rs"]
mod attempts;
#[path = "anti_loop/classify.rs"]
mod classify;
#[path = "anti_loop/model.rs"]
mod model;
#[path = "anti_loop/receipts.rs"]
mod receipts;
#[path = "anti_loop/routing.rs"]
mod routing;

pub use attempts::{
    attempt_key_hash, build_attempt_key, failure_attempt_fingerprint, latest_failure_class,
    register_attempt, register_failure_attempt, retry_budget_remaining,
    should_block_retry_without_change, should_trip_retry_guard, trailing_repetition_count,
};
pub use classify::{classify_failure, requires_wait_for_clarification, to_routing_failure_class};
pub use model::{
    tier_as_str, AttemptKey, FailureClass, TierRoutingDecision, RETRY_GUARD_REPEAT_LIMIT,
    RETRY_GUARD_WINDOW,
};
pub use receipts::{
    emit_routing_receipt, extract_artifacts, lineage_pointer, mutation_receipt_pointer,
    policy_binding_hash,
};
pub use routing::{
    build_post_state_summary, build_state_summary, choose_routing_tier, escalation_path_for_failure,
};

#[cfg(test)]
#[path = "anti_loop/tests.rs"]
mod tests;
