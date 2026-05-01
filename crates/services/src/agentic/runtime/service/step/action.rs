// Path: crates/services/src/agentic/runtime/service/step/action.rs

#[path = "action/command_contract.rs"]
pub(crate) mod command_contract;
#[path = "action/json.rs"]
pub(crate) mod json;
#[path = "action/probe.rs"]
mod probe;
#[path = "action/processing/mod.rs"]
mod processing;
#[path = "action/refusal_eval.rs"]
mod refusal_eval;
#[path = "action/search.rs"]
mod search;
#[path = "action/support.rs"]
mod support;

pub use crate::agentic::runtime::service::actions::resume_pending_action;
pub use probe::{
    is_command_probe_intent, is_system_clock_read_intent, is_ui_capture_screenshot_intent,
    summarize_command_probe_output, summarize_structured_command_receipt_output,
    summarize_system_clock_or_plain_output, summarize_system_clock_output,
};
pub(crate) use processing::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event,
    emit_execution_contract_receipt_event_with_observation, enforce_file_write_observation,
    record_file_read_observation, record_non_command_success_receipts, resolved_intent_id,
    verified_command_probe_completion_summary,
};
pub use processing::{process_tool_output, resolve_action_routing_context};
pub(crate) use search::{is_search_results_url, search_query_from_url};
pub use support::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    execution_evidence_key, execution_evidence_key_for, execution_evidence_value,
    has_execution_evidence, has_success_condition, mark_action_fingerprint_executed_at_step,
    persist_step_evidence, persist_step_evidence_to_ledger, record_execution_evidence,
    record_execution_evidence_for, record_execution_evidence_for_value,
    record_execution_evidence_with_value, record_success_condition, success_condition_key,
    RuntimeEvidence,
};
