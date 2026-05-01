use super::terminal_reply::{
    observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
};
use crate::agentic::runtime::service::tool_execution::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event_with_observation,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use ioi_types::app::KernelEvent;

pub(super) fn emit_terminal_chat_reply_receipts(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    agent_step_index: u32,
    intent_id: &str,
    summary: &str,
    verification_checks: &mut Vec<String>,
) {
    let Some(tx) = &service.event_sender else {
        return;
    };

    verification_checks.push("terminal_chat_reply_emitted=true".to_string());
    let reply_digest = ioi_crypto::algorithms::hash::sha256(summary.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    emit_completion_gate_status_event(
        service,
        session_id,
        step_index,
        intent_id,
        true,
        "queue_completion_summary_gate_passed",
    );
    verification_checks.push("cec_completion_gate_emitted=true".to_string());
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_binding",
        true,
        &format!(
            "probe_source=queue.chat_reply_binding.v1;observed_value={};evidence_type=sha256",
            reply_digest
        ),
        Some("queue.chat_reply_binding.v1"),
        Some(reply_digest.as_str()),
        Some("sha256"),
        None,
        None,
        None,
    );
    verification_checks.push("cec_postcondition_terminal_chat_reply_binding=true".to_string());
    verification_checks.push(format!("terminal_chat_reply_sha256={}", reply_digest));

    let shape_facts = observe_terminal_chat_reply_shape(summary);
    let layout_profile = terminal_chat_reply_layout_profile(&shape_facts);
    let emit_postcondition_receipt =
        |key: &str, satisfied: bool, observed_value: &str, evidence_type: &str| {
            emit_execution_contract_receipt_event_with_observation(
                service,
                session_id,
                step_index,
                intent_id,
                "postcondition",
                key,
                satisfied,
                &format!(
                    "probe_source=queue.chat_reply_shape.v1;observed_value={};evidence_type={}",
                    observed_value, evidence_type
                ),
                Some("queue.chat_reply_shape.v1"),
                Some(observed_value),
                Some(evidence_type),
                None,
                None,
                None,
            );
        };
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_layout_profile",
        true,
        &format!(
            "probe_source=queue.chat_reply_shape.v1;observed_value={};evidence_type=label",
            layout_profile.as_str()
        ),
        Some("queue.chat_reply_shape.v1"),
        Some(layout_profile.as_str()),
        Some("label"),
        None,
        None,
        None,
    );
    let story_header_count = shape_facts.story_header_count.to_string();
    emit_postcondition_receipt(
        "terminal_chat_reply_story_headers_absent",
        shape_facts.story_header_count == 0,
        story_header_count.as_str(),
        "scalar",
    );
    let comparison_label_count = shape_facts.comparison_label_count.to_string();
    emit_postcondition_receipt(
        "terminal_chat_reply_comparison_absent",
        shape_facts.comparison_label_count == 0,
        comparison_label_count.as_str(),
        "scalar",
    );
    let temporal_anchor_summary = format!(
        "run_date_present={};run_timestamp_present={}",
        shape_facts.run_date_present, shape_facts.run_timestamp_present
    );
    emit_postcondition_receipt(
        "terminal_chat_reply_temporal_anchor_floor",
        shape_facts.run_date_present && shape_facts.run_timestamp_present,
        temporal_anchor_summary.as_str(),
        "summary",
    );
    let postamble_summary = format!(
        "run_date_present={};run_timestamp_present={};overall_confidence_present={}",
        shape_facts.run_date_present,
        shape_facts.run_timestamp_present,
        shape_facts.overall_confidence_present
    );
    emit_postcondition_receipt(
        "terminal_chat_reply_postamble_floor",
        shape_facts.run_date_present
            && shape_facts.run_timestamp_present
            && shape_facts.overall_confidence_present,
        postamble_summary.as_str(),
        "summary",
    );
    verification_checks.push(format!(
        "terminal_chat_reply_layout_profile={}",
        layout_profile.as_str()
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_story_header_count={}",
        shape_facts.story_header_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_comparison_label_count={}",
        shape_facts.comparison_label_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_date_present={}",
        shape_facts.run_date_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_timestamp_present={}",
        shape_facts.run_timestamp_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_overall_confidence_present={}",
        shape_facts.overall_confidence_present
    ));
    let _ = tx.send(KernelEvent::AgentActionResult {
        session_id,
        step_index: agent_step_index,
        tool_name: "chat__reply".to_string(),
        output: summary.to_string(),
        error_class: None,
        agent_status: "Completed".to_string(),
    });
}
