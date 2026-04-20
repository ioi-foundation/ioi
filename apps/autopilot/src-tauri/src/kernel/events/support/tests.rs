use super::{
    detect_clarification_preset, duplicate_noop_loop_requires_intent_clarification_from_events,
    duplicate_noop_loop_requires_intent_clarification_from_history,
    explicit_clarification_preset_for_tool, ClarificationPreset,
};
use crate::models::{AgentEvent, ChatMessage, EventStatus, EventType};
use serde_json::json;

#[test]
fn detects_intent_clarification_marker() {
    let output = "System: WAIT_FOR_INTENT_CLARIFICATION. Intent confidence is too low.";
    assert!(matches!(
        detect_clarification_preset("system::intent_clarification", output),
        Some(ClarificationPreset::IntentClarification)
    ));
}

#[test]
fn detects_locality_clarification_marker() {
    let output = "System: WAIT_FOR_LOCALITY_SCOPE. Provide city/region or ZIP.";
    assert!(matches!(
        detect_clarification_preset("system::locality_clarification", output),
        Some(ClarificationPreset::IntentClarification)
    ));
}

#[test]
fn maps_explicit_intent_clarification_tools() {
    assert!(matches!(
        explicit_clarification_preset_for_tool("system::intent_clarification"),
        Some(ClarificationPreset::IntentClarification)
    ));
    assert!(matches!(
        explicit_clarification_preset_for_tool("system::locality_clarification"),
        Some(ClarificationPreset::IntentClarification)
    ));
}

fn system_message(text: &str) -> ChatMessage {
    ChatMessage {
        role: "system".to_string(),
        text: text.to_string(),
        timestamp: 0,
    }
}

#[test]
fn duplicate_noop_loop_promotes_intent_clarification_after_threshold() {
    let history = vec![
        system_message("RoutingReceipt(step=14, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
        system_message("RoutingReceipt(step=15, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
    ];
    let checks = vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ];

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_history(
            &history,
            "math__eval",
            &checks,
        )
    );
}

#[test]
fn duplicate_noop_loop_still_promotes_after_operator_turn_when_signature_repeats() {
    let history = vec![
        system_message("RoutingReceipt(step=14, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
        ChatMessage {
            role: "user".to_string(),
            text: "Please keep going.".to_string(),
            timestamp: 1,
        },
        system_message("RoutingReceipt(step=15, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
    ];
    let checks = vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ];

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_history(
            &history,
            "math__eval",
            &checks,
        )
    );
}

#[test]
fn duplicate_noop_loop_counts_across_interleaved_agent_and_tool_events() {
    let history = vec![
        system_message("RoutingReceipt(step=14, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
        ChatMessage {
            role: "agent".to_string(),
            text: "Could you share more context?".to_string(),
            timestamp: 1,
        },
        ChatMessage {
            role: "tool".to_string(),
            text: "Skipped immediate replay of 'math__eval'.".to_string(),
            timestamp: 2,
        },
        system_message("RoutingReceipt(step=15, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"),
    ];
    let checks = vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ];

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_history(
            &history,
            "math__eval",
            &checks,
        )
    );
}

#[test]
fn duplicate_noop_loop_counts_receipts_from_persisted_events() {
    let events = vec![
        AgentEvent {
            event_id: "evt-system".to_string(),
            timestamp: "2026-04-04T00:00:00Z".to_string(),
            thread_id: "thread".to_string(),
            step_index: 14,
            event_type: EventType::InfoNote,
            title: "System update: ExecutionContract".to_string(),
            digest: json!({}),
            details: json!({}),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        },
        AgentEvent {
            event_id: "evt-receipt-1".to_string(),
            timestamp: "2026-04-04T00:00:01Z".to_string(),
            thread_id: "thread".to_string(),
            step_index: 14,
            event_type: EventType::Receipt,
            title: "Receipt: math__eval (allowed)".to_string(),
            digest: json!({}),
            details: json!({
                "receipt_summary": "RoutingReceipt(step=14, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"
            }),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        },
        AgentEvent {
            event_id: "evt-tool".to_string(),
            timestamp: "2026-04-04T00:00:02Z".to_string(),
            thread_id: "thread".to_string(),
            step_index: 15,
            event_type: EventType::CommandRun,
            title: "Ran math__eval".to_string(),
            digest: json!({}),
            details: json!({}),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        },
        AgentEvent {
            event_id: "evt-receipt-2".to_string(),
            timestamp: "2026-04-04T00:00:03Z".to_string(),
            thread_id: "thread".to_string(),
            step_index: 15,
            event_type: EventType::Receipt,
            title: "Receipt: math__eval (allowed)".to_string(),
            digest: json!({}),
            details: json!({
                "receipt_summary": "RoutingReceipt(step=15, tier=ToolFirst, tool=math__eval, decision=allowed, verify=[invalid_tool_call_repair_attempted=true, duplicate_action_fingerprint_prior_success_noop=true, duplicate_action_fingerprint_non_command_skipped=true])"
            }),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        },
    ];
    let checks = vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ];

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_events(
            &events,
            "math__eval",
            &checks,
        )
    );
}
