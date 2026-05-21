use super::{
    detect_clarification_preset, duplicate_noop_loop_requires_intent_clarification_from_events,
    explicit_clarification_preset_for_tool, ClarificationPreset,
};
use crate::models::{AgentEvent, EventStatus, EventType};
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

fn duplicate_noop_checks() -> Vec<String> {
    vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ]
}

fn receipt_event(step_index: u32, tool_name: &str) -> AgentEvent {
    AgentEvent {
        event_id: format!("evt-receipt-{}", step_index),
        timestamp: "2026-04-04T00:00:00Z".to_string(),
        thread_id: "thread".to_string(),
        step_index,
        event_type: EventType::Receipt,
        title: format!("Receipt: {} (allowed)", tool_name),
        digest: json!({
            "tool_name": tool_name,
        }),
        details: json!({
            "verification_checks": duplicate_noop_checks(),
        }),
        artifact_refs: Vec::new(),
        receipt_ref: None,
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    }
}

#[test]
fn duplicate_noop_loop_promotes_intent_clarification_after_threshold() {
    let events = vec![
        receipt_event(14, "math__eval"),
        receipt_event(15, "math__eval"),
    ];
    let checks = duplicate_noop_checks();

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_events(
            &events,
            "math__eval",
            &checks,
        )
    );
}

#[test]
fn duplicate_noop_loop_requires_current_typed_checks() {
    let events = vec![
        receipt_event(14, "file__read"),
        receipt_event(15, "math__eval"),
    ];
    let checks = vec![
        "invalid_tool_call_repair_attempted=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
    ];

    assert!(
        !duplicate_noop_loop_requires_intent_clarification_from_events(
            &events,
            "math__eval",
            &checks,
        )
    );
}

#[test]
fn duplicate_noop_loop_counts_across_interleaved_agent_and_tool_events() {
    let events = vec![
        receipt_event(14, "math__eval"),
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
        receipt_event(15, "math__eval"),
    ];
    let checks = duplicate_noop_checks();

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_events(
            &events,
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
            digest: json!({
                "tool_name": "math__eval",
            }),
            details: json!({
                "verification_checks": duplicate_noop_checks(),
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
            digest: json!({
                "tool_name": "math__eval",
            }),
            details: json!({
                "verification_checks": duplicate_noop_checks(),
            }),
            artifact_refs: Vec::new(),
            receipt_ref: None,
            input_refs: Vec::new(),
            status: EventStatus::Success,
            duration_ms: None,
        },
    ];
    let checks = duplicate_noop_checks();

    assert!(
        duplicate_noop_loop_requires_intent_clarification_from_events(
            &events,
            "math__eval",
            &checks,
        )
    );
}
