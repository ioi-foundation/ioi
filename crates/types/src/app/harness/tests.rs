use super::*;
use crate::app::events::{
    RoutingEffectiveToolSurface, RoutingPostStateSummary, RoutingRouteDecision, RoutingStateSummary,
};

fn routing_receipt(policy_decision: &str, gate_state: &str) -> RoutingReceiptEvent {
    RoutingReceiptEvent {
        session_id: [7; 32],
        step_index: 3,
        intent_hash: "intent-hash".to_string(),
        policy_decision: policy_decision.to_string(),
        tool_name: "shell__run".to_string(),
        tool_version: "1".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "running".to_string(),
            tier: "foreground".to_string(),
            step_index: 2,
            consecutive_failures: 0,
            target_hint: None,
        },
        action_json: "{}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "paused".to_string(),
            tier: "foreground".to_string(),
            step_index: 3,
            consecutive_failures: 0,
            success: false,
            verification_checks: vec![],
        },
        artifacts: vec![],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: "tool".to_string(),
        incident_id: "incident".to_string(),
        incident_stage: "policy".to_string(),
        strategy_name: "default".to_string(),
        strategy_node: "gate".to_string(),
        gate_state: gate_state.to_string(),
        resolution_action: "wait_for_user".to_string(),
        stop_condition_hit: false,
        escalation_path: None,
        lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "policy-binding".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
        route_decision: RoutingRouteDecision {
            route_family: "tool".to_string(),
            direct_answer_allowed: false,
            direct_answer_blockers: vec![],
            currentness_override: false,
            connector_candidate_count: 0,
            selected_provider_family: None,
            selected_provider_route_label: None,
            connector_first_preference: false,
            narrow_tool_preference: true,
            file_output_intent: false,
            artifact_output_intent: false,
            inline_visual_intent: false,
            skill_prep_required: false,
            output_intent: "tool".to_string(),
            effective_tool_surface: RoutingEffectiveToolSurface::default(),
        },
    }
}

#[test]
fn default_harness_components_have_complete_contracts() {
    let components = default_agent_harness_components();
    assert_eq!(components.len(), 20);
    assert!(components
        .iter()
        .any(|component| component.kind == HarnessComponentKind::McpProvider));
    assert!(components
        .iter()
        .any(|component| component.kind == HarnessComponentKind::McpToolCall));
    for component in components {
        assert!(component.component_id.starts_with("ioi.agent-harness."));
        assert_eq!(component.version, HARNESS_COMPONENT_VERSION_V1);
        assert_eq!(component.input_schema, HARNESS_INPUT_SCHEMA_ID);
        assert_eq!(component.output_schema, HARNESS_OUTPUT_SCHEMA_ID);
        assert_eq!(component.error_schema, HARNESS_ERROR_SCHEMA_ID);
        assert!(!component.kernel_ref.is_empty());
        assert!(!component.required_capability_scope.is_empty());
        assert!(!component.emitted_events.is_empty());
        assert!(!component.evidence.is_empty());
        assert!(component.timeout.timeout_ms > 0);
        assert!(component.retry.max_attempts >= 1);
    }
}

#[test]
fn default_harness_action_frames_are_workflow_addressable() {
    let frames = default_agent_harness_action_frames();
    assert_eq!(frames.len(), 20);
    assert!(frames.iter().all(|frame| {
        frame.workflow_id == DEFAULT_AGENT_HARNESS_WORKFLOW_ID
            && frame.workflow_hash == DEFAULT_AGENT_HARNESS_HASH
            && frame.deterministic_envelope
            && frame.node_id.starts_with("harness.")
    }));
    let tool_frame = frames
        .iter()
        .find(|frame| frame.component_kind == HarnessComponentKind::ToolCall)
        .expect("tool call frame");
    assert_eq!(tool_frame.slot_ids, vec!["slot.tool-grants"]);
}

#[test]
fn routing_receipts_map_policy_and_approval_gates() {
    let policy = default_harness_receipt_binding_for_routing(&routing_receipt("ALLOW", "None"));
    assert_eq!(policy.component_kind, HarnessComponentKind::PolicyGate);
    assert_eq!(policy.workflow_node_id, "harness.policy_gate");

    let approval = default_harness_receipt_binding_for_routing(&routing_receipt(
        "REQUIRE_APPROVAL",
        "Pending",
    ));
    assert_eq!(approval.component_kind, HarnessComponentKind::ApprovalGate);
    assert_eq!(approval.workflow_node_id, "harness.approval_gate");
    assert!(approval
        .evidence_refs
        .iter()
        .any(|item| item == "policy_decision:REQUIRE_APPROVAL"));
}

#[test]
fn tool_names_and_action_targets_componentize_native_mcp_connector_and_model_calls() {
    assert_eq!(
        harness_component_kind_for_action_target(&ActionTarget::ModelRespond),
        HarnessComponentKind::ModelCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("mcp__filesystem__read"),
        HarnessComponentKind::McpToolCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("gmail__send_email"),
        HarnessComponentKind::ConnectorCall
    );
    assert_eq!(
        harness_component_kind_for_tool_name("memory__save"),
        HarnessComponentKind::MemoryWrite
    );
    assert_eq!(
        harness_component_kind_for_tool_name("shell__run"),
        HarnessComponentKind::ToolCall
    );
}

#[test]
fn worker_binding_requires_activation_identity() {
    let binding = default_harness_worker_binding();
    validate_harness_worker_binding(&binding).expect("default binding is valid");

    let missing_activation = HarnessWorkerBinding {
        harness_activation_id: None,
        ..binding
    };
    assert_eq!(
        validate_harness_worker_binding(&missing_activation),
        Err(HarnessBindingError::MissingActivationId)
    );
}
