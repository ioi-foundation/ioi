// Path: crates/cli/tests/ui_find_parity.rs

use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary, classify_failure, policy_binding_hash,
    to_routing_failure_class, FailureClass,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{RoutingFailureClass, RoutingReceiptEvent};
use std::collections::BTreeMap;

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0x33; 32],
        goal: "find calculator icon".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 12,
        max_steps: 32,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 64,
        tokens_used: 0,
        consecutive_failures: 1,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::VisualForeground,
        last_screen_phash: None,
        execution_queue: vec![],
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: Some(InteractionTarget {
            app_hint: Some("calculator".to_string()),
            title_pattern: None,
        }),
        active_lens: Some("ReactLens".to_string()),
    }
}

#[test]
fn ui_find_failure_class_maps_to_vision_target_not_found() {
    let err =
        "ERROR_CLASS=VisionTargetNotFound Visual localization confidence too low (0.41) for 'calculator icon'.";
    let internal = classify_failure(Some(err), "allowed");
    assert_eq!(internal, Some(FailureClass::VisionTargetNotFound));
    assert_eq!(
        internal.map(to_routing_failure_class),
        Some(RoutingFailureClass::VisionTargetNotFound)
    );
}

#[test]
fn routing_receipt_contract_for_ui_find_includes_pre_state_and_binding_hash() {
    let state = test_agent_state();
    let tool = AgentTool::UiFind {
        query: "calculator icon".to_string(),
    };

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "ui__find");
    assert_eq!(
        args.get("query").and_then(|value| value.as_str()),
        Some("calculator icon")
    );

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::VisualForeground,
        state.step_count,
        "test-v1",
    );
    assert!(!intent_hash.is_empty());

    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "routing_tier_selected=VisualLast".to_string(),
        "failure_class=VisionTargetNotFound".to_string(),
    ];
    let post_state = build_post_state_summary(&state, false, verification_checks.clone());
    let binding_hash = policy_binding_hash(&intent_hash, "allowed");

    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash,
        policy_decision: "allowed".to_string(),
        tool_name,
        tool_version: "test-v1".to_string(),
        pre_state: pre_state.clone(),
        action_json: serde_json::to_string(&tool).unwrap(),
        post_state,
        artifacts: vec!["trace://agent_step/12".to_string()],
        failure_class: Some(RoutingFailureClass::VisionTargetNotFound),
        stop_condition_hit: false,
        escalation_path: Some("Visual grounding failed; request user guidance.".to_string()),
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: binding_hash.clone(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "VisualLast");
    assert_eq!(receipt.pre_state.step_index, 12);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("calculator"));
    assert_eq!(
        receipt.failure_class,
        Some(RoutingFailureClass::VisionTargetNotFound)
    );
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
    assert!(!receipt.policy_binding_hash.is_empty());
    assert_eq!(receipt.policy_binding_hash, binding_hash);
}
