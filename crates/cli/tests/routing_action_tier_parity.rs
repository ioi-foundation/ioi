// Path: crates/cli/tests/routing_action_tier_parity.rs

use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity, resolve_action_routing_context,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, failure_attempt_fingerprint, policy_binding_hash, FailureClass,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::RoutingReceiptEvent;
use serde_json::json;
use std::collections::BTreeMap;

fn action_failure_state() -> AgentState {
    AgentState {
        session_id: [0x4a; 32],
        goal: "execute routed action with tier coherence".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 12,
        max_steps: 32,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 32,
        tokens_used: 0,
        consecutive_failures: 1,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: vec![failure_attempt_fingerprint(
            FailureClass::TargetNotFound,
            "action-attempt-hash",
        )],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
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
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
    }
}

#[test]
fn action_router_applies_selected_tier_before_pre_state_snapshot() {
    let mut state = action_failure_state();

    let (routing_decision, pre_state) = resolve_action_routing_context(&mut state);

    assert_eq!(routing_decision.tier, ExecutionTier::VisualForeground);
    assert_eq!(state.current_tier, ExecutionTier::VisualForeground);
    assert_eq!(pre_state.tier, "VisualLast");
    assert_eq!(pre_state.agent_status, "Running");
    assert_eq!(pre_state.step_index, 12);
}

#[test]
fn action_routing_receipt_uses_visual_last_tier_for_pre_state_and_intent_hash() {
    let mut state = action_failure_state();
    let (routing_decision, pre_state) = resolve_action_routing_context(&mut state);

    let tool = AgentTool::Dynamic(json!({
        "name": "gui__click_element",
        "arguments": {
            "id": "btn_submit"
        }
    }));
    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "gui__click_element");

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        routing_decision.tier,
        pre_state.step_index,
        "test-v1",
    );

    let expected_payload = json!({
        "tool_name": "gui__click_element",
        "args": { "id": "btn_submit" },
        "tier": "VisualLast",
        "step_index": 12,
        "tool_version": "test-v1",
    });
    let expected_hash = sha256(&serde_jcs::to_vec(&expected_payload).unwrap())
        .map(hex::encode)
        .unwrap();
    assert_eq!(intent_hash, expected_hash);

    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "was_queue=false".to_string(),
        "routing_tier_selected=VisualLast".to_string(),
        format!(
            "routing_tier_matches_pre_state={}",
            pre_state.tier == "VisualLast"
        ),
    ];
    let post_state = build_post_state_summary(&state, true, verification_checks.clone());
    let binding = policy_binding_hash(&intent_hash, "allowed");

    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash: intent_hash.clone(),
        policy_decision: "allowed".to_string(),
        tool_name,
        tool_version: "test-v1".to_string(),
        pre_state: pre_state.clone(),
        action_json: serde_json::to_string(&tool).unwrap(),
        post_state,
        artifacts: vec!["trace://agent_step/12".to_string()],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: String::new(),
        incident_id: String::new(),
        incident_stage: String::new(),
        strategy_name: String::new(),
        strategy_node: String::new(),
        gate_state: String::new(),
        resolution_action: String::new(),
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: binding.clone(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.tier, "VisualLast");
    assert_eq!(receipt.intent_hash, expected_hash);
    assert_eq!(receipt.policy_binding_hash, binding);
    assert!(receipt
        .post_state
        .verification_checks
        .contains(&"routing_tier_matches_pre_state=true".to_string()));
}
