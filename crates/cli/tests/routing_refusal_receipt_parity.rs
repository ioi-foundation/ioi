// Path: crates/cli/tests/routing_refusal_receipt_parity.rs

use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::service::step::action::canonical_intent_hash;
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary, escalation_path_for_failure,
    policy_binding_hash, to_routing_failure_class, FailureClass,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::{RoutingFailureClass, RoutingReceiptEvent};
use serde_json::json;
use std::collections::BTreeMap;

fn refusal_state() -> AgentState {
    AgentState {
        session_id: [0x66; 32],
        goal: "handle refusal with receipt".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 5,
        max_steps: 20,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 10,
        tokens_used: 0,
        consecutive_failures: 0,
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
            app_hint: Some("browser".to_string()),
            title_pattern: None,
        }),
        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
    }
}

#[test]
fn refusal_routing_receipt_uses_canonical_intent_and_complete_pre_state() {
    let mut state = refusal_state();
    let reason = "Model refused to proceed without clarification.";
    let tool_name = "system::refusal";
    let args = json!({ "reason": reason });

    let intent_hash = canonical_intent_hash(
        tool_name,
        &args,
        ExecutionTier::VisualForeground,
        5,
        "test-v1",
    );
    let expected_payload = json!({
        "tool_name": "system::refusal",
        "args": { "reason": reason },
        "tier": "VisualLast",
        "step_index": 5,
        "tool_version": "test-v1",
    });
    let expected_hash = sha256(&serde_jcs::to_vec(&expected_payload).unwrap())
        .map(hex::encode)
        .unwrap();
    assert_eq!(intent_hash, expected_hash);

    let pre_state = build_state_summary(&state);
    state.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
    state.step_count += 1;

    let failure = FailureClass::UserInterventionNeeded;
    let verification_checks = vec![
        "policy_decision=denied".to_string(),
        "was_refusal=true".to_string(),
        "stop_condition_hit=true".to_string(),
        "routing_tier_selected=VisualLast".to_string(),
        "routing_reason_code=tool_first_default".to_string(),
        "routing_source_failure=None".to_string(),
        "routing_tier_matches_pre_state=true".to_string(),
        format!("failure_class={}", failure.as_str()),
    ];
    let post_state = build_post_state_summary(&state, false, verification_checks.clone());
    let binding = policy_binding_hash(&intent_hash, "denied");

    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash,
        policy_decision: "denied".to_string(),
        tool_name: tool_name.to_string(),
        tool_version: "test-v1".to_string(),
        pre_state: pre_state.clone(),
        action_json: serde_json::to_string(&json!({
            "name": "system::refusal",
            "arguments": { "reason": reason }
        }))
        .unwrap(),
        post_state,
        artifacts: vec!["trace://agent_step/5".to_string()],
        failure_class: Some(to_routing_failure_class(failure)),
        stop_condition_hit: true,
        escalation_path: Some(escalation_path_for_failure(failure).to_string()),
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: binding.clone(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "VisualLast");
    assert_eq!(receipt.pre_state.step_index, 5);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("browser"));
    assert_eq!(
        receipt.failure_class,
        Some(RoutingFailureClass::UserInterventionNeeded)
    );
    assert!(receipt.stop_condition_hit);
    assert!(!receipt.policy_binding_hash.is_empty());
    assert_eq!(receipt.policy_binding_hash, binding);
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}

#[test]
fn parse_failure_fallback_intent_hash_is_stable_and_non_empty() {
    let raw_output = "not-json tool output";
    let parse_error = "Failed to parse tool call: invalid format";

    let args = json!({
        "raw_tool_output": raw_output,
        "parse_error": parse_error,
    });
    let hash = canonical_intent_hash(
        "system::invalid_tool_call",
        &args,
        ExecutionTier::DomHeadless,
        3,
        "test-v1",
    );
    assert!(!hash.is_empty());

    let reordered_args = json!({
        "parse_error": parse_error,
        "raw_tool_output": raw_output,
    });
    let reordered_hash = canonical_intent_hash(
        "system::invalid_tool_call",
        &reordered_args,
        ExecutionTier::DomHeadless,
        3,
        "test-v1",
    );
    assert_eq!(hash, reordered_hash);
}
