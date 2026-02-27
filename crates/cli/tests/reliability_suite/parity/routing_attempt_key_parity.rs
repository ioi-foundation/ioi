// Path: crates/cli/tests/routing_attempt_key_parity.rs

use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, escalation_path_for_failure,
    register_failure_attempt, retry_budget_remaining, should_block_retry_without_change,
    to_routing_failure_class, FailureClass,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{RoutingFailureClass, RoutingReceiptEvent};
use serde_json::json;
use std::collections::BTreeMap;

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0xAB; 32],
        goal: "retry parity".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 7,
        max_steps: 16,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 5,
        tokens_used: 0,
        consecutive_failures: 1,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_visual_hash: None,
        recent_actions: vec![],
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
        command_history: Default::default(),
        active_lens: None,
        pending_search_completion: None,
    }
}

#[test]
fn stable_attempt_key_enforces_changed_condition_and_preserves_receipt_state() {
    let mut state = test_agent_state();

    let stable_key = build_attempt_key(
        "feedface",
        ExecutionTier::DomHeadless,
        "sys__exec",
        Some("btn_equals"),
        Some("ff00ff00"),
    );
    let (first_repeat, key_hash_first) =
        register_failure_attempt(&mut state, FailureClass::TargetNotFound, &stable_key);
    let (second_repeat, key_hash_second) =
        register_failure_attempt(&mut state, FailureClass::TargetNotFound, &stable_key);

    assert_eq!(first_repeat, 1);
    assert_eq!(second_repeat, 2);
    assert_eq!(key_hash_first, key_hash_second);
    assert!(should_block_retry_without_change(
        FailureClass::TargetNotFound,
        second_repeat
    ));
    assert_eq!(retry_budget_remaining(second_repeat), 1);

    let changed_condition_key = build_attempt_key(
        "feedface",
        ExecutionTier::VisualBackground,
        "sys__exec",
        Some("btn_equals"),
        Some("ff00ff00"),
    );
    let (repeat_after_change, _) = register_failure_attempt(
        &mut state,
        FailureClass::TargetNotFound,
        &changed_condition_key,
    );
    assert_eq!(repeat_after_change, 1);

    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        format!("attempt_repeat_count={}", second_repeat),
        format!("attempt_key_hash={}", key_hash_second),
        format!(
            "attempt_retry_budget_remaining={}",
            retry_budget_remaining(second_repeat)
        ),
        "attempt_retry_blocked_without_change=true".to_string(),
    ];
    let post_state = build_post_state_summary(&state, false, verification_checks.clone());
    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash: "feedface".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "sys__exec".to_string(),
        tool_version: "test".to_string(),
        pre_state: pre_state.clone(),
        action_json: "{\"name\":\"sys__exec\"}".to_string(),
        post_state,
        artifacts: vec!["trace://agent_step/7".to_string()],
        failure_class: Some(to_routing_failure_class(FailureClass::TargetNotFound)),
        failure_class_name: String::new(),
        intent_class: String::new(),
        incident_id: String::new(),
        incident_stage: String::new(),
        strategy_name: String::new(),
        strategy_node: String::new(),
        gate_state: String::new(),
        resolution_action: String::new(),
        stop_condition_hit: true,
        escalation_path: Some(
            escalation_path_for_failure(FailureClass::TargetNotFound).to_string(),
        ),
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.tier, "ToolFirst");
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("calculator"));
    assert_eq!(
        receipt.failure_class,
        Some(RoutingFailureClass::TargetNotFound)
    );
    assert!(receipt.stop_condition_hit);
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}

#[test]
fn stable_attempt_key_for_resume_or_queue_blocks_unchanged_retry_and_resets_on_window_change() {
    let mut state = test_agent_state();

    let stable_resume_like_key = build_attempt_key(
        "resume_intent_hash",
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("calculator"),
        Some("window_a"),
    );

    let (first_repeat, first_hash) = register_failure_attempt(
        &mut state,
        FailureClass::NonDeterministicUI,
        &stable_resume_like_key,
    );
    let (second_repeat, second_hash) = register_failure_attempt(
        &mut state,
        FailureClass::NonDeterministicUI,
        &stable_resume_like_key,
    );

    assert_eq!(first_repeat, 1);
    assert_eq!(second_repeat, 2);
    assert_eq!(first_hash, second_hash);
    assert!(should_block_retry_without_change(
        FailureClass::NonDeterministicUI,
        second_repeat
    ));
    assert_eq!(retry_budget_remaining(second_repeat), 1);

    let changed_window_key = build_attempt_key(
        "resume_intent_hash",
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("calculator"),
        Some("window_b"),
    );
    let (repeat_after_window_change, _) = register_failure_attempt(
        &mut state,
        FailureClass::NonDeterministicUI,
        &changed_window_key,
    );
    assert_eq!(repeat_after_window_change, 1);
}

#[test]
fn canonical_intent_hash_uses_jcs_payload_contract() {
    let tool = AgentTool::Dynamic(json!({
        "name": "gui__click_element",
        "arguments": {
            "id": "btn_submit",
            "retry": 1
        }
    }));

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "gui__click_element");

    let hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::VisualForeground,
        12,
        "test-v1",
    );

    let expected_payload = json!({
        "tool_name": "gui__click_element",
        "args": {
            "id": "btn_submit",
            "retry": 1
        },
        "tier": "VisualLast",
        "step_index": 12,
        "tool_version": "test-v1",
    });
    let expected_hash = sha256(&serde_jcs::to_vec(&expected_payload).unwrap())
        .map(hex::encode)
        .unwrap();
    assert_eq!(hash, expected_hash);

    let same_args_different_order = json!({
        "retry": 1,
        "id": "btn_submit"
    });
    let reordered_hash = canonical_intent_hash(
        &tool_name,
        &same_args_different_order,
        ExecutionTier::VisualForeground,
        12,
        "test-v1",
    );
    assert_eq!(hash, reordered_hash);

    let tier_changed =
        canonical_intent_hash(&tool_name, &args, ExecutionTier::DomHeadless, 12, "test-v1");
    assert_ne!(hash, tier_changed);
}

#[test]
fn retry_intent_hash_is_stable_across_steps_for_attempt_dedupe() {
    let args = json!({
        "id": "btn_submit",
        "retry": 1
    });

    let step_12_intent = canonical_intent_hash(
        "gui__click_element",
        &args,
        ExecutionTier::VisualForeground,
        12,
        "test-v1",
    );
    let step_13_intent = canonical_intent_hash(
        "gui__click_element",
        &args,
        ExecutionTier::VisualForeground,
        13,
        "test-v1",
    );
    assert_ne!(step_12_intent, step_13_intent);

    let retry_hash = canonical_retry_intent_hash(
        "gui__click_element",
        &args,
        ExecutionTier::VisualForeground,
        "test-v1",
    );
    assert!(!retry_hash.is_empty());

    let mut legacy_state = test_agent_state();
    let legacy_key_step_12 = build_attempt_key(
        &step_12_intent,
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("btn_submit"),
        Some("window_a"),
    );
    let (legacy_first_repeat, _) = register_failure_attempt(
        &mut legacy_state,
        FailureClass::TargetNotFound,
        &legacy_key_step_12,
    );
    let legacy_key_step_13 = build_attempt_key(
        &step_13_intent,
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("btn_submit"),
        Some("window_a"),
    );
    let (legacy_second_repeat, _) = register_failure_attempt(
        &mut legacy_state,
        FailureClass::TargetNotFound,
        &legacy_key_step_13,
    );
    assert_eq!(legacy_first_repeat, 1);
    assert_eq!(legacy_second_repeat, 1);

    let mut stable_state = test_agent_state();
    let stable_key_step_12 = build_attempt_key(
        &retry_hash,
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("btn_submit"),
        Some("window_a"),
    );
    let (stable_first_repeat, _) = register_failure_attempt(
        &mut stable_state,
        FailureClass::TargetNotFound,
        &stable_key_step_12,
    );
    let stable_key_step_13 = build_attempt_key(
        &retry_hash,
        ExecutionTier::VisualForeground,
        "gui__click_element",
        Some("btn_submit"),
        Some("window_a"),
    );
    let (stable_second_repeat, _) = register_failure_attempt(
        &mut stable_state,
        FailureClass::TargetNotFound,
        &stable_key_step_13,
    );
    assert_eq!(stable_first_repeat, 1);
    assert_eq!(stable_second_repeat, 2);
    assert!(should_block_retry_without_change(
        FailureClass::TargetNotFound,
        stable_second_repeat
    ));
}
