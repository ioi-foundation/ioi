// Path: crates/cli/tests/filesystem_edit_line_parity.rs

use ioi_services::agentic::desktop::execution::filesystem::edit_line_content;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::RoutingReceiptEvent;
use std::collections::BTreeMap;

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0x11; 32],
        goal: "edit a single line".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 4,
        max_steps: 32,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 16,
        tokens_used: 0,
        consecutive_failures: 0,
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
            app_hint: Some("workspace".to_string()),
            title_pattern: None,
        }),
        active_lens: None,
    }
}

#[test]
fn filesystem_atomic_line_edit_rewrites_only_target_line() {
    let original = "alpha\nbeta\ngamma\n";
    let updated = edit_line_content(original, 2, "BETA").expect("line edit should succeed");
    assert_eq!(updated, "alpha\nBETA\ngamma\n");
}

#[test]
fn filesystem_atomic_line_edit_rejects_out_of_range_line() {
    let original = "alpha\nbeta\n";
    let err = edit_line_content(original, 5, "BETA").expect_err("expected out-of-range failure");
    assert!(err.contains("out of range"));
}

#[test]
fn routing_receipt_contract_for_atomic_line_edit_includes_pre_state() {
    let state = test_agent_state();
    let tool = AgentTool::FsWrite {
        path: "/tmp/ioi/demo.txt".to_string(),
        content: "BETA".to_string(),
        line_number: Some(2),
    };

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "filesystem__write_file");
    assert_eq!(args.get("line_number").and_then(|v| v.as_u64()), Some(2));

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::DomHeadless,
        state.step_count,
        "test-v1",
    );
    assert!(!intent_hash.is_empty());

    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "line_edit=true".to_string(),
    ];
    let post_state = build_post_state_summary(&state, true, verification_checks.clone());

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
        artifacts: vec!["trace://agent_step/4".to_string()],
        failure_class: None,
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding-hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "ToolFirst");
    assert_eq!(receipt.pre_state.step_index, 4);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("workspace"));
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}
