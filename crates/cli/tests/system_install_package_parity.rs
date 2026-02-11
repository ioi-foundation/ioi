// Path: crates/cli/tests/system_install_package_parity.rs

use ioi_services::agentic::desktop::middleware::normalize_tool_call;
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
        session_id: [0x22; 32],
        goal: "install pydantic".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 7,
        max_steps: 32,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 32,
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
            app_hint: Some("terminal".to_string()),
            title_pattern: None,
        }),
        active_lens: None,
    }
}

#[test]
fn sys_install_package_normalizes_to_deterministic_sys_exec() {
    let tool = normalize_tool_call(
        r#"{"name":"sys__install_package","arguments":{"manager":"pip","package":"pydantic"}}"#,
    )
    .expect("normalization should succeed");

    match tool {
        AgentTool::SysExec {
            command,
            args,
            detach,
        } => {
            assert_eq!(command, "python");
            assert_eq!(
                args,
                vec![
                    "-m".to_string(),
                    "pip".to_string(),
                    "install".to_string(),
                    "pydantic".to_string()
                ]
            );
            assert!(!detach);
        }
        _ => panic!("expected sys__exec lowering"),
    }
}

#[test]
fn sys_install_package_rejects_unsafe_identifier() {
    let err = normalize_tool_call(
        r#"{"name":"sys__install_package","arguments":{"manager":"pip","package":"bad; rm -rf /"}}"#,
    )
    .expect_err("unsafe package names must be rejected");
    assert!(err.to_string().contains("Invalid package identifier"));
}

#[test]
fn routing_receipt_contract_for_install_package_includes_pre_state() {
    let state = test_agent_state();
    let tool = normalize_tool_call(
        r#"{"name":"sys__install_package","arguments":{"manager":"pip","package":"pydantic"}}"#,
    )
    .expect("normalization should succeed");

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "sys__exec");
    assert_eq!(args.get("command").and_then(|v| v.as_str()), Some("python"));
    assert_eq!(
        args.get("args")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.get(2))
            .and_then(|v| v.as_str()),
        Some("install")
    );

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
        "deterministic_install=true".to_string(),
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
        artifacts: vec!["trace://agent_step/7".to_string()],
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
    assert_eq!(receipt.pre_state.step_index, 7);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("terminal"));
    assert!(receipt.action_json.contains("\"command\":\"python\""));
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
    assert_eq!(receipt.policy_binding_hash, "binding-hash");
}
