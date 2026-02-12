// Path: crates/cli/tests/routing_queue_tier_parity.rs

use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, failure_attempt_fingerprint, policy_binding_hash, FailureClass,
};
use ioi_services::agentic::desktop::service::step::queue::{
    queue_action_request_to_tool, resolve_queue_routing_context,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionRequest, ActionTarget, RoutingReceiptEvent};
use serde_json::json;
use std::collections::BTreeMap;

fn queue_failure_state() -> AgentState {
    AgentState {
        session_id: [0x33; 32],
        goal: "drain queue with tier coherence".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 9,
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
            "queue-attempt-hash",
        )],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![ActionRequest {
            target: ActionTarget::Custom("gui__click_element".to_string()),
            params: serde_jcs::to_vec(&json!({ "id": "btn_submit" })).unwrap(),
            context: ioi_types::app::ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some([0x33; 32]),
                window_id: None,
            },
            nonce: 9,
        }],
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: Some(InteractionTarget {
            app_hint: Some("calculator".to_string()),
            title_pattern: None,
        }),
        working_directory: ".".to_string(),
        active_lens: None,
    }
}

#[test]
fn queue_router_applies_selected_tier_before_pre_state_snapshot() {
    let mut state = queue_failure_state();

    let (routing_decision, pre_state) = resolve_queue_routing_context(&mut state);

    assert_eq!(routing_decision.tier, ExecutionTier::VisualForeground);
    assert_eq!(state.current_tier, ExecutionTier::VisualForeground);
    assert_eq!(pre_state.tier, "VisualLast");
    assert_eq!(pre_state.agent_status, "Running");
    assert_eq!(pre_state.step_index, 9);
}

#[test]
fn queue_routing_receipt_uses_visual_last_tier_for_pre_state_and_intent_hash() {
    let mut state = queue_failure_state();
    let (routing_decision, pre_state) = resolve_queue_routing_context(&mut state);

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
        "step_index": 9,
        "tool_version": "test-v1",
    });
    let expected_hash = sha256(&serde_jcs::to_vec(&expected_payload).unwrap())
        .map(hex::encode)
        .unwrap();
    assert_eq!(intent_hash, expected_hash);

    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "was_queue=true".to_string(),
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
        artifacts: vec!["trace://agent_step/9".to_string()],
        failure_class: None,
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

#[test]
fn queue_browser_local_target_normalizes_with_local_context() {
    let request = ActionRequest {
        target: ActionTarget::BrowserNavigateLocal,
        params: serde_jcs::to_vec(&json!({
            "url": "https://example.com"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x44; 32]),
            window_id: None,
        },
        nonce: 1,
    };

    let tool = queue_action_request_to_tool(&request).expect("queue tool should normalize");
    match tool {
        AgentTool::BrowserNavigate {
            ref url,
            ref context,
        } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(context, "local");
        }
        other => panic!("expected BrowserNavigate, got {:?}", other),
    }

    assert_eq!(tool.target(), ActionTarget::BrowserNavigateLocal);
}

#[test]
fn queue_browser_target_context_feeds_routing_receipt_intent_hash() {
    let request = ActionRequest {
        target: ActionTarget::BrowserNavigateLocal,
        params: serde_jcs::to_vec(&json!({
            "url": "https://example.com",
            "context": "hermetic"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x55; 32]),
            window_id: None,
        },
        nonce: 12,
    };
    let tool = queue_action_request_to_tool(&request).expect("queue tool should normalize");
    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "browser__navigate");
    assert_eq!(args.get("context").and_then(|v| v.as_str()), Some("local"));

    let intent_hash =
        canonical_intent_hash(&tool_name, &args, ExecutionTier::DomHeadless, 12, "test-v1");
    let expected_payload = json!({
        "tool_name": "browser__navigate",
        "args": {
            "url": "https://example.com",
            "context": "local"
        },
        "tier": "ToolFirst",
        "step_index": 12,
        "tool_version": "test-v1",
    });
    let expected_hash = sha256(&serde_jcs::to_vec(&expected_payload).unwrap())
        .map(hex::encode)
        .unwrap();
    assert_eq!(intent_hash, expected_hash);

    let state = queue_failure_state();
    let pre_state =
        ioi_services::agentic::desktop::service::step::anti_loop::build_state_summary(&state);
    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash: intent_hash.clone(),
        policy_decision: "allowed".to_string(),
        tool_name,
        tool_version: "test-v1".to_string(),
        pre_state: pre_state.clone(),
        action_json: serde_json::to_string(&tool).unwrap(),
        post_state: build_post_state_summary(
            &state,
            true,
            vec!["policy_decision=allowed".to_string()],
        ),
        artifacts: vec!["trace://agent_step/9".to_string()],
        failure_class: None,
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: policy_binding_hash(&intent_hash, "allowed"),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert!(receipt.action_json.contains("\"context\":\"local\""));
    assert_eq!(
        receipt.policy_binding_hash,
        policy_binding_hash(&intent_hash, "allowed")
    );
    assert_eq!(receipt.pre_state.tier, "ToolFirst");
}

#[test]
fn queue_custom_browser_click_target_maps_selector_and_id_variants() {
    let selector_request = ActionRequest {
        target: ActionTarget::Custom("browser::click".to_string()),
        params: serde_jcs::to_vec(&json!({
            "selector": "#submit"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x66; 32]),
            window_id: None,
        },
        nonce: 3,
    };
    let selector_tool =
        queue_action_request_to_tool(&selector_request).expect("selector variant should normalize");
    match selector_tool {
        AgentTool::BrowserClick { ref selector } => {
            assert_eq!(selector, "#submit");
        }
        other => panic!("expected BrowserClick, got {:?}", other),
    }

    let id_request = ActionRequest {
        target: ActionTarget::Custom("browser::click".to_string()),
        params: serde_jcs::to_vec(&json!({
            "id": "btn_submit"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x67; 32]),
            window_id: None,
        },
        nonce: 4,
    };
    let id_tool = queue_action_request_to_tool(&id_request).expect("id variant should normalize");
    match id_tool {
        AgentTool::BrowserClickElement { ref id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_custom_browser_scroll_target_maps_to_browser_scroll_tool() {
    let request = ActionRequest {
        target: ActionTarget::Custom("browser::scroll".to_string()),
        params: serde_jcs::to_vec(&json!({
            "delta_y": 500,
            "delta_x": -20
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x71; 32]),
            window_id: None,
        },
        nonce: 10,
    };

    let tool = queue_action_request_to_tool(&request).expect("scroll variant should normalize");
    match tool {
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            assert_eq!(delta_x, -20);
            assert_eq!(delta_y, 500);
        }
        other => panic!("expected BrowserScroll, got {:?}", other),
    }
}

#[test]
fn queue_filesystem_targets_map_to_canonical_tools() {
    let read_request = ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&json!({
            "path": "Cargo.toml"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x68; 32]),
            window_id: None,
        },
        nonce: 5,
    };
    let read_tool =
        queue_action_request_to_tool(&read_request).expect("fs read target should normalize");
    match read_tool {
        AgentTool::FsRead { ref path } => assert_eq!(path, "Cargo.toml"),
        other => panic!("expected FsRead, got {:?}", other),
    }

    let write_request = ActionRequest {
        target: ActionTarget::FsWrite,
        params: serde_jcs::to_vec(&json!({
            "path": "notes.txt",
            "content": "hello"
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "macro".to_string(),
            session_id: Some([0x69; 32]),
            window_id: None,
        },
        nonce: 6,
    };
    let write_tool =
        queue_action_request_to_tool(&write_request).expect("fs write target should normalize");
    match write_tool {
        AgentTool::FsWrite {
            ref path,
            ref content,
            line_number,
        } => {
            assert_eq!(path, "notes.txt");
            assert_eq!(content, "hello");
            assert_eq!(line_number, None);
        }
        other => panic!("expected FsWrite, got {:?}", other),
    }
}
