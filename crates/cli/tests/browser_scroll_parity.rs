// Path: crates/cli/tests/browser_scroll_parity.rs

use ioi_api::state::{StateAccess, StateScanIter};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_services::agentic::desktop::middleware::normalize_tool_call;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary,
};
use ioi_services::agentic::desktop::service::step::queue::queue_action_request_to_tool;
use ioi_services::agentic::desktop::tools::discover_tools;
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionRequest, ActionTarget, RoutingReceiptEvent};
use ioi_types::error::StateError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0x72; 32],
        goal: "scroll in headless browser".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 11,
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
            app_hint: Some("chrome".to_string()),
            title_pattern: None,
        }),
        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
    }
}

#[test]
fn browser_scroll_tool_maps_to_browser_scroll_scope() {
    let tool = AgentTool::BrowserScroll {
        delta_x: 0,
        delta_y: 500,
    };
    assert_eq!(
        tool.target(),
        ActionTarget::Custom("browser::scroll".into())
    );
}

#[test]
fn browser_scroll_normalizer_accepts_float_json_numbers() {
    let tool = normalize_tool_call(
        r#"{"name":"browser__scroll","arguments":{"delta_x":-42.7,"delta_y":500.4}}"#,
    )
    .expect("normalization should succeed");

    match tool {
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            assert_eq!(delta_x, -42);
            assert_eq!(delta_y, 500);
        }
        other => panic!("expected BrowserScroll, got {:?}", other),
    }
}

#[test]
fn queue_browser_scroll_custom_target_maps_to_typed_tool() {
    let request = ActionRequest {
        target: ActionTarget::Custom("browser::scroll".to_string()),
        params: serde_jcs::to_vec(&serde_json::json!({
            "delta_y": 500
        }))
        .unwrap(),
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some([0x72; 32]),
            window_id: None,
        },
        nonce: 11,
    };

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            assert_eq!(delta_x, 0);
            assert_eq!(delta_y, 500);
        }
        other => panic!("expected BrowserScroll, got {:?}", other),
    }
}

#[test]
fn routing_receipt_contract_for_browser_scroll_stays_tool_first() {
    let state = test_agent_state();
    let tool = AgentTool::BrowserScroll {
        delta_x: 0,
        delta_y: 500,
    };

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "browser__scroll");
    assert_eq!(args.get("delta_y").and_then(|v| v.as_i64()), Some(500));
    assert_eq!(args.get("delta_x").and_then(|v| v.as_i64()), Some(0));

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::DomHeadless,
        state.step_count,
        "test-v1",
    );
    assert!(!intent_hash.is_empty());

    let pre_state = build_state_summary(&state);
    let verification_checks = vec!["policy_decision=allowed".to_string()];
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
        artifacts: vec!["trace://agent_step/11".to_string()],
        failure_class: None,
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding-hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.tool_name, "browser__scroll");
    assert_eq!(receipt.policy_decision, "allowed");
    assert_eq!(receipt.pre_state.tier, "ToolFirst");
}

#[tokio::test]
async fn tool_discovery_exposes_browser_scroll_in_headless_browser_context() {
    let state = MockState::default();
    let runtime = Arc::new(MockInferenceRuntime::default());

    let names: BTreeSet<String> = discover_tools(
        &state,
        None,
        "scroll down the page",
        runtime,
        ExecutionTier::DomHeadless,
        "Google Chrome",
    )
    .await
    .into_iter()
    .map(|tool| tool.name)
    .collect();

    assert!(names.contains("browser__scroll"));
}
