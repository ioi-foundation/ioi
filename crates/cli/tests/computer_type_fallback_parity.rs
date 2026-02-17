use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{AtomicInput, GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary, policy_binding_hash,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::{ActionRequest, ContextSlice, RoutingReceiptEvent};
use ioi_types::error::VmError;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

struct FallbackGuiDriver {
    events: Mutex<Vec<InputEvent>>,
    fail_direct_type: bool,
    fail_atomic_type: bool,
}

impl FallbackGuiDriver {
    fn new(fail_direct_type: bool, fail_atomic_type: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_direct_type,
            fail_atomic_type,
        }
    }

    fn take_events(&self) -> Vec<InputEvent> {
        let mut guard = self.events.lock().expect("events mutex poisoned");
        std::mem::take(&mut *guard)
    }
}

#[async_trait]
impl GuiDriver for FallbackGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Ok(Vec::new())
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(Vec::new())
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError(
            "capture_context is not used in this test".to_string(),
        ))
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        let mut guard = self.events.lock().expect("events mutex poisoned");
        guard.push(event.clone());
        drop(guard);

        match event {
            InputEvent::Type { .. } if self.fail_direct_type => Err(VmError::HostError(
                "direct type injection unavailable".to_string(),
            )),
            InputEvent::AtomicSequence(_) if self.fail_atomic_type => Err(VmError::HostError(
                "atomic injection unavailable".to_string(),
            )),
            _ => Ok(()),
        }
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn get_cursor_position(&self) -> Result<(u32, u32), VmError> {
        Ok((0, 0))
    }
}

fn build_executor(gui: Arc<FallbackGuiDriver>) -> ToolExecutor {
    let gui_driver: Arc<dyn GuiDriver> = gui;
    ToolExecutor::new(
        gui_driver,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        Arc::new(McpManager::new()),
        None,
        None,
        Arc::new(MockInferenceRuntime::default()),
    )
    .with_window_context(None, None, Some(ExecutionTier::VisualForeground))
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0x65; 32],
        goal: "type into autopilot".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 11,
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
        current_tier: ExecutionTier::VisualForeground,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: Some(InteractionTarget {
            app_hint: Some("autopilot".to_string()),
            title_pattern: None,
        }),
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

#[tokio::test]
async fn gui_type_falls_back_to_atomic_sequence_when_direct_type_fails() {
    let gui = Arc::new(FallbackGuiDriver::new(true, false));
    let exec = build_executor(gui.clone());
    let text = "Ab\t\n".to_string();

    let result = exec
        .execute(
            AgentTool::GuiType { text: text.clone() },
            [0u8; 32],
            1,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![
            InputEvent::Type { text },
            InputEvent::AtomicSequence(vec![
                AtomicInput::KeyPress {
                    key: "A".to_string()
                },
                AtomicInput::KeyPress {
                    key: "b".to_string()
                },
                AtomicInput::KeyPress {
                    key: "tab".to_string()
                },
                AtomicInput::KeyPress {
                    key: "enter".to_string()
                },
            ]),
        ]
    );
}

#[tokio::test]
async fn computer_type_reports_tool_unavailable_when_direct_and_fallback_fail() {
    let gui = Arc::new(FallbackGuiDriver::new(true, true));
    let exec = build_executor(gui.clone());

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::Type {
                text: "fallback".to_string(),
            }),
            [0u8; 32],
            2,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(!result.success);
    let error = result.error.unwrap_or_default();
    assert!(error.contains("ERROR_CLASS=ToolUnavailable"));
    assert!(error.contains("Atomic typing fallback failed"));

    let events = gui.take_events();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], InputEvent::Type { text } if text == "fallback"));
    assert!(matches!(&events[1], InputEvent::AtomicSequence(_)));
}

#[test]
fn routing_receipt_contract_for_gui_type_fallback_includes_pre_state_and_binding_hash() {
    let state = test_agent_state();
    let tool = AgentTool::GuiType {
        text: "fallback".to_string(),
    };

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "gui__type");
    assert_eq!(args.get("text").and_then(|v| v.as_str()), Some("fallback"));

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
        "type_fallback=atomic_sequence".to_string(),
    ];
    let post_state = build_post_state_summary(&state, true, verification_checks.clone());
    let binding_hash = policy_binding_hash(&intent_hash, "allowed");

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
        artifacts: vec!["trace://agent_step/11".to_string()],
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
        policy_binding_hash: binding_hash.clone(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.intent_hash, intent_hash);
    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "VisualLast");
    assert_eq!(receipt.pre_state.step_index, 11);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("autopilot"));
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
    assert_eq!(receipt.policy_binding_hash, binding_hash);
}
