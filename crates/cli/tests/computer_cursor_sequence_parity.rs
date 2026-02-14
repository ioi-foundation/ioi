use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{AtomicInput, GuiDriver, InputEvent, MouseButton};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::computer::{
    build_cursor_click_sequence, build_cursor_drag_sequence,
};
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_services::agentic::desktop::service::actions::checks::requires_visual_integrity;
use ioi_services::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_tool_identity,
};
use ioi_services::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, build_state_summary,
};
use ioi_services::agentic::desktop::types::{ExecutionTier, InteractionTarget};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::{ActionRequest, ContextSlice, RoutingReceiptEvent};
use ioi_types::error::VmError;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockGuiDriver {
    events: Mutex<Vec<InputEvent>>,
    cursor: Mutex<(u32, u32)>,
}

impl MockGuiDriver {
    fn take_events(&self) -> Vec<InputEvent> {
        let mut guard = self.events.lock().expect("events mutex poisoned");
        std::mem::take(&mut *guard)
    }

    fn set_cursor(&self, x: u32, y: u32) {
        let mut guard = self.cursor.lock().expect("cursor mutex poisoned");
        *guard = (x, y);
    }
}

#[async_trait]
impl GuiDriver for MockGuiDriver {
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
        guard.push(event);
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn get_cursor_position(&self) -> Result<(u32, u32), VmError> {
        let guard = self.cursor.lock().expect("cursor mutex poisoned");
        Ok(*guard)
    }
}

fn build_executor(gui: Arc<MockGuiDriver>) -> ToolExecutor {
    build_executor_with_tier(gui, ExecutionTier::VisualForeground)
}

fn build_executor_with_tier(gui: Arc<MockGuiDriver>, tier: ExecutionTier) -> ToolExecutor {
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
    .with_window_context(None, None, Some(tier))
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0x33; 32],
        goal: "open context menu".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 7,
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

#[tokio::test]
async fn left_click_without_coordinates_uses_cursor_click_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::LeftClick { coordinate: None }),
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
        vec![InputEvent::AtomicSequence(build_cursor_click_sequence(
            MouseButton::Left
        ))]
    );
}

#[tokio::test]
async fn left_click_drag_executes_cursor_drag_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());
    let target = [640u32, 360u32];

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::LeftClickDrag { coordinate: target }),
            [0u8; 32],
            2,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::AtomicSequence(build_cursor_drag_sequence(
            target
        ))]
    );
}

#[tokio::test]
async fn right_click_without_coordinates_uses_cursor_click_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::RightClick { coordinate: None }),
            [0u8; 32],
            4,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::AtomicSequence(build_cursor_click_sequence(
            MouseButton::Right
        ))]
    );
}

#[tokio::test]
async fn double_click_without_coordinates_uses_cursor_double_click_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::DoubleClick { coordinate: None }),
            [0u8; 32],
            5,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::AtomicSequence(vec![
            AtomicInput::MouseDown {
                button: MouseButton::Left
            },
            AtomicInput::Wait { millis: 50 },
            AtomicInput::MouseUp {
                button: MouseButton::Left
            },
            AtomicInput::Wait { millis: 80 },
            AtomicInput::MouseDown {
                button: MouseButton::Left
            },
            AtomicInput::Wait { millis: 50 },
            AtomicInput::MouseUp {
                button: MouseButton::Left
            },
        ])]
    );
}

#[tokio::test]
async fn right_click_coordinate_uses_som_fallback_outside_visual_last() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor_with_tier(gui.clone(), ExecutionTier::VisualBackground);
    let som_map = BTreeMap::from([(42u32, (100i32, 200i32, 40i32, 20i32))]);

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::RightClick {
                coordinate: Some([119, 209]),
            }),
            [0u8; 32],
            6,
            [0u8; 32],
            Some(&som_map),
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::Click {
            button: MouseButton::Right,
            x: 120,
            y: 210,
            expected_visual_hash: None,
        }]
    );
}

#[tokio::test]
async fn double_click_coordinate_uses_som_fallback_outside_visual_last() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor_with_tier(gui.clone(), ExecutionTier::VisualBackground);
    let som_map = BTreeMap::from([(42u32, (100i32, 200i32, 40i32, 20i32))]);

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::DoubleClick {
                coordinate: Some([119, 209]),
            }),
            [0u8; 32],
            7,
            [0u8; 32],
            Some(&som_map),
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![
            InputEvent::Click {
                button: MouseButton::Left,
                x: 120,
                y: 210,
                expected_visual_hash: None,
            },
            InputEvent::Click {
                button: MouseButton::Left,
                x: 120,
                y: 210,
                expected_visual_hash: None,
            }
        ]
    );
}

#[test]
fn right_click_actions_opt_into_visual_integrity_guard() {
    assert!(requires_visual_integrity(&AgentTool::Computer(
        ComputerAction::RightClick {
            coordinate: Some([119, 209]),
        },
    )));
    assert!(requires_visual_integrity(&AgentTool::Computer(
        ComputerAction::RightClickId { id: 42 },
    )));
    assert!(requires_visual_integrity(&AgentTool::Computer(
        ComputerAction::RightClickElement {
            id: "submit_button".to_string(),
        },
    )));
    assert!(!requires_visual_integrity(&AgentTool::Computer(
        ComputerAction::RightClick { coordinate: None },
    )));
}

#[tokio::test]
async fn right_click_element_uses_semantic_map_and_emits_right_click() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());

    let som_map = BTreeMap::from([(7u32, (100i32, 200i32, 40i32, 20i32))]);
    let semantic_map = BTreeMap::from([(7u32, "submit_button".to_string())]);

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::RightClickElement {
                id: "submit_button".to_string(),
            }),
            [0u8; 32],
            5,
            [0u8; 32],
            Some(&som_map),
            Some(&semantic_map),
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::Click {
            button: MouseButton::Right,
            x: 120,
            y: 210,
            expected_visual_hash: None,
        }]
    );
}

#[tokio::test]
async fn cursor_position_returns_structured_screen_logical_payload() {
    let gui = Arc::new(MockGuiDriver::default());
    gui.set_cursor(321, 654);
    let exec = build_executor(gui.clone());

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::CursorPosition),
            [0u8; 32],
            3,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    let output = result.history_entry.expect("missing cursor output");
    let payload = output
        .strip_prefix("Cursor position: ")
        .expect("cursor output prefix changed");
    let parsed: Value = serde_json::from_str(payload).expect("cursor payload is valid json");

    assert_eq!(parsed.get("x").and_then(|v| v.as_u64()), Some(321));
    assert_eq!(parsed.get("y").and_then(|v| v.as_u64()), Some(654));
    assert_eq!(
        parsed.get("coordinate_space").and_then(|v| v.as_str()),
        Some("ScreenLogical")
    );
    assert!(gui.take_events().is_empty());
}

#[test]
fn routing_receipt_contract_for_right_click_element_includes_pre_state() {
    let state = test_agent_state();
    let tool = AgentTool::Computer(ComputerAction::RightClickElement {
        id: "submit_button".to_string(),
    });

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "computer");
    assert_eq!(
        args.get("action").and_then(|v| v.as_str()),
        Some("right_click_element")
    );
    assert_eq!(
        args.get("id").and_then(|v| v.as_str()),
        Some("submit_button")
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
        "right_click_element=true".to_string(),
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
        policy_binding_hash: "binding-hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "VisualLast");
    assert_eq!(receipt.pre_state.step_index, 7);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("browser"));
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}

#[test]
fn routing_receipt_contract_for_coordinate_right_click_som_fallback_includes_pre_state() {
    let mut state = test_agent_state();
    state.step_count = 8;
    state.current_tier = ExecutionTier::VisualBackground;

    let tool = AgentTool::Computer(ComputerAction::RightClick {
        coordinate: Some([119, 209]),
    });

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "computer");
    assert_eq!(
        args.get("action").and_then(|v| v.as_str()),
        Some("right_click")
    );
    assert_eq!(
        args.get("coordinate")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_u64()),
        Some(119)
    );
    assert_eq!(
        args.get("coordinate")
            .and_then(|v| v.get(1))
            .and_then(|v| v.as_u64()),
        Some(209)
    );

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::VisualBackground,
        state.step_count,
        "test-v1",
    );
    assert!(!intent_hash.is_empty());

    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "som_coordinate_fallback=true".to_string(),
        "button=right".to_string(),
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
        artifacts: vec!["trace://agent_step/8".to_string()],
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
        policy_binding_hash: "binding-hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "AxFirst");
    assert_eq!(receipt.pre_state.step_index, 8);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("browser"));
    assert_eq!(receipt.failure_class, None);
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}

#[test]
fn routing_receipt_contract_for_coordinate_double_click_includes_pre_state() {
    let mut state = test_agent_state();
    state.step_count = 9;
    state.current_tier = ExecutionTier::VisualBackground;

    let tool = AgentTool::Computer(ComputerAction::DoubleClick {
        coordinate: Some([119, 209]),
    });

    let (tool_name, args) = canonical_tool_identity(&tool);
    assert_eq!(tool_name, "computer");
    assert_eq!(
        args.get("action").and_then(|v| v.as_str()),
        Some("double_click")
    );
    assert_eq!(
        args.get("coordinate")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_u64()),
        Some(119)
    );
    assert_eq!(
        args.get("coordinate")
            .and_then(|v| v.get(1))
            .and_then(|v| v.as_u64()),
        Some(209)
    );

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::VisualBackground,
        state.step_count,
        "test-v1",
    );
    assert!(!intent_hash.is_empty());

    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        "policy_decision=allowed".to_string(),
        "som_coordinate_fallback=true".to_string(),
        "click_count=2".to_string(),
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
        artifacts: vec!["trace://agent_step/9".to_string()],
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
        policy_binding_hash: "binding-hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert_eq!(receipt.pre_state.agent_status, "Running");
    assert_eq!(receipt.pre_state.tier, "AxFirst");
    assert_eq!(receipt.pre_state.step_index, 9);
    assert_eq!(receipt.pre_state.target_hint.as_deref(), Some("browser"));
    assert_eq!(receipt.failure_class, None);
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}
