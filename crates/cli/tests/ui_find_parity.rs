// Path: crates/cli/tests/ui_find_parity.rs

use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::lenses::{auto::AutoLens, react::ReactLens, LensRegistry};
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::computer::find_semantic_ui_match;
use ioi_services::agentic::desktop::execution::ToolExecutor;
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
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::app::{RoutingFailureClass, RoutingReceiptEvent};
use ioi_types::error::VmError;
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct UiFindMockGuiDriver {
    screenshot: Vec<u8>,
}

impl UiFindMockGuiDriver {
    fn new(screenshot: Vec<u8>) -> Self {
        Self { screenshot }
    }
}

#[async_trait]
impl GuiDriver for UiFindMockGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Ok(self.screenshot.clone())
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(self.screenshot.clone())
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError(
            "capture_context is not used in this test".to_string(),
        ))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn get_cursor_position(&self) -> Result<(u32, u32), VmError> {
        Ok((0, 0))
    }
}

#[derive(Default)]
struct MockVisualRuntime {
    prompts: Mutex<Vec<String>>,
}

impl MockVisualRuntime {
    fn first_prompt(&self) -> Option<String> {
        self.prompts
            .lock()
            .expect("prompt mutex poisoned")
            .first()
            .cloned()
    }
}

#[async_trait]
impl InferenceRuntime for MockVisualRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input_context).to_string();
        self.prompts
            .lock()
            .expect("prompt mutex poisoned")
            .push(prompt.clone());

        if prompt.contains("gear icon") {
            return Ok(
                r#"{"x":120,"y":160,"confidence":0.94,"reasoning":"Found a gear icon"}"#
                    .as_bytes()
                    .to_vec(),
            );
        }

        Ok(r#"{"x":0,"y":0,"confidence":0.0,"reasoning":"not found"}"#
            .as_bytes()
            .to_vec())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_test_png(width: u32, height: u32) -> Vec<u8> {
    let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        width,
        height,
        image::Rgba([255, 255, 255, 255]),
    ));
    let mut bytes = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
        .expect("failed to encode png");
    bytes
}

#[test]
fn legacy_lens_alias_resolves_to_registered_react_lens() {
    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let resolved = registry.get("ReactLens").map(|lens| lens.name());
    assert_eq!(resolved, Some("react_semantic"));
}

#[test]
fn ui_find_primary_semantic_path_uses_aria_label_hints() {
    let mut button_attrs = HashMap::new();
    button_attrs.insert("aria-label".to_string(), "Save Draft".to_string());
    button_attrs.insert("data-testid".to_string(), "editor-save-button".to_string());

    let tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![AccessibilityNode {
            id: "button_17".to_string(),
            role: "button".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 420,
                y: 188,
                width: 132,
                height: 40,
            },
            is_visible: true,
            attributes: button_attrs,
            som_id: None,
            children: vec![],
        }],
    };

    let found = find_semantic_ui_match(&tree, "save draft")
        .expect("semantic ui__find should resolve aria-label-backed controls");
    assert_eq!(found.id.as_deref(), Some("button_17"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");

    let visual_clause = find_semantic_ui_match(&tree, "save draft icon")
        .expect("semantic ui__find should recover match with extra visual clause");
    assert_eq!(visual_clause.id.as_deref(), Some("button_17"));
    assert_eq!(visual_clause.label.as_deref(), Some("Save Draft"));
    assert_eq!(visual_clause.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_preserves_semantic_wrapper_labels() {
    let mut wrapper_attrs = HashMap::new();
    wrapper_attrs.insert("aria-label".to_string(), "Save Draft".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![AccessibilityNode {
            id: "wrapper_42".to_string(),
            role: "generic".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 420,
                y: 188,
                width: 132,
                height: 40,
            },
            is_visible: true,
            attributes: wrapper_attrs,
            som_id: None,
            children: vec![AccessibilityNode {
                id: "icon_save".to_string(),
                role: "image".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 456,
                    y: 196,
                    width: 16,
                    height: 16,
                },
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
                children: vec![],
            }],
        }],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should keep semantic wrapper node");

    let found = find_semantic_ui_match(&transformed, "save draft")
        .expect("semantic query should resolve wrapper aria-label after lens transform");
    assert_eq!(found.id.as_deref(), Some("wrapper_42"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_resolves_aria_labelledby_to_primary_control() {
    let mut target_attrs = HashMap::new();
    target_attrs.insert("data-testid".to_string(), "primary-action".to_string());
    target_attrs.insert("aria-labelledby".to_string(), "lbl_9f3".to_string());

    let mut distractor_attrs = HashMap::new();
    distractor_attrs.insert("data-testid".to_string(), "secondary-action".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![
            AccessibilityNode {
                id: "lbl_9f3".to_string(),
                role: "text".to_string(),
                name: Some("Save Draft".to_string()),
                value: None,
                rect: Rect {
                    x: 410,
                    y: 172,
                    width: 120,
                    height: 18,
                },
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
                children: vec![],
            },
            AccessibilityNode {
                id: "btn_unlabeled".to_string(),
                role: "button".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 410,
                    y: 192,
                    width: 132,
                    height: 40,
                },
                is_visible: true,
                attributes: target_attrs,
                som_id: None,
                children: vec![],
            },
            AccessibilityNode {
                id: "btn_other".to_string(),
                role: "button".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 560,
                    y: 192,
                    width: 92,
                    height: 40,
                },
                is_visible: true,
                attributes: distractor_attrs,
                som_id: None,
                children: vec![],
            },
        ],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should preserve action controls");

    let found = find_semantic_ui_match(&transformed, "save draft")
        .expect("semantic query should resolve the labelled control, not only the label text node");
    assert_eq!(found.id.as_deref(), Some("primary-action"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_prefers_control_when_name_is_generic_role_word() {
    let mut target_attrs = HashMap::new();
    target_attrs.insert("data-testid".to_string(), "publish-primary".to_string());
    target_attrs.insert("aria-labelledby".to_string(), "lbl_publish".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![
            AccessibilityNode {
                id: "lbl_publish".to_string(),
                role: "text".to_string(),
                name: Some("Publish".to_string()),
                value: None,
                rect: Rect {
                    x: 410,
                    y: 172,
                    width: 120,
                    height: 18,
                },
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
                children: vec![],
            },
            AccessibilityNode {
                id: "btn_generic_name".to_string(),
                role: "button".to_string(),
                // Many platform trees expose role words as names.
                // This should not block labelledby recovery.
                name: Some("button".to_string()),
                value: None,
                rect: Rect {
                    x: 410,
                    y: 192,
                    width: 132,
                    height: 40,
                },
                is_visible: true,
                attributes: target_attrs,
                som_id: None,
                children: vec![],
            },
        ],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should preserve action controls");

    let found = find_semantic_ui_match(&transformed, "publish")
        .expect("semantic query should resolve control with generic role-word name");
    assert_eq!(found.id.as_deref(), Some("publish-primary"));
    assert_eq!(found.label.as_deref(), Some("Publish"));
    assert_eq!(found.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_resolves_aria_labelledby_via_html_id_attribute() {
    let mut label_attrs = HashMap::new();
    label_attrs.insert("id".to_string(), "save_label".to_string());

    let mut target_attrs = HashMap::new();
    target_attrs.insert("data-testid".to_string(), "primary-action".to_string());
    target_attrs.insert("aria-labelledby".to_string(), "save_label".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![
            AccessibilityNode {
                id: "generated_label_node".to_string(),
                role: "text".to_string(),
                name: Some("Save Draft".to_string()),
                value: None,
                rect: Rect {
                    x: 410,
                    y: 172,
                    width: 120,
                    height: 18,
                },
                is_visible: true,
                attributes: label_attrs,
                som_id: None,
                children: vec![],
            },
            AccessibilityNode {
                id: "btn_unlabeled".to_string(),
                role: "button".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 410,
                    y: 192,
                    width: 132,
                    height: 40,
                },
                is_visible: true,
                attributes: target_attrs,
                som_id: None,
                children: vec![],
            },
        ],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should preserve action controls");

    let found = find_semantic_ui_match(&transformed, "save draft")
        .expect("semantic query should resolve html id-labelled control");
    assert_eq!(found.id.as_deref(), Some("primary-action"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_resolves_nested_labelledby_container_text() {
    let mut target_attrs = HashMap::new();
    target_attrs.insert("data-testid".to_string(), "primary-action".to_string());
    target_attrs.insert("aria-labelledby".to_string(), "lbl_container".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_editor".to_string(),
        role: "window".to_string(),
        name: Some("Editor".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![
            AccessibilityNode {
                id: "lbl_container".to_string(),
                role: "group".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 410,
                    y: 170,
                    width: 140,
                    height: 22,
                },
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
                children: vec![AccessibilityNode {
                    id: "lbl_text".to_string(),
                    role: "text".to_string(),
                    name: Some("Save Draft".to_string()),
                    value: None,
                    rect: Rect {
                        x: 412,
                        y: 172,
                        width: 120,
                        height: 18,
                    },
                    is_visible: true,
                    attributes: HashMap::new(),
                    som_id: None,
                    children: vec![],
                }],
            },
            AccessibilityNode {
                id: "btn_unlabeled".to_string(),
                role: "button".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 410,
                    y: 192,
                    width: 132,
                    height: 40,
                },
                is_visible: true,
                attributes: target_attrs,
                som_id: None,
                children: vec![],
            },
        ],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should preserve action controls");

    let found = find_semantic_ui_match(&transformed, "save draft")
        .expect("semantic query should resolve labelledby container text onto control");
    assert_eq!(found.id.as_deref(), Some("primary-action"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
}

#[test]
fn ui_find_react_lens_resolves_htmlfor_label_to_form_control() {
    let mut label_attrs = HashMap::new();
    label_attrs.insert("htmlFor".to_string(), "profile_email".to_string());

    let mut input_attrs = HashMap::new();
    input_attrs.insert("id".to_string(), "profile_email".to_string());
    input_attrs.insert("data-testid".to_string(), "profile-email-field".to_string());

    let raw_tree = AccessibilityNode {
        id: "window_profile".to_string(),
        role: "window".to_string(),
        name: Some("Profile".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 1200,
            height: 800,
        },
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
        children: vec![
            AccessibilityNode {
                id: "label_email".to_string(),
                role: "text".to_string(),
                name: Some("Email Address".to_string()),
                value: None,
                rect: Rect {
                    x: 380,
                    y: 220,
                    width: 150,
                    height: 22,
                },
                is_visible: true,
                attributes: label_attrs,
                som_id: None,
                children: vec![],
            },
            AccessibilityNode {
                id: "input_email".to_string(),
                role: "textbox".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 380,
                    y: 248,
                    width: 260,
                    height: 40,
                },
                is_visible: true,
                attributes: input_attrs,
                som_id: None,
                children: vec![],
            },
        ],
    };

    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let transformed = registry
        .get("ReactLens")
        .expect("react lens should be registered")
        .transform(&raw_tree)
        .expect("react lens should preserve form controls");

    let found = find_semantic_ui_match(&transformed, "email address")
        .expect("semantic query should resolve htmlFor-labelled textbox");
    assert_eq!(found.id.as_deref(), Some("profile-email-field"));
    assert_eq!(found.label.as_deref(), Some("Email Address"));
    assert_eq!(found.source, "semantic_tree");
}

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
        pending_search_completion: None,
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
        failure_class_name: String::new(),
        intent_class: String::new(),
        incident_id: String::new(),
        incident_stage: String::new(),
        strategy_name: String::new(),
        strategy_node: String::new(),
        gate_state: String::new(),
        resolution_action: String::new(),
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

#[test]
fn routing_receipt_for_ui_find_primary_success_exposes_fallback_visibility() {
    let state = test_agent_state();
    let tool = AgentTool::UiFind {
        query: "save draft".to_string(),
    };
    let (tool_name, args) = canonical_tool_identity(&tool);

    let intent_hash = canonical_intent_hash(
        &tool_name,
        &args,
        ExecutionTier::VisualForeground,
        state.step_count,
        "test-v1",
    );
    let pre_state = build_state_summary(&state);
    let verification_checks = vec![
        "routing_reason_code=primary_success".to_string(),
        "escalation_chain=ToolFirst(ui__find.semantic)".to_string(),
        "fallback_used=false".to_string(),
    ];
    let post_state = build_post_state_summary(&state, true, verification_checks.clone());
    let binding_hash = policy_binding_hash(&intent_hash, "allowed");

    let receipt = RoutingReceiptEvent {
        session_id: state.session_id,
        step_index: pre_state.step_index,
        intent_hash,
        policy_decision: "allowed".to_string(),
        tool_name,
        tool_version: "test-v1".to_string(),
        pre_state,
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
        policy_binding_hash: binding_hash,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    assert!(receipt.post_state.success);
    assert_eq!(receipt.failure_class, None);
    assert_eq!(receipt.post_state.verification_checks, verification_checks);
}

#[tokio::test]
async fn ui_find_uses_visual_locator_for_visual_queries() {
    let gui: Arc<dyn GuiDriver> = Arc::new(UiFindMockGuiDriver::new(build_test_png(320, 240)));
    let inference_runtime = Arc::new(MockVisualRuntime::default());
    let inference: Arc<dyn InferenceRuntime> = inference_runtime.clone();
    let executor = ToolExecutor::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(ioi_drivers::browser::BrowserDriver::new()),
        Arc::new(McpManager::new()),
        None,
        None,
        inference,
    )
    .with_window_context(
        Some(WindowInfo {
            title: "Settings".to_string(),
            x: 0,
            y: 0,
            width: 400,
            height: 400,
            app_name: "settings".to_string(),
        }),
        None,
        Some(ExecutionTier::VisualForeground),
    );

    let result = executor
        .execute(
            AgentTool::UiFind {
                query: "gear icon".to_string(),
            },
            [0u8; 32],
            12,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "ui__find failed: {:?}", result.error);

    let history = result.history_entry.expect("missing ui__find output");
    let payload = history
        .strip_prefix("UI find resolved: ")
        .expect("unexpected ui__find payload prefix");
    let parsed: serde_json::Value = serde_json::from_str(payload).expect("invalid JSON payload");

    assert_eq!(parsed["source"], "visual_locator");
    assert_eq!(parsed["x"], 120);
    assert_eq!(parsed["y"], 160);
    assert_eq!(parsed["query"], "gear icon");
    assert_eq!(parsed["query_is_visual"], true);
    assert_eq!(parsed["routing_reason_code"], "primary_failed_escalated");
    assert_eq!(parsed["fallback_used"], true);
    let escalation_chain = parsed["escalation_chain"]
        .as_str()
        .expect("escalation_chain should be a string");
    assert!(escalation_chain.starts_with("ToolFirst(ui__find.semantic"));
    assert!(escalation_chain.ends_with("VisualLast(ui__find.visual_locator)"));

    let prompt = inference_runtime
        .first_prompt()
        .expect("expected one inference request");
    assert!(prompt.contains("gear icon"), "prompt should include query");
    assert!(
        prompt.contains("prioritize visual matching"),
        "prompt should instruct visual matching"
    );
}
