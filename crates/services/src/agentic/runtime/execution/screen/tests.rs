use super::*;
use crate::agentic::runtime::types::ExecutionTier;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::{AgentTool, ScreenAction};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct RecordingGuiDriver {
    injected: Mutex<Vec<InputEvent>>,
    tree_xml: Mutex<Option<String>>,
}

impl RecordingGuiDriver {
    fn take_events(&self) -> Vec<InputEvent> {
        let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }

    fn with_tree_xml(xml: impl Into<String>) -> Self {
        Self {
            injected: Mutex::new(Vec::new()),
            tree_xml: Mutex::new(Some(xml.into())),
        }
    }
}

#[async_trait]
impl GuiDriver for RecordingGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("capture_screen not implemented".into()))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "capture_raw_screen not implemented".into(),
        ))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        if let Some(xml) = self
            .tree_xml
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            Ok(xml)
        } else {
            Err(VmError::HostError("capture_tree not implemented".into()))
        }
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("capture_context not implemented".into()))
    }

    async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
        let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(event);
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

struct TestOsDriver {
    active_window: Option<WindowInfo>,
}

#[async_trait]
impl OsDriver for TestOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(self.active_window.as_ref().map(|w| w.title.clone()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(self.active_window.clone())
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

fn browser_window() -> WindowInfo {
    WindowInfo {
        title: "Google Chrome".to_string(),
        app_name: "chrome".to_string(),
        x: 10,
        y: 20,
        width: 300,
        height: 200,
    }
}

fn build_executor(
    gui: Arc<RecordingGuiDriver>,
    active_window: Option<WindowInfo>,
    tier: ExecutionTier,
) -> ToolExecutor {
    let os: Arc<dyn OsDriver> = Arc::new(TestOsDriver {
        active_window: active_window.clone(),
    });
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let mcp = Arc::new(McpManager::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime::default());

    ToolExecutor::new(gui, os, terminal, browser, mcp, None, None, inference, None)
        .with_window_context(active_window, None, Some(tier))
}

#[test]
fn raw_coordinate_click_skips_tree_fetch_without_grounding_context() {
    let empty_som_map = BTreeMap::new();
    let empty_semantic_map = BTreeMap::new();

    assert!(!dispatch::should_try_coordinate_semantic_override(
        true, None, None, None
    ));
    assert!(!dispatch::should_try_coordinate_semantic_override(
        true,
        Some(&empty_som_map),
        Some(&empty_semantic_map),
        None
    ));
}

#[test]
fn coordinate_click_uses_tree_fetch_when_grounding_is_required() {
    let som_map = BTreeMap::from([(42u32, (600, 600, 40, 40))]);
    let semantic_map = BTreeMap::from([(42u32, "submit".to_string())]);

    assert!(dispatch::should_try_coordinate_semantic_override(
        false, None, None, None
    ));
    assert!(dispatch::should_try_coordinate_semantic_override(
        true,
        Some(&som_map),
        None,
        None
    ));
    assert!(dispatch::should_try_coordinate_semantic_override(
        true,
        None,
        Some(&semantic_map),
        None
    ));
    assert!(dispatch::should_try_coordinate_semantic_override(
        true,
        None,
        None,
        Some("auto")
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn gui_scroll_is_allowed_outside_visual_foreground() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(gui.clone(), None, ExecutionTier::VisualBackground);

    let result = handle(
        &exec,
        AgentTool::GuiScroll {
            delta_x: 12,
            delta_y: 340,
        },
        None,
        None,
        None,
    )
    .await;

    assert!(result.success);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::Scroll { dx: 12, dy: 340 }]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gui_snapshot_prefers_driver_capture_tree() {
    let gui = Arc::new(RecordingGuiDriver::with_tree_xml(
        "<window id=\"fixture\" name=\"Fixture\" />",
    ));
    let exec = build_executor(gui, None, ExecutionTier::VisualBackground);

    let result = handle(&exec, AgentTool::GuiSnapshot {}, None, None, None).await;

    assert!(result.success);
    assert_eq!(
        result.history_entry.as_deref(),
        Some("<window id=\"fixture\" name=\"Fixture\" />")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn gui_click_inside_browser_window_is_blocked_phase0() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::GuiClick {
            x: 50,
            y: 50,
            button: Some("left".to_string()),
        },
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn gui_click_outside_browser_window_is_allowed() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::GuiClick {
            x: 600,
            y: 600,
            button: Some("left".to_string()),
        },
        None,
        None,
        None,
    )
    .await;

    assert!(result.success);
    assert_eq!(gui.take_events().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn computer_left_click_without_coordinate_is_blocked_when_browser_active() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::Screen(ScreenAction::LeftClick { coordinate: None }),
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn gui_click_element_is_blocked_when_browser_active_and_target_unresolved() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::GuiClickElement {
            id: "btn_submit".to_string(),
        },
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn computer_right_click_element_is_blocked_when_browser_active_and_target_unresolved() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::Screen(ScreenAction::RightClickElement {
            id: "btn_context_menu".to_string(),
        }),
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn computer_drag_drop_with_coordinate_inside_browser_is_blocked() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::Screen(ScreenAction::DragDrop {
            from: [50, 60],
            to: [600, 600],
        }),
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn computer_drag_drop_id_is_blocked_when_browser_active_and_target_unresolved() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );

    let result = handle(
        &exec,
        AgentTool::Screen(ScreenAction::DragDropId {
            from_id: 111,
            to_id: 222,
        }),
        None,
        None,
        None,
    )
    .await;

    assert!(!result.success);
    let err = result.error.unwrap_or_default();
    assert!(err.contains("ERROR_CLASS=TierViolation"));
    assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
    assert!(gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn computer_right_click_element_outside_browser_is_allowed() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(
        gui.clone(),
        Some(browser_window()),
        ExecutionTier::VisualForeground,
    );
    let som_map = BTreeMap::from([(42u32, (600, 600, 40, 40))]);

    let result = handle(
        &exec,
        AgentTool::Screen(ScreenAction::RightClickElement {
            id: "42".to_string(),
        }),
        Some(&som_map),
        None,
        None,
    )
    .await;

    assert!(result.success);
    assert!(!gui.take_events().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn gui_click_element_som_path_emits_verify_when_snapshot_unavailable() {
    let gui = Arc::new(RecordingGuiDriver::default());
    let exec = build_executor(gui.clone(), None, ExecutionTier::VisualBackground);
    let som_map = BTreeMap::from([(42u32, (600, 600, 40, 40))]);

    let result = handle(
        &exec,
        AgentTool::GuiClickElement {
            id: "42".to_string(),
        },
        Some(&som_map),
        None,
        None,
    )
    .await;

    assert!(result.success);
    let history = result.history_entry.unwrap_or_default();
    assert!(history.contains("verify="));
    assert!(history.contains("\"snapshot\":\"unavailable\""));
    assert!(!gui.take_events().is_empty());
}
