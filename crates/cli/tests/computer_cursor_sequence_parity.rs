use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent, MouseButton};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::computer::{
    build_cursor_click_sequence, build_cursor_drag_sequence,
};
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use serde_json::Value;
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
