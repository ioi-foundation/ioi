use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{AtomicInput, GuiDriver, InputEvent, MouseButton};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockGuiDriver {
    events: Mutex<Vec<InputEvent>>,
}

impl MockGuiDriver {
    fn take_events(&self) -> Vec<InputEvent> {
        let mut guard = self.events.lock().expect("events mutex poisoned");
        std::mem::take(&mut *guard)
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
        Ok((0, 0))
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
async fn drag_drop_id_resolves_som_centers_and_executes_atomic_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());
    let som_map = BTreeMap::from([
        (1u32, (100i32, 100i32, 50i32, 50i32)),
        (2u32, (400i32, 400i32, 100i32, 100i32)),
    ]);

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::DragDropId {
                from_id: 1,
                to_id: 2,
            }),
            [0u8; 32],
            1,
            [0u8; 32],
            Some(&som_map),
            None,
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::AtomicSequence(vec![
            AtomicInput::MouseMove { x: 125, y: 125 },
            AtomicInput::MouseDown {
                button: MouseButton::Left
            },
            AtomicInput::Wait { millis: 200 },
            AtomicInput::MouseMove { x: 450, y: 450 },
            AtomicInput::Wait { millis: 200 },
            AtomicInput::MouseUp {
                button: MouseButton::Left
            },
        ])]
    );
}

#[tokio::test]
async fn drag_drop_element_resolves_semantic_map_and_executes_atomic_sequence() {
    let gui = Arc::new(MockGuiDriver::default());
    let exec = build_executor(gui.clone());
    let som_map = BTreeMap::from([
        (7u32, (10i32, 20i32, 20i32, 20i32)),
        (9u32, (210i32, 220i32, 40i32, 60i32)),
    ]);
    let semantic_map = BTreeMap::from([
        (7u32, "file_icon".to_string()),
        (9u32, "trash_bin".to_string()),
    ]);

    let result = exec
        .execute(
            AgentTool::Computer(ComputerAction::DragDropElement {
                from_id: "file_icon".to_string(),
                to_id: "trash_bin".to_string(),
            }),
            [0u8; 32],
            2,
            [0u8; 32],
            Some(&som_map),
            Some(&semantic_map),
            None,
        )
        .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        gui.take_events(),
        vec![InputEvent::AtomicSequence(vec![
            AtomicInput::MouseMove { x: 20, y: 30 },
            AtomicInput::MouseDown {
                button: MouseButton::Left
            },
            AtomicInput::Wait { millis: 200 },
            AtomicInput::MouseMove { x: 230, y: 250 },
            AtomicInput::Wait { millis: 200 },
            AtomicInput::MouseUp {
                button: MouseButton::Left
            },
        ])]
    );
}
