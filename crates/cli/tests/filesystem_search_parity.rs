use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

#[derive(Default)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
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

fn build_executor() -> ToolExecutor {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    ToolExecutor::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        Arc::new(McpManager::new()),
        None,
        None,
        Arc::new(MockInferenceRuntime::default()),
    )
}

#[tokio::test]
async fn filesystem_search_finds_pattern_in_nested_files_with_filter() {
    let dir = tempdir().expect("tempdir should be created");
    let root = dir.path();
    let src = root.join("src");
    fs::create_dir(&src).expect("src dir should be created");

    fs::write(
        src.join("main.rs"),
        "fn main() { println!(\"Hello World\"); }\n",
    )
    .expect("main.rs should be written");
    fs::write(src.join("lib.rs"), "pub struct Config { pub id: String }\n")
        .expect("lib.rs should be written");
    fs::write(root.join("README.md"), "# Config\nThis describes Config.\n")
        .expect("README should be written");

    let exec = build_executor();
    let result = exec
        .execute(
            AgentTool::FsSearch {
                path: root.to_string_lossy().to_string(),
                regex: "struct\\s+Config".to_string(),
                file_pattern: Some("*.rs".to_string()),
            },
            [0u8; 32],
            1,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "search should succeed: {:?}", result.error);

    let output = result.history_entry.unwrap_or_default();
    assert!(
        output.contains("lib.rs"),
        "expected lib.rs in output: {}",
        output
    );
    assert!(
        output.contains("pub struct Config"),
        "expected matching line in output: {}",
        output
    );
    assert!(
        !output.contains("README.md"),
        "README.md should be excluded by *.rs filter: {}",
        output
    );
}

#[tokio::test]
async fn filesystem_search_respects_regex() {
    let dir = tempdir().expect("tempdir should be created");
    fs::write(
        dir.path().join("data.txt"),
        "item=123\nitem=abc\nitem=456\n",
    )
    .expect("data file should be written");

    let exec = build_executor();
    let result = exec
        .execute(
            AgentTool::FsSearch {
                path: dir.path().to_string_lossy().to_string(),
                regex: r"item=\d+".to_string(),
                file_pattern: None,
            },
            [0u8; 32],
            2,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(result.success, "search should succeed: {:?}", result.error);

    let output = result.history_entry.unwrap_or_default();
    assert!(
        output.contains("item=123"),
        "expected item=123 in {}",
        output
    );
    assert!(
        output.contains("item=456"),
        "expected item=456 in {}",
        output
    );
    assert!(
        !output.contains("item=abc"),
        "non-matching line should not appear in {}",
        output
    );
}
