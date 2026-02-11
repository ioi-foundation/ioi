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
async fn filesystem_patch_lifecycle() {
    let dir = tempdir().expect("tempdir should be created");
    let file_path = dir.path().join("code.py");
    fs::write(
        &file_path,
        "def hello():\n    print('hello world')\n    return True\n",
    )
    .expect("seed file should be written");

    let path_str = file_path.to_string_lossy().to_string();
    let exec = build_executor();

    let ambiguous = exec
        .execute(
            AgentTool::FsPatch {
                path: path_str.clone(),
                search: "hello".to_string(),
                replace: "bye".to_string(),
            },
            [0u8; 32],
            1,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;
    assert!(!ambiguous.success, "ambiguous patch should fail");
    let ambiguous_error = ambiguous.error.unwrap_or_default().to_lowercase();
    assert!(
        ambiguous_error.contains("ambiguous"),
        "expected ambiguous error, got: {}",
        ambiguous_error
    );

    let valid = exec
        .execute(
            AgentTool::FsPatch {
                path: path_str.clone(),
                search: "print('hello world')".to_string(),
                replace: "print('hello universe')".to_string(),
            },
            [0u8; 32],
            2,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;
    assert!(
        valid.success,
        "valid patch should succeed: {:?}",
        valid.error
    );

    let content = fs::read_to_string(&file_path).expect("patched file should be readable");
    assert!(content.contains("print('hello universe')"));
    assert!(!content.contains("print('hello world')"));
}

#[tokio::test]
async fn filesystem_patch_tolerates_indentation_mismatch() {
    let dir = tempdir().expect("tempdir should be created");
    let file_path = dir.path().join("code.py");
    fs::write(
        &file_path,
        "def hello():\n    print(\"Hello\")\n    return True\n",
    )
    .expect("seed file should be written");

    let exec = build_executor();
    let result = exec
        .execute(
            AgentTool::FsPatch {
                path: file_path.to_string_lossy().to_string(),
                search: "  print(\"Hello\")\n  return True".to_string(),
                replace: "    print(\"World\")\n    return False".to_string(),
            },
            [0u8; 32],
            3,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(
        result.success,
        "fuzzy indentation patch should succeed: {:?}",
        result.error
    );

    let content = fs::read_to_string(&file_path).expect("patched file should be readable");
    assert!(content.contains("    print(\"World\")"));
    assert!(content.contains("    return False"));
    assert!(!content.contains("print(\"Hello\")"));
}

#[tokio::test]
async fn filesystem_patch_prefers_exact_match_when_fuzzy_is_ambiguous() {
    let dir = tempdir().expect("tempdir should be created");
    let file_path = dir.path().join("config.toml");
    fs::write(&file_path, "key = 1\nkey =  1\n").expect("seed file should be written");

    let exec = build_executor();
    let result = exec
        .execute(
            AgentTool::FsPatch {
                path: file_path.to_string_lossy().to_string(),
                search: "key = 1".to_string(),
                replace: "key = 2".to_string(),
            },
            [0u8; 32],
            4,
            [0u8; 32],
            None,
            None,
            None,
        )
        .await;

    assert!(
        result.success,
        "exact-match patch should succeed: {:?}",
        result.error
    );

    let content = fs::read_to_string(&file_path).expect("patched file should be readable");
    assert_eq!(content, "key = 2\nkey =  1\n");
}
