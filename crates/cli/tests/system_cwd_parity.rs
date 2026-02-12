use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::system::handle;
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{sleep, Duration};

struct NoOpGui;

#[async_trait]
impl GuiDriver for NoOpGui {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("NoOpGui".into()))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

fn create_executor() -> ToolExecutor {
    ToolExecutor::new(
        Arc::new(NoOpGui),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        Arc::new(McpManager::new()),
        None,
        None,
        Arc::new(MockInferenceRuntime::default()),
    )
}

#[tokio::test]
async fn sys_change_dir_resolves_absolute_path() {
    let dir = tempdir().expect("tempdir should be created");
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).expect("subdir should be created");

    let exec = create_executor();
    let result = handle(
        &exec,
        AgentTool::SysChangeDir {
            path: "subdir".to_string(),
        },
        dir.path().to_str().expect("tempdir path should be utf-8"),
    )
    .await;

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        result.history_entry,
        Some(
            subdir
                .canonicalize()
                .expect("subdir should canonicalize")
                .to_string_lossy()
                .to_string()
        )
    );
}

#[tokio::test]
async fn sys_exec_respects_cwd() {
    let dir = tempdir().expect("tempdir should be created");
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).expect("subdir should be created");

    let exec = create_executor();
    let marker = "cwd_marker.txt";
    let (command, args) = if cfg!(target_os = "windows") {
        (
            "cmd".to_string(),
            vec!["/C".to_string(), format!("echo from_subdir>{}", marker)],
        )
    } else {
        (
            "sh".to_string(),
            vec!["-c".to_string(), format!("echo from_subdir > {}", marker)],
        )
    };

    let result = handle(
        &exec,
        AgentTool::SysExec {
            command,
            args,
            detach: true,
        },
        subdir.to_str().expect("subdir path should be utf-8"),
    )
    .await;

    assert!(result.success, "{:?}", result.error);
    let subdir_marker = subdir.join(marker);
    let root_marker = dir.path().join(marker);
    for _ in 0..100 {
        if subdir_marker.exists() {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    assert!(subdir_marker.exists(), "marker file should exist in subdir");
    assert!(
        !root_marker.exists(),
        "marker file should not exist in root"
    );
}
