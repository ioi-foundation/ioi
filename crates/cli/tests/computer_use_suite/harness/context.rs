use anyhow::{anyhow, Result};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_services::agentic::desktop::execution::ToolExecutor;
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

use super::support::{headless_for_run, now_ms};
use crate::computer_use_suite::types::SuiteConfig;

struct RecordingGuiDriver {
    browser: Arc<BrowserDriver>,
}

impl RecordingGuiDriver {
    fn new(browser: Arc<BrowserDriver>) -> Self {
        Self { browser }
    }

    fn placeholder_screen() -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("mock png encoding failed: {}", e)))?;
        Ok(bytes)
    }

    async fn browser_screen(&self) -> Result<Vec<u8>, VmError> {
        match self.browser.capture_tab_screenshot(false).await {
            Ok(bytes) => Ok(bytes),
            Err(_) => Self::placeholder_screen(),
        }
    }
}

#[async_trait]
impl GuiDriver for RecordingGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        self.browser_screen().await
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.browser_screen().await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError(
            "capture_tree not implemented in computer_use_suite".to_string(),
        ))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError(
            "capture_context not implemented in computer_use_suite".to_string(),
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

    async fn register_som_overlay(
        &self,
        _map: HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Default)]
struct StaticOsDriver {
    clipboard: Mutex<String>,
}

#[async_trait]
impl OsDriver for StaticOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("Chromium".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "Chromium".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "chromium".to_string(),
        }))
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(true)
    }

    async fn set_clipboard(&self, content: &str) -> Result<(), VmError> {
        if let Ok(mut clipboard) = self.clipboard.lock() {
            *clipboard = content.to_string();
        }
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(self
            .clipboard
            .lock()
            .map(|clipboard| clipboard.clone())
            .unwrap_or_default())
    }
}

#[derive(Clone, Default)]
struct MiniwobNoopRuntime;

#[async_trait]
impl InferenceRuntime for MiniwobNoopRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: ioi_types::app::agentic::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop runtime".to_string()))
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _model_path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_executor_with_events(
    event_sender: Option<broadcast::Sender<KernelEvent>>,
) -> (ToolExecutor, Arc<BrowserDriver>) {
    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
    let gui = Arc::new(RecordingGuiDriver::new(browser.clone()));
    let os: Arc<dyn OsDriver> = Arc::new(StaticOsDriver::default());
    let terminal = Arc::new(TerminalDriver::new());
    let mcp = Arc::new(McpManager::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MiniwobNoopRuntime);
    let executor = ToolExecutor::new(
        gui,
        os,
        terminal,
        browser.clone(),
        mcp,
        event_sender,
        None,
        inference,
        None,
    )
    .with_window_context(None, None, Some(ExecutionTier::DomHeadless));
    (executor, browser)
}

#[derive(Clone)]
pub(super) struct ToolExecutionContext {
    exec: Arc<ToolExecutor>,
    browser: Arc<BrowserDriver>,
    event_sender: broadcast::Sender<KernelEvent>,
    initial_launch_timing_ms: Arc<Mutex<Option<(u64, u64)>>>,
}

impl ToolExecutionContext {
    pub(super) async fn start(config: &SuiteConfig) -> Result<Self> {
        let headless = headless_for_run(config)?;
        let (event_sender, _) = broadcast::channel(512);
        let (exec, browser) = build_executor_with_events(Some(event_sender.clone()));
        let browser_launch_started_at_ms = now_ms();
        browser
            .launch(headless)
            .await
            .map_err(|err| anyhow!("launch Chromium: {}", err))?;
        let browser_launch_finished_at_ms = now_ms();
        Ok(Self {
            exec: Arc::new(exec),
            browser,
            event_sender,
            initial_launch_timing_ms: Arc::new(Mutex::new(Some((
                browser_launch_started_at_ms,
                browser_launch_finished_at_ms,
            )))),
        })
    }

    pub(super) fn exec(&self) -> Arc<ToolExecutor> {
        self.exec.clone()
    }

    pub(super) fn browser(&self) -> Arc<BrowserDriver> {
        self.browser.clone()
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_sender.subscribe()
    }

    pub(super) fn take_launch_timing_ms(&self) -> Option<(u64, u64)> {
        self.initial_launch_timing_ms
            .lock()
            .expect("shared launch timing mutex poisoned")
            .take()
    }

    pub(super) async fn reset_navigation_target(&self) -> Result<()> {
        self.browser
            .reset_active_page_for_navigation()
            .await
            .map_err(|err| anyhow!("reset shared browser page: {}", err))
    }

    pub(super) async fn stop(&self) {
        self.browser.stop().await;
    }
}
