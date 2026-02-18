// Path: crates/services/src/agentic/desktop/execution/mod.rs

pub mod browser;
pub mod computer;
pub mod filesystem;
pub mod mcp;
pub mod resilience;
pub mod system;
pub mod web;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::Sender;

use crate::agentic::desktop::types::ExecutionTier;
use crate::agentic::pii_scrubber::PiiScrubber;
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::gui::geometry::{DisplayTransform, Point};
use ioi_drivers::gui::lenses::LensRegistry;
use ioi_drivers::gui::operator::ClickTarget;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::KernelEvent;
use serde::{Deserialize, Serialize};

pub(crate) mod workload {
    use super::ToolExecutor;
    use ioi_crypto::algorithms::hash::sha256;
    use ioi_types::app::{
        KernelEvent, WorkloadActivityEvent, WorkloadActivityKind, WorkloadReceipt,
        WorkloadReceiptEvent,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) const WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER: &str = "[REDACTED_PII]";

    fn unix_timestamp_ms_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub(crate) fn compute_workload_id(
        session_id: [u8; 32],
        step_index: u32,
        tool_name: &str,
        command_preview: &str,
    ) -> String {
        let seed = format!(
            "{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            tool_name,
            command_preview
        );
        sha256(seed.as_bytes())
            .map(hex::encode)
            .unwrap_or_else(|_| format!("{}:{}:{}", hex::encode(session_id), step_index, tool_name))
    }

    pub(crate) fn extract_error_class(error: Option<&str>) -> Option<String> {
        let msg = error?;
        let marker = "ERROR_CLASS=";
        let start = msg.find(marker)?;
        let token = msg[start + marker.len()..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    }

    pub(crate) async fn scrub_workload_text_field_for_receipt(
        exec: &ToolExecutor,
        input: &str,
    ) -> String {
        let Some(scrubber) = exec.pii_scrubber.as_ref() else {
            return input.to_string();
        };
        match scrubber.scrub(input).await {
            Ok((scrubbed, _)) => scrubbed,
            Err(_) => WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string(),
        }
    }

    pub(crate) fn emit_workload_activity(
        tx: &tokio::sync::broadcast::Sender<KernelEvent>,
        session_id: [u8; 32],
        step_index: u32,
        workload_id: String,
        kind: WorkloadActivityKind,
    ) {
        let _ = tx.send(KernelEvent::WorkloadActivity(WorkloadActivityEvent {
            session_id,
            step_index,
            workload_id,
            timestamp_ms: unix_timestamp_ms_now(),
            kind,
        }));
    }

    pub(crate) fn emit_workload_receipt(
        tx: &tokio::sync::broadcast::Sender<KernelEvent>,
        session_id: [u8; 32],
        step_index: u32,
        workload_id: String,
        receipt: WorkloadReceipt,
    ) {
        let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id,
            step_index,
            workload_id,
            timestamp_ms: unix_timestamp_ms_now(),
            receipt,
        }));
    }
}

/// Result of a single tool execution.
#[derive(Debug, Clone)]
pub struct ToolExecutionResult {
    pub success: bool,
    pub history_entry: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingDebug {
    pub transform: DisplayTransform,
    pub target: ClickTarget,
    pub resolved_point: Point,
    pub debug_image_path: String,
}

impl ToolExecutionResult {
    pub fn success(output: impl Into<String>) -> Self {
        Self {
            success: true,
            history_entry: Some(output.into()),
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            history_entry: None,
            error: Some(error.into()),
        }
    }
}

/// The main execution engine for agent tools.
///
/// It holds references to all necessary hardware drivers and dispatches
/// `AgentTool` enums to specific implementation logic.
pub struct ToolExecutor {
    pub(crate) gui: Arc<dyn GuiDriver>,
    pub(crate) os: Arc<dyn OsDriver>,
    pub(crate) terminal: Arc<TerminalDriver>,
    pub(crate) browser: Arc<BrowserDriver>,
    pub(crate) mcp: Arc<McpManager>,
    pub(crate) event_sender: Option<Sender<KernelEvent>>,
    pub(crate) lens_registry: Option<Arc<LensRegistry>>,
    pub(crate) inference: Arc<dyn InferenceRuntime>,
    pub(crate) pii_scrubber: Option<PiiScrubber>,

    // Context fields populated via builder pattern
    pub(crate) active_window: Option<WindowInfo>,
    pub(crate) target_app_hint: Option<String>,
    pub(crate) current_tier: Option<ExecutionTier>,
    pub(crate) expected_visual_hash: Option<[u8; 32]>,
    pub(crate) working_directory: Option<String>,
}

impl ToolExecutor {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        os: Arc<dyn OsDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        mcp: Arc<McpManager>,
        event_sender: Option<Sender<KernelEvent>>,
        lens_registry: Option<Arc<LensRegistry>>,
        inference: Arc<dyn InferenceRuntime>,
        pii_scrubber: Option<PiiScrubber>,
    ) -> Self {
        Self {
            gui,
            os,
            terminal,
            browser,
            mcp,
            event_sender,
            lens_registry,
            inference,
            pii_scrubber,
            active_window: None,
            target_app_hint: None,
            current_tier: None,
            expected_visual_hash: None,
            working_directory: None,
        }
    }

    pub fn with_window_context(
        mut self,
        active: Option<WindowInfo>,
        hint: Option<String>,
        tier: Option<ExecutionTier>,
    ) -> Self {
        self.active_window = active;
        self.target_app_hint = hint;
        self.current_tier = tier;
        self
    }

    pub fn with_expected_visual_hash(mut self, hash: Option<[u8; 32]>) -> Self {
        self.expected_visual_hash = hash;
        self
    }

    pub fn with_working_directory(mut self, working_directory: Option<String>) -> Self {
        self.working_directory = working_directory;
        self
    }

    pub(crate) async fn emit_grounding_debug_packet(
        &self,
        mut debug: GroundingDebug,
    ) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis())
            .unwrap_or(0);

        let base_dir = PathBuf::from("/tmp/ioi-grounding");
        if std::fs::create_dir_all(&base_dir).is_err() {
            return None;
        }

        if debug.debug_image_path.is_empty() {
            if let Ok(img_bytes) = self.gui.capture_screen(None).await {
                let img_path = base_dir.join(format!("grounding_debug_{}.png", now));
                if std::fs::write(&img_path, img_bytes).is_ok() {
                    debug.debug_image_path = img_path.to_string_lossy().to_string();
                }
            }
        }

        let json_path = base_dir.join(format!("grounding_debug_{}.json", now));
        match serde_json::to_vec_pretty(&debug) {
            Ok(bytes) => {
                if std::fs::write(&json_path, bytes).is_ok() {
                    if let Some(tx) = &self.event_sender {
                        let _ = tx.send(KernelEvent::GhostInput {
                            device: "grounding".into(),
                            description: format!(
                                "Grounding debug packet: {}",
                                json_path.to_string_lossy()
                            ),
                        });
                    }
                    Some(json_path.to_string_lossy().to_string())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub async fn execute(
        &self,
        tool: AgentTool,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
        som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
        semantic_map: Option<&BTreeMap<u32, String>>,
        active_lens: Option<&str>,
    ) -> ToolExecutionResult {
        match tool {
            // Computer / GUI Domain
            AgentTool::Computer(_)
            | AgentTool::GuiClick { .. }
            | AgentTool::GuiType { .. }
            | AgentTool::GuiScroll { .. }
            | AgentTool::GuiClickElement { .. }
            | AgentTool::OsFocusWindow { .. }
            | AgentTool::OsCopy { .. }
            | AgentTool::OsPaste { .. }
            | AgentTool::UiFind { .. } => {
                computer::handle(self, tool, som_map, semantic_map, active_lens).await
            }

            // Browser Domain
            AgentTool::BrowserNavigate { .. }
            | AgentTool::BrowserSnapshot { .. }
            | AgentTool::BrowserClick { .. }
            | AgentTool::BrowserClickElement { .. }
            | AgentTool::BrowserSyntheticClick { .. }
            | AgentTool::BrowserScroll { .. }
            | AgentTool::BrowserType { .. }
            | AgentTool::BrowserKey { .. } => browser::handle(self, tool).await,

            // Web Retrieval Domain
            AgentTool::WebSearch { .. } | AgentTool::WebRead { .. } => {
                web::handle(self, tool, session_id, step_index).await
            }

            // Filesystem Domain
            AgentTool::FsRead { .. }
            | AgentTool::FsWrite { .. }
            | AgentTool::FsPatch { .. }
            | AgentTool::FsList { .. }
            | AgentTool::FsSearch { .. }
            | AgentTool::FsCreateDirectory { .. }
            | AgentTool::FsMove { .. }
            | AgentTool::FsCopy { .. }
            | AgentTool::FsDelete { .. } => filesystem::handle(self, tool).await,

            // System Domain
            AgentTool::SysExec { .. }
            | AgentTool::SysExecSession { .. }
            | AgentTool::SysExecSessionReset {}
            | AgentTool::SysChangeDir { .. }
            | AgentTool::SysInstallPackage { .. }
            | AgentTool::OsLaunchApp { .. } => {
                let cwd = self.working_directory.as_deref().unwrap_or(".");
                system::handle(self, tool, cwd, session_id, step_index).await
            }

            // MCP / Dynamic Domain
            // Special-case deterministic-but-not-yet-typed tools so they don't route into MCP.
            AgentTool::Dynamic(val) => {
                let name = val
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if name == "net__fetch" {
                    web::handle(self, AgentTool::Dynamic(val), session_id, step_index).await
                } else {
                    mcp::handle(self, val).await
                }
            }

            // Handled by Service Logic (Lifecycle/Meta), should not reach here
            _ => ToolExecutionResult::failure(format!("Tool {:?} not handled by executor", tool)),
        }
    }
}
