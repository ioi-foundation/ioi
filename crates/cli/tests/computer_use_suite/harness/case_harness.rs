use anyhow::{anyhow, Result};
use ioi_services::agentic::desktop::execution::ToolExecutionResult;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::KernelEvent;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time::sleep;

use super::bridge::BridgeClient;
use super::context::ToolExecutionContext;
use super::support::compute_session_id;
use crate::computer_use_suite::types::{BridgeState, ComputerUseMode, LocalJudge, ToolStepRecord};

const DEFAULT_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_secs(2);
const FAST_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_millis(300);
const POINTER_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_millis(250);
const DROP_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_millis(1_200);

pub(super) fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

fn tool_json_parts(tool: &AgentTool) -> Result<(String, Value)> {
    let value = serde_json::to_value(tool)?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tool json missing name"))?
        .to_string();
    let args = value.get("arguments").cloned().unwrap_or_else(|| json!({}));
    Ok((name, args))
}

fn bridge_state_timeout_for_tool(tool: &AgentTool) -> Duration {
    match tool {
        AgentTool::BrowserHover { .. }
        | AgentTool::BrowserMoveMouse { .. }
        | AgentTool::BrowserMouseDown { .. }
        | AgentTool::BrowserMouseUp { .. }
        | AgentTool::BrowserSelectText { .. }
        | AgentTool::BrowserCopySelection {}
        | AgentTool::BrowserPasteClipboard { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. }
        | AgentTool::BrowserSnapshot {} => FAST_BRIDGE_STATE_TIMEOUT,
        AgentTool::BrowserSyntheticClick { .. } | AgentTool::BrowserKey { .. } => {
            POINTER_BRIDGE_STATE_TIMEOUT
        }
        AgentTool::BrowserSelectDropdown { .. } => DROP_BRIDGE_STATE_TIMEOUT,
        _ => DEFAULT_BRIDGE_STATE_TIMEOUT,
    }
}

pub(super) struct CaseHarness {
    pub(super) client: BridgeClient,
    pub(super) session_id: String,
    session_bytes: [u8; 32],
    exec: std::sync::Arc<ioi_services::agentic::desktop::execution::ToolExecutor>,
    browser: std::sync::Arc<ioi_drivers::browser::BrowserDriver>,
    step_index: u32,
    pub(super) bridge_state: BridgeState,
    pub(super) kernel_events: Vec<KernelEvent>,
    event_rx: broadcast::Receiver<KernelEvent>,
    pub(super) tool_steps: Vec<ToolStepRecord>,
}

impl CaseHarness {
    pub(super) async fn new(
        client: BridgeClient,
        session_id: String,
        bridge_state: BridgeState,
        seed: u64,
        shared: &ToolExecutionContext,
    ) -> Result<Self> {
        shared.reset_navigation_target().await?;
        Ok(Self {
            client,
            session_id,
            session_bytes: compute_session_id(seed, ComputerUseMode::Agent),
            exec: shared.exec(),
            browser: shared.browser(),
            step_index: 0,
            bridge_state,
            kernel_events: Vec::new(),
            event_rx: shared.subscribe(),
            tool_steps: Vec::new(),
        })
    }

    pub(super) fn step_count(&self) -> u32 {
        self.step_index
    }

    async fn wait_for_state_change(
        &mut self,
        previous_sync_ms: Option<u64>,
        timeout: Duration,
    ) -> Result<BridgeState> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = self.client.state(&self.session_id).await?;
            let sync_advanced = state.last_sync_ms != previous_sync_ms;
            let became_ready =
                state.info.task_ready.unwrap_or(false) && !state.utterance.is_empty();
            if sync_advanced || became_ready || state.terminated {
                self.bridge_state = state.clone();
                return Ok(state);
            }
            if Instant::now() >= deadline {
                self.bridge_state = state.clone();
                return Ok(state);
            }
            sleep(Duration::from_millis(60)).await;
        }
    }

    pub(super) async fn wait_until_ready(&mut self) -> Result<BridgeState> {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            let state = self.client.state(&self.session_id).await?;
            if state.info.task_ready.unwrap_or(false) && !state.utterance.is_empty() {
                self.bridge_state = state.clone();
                return Ok(state);
            }
            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "session {} did not become ready (last state: {:?})",
                    self.session_id,
                    state.info.reason
                ));
            }
            sleep(Duration::from_millis(80)).await;
        }
    }

    pub(super) async fn refresh_bridge_state(&mut self) -> Result<BridgeState> {
        let state = self.client.state(&self.session_id).await?;
        self.bridge_state = state.clone();
        Ok(state)
    }

    pub(super) async fn execute_tool(&mut self, tool: AgentTool) -> Result<ToolExecutionResult> {
        let (tool_name, arguments) = tool_json_parts(&tool)?;
        let state_timeout = bridge_state_timeout_for_tool(&tool);
        self.step_index = self.step_index.saturating_add(1);
        let previous_sync_ms = self.bridge_state.last_sync_ms;
        let result = self
            .exec
            .execute(
                tool,
                self.session_bytes,
                self.step_index,
                [0u8; 32],
                None,
                None,
                None,
            )
            .await;
        sleep(Duration::from_millis(40)).await;
        drain_events(&mut self.event_rx, &mut self.kernel_events);
        let state = self
            .wait_for_state_change(previous_sync_ms, state_timeout)
            .await?;
        self.tool_steps.push(ToolStepRecord {
            step_index: self.step_index,
            tool_name,
            arguments,
            success: result.success,
            history_entry: result.history_entry.clone(),
            error: result.error.clone(),
            bridge_reward: state.reward,
            bridge_terminated: state.terminated,
        });
        Ok(result)
    }

    pub(super) async fn capture_screenshot(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = self
            .browser
            .capture_tab_screenshot(false)
            .await
            .map_err(|err| anyhow!("capture screenshot: {}", err))?;
        fs::write(path, bytes)?;
        Ok(())
    }

    pub(super) async fn stop(mut self) {
        drain_events(&mut self.event_rx, &mut self.kernel_events);
    }
}

pub(super) async fn settle_final_bridge_state(
    harness: &mut CaseHarness,
    local_judge: LocalJudge,
) -> Result<BridgeState> {
    let mut state = harness.client.state(&harness.session_id).await?;
    harness.bridge_state = state.clone();
    if matches!(local_judge, LocalJudge::HoverShapeReceipts) || state.terminated || state.truncated
    {
        return Ok(state);
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
        let refreshed = harness.client.state(&harness.session_id).await?;
        let changed = refreshed.last_sync_ms != state.last_sync_ms
            || refreshed.reward != state.reward
            || refreshed.info.raw_reward != state.info.raw_reward
            || refreshed.terminated != state.terminated
            || refreshed.truncated != state.truncated;
        if changed {
            state = refreshed;
            harness.bridge_state = state.clone();
            if state.terminated || state.truncated {
                break;
            }
        }
    }

    Ok(state)
}
