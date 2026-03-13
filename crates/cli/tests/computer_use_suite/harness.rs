use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::browser::{BrowserCanvasShapeSummary, BrowserDomElementSummary, BrowserDriver};
use ioi_drivers::gui::geometry::Rect as GuiRect;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::execution::{ToolExecutionResult, ToolExecutor};
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::types::ExecutionTier;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, StartAgentParams, StepAgentParams,
};
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    AgentTool, CapabilityId, InferenceOptions, IntentConfidenceBand, IntentScopeProfile,
    ResolvedIntentState,
};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, WorkloadReceipt};
use ioi_types::{codec, error::VmError};
use portpicker::pick_unused_port;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::process::{Child, Command};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

use super::types::{
    ArtifactBundle, BenchmarkSupportState, BridgeInteractiveElement, BridgeScrollTarget,
    BridgeState, ComputerUseCase, ComputerUseCaseResult, ComputerUseMode,
    KernelBehaviorObservation, LocalJudge, OracleStepRecord, RecipeId, SuiteConfig, TaskSet,
    ToolStepRecord, ValidationSummary,
};

pub struct ModeRunReport {
    pub results: Vec<ComputerUseCaseResult>,
}

#[derive(Debug, Deserialize)]
struct BridgeCreateResponse {
    session_id: String,
    url: String,
    state: BridgeState,
}

#[derive(Clone)]
struct BridgeClient {
    http: Client,
    base_url: String,
}

impl BridgeClient {
    fn new(base_url: String) -> Result<Self> {
        Ok(Self {
            http: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .context("build bridge client")?,
            base_url,
        })
    }

    async fn health(&self) -> Result<Value> {
        let response = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .context("bridge health request")?
            .error_for_status()
            .context("bridge health status")?;
        Ok(response
            .json::<Value>()
            .await
            .context("bridge health json")?)
    }

    async fn create_session(&self, case: &ComputerUseCase) -> Result<BridgeCreateResponse> {
        let response = self
            .http
            .post(format!("{}/session/create", self.base_url))
            .json(&json!({
                "env_id": &case.env_id,
                "seed": case.seed,
                "data_mode": "train",
            }))
            .send()
            .await
            .context("bridge create session")?
            .error_for_status()
            .context("bridge create session status")?;
        response
            .json::<BridgeCreateResponse>()
            .await
            .context("bridge create session json")
    }

    async fn state(&self, session_id: &str) -> Result<BridgeState> {
        let response = self
            .http
            .get(format!("{}/session/{}/state", self.base_url, session_id))
            .send()
            .await
            .context("bridge state request")?
            .error_for_status()
            .context("bridge state status")?;
        response
            .json::<BridgeState>()
            .await
            .context("bridge state json")
    }

    async fn oracle_step(&self, session_id: &str, kind: &str, arguments: Value) -> Result<()> {
        self.http
            .post(format!(
                "{}/session/{}/oracle_step",
                self.base_url, session_id
            ))
            .json(&json!({
                "type": kind,
                "arguments": arguments,
            }))
            .send()
            .await
            .context("bridge oracle step request")?
            .error_for_status()
            .context("bridge oracle step status")?;
        Ok(())
    }

    async fn close(&self, session_id: &str) -> Result<()> {
        let _ = self
            .http
            .post(format!("{}/session/{}/close", self.base_url, session_id))
            .json(&json!({}))
            .send()
            .await
            .context("bridge close session request")?;
        Ok(())
    }
}

struct BridgeProcess {
    child: Child,
    client: BridgeClient,
}

impl BridgeProcess {
    async fn start(config: &SuiteConfig) -> Result<Self> {
        let port = pick_unused_port().ok_or_else(|| anyhow!("no unused port for bridge"))?;
        let base_url = format!("http://127.0.0.1:{}", port);
        let mut command = Command::new(&config.python_bin);
        command
            .arg("tools/miniwob/bridge.py")
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .current_dir(repo_root());
        if let Some(source_dir) = &config.bridge_source_dir {
            command.env("COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR", source_dir);
        }
        let child = command.spawn().context("spawn MiniWoB bridge")?;
        let client = BridgeClient::new(base_url)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match client.health().await {
                Ok(_) => break,
                Err(err) => {
                    if Instant::now() >= deadline {
                        return Err(anyhow!("bridge failed to start: {}", err));
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Ok(Self { child, client })
    }

    async fn stop(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

#[derive(Default)]
struct RecordingGuiDriver;

#[async_trait]
impl GuiDriver for RecordingGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "capture_screen not implemented in computer_use_suite".to_string(),
        ))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError(
            "capture_raw_screen not implemented in computer_use_suite".to_string(),
        ))
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
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn build_ctx<'a>(services: &'a ServiceDirectory) -> TxContext<'a> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    TxContext {
        block_height: 1,
        block_timestamp: now_ns,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn build_scs(path_name: &str) -> Result<(SovereignContextStore, tempfile::TempDir)> {
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join(path_name);
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x11; 32],
        },
    )?;
    Ok((scs, temp_dir))
}

fn read_agent_state(state: &IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) -> AgentState {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    codec::from_bytes_canonical(&bytes).expect("agent state should decode")
}

fn apply_allow_all_policy(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    rules.defaults = DefaultPolicy::AllowAll;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state
        .insert(
            &policy_key,
            &codec::to_bytes_canonical(&rules).expect("policy encode"),
        )
        .expect("policy insert should not fail");
}

fn seed_browser_resolved_intent(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    let mut agent_state: AgentState =
        codec::from_bytes_canonical(&bytes).expect("agent state should decode");
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: "computer_use_suite.browser".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("browser.interact"),
            CapabilityId::from("browser.inspect"),
            CapabilityId::from("conversation.reply"),
        ],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "computer_use_suite".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    });
    agent_state.awaiting_intent_clarification = false;
    agent_state.status = AgentStatus::Running;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("state encode"),
        )
        .expect("state insert should not fail");
}

fn build_executor_with_events(
    event_sender: Option<broadcast::Sender<KernelEvent>>,
) -> (ToolExecutor, Arc<BrowserDriver>) {
    let gui = Arc::new(RecordingGuiDriver);
    let os: Arc<dyn OsDriver> = Arc::new(StaticOsDriver::default());
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
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

struct DirectExecutionContext {
    exec: Arc<ToolExecutor>,
    browser: Arc<BrowserDriver>,
    event_sender: broadcast::Sender<KernelEvent>,
}

impl DirectExecutionContext {
    async fn start(headless: bool) -> Result<Self> {
        let (event_sender, _) = broadcast::channel(512);
        let (exec, browser) = build_executor_with_events(Some(event_sender.clone()));
        browser
            .launch(headless)
            .await
            .map_err(|err| anyhow!("launch Chromium: {}", err))?;
        Ok(Self {
            exec: Arc::new(exec),
            browser,
            event_sender,
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_sender.subscribe()
    }

    async fn stop(&self) {
        self.browser.stop().await;
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
        _options: InferenceOptions,
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

fn compute_session_id(seed: u64, mode: ComputerUseMode) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mode_byte = match mode {
        ComputerUseMode::Oracle => 0x11,
        ComputerUseMode::Runtime => 0x22,
        ComputerUseMode::Agent => 0x33,
    };
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add((idx as u64) * 17)
            .wrapping_add(mode_byte as u64) as u8;
    }
    out
}

fn headless_for_run(config: &SuiteConfig) -> Result<bool> {
    if config.require_browser_display
        && std::env::var("DISPLAY").is_err()
        && std::env::var("WAYLAND_DISPLAY").is_err()
    {
        return Err(anyhow!(
            "display session required by COMPUTER_USE_SUITE_REQUIRE_DISPLAY"
        ));
    }

    if let Ok(value) = std::env::var("COMPUTER_USE_SUITE_HEADLESS") {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized == "0" || normalized == "false" {
            return Ok(false);
        }
        if normalized == "1" || normalized == "true" {
            return Ok(true);
        }
    }

    Ok(std::env::var("DISPLAY").is_err() && std::env::var("WAYLAND_DISPLAY").is_err())
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

const DEFAULT_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_secs(4);
const POINTER_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_millis(250);
const DROP_BRIDGE_STATE_TIMEOUT: Duration = Duration::from_millis(1_200);

async fn drain_events_until_quiescent(
    rx: &mut broadcast::Receiver<KernelEvent>,
    sink: &mut Vec<KernelEvent>,
) {
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        let before = sink.len();
        drain_events(rx, sink);
        if sink.len() == before {
            sleep(Duration::from_millis(25)).await;
        }
    }
}

fn tool_json_parts(tool: &AgentTool) -> Result<(String, Value)> {
    let value = serde_json::to_value(tool).context("serialize agent tool")?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tool json missing name"))?
        .to_string();
    let args = value.get("arguments").cloned().unwrap_or_else(|| json!({}));
    Ok((name, args))
}

fn normalize_label(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

const TABLE_FIELD_LABELS: &[&str] = &[
    "Color",
    "First name",
    "Last name",
    "Country",
    "Gender",
    "Language",
    "Year of Birth",
    "Religion",
];

fn extract_selection_text(history_entry: Option<&str>) -> Option<String> {
    let raw = history_entry?;
    let value = serde_json::from_str::<Value>(raw).ok()?;
    value
        .get("selection")
        .and_then(|selection| selection.get("selected_text"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn extract_clipboard_text(history_entry: Option<&str>) -> Option<String> {
    let raw = history_entry?;
    let value = serde_json::from_str::<Value>(raw).ok()?;
    value
        .get("clipboard")
        .and_then(|clipboard| clipboard.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn extract_canvas_summary(history_entry: Option<&str>) -> Option<BrowserCanvasShapeSummary> {
    let raw = history_entry?;
    let value = serde_json::from_str::<Value>(raw).ok()?;
    serde_json::from_value(
        value
            .get("canvas")
            .and_then(|canvas| canvas.get("summary"))
            .cloned()?,
    )
    .ok()
}

fn primary_browser_modifier() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta"
    } else {
        "Control"
    }
}

fn parse_ordinal_index(query: &str) -> Option<usize> {
    let query_lc = query.to_ascii_lowercase();
    if query_lc.contains("1st") || query_lc.contains("first") {
        Some(1)
    } else if query_lc.contains("2nd") || query_lc.contains("second") {
        Some(2)
    } else if query_lc.contains("3rd") || query_lc.contains("third") {
        Some(3)
    } else {
        None
    }
}

fn highlight_target_selector(query: &str) -> String {
    parse_ordinal_index(query)
        .map(|index| format!("#randomText p:nth-of-type({})", index))
        .unwrap_or_else(|| "#randomText".to_string())
}

fn copy_paste_source_selector(query: &str) -> String {
    parse_ordinal_index(query)
        .map(|index| format!("#text-{}", index))
        .unwrap_or_else(|| "#to-copy".to_string())
}

fn parse_named_ordinal(query: &str, noun: &str) -> Option<usize> {
    let query_lc = query.to_ascii_lowercase();
    for (index, ordinal) in [(1, "1st"), (2, "2nd"), (3, "3rd")] {
        if query_lc.contains(&format!("{} {}", ordinal, noun)) {
            return Some(index);
        }
    }
    for (index, ordinal) in [(1, "first"), (2, "second"), (3, "third")] {
        if query_lc.contains(&format!("{} {}", ordinal, noun)) {
            return Some(index);
        }
    }
    None
}

fn parse_form_sequence_slider_target(query: &str) -> Option<i32> {
    between(query, "Select ", " with the slider")?
        .trim()
        .parse::<i32>()
        .ok()
}

fn parse_form_sequence_checkbox_index(query: &str) -> Option<usize> {
    parse_named_ordinal(query, "checkbox")
}

fn parse_form_sequence_2_textbox_index(query: &str) -> Option<usize> {
    parse_named_ordinal(query, "textbox")
}

fn parse_form_sequence_2_radio_index(query: &str) -> Option<usize> {
    parse_named_ordinal(query, "radio button")
}

fn parse_form_sequence_3_dropdown_label(query: &str) -> Option<String> {
    between(query, "Choose ", " from the dropdown").map(str::to_string)
}

fn parse_text_editor_action_token(query: &str) -> Option<String> {
    let query_lc = query.to_ascii_lowercase();
    between(&query_lc, " the style ", " and press submit")
        .or_else(|| between(&query_lc, " the color ", " and press submit"))
        .or_else(|| between(&query_lc, " the color ", "."))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_text_editor_target(query: &str) -> Option<Option<String>> {
    let query_lc = query.to_ascii_lowercase();
    if query_lc.contains("everything") {
        return Some(None);
    }
    between(query, "give the text ", " the style ")
        .or_else(|| between(query, "give the text ", " the color "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| Some(value.to_string()))
}

fn text_editor_color_value(color: &str) -> Option<&'static str> {
    match color.trim().to_ascii_lowercase().as_str() {
        "red" => Some("#e60000"),
        "orange" => Some("#ff9900"),
        "yellow" => Some("#ffff00"),
        "green" => Some("#008a00"),
        "blue" => Some("#0066cc"),
        "purple" => Some("#9933ff"),
        _ => None,
    }
}

fn search_result_selector(
    elements: &[BridgeInteractiveElement],
    local_index: usize,
) -> Option<String> {
    elements
        .iter()
        .filter(|element| {
            element.visible
                && !element.disabled
                && element
                    .class_list
                    .iter()
                    .any(|class_name| class_name == "search-title")
        })
        .nth(local_index.saturating_sub(1))
        .and_then(|element| element.selector.clone())
}

fn search_results_page_matches(elements: &[BridgeInteractiveElement], page: u32) -> bool {
    let previous_visible = bridge_selector_for_label(elements, "<").is_some();
    let next_visible = bridge_selector_for_label(elements, ">").is_some();
    match page {
        1 => !previous_visible,
        2 => previous_visible && next_visible,
        3 => !next_visible,
        _ => true,
    }
}

fn parse_ordinal_token(token: &str) -> Option<usize> {
    let token_lc = token.trim().trim_matches('.').to_ascii_lowercase();
    let digits = token_lc
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if !digits.is_empty() {
        return digits.parse::<usize>().ok();
    }
    match token_lc.as_str() {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        "fifth" => Some(5),
        "sixth" => Some(6),
        "seventh" => Some(7),
        "eighth" => Some(8),
        "ninth" => Some(9),
        "tenth" => Some(10),
        "eleventh" => Some(11),
        "twelfth" => Some(12),
        "thirteenth" => Some(13),
        "fourteenth" => Some(14),
        "fifteenth" => Some(15),
        _ => None,
    }
}

fn parse_find_word_index(query: &str) -> Option<usize> {
    between(query, "Find the ", " word")
        .and_then(|value| value.split_whitespace().last())
        .and_then(parse_ordinal_token)
}

fn parse_read_table_target(query: &str) -> Option<String> {
    between(query, "Enter the value of ", " into the text field").map(str::to_string)
}

fn parse_phone_book_name(query: &str) -> Option<String> {
    between(query, "Find ", " in the contact book").map(str::to_string)
}

fn parse_phone_book_target(query: &str) -> Option<String> {
    between(query, "click on their ", ".").map(str::to_string)
}

fn parse_social_media_button(query: &str) -> Option<String> {
    quoted_values(query).into_iter().next()
}

fn parse_social_media_user(query: &str) -> Option<String> {
    between(query, "For the user ", ", click on the ")
        .or_else(|| between(query, "button on all posts by ", " and then click Submit"))
        .or_else(|| between(query, " post by ", " and then click Submit"))
        .or_else(|| between(query, " posts by ", " and then click Submit"))
        .map(str::to_string)
}

fn parse_social_media_amount(query: &str) -> Option<usize> {
    between(query, "button on ", " post").and_then(|value| value.trim().parse::<usize>().ok())
}

fn parse_email_inbox_sender(query: &str) -> Option<String> {
    between(query, "Find the email by ", " and ").map(str::to_string)
}

fn parse_email_inbox_reply_text(query: &str) -> Option<String> {
    between(query, "reply to them with the text \"", "\".").map(str::to_string)
}

fn parse_email_inbox_forward_recipient(query: &str) -> Option<String> {
    between(query, "forward that email to ", ".").map(str::to_string)
}

fn parse_email_inbox_action(query: &str) -> Option<&'static str> {
    let query_lc = query.to_ascii_lowercase();
    if query_lc.contains("reply to them with the text") {
        Some("reply")
    } else if query_lc.contains("forward that email to ") {
        Some("forward")
    } else if query_lc.contains("trash icon") {
        Some("delete")
    } else if query_lc.contains("star icon") {
        Some("important")
    } else {
        None
    }
}

fn bridge_field_value<'a>(bridge_state: &'a BridgeState, key: &str) -> Option<&'a str> {
    bridge_state
        .info
        .fields
        .iter()
        .find(|field| field.key.eq_ignore_ascii_case(key))
        .map(|field| field.value.trim())
        .filter(|value| !value.is_empty())
}

fn email_inbox_sender_value(bridge_state: &BridgeState, query: &str) -> Option<String> {
    bridge_field_value(bridge_state, "by")
        .map(str::to_string)
        .or_else(|| parse_email_inbox_sender(query))
}

fn email_inbox_reply_value(bridge_state: &BridgeState, query: &str) -> Option<String> {
    bridge_field_value(bridge_state, "message")
        .map(str::to_string)
        .or_else(|| parse_email_inbox_reply_text(query))
}

fn email_inbox_forward_value(bridge_state: &BridgeState, query: &str) -> Option<String> {
    bridge_field_value(bridge_state, "to")
        .map(str::to_string)
        .or_else(|| parse_email_inbox_forward_recipient(query))
}

fn email_inbox_action_value(bridge_state: &BridgeState, query: &str) -> Option<&'static str> {
    if let Some(task) = bridge_field_value(bridge_state, "task") {
        let normalized = task.to_ascii_lowercase();
        return match normalized.as_str() {
            "reply" => Some("reply"),
            "forward" => Some("forward"),
            "delete" => Some("delete"),
            "important" | "star" => Some("important"),
            _ => None,
        };
    }
    if bridge_field_value(bridge_state, "to").is_some() {
        return Some("forward");
    }
    if bridge_field_value(bridge_state, "message").is_some() {
        return Some("reply");
    }
    parse_email_inbox_action(query)
}

fn email_inbox_row_selector(row_index: usize) -> String {
    format!(
        "#main .email-thread[data-index='{}']",
        row_index.saturating_sub(1)
    )
}

fn find_email_inbox_row_index(rows: &[String], sender: &str) -> Option<usize> {
    let target = normalize_label(sender);
    rows.iter()
        .position(|row| normalize_label(row) == target)
        .or_else(|| {
            rows.iter()
                .position(|row| normalize_label(row).contains(&target))
        })
        .map(|index| index + 1)
}

fn social_media_action_class(label: &str) -> Option<(&'static str, bool)> {
    match normalize_label(label).as_str() {
        "reply" => Some(("reply", false)),
        "retweet" => Some(("retweet", false)),
        "like" => Some(("like", false)),
        "share" => Some(("share", false)),
        "share via dm" => Some(("share", true)),
        "copy link to tweet" => Some(("copy", true)),
        "embed tweet" => Some(("embed", true)),
        "mute" => Some(("menu-user", true)),
        "block" => Some(("block-user", true)),
        "report" => Some(("report", true)),
        _ => None,
    }
}

fn parse_stock_market_threshold(query: &str) -> Option<f64> {
    let value = query
        .split_once(" less than ")?
        .1
        .trim()
        .trim_end_matches('.');
    value.trim_start_matches('$').parse::<f64>().ok()
}

fn parse_currency_text(value: &str) -> Option<f64> {
    value.trim().trim_start_matches('$').parse::<f64>().ok()
}

fn parse_stock_market_visible_price(text: &str) -> Option<f64> {
    let marker = "Stock price:";
    let start = text.find(marker)? + marker.len();
    let tail = text[start..].trim_start();
    let price = tail
        .split_whitespace()
        .next()
        .map(str::trim)
        .filter(|value| value.starts_with('$'))?;
    parse_currency_text(price)
}

fn parse_count_shape_descriptor(query: &str) -> Option<String> {
    between(query, "How many ", "s are there?").map(str::to_string)
}

fn bridge_visible_text_excerpt(bridge_state: &BridgeState) -> &str {
    bridge_state
        .info
        .visible_text_excerpt
        .as_deref()
        .unwrap_or_default()
}

fn trim_reward_display_suffix(text: &str) -> &str {
    text.split_once("Last reward:")
        .map(|(prefix, _)| prefix.trim())
        .unwrap_or_else(|| text.trim())
}

fn trim_submit_button_suffix(text: &str) -> &str {
    text.strip_suffix("Submit")
        .map(str::trim)
        .unwrap_or_else(|| text.trim())
}

fn bridge_visible_content_after_query<'a>(bridge_state: &'a BridgeState, query: &str) -> &'a str {
    let text = trim_reward_display_suffix(bridge_visible_text_excerpt(bridge_state));
    text.strip_prefix(query).map(str::trim).unwrap_or(text)
}

fn visible_table_value_map(visible_text: &str) -> BTreeMap<String, String> {
    let content = trim_submit_button_suffix(visible_text);
    let mut occurrences = Vec::new();

    for label in TABLE_FIELD_LABELS {
        let mut search_start = 0;
        while let Some(relative_index) = content[search_start..].find(label) {
            let index = search_start + relative_index;
            let before_ok = index == 0
                || content[..index]
                    .chars()
                    .last()
                    .map(|ch| ch.is_whitespace())
                    .unwrap_or(true);
            let after = &content[index + label.len()..];
            let with_colon = after.starts_with(':');
            let after_ok = after
                .chars()
                .next()
                .map(|ch| ch == ':' || ch.is_whitespace())
                .unwrap_or(true);
            if before_ok && after_ok {
                occurrences.push((index, *label, with_colon));
            }
            search_start = index + label.len();
        }
    }

    occurrences.sort_by_key(|(index, _, _)| *index);

    let mut values = BTreeMap::new();
    for (index, label, with_colon) in occurrences.iter().copied() {
        if with_colon {
            continue;
        }
        let start = index + label.len();
        let end = occurrences
            .iter()
            .filter(|(next_index, _, _)| *next_index > index)
            .map(|(next_index, _, _)| *next_index)
            .min()
            .unwrap_or(content.len());
        let value = content[start..end].trim();
        if !value.is_empty() {
            values.insert(label.to_string(), value.to_string());
        }
    }

    values
}

fn odd_or_even_visible_numbers(visible_text: &str) -> Vec<i32> {
    trim_submit_button_suffix(visible_text)
        .split_whitespace()
        .filter_map(|token| token.parse::<i32>().ok())
        .collect()
}

fn phone_book_visible_name(visible_text: &str) -> Option<String> {
    visible_text
        .split_once(" Phone:")
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

fn is_shape_color_token(token: &str) -> bool {
    matches!(
        token,
        "red" | "green" | "blue" | "aqua" | "black" | "magenta" | "yellow"
    )
}

fn parse_css_pixels(value: &str) -> Option<f64> {
    value
        .trim()
        .trim_end_matches("px")
        .trim()
        .parse::<f64>()
        .ok()
}

fn svg_shape_kind(summary: &BrowserDomElementSummary) -> Option<&'static str> {
    match summary.tag.as_str() {
        "rect" => Some("rectangle"),
        "circle" => Some("circle"),
        "polygon" => Some("triangle"),
        "text" => {
            let text = summary.text.trim();
            if text.len() == 1 && text.chars().all(|ch| ch.is_ascii_digit()) {
                Some("digit")
            } else if text.len() == 1 && text.chars().all(|ch| ch.is_ascii_alphabetic()) {
                Some("letter")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn svg_shape_size(summary: &BrowserDomElementSummary) -> Option<&'static str> {
    if summary.tag == "text" {
        let font_size = summary
            .attributes
            .get("font-size")
            .and_then(|value| parse_css_pixels(value))?;
        return Some(if font_size >= 15.0 { "large" } else { "small" });
    }

    let extent = summary.width.max(summary.height);
    if extent <= 0.0 {
        None
    } else if extent >= 15.0 {
        Some("large")
    } else {
        Some("small")
    }
}

fn svg_shape_color(summary: &BrowserDomElementSummary) -> Option<String> {
    summary
        .attributes
        .get("fill")
        .map(|value| normalize_label(value))
        .filter(|value| !value.is_empty())
}

fn svg_numeric_attribute(summary: &BrowserDomElementSummary, name: &str) -> Option<f64> {
    summary.attributes.get(name)?.trim().parse::<f64>().ok()
}

fn count_shape_matches(elements: &[BrowserDomElementSummary], descriptor: &str) -> usize {
    let normalized = normalize_label(descriptor);
    let mut required_size: Option<&str> = None;
    let mut required_color: Option<&str> = None;
    let mut required_kind = "item";

    for token in normalized.split_whitespace() {
        match token {
            "small" | "large" => required_size = Some(token),
            _ if is_shape_color_token(token) => required_color = Some(token),
            other => required_kind = other,
        }
    }

    elements
        .iter()
        .filter(|summary| summary.visible)
        .filter(|summary| {
            let Some(kind) = svg_shape_kind(summary) else {
                return false;
            };
            if required_kind != "item" && required_kind != kind {
                return false;
            }
            if let Some(size) = required_size {
                if svg_shape_size(summary) != Some(size) {
                    return false;
                }
            }
            if let Some(color) = required_color {
                if svg_shape_color(summary).as_deref() != Some(color) {
                    return false;
                }
            }
            true
        })
        .count()
}

fn parse_first_integer(text: &str) -> Option<i32> {
    let mut token = String::new();
    let mut started = false;
    for ch in text.chars() {
        if !started && ch == '-' {
            token.push(ch);
            started = true;
            continue;
        }
        if ch.is_ascii_digit() {
            token.push(ch);
            started = true;
            continue;
        }
        if started {
            break;
        }
    }
    if token.is_empty() || token == "-" {
        return None;
    }
    token.parse::<i32>().ok()
}

fn solve_simple_arithmetic_problem(problem: &str) -> Option<i32> {
    let cleaned = problem.replace('=', "");
    let tokens = cleaned.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 3 {
        return None;
    }
    let lhs = tokens[0].parse::<i32>().ok()?;
    let rhs = tokens[2].parse::<i32>().ok()?;
    match tokens[1] {
        "+" => Some(lhs + rhs),
        "-" => Some(lhs - rhs),
        "x" => Some(lhs * rhs),
        _ => None,
    }
}

fn solve_simple_algebra_problem(problem: &str) -> Option<i32> {
    let tokens = problem.split_whitespace().collect::<Vec<_>>();
    if tokens.len() != 5 || tokens[3] != "=" {
        return None;
    }
    let result = tokens[4].parse::<i32>().ok()?;
    match (tokens[0], tokens[1], tokens[2]) {
        ("x", "+", rhs) => Some(result - rhs.parse::<i32>().ok()?),
        ("x", "-", rhs) => Some(result + rhs.parse::<i32>().ok()?),
        (lhs, "+", "x") => Some(result - lhs.parse::<i32>().ok()?),
        (lhs, "-", "x") => Some(lhs.parse::<i32>().ok()? - result),
        _ => None,
    }
}

fn table_value_map(cell_texts: &[String]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let mut iter = cell_texts.iter();
    while let Some(key) = iter.next() {
        let Some(value) = iter.next() else {
            break;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    values
}

fn quoted_values(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut buf = String::new();
        while let Some(next) = chars.next() {
            if next == '"' {
                break;
            }
            buf.push(next);
        }
        if !buf.is_empty() {
            out.push(buf);
        }
    }
    out
}

fn between<'a>(input: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_idx = input.find(start)? + start.len();
    let rest = &input[start_idx..];
    let end_idx = rest.find(end)?;
    Some(rest[..end_idx].trim())
}

fn parse_checkbox_targets(query: &str) -> Vec<String> {
    let Some(raw) = between(query, "Select ", " and click Submit.") else {
        return Vec::new();
    };
    if raw.eq_ignore_ascii_case("nothing") {
        return Vec::new();
    }
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_tab_number(query: &str) -> Option<u32> {
    let marker = "Tab #";
    let start = query.find(marker)? + marker.len();
    let digits = query[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u32>().ok()
}

fn parse_focus_index(query: &str) -> Option<u32> {
    if query.contains("1st") {
        Some(1)
    } else if query.contains("2nd") {
        Some(2)
    } else if query.contains("3rd") {
        Some(3)
    } else {
        None
    }
}

fn parse_search_result_position(query: &str) -> Option<u32> {
    let marker = "click the ";
    let start = query.to_ascii_lowercase().find(marker)? + marker.len();
    let digits = query[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u32>().ok()
}

fn parse_submit_target(query: &str) -> Option<String> {
    between(query, "Select ", " from the list")
        .or_else(|| between(query, "Select ", " and click Submit."))
        .map(str::to_string)
}

fn parse_uppercase_transform(query: &str, raw_text: &str) -> String {
    if query
        .to_ascii_lowercase()
        .contains("all upper case letters")
    {
        raw_text.to_ascii_uppercase()
    } else if query
        .to_ascii_lowercase()
        .contains("all lower case letters")
    {
        raw_text.to_ascii_lowercase()
    } else {
        raw_text.to_string()
    }
}

const MINIWOB_COUNTRY_OPTIONS: &[&str] = &[
    "Afghanistan",
    "Aland Islands",
    "Albania",
    "Algeria",
    "American Samoa",
    "Andorra",
    "Angola",
    "Anguilla",
    "Antarctica",
    "Antigua and Barbuda",
    "Argentina",
    "Armenia",
    "Aruba",
    "Australia",
    "Austria",
    "Azerbaijan",
    "Bahamas",
    "Bahrain",
    "Bangladesh",
    "Barbados",
    "Belarus",
    "Belgium",
    "Belize",
    "Benin",
    "Bermuda",
    "Bhutan",
    "Bolivia",
    "Bonaire",
    "Bosnia and Herzegovina",
    "Botswana",
    "Bouvet Island",
    "Brazil",
    "Brunei Darussalam",
    "Bulgaria",
    "Burkina Faso",
    "Burundi",
    "Cambodia",
    "Cameroon",
    "Canada",
    "Cape Verde",
    "Cayman Islands",
    "Central African Republic",
    "Chad",
    "Chile",
    "China",
    "Christmas Island",
    "Cocos Islands",
    "Colombia",
    "Comoros",
    "Congo",
    "Congo",
    "Cook Islands",
    "Costa Rica",
    "Croatia",
    "Cuba",
    "Cyprus",
    "Czech Republic",
    "Denmark",
    "Djibouti",
    "Dominica",
    "Dominican Republic",
    "Ecuador",
    "Egypt",
    "El Salvador",
    "Equatorial Guinea",
    "Eritrea",
    "Estonia",
    "Ethiopia",
    "Falkland Islands",
    "Faroe Islands",
    "Fiji",
    "Finland",
    "France",
    "French Guiana",
    "French Polynesia",
    "Gabon",
    "Gambia",
    "Georgia",
    "Germany",
    "Ghana",
    "Gibraltar",
    "Greece",
    "Greenland",
    "Grenada",
    "Guadeloupe",
    "Guam",
    "Guatemala",
    "Guernsey",
    "Guinea",
    "Guinea-Bissau",
    "Guyana",
    "Haiti",
    "Heard Island and McDonald Islands",
    "Vatican City State",
    "Honduras",
    "Hong Kong",
    "Hungary",
    "Iceland",
    "India",
    "Indonesia",
    "Iran",
    "Iraq",
    "Ireland",
    "Isle of Man",
    "Israel",
    "Italy",
    "Jamaica",
    "Japan",
    "Jersey",
    "Jordan",
    "Kazakhstan",
    "Kenya",
    "Kiribati",
    "Korea",
    "Kuwait",
    "Kyrgyzstan",
    "Latvia",
    "Lebanon",
    "Lesotho",
    "Liberia",
    "Libya",
    "Liechtenstein",
    "Lithuania",
    "Luxembourg",
    "Macao",
    "Macedonia",
    "Madagascar",
    "Malawi",
    "Malaysia",
    "Maldives",
    "Mali",
    "Malta",
    "Marshall Islands",
    "Martinique",
    "Mauritania",
    "Mauritius",
    "Mayotte",
    "Mexico",
    "Micronesia",
    "Moldova",
    "Monaco",
    "Mongolia",
    "Montenegro",
    "Montserrat",
    "Morocco",
    "Mozambique",
    "Myanmar",
    "Namibia",
    "Nauru",
    "Nepal",
    "Netherlands",
    "New Caledonia",
    "New Zealand",
    "Nicaragua",
    "Niger",
    "Nigeria",
    "Niue",
    "Norfolk Island",
    "Northern Mariana Islands",
    "Norway",
    "Oman",
    "Pakistan",
    "Palau",
    "Panama",
    "Papua New Guinea",
    "Paraguay",
    "Peru",
    "Philippines",
    "Pitcairn",
    "Poland",
    "Portugal",
    "Puerto Rico",
    "Qatar",
    "Reunion",
    "Romania",
    "Russian Federation",
    "Rwanda",
    "Saint Helena",
    "Saint Lucia",
    "Saint Martin",
    "Samoa",
    "San Marino",
    "Sao Tome and Principe",
    "Saudi Arabia",
    "Senegal",
    "Serbia",
    "Seychelles",
    "Sierra Leone",
    "Singapore",
    "Sint Maarten",
    "Slovakia",
    "Slovenia",
    "Solomon Islands",
    "Somalia",
    "South Africa",
    "South Sudan",
    "Spain",
    "Sri Lanka",
    "Sudan",
    "Suriname",
    "Svalbard and Jan Mayen",
    "Swaziland",
    "Sweden",
    "Switzerland",
    "Syrian Arab Republic",
    "Taiwan",
    "Tajikistan",
    "Tanzania",
    "Thailand",
    "Timor-Leste",
    "Togo",
    "Tokelau",
    "Tonga",
    "Trinidad and Tobago",
    "Tunisia",
    "Turkey",
    "Turkmenistan",
    "Turks and Caicos Islands",
    "Tuvalu",
    "Uganda",
    "Ukraine",
    "United Arab Emirates",
    "United Kingdom",
    "United States",
    "Uruguay",
    "Uzbekistan",
    "Vanuatu",
    "Venezuela",
    "Western Sahara",
    "Yemen",
    "Zambia",
    "Zimbabwe",
];

fn infer_autocomplete_target(query: &str) -> Option<String> {
    let quoted = quoted_values(query);
    let prefix = quoted.first()?.to_ascii_lowercase();
    let suffix = quoted.get(1).map(|value| value.to_ascii_lowercase());

    MINIWOB_COUNTRY_OPTIONS
        .iter()
        .find(|option| {
            let normalized = option.to_ascii_lowercase();
            normalized.starts_with(&prefix)
                && suffix
                    .as_ref()
                    .map(|value| normalized.ends_with(value))
                    .unwrap_or(true)
        })
        .map(|option| (*option).to_string())
}

fn extract_error_class(input: &str) -> Option<String> {
    let marker = "ERROR_CLASS=";
    let start = input.find(marker)? + marker.len();
    let rest = &input[start..];
    let value = rest.split_whitespace().next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn write_json_file(path: &PathBuf, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {:?}", parent))?;
    }
    let bytes = serde_json::to_vec_pretty(value).context("serialize json file")?;
    fs::write(path, bytes).with_context(|| format!("write {:?}", path))?;
    Ok(())
}

fn write_text_file(path: &PathBuf, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {:?}", parent))?;
    }
    fs::write(path, content.as_bytes()).with_context(|| format!("write {:?}", path))?;
    Ok(())
}

fn round_pointer_coordinate(value: f64) -> Result<u32> {
    if !value.is_finite() || value < 0.0 || value > u32::MAX as f64 {
        return Err(anyhow!("invalid pointer coordinate: {}", value));
    }
    Ok(value.round() as u32)
}

struct DirectHarness {
    client: BridgeClient,
    session_id: String,
    session_bytes: [u8; 32],
    exec: Arc<ToolExecutor>,
    browser: Arc<BrowserDriver>,
    step_index: u32,
    bridge_state: BridgeState,
    kernel_events: Vec<KernelEvent>,
    event_rx: broadcast::Receiver<KernelEvent>,
    tool_steps: Vec<ToolStepRecord>,
    oracle_steps: Vec<OracleStepRecord>,
}

impl DirectHarness {
    async fn new(
        client: BridgeClient,
        session_id: String,
        bridge_state: BridgeState,
        mode: ComputerUseMode,
        seed: u64,
        shared: &DirectExecutionContext,
    ) -> Result<Self> {
        Ok(Self {
            client,
            session_id,
            session_bytes: compute_session_id(seed, mode),
            exec: shared.exec.clone(),
            browser: shared.browser.clone(),
            step_index: 0,
            bridge_state,
            kernel_events: Vec::new(),
            event_rx: shared.subscribe(),
            tool_steps: Vec::new(),
            oracle_steps: Vec::new(),
        })
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

    async fn wait_until_ready(&mut self) -> Result<BridgeState> {
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

    async fn wait_for_oracle_progress(
        &mut self,
        previous_episode_step: u32,
    ) -> Result<BridgeState> {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let state = self.client.state(&self.session_id).await?;
            if state.episode_step > previous_episode_step || state.terminated {
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

    async fn refresh_bridge_state(&mut self) -> Result<BridgeState> {
        let state = self.client.state(&self.session_id).await?;
        self.bridge_state = state.clone();
        Ok(state)
    }

    async fn execute_tool(&mut self, tool: AgentTool) -> Result<ToolExecutionResult> {
        self.execute_tool_with_state_timeout(tool, DEFAULT_BRIDGE_STATE_TIMEOUT)
            .await
    }

    async fn execute_tool_with_state_timeout(
        &mut self,
        tool: AgentTool,
        state_timeout: Duration,
    ) -> Result<ToolExecutionResult> {
        let (tool_name, arguments) = tool_json_parts(&tool)?;
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

    async fn oracle_command(&mut self, command_type: &str, arguments: Value) -> Result<()> {
        self.step_index = self.step_index.saturating_add(1);
        let previous_episode_step = self.bridge_state.episode_step;
        self.client
            .oracle_step(&self.session_id, command_type, arguments.clone())
            .await?;
        let state = self.wait_for_oracle_progress(previous_episode_step).await?;
        self.oracle_steps.push(OracleStepRecord {
            step_index: self.step_index,
            command_type: command_type.to_string(),
            payload: arguments,
            bridge_reward: state.reward,
            bridge_terminated: state.terminated,
        });
        Ok(())
    }

    async fn oracle_click_selector(&mut self, selector: &str) -> Result<()> {
        self.oracle_command("click_selector", json!({ "selector": selector }))
            .await
    }

    async fn oracle_click_text(&mut self, text: &str) -> Result<()> {
        self.oracle_command("click_text", json!({ "text": text }))
            .await
    }

    async fn oracle_focus_selector(&mut self, selector: &str) -> Result<()> {
        self.oracle_command("focus_selector", json!({ "selector": selector }))
            .await
    }

    async fn oracle_type_text(&mut self, selector: &str, text: &str) -> Result<()> {
        self.oracle_command(
            "type_selector",
            json!({
                "selector": selector,
                "text": text,
                "replace": true,
            }),
        )
        .await
    }

    async fn oracle_select_label(&mut self, selector: &str, label: &str) -> Result<()> {
        self.oracle_command(
            "select_label",
            json!({
                "selector": selector,
                "label": label,
            }),
        )
        .await
    }

    async fn oracle_scroll_target(&mut self, selector: &str, position: &str) -> Result<()> {
        self.oracle_command(
            "scroll_target",
            json!({
                "selector": selector,
                "position": position,
            }),
        )
        .await
    }

    async fn click_selector(&mut self, selector: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserClick {
                selector: selector.to_string(),
            })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__click '{}' failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn click_point(&mut self, x: f64, y: f64) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserSyntheticClick {
                    x: round_pointer_coordinate(x)?,
                    y: round_pointer_coordinate(y)?,
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__synthetic_click ({:.2}, {:.2}) failed: {}",
                x,
                y,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn click_bridge_label(&mut self, label: &str) -> Result<()> {
        let state = self.refresh_bridge_state().await?;
        let selector = bridge_selector_for_label(&state.info.interactive_elements, label)
            .ok_or_else(|| anyhow!("could not find selector for '{}'", label))?;
        self.click_selector(&selector).await
    }

    async fn hover_selector(&mut self, selector: &str) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserHover {
                    selector: Some(selector.to_string()),
                    id: None,
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__hover '{}' failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn move_mouse(&mut self, x: f64, y: f64) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserMoveMouse {
                    x: round_pointer_coordinate(x)?,
                    y: round_pointer_coordinate(y)?,
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__move_mouse ({:.2}, {:.2}) failed: {}",
                x,
                y,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn mouse_down(&mut self, button: &str) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserMouseDown {
                    button: Some(button.to_string()),
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__mouse_down '{}' failed: {}",
                button,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn mouse_up(&mut self, button: &str) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserMouseUp {
                    button: Some(button.to_string()),
                },
                DROP_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__mouse_up '{}' failed: {}",
                button,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn type_text(&mut self, selector: &str, text: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserType {
                text: text.to_string(),
                selector: Some(selector.to_string()),
            })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__type '{}' failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn select_text(
        &mut self,
        selector: Option<&str>,
        start_offset: Option<u32>,
        end_offset: Option<u32>,
    ) -> Result<String> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserSelectText {
                    selector: selector.map(str::to_string),
                    start_offset,
                    end_offset,
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if !result.success {
            return Err(anyhow!(
                "browser__select_text {:?} failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        extract_selection_text(result.history_entry.as_deref())
            .ok_or_else(|| anyhow!("browser__select_text returned no selection payload"))
    }

    async fn press_key(&mut self, key: &str) -> Result<()> {
        self.press_key_with_modifiers(key, &[]).await
    }

    async fn press_key_with_modifiers(&mut self, key: &str, modifiers: &[&str]) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserKey {
                    key: key.to_string(),
                    modifiers: (!modifiers.is_empty()).then(|| {
                        modifiers
                            .iter()
                            .map(|modifier| (*modifier).to_string())
                            .collect()
                    }),
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__key '{}' with modifiers {:?} failed: {}",
                key,
                modifiers,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn copy_selection(&mut self) -> Result<String> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserCopySelection {},
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if !result.success {
            return Err(anyhow!(
                "browser__copy_selection failed: {}",
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        extract_clipboard_text(result.history_entry.as_deref())
            .ok_or_else(|| anyhow!("browser__copy_selection returned no clipboard payload"))
    }

    async fn paste_clipboard(&mut self, selector: Option<&str>) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserPasteClipboard {
                    selector: selector.map(str::to_string),
                },
                DEFAULT_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__paste_clipboard {:?} failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn canvas_shape_summary(&mut self, selector: &str) -> Result<BrowserCanvasShapeSummary> {
        let result = self
            .execute_tool(AgentTool::BrowserCanvasSummary {
                selector: selector.to_string(),
            })
            .await?;
        if !result.success {
            return Err(anyhow!(
                "browser__canvas_summary '{}' failed: {}",
                selector,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }
        extract_canvas_summary(result.history_entry.as_deref())
            .ok_or_else(|| anyhow!("browser__canvas_summary returned no canvas payload"))
    }

    async fn wait_ms(&mut self, ms: u64) -> Result<()> {
        let result = self
            .execute_tool_with_state_timeout(
                AgentTool::BrowserWait {
                    ms: Some(ms),
                    condition: None,
                    selector: None,
                    query: None,
                    scope: None,
                    timeout_ms: None,
                },
                POINTER_BRIDGE_STATE_TIMEOUT,
            )
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__wait {} failed: {}",
                ms,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn select_dropdown_label(&mut self, selector: &str, label: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserSelectDropdown {
                selector: Some(selector.to_string()),
                som_id: None,
                value: None,
                label: Some(label.to_string()),
            })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__select_dropdown '{}' failed: {}",
                label,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn select_dropdown_value(&mut self, selector: &str, value: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserSelectDropdown {
                selector: Some(selector.to_string()),
                som_id: None,
                value: Some(value.to_string()),
                label: None,
            })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__select_dropdown '{}' failed: {}",
                value,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn capture_screenshot(&self, path: &PathBuf) -> Result<()> {
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

    async fn selector_texts(&self, selector: &str) -> Result<Vec<String>> {
        self.browser
            .selector_texts(selector)
            .await
            .map_err(|err| anyhow!("selector_texts '{}': {}", selector, err))
    }

    async fn selector_text(&self, selector: &str) -> Result<Option<String>> {
        self.browser
            .selector_text(selector)
            .await
            .map_err(|err| anyhow!("selector_text '{}': {}", selector, err))
    }

    async fn selector_texts_all(&self, selector: &str) -> Result<Vec<String>> {
        self.browser
            .selector_texts_all(selector)
            .await
            .map_err(|err| anyhow!("selector_texts_all '{}': {}", selector, err))
    }

    async fn selector_elements(&self, selector: &str) -> Result<Vec<BrowserDomElementSummary>> {
        self.browser
            .selector_elements(selector)
            .await
            .map_err(|err| anyhow!("selector_elements '{}': {}", selector, err))
    }

    async fn stop(mut self) {
        drain_events(&mut self.event_rx, &mut self.kernel_events);
    }
}

async fn capture_catalog_diagnostics(harness: &mut DirectHarness) {
    let _ = harness.execute_tool(AgentTool::BrowserSnapshot {}).await;
    let _ = harness
        .execute_tool(AgentTool::BrowserWait {
            ms: Some(50),
            condition: None,
            selector: None,
            query: None,
            scope: None,
            timeout_ms: None,
        })
        .await;
}

async fn settle_final_bridge_state(
    harness: &mut DirectHarness,
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

async fn scroll_textarea_with_browser_tools(
    harness: &mut DirectHarness,
    go_bottom: bool,
) -> Result<()> {
    let selector = scroll_target_selector(&harness.bridge_state.info.scroll_targets, "text-area")
        .unwrap_or_else(|| "#text-area".to_string());
    let page_key = scroll_page_key(go_bottom);
    let (jump_key, jump_modifiers) = scroll_jump_key(go_bottom);
    let mut last_scroll_action = None::<&str>;

    for _ in 0..12 {
        let state = harness.refresh_bridge_state().await?;
        if let Some(target) = scroll_target_by_id(&state.info.scroll_targets, "text-area") {
            if scroll_target_reached(target, go_bottom) {
                return Ok(());
            }
        }
        if !bridge_focus_matches(&state, &selector) {
            harness.click_selector(&selector).await?;
            last_scroll_action = Some("focus");
        } else if last_scroll_action == Some("jump_key") {
            harness.press_key(page_key).await?;
            harness.wait_ms(80).await?;
            last_scroll_action = Some("page_key");
        } else {
            harness
                .press_key_with_modifiers(jump_key, jump_modifiers)
                .await?;
            harness.wait_ms(80).await?;
            last_scroll_action = Some("jump_key");
        }
    }

    Ok(())
}

async fn wait_for_bridge_label_selector(
    harness: &mut DirectHarness,
    label: &str,
    attempts: usize,
    delay_ms: u64,
) -> Result<Option<String>> {
    for attempt in 0..=attempts {
        let state = harness.refresh_bridge_state().await?;
        if let Some(selector) = bridge_selector_for_label(&state.info.interactive_elements, label) {
            return Ok(Some(selector));
        }
        if attempt < attempts && delay_ms > 0 {
            harness.wait_ms(delay_ms).await?;
        }
    }
    Ok(None)
}

fn bridge_element_display_text(element: &BridgeInteractiveElement) -> String {
    if !element.text.trim().is_empty() {
        element.text.trim().to_string()
    } else {
        element.value.clone().unwrap_or_default()
    }
}

fn bridge_visible_label_match_index(
    elements: &[BridgeInteractiveElement],
    label: &str,
) -> Option<usize> {
    let target = normalize_label(label);
    let mut fuzzy_match = None;

    for (index, element) in elements.iter().enumerate() {
        if !element.visible || element.disabled {
            continue;
        }
        let normalized = normalize_label(&bridge_element_display_text(element));
        if normalized == target {
            return Some(index);
        }
        if fuzzy_match.is_none()
            && !normalized.is_empty()
            && (normalized.contains(&target) || target.contains(&normalized))
        {
            fuzzy_match = Some(index);
        }
    }

    fuzzy_match
}

fn bridge_selector_for_label(elements: &[BridgeInteractiveElement], label: &str) -> Option<String> {
    bridge_visible_label_match_index(elements, label)
        .and_then(|index| elements.get(index))
        .and_then(|element| element.selector.clone())
}

fn selector_tab_panel_index(selector: &str) -> Option<u32> {
    let suffix = selector.strip_prefix("#tabs-")?;
    let digits = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

fn bridge_hidden_tab_selector_for_label(
    elements: &[BridgeInteractiveElement],
    label: &str,
) -> Option<String> {
    let target = normalize_label(label);
    let mut fuzzy_match = None;

    for element in elements
        .iter()
        .filter(|element| !element.disabled && !element.visible)
    {
        let Some(selector) = element.selector.as_deref() else {
            continue;
        };
        let Some(tab_index) = selector_tab_panel_index(selector) else {
            continue;
        };
        let normalized = normalize_label(&bridge_element_display_text(element));
        let tab_selector = format!("a[href='#tabs-{}']", tab_index);
        if normalized == target {
            return Some(tab_selector);
        }
        if fuzzy_match.is_none()
            && !normalized.is_empty()
            && (normalized.contains(&target) || target.contains(&normalized))
        {
            fuzzy_match = Some(tab_selector);
        }
    }

    fuzzy_match
}

fn accordion_panel_section_index(selector: &str) -> Option<u32> {
    let suffix = selector.strip_prefix("#ui-id-")?;
    let digits = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    let panel_id = digits.parse::<u32>().ok()?;
    if panel_id >= 2 && panel_id % 2 == 0 {
        Some(panel_id / 2)
    } else {
        None
    }
}

fn bridge_hidden_collapsible_selector_for_label(
    elements: &[BridgeInteractiveElement],
    label: &str,
) -> Option<String> {
    let target = normalize_label(label);
    let mut fuzzy_match = None;

    for element in elements
        .iter()
        .filter(|element| !element.disabled && !element.visible)
    {
        let Some(selector) = element.selector.as_deref() else {
            continue;
        };
        let Some(section_index) = accordion_panel_section_index(selector) else {
            continue;
        };
        let normalized = normalize_label(&bridge_element_display_text(element));
        let header_selector = format!("#area h3:nth-of-type({})", section_index);
        if normalized == target {
            return Some(header_selector);
        }
        if fuzzy_match.is_none()
            && !normalized.is_empty()
            && (normalized.contains(&target) || target.contains(&normalized))
        {
            fuzzy_match = Some(header_selector);
        }
    }

    fuzzy_match
}

fn bridge_element_by_selector<'a>(
    elements: &'a [BridgeInteractiveElement],
    selector: &str,
) -> Option<&'a BridgeInteractiveElement> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
}

fn bridge_value_by_selector(elements: &[BridgeInteractiveElement], selector: &str) -> String {
    bridge_element_by_selector(elements, selector)
        .and_then(|element| element.value.clone())
        .unwrap_or_default()
}

fn bridge_selected_contains(
    elements: &[BridgeInteractiveElement],
    selector: &str,
    label: &str,
) -> bool {
    let target = normalize_label(label);
    bridge_element_by_selector(elements, selector)
        .map(|element| {
            element
                .selected_labels
                .iter()
                .any(|entry| normalize_label(entry) == target)
        })
        .unwrap_or(false)
}

fn bridge_checkbox_checked_for_label(
    elements: &[BridgeInteractiveElement],
    label: &str,
) -> Option<bool> {
    let index = bridge_visible_label_match_index(elements, label)?;
    let element = elements.get(index)?;
    if let Some(checked) = element.checked {
        return Some(checked);
    }
    for neighbor in [Some(index + 1), Some(index + 2), index.checked_sub(1)]
        .into_iter()
        .flatten()
    {
        let Some(candidate) = elements.get(neighbor) else {
            continue;
        };
        if candidate.disabled || !candidate.visible {
            continue;
        }
        if let Some(checked) = candidate.checked {
            return Some(checked);
        }
    }
    None
}

fn bridge_focus_matches(bridge_state: &BridgeState, selector: &str) -> bool {
    match selector {
        "#tt" => bridge_state.info.focused_id.as_deref() == Some("tt"),
        "#tt1" => bridge_state.info.focused_id.as_deref() == Some("tt1"),
        "#tt2" => bridge_state.info.focused_id.as_deref() == Some("tt2"),
        "#tt3" => bridge_state.info.focused_id.as_deref() == Some("tt3"),
        "#math-answer" => bridge_state.info.focused_id.as_deref() == Some("math-answer"),
        "#answer-input" => bridge_state.info.focused_id.as_deref() == Some("answer-input"),
        "#tags" => bridge_state.info.focused_id.as_deref() == Some("tags"),
        "#username" => bridge_state.info.focused_id.as_deref() == Some("username"),
        "#password" => bridge_state.info.focused_id.as_deref() == Some("password"),
        "#verify" => bridge_state.info.focused_id.as_deref() == Some("verify"),
        "#search-text" => bridge_state.info.focused_id.as_deref() == Some("search-text"),
        "#text-area" => bridge_state.info.focused_id.as_deref() == Some("text-area"),
        _ => false,
    }
}

fn scroll_target_by_id<'a>(
    targets: &'a [BridgeScrollTarget],
    id: &str,
) -> Option<&'a BridgeScrollTarget> {
    targets
        .iter()
        .find(|target| target.id.as_deref() == Some(id))
}

fn scroll_target_selector(targets: &[BridgeScrollTarget], id: &str) -> Option<String> {
    targets.iter().find_map(|target| {
        if target.id.as_deref() == Some(id) {
            target
                .selector
                .clone()
                .or_else(|| target.id.as_ref().map(|id| format!("#{id}")))
        } else {
            None
        }
    })
}

fn scroll_target_reached(target: &BridgeScrollTarget, go_bottom: bool) -> bool {
    if go_bottom {
        target.scroll_top + target.client_height + 10.0 >= target.scroll_height
    } else {
        target.scroll_top <= 10.0
    }
}

fn scroll_page_key(go_bottom: bool) -> &'static str {
    if go_bottom { "PageDown" } else { "PageUp" }
}

fn scroll_jump_key(go_bottom: bool) -> (&'static str, &'static [&'static str]) {
    if cfg!(target_os = "macos") {
        if go_bottom {
            ("ArrowDown", &["Meta"])
        } else {
            ("ArrowUp", &["Meta"])
        }
    } else if go_bottom {
        ("End", &["Control"])
    } else {
        ("Home", &["Control"])
    }
}

async fn run_hover_shape_sequence(harness: &mut DirectHarness) -> Result<()> {
    harness.hover_selector("#highlight").await?;
    harness.wait_ms(1_300).await?;
    harness.hover_selector("#highlight").await?;
    harness.wait_ms(1_300).await?;
    harness.hover_selector("#highlight").await?;
    Ok(())
}

async fn run_highlight_text_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let selector = highlight_target_selector(query);
    let selected_text = harness.select_text(Some(&selector), None, None).await?;
    if normalize_label(&selected_text).is_empty() {
        return Err(anyhow!("highlight-text selection is empty"));
    }
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_copy_paste_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let source_selector = copy_paste_source_selector(query);
    harness.click_selector(&source_selector).await?;
    harness
        .press_key_with_modifiers("a", &[primary_browser_modifier()])
        .await?;
    let copied_text = harness.copy_selection().await?;
    if copied_text.is_empty() {
        return Err(anyhow!("copy-paste selection copied no text"));
    }
    harness.paste_clipboard(Some("#answer-input")).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_form_sequence_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let target_value =
        parse_form_sequence_slider_target(query).ok_or_else(|| anyhow!("form-sequence target"))?;
    let checkbox_index = parse_form_sequence_checkbox_index(query)
        .ok_or_else(|| anyhow!("form-sequence checkbox"))?;

    if harness.click_selector("#slider span").await.is_err() {
        harness.click_selector("#slider").await?;
    }
    harness.wait_ms(60).await?;

    let current_value = harness
        .selector_texts("#val")
        .await?
        .into_iter()
        .find_map(|text| text.trim().parse::<i32>().ok())
        .ok_or_else(|| anyhow!("form-sequence slider value"))?;
    let delta = target_value - current_value;
    let key = if delta >= 0 {
        "ArrowRight"
    } else {
        "ArrowLeft"
    };
    for _ in 0..delta.abs() {
        harness.press_key(key).await?;
        harness.wait_ms(25).await?;
    }

    let final_value = harness
        .selector_texts("#val")
        .await?
        .into_iter()
        .find_map(|text| text.trim().parse::<i32>().ok())
        .ok_or_else(|| anyhow!("form-sequence final slider value"))?;
    if final_value != target_value {
        return Err(anyhow!(
            "form-sequence slider value {} did not reach target {}",
            final_value,
            target_value
        ));
    }

    harness
        .click_selector(&format!("#checkbox-{}", checkbox_index))
        .await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_form_sequence_2_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let radio_index =
        parse_form_sequence_2_radio_index(query).ok_or_else(|| anyhow!("form-sequence-2 radio"))?;
    let textbox_index = parse_form_sequence_2_textbox_index(query)
        .ok_or_else(|| anyhow!("form-sequence-2 textbox"))?;
    let number = quoted_values(query)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("form-sequence-2 number"))?;

    harness
        .click_selector(&format!(
            "#area > div:nth-of-type(1) > input:nth-of-type({})",
            radio_index
        ))
        .await?;
    harness
        .type_text(&format!("#input-{}", textbox_index), &number)
        .await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_form_sequence_3_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let dropdown_label = parse_form_sequence_3_dropdown_label(query)
        .ok_or_else(|| anyhow!("form-sequence-3 dropdown"))?;
    let button_label = quoted_values(query)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("form-sequence-3 button"))?;

    harness
        .select_dropdown_label("#dropdown", &dropdown_label)
        .await?;
    harness.click_bridge_label(&button_label).await?;
    Ok(())
}

async fn dismiss_login_popup_if_present(harness: &mut DirectHarness) -> Result<bool> {
    let state = harness.refresh_bridge_state().await?;
    let Some(selector) = bridge_selector_for_label(&state.info.interactive_elements, "Cancel")
    else {
        return Ok(false);
    };
    harness.click_selector(&selector).await?;
    harness.wait_ms(80).await?;
    Ok(true)
}

async fn focus_login_field_with_popup_recovery(
    harness: &mut DirectHarness,
    selector: &str,
) -> Result<()> {
    match harness.click_selector(selector).await {
        Ok(()) => {
            if dismiss_login_popup_if_present(harness).await? {
                harness.click_selector(selector).await?;
            }
            Ok(())
        }
        Err(err) => {
            if dismiss_login_popup_if_present(harness).await? {
                harness.click_selector(selector).await?;
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

async fn run_login_user_popup_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let quoted = quoted_values(query);
    let username = quoted
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("login-user-popup username"))?;
    let password = quoted
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow!("login-user-popup password"))?;

    focus_login_field_with_popup_recovery(harness, "#username").await?;
    harness.type_text("#username", &username).await?;

    focus_login_field_with_popup_recovery(harness, "#password").await?;
    harness.type_text("#password", &password).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_text_editor_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    const EDITOR_SELECTOR: &str = "#editor .ql-editor";
    const COLOR_SELECTOR: &str = "#area > div:nth-of-type(1) > span:nth-of-type(1) > select";

    let editor_text = harness
        .selector_texts(EDITOR_SELECTOR)
        .await?
        .into_iter()
        .find(|text| !text.trim().is_empty())
        .map(|text| {
            text.lines()
                .next()
                .unwrap_or(text.as_str())
                .trim()
                .to_string()
        })
        .ok_or_else(|| anyhow!("text-editor content"))?;
    let action_token =
        parse_text_editor_action_token(query).ok_or_else(|| anyhow!("text-editor action"))?;
    let target = parse_text_editor_target(query).ok_or_else(|| anyhow!("text-editor target"))?;

    let (start_offset, end_offset) = if let Some(target_text) = target {
        let start_byte = editor_text
            .find(&target_text)
            .ok_or_else(|| anyhow!("text-editor target '{}' not found", target_text))?;
        let prefix = &editor_text[..start_byte];
        let start = prefix.chars().count() as u32;
        let end = start + target_text.chars().count() as u32;
        (start, end)
    } else {
        (0, editor_text.chars().count() as u32)
    };

    harness
        .select_text(Some(EDITOR_SELECTOR), Some(start_offset), Some(end_offset))
        .await?;

    match action_token.as_str() {
        "bold" => {
            harness
                .press_key_with_modifiers("b", &[primary_browser_modifier()])
                .await?
        }
        "italics" => {
            harness
                .press_key_with_modifiers("i", &[primary_browser_modifier()])
                .await?
        }
        "underlined" => {
            harness
                .press_key_with_modifiers("u", &[primary_browser_modifier()])
                .await?
        }
        color_name => {
            let color_value = text_editor_color_value(color_name)
                .ok_or_else(|| anyhow!("unsupported text-editor color '{}'", color_name))?;
            harness
                .select_dropdown_value(COLOR_SELECTOR, color_value)
                .await?;
        }
    }

    harness.wait_ms(80).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_simple_arithmetic_sequence(harness: &mut DirectHarness) -> Result<()> {
    let problem = harness
        .selector_texts("#math-problem")
        .await?
        .into_iter()
        .find(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("simple-arithmetic problem"))?;
    let answer = solve_simple_arithmetic_problem(&problem)
        .ok_or_else(|| anyhow!("simple-arithmetic solve '{}'", problem))?;
    harness
        .type_text("#math-answer", &answer.to_string())
        .await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_simple_algebra_sequence(harness: &mut DirectHarness) -> Result<()> {
    let problem = harness
        .selector_texts("#math-problem")
        .await?
        .into_iter()
        .find(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("simple-algebra problem"))?;
    let answer = solve_simple_algebra_problem(&problem)
        .ok_or_else(|| anyhow!("simple-algebra solve '{}'", problem))?;
    harness
        .type_text("#math-answer", &answer.to_string())
        .await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_odd_or_even_sequence(harness: &mut DirectHarness) -> Result<()> {
    let numbers = harness.selector_texts("#numbers .display-number").await?;
    if numbers.is_empty() {
        return Err(anyhow!("odd-or-even numbers"));
    }
    for (index, number_text) in numbers.iter().enumerate() {
        let value = parse_first_integer(number_text)
            .ok_or_else(|| anyhow!("odd-or-even parse '{}'", number_text))?;
        let parity_selector = if value.rem_euclid(2) == 0 {
            ".even"
        } else {
            ".odd"
        };
        harness
            .click_selector(&format!(
                "#numbers .row:nth-of-type({}) {}",
                index + 1,
                parity_selector
            ))
            .await?;
    }
    harness.click_selector("#submit").await?;
    Ok(())
}

async fn replace_input_text(harness: &mut DirectHarness, selector: &str, text: &str) -> Result<()> {
    harness.click_selector(selector).await?;
    harness
        .press_key_with_modifiers("a", &[primary_browser_modifier()])
        .await?;
    harness.type_text(selector, text).await?;
    Ok(())
}

async fn run_guess_number_sequence(harness: &mut DirectHarness) -> Result<()> {
    let mut low = 0;
    let mut high = 9;
    for _ in 0..5 {
        let guess = (low + high) / 2;
        replace_input_text(harness, "#tt", &guess.to_string()).await?;
        harness.click_selector("#subbtn").await?;

        if harness
            .selector_texts("#correct:not(.hide)")
            .await?
            .into_iter()
            .any(|text| normalize_label(&text) == "correct!")
        {
            return Ok(());
        }

        if let Some(feedback) = harness
            .selector_texts("#higher:not(.hide)")
            .await?
            .into_iter()
            .find(|text| !text.trim().is_empty())
        {
            let pivot = parse_first_integer(&feedback)
                .ok_or_else(|| anyhow!("guess-number higher feedback '{}'", feedback))?;
            low = pivot + 1;
            continue;
        }

        if let Some(feedback) = harness
            .selector_texts("#lower:not(.hide)")
            .await?
            .into_iter()
            .find(|text| !text.trim().is_empty())
        {
            let pivot = parse_first_integer(&feedback)
                .ok_or_else(|| anyhow!("guess-number lower feedback '{}'", feedback))?;
            high = pivot - 1;
            continue;
        }
    }

    Err(anyhow!("guess-number failed to converge"))
}

async fn run_find_greatest_sequence(harness: &mut DirectHarness) -> Result<()> {
    let card_values = harness
        .selector_texts_all("#cardholder .card-value")
        .await?;
    let (target_index, _) = card_values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| parse_first_integer(value).map(|parsed| (index, parsed)))
        .max_by_key(|(_, value)| *value)
        .ok_or_else(|| anyhow!("find-greatest card values"))?;
    harness
        .click_selector(&format!(
            "#cardholder .card:nth-of-type({})",
            target_index + 1
        ))
        .await?;
    harness.click_selector("#submit").await?;
    Ok(())
}

async fn run_find_word_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let word_index = parse_find_word_index(query).ok_or_else(|| anyhow!("find-word index"))?;
    let paragraph = harness
        .selector_texts("#area p")
        .await?
        .into_iter()
        .find(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow!("find-word paragraph"))?;
    let words = paragraph
        .split_whitespace()
        .map(|word| {
            word.chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .collect::<String>()
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let answer = words
        .get(word_index.saturating_sub(1))
        .cloned()
        .ok_or_else(|| anyhow!("find-word target word {}", word_index))?;
    harness.type_text("#answer-input", &answer).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_read_table_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let target = parse_read_table_target(query).ok_or_else(|| anyhow!("read-table target"))?;
    let values = table_value_map(&harness.selector_texts("#tab table td").await?);
    let answer = values
        .get(&target)
        .cloned()
        .ok_or_else(|| anyhow!("read-table value for '{}'", target))?;
    harness.type_text("#tt", &answer).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_read_table_2_sequence(harness: &mut DirectHarness) -> Result<()> {
    let values = table_value_map(&harness.selector_texts("#tab table td").await?);
    let label_1 = harness
        .selector_texts("#ll1")
        .await?
        .into_iter()
        .next()
        .map(|text| text.trim().trim_end_matches(':').to_string())
        .filter(|text| !text.is_empty())
        .ok_or_else(|| anyhow!("read-table-2 label 1"))?;
    let label_2 = harness
        .selector_texts("#ll2")
        .await?
        .into_iter()
        .next()
        .map(|text| text.trim().trim_end_matches(':').to_string())
        .filter(|text| !text.is_empty())
        .ok_or_else(|| anyhow!("read-table-2 label 2"))?;
    let value_1 = values
        .get(&label_1)
        .cloned()
        .ok_or_else(|| anyhow!("read-table-2 value for '{}'", label_1))?;
    let value_2 = values
        .get(&label_2)
        .cloned()
        .ok_or_else(|| anyhow!("read-table-2 value for '{}'", label_2))?;
    harness.type_text("#tt1", &value_1).await?;
    harness.type_text("#tt2", &value_2).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn advance_phone_book_page(harness: &mut DirectHarness) -> Result<()> {
    if harness.click_bridge_label(">").await.is_ok() {
        harness.wait_ms(80).await?;
        return Ok(());
    }
    for selector in ["#pagination li.next a", "#pagination .next a"] {
        if harness.click_selector(selector).await.is_ok() {
            harness.wait_ms(80).await?;
            return Ok(());
        }
    }
    Err(anyhow!("phone-book next page control not available"))
}

async fn run_phone_book_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let target_name = parse_phone_book_name(query).ok_or_else(|| anyhow!("phone-book name"))?;
    let target_kind = parse_phone_book_target(query).ok_or_else(|| anyhow!("phone-book target"))?;
    let property_selector = match normalize_label(&target_kind).as_str() {
        "phone number" | "phone" => "#contact .phone",
        "email" => "#contact .email",
        "address" => "#contact .address",
        other => return Err(anyhow!("phone-book target '{}'", other)),
    };

    for page_index in 0..5 {
        let current_name = harness
            .selector_texts("#contact .name")
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("phone-book current contact"))?;
        if normalize_label(&current_name) == normalize_label(&target_name) {
            harness.click_selector(property_selector).await?;
            return Ok(());
        }
        if page_index < 4 {
            advance_phone_book_page(harness).await?;
        }
    }

    Err(anyhow!("phone-book contact '{}' not found", target_name))
}

async fn click_social_media_action_for_row(
    harness: &mut DirectHarness,
    row_index: usize,
    button_label: &str,
) -> Result<()> {
    let (action_class, requires_menu) = social_media_action_class(button_label)
        .ok_or_else(|| anyhow!("social-media button '{}'", button_label))?;
    let row_selector = format!("#area .media:nth-of-type({})", row_index);
    if requires_menu {
        harness
            .click_selector(&format!("{row_selector} .more"))
            .await?;
        harness.wait_ms(50).await?;
    }
    harness
        .click_selector(&format!("{row_selector} .{action_class}"))
        .await?;
    Ok(())
}

async fn run_social_media_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let target_user = parse_social_media_user(query).ok_or_else(|| anyhow!("social-media user"))?;
    let button_label =
        parse_social_media_button(query).ok_or_else(|| anyhow!("social-media button"))?;
    let usernames = harness.selector_texts_all("#area .media .username").await?;
    let row_index = usernames
        .iter()
        .position(|username| normalize_label(username) == normalize_label(&target_user))
        .map(|index| index + 1)
        .ok_or_else(|| anyhow!("social-media user '{}' not found", target_user))?;
    click_social_media_action_for_row(harness, row_index, &button_label).await?;
    Ok(())
}

async fn run_social_media_multi_sequence(
    harness: &mut DirectHarness,
    query: &str,
    required_count: Option<usize>,
) -> Result<()> {
    let target_user = parse_social_media_user(query).ok_or_else(|| anyhow!("social-media user"))?;
    let button_label =
        parse_social_media_button(query).ok_or_else(|| anyhow!("social-media button"))?;
    let usernames = harness.selector_texts_all("#area .media .username").await?;
    let matching_rows = usernames
        .iter()
        .enumerate()
        .filter_map(|(index, username)| {
            (normalize_label(username) == normalize_label(&target_user)).then_some(index + 1)
        })
        .collect::<Vec<_>>();
    let expected_count = required_count.unwrap_or(matching_rows.len());
    if matching_rows.len() < expected_count {
        return Err(anyhow!(
            "social-media expected {} rows for '{}', found {}",
            expected_count,
            target_user,
            matching_rows.len()
        ));
    }
    for row_index in matching_rows.into_iter().take(expected_count) {
        click_social_media_action_for_row(harness, row_index, &button_label).await?;
    }
    harness.click_selector("#submitRow button").await?;
    Ok(())
}

async fn run_stock_market_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let threshold =
        parse_stock_market_threshold(query).ok_or_else(|| anyhow!("stock-market threshold"))?;
    for _ in 0..3 {
        let state = harness.refresh_bridge_state().await?;
        if state.info.focused_id.as_deref() == Some("buy") {
            break;
        }
        harness.press_key("Tab").await?;
    }
    for _ in 0..120 {
        let state = harness.refresh_bridge_state().await?;
        let bridge_price = state
            .info
            .visible_text_excerpt
            .as_deref()
            .and_then(parse_stock_market_visible_price);
        let dom_price = timeout(
            Duration::from_millis(300),
            harness.selector_text("#stock-price"),
        )
        .await
        .ok()
        .and_then(|result| result.ok())
        .flatten()
        .and_then(|text| parse_currency_text(&text));
        let current_price = dom_price.or(bridge_price);
        if let Some(current_price) = current_price {
            if current_price <= threshold {
                if state.info.focused_id.as_deref() == Some("buy") {
                    harness.press_key("Enter").await?;
                } else {
                    harness.click_selector("#buy").await?;
                }
                return Ok(());
            }
        }
        harness.wait_ms(100).await?;
    }
    Err(anyhow!(
        "stock-market price never reached threshold {}",
        threshold
    ))
}

async fn run_email_inbox_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let sender = email_inbox_sender_value(&harness.bridge_state, query)
        .ok_or_else(|| anyhow!("email-inbox sender"))?;
    let action = email_inbox_action_value(&harness.bridge_state, query)
        .ok_or_else(|| anyhow!("email-inbox action"))?;
    let senders = harness
        .selector_texts_all("#main .email-thread .email-sender")
        .await?;
    let row_index = find_email_inbox_row_index(&senders, &sender)
        .ok_or_else(|| anyhow!("email-inbox sender '{}' not found", sender))?;
    let row_selector = email_inbox_row_selector(row_index);

    match action {
        "delete" => {
            harness
                .click_selector(&format!("{row_selector} .trash"))
                .await?;
        }
        "important" => {
            harness
                .click_selector(&format!("{row_selector} .star"))
                .await?;
        }
        "reply" => {
            let reply_text = email_inbox_reply_value(&harness.bridge_state, query)
                .ok_or_else(|| anyhow!("email-inbox reply text"))?;
            harness.click_selector(&row_selector).await?;
            harness.wait_ms(80).await?;
            harness.click_selector("#email .email-reply").await?;
            harness.wait_ms(80).await?;
            harness.type_text("#reply-text", &reply_text).await?;
            harness.click_selector("#send-reply").await?;
        }
        "forward" => {
            let recipient = email_inbox_forward_value(&harness.bridge_state, query)
                .ok_or_else(|| anyhow!("email-inbox forward recipient"))?;
            harness.click_selector(&row_selector).await?;
            harness.wait_ms(80).await?;
            harness.click_selector("#email .email-forward").await?;
            harness.wait_ms(80).await?;
            harness.type_text(".forward-sender", &recipient).await?;
            harness.click_selector("#send-forward").await?;
        }
        other => return Err(anyhow!("email-inbox unsupported action '{}'", other)),
    }

    Ok(())
}

async fn run_visual_addition_sequence(harness: &mut DirectHarness) -> Result<()> {
    let addend_a = harness
        .selector_elements("#visual-1 .addition-block")
        .await?
        .into_iter()
        .filter(|summary| summary.visible)
        .count();
    let addend_b = harness
        .selector_elements("#visual-2 .addition-block")
        .await?
        .into_iter()
        .filter(|summary| summary.visible)
        .count();
    harness
        .type_text("#math-answer", &(addend_a + addend_b).to_string())
        .await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

async fn run_identify_shape_sequence(harness: &mut DirectHarness) -> Result<()> {
    let elements = harness.selector_elements("#area_svg > *").await?;
    let summary = elements
        .into_iter()
        .find(|summary| summary.visible)
        .ok_or_else(|| anyhow!("identify-shape found no visible SVG element"))?;
    let target = svg_shape_kind(&summary).ok_or_else(|| anyhow!("identify-shape kind"))?;
    harness
        .click_selector(&format!("#area-buttons button[data-type='{}']", target))
        .await?;
    Ok(())
}

async fn run_count_shape_sequence(harness: &mut DirectHarness, query: &str) -> Result<()> {
    let descriptor =
        parse_count_shape_descriptor(query).ok_or_else(|| anyhow!("count-shape descriptor"))?;
    let elements = harness.selector_elements("#area_svg > *").await?;
    let count = count_shape_matches(&elements, &descriptor);
    harness.click_bridge_label(&count.to_string()).await?;
    Ok(())
}

async fn run_count_sides_sequence(harness: &mut DirectHarness) -> Result<()> {
    let summary = harness.canvas_shape_summary("#c").await?;
    let estimated_sides = summary
        .estimated_sides
        .ok_or_else(|| anyhow!("count-sides summary missing estimate: {:?}", summary))?;
    harness
        .click_bridge_label(&estimated_sides.to_string())
        .await?;
    Ok(())
}

async fn run_find_midpoint_sequence(harness: &mut DirectHarness) -> Result<()> {
    let circles = harness.selector_elements("#svg-grid .black-circle").await?;
    let visible_circles = circles
        .into_iter()
        .filter(|summary| summary.visible)
        .collect::<Vec<_>>();
    if visible_circles.len() != 2 {
        return Err(anyhow!(
            "find-midpoint expected 2 visible circles, found {}",
            visible_circles.len()
        ));
    }
    let svg_rect = harness
        .browser
        .get_selector_rect_window_logical("#svg-grid")
        .await
        .map_err(|err| anyhow!("find-midpoint svg rect: {}", err))?;
    let point_a_x = svg_numeric_attribute(&visible_circles[0], "cx")
        .unwrap_or(visible_circles[0].center_x - svg_rect.x);
    let point_a_y = svg_numeric_attribute(&visible_circles[0], "cy")
        .unwrap_or(visible_circles[0].center_y - svg_rect.y);
    let point_b_x = svg_numeric_attribute(&visible_circles[1], "cx")
        .unwrap_or(visible_circles[1].center_x - svg_rect.x);
    let point_b_y = svg_numeric_attribute(&visible_circles[1], "cy")
        .unwrap_or(visible_circles[1].center_y - svg_rect.y);
    let midpoint_x = svg_rect.x + ((point_a_x + point_b_x) / 2.0);
    let midpoint_y = svg_rect.y + ((point_a_y + point_b_y) / 2.0);
    harness.click_point(midpoint_x, midpoint_y).await?;
    harness.wait_ms(80).await?;
    harness.click_selector("#subbtn").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        bridge_checkbox_checked_for_label, bridge_hidden_collapsible_selector_for_label,
        bridge_hidden_tab_selector_for_label, count_shape_matches, email_inbox_action_value,
        email_inbox_forward_value, email_inbox_reply_value, email_inbox_sender_value,
        find_email_inbox_row_index, odd_or_even_visible_numbers, parse_count_shape_descriptor,
        parse_email_inbox_action, parse_email_inbox_forward_recipient,
        parse_email_inbox_reply_text, parse_email_inbox_sender, parse_social_media_user,
        parse_stock_market_threshold, parse_stock_market_visible_price,
        should_break_agent_loop_for_reward, solve_simple_algebra_problem,
        solve_simple_arithmetic_problem, svg_shape_kind, visible_table_value_map, BridgeClient,
        ComputerUseCase, MiniwobAgentRuntime,
    };
    use crate::computer_use_suite::types::{
        AllowedToolProfile, BridgeField, BridgeInfo, BridgeInteractiveElement, BridgeScrollTarget,
        BridgeState, LocalJudge, RecipeId, TaskSet,
    };
    use ioi_drivers::browser::BrowserDomElementSummary;
    use ioi_types::app::agentic::StepTrace;
    use ioi_types::app::{
        KernelEvent, RoutingPostStateSummary, RoutingReceiptEvent, RoutingStateSummary,
    };
    use reqwest::Client;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Mutex;

    fn test_runtime(recipe: RecipeId, expected_reward_floor: f32) -> MiniwobAgentRuntime {
        MiniwobAgentRuntime {
            case: ComputerUseCase {
                id: format!("test_{recipe:?}").to_ascii_lowercase(),
                env_id: "test-env".to_string(),
                seed: 1,
                task_set: TaskSet::Catalog,
                max_steps: 16,
                timeout_seconds: 20,
                allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelectionClipboard,
                expected_reward_floor,
                expected_pass: true,
                local_judge: LocalJudge::MiniwobReward,
                recipe,
            },
            client: BridgeClient {
                http: Client::new(),
                base_url: "http://127.0.0.1:1".to_string(),
            },
            session_id: "test-session".to_string(),
            url: "file:///tmp/miniwob/test.1.html".to_string(),
            startup_navigation_issued: Mutex::new(true),
            pending_followup: Mutex::new(None),
            optimistic_checked_labels: Mutex::new(BTreeSet::new()),
            last_scroll_action: Mutex::new(None),
            last_copy_paste_action: Mutex::new(None),
            last_hover_shape_phase: Mutex::new(None),
        }
    }

    #[test]
    fn parses_social_media_user_variants() {
        assert_eq!(
            parse_social_media_user("For the user @cedar, click on the \"Like\" button."),
            Some("@cedar".to_string())
        );
        assert_eq!(
            parse_social_media_user(
                "Click the \"Like\" button on all posts by @elm and then click Submit."
            ),
            Some("@elm".to_string())
        );
        assert_eq!(
            parse_social_media_user(
                "Click the \"Share\" button on 1 post by @arcu and then click Submit."
            ),
            Some("@arcu".to_string())
        );
    }

    #[test]
    fn parses_stock_market_price_from_query_and_visible_text() {
        assert_eq!(
            parse_stock_market_threshold("Buy YJV stock when the price is less than $59.60."),
            Some(59.60)
        );
        assert_eq!(
            parse_stock_market_visible_price(
                "Buy YJV stock when the price is less than $59.60. Company: YJV Stock price: $58.00 Buy"
            ),
            Some(58.00)
        );
    }

    #[test]
    fn solves_text_math_problems() {
        assert_eq!(solve_simple_arithmetic_problem("7 x 5 ="), Some(35));
        assert_eq!(solve_simple_arithmetic_problem("9 - 4 ="), Some(5));
        assert_eq!(solve_simple_algebra_problem("x + 7 = 18"), Some(11));
        assert_eq!(solve_simple_algebra_problem("x - 3 = 10"), Some(13));
        assert_eq!(solve_simple_algebra_problem("9 - x = 4"), Some(5));
        assert_eq!(solve_simple_algebra_problem("6 + x = 15"), Some(9));
    }

    #[test]
    fn visible_table_value_map_ignores_form_labels_after_table_values() {
        let values = visible_table_value_map(
            "First name Alvinia Country Faroe Islands Gender Male Color green Religion Hinduism First name: Country: Submit",
        );

        assert_eq!(values.get("First name"), Some(&"Alvinia".to_string()));
        assert_eq!(values.get("Country"), Some(&"Faroe Islands".to_string()));
        assert_eq!(values.get("Religion"), Some(&"Hinduism".to_string()));
    }

    #[test]
    fn odd_or_even_visible_numbers_preserve_signed_values() {
        assert_eq!(
            odd_or_even_visible_numbers("Odd 9 Even Odd -2 Even Odd -5 Even Submit"),
            vec![9, -2, -5]
        );
    }

    #[test]
    fn parses_count_shape_descriptors_and_matches_visible_shapes() {
        assert_eq!(
            parse_count_shape_descriptor("How many large red items are there?"),
            Some("large red item".to_string())
        );

        let large_red_rect = BrowserDomElementSummary {
            tag: "rect".to_string(),
            text: String::new(),
            visible: true,
            attributes: HashMap::from([("fill".to_string(), "red".to_string())]),
            x: 0.0,
            y: 0.0,
            width: 20.0,
            height: 20.0,
            center_x: 10.0,
            center_y: 10.0,
        };
        let small_blue_circle = BrowserDomElementSummary {
            tag: "circle".to_string(),
            text: String::new(),
            visible: true,
            attributes: HashMap::from([("fill".to_string(), "blue".to_string())]),
            x: 0.0,
            y: 0.0,
            width: 10.0,
            height: 10.0,
            center_x: 5.0,
            center_y: 5.0,
        };
        let hidden_red_rect = BrowserDomElementSummary {
            visible: false,
            ..large_red_rect.clone()
        };

        assert_eq!(
            count_shape_matches(
                &[large_red_rect, small_blue_circle, hidden_red_rect],
                "large red item"
            ),
            1
        );
    }

    #[test]
    fn classifies_svg_text_nodes_as_letters_or_digits() {
        let letter = BrowserDomElementSummary {
            tag: "text".to_string(),
            text: "A".to_string(),
            visible: true,
            attributes: HashMap::from([("font-size".to_string(), "20px".to_string())]),
            x: 0.0,
            y: 0.0,
            width: 20.0,
            height: 20.0,
            center_x: 10.0,
            center_y: 10.0,
        };
        let digit = BrowserDomElementSummary {
            text: "7".to_string(),
            ..letter.clone()
        };

        assert_eq!(svg_shape_kind(&letter), Some("letter"));
        assert_eq!(svg_shape_kind(&digit), Some("digit"));
    }

    #[test]
    fn parses_email_inbox_queries_and_finds_row_indices() {
        assert_eq!(
            parse_email_inbox_sender(
                "Find the email by Riley Oak and reply to them with the text \"see you\"."
            ),
            Some("Riley Oak".to_string())
        );
        assert_eq!(
            parse_email_inbox_reply_text(
                "Find the email by Riley Oak and reply to them with the text \"see you\"."
            ),
            Some("see you".to_string())
        );
        assert_eq!(
            parse_email_inbox_forward_recipient(
                "Find the email by Riley Oak and forward that email to Avery Lake."
            ),
            Some("Avery Lake".to_string())
        );
        assert_eq!(
            parse_email_inbox_action(
                "Find the email by Riley Oak and click the star icon to mark it as important."
            ),
            Some("important")
        );
        assert_eq!(
            find_email_inbox_row_index(
                &["Alex Reed".to_string(), "Riley Oak".to_string()],
                "Riley Oak"
            ),
            Some(2)
        );
    }

    #[test]
    fn email_inbox_bridge_fields_override_literal_query_parsing() {
        let bridge_state = BridgeState {
            utterance: "Delete the email from Pearla.".to_string(),
            info: BridgeInfo {
                fields: vec![
                    BridgeField {
                        key: "task".to_string(),
                        value: "delete".to_string(),
                    },
                    BridgeField {
                        key: "by".to_string(),
                        value: "Pearla".to_string(),
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        assert_eq!(
            email_inbox_sender_value(&bridge_state, &bridge_state.utterance),
            Some("Pearla".to_string())
        );
        assert_eq!(
            email_inbox_action_value(&bridge_state, &bridge_state.utterance),
            Some("delete")
        );
    }

    #[test]
    fn email_inbox_bridge_fields_infer_forward_and_reply_variants() {
        let forward_state = BridgeState {
            utterance: "Give Floria the message you received from Freida,".to_string(),
            info: BridgeInfo {
                fields: vec![
                    BridgeField {
                        key: "by".to_string(),
                        value: "Freida".to_string(),
                    },
                    BridgeField {
                        key: "to".to_string(),
                        value: "Floria".to_string(),
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };
        let reply_state = BridgeState {
            utterance: "Reply to NAME's email with \"MSG\"".to_string(),
            info: BridgeInfo {
                fields: vec![
                    BridgeField {
                        key: "task".to_string(),
                        value: "reply".to_string(),
                    },
                    BridgeField {
                        key: "by".to_string(),
                        value: "Nina".to_string(),
                    },
                    BridgeField {
                        key: "message".to_string(),
                        value: "see you soon".to_string(),
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        assert_eq!(
            email_inbox_action_value(&forward_state, &forward_state.utterance),
            Some("forward")
        );
        assert_eq!(
            email_inbox_forward_value(&forward_state, &forward_state.utterance),
            Some("Floria".to_string())
        );
        assert_eq!(
            email_inbox_action_value(&reply_state, &reply_state.utterance),
            Some("reply")
        );
        assert_eq!(
            email_inbox_reply_value(&reply_state, &reply_state.utterance),
            Some("see you soon".to_string())
        );
    }

    #[test]
    fn agent_loop_reward_short_circuit_ignores_zero_floor_tasks() {
        let zero_floor_state = BridgeState {
            reward: 0.0,
            ..BridgeState::default()
        };
        let positive_floor_state = BridgeState {
            reward: 1.0,
            ..BridgeState::default()
        };

        assert!(!should_break_agent_loop_for_reward(&zero_floor_state, 0.0));
        assert!(should_break_agent_loop_for_reward(
            &positive_floor_state,
            1.0
        ));
    }

    #[test]
    fn zero_floor_hover_tasks_do_not_short_circuit_after_readiness() {
        let runtime = MiniwobAgentRuntime {
            case: ComputerUseCase {
                id: "miniwob_catalog_hover_shape".to_string(),
                env_id: "hover-shape".to_string(),
                seed: 11,
                task_set: TaskSet::Catalog,
                max_steps: 8,
                timeout_seconds: 20,
                allowed_tool_profile: AllowedToolProfile::BrowserCore,
                expected_reward_floor: 0.0,
                expected_pass: true,
                local_judge: LocalJudge::HoverShapeReceipts,
                recipe: RecipeId::HoverShape,
            },
            client: BridgeClient {
                http: Client::new(),
                base_url: "http://127.0.0.1:1".to_string(),
            },
            session_id: "hover-session".to_string(),
            url: "file:///tmp/miniwob/hover-shape.1.html".to_string(),
            startup_navigation_issued: Mutex::new(true),
            pending_followup: Mutex::new(None),
            optimistic_checked_labels: Mutex::new(BTreeSet::new()),
            last_scroll_action: Mutex::new(None),
            last_copy_paste_action: Mutex::new(None),
            last_hover_shape_phase: Mutex::new(None),
        };
        let bridge_state = BridgeState {
            utterance: "Keep the mouse hovered over the colored square.".to_string(),
            reward: 0.0,
            info: BridgeInfo {
                task_ready: Some(true),
                raw_reward: Some(0.0),
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse tool action");

        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__hover")
        );
    }

    #[test]
    fn hidden_tab_target_maps_back_to_tab_anchor() {
        let elements = vec![
            BridgeInteractiveElement {
                selector: Some("#tabs-3 > p > span:nth-of-type(4)".to_string()),
                text: "nibh.".to_string(),
                visible: false,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
            BridgeInteractiveElement {
                selector: Some("#ui-id-3".to_string()),
                text: "Tab #3".to_string(),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
        ];

        assert_eq!(
            bridge_hidden_tab_selector_for_label(&elements, "nibh."),
            Some("a[href='#tabs-3']".to_string())
        );
    }

    #[test]
    fn hidden_collapsible_target_maps_back_to_section_header() {
        let elements = vec![BridgeInteractiveElement {
            selector: Some("#ui-id-4 > span:nth-of-type(4)".to_string()),
            text: "et".to_string(),
            visible: false,
            disabled: false,
            ..BridgeInteractiveElement::default()
        }];

        assert_eq!(
            bridge_hidden_collapsible_selector_for_label(&elements, "et"),
            Some("#area h3:nth-of-type(2)".to_string())
        );
    }

    #[test]
    fn checkbox_checked_state_is_resolved_from_adjacent_input() {
        let elements = vec![
            BridgeInteractiveElement {
                selector: Some("#boxes-left > label:nth-of-type(0)".to_string()),
                text: "Other".to_string(),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
            BridgeInteractiveElement {
                selector: Some("#ch-1".to_string()),
                checked: Some(false),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
            BridgeInteractiveElement {
                selector: Some("#boxes-left > label:nth-of-type(1)".to_string()),
                text: "PfKtB".to_string(),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
            BridgeInteractiveElement {
                selector: Some("#ch0".to_string()),
                checked: Some(true),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
        ];

        assert_eq!(
            bridge_checkbox_checked_for_label(&elements, "PfKtB"),
            Some(true)
        );
    }

    #[test]
    fn hover_shape_recovery_waits_before_retrying_same_phase() {
        let runtime = MiniwobAgentRuntime {
            case: ComputerUseCase {
                id: "miniwob_catalog_hover_shape".to_string(),
                env_id: "hover-shape".to_string(),
                seed: 11,
                task_set: TaskSet::Catalog,
                max_steps: 12,
                timeout_seconds: 20,
                allowed_tool_profile: AllowedToolProfile::BrowserCore,
                expected_reward_floor: 0.0,
                expected_pass: true,
                local_judge: LocalJudge::HoverShapeReceipts,
                recipe: RecipeId::HoverShape,
            },
            client: BridgeClient {
                http: Client::new(),
                base_url: "http://127.0.0.1:1".to_string(),
            },
            session_id: "hover-session".to_string(),
            url: "file:///tmp/miniwob/hover-shape.1.html".to_string(),
            startup_navigation_issued: Mutex::new(true),
            pending_followup: Mutex::new(None),
            optimistic_checked_labels: Mutex::new(BTreeSet::new()),
            last_scroll_action: Mutex::new(None),
            last_copy_paste_action: Mutex::new(None),
            last_hover_shape_phase: Mutex::new(Some("await_post_hover_2".to_string())),
        };
        let bridge_state = BridgeState {
            utterance: "Keep the mouse hovered over the colored square.".to_string(),
            reward: 0.0,
            info: BridgeInfo {
                task_ready: Some(true),
                raw_reward: Some(0.0),
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let recovery = runtime.hover_shape_recovery_action(
            "You are an ontology incident resolver.\n2. Forbidden tools: \n- Visited remedy fingerprints: none\n",
        );
        let recovery_parsed: Value = serde_json::from_slice(&recovery).expect("parse wait");
        assert_eq!(
            recovery_parsed.get("name").and_then(Value::as_str),
            Some("browser__wait")
        );
        assert_eq!(
            recovery_parsed
                .get("arguments")
                .and_then(|args| args.get("ms"))
                .and_then(Value::as_u64),
            Some(1300)
        );
        assert_eq!(
            runtime.hover_shape_phase().as_deref(),
            Some("retry_hover_2_after_wait")
        );

        let retry_hover = runtime.next_action(&bridge_state);
        let retry_hover_parsed: Value =
            serde_json::from_slice(&retry_hover).expect("parse hover retry");
        assert_eq!(
            retry_hover_parsed.get("name").and_then(Value::as_str),
            Some("browser__hover")
        );
        assert_eq!(
            retry_hover_parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#highlight")
        );
        assert_eq!(
            runtime.hover_shape_phase().as_deref(),
            Some("await_post_hover_2")
        );
    }

    #[test]
    fn click_tab_without_quoted_target_uses_numeric_tab_selector() {
        let runtime = test_runtime(RecipeId::ClickTab, 1.0);
        let bridge_state = BridgeState {
            utterance: "Click on Tab #2.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#ui-id-1".to_string()),
                        text: "Tab #1".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ui-id-2".to_string()),
                        text: "Tab #2".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse click-tab action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#ui-id-2")
        );
    }

    #[test]
    fn checkbox_agent_progress_is_driven_by_checked_state_not_episode_step() {
        let runtime = test_runtime(RecipeId::ClickCheckboxes, 0.5);
        let bridge_state = BridgeState {
            utterance: "Select NYt2, Pj6KGY and click Submit.".to_string(),
            episode_step: 10,
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#boxes-left > label:nth-of-type(1)".to_string()),
                        text: "NYt2".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch0".to_string()),
                        checked: Some(false),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#boxes-right > label:nth-of-type(1)".to_string()),
                        text: "Pj6KGY".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch1".to_string()),
                        checked: Some(false),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("button".to_string()),
                        text: "Submit".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse checkbox action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#boxes-left > label:nth-of-type(1)")
        );
    }

    #[test]
    fn checkbox_agent_advances_with_optimistic_click_state_until_bridge_confirms() {
        let runtime = test_runtime(RecipeId::ClickCheckboxes, 0.5);
        let stale_bridge_state = BridgeState {
            utterance: "Select NYt2, Pj6KGY and click Submit.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#boxes-left > label:nth-of-type(1)".to_string()),
                        text: "NYt2".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch0".to_string()),
                        checked: Some(false),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#boxes-right > label:nth-of-type(1)".to_string()),
                        text: "Pj6KGY".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch1".to_string()),
                        checked: Some(false),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("button".to_string()),
                        text: "Submit".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let first_action = runtime.next_action(&stale_bridge_state);
        let first_parsed: Value =
            serde_json::from_slice(&first_action).expect("parse first checkbox action");
        assert_eq!(
            first_parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#boxes-left > label:nth-of-type(1)")
        );

        let second_action = runtime.next_action(&stale_bridge_state);
        let second_parsed: Value =
            serde_json::from_slice(&second_action).expect("parse second checkbox action");
        assert_eq!(
            second_parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#boxes-right > label:nth-of-type(1)")
        );

        let sync_action = runtime.next_action(&stale_bridge_state);
        let sync_parsed: Value =
            serde_json::from_slice(&sync_action).expect("parse checkbox sync action");
        assert_eq!(
            sync_parsed.get("name").and_then(Value::as_str),
            Some("browser__wait")
        );

        let confirmed_bridge_state = BridgeState {
            utterance: stale_bridge_state.utterance.clone(),
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#boxes-left > label:nth-of-type(1)".to_string()),
                        text: "NYt2".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch0".to_string()),
                        checked: Some(true),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#boxes-right > label:nth-of-type(1)".to_string()),
                        text: "Pj6KGY".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#ch1".to_string()),
                        checked: Some(true),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("button".to_string()),
                        text: "Submit".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let submit_action = runtime.next_action(&confirmed_bridge_state);
        let submit_parsed: Value =
            serde_json::from_slice(&submit_action).expect("parse checkbox submit action");
        assert_eq!(
            submit_parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("button")
        );
    }

    #[test]
    fn checkbox_checked_state_uses_fuzzy_label_resolution() {
        let elements = vec![
            BridgeInteractiveElement {
                selector: Some("#boxes > label:nth-of-type(1)".to_string()),
                text: "large".to_string(),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
            BridgeInteractiveElement {
                selector: Some("#ch0".to_string()),
                checked: Some(true),
                visible: true,
                disabled: false,
                ..BridgeInteractiveElement::default()
            },
        ];

        assert_eq!(
            bridge_checkbox_checked_for_label(&elements, "words similar to large"),
            Some(true)
        );
    }

    #[test]
    fn enter_password_agent_moves_to_verify_field_after_first_value_matches() {
        let runtime = test_runtime(RecipeId::EnterPassword, 1.0);
        let bridge_state = BridgeState {
            utterance: "Enter the password \"P322\" into both text fields and press submit."
                .to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("subbtn".to_string()),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#password".to_string()),
                        id: Some("password".to_string()),
                        value: Some("P322".to_string()),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#verify".to_string()),
                        id: Some("verify".to_string()),
                        value: Some(String::new()),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse enter-password action");
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__click")
        );
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#verify")
        );
    }

    #[test]
    fn login_user_agent_moves_to_password_field_after_username_matches() {
        let runtime = test_runtime(RecipeId::LoginUser, 1.0);
        let bridge_state = BridgeState {
            utterance:
                "Enter the username \"annis\" and the password \"7mQ\" into the text fields and press login."
                    .to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("username".to_string()),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#username".to_string()),
                        id: Some("username".to_string()),
                        value: Some("annis".to_string()),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#password".to_string()),
                        id: Some("password".to_string()),
                        value: Some(String::new()),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse login-user action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#password")
        );
    }

    #[test]
    fn click_collapsible_agent_uses_hidden_target_to_pick_section() {
        let runtime = test_runtime(RecipeId::ClickCollapsible2, 1.0);
        let bridge_state = BridgeState {
            utterance: "Expand the sections below, to find and click on the link \"et\"."
                .to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![BridgeInteractiveElement {
                    selector: Some("#ui-id-4 > span:nth-of-type(4)".to_string()),
                    text: "et".to_string(),
                    visible: false,
                    disabled: false,
                    ..BridgeInteractiveElement::default()
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse collapsible action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#area h3:nth-of-type(2)")
        );
    }

    #[test]
    fn search_engine_agent_clicks_search_once_textbox_matches() {
        let runtime = test_runtime(RecipeId::SearchEngine, 1.0);
        let bridge_state = BridgeState {
            utterance:
                "Use the textbox to enter \"Sergio\" and press \"Search\", then find and click the 6th search result."
                    .to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("search-text".to_string()),
                interactive_elements: vec![
                    BridgeInteractiveElement {
                        selector: Some("#search-text".to_string()),
                        id: Some("search-text".to_string()),
                        value: Some("Sergio".to_string()),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                    BridgeInteractiveElement {
                        selector: Some("#search".to_string()),
                        id: Some("search".to_string()),
                        text: "Search".to_string(),
                        visible: true,
                        disabled: false,
                        ..BridgeInteractiveElement::default()
                    },
                ],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse search action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#search")
        );
    }

    #[test]
    fn simple_arithmetic_agent_types_answer_from_visible_excerpt() {
        let runtime = test_runtime(RecipeId::SimpleArithmetic, 1.0);
        let bridge_state = BridgeState {
            utterance: "Solve the math problem and type your answer into the textbox. Press submit when done.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("math-answer".to_string()),
                visible_text_excerpt: Some(
                    "Solve the math problem and type your answer into the textbox. Press submit when done. 4 + 2 = Submit Last reward: 0.00".to_string(),
                ),
                interactive_elements: vec![BridgeInteractiveElement {
                    selector: Some("#math-answer".to_string()),
                    id: Some("math-answer".to_string()),
                    value: Some(String::new()),
                    visible: true,
                    disabled: false,
                    ..BridgeInteractiveElement::default()
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse arithmetic action");
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__type")
        );
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("text"))
                .and_then(Value::as_str),
            Some("6")
        );
    }

    #[test]
    fn odd_or_even_agent_clicks_row_specific_parity_button() {
        let runtime = test_runtime(RecipeId::OddOrEven, 1.0);
        let bridge_state = BridgeState {
            utterance: "Mark the numbers below as odd or even and press submit when done."
                .to_string(),
            episode_step: 1,
            info: BridgeInfo {
                task_ready: Some(true),
                visible_text_excerpt: Some(
                    "Mark the numbers below as odd or even and press submit when done. Odd 9 Even Odd -2 Even Odd -5 Even Submit Last reward: 0.00".to_string(),
                ),
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse odd-even action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#numbers .row:nth-of-type(2) .even")
        );
    }

    #[test]
    fn phone_book_agent_pages_forward_until_target_name_matches() {
        let runtime = test_runtime(RecipeId::PhoneBook, 1.0);
        let bridge_state = BridgeState {
            utterance: "Find Deena in the contact book and click on their address.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                visible_text_excerpt: Some(
                    "Find Deena in the contact book and click on their address. Aaren Phone: 315-479-0478 Email: aaren689@live.se Address: 5159 Middleton Crescent, Apt 5 <1> Last reward: 0.00".to_string(),
                ),
                interactive_elements: vec![BridgeInteractiveElement {
                    selector: Some("#pagination > li:nth-of-type(4) > a".to_string()),
                    text: ">".to_string(),
                    visible: true,
                    disabled: false,
                    ..BridgeInteractiveElement::default()
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse phone-book action");
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("selector"))
                .and_then(Value::as_str),
            Some("#pagination > li:nth-of-type(4) > a")
        );
    }

    #[test]
    fn scroll_text_agent_uses_jump_key_for_top_navigation() {
        let runtime = test_runtime(RecipeId::ScrollText2, 1.0);
        let bridge_state = BridgeState {
            utterance: "Scroll the textarea to the top of the text hit submit.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("text-area".to_string()),
                scroll_targets: vec![BridgeScrollTarget {
                    tag: "textarea".to_string(),
                    id: Some("text-area".to_string()),
                    selector: Some("#text-area".to_string()),
                    center_x: Some(80),
                    center_y: Some(110),
                    scroll_top: 120.0,
                    scroll_height: 510.0,
                    client_height: 104.0,
                    value: Some(String::new()),
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse scroll action");
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__key")
        );
        let expected_key = if cfg!(target_os = "macos") {
            "ArrowUp"
        } else {
            "Home"
        };
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("key"))
                .and_then(Value::as_str),
            Some(expected_key)
        );
        let expected_modifier = super::primary_browser_modifier();
        let modifiers = parsed
            .get("arguments")
            .and_then(|args| args.get("modifiers"))
            .and_then(Value::as_array)
            .expect("jump key modifiers");
        assert_eq!(modifiers.len(), 1);
        assert_eq!(modifiers[0].as_str(), Some(expected_modifier));
    }

    #[test]
    fn scroll_text_agent_falls_back_to_page_up_after_jump_key() {
        let runtime = test_runtime(RecipeId::ScrollText2, 1.0);
        runtime.note_scroll_action("jump_key");
        let bridge_state = BridgeState {
            utterance: "Scroll the textarea to the top of the text hit submit.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                focused_id: Some("text-area".to_string()),
                scroll_targets: vec![BridgeScrollTarget {
                    tag: "textarea".to_string(),
                    id: Some("text-area".to_string()),
                    selector: Some("#text-area".to_string()),
                    center_x: Some(80),
                    center_y: Some(110),
                    scroll_top: 120.0,
                    scroll_height: 510.0,
                    client_height: 104.0,
                    value: Some(String::new()),
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse scroll fallback action");
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__key")
        );
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("key"))
                .and_then(Value::as_str),
            Some("PageUp")
        );
    }

    #[test]
    fn autocomplete_recovery_respects_forbidden_click_tools() {
        let runtime = test_runtime(RecipeId::UseAutocomplete, 1.0);
        let bridge_state = BridgeState {
            utterance: "Enter the country beginning with \"uni\" and press submit.".to_string(),
            info: BridgeInfo {
                task_ready: Some(true),
                interactive_elements: vec![BridgeInteractiveElement {
                    selector: Some("#tags".to_string()),
                    id: Some("tags".to_string()),
                    value: Some(String::new()),
                    visible: true,
                    disabled: false,
                    ..BridgeInteractiveElement::default()
                }],
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.recovery_action(
            &bridge_state,
            "You are an ontology incident resolver.\n2. Forbidden tools: browser__click\n- Visited remedy fingerprints: none\n",
        );
        let parsed: Value = serde_json::from_slice(&action).expect("parse recovery action");
        assert_ne!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__click")
        );
    }

    #[test]
    fn agent_startup_issues_navigation_before_waiting_on_bridge_readiness() {
        let runtime = MiniwobAgentRuntime {
            case: ComputerUseCase {
                id: "miniwob_catalog_highlight_text".to_string(),
                env_id: "highlight-text".to_string(),
                seed: 7,
                task_set: TaskSet::Catalog,
                max_steps: 10,
                timeout_seconds: 20,
                allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelectionClipboard,
                expected_reward_floor: 1.0,
                expected_pass: true,
                local_judge: LocalJudge::MiniwobReward,
                recipe: RecipeId::HighlightText,
            },
            client: BridgeClient {
                http: Client::new(),
                base_url: "http://127.0.0.1:1".to_string(),
            },
            session_id: "test-session".to_string(),
            url: "file:///tmp/miniwob/highlight-text.1.html".to_string(),
            startup_navigation_issued: Mutex::new(false),
            pending_followup: Mutex::new(None),
            optimistic_checked_labels: Mutex::new(BTreeSet::new()),
            last_scroll_action: Mutex::new(None),
            last_copy_paste_action: Mutex::new(None),
            last_hover_shape_phase: Mutex::new(None),
        };
        let bridge_state = BridgeState {
            utterance: String::new(),
            info: BridgeInfo {
                page_url: Some(runtime.url.clone()),
                task_ready: Some(false),
                ..BridgeInfo::default()
            },
            ..BridgeState::default()
        };

        let action = runtime.next_action(&bridge_state);
        let parsed: Value = serde_json::from_slice(&action).expect("parse tool action");

        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("browser__navigate")
        );
        assert_eq!(
            parsed
                .get("arguments")
                .and_then(|args| args.get("url"))
                .and_then(Value::as_str),
            Some(runtime.url.as_str())
        );
        assert!(runtime.startup_navigation_issued());
    }

    #[test]
    fn queued_agent_macro_steps_are_reconstructed_into_tool_steps() {
        let bridge_state = BridgeState::default();
        let kernel_events = vec![
            KernelEvent::AgentStep(StepTrace {
                session_id: [0u8; 32],
                step_index: 5,
                visual_hash: [0u8; 32],
                full_prompt: "[Macro Step] Executing queued action".to_string(),
                raw_output: r##"{"pointer":{"action":"hover","hovered":true,"target":{"selector":"#highlight","target_kind":"selector"},"x":12.0,"y":18.0}}"##.to_string(),
                success: true,
                error: None,
                cost_incurred: 0,
                fitness_score: None,
                skill_hash: None,
                timestamp: 1,
            }),
            KernelEvent::RoutingReceipt(RoutingReceiptEvent {
                session_id: [0u8; 32],
                step_index: 5,
                intent_hash: "intent-hover".to_string(),
                policy_decision: "allowed".to_string(),
                tool_name: "browser__hover".to_string(),
                tool_version: "0.1.0".to_string(),
                pre_state: RoutingStateSummary {
                    agent_status: "Running".to_string(),
                    tier: "ToolFirst".to_string(),
                    step_index: 5,
                    consecutive_failures: 0,
                    target_hint: None,
                },
                action_json: r##"{"name":"browser__hover","arguments":{"selector":"#highlight"}}"##
                    .to_string(),
                post_state: RoutingPostStateSummary {
                    agent_status: "Running".to_string(),
                    tier: "ToolFirst".to_string(),
                    step_index: 6,
                    consecutive_failures: 0,
                    success: true,
                    verification_checks: Vec::new(),
                },
                artifacts: Vec::new(),
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
                policy_binding_hash: "binding-hover".to_string(),
                policy_binding_sig: None,
                policy_binding_signer: None,
            }),
            KernelEvent::AgentStep(StepTrace {
                session_id: [0u8; 32],
                step_index: 7,
                visual_hash: [0u8; 32],
                full_prompt: "[Macro Step] Executing queued action".to_string(),
                raw_output: r#"{"wait":{"condition":"fixed_ms","elapsed_ms":1300,"met":true}}"#
                    .to_string(),
                success: true,
                error: None,
                cost_incurred: 0,
                fitness_score: None,
                skill_hash: None,
                timestamp: 2,
            }),
            KernelEvent::RoutingReceipt(RoutingReceiptEvent {
                session_id: [0u8; 32],
                step_index: 7,
                intent_hash: "intent-wait".to_string(),
                policy_decision: "allowed".to_string(),
                tool_name: "browser__wait".to_string(),
                tool_version: "0.1.0".to_string(),
                pre_state: RoutingStateSummary {
                    agent_status: "Running".to_string(),
                    tier: "ToolFirst".to_string(),
                    step_index: 7,
                    consecutive_failures: 0,
                    target_hint: None,
                },
                action_json: r#"{"name":"browser__wait","arguments":{"ms":1300}}"#.to_string(),
                post_state: RoutingPostStateSummary {
                    agent_status: "Running".to_string(),
                    tier: "ToolFirst".to_string(),
                    step_index: 8,
                    consecutive_failures: 0,
                    success: true,
                    verification_checks: Vec::new(),
                },
                artifacts: Vec::new(),
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
                policy_binding_hash: "binding-wait".to_string(),
                policy_binding_sig: None,
                policy_binding_signer: None,
            }),
            KernelEvent::AgentActionResult {
                session_id: [0u8; 32],
                step_index: 8,
                tool_name: "system::max_steps_reached".to_string(),
                output: "Max steps reached. Task completed.".to_string(),
                error_class: None,
                agent_status: "Completed".to_string(),
            },
        ];

        let observations = super::collect_agent_kernel_observations(&kernel_events, &bridge_state);

        assert_eq!(observations.tool_steps.len(), 3);
        assert_eq!(observations.tool_steps[0].tool_name, "browser__hover");
        assert_eq!(
            observations.tool_steps[0]
                .arguments
                .get("selector")
                .and_then(Value::as_str),
            Some("#highlight")
        );
        assert_eq!(observations.tool_steps[0].success, true);
        assert_eq!(
            observations.tool_steps[0].history_entry.as_deref(),
            Some(
                r##"{"pointer":{"action":"hover","hovered":true,"target":{"selector":"#highlight","target_kind":"selector"},"x":12.0,"y":18.0}}"##
            )
        );

        assert_eq!(observations.tool_steps[1].tool_name, "browser__wait");
        assert_eq!(
            observations.tool_steps[1]
                .arguments
                .get("ms")
                .and_then(Value::as_u64),
            Some(1300)
        );
        assert_eq!(
            observations.tool_steps[1].history_entry.as_deref(),
            Some(r#"{"wait":{"condition":"fixed_ms","elapsed_ms":1300,"met":true}}"#)
        );

        assert_eq!(
            observations.executed_tools,
            vec![
                "browser__hover".to_string(),
                "browser__wait".to_string(),
                "system::max_steps_reached".to_string()
            ]
        );
    }
}

fn parse_drag_source_name(query: &str) -> Option<String> {
    let query = query.trim();
    let remainder = query.strip_prefix("Drag ")?;
    for suffix in [
        " to the top.",
        " to the bottom.",
        " down by one position.",
        " up by one position.",
    ] {
        if let Some(source) = remainder.strip_suffix(suffix) {
            return Some(source.trim().to_string());
        }
    }

    let (source, position_clause) = remainder.split_once(" to the ")?;
    if position_clause.ends_with(" position.") {
        return Some(source.trim().to_string());
    }
    None
}

fn parse_drag_target_position(
    query: &str,
    source_index: usize,
    item_count: usize,
) -> Option<usize> {
    let query = query.trim();
    if query.ends_with(" to the top.") {
        return Some(1);
    }
    if query.ends_with(" to the bottom.") {
        return Some(item_count);
    }
    if query.ends_with(" down by one position.") {
        return Some((source_index + 1).min(item_count));
    }
    if query.ends_with(" up by one position.") {
        return source_index.checked_sub(1);
    }

    let (_, position_clause) = query.strip_prefix("Drag ")?.split_once(" to the ")?;
    let digits = position_clause
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    let position = digits.parse::<usize>().ok()?;
    (1..=item_count).contains(&position).then_some(position)
}

fn drag_drop_y(rects: &[GuiRect], source_index: usize, target_position: usize) -> Result<f64> {
    if rects.is_empty() {
        return Err(anyhow!("drag-items requires at least one list item"));
    }
    if !(1..=rects.len()).contains(&source_index) {
        return Err(anyhow!(
            "drag-items source index {} is out of range",
            source_index
        ));
    }
    if !(1..=rects.len()).contains(&target_position) {
        return Err(anyhow!(
            "drag-items target position {} is out of range",
            target_position
        ));
    }

    if target_position == source_index {
        let rect = rects[source_index - 1];
        return Ok(rect.center().y);
    }

    if target_position < source_index {
        if target_position == 1 {
            let first = rects[0];
            return Ok((first.y - (first.height * 0.35)).max(4.0));
        }
        let follower = rects[target_position - 1];
        return Ok(follower.y + (follower.height * 0.25));
    }

    if target_position == rects.len() {
        let last = rects[rects.len() - 1];
        return Ok(last.y + last.height + (last.height * 0.35));
    }

    let follower = rects[target_position];
    Ok(follower.y + (follower.height * 0.25))
}

async fn drag_sortable_item(
    harness: &mut DirectHarness,
    source_name: &str,
    target_position: usize,
) -> Result<()> {
    let current_order = harness.selector_texts("#sortable li").await?;
    if current_order.is_empty() {
        return Err(anyhow!("drag-items list order is empty"));
    }

    let source_index = current_order
        .iter()
        .position(|item| normalize_label(item) == normalize_label(source_name))
        .map(|index| index + 1)
        .ok_or_else(|| anyhow!("drag-items source '{}' not found", source_name))?;
    if source_index == target_position {
        return Ok(());
    }

    let mut rects = Vec::with_capacity(current_order.len());
    for index in 1..=current_order.len() {
        let selector = format!("#sortable li:nth-of-type({})", index);
        rects.push(
            harness
                .browser
                .get_selector_rect_window_logical(&selector)
                .await
                .map_err(|err| anyhow!("drag-items rect '{}': {}", selector, err))?,
        );
    }

    let source_rect = rects[source_index - 1];
    let drag_x = source_rect.x + (source_rect.width * 0.35);
    let start_y = source_rect.center().y;
    let drop_y = drag_drop_y(&rects, source_index, target_position)?;
    let direction_bias = if target_position < source_index {
        -18.0
    } else {
        18.0
    };

    harness
        .hover_selector(&format!("#sortable li:nth-of-type({})", source_index))
        .await?;
    harness.move_mouse(drag_x, start_y).await?;
    harness.mouse_down("left").await?;
    harness.wait_ms(40).await?;
    harness.move_mouse(drag_x, start_y + direction_bias).await?;
    harness.wait_ms(40).await?;
    for fraction in [0.25_f64, 0.5_f64, 0.75_f64, 1.0_f64] {
        let next_y = start_y + ((drop_y - start_y) * fraction);
        harness.move_mouse(drag_x, next_y).await?;
        harness.wait_ms(40).await?;
    }
    harness.wait_ms(80).await?;
    harness.mouse_up("left").await?;
    Ok(())
}

async fn run_oracle_recipe(harness: &mut DirectHarness, case: &ComputerUseCase) -> Result<()> {
    let query = harness
        .bridge_state
        .info
        .query_text
        .clone()
        .unwrap_or_else(|| harness.bridge_state.utterance.clone());

    match case.recipe {
        RecipeId::ClickButton | RecipeId::ClickLink => {
            let label = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("oracle query missing quoted label"))?;
            harness.oracle_click_text(&label).await?;
        }
        RecipeId::EnterText => {
            let text = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("oracle enter-text query missing text"))?;
            harness.oracle_type_text("#tt", &text).await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::FocusText => {
            harness.oracle_focus_selector("#tt").await?;
        }
        RecipeId::ChooseList => {
            let label = parse_submit_target(&query)
                .ok_or_else(|| anyhow!("oracle choose-list query missing target"))?;
            harness.oracle_select_label("#options", &label).await?;
            harness.oracle_click_selector("button").await?;
        }
        RecipeId::ClickTab => {
            if let Some(target) = quoted_values(&query).into_iter().next() {
                if let Some(selector) =
                    wait_for_bridge_label_selector(harness, &target, 4, 80).await?
                {
                    harness.oracle_click_selector(&selector).await?;
                } else {
                    let state = harness.refresh_bridge_state().await?;
                    if let Some(tab_selector) =
                        bridge_hidden_tab_selector_for_label(&state.info.interactive_elements, &target)
                    {
                        harness.oracle_click_selector(&tab_selector).await?;
                        let selector = wait_for_bridge_label_selector(harness, &target, 4, 80)
                            .await?
                            .ok_or_else(|| {
                                anyhow!(
                                    "oracle click-tab target '{}' not visible after tab switch",
                                    target
                                )
                            })?;
                        harness.oracle_click_selector(&selector).await?;
                    } else {
                        return Err(anyhow!(
                            "oracle click-tab target '{}' not found in visible or hidden tabs",
                            target
                        ));
                    }
                }
            } else {
                let number = parse_tab_number(&query).ok_or_else(|| anyhow!("oracle click-tab"))?;
                harness
                    .oracle_click_selector(&format!("a[href='#tabs-{}']", number))
                    .await?;
            }
        }
        RecipeId::UseAutocomplete => {
            let target =
                infer_autocomplete_target(&query).ok_or_else(|| anyhow!("oracle autocomplete"))?;
            harness.oracle_type_text("#tags", &target).await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::ScrollText2 => {
            let go_bottom = query.to_ascii_lowercase().contains("bottom");
            let state = harness.refresh_bridge_state().await?;
            let selector = scroll_target_selector(&state.info.scroll_targets, "text-area")
                .unwrap_or_else(|| "#text-area".to_string());
            harness
                .oracle_scroll_target(&selector, if go_bottom { "bottom" } else { "top" })
                .await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::ClickOption => {
            let label =
                parse_submit_target(&query).ok_or_else(|| anyhow!("oracle click-option"))?;
            harness.oracle_click_text(&label).await?;
            harness.oracle_click_selector("button").await?;
        }
        RecipeId::ClickCheckboxes | RecipeId::ClickCheckboxesTransfer => {
            for target in parse_checkbox_targets(&query) {
                harness.oracle_click_text(&target).await?;
            }
            harness.oracle_click_selector("button").await?;
        }
        RecipeId::EnterPassword => {
            let password = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("oracle enter-password"))?;
            harness.oracle_type_text("#password", &password).await?;
            harness.oracle_type_text("#verify", &password).await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::LoginUser => {
            let quoted = quoted_values(&query);
            let username = quoted
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("oracle login-user"))?;
            let password = quoted
                .get(1)
                .cloned()
                .ok_or_else(|| anyhow!("oracle login-user"))?;
            harness.oracle_type_text("#username", &username).await?;
            harness.oracle_type_text("#password", &password).await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::FocusText2 => {
            let index = parse_focus_index(&query).ok_or_else(|| anyhow!("oracle focus-text-2"))?;
            harness
                .oracle_focus_selector(&format!("#tt{}", index))
                .await?;
        }
        RecipeId::EnterText2 => {
            let raw_text = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("oracle enter-text-2"))?;
            let text = parse_uppercase_transform(&query, &raw_text);
            harness.oracle_type_text("#tt", &text).await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::ClickButtonSequence => {
            harness.oracle_click_selector("#subbtn").await?;
            harness.oracle_click_selector("#subbtn2").await?;
        }
        RecipeId::ClickCollapsible => {
            harness.oracle_click_selector("#area h3").await?;
            harness.oracle_click_selector("#subbtn").await?;
        }
        RecipeId::ClickCollapsible2 => {
            let target = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("oracle click-collapsible-2"))?;
            for index in 1..=3 {
                let state = harness.refresh_bridge_state().await?;
                if bridge_selector_for_label(&state.info.interactive_elements, &target).is_some() {
                    break;
                }
                harness
                    .oracle_click_selector(&format!("#area h3:nth-of-type({})", index))
                    .await?;
            }
            harness.oracle_click_text(&target).await?;
        }
        RecipeId::SearchEngine => {
            let quoted = quoted_values(&query);
            let search_term = quoted
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("oracle search"))?;
            let position =
                parse_search_result_position(&query).ok_or_else(|| anyhow!("oracle search"))?;
            let page = ((position - 1) / 3) + 1;
            let local_index = ((position - 1) % 3) + 1;
            harness
                .oracle_type_text("#search-text", &search_term)
                .await?;
            harness.oracle_click_selector("#search").await?;
            if page > 1 {
                harness.oracle_click_text(&page.to_string()).await?;
            }
            let state = harness.refresh_bridge_state().await?;
            let result_selector =
                search_result_selector(&state.info.interactive_elements, local_index as usize)
                    .ok_or_else(|| anyhow!("oracle search result {}", local_index))?;
            harness.oracle_click_selector(&result_selector).await?;
        }
        RecipeId::FormSequence => {
            run_form_sequence_sequence(harness, &query).await?;
        }
        RecipeId::FormSequence2 => {
            run_form_sequence_2_sequence(harness, &query).await?;
        }
        RecipeId::FormSequence3 => {
            run_form_sequence_3_sequence(harness, &query).await?;
        }
        RecipeId::LoginUserPopup => {
            run_login_user_popup_sequence(harness, &query).await?;
        }
        RecipeId::TextEditor => {
            run_text_editor_sequence(harness, &query).await?;
        }
        RecipeId::SimpleArithmetic => {
            run_simple_arithmetic_sequence(harness).await?;
        }
        RecipeId::SimpleAlgebra => {
            run_simple_algebra_sequence(harness).await?;
        }
        RecipeId::OddOrEven => {
            run_odd_or_even_sequence(harness).await?;
        }
        RecipeId::GuessNumber => {
            run_guess_number_sequence(harness).await?;
        }
        RecipeId::FindGreatest => {
            run_find_greatest_sequence(harness).await?;
        }
        RecipeId::FindWord => {
            run_find_word_sequence(harness, &query).await?;
        }
        RecipeId::ReadTable => {
            run_read_table_sequence(harness, &query).await?;
        }
        RecipeId::ReadTable2 => {
            run_read_table_2_sequence(harness).await?;
        }
        RecipeId::PhoneBook => {
            run_phone_book_sequence(harness, &query).await?;
        }
        RecipeId::SocialMedia => {
            run_social_media_sequence(harness, &query).await?;
        }
        RecipeId::SocialMediaAll => {
            run_social_media_multi_sequence(harness, &query, None).await?;
        }
        RecipeId::SocialMediaSome => {
            let amount = parse_social_media_amount(&query)
                .ok_or_else(|| anyhow!("social-media-some amount"))?;
            run_social_media_multi_sequence(harness, &query, Some(amount)).await?;
        }
        RecipeId::StockMarket => {
            run_stock_market_sequence(harness, &query).await?;
        }
        RecipeId::EmailInbox => {
            run_email_inbox_sequence(harness, &query).await?;
        }
        RecipeId::VisualAddition => {
            run_visual_addition_sequence(harness).await?;
        }
        RecipeId::IdentifyShape => {
            run_identify_shape_sequence(harness).await?;
        }
        RecipeId::CountShape => {
            run_count_shape_sequence(harness, &query).await?;
        }
        RecipeId::CountSides => {
            run_count_sides_sequence(harness).await?;
        }
        RecipeId::FindMidpoint => {
            run_find_midpoint_sequence(harness).await?;
        }
        RecipeId::HoverShape => {
            run_hover_shape_sequence(harness).await?;
        }
        RecipeId::DragItems => {
            let source_name =
                parse_drag_source_name(&query).ok_or_else(|| anyhow!("oracle drag-items"))?;
            let current_order = harness.selector_texts("#sortable li").await?;
            let source_index = current_order
                .iter()
                .position(|item| normalize_label(item) == normalize_label(&source_name))
                .map(|index| index + 1)
                .ok_or_else(|| anyhow!("oracle drag-items source '{}' not found", source_name))?;
            let target_position =
                parse_drag_target_position(&query, source_index, current_order.len())
                    .ok_or_else(|| anyhow!("oracle drag-items target"))?;
            drag_sortable_item(harness, &source_name, target_position).await?;
        }
        RecipeId::HighlightText => {
            run_highlight_text_sequence(harness, &query).await?;
        }
        RecipeId::CopyPaste => {
            run_copy_paste_sequence(harness, &query).await?;
        }
        RecipeId::SurveyOnly => {
            capture_catalog_diagnostics(harness).await;
            return Err(anyhow!(
                "ERROR_CLASS=CatalogSurvey no curated oracle recipe is available for '{}'",
                case.env_id
            ));
        }
    }
    Ok(())
}

async fn run_runtime_recipe(harness: &mut DirectHarness, case: &ComputerUseCase) -> Result<()> {
    let query = harness
        .bridge_state
        .info
        .query_text
        .clone()
        .unwrap_or_else(|| harness.bridge_state.utterance.clone());

    match case.recipe {
        RecipeId::ClickButton | RecipeId::ClickLink => {
            let target = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime query missing quoted target"))?;
            harness.click_bridge_label(&target).await?;
        }
        RecipeId::EnterText => {
            let text = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime enter-text query missing text"))?;
            harness.type_text("#tt", &text).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::FocusText => {
            harness.click_selector("#tt").await?;
        }
        RecipeId::ChooseList => {
            let label =
                parse_submit_target(&query).ok_or_else(|| anyhow!("runtime choose-list"))?;
            harness.select_dropdown_label("#options", &label).await?;
            harness.click_selector("button").await?;
        }
        RecipeId::ClickTab => {
            if let Some(target) = quoted_values(&query).into_iter().next() {
                if let Some(selector) =
                    wait_for_bridge_label_selector(harness, &target, 4, 80).await?
                {
                    harness.click_selector(&selector).await?;
                } else {
                    let state = harness.refresh_bridge_state().await?;
                    if let Some(tab_selector) =
                        bridge_hidden_tab_selector_for_label(&state.info.interactive_elements, &target)
                    {
                        harness.click_selector(&tab_selector).await?;
                        harness.wait_ms(120).await?;
                        let selector = wait_for_bridge_label_selector(harness, &target, 4, 80)
                            .await?
                            .ok_or_else(|| {
                                anyhow!(
                                    "runtime click-tab target '{}' not visible after tab switch",
                                    target
                                )
                            })?;
                        harness.click_selector(&selector).await?;
                    } else {
                        return Err(anyhow!(
                            "runtime click-tab target '{}' not found in visible or hidden tabs",
                            target
                        ));
                    }
                }
            } else {
                let number =
                    parse_tab_number(&query).ok_or_else(|| anyhow!("runtime click-tab"))?;
                harness
                    .click_selector(&format!("a[href='#tabs-{}']", number))
                    .await?;
            }
        }
        RecipeId::UseAutocomplete => {
            let target = infer_autocomplete_target(&query)
                .ok_or_else(|| anyhow!("runtime autocomplete target not found"))?;
            harness.type_text("#tags", &target).await?;
            harness.wait_ms(350).await?;
            harness.press_key("Escape").await?;
            harness.wait_ms(120).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::ScrollText2 => {
            let go_bottom = query.to_ascii_lowercase().contains("bottom");
            scroll_textarea_with_browser_tools(harness, go_bottom).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::ClickOption => {
            let label =
                parse_submit_target(&query).ok_or_else(|| anyhow!("runtime click-option"))?;
            harness.click_bridge_label(&label).await?;
            harness.click_selector("button").await?;
        }
        RecipeId::ClickCheckboxes | RecipeId::ClickCheckboxesTransfer => {
            for label in parse_checkbox_targets(&query) {
                harness.click_bridge_label(&label).await?;
            }
            harness.click_selector("button").await?;
        }
        RecipeId::EnterPassword => {
            let password = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime enter-password"))?;
            harness.type_text("#password", &password).await?;
            harness.type_text("#verify", &password).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::LoginUser => {
            let quoted = quoted_values(&query);
            let username = quoted
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("runtime login-user"))?;
            let password = quoted
                .get(1)
                .cloned()
                .ok_or_else(|| anyhow!("runtime login-user"))?;
            harness.type_text("#username", &username).await?;
            harness.type_text("#password", &password).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::FocusText2 => {
            let index = parse_focus_index(&query).ok_or_else(|| anyhow!("runtime focus-text-2"))?;
            harness.click_selector(&format!("#tt{}", index)).await?;
        }
        RecipeId::EnterText2 => {
            let raw_text = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime enter-text-2"))?;
            let text = parse_uppercase_transform(&query, &raw_text);
            harness.type_text("#tt", &text).await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::ClickButtonSequence => {
            harness.click_selector("#subbtn").await?;
            harness.click_selector("#subbtn2").await?;
        }
        RecipeId::ClickCollapsible => {
            harness.click_selector("#area h3").await?;
            harness.click_selector("#subbtn").await?;
        }
        RecipeId::ClickCollapsible2 => {
            let target = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime click-collapsible-2"))?;
            let mut target_selector =
                wait_for_bridge_label_selector(harness, &target, 0, 0).await?;
            for index in 1..=3 {
                if target_selector.is_some() {
                    break;
                }
                harness
                    .click_selector(&format!("#area h3:nth-of-type({})", index))
                    .await?;
                harness.wait_ms(120).await?;
                target_selector = wait_for_bridge_label_selector(harness, &target, 3, 80).await?;
            }
            let selector = target_selector.ok_or_else(|| {
                anyhow!("runtime click-collapsible-2 target '{}' not found", target)
            })?;
            harness.wait_ms(80).await?;
            harness.click_selector(&selector).await?;
        }
        RecipeId::SearchEngine => {
            let search_term = quoted_values(&query)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime search-engine"))?;
            let position =
                parse_search_result_position(&query).ok_or_else(|| anyhow!("runtime search"))?;
            let page = ((position - 1) / 3) + 1;
            let local_index = ((position - 1) % 3) + 1;
            harness.type_text("#search-text", &search_term).await?;
            harness.click_selector("#search").await?;
            harness.wait_ms(150).await?;
            if page > 1 {
                harness.click_bridge_label(&page.to_string()).await?;
                harness.wait_ms(100).await?;
            }
            let state = harness.refresh_bridge_state().await?;
            let result_selector =
                search_result_selector(&state.info.interactive_elements, local_index as usize)
                    .ok_or_else(|| anyhow!("runtime search result {}", local_index))?;
            harness.click_selector(&result_selector).await?;
        }
        RecipeId::FormSequence => {
            run_form_sequence_sequence(harness, &query).await?;
        }
        RecipeId::FormSequence2 => {
            run_form_sequence_2_sequence(harness, &query).await?;
        }
        RecipeId::FormSequence3 => {
            run_form_sequence_3_sequence(harness, &query).await?;
        }
        RecipeId::LoginUserPopup => {
            run_login_user_popup_sequence(harness, &query).await?;
        }
        RecipeId::TextEditor => {
            run_text_editor_sequence(harness, &query).await?;
        }
        RecipeId::SimpleArithmetic => {
            run_simple_arithmetic_sequence(harness).await?;
        }
        RecipeId::SimpleAlgebra => {
            run_simple_algebra_sequence(harness).await?;
        }
        RecipeId::OddOrEven => {
            run_odd_or_even_sequence(harness).await?;
        }
        RecipeId::GuessNumber => {
            run_guess_number_sequence(harness).await?;
        }
        RecipeId::FindGreatest => {
            run_find_greatest_sequence(harness).await?;
        }
        RecipeId::FindWord => {
            run_find_word_sequence(harness, &query).await?;
        }
        RecipeId::ReadTable => {
            run_read_table_sequence(harness, &query).await?;
        }
        RecipeId::ReadTable2 => {
            run_read_table_2_sequence(harness).await?;
        }
        RecipeId::PhoneBook => {
            run_phone_book_sequence(harness, &query).await?;
        }
        RecipeId::SocialMedia => {
            run_social_media_sequence(harness, &query).await?;
        }
        RecipeId::SocialMediaAll => {
            run_social_media_multi_sequence(harness, &query, None).await?;
        }
        RecipeId::SocialMediaSome => {
            let amount = parse_social_media_amount(&query)
                .ok_or_else(|| anyhow!("social-media-some amount"))?;
            run_social_media_multi_sequence(harness, &query, Some(amount)).await?;
        }
        RecipeId::StockMarket => {
            run_stock_market_sequence(harness, &query).await?;
        }
        RecipeId::EmailInbox => {
            run_email_inbox_sequence(harness, &query).await?;
        }
        RecipeId::VisualAddition => {
            run_visual_addition_sequence(harness).await?;
        }
        RecipeId::IdentifyShape => {
            run_identify_shape_sequence(harness).await?;
        }
        RecipeId::CountShape => {
            run_count_shape_sequence(harness, &query).await?;
        }
        RecipeId::CountSides => {
            run_count_sides_sequence(harness).await?;
        }
        RecipeId::FindMidpoint => {
            run_find_midpoint_sequence(harness).await?;
        }
        RecipeId::HoverShape => {
            run_hover_shape_sequence(harness).await?;
        }
        RecipeId::DragItems => {
            let source_name =
                parse_drag_source_name(&query).ok_or_else(|| anyhow!("runtime drag-items"))?;
            let current_order = harness.selector_texts("#sortable li").await?;
            let source_index = current_order
                .iter()
                .position(|item| normalize_label(item) == normalize_label(&source_name))
                .map(|index| index + 1)
                .ok_or_else(|| anyhow!("runtime drag-items source '{}' not found", source_name))?;
            let target_position =
                parse_drag_target_position(&query, source_index, current_order.len())
                    .ok_or_else(|| anyhow!("runtime drag-items target"))?;
            drag_sortable_item(harness, &source_name, target_position).await?;
        }
        RecipeId::HighlightText => {
            run_highlight_text_sequence(harness, &query).await?;
        }
        RecipeId::CopyPaste => {
            run_copy_paste_sequence(harness, &query).await?;
        }
        RecipeId::SurveyOnly => {
            capture_catalog_diagnostics(harness).await;
            return Err(anyhow!(
                "ERROR_CLASS=CatalogSurvey no curated runtime recipe is available for '{}'",
                case.env_id
            ));
        }
    }

    Ok(())
}

fn extract_system_prompt(input_context: &[u8]) -> String {
    let raw = String::from_utf8_lossy(input_context).to_string();
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return raw;
    };
    let Some(messages) = value.as_array() else {
        return raw;
    };
    messages
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("system"))
        .filter_map(|message| message.get("content"))
        .map(extract_content_text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_incident_recovery_prompt(system_prompt: &str) -> bool {
    system_prompt
        .to_ascii_lowercase()
        .contains("ontology incident resolver")
}

fn incident_root_tool(system_prompt: &str) -> Option<&str> {
    system_prompt
        .lines()
        .find_map(|line| line.trim().strip_prefix("- Root tool: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn incident_forbidden_tools(system_prompt: &str) -> BTreeSet<String> {
    system_prompt
        .lines()
        .find_map(|line| line.trim().strip_prefix("2. Forbidden tools: "))
        .map(|line| {
            line.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn incident_visited_fingerprints(system_prompt: &str) -> BTreeSet<String> {
    system_prompt
        .lines()
        .find_map(|line| line.trim().strip_prefix("- Visited remedy fingerprints: "))
        .map(|line| {
            if line.eq_ignore_ascii_case("none") {
                return BTreeSet::new();
            }
            line.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn incident_tool_fingerprint(name: &str, arguments: &Value) -> Option<String> {
    let payload = json!({
        "name": name,
        "arguments": arguments,
    });
    let canonical = serde_jcs::to_vec(&payload).ok()?;
    let digest = sha256(&canonical).ok()?;
    Some(hex::encode(digest))
}

fn pick_incident_recovery_candidate(
    system_prompt: &str,
    candidates: &[(&str, Value)],
) -> Option<(String, Value)> {
    let forbidden = incident_forbidden_tools(system_prompt);
    let visited = incident_visited_fingerprints(system_prompt);
    candidates.iter().find_map(|(name, arguments)| {
        if forbidden.contains(*name) {
            return None;
        }
        if incident_tool_fingerprint(name, arguments)
            .as_ref()
            .is_some_and(|fingerprint| visited.contains(fingerprint))
        {
            return None;
        }
        Some(((*name).to_string(), arguments.clone()))
    })
}

fn pick_incident_recovery_tool(
    system_prompt: &str,
    candidates: &[(&str, Value)],
) -> Option<Vec<u8>> {
    pick_incident_recovery_candidate(system_prompt, candidates)
        .map(|(name, arguments)| inference_tool_call(&name, arguments))
}

fn extract_content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn inference_tool_call(name: &str, arguments: Value) -> Vec<u8> {
    json!({
        "name": name,
        "arguments": arguments,
    })
    .to_string()
    .into_bytes()
}

fn inference_wait(ms: u64) -> Vec<u8> {
    inference_tool_call("browser__wait", json!({ "ms": ms }))
}

fn inference_fail(reason: &str) -> Vec<u8> {
    inference_tool_call("system__fail", json!({ "reason": reason }))
}

fn should_break_agent_loop_for_reward(
    bridge_state: &BridgeState,
    expected_reward_floor: f32,
) -> bool {
    expected_reward_floor > 0.0
        && bridge_state.info.raw_reward.unwrap_or(bridge_state.reward) >= expected_reward_floor
}

#[derive(Default)]
struct AgentKernelObservations {
    tool_steps: Vec<ToolStepRecord>,
    executed_tools: Vec<String>,
    routing_receipt_count: usize,
    intent_receipt_count: usize,
    execution_contract_receipt_count: usize,
    workload_receipt_count: usize,
    workload_activity_count: usize,
    failure_class: Option<String>,
}

fn parse_action_json_parts(action_json: &str) -> Option<(String, Value)> {
    let parsed = serde_json::from_str::<Value>(action_json).ok()?;
    let name = parsed.get("name").and_then(Value::as_str)?.to_string();
    let arguments = parsed
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some((name, arguments))
}

fn raw_output_is_action_echo(raw_output: &str, action_json: &str) -> bool {
    let trimmed = raw_output.trim();
    if trimmed.is_empty() || trimmed == action_json.trim() {
        return true;
    }

    serde_json::from_str::<Value>(trimmed)
        .ok()
        .and_then(|value| {
            Some(
                value.get("name").and_then(Value::as_str).is_some()
                    && value.get("arguments").is_some(),
            )
        })
        .unwrap_or(false)
}

fn collect_agent_kernel_observations(
    kernel_events: &[KernelEvent],
    bridge_state: &BridgeState,
) -> AgentKernelObservations {
    let mut observations = AgentKernelObservations::default();
    let mut step_traces = BTreeMap::<u32, String>::new();
    let mut action_results = BTreeMap::<(u32, String), (String, Option<String>)>::new();
    let mut matched_action_results = BTreeSet::<(u32, String)>::new();

    for event in kernel_events {
        match event {
            KernelEvent::AgentStep(trace) => {
                step_traces
                    .entry(trace.step_index)
                    .or_insert_with(|| trace.raw_output.clone());
            }
            KernelEvent::AgentActionResult {
                step_index,
                tool_name,
                output,
                error_class,
                ..
            } => {
                action_results.insert(
                    (*step_index, tool_name.clone()),
                    (output.clone(), error_class.clone()),
                );
                if observations.failure_class.is_none()
                    && !tool_name.starts_with("system::")
                    && error_class.is_some()
                {
                    observations.failure_class = error_class.clone();
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                observations.routing_receipt_count =
                    observations.routing_receipt_count.saturating_add(1);
                if observations.failure_class.is_none()
                    && !receipt.tool_name.starts_with("system::")
                    && !receipt.post_state.success
                    && !receipt.failure_class_name.is_empty()
                {
                    observations.failure_class = Some(receipt.failure_class_name.clone());
                }
            }
            KernelEvent::IntentResolutionReceipt(_) => {
                observations.intent_receipt_count =
                    observations.intent_receipt_count.saturating_add(1);
            }
            KernelEvent::ExecutionContractReceipt(_) => {
                observations.execution_contract_receipt_count = observations
                    .execution_contract_receipt_count
                    .saturating_add(1);
            }
            KernelEvent::WorkloadReceipt(receipt) => {
                observations.workload_receipt_count =
                    observations.workload_receipt_count.saturating_add(1);
                if observations.failure_class.is_none() {
                    observations.failure_class = match &receipt.receipt {
                        WorkloadReceipt::Exec(item) => item.error_class.clone(),
                        WorkloadReceipt::FsWrite(item) => item.error_class.clone(),
                        WorkloadReceipt::NetFetch(item) => item.error_class.clone(),
                        WorkloadReceipt::WebRetrieve(item) => item.error_class.clone(),
                        WorkloadReceipt::ScsRetrieve(item) => item.error_class.clone(),
                        WorkloadReceipt::Adapter(item) => item.error_class.clone(),
                    };
                }
            }
            KernelEvent::WorkloadActivity(_) => {
                observations.workload_activity_count =
                    observations.workload_activity_count.saturating_add(1);
            }
            _ => {}
        }
    }

    for event in kernel_events {
        let KernelEvent::RoutingReceipt(receipt) = event else {
            continue;
        };

        let (tool_name, arguments) = parse_action_json_parts(&receipt.action_json)
            .unwrap_or_else(|| (receipt.tool_name.clone(), json!({})));
        let action_result_key = (receipt.step_index, receipt.tool_name.clone());
        let action_result = action_results.get(&action_result_key);
        if action_result.is_some() {
            matched_action_results.insert(action_result_key);
        }
        let history_entry = action_result.map(|(output, _)| output.clone()).or_else(|| {
            step_traces
                .get(&receipt.step_index)
                .filter(|raw_output| !raw_output_is_action_echo(raw_output, &receipt.action_json))
                .cloned()
        });
        let error = action_result
            .and_then(|(_, error_class)| error_class.clone())
            .or_else(|| {
                (!receipt.post_state.success && !receipt.failure_class_name.is_empty())
                    .then(|| receipt.failure_class_name.clone())
            });

        observations.executed_tools.push(tool_name.clone());
        observations.tool_steps.push(ToolStepRecord {
            step_index: receipt.step_index,
            tool_name,
            arguments,
            success: receipt.post_state.success,
            history_entry,
            error,
            bridge_reward: bridge_state.reward,
            bridge_terminated: bridge_state.terminated,
        });
    }

    for event in kernel_events {
        let KernelEvent::AgentActionResult {
            step_index,
            tool_name,
            output,
            error_class,
            ..
        } = event
        else {
            continue;
        };

        if matched_action_results.contains(&(*step_index, tool_name.clone())) {
            continue;
        }

        observations.executed_tools.push(tool_name.clone());
        observations.tool_steps.push(ToolStepRecord {
            step_index: *step_index,
            tool_name: tool_name.clone(),
            arguments: json!({}),
            success: error_class.is_none(),
            history_entry: Some(output.clone()),
            error: error_class.clone(),
            bridge_reward: bridge_state.reward,
            bridge_terminated: bridge_state.terminated,
        });
    }

    observations
}

struct MiniwobAgentRuntime {
    case: ComputerUseCase,
    client: BridgeClient,
    session_id: String,
    url: String,
    startup_navigation_issued: Mutex<bool>,
    pending_followup: Mutex<Option<String>>,
    optimistic_checked_labels: Mutex<BTreeSet<String>>,
    last_scroll_action: Mutex<Option<String>>,
    last_copy_paste_action: Mutex<Option<String>>,
    last_hover_shape_phase: Mutex<Option<String>>,
}

impl MiniwobAgentRuntime {
    fn startup_navigation_issued(&self) -> bool {
        self.startup_navigation_issued
            .lock()
            .map(|issued| *issued)
            .unwrap_or(false)
    }

    fn mark_startup_navigation_issued(&self) {
        if let Ok(mut issued) = self.startup_navigation_issued.lock() {
            *issued = true;
        }
    }

    fn note_pending_followup(&self, phase: &str) {
        if let Ok(mut pending) = self.pending_followup.lock() {
            *pending = Some(phase.to_string());
        }
    }

    fn take_pending_followup(&self) -> Option<String> {
        self.pending_followup
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    fn note_checkbox_click(&self, label: &str) {
        if let Ok(mut labels) = self.optimistic_checked_labels.lock() {
            labels.insert(normalize_label(label));
        }
    }

    fn checkbox_target_satisfied(
        &self,
        elements: &[BridgeInteractiveElement],
        label: &str,
    ) -> bool {
        if bridge_checkbox_checked_for_label(elements, label).unwrap_or(false) {
            return true;
        }
        self.optimistic_checked_labels
            .lock()
            .map(|labels| labels.contains(&normalize_label(label)))
            .unwrap_or(false)
    }

    fn note_scroll_action(&self, action: &str) {
        if let Ok(mut last) = self.last_scroll_action.lock() {
            *last = Some(action.to_string());
        }
    }

    fn last_scroll_action(&self) -> Option<String> {
        self.last_scroll_action
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn note_copy_paste_action(&self, action: &str) {
        if let Ok(mut last) = self.last_copy_paste_action.lock() {
            *last = Some(action.to_string());
        }
    }

    fn last_copy_paste_action(&self) -> Option<String> {
        self.last_copy_paste_action
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn note_hover_shape_phase(&self, phase: &str) {
        if let Ok(mut last) = self.last_hover_shape_phase.lock() {
            *last = Some(phase.to_string());
        }
    }

    fn hover_shape_phase(&self) -> Option<String> {
        self.last_hover_shape_phase
            .lock()
            .ok()
            .and_then(|last| last.clone())
    }

    fn fill_text_field_if_needed(
        &self,
        bridge_state: &BridgeState,
        elements: &[BridgeInteractiveElement],
        selector: &str,
        text: &str,
    ) -> Option<Vec<u8>> {
        if bridge_value_by_selector(elements, selector) == text {
            return None;
        }

        Some(if bridge_focus_matches(bridge_state, selector) {
            self.note_pending_followup("form_type");
            inference_tool_call(
                "browser__type",
                json!({ "selector": selector, "text": text }),
            )
        } else {
            inference_tool_call("browser__click", json!({ "selector": selector }))
        })
    }

    fn hover_shape_recovery_action(&self, system_prompt: &str) -> Vec<u8> {
        let phase = self.hover_shape_phase();
        let candidates = match phase.as_deref() {
            Some("await_post_wait_1") => vec![
                ("browser__hover", json!({ "selector": "#highlight" })),
                ("browser__wait", json!({ "ms": 1450 })),
            ],
            Some("await_post_wait_2") => vec![
                ("browser__hover", json!({ "selector": "#highlight" })),
                ("browser__wait", json!({ "ms": 1450 })),
            ],
            Some("await_post_hover_2") | Some("retry_hover_2_after_wait") => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
            Some("await_post_hover_3") | Some("retry_hover_3_after_wait") => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
            Some("complete") => return inference_tool_call("agent__complete", json!({})),
            _ => vec![
                ("browser__wait", json!({ "ms": 1300 })),
                ("browser__wait", json!({ "ms": 1450 })),
                ("browser__hover", json!({ "selector": "#highlight" })),
            ],
        };
        if let Some((name, arguments)) =
            pick_incident_recovery_candidate(system_prompt, &candidates)
        {
            match (phase.as_deref(), name.as_str()) {
                (Some("await_post_wait_1"), "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                }
                (Some("await_post_wait_2"), "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                }
                (
                    Some("await_post_hover_2") | Some("retry_hover_2_after_wait"),
                    "browser__wait",
                ) => {
                    self.note_hover_shape_phase("retry_hover_2_after_wait");
                }
                (
                    Some("await_post_hover_2") | Some("retry_hover_2_after_wait"),
                    "browser__hover",
                ) => {
                    self.note_hover_shape_phase("await_post_hover_2");
                }
                (
                    Some("await_post_hover_3") | Some("retry_hover_3_after_wait"),
                    "browser__wait",
                ) => {
                    self.note_hover_shape_phase("retry_hover_3_after_wait");
                }
                (
                    Some("await_post_hover_3") | Some("retry_hover_3_after_wait"),
                    "browser__hover",
                ) => {
                    self.note_hover_shape_phase("await_post_hover_3");
                }
                (_, "browser__wait") => {
                    self.note_hover_shape_phase("retry_hover_1_after_wait");
                }
                (_, "browser__hover") => {
                    self.note_hover_shape_phase("await_post_hover_1");
                }
                _ => {}
            }
            return inference_tool_call(&name, arguments);
        }

        self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
    }

    fn recovery_tool_or_safe_fallback(
        &self,
        system_prompt: &str,
        candidates: &[(&str, Value)],
    ) -> Vec<u8> {
        if let Some(tool) = pick_incident_recovery_tool(system_prompt, candidates) {
            return tool;
        }

        let visited_len = incident_visited_fingerprints(system_prompt).len() as u64;
        let wait_base = 125 + (visited_len * 37);
        for ms in [wait_base, wait_base + 43, wait_base + 89] {
            let wait_candidate = [("browser__wait", json!({ "ms": ms }))];
            if let Some(tool) = pick_incident_recovery_tool(system_prompt, &wait_candidate) {
                return tool;
            }
        }

        let navigate_candidate = [("browser__navigate", json!({ "url": self.url }))];
        if let Some(tool) = pick_incident_recovery_tool(system_prompt, &navigate_candidate) {
            return tool;
        }

        inference_wait(wait_base)
    }

    fn recovery_action(&self, bridge_state: &BridgeState, system_prompt: &str) -> Vec<u8> {
        match self.case.recipe {
            RecipeId::ScrollText2 => {
                let root_tool = incident_root_tool(system_prompt).unwrap_or_default();
                let go_bottom = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("bottom");
                if let Some(target) =
                    scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
                {
                    if scroll_target_reached(target, go_bottom) {
                        if let Some(tool) = pick_incident_recovery_tool(
                            system_prompt,
                            &[
                                ("browser__click", json!({ "selector": "#subbtn" })),
                                ("browser__snapshot", json!({})),
                            ],
                        ) {
                            return tool;
                        }
                    }

                    let page_key = scroll_page_key(go_bottom);
                    let (jump_key, jump_modifiers) = scroll_jump_key(go_bottom);
                    let focus_candidate = ("browser__click", json!({ "selector": "#text-area" }));
                    let type_candidate = (
                        "browser__type",
                        json!({ "selector": "#text-area", "text": "" }),
                    );
                    let page_key_candidate = ("browser__key", json!({ "key": page_key }));
                    let jump_key_candidate = (
                        "browser__key",
                        json!({ "key": jump_key, "modifiers": jump_modifiers }),
                    );
                    let candidates = match root_tool {
                        "browser__key" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                            type_candidate.clone(),
                        ],
                        "browser__click" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            type_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        "browser__type" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        "browser__scroll" => vec![
                            jump_key_candidate.clone(),
                            page_key_candidate.clone(),
                            focus_candidate.clone(),
                            ("browser__snapshot", json!({})),
                        ],
                        _ => vec![
                            jump_key_candidate,
                            page_key_candidate,
                            focus_candidate,
                            ("browser__snapshot", json!({})),
                            type_candidate,
                        ],
                    };
                    return self.recovery_tool_or_safe_fallback(system_prompt, &candidates);
                }

                self.recovery_tool_or_safe_fallback(
                    system_prompt,
                    &[
                        ("browser__click", json!({ "selector": "#text-area" })),
                        ("browser__snapshot", json!({})),
                    ],
                )
            }
            RecipeId::ChooseList => {
                let label = parse_submit_target(
                    bridge_state
                        .info
                        .query_text
                        .as_deref()
                        .or(Some(bridge_state.utterance.as_str()))
                        .unwrap_or_default(),
                )
                .unwrap_or_default();
                let candidates = if bridge_selected_contains(
                    &bridge_state.info.interactive_elements,
                    "#options",
                    &label,
                ) {
                    vec![
                        ("browser__click", json!({ "selector": "#options" })),
                        ("browser__click", json!({ "selector": "button" })),
                        ("browser__snapshot", json!({})),
                    ]
                } else {
                    vec![
                        ("browser__click", json!({ "selector": "#options" })),
                        ("browser__snapshot", json!({})),
                    ]
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::UseAutocomplete => {
                let target =
                    bridge_value_by_selector(&bridge_state.info.interactive_elements, "#tags");
                let candidates = if target.is_empty() {
                    vec![
                        ("browser__click", json!({ "selector": "#tags" })),
                        ("browser__wait", json!({ "ms": 120 })),
                        ("browser__snapshot", json!({})),
                    ]
                } else {
                    vec![
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        ("browser__key", json!({ "key": "Escape" })),
                        ("browser__wait", json!({ "ms": 120 })),
                    ]
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::HoverShape => self.hover_shape_recovery_action(system_prompt),
            RecipeId::DragItems => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[("browser__wait", json!({ "ms": 180 }))],
            ),
            RecipeId::HighlightText => {
                let query = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default();
                let selector = highlight_target_selector(query);
                let candidates = match incident_root_tool(system_prompt).unwrap_or_default() {
                    "browser__select_text" => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                    "browser__click" => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                    _ => vec![
                        ("browser__wait", json!({ "ms": 150 })),
                        ("browser__click", json!({ "selector": "#subbtn" })),
                        (
                            "browser__select_text",
                            json!({ "selector": selector.clone() }),
                        ),
                        ("browser__click", json!({ "selector": selector })),
                    ],
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::CopyPaste => {
                let query = bridge_state
                    .info
                    .query_text
                    .as_deref()
                    .or(Some(bridge_state.utterance.as_str()))
                    .unwrap_or_default();
                let source_selector = copy_paste_source_selector(query);
                let source_value = bridge_value_by_selector(
                    &bridge_state.info.interactive_elements,
                    &source_selector,
                );
                let answer_value = bridge_value_by_selector(
                    &bridge_state.info.interactive_elements,
                    "#answer-input",
                );
                if !source_value.is_empty() && answer_value == source_value {
                    if let Some(tool) = pick_incident_recovery_tool(
                        system_prompt,
                        &[
                            ("browser__click", json!({ "selector": "#subbtn" })),
                            ("browser__click", json!({ "selector": "#answer-input" })),
                            (
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            ),
                        ],
                    ) {
                        return tool;
                    }
                }

                let select_all_args =
                    json!({ "key": "a", "modifiers": [primary_browser_modifier()] });
                let reselect_source_args = json!({ "selector": source_selector.clone() });
                let candidates = match incident_root_tool(system_prompt).unwrap_or_default() {
                    "browser__click" => vec![
                        ("browser__key", select_all_args.clone()),
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__key" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__copy_selection" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__key", select_all_args.clone()),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                    ],
                    "browser__paste_clipboard" => vec![
                        ("browser__select_text", reselect_source_args.clone()),
                        ("browser__copy_selection", json!({})),
                        ("browser__key", select_all_args.clone()),
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                        (
                            "browser__paste_clipboard",
                            json!({ "selector": "#answer-input" }),
                        ),
                    ],
                    _ => vec![
                        (
                            "browser__click",
                            json!({ "selector": source_selector.clone() }),
                        ),
                        ("browser__key", select_all_args),
                        ("browser__select_text", reselect_source_args),
                        ("browser__copy_selection", json!({})),
                        (
                            "browser__paste_clipboard",
                            json!({ "selector": "#answer-input" }),
                        ),
                    ],
                };
                self.recovery_tool_or_safe_fallback(system_prompt, &candidates)
            }
            RecipeId::EmailInbox
            | RecipeId::VisualAddition
            | RecipeId::IdentifyShape
            | RecipeId::CountShape
            | RecipeId::CountSides
            | RecipeId::FindMidpoint
            | RecipeId::SurveyOnly => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[("browser__wait", json!({ "ms": 180 }))],
            ),
            _ => self.recovery_tool_or_safe_fallback(
                system_prompt,
                &[
                    ("browser__snapshot", json!({})),
                    ("browser__click", json!({ "selector": "button" })),
                    ("browser__click", json!({ "selector": "#subbtn" })),
                ],
            ),
        }
    }

    fn next_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        if !bridge_state.info.task_ready.unwrap_or(false) || bridge_state.utterance.is_empty() {
            if !self.startup_navigation_issued() {
                self.mark_startup_navigation_issued();
                return inference_tool_call("browser__navigate", json!({ "url": self.url }));
            }
            if bridge_state.info.page_url.as_deref() == Some(self.url.as_str()) {
                return inference_wait(100);
            }
            return inference_tool_call("browser__navigate", json!({ "url": self.url }));
        }
        if bridge_state.terminated
            || should_break_agent_loop_for_reward(bridge_state, self.case.expected_reward_floor)
        {
            return inference_wait(50);
        }

        let query = bridge_state
            .info
            .query_text
            .clone()
            .unwrap_or_else(|| bridge_state.utterance.clone());
        let elements = &bridge_state.info.interactive_elements;
        let stage = bridge_state.episode_step as usize;

        if let Some(phase) = self.take_pending_followup() {
            let wait_ms = match phase.as_str() {
                "form_type" => 120,
                "search_click" => 150,
                _ => 50,
            };
            return inference_wait(wait_ms);
        }

        let click_label = |label: &str| {
            bridge_selector_for_label(elements, label).map(|selector| {
                inference_tool_call("browser__click", json!({ "selector": selector }))
            })
        };

        match self.case.recipe {
            RecipeId::ClickButton | RecipeId::ClickLink => {
                let target = quoted_values(&query).into_iter().next().unwrap_or_default();
                click_label(&target).unwrap_or_else(|| {
                    inference_fail("ERROR_CLASS=TargetNotFound missing selector for target")
                })
            }
            RecipeId::EnterText => {
                let text = quoted_values(&query).into_iter().next().unwrap_or_default();
                if bridge_value_by_selector(elements, "#tt") != text {
                    inference_tool_call("browser__type", json!({ "selector": "#tt", "text": text }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::FocusText => {
                if bridge_focus_matches(bridge_state, "#tt") {
                    inference_wait(50)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#tt" }))
                }
            }
            RecipeId::ChooseList => {
                let label = parse_submit_target(&query).unwrap_or_default();
                if !bridge_selected_contains(elements, "#options", &label) {
                    inference_tool_call(
                        "browser__select_dropdown",
                        json!({ "selector": "#options", "label": label }),
                    )
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "button" }))
                }
            }
            RecipeId::ClickTab => {
                if let Some(target) = quoted_values(&query)
                    .into_iter()
                    .find(|target| !target.trim().is_empty())
                {
                    if let Some(selector) = bridge_selector_for_label(elements, &target) {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else if let Some(selector) =
                        bridge_hidden_tab_selector_for_label(elements, &target)
                    {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_fail("ERROR_CLASS=TargetNotFound click-tab target missing")
                    }
                } else {
                    let number = parse_tab_number(&query).unwrap_or(1);
                    let selector = format!("#ui-id-{}", number);
                    if bridge_element_by_selector(elements, &selector).is_some() {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_tool_call(
                            "browser__click",
                            json!({ "selector": format!("a[href='#tabs-{}']", number) }),
                        )
                    }
                }
            }
            RecipeId::UseAutocomplete => {
                let target = infer_autocomplete_target(&query).unwrap_or_default();
                let value = bridge_value_by_selector(elements, "#tags");
                if value != target {
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#tags", "text": target }),
                    )
                } else if bridge_state.episode_step == 0 {
                    inference_tool_call("browser__key", json!({ "key": "Escape" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ScrollText2 => {
                let go_bottom = query.to_ascii_lowercase().contains("bottom");
                let selector =
                    scroll_target_selector(&bridge_state.info.scroll_targets, "text-area")
                        .unwrap_or_else(|| "#text-area".to_string());
                let page_key = scroll_page_key(go_bottom);
                let (jump_key, jump_modifiers) = scroll_jump_key(go_bottom);
                if let Some(target) =
                    scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
                {
                    if scroll_target_reached(target, go_bottom) {
                        self.note_scroll_action("submit");
                        inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                    } else if !bridge_focus_matches(bridge_state, &selector) {
                        self.note_scroll_action("focus");
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else if self.last_scroll_action().as_deref() == Some("jump_key") {
                        self.note_scroll_action("page_key");
                        inference_tool_call("browser__key", json!({ "key": page_key }))
                    } else {
                        self.note_scroll_action("jump_key");
                        inference_tool_call(
                            "browser__key",
                            json!({ "key": jump_key, "modifiers": jump_modifiers }),
                        )
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                }
            }
            RecipeId::ClickOption => match stage {
                0 => {
                    let label = parse_submit_target(&query).unwrap_or_default();
                    click_label(&label).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound click-option target missing")
                    })
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "button" })),
            },
            RecipeId::ClickCheckboxes | RecipeId::ClickCheckboxesTransfer => {
                let targets = parse_checkbox_targets(&query);
                if let Some(label) = targets
                    .iter()
                    .find(|label| !self.checkbox_target_satisfied(elements, label))
                {
                    click_label(label)
                        .map(|action| {
                            self.note_checkbox_click(label);
                            action
                        })
                        .unwrap_or_else(|| {
                            inference_fail("ERROR_CLASS=TargetNotFound checkbox target missing")
                        })
                } else if !targets.is_empty()
                    && !targets.iter().all(|label| {
                        bridge_checkbox_checked_for_label(elements, label).unwrap_or(false)
                    })
                {
                    inference_wait(120)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "button" }))
                }
            }
            RecipeId::EnterPassword => {
                let password = quoted_values(&query).into_iter().next().unwrap_or_default();
                let password_value = bridge_value_by_selector(elements, "#password");
                let verify_value = bridge_value_by_selector(elements, "#verify");
                if password_value != password {
                    if bridge_focus_matches(bridge_state, "#password") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#password", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#password" }))
                    }
                } else if verify_value != password {
                    if bridge_focus_matches(bridge_state, "#verify") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#verify", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#verify" }))
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::LoginUser => {
                let quoted = quoted_values(&query);
                let username = quoted.first().cloned().unwrap_or_default();
                let password = quoted.get(1).cloned().unwrap_or_default();
                let username_value = bridge_value_by_selector(elements, "#username");
                let password_value = bridge_value_by_selector(elements, "#password");
                if username_value != username {
                    if bridge_focus_matches(bridge_state, "#username") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#username", "text": username }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#username" }))
                    }
                } else if password_value != password {
                    if bridge_focus_matches(bridge_state, "#password") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#password", "text": password }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#password" }))
                    }
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::FocusText2 => {
                let index = parse_focus_index(&query).unwrap_or(1);
                let selector = format!("#tt{}", index);
                if bridge_focus_matches(bridge_state, &selector) {
                    inference_wait(50)
                } else {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                }
            }
            RecipeId::EnterText2 => match stage {
                0 => {
                    let raw_text = quoted_values(&query).into_iter().next().unwrap_or_default();
                    let text = parse_uppercase_transform(&query, &raw_text);
                    inference_tool_call("browser__type", json!({ "selector": "#tt", "text": text }))
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
            },
            RecipeId::ClickButtonSequence => {
                if stage == 0 {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn2" }))
                }
            }
            RecipeId::ClickCollapsible => {
                if stage == 0 {
                    inference_tool_call("browser__click", json!({ "selector": "#area h3" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ClickCollapsible2 => {
                let target = quoted_values(&query).into_iter().next().unwrap_or_default();
                if let Some(action) = click_label(&target) {
                    action
                } else if let Some(selector) =
                    bridge_hidden_collapsible_selector_for_label(elements, &target)
                {
                    inference_tool_call("browser__click", json!({ "selector": selector }))
                } else {
                    inference_fail("ERROR_CLASS=TargetNotFound click-collapsible-2 target missing")
                }
            }
            RecipeId::SearchEngine => {
                let position = parse_search_result_position(&query).unwrap_or(1);
                let page = ((position - 1) / 3) + 1;
                let local_index = ((position - 1) % 3) + 1;
                let search_term = quoted_values(&query).into_iter().next().unwrap_or_default();
                let search_value = bridge_value_by_selector(elements, "#search-text");
                if search_value != search_term {
                    if bridge_focus_matches(bridge_state, "#search-text") {
                        self.note_pending_followup("form_type");
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#search-text", "text": search_term }),
                        )
                    } else {
                        inference_tool_call("browser__click", json!({ "selector": "#search-text" }))
                    }
                } else if search_result_selector(elements, 1).is_none() {
                    self.note_pending_followup("search_click");
                    inference_tool_call("browser__click", json!({ "selector": "#search" }))
                } else if page > 1 && !search_results_page_matches(elements, page) {
                    self.note_pending_followup("search_click");
                    click_label(&page.to_string()).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound pagination target missing")
                    })
                } else {
                    if let Some(selector) = search_result_selector(elements, local_index as usize) {
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else {
                        inference_fail(
                            "ERROR_CLASS=TargetNotFound search-engine result selector missing",
                        )
                    }
                }
            }
            RecipeId::SimpleArithmetic => {
                let problem =
                    trim_submit_button_suffix(bridge_visible_content_after_query(bridge_state, &query));
                let Some(answer) = solve_simple_arithmetic_problem(problem) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap simple-arithmetic prompt missing",
                    );
                };
                let answer = answer.to_string();
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#math-answer", &answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::SimpleAlgebra => {
                let visible_problem =
                    trim_submit_button_suffix(bridge_visible_content_after_query(bridge_state, &query));
                let problem = visible_problem
                    .split_once(" x =")
                    .map(|(value, _)| value.trim())
                    .unwrap_or(visible_problem);
                let Some(answer) = solve_simple_algebra_problem(problem) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap simple-algebra prompt missing",
                    );
                };
                let answer = answer.to_string();
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#math-answer", &answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::OddOrEven => {
                let visible_numbers =
                    odd_or_even_visible_numbers(bridge_visible_content_after_query(bridge_state, &query));
                if visible_numbers.is_empty() {
                    inference_fail("ERROR_CLASS=ObservationGap odd-or-even numbers missing")
                } else if stage < visible_numbers.len() {
                    let parity_selector = if visible_numbers[stage].rem_euclid(2) == 0 {
                        ".even"
                    } else {
                        ".odd"
                    };
                    inference_tool_call(
                        "browser__click",
                        json!({
                            "selector": format!(
                                "#numbers .row:nth-of-type({}) {}",
                                stage + 1,
                                parity_selector
                            )
                        }),
                    )
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#submit" }))
                }
            }
            RecipeId::FindWord => {
                let word_index = parse_find_word_index(&query).unwrap_or(1);
                let paragraph =
                    trim_submit_button_suffix(bridge_visible_content_after_query(bridge_state, &query));
                let words = paragraph
                    .split_whitespace()
                    .map(|word| {
                        word.chars()
                            .filter(|ch| ch.is_ascii_alphanumeric())
                            .collect::<String>()
                    })
                    .filter(|word| !word.is_empty())
                    .collect::<Vec<_>>();
                let Some(answer) = words.get(word_index.saturating_sub(1)) else {
                    return inference_fail("ERROR_CLASS=ObservationGap find-word target missing");
                };
                if let Some(action) = self.fill_text_field_if_needed(
                    bridge_state,
                    elements,
                    "#answer-input",
                    answer,
                ) {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ReadTable => {
                let target = parse_read_table_target(&query).unwrap_or_default();
                let values = visible_table_value_map(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let Some(answer) = values.get(&target) else {
                    return inference_fail("ERROR_CLASS=ObservationGap read-table value missing");
                };
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt", answer)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::ReadTable2 => {
                let values = visible_table_value_map(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ));
                let label_1 = bridge_element_by_selector(elements, "#ll1")
                    .map(bridge_element_display_text)
                    .map(|text| text.trim().trim_end_matches(':').to_string())
                    .unwrap_or_default();
                let label_2 = bridge_element_by_selector(elements, "#ll2")
                    .map(bridge_element_display_text)
                    .map(|text| text.trim().trim_end_matches(':').to_string())
                    .unwrap_or_default();
                let Some(answer_1) = values.get(&label_1) else {
                    return inference_fail("ERROR_CLASS=ObservationGap read-table-2 first value missing");
                };
                let Some(answer_2) = values.get(&label_2) else {
                    return inference_fail(
                        "ERROR_CLASS=ObservationGap read-table-2 second value missing",
                    );
                };
                if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt1", answer_1)
                {
                    action
                } else if let Some(action) =
                    self.fill_text_field_if_needed(bridge_state, elements, "#tt2", answer_2)
                {
                    action
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            RecipeId::PhoneBook => {
                let target_name = parse_phone_book_name(&query).unwrap_or_default();
                let target_kind = parse_phone_book_target(&query).unwrap_or_default();
                let property_selector = match normalize_label(&target_kind).as_str() {
                    "phone number" | "phone" => "#contact .phone",
                    "email" => "#contact .email",
                    "address" => "#contact .address",
                    _ => {
                        return inference_fail(
                            "ERROR_CLASS=TargetNotFound phone-book target kind missing",
                        )
                    }
                };
                let current_name = phone_book_visible_name(bridge_visible_content_after_query(
                    bridge_state,
                    &query,
                ))
                .unwrap_or_default();
                if normalize_label(&current_name) == normalize_label(&target_name) {
                    inference_tool_call(
                        "browser__click",
                        json!({ "selector": property_selector }),
                    )
                } else if let Some(next_selector) = bridge_selector_for_label(elements, ">") {
                    inference_tool_call("browser__click", json!({ "selector": next_selector }))
                } else {
                    inference_fail("ERROR_CLASS=TargetNotFound phone-book next page missing")
                }
            }
            RecipeId::FormSequence
            | RecipeId::FormSequence2
            | RecipeId::FormSequence3
            | RecipeId::LoginUserPopup
            | RecipeId::TextEditor
            | RecipeId::GuessNumber
            | RecipeId::FindGreatest
            | RecipeId::SocialMedia
            | RecipeId::SocialMediaAll
            | RecipeId::SocialMediaSome
            | RecipeId::StockMarket
            | RecipeId::EmailInbox
            | RecipeId::VisualAddition
            | RecipeId::IdentifyShape
            | RecipeId::CountShape
            | RecipeId::CountSides
            | RecipeId::FindMidpoint => {
                inference_fail("ERROR_CLASS=CatalogSurvey agent recipe pending for PR8 follow-up")
            }
            RecipeId::HoverShape => match self.hover_shape_phase().as_deref() {
                None => {
                    self.note_hover_shape_phase("await_post_hover_1");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_1_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_1");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_1") => {
                    self.note_hover_shape_phase("await_post_wait_1");
                    inference_tool_call("browser__wait", json!({ "ms": 1300 }))
                }
                Some("await_post_wait_1") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_2_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_2");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_2") => {
                    self.note_hover_shape_phase("await_post_wait_2");
                    inference_tool_call("browser__wait", json!({ "ms": 1300 }))
                }
                Some("await_post_wait_2") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("retry_hover_3_after_wait") => {
                    self.note_hover_shape_phase("await_post_hover_3");
                    inference_tool_call("browser__hover", json!({ "selector": "#highlight" }))
                }
                Some("await_post_hover_3") => {
                    self.note_hover_shape_phase("complete");
                    inference_tool_call("agent__complete", json!({}))
                }
                _ => inference_tool_call("agent__complete", json!({})),
            },
            RecipeId::DragItems => inference_fail(
                "ERROR_CLASS=PlannerGap drag-items agent recipe needs structured order readback",
            ),
            RecipeId::HighlightText => {
                let selector = highlight_target_selector(&query);
                match stage {
                    0 => {
                        inference_tool_call("browser__select_text", json!({ "selector": selector }))
                    }
                    1 => inference_wait(150),
                    _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
                }
            }
            RecipeId::CopyPaste => {
                let source_selector = copy_paste_source_selector(&query);
                let source_value = bridge_value_by_selector(elements, &source_selector);
                let answer_value = bridge_value_by_selector(elements, "#answer-input");
                let phase = self.last_copy_paste_action();
                if !source_value.is_empty() && answer_value == source_value {
                    match phase.as_deref() {
                        Some("paste") => {
                            self.note_copy_paste_action("submit_wait");
                            inference_wait(150)
                        }
                        Some("submit_wait") | Some("paste_retry") => {
                            self.note_copy_paste_action("submit");
                            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                        }
                        Some("submit") => inference_wait(50),
                        _ => {
                            self.note_copy_paste_action("submit");
                            inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                        }
                    }
                } else {
                    match phase.as_deref() {
                        None => {
                            self.note_copy_paste_action("click_source");
                            inference_tool_call(
                                "browser__click",
                                json!({ "selector": source_selector }),
                            )
                        }
                        Some("click_source") => {
                            self.note_copy_paste_action("focus_wait");
                            inference_wait(100)
                        }
                        Some("focus_wait") => {
                            self.note_copy_paste_action("key_chord");
                            inference_tool_call(
                                "browser__key",
                                json!({ "key": "a", "modifiers": [primary_browser_modifier()] }),
                            )
                        }
                        Some("key_chord") => {
                            self.note_copy_paste_action("selection_wait");
                            inference_wait(100)
                        }
                        Some("selection_wait") => {
                            self.note_copy_paste_action("copy");
                            inference_tool_call("browser__copy_selection", json!({}))
                        }
                        Some("copy") => {
                            self.note_copy_paste_action("paste");
                            inference_tool_call(
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            )
                        }
                        Some("paste") => {
                            self.note_copy_paste_action("paste_wait");
                            inference_wait(100)
                        }
                        Some("paste_wait") => {
                            self.note_copy_paste_action("paste_retry");
                            inference_tool_call(
                                "browser__paste_clipboard",
                                json!({ "selector": "#answer-input" }),
                            )
                        }
                        _ => {
                            self.note_copy_paste_action("copy");
                            inference_tool_call("browser__copy_selection", json!({}))
                        }
                    }
                }
            }
            RecipeId::SurveyOnly => inference_fail("ERROR_CLASS=CatalogSurvey survey-only case"),
        }
    }
}

#[async_trait]
impl InferenceRuntime for MiniwobAgentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        if std::env::var_os("COMPUTER_USE_SUITE_DEBUG_PROMPTS").is_some() {
            let debug_path = std::env::temp_dir()
                .join(format!("computer_use_suite_{}_prompt.json", self.case.id));
            let _ = fs::write(&debug_path, input_context);
        }
        let system_prompt = extract_system_prompt(input_context);
        let bridge_state = self
            .client
            .state(&self.session_id)
            .await
            .map_err(|err| VmError::HostError(format!("bridge state: {}", err)))?;
        if is_incident_recovery_prompt(&system_prompt) {
            if matches!(self.case.recipe, RecipeId::HoverShape) {
                return Ok(self.hover_shape_recovery_action(&system_prompt));
            }
            return Ok(self.recovery_action(&bridge_state, &system_prompt));
        }
        Ok(self.next_action(&bridge_state))
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

async fn run_direct_case(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    client: BridgeClient,
    case: &ComputerUseCase,
    artifact_root: PathBuf,
    shared: &DirectExecutionContext,
) -> Result<ComputerUseCaseResult> {
    let created = client.create_session(case).await?;
    let mut harness = DirectHarness::new(
        client.clone(),
        created.session_id.clone(),
        created.state,
        mode,
        case.seed,
        shared,
    )
    .await?;

    let started = Instant::now();
    let execution_result = match timeout(
        Duration::from_secs(case.timeout_seconds),
        Box::pin(async {
            let navigate_result = harness
                .execute_tool(AgentTool::BrowserNavigate { url: created.url })
                .await?;
            if !navigate_result.success {
                return Err(anyhow!(
                    "browser__navigate failed: {}",
                    navigate_result
                        .error
                        .unwrap_or_else(|| "unknown error".to_string())
                ));
            }
            harness.wait_until_ready().await?;

            match mode {
                ComputerUseMode::Oracle => run_oracle_recipe(&mut harness, case).await,
                ComputerUseMode::Runtime => run_runtime_recipe(&mut harness, case).await,
                ComputerUseMode::Agent => Err(anyhow!("agent mode must use run_agent_case")),
            }
        }),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang direct case exceeded {}s",
            case.timeout_seconds
        )),
    };

    let mut failure_class = execution_result
        .as_ref()
        .err()
        .and_then(|err| extract_error_class(&err.to_string()));
    let final_state = settle_final_bridge_state(&mut harness, case.local_judge).await?;
    let screenshot_path = artifact_root.join("final.png");
    let bridge_state_path = artifact_root.join("bridge_state.json");
    let kernel_events_path = artifact_root.join("kernel_events.json");
    let should_capture_artifacts = config.retain_artifacts_for_all_runs
        || execution_result.is_err()
        || !final_state.terminated;
    if should_capture_artifacts {
        let _ = timeout(
            Duration::from_secs(2),
            harness.capture_screenshot(&screenshot_path),
        )
        .await;
        write_json_file(&bridge_state_path, &final_state)?;
        write_json_file(&kernel_events_path, &harness.kernel_events)?;
    }
    let mut snapshot_paths = Vec::new();
    for (index, step) in harness.tool_steps.iter().enumerate() {
        if step.tool_name == "browser__snapshot" {
            let path = artifact_root.join(format!("snapshot_{}.xml", index + 1));
            if let Some(xml) = &step.history_entry {
                let _ = write_text_file(&path, xml);
                snapshot_paths.push(path.to_string_lossy().to_string());
            }
        }
    }
    drain_events(&mut harness.event_rx, &mut harness.kernel_events);
    let kernel_behavior = KernelBehaviorObservation {
        executed_tools: harness
            .tool_steps
            .iter()
            .map(|step| step.tool_name.clone())
            .collect(),
        action_result_count: 0,
        routing_receipt_count: 0,
        intent_receipt_count: 0,
        execution_contract_receipt_count: 0,
        workload_receipt_count: 0,
        workload_activity_count: 0,
        disallowed_tools: Vec::new(),
    };
    if !final_state.terminated && failure_class.is_none() {
        failure_class = Some("task_not_terminated".to_string());
    }
    let result = ComputerUseCaseResult {
        case_id: case.id.clone(),
        env_id: case.env_id.clone(),
        seed: case.seed,
        mode,
        task_set: case.task_set,
        utterance: final_state.utterance.clone(),
        elapsed_ms: started.elapsed().as_millis(),
        expected_reward_floor: case.expected_reward_floor,
        final_reward: final_state.reward,
        expected_pass: case.expected_pass,
        terminated: final_state.terminated,
        truncated: final_state.truncated,
        overall_pass: false,
        tool_steps: harness.tool_steps.clone(),
        oracle_steps: harness.oracle_steps.clone(),
        kernel_events: harness.kernel_events.clone(),
        bridge_state: final_state.clone(),
        kernel_behavior,
        validation: ValidationSummary::default(),
        artifacts: ArtifactBundle {
            artifact_root: artifact_root.to_string_lossy().to_string(),
            bridge_state_path: should_capture_artifacts
                .then(|| bridge_state_path.to_string_lossy().to_string()),
            kernel_events_path: should_capture_artifacts
                .then(|| kernel_events_path.to_string_lossy().to_string()),
            json_report_path: None,
            markdown_summary_path: None,
            csv_summary_path: None,
            screenshot_paths: should_capture_artifacts
                .then(|| vec![screenshot_path.to_string_lossy().to_string()])
                .unwrap_or_default(),
            snapshot_paths,
        },
        failure_class,
        support_state: BenchmarkSupportState::NotYetAttempted,
        primary_gap_class: None,
        secondary_gap_tags: Vec::new(),
    };
    harness.client.close(&harness.session_id).await?;
    harness.stop().await;
    Ok(result)
}

fn direct_case_error_result(
    case: &ComputerUseCase,
    mode: ComputerUseMode,
    artifact_root: PathBuf,
    elapsed_ms: u128,
    failure_class: String,
) -> ComputerUseCaseResult {
    ComputerUseCaseResult {
        case_id: case.id.clone(),
        env_id: case.env_id.clone(),
        seed: case.seed,
        mode,
        task_set: case.task_set,
        utterance: String::new(),
        elapsed_ms,
        expected_reward_floor: case.expected_reward_floor,
        final_reward: 0.0,
        expected_pass: case.expected_pass,
        terminated: false,
        truncated: false,
        overall_pass: false,
        tool_steps: Vec::new(),
        oracle_steps: Vec::new(),
        kernel_events: Vec::new(),
        bridge_state: BridgeState::default(),
        kernel_behavior: KernelBehaviorObservation::default(),
        validation: ValidationSummary::default(),
        artifacts: ArtifactBundle {
            artifact_root: artifact_root.to_string_lossy().to_string(),
            bridge_state_path: None,
            kernel_events_path: None,
            json_report_path: None,
            markdown_summary_path: None,
            csv_summary_path: None,
            screenshot_paths: Vec::new(),
            snapshot_paths: Vec::new(),
        },
        failure_class: Some(failure_class),
        support_state: BenchmarkSupportState::NotYetAttempted,
        primary_gap_class: None,
        secondary_gap_tags: Vec::new(),
    }
}

async fn run_agent_case(
    config: &SuiteConfig,
    client: BridgeClient,
    case: &ComputerUseCase,
    artifact_root: PathBuf,
) -> Result<ComputerUseCaseResult> {
    let created = client.create_session(case).await?;
    let headless = headless_for_run(config)?;
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(RecordingGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
    browser
        .launch(headless)
        .await
        .map_err(|err| anyhow!("launch Chromium for agent mode: {}", err))?;
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(MiniwobAgentRuntime {
        case: case.clone(),
        client: client.clone(),
        session_id: created.session_id.clone(),
        url: created.url.clone(),
        startup_navigation_issued: Mutex::new(false),
        pending_followup: Mutex::new(None),
        optimistic_checked_labels: Mutex::new(BTreeSet::new()),
        last_scroll_action: Mutex::new(None),
        last_copy_paste_action: Mutex::new(None),
        last_hover_shape_phase: Mutex::new(None),
    });
    let (scs, _scs_tmp_dir) = build_scs(&format!("computer_use_suite_{}.scs", case.id))?;
    let service =
        DesktopAgentService::new_hybrid(gui, terminal, browser.clone(), runtime.clone(), runtime)
            .with_scs(Arc::new(Mutex::new(scs)))
            .with_event_sender(event_tx)
            .with_os_driver(Arc::new(StaticOsDriver::default()));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(Vec::<Arc<dyn BlockchainService>>::new());
    let mut ctx = build_ctx(&services_dir);
    let session_id = compute_session_id(case.seed, ComputerUseMode::Agent);

    let start_params = StartAgentParams {
        session_id,
        goal: format!(
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task: {}",
            case.env_id
        ),
        max_steps: case.max_steps,
        parent_session_id: None,
        initial_budget: 4_000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|err| anyhow!("encode start params: {}", err))?,
            &mut ctx,
        )
        .await?;
    apply_allow_all_policy(&mut state, session_id);
    seed_browser_resolved_intent(&mut state, session_id);

    let started = Instant::now();
    let deadline = Duration::from_secs(case.timeout_seconds);
    let mut kernel_events = Vec::new();
    loop {
        drain_events(&mut event_rx, &mut kernel_events);
        let live_bridge_state = client.state(&created.session_id).await?;
        if live_bridge_state.terminated
            || should_break_agent_loop_for_reward(&live_bridge_state, case.expected_reward_floor)
        {
            break;
        }
        let current = read_agent_state(&state, session_id);
        match &current.status {
            AgentStatus::Completed(_)
            | AgentStatus::Failed(_)
            | AgentStatus::Paused(_)
            | AgentStatus::Terminated => break,
            AgentStatus::Idle | AgentStatus::Running => {}
        }
        if started.elapsed() > deadline {
            break;
        }

        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|err| anyhow!("encode step params: {}", err))?,
                &mut ctx,
            )
            .await?;
    }

    let final_state = read_agent_state(&state, session_id);
    if matches!(
        final_state.status,
        AgentStatus::Completed(_)
            | AgentStatus::Failed(_)
            | AgentStatus::Paused(_)
            | AgentStatus::Terminated
    ) {
        drain_events_until_quiescent(&mut event_rx, &mut kernel_events).await;
    }

    let bridge_state = client.state(&created.session_id).await?;
    let screenshot_path = artifact_root.join("final.png");
    let bridge_state_path = artifact_root.join("bridge_state.json");
    let kernel_events_path = artifact_root.join("kernel_events.json");
    let agent_state_path = artifact_root.join("agent_state.json");
    let should_capture_artifacts = config.retain_artifacts_for_all_runs
        || !bridge_state.terminated
        || bridge_state.reward < case.expected_reward_floor;
    if should_capture_artifacts {
        let bytes = browser
            .capture_tab_screenshot(false)
            .await
            .map_err(|err| anyhow!("agent screenshot: {}", err))?;
        if let Some(parent) = screenshot_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&screenshot_path, bytes)?;
        write_json_file(&bridge_state_path, &bridge_state)?;
        write_json_file(&kernel_events_path, &kernel_events)?;
        write_json_file(&agent_state_path, &final_state)?;
    }

    let observations = collect_agent_kernel_observations(&kernel_events, &bridge_state);
    let tool_steps = observations.tool_steps;
    let executed_tools = observations.executed_tools;
    let routing_receipt_count = observations.routing_receipt_count;
    let intent_receipt_count = observations.intent_receipt_count;
    let execution_contract_receipt_count = observations.execution_contract_receipt_count;
    let workload_receipt_count = observations.workload_receipt_count;
    let workload_activity_count = observations.workload_activity_count;
    let mut failure_class = observations.failure_class;

    if failure_class.is_none() {
        failure_class = match &final_state.status {
            AgentStatus::Paused(reason) => {
                extract_error_class(reason).or_else(|| Some("agent_paused".to_string()))
            }
            AgentStatus::Failed(reason) => {
                extract_error_class(reason).or_else(|| Some("agent_failed".to_string()))
            }
            _ => None,
        };
    }

    let mut snapshot_paths = Vec::new();
    for (index, step) in tool_steps.iter().enumerate() {
        if step.tool_name == "browser__snapshot" {
            let path = artifact_root.join(format!("snapshot_{}.xml", index + 1));
            if let Some(xml) = &step.history_entry {
                let _ = write_text_file(&path, xml);
                snapshot_paths.push(path.to_string_lossy().to_string());
            }
        }
    }

    client.close(&created.session_id).await?;
    browser.stop().await;

    Ok(ComputerUseCaseResult {
        case_id: case.id.clone(),
        env_id: case.env_id.clone(),
        seed: case.seed,
        mode: ComputerUseMode::Agent,
        task_set: case.task_set,
        utterance: bridge_state.utterance.clone(),
        elapsed_ms: started.elapsed().as_millis(),
        expected_reward_floor: case.expected_reward_floor,
        final_reward: bridge_state.reward,
        expected_pass: case.expected_pass,
        terminated: bridge_state.terminated,
        truncated: bridge_state.truncated,
        overall_pass: false,
        tool_steps,
        oracle_steps: Vec::new(),
        kernel_events: kernel_events.clone(),
        bridge_state: bridge_state.clone(),
        kernel_behavior: KernelBehaviorObservation {
            executed_tools,
            action_result_count: kernel_events
                .iter()
                .filter(|event| matches!(event, KernelEvent::AgentActionResult { .. }))
                .count(),
            routing_receipt_count,
            intent_receipt_count,
            execution_contract_receipt_count,
            workload_receipt_count,
            workload_activity_count,
            disallowed_tools: Vec::new(),
        },
        validation: ValidationSummary::default(),
        artifacts: ArtifactBundle {
            artifact_root: artifact_root.to_string_lossy().to_string(),
            bridge_state_path: should_capture_artifacts
                .then(|| bridge_state_path.to_string_lossy().to_string()),
            kernel_events_path: should_capture_artifacts
                .then(|| kernel_events_path.to_string_lossy().to_string()),
            json_report_path: None,
            markdown_summary_path: None,
            csv_summary_path: None,
            screenshot_paths: should_capture_artifacts
                .then(|| vec![screenshot_path.to_string_lossy().to_string()])
                .unwrap_or_default(),
            snapshot_paths,
        },
        failure_class,
        support_state: BenchmarkSupportState::NotYetAttempted,
        primary_gap_class: None,
        secondary_gap_tags: Vec::new(),
    })
}

pub async fn run_mode(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    cases: &[ComputerUseCase],
) -> Result<ModeRunReport> {
    let mut bridge = BridgeProcess::start(config).await?;
    let direct_headless = if matches!(mode, ComputerUseMode::Oracle | ComputerUseMode::Runtime) {
        Some(headless_for_run(config)?)
    } else {
        None
    };
    let mut direct_context = if let Some(headless) = direct_headless {
        Some(DirectExecutionContext::start(headless).await?)
    } else {
        None
    };
    let mut results = Vec::new();
    for case in cases {
        let case_root = config
            .artifact_root
            .join(mode.as_str())
            .join(case.id.to_string());
        fs::create_dir_all(&case_root)?;
        let result = match mode {
            ComputerUseMode::Oracle | ComputerUseMode::Runtime => {
                let started = Instant::now();
                let result = timeout(
                    Duration::from_secs(case.timeout_seconds.saturating_add(15)),
                    Box::pin(run_direct_case(
                        config,
                        mode,
                        bridge.client.clone(),
                        case,
                        case_root.clone(),
                        direct_context
                            .as_ref()
                            .expect("direct execution context should exist for direct modes"),
                    )),
                )
                .await;
                match result {
                    Ok(result) => result,
                    Err(_) => {
                        let error_path = case_root.join("error.txt");
                        let _ = write_text_file(
                            &error_path,
                            &format!(
                                "direct case timed out after {}s wall clock; resetting bridge and browser context",
                                case.timeout_seconds.saturating_add(15)
                            ),
                        );
                        if let Some(context) = direct_context.take() {
                            context.stop().await;
                        }
                        bridge.stop().await;
                        bridge = BridgeProcess::start(config).await?;
                        if let Some(headless) = direct_headless {
                            direct_context = Some(DirectExecutionContext::start(headless).await?);
                        }
                        results.push(direct_case_error_result(
                            case,
                            mode,
                            case_root,
                            started.elapsed().as_millis(),
                            "TimeoutOrHang".to_string(),
                        ));
                        continue;
                    }
                }
            }
            ComputerUseMode::Agent => {
                run_agent_case(config, bridge.client.clone(), case, case_root).await
            }
        };
        match result {
            Ok(result) => results.push(result),
            Err(err) => {
                let case_artifact_root = config
                    .artifact_root
                    .join(mode.as_str())
                    .join(case.id.clone());
                let error_path = case_artifact_root.join("error.txt");
                let _ = write_text_file(&error_path, &format!("{:#}", err));
                results.push(direct_case_error_result(
                    case,
                    mode,
                    case_artifact_root,
                    0,
                    extract_error_class(&err.to_string())
                        .unwrap_or_else(|| "harness_error".to_string()),
                ))
            }
        }
    }
    if let Some(context) = &direct_context {
        context.stop().await;
    }
    bridge.stop().await;
    Ok(ModeRunReport { results })
}

pub async fn persist_mode_report(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    task_set: TaskSet,
    results: &[ComputerUseCaseResult],
) -> Result<()> {
    let mode_root = config.artifact_root.join(mode.as_str());
    fs::create_dir_all(&mode_root)?;
    let stem = format!("{}_{}", mode.as_str(), task_set.as_str());
    let jsonl_path = mode_root.join(format!("{}.jsonl", stem));
    let markdown_path = mode_root.join(format!("{}.md", stem));
    let csv_path = mode_root.join(format!("{}.csv", stem));
    let gap_matrix_path = mode_root.join(format!("{}_gap_matrix.json", stem));

    let mut jsonl = String::new();
    let mut csv = String::from(
        "case_id,env_id,mode,task_set,pass,support_state,primary_gap_class,secondary_gap_tags,reward,terminated,elapsed_ms,failure_class\n",
    );
    let mut support_counts = BTreeMap::<String, usize>::new();
    let mut gap_counts = BTreeMap::<String, usize>::new();
    for result in results {
        jsonl.push_str(&serde_json::to_string(result)?);
        jsonl.push('\n');
        *support_counts
            .entry(result.support_state.as_str().to_string())
            .or_default() += 1;
        if let Some(gap_class) = result.primary_gap_class {
            *gap_counts
                .entry(gap_class.as_str().to_string())
                .or_default() += 1;
        }
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.3},{},{},{}\n",
            result.case_id,
            result.env_id,
            result.mode.as_str(),
            result.task_set.as_str(),
            result.overall_pass,
            result.support_state.as_str(),
            result
                .primary_gap_class
                .map(|gap_class| gap_class.as_str().to_string())
                .unwrap_or_default(),
            result.secondary_gap_tags.join("|"),
            result.final_reward,
            result.terminated,
            result.elapsed_ms,
            result.failure_class.clone().unwrap_or_default()
        ));
    }

    let passing = results.iter().filter(|result| result.overall_pass).count();
    let markdown = format!(
        "# Computer Use Suite\n\n- mode: `{}`\n- task_set: `{}`\n- passing: `{}` / `{}`\n- artifact_root: `{}`\n- support_counts: `{}`\n- gap_counts: `{}`\n\n| case | env | pass | support | gap | tags | reward | terminated | failure |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n{}",
        mode.as_str(),
        task_set.as_str(),
        passing,
        results.len(),
        config.artifact_root.display(),
        serde_json::to_string(&support_counts)?,
        serde_json::to_string(&gap_counts)?,
        results
            .iter()
            .map(|result| {
                format!(
                    "| {} | {} | {} | {} | {} | {} | {:.3} | {} | {} |",
                    result.case_id,
                    result.env_id,
                    if result.overall_pass { "yes" } else { "no" },
                    result.support_state.as_str(),
                    result
                        .primary_gap_class
                        .map(|gap_class| gap_class.as_str().to_string())
                        .unwrap_or_default(),
                    result.secondary_gap_tags.join(", "),
                    result.final_reward,
                    result.terminated,
                    result.failure_class.clone().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );

    let gap_matrix = json!({
        "mode": mode.as_str(),
        "task_set": task_set.as_str(),
        "artifact_root": config.artifact_root.to_string_lossy(),
        "totals": {
            "cases": results.len(),
            "passing": passing,
            "failing": results.len().saturating_sub(passing),
        },
        "by_support_state": support_counts,
        "by_gap_class": gap_counts,
        "results": results.iter().map(|result| {
            json!({
                "case_id": &result.case_id,
                "env_id": &result.env_id,
                "overall_pass": result.overall_pass,
                "support_state": result.support_state.as_str(),
                "primary_gap_class": result.primary_gap_class.map(|gap_class| gap_class.as_str()),
                "secondary_gap_tags": &result.secondary_gap_tags,
                "failure_class": result.failure_class.as_deref(),
                "artifact_root": &result.artifacts.artifact_root,
            })
        }).collect::<Vec<_>>(),
    });

    write_text_file(&jsonl_path, &jsonl)?;
    write_text_file(&markdown_path, &markdown)?;
    write_text_file(&csv_path, &csv)?;
    write_json_file(&gap_matrix_path, &gap_matrix)?;
    Ok(())
}
