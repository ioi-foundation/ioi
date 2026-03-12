use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_crypto::algorithms::hash::sha256;
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
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::process::{Child, Command};
use tokio::sync::broadcast;
use tokio::time::sleep;

use super::types::{
    ArtifactBundle, BridgeInteractiveElement, BridgeScrollTarget, BridgeState, ComputerUseCase,
    ComputerUseCaseResult, ComputerUseMode, KernelBehaviorObservation, OracleStepRecord, RecipeId,
    SuiteConfig, TaskSet, ToolStepRecord, ValidationSummary,
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

#[derive(Debug, Deserialize)]
struct BridgeUrlResponse {
    url: String,
}

#[derive(Debug, Deserialize)]
struct BridgeCommandEnvelope {
    command: Option<Value>,
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
        Ok(response.json::<Value>().await.context("bridge health json")?)
    }

    async fn create_session(&self, case: &ComputerUseCase) -> Result<BridgeCreateResponse> {
        let response = self
            .http
            .post(format!("{}/session/create", self.base_url))
            .json(&json!({
                "env_id": case.env_id,
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
        response.json::<BridgeState>().await.context("bridge state json")
    }

    async fn url(&self, session_id: &str) -> Result<String> {
        let response = self
            .http
            .get(format!("{}/session/{}/url", self.base_url, session_id))
            .send()
            .await
            .context("bridge url request")?
            .error_for_status()
            .context("bridge url status")?;
        let payload = response
            .json::<BridgeUrlResponse>()
            .await
            .context("bridge url json")?;
        Ok(payload.url)
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

    async fn oracle_poll(&self, session_id: &str, generation: u32, after: u32) -> Result<Value> {
        let response = self
            .http
            .get(format!(
                "{}/session/{}/oracle_poll?generation={}&after={}",
                self.base_url, session_id, generation, after
            ))
            .send()
            .await
            .context("bridge oracle poll request")?
            .error_for_status()
            .context("bridge oracle poll status")?;
        let envelope = response
            .json::<BridgeCommandEnvelope>()
            .await
            .context("bridge oracle poll json")?;
        Ok(envelope.command.unwrap_or(Value::Null))
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

struct StaticOsDriver;

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

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
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

fn seed_browser_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) {
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
    let os: Arc<dyn OsDriver> = Arc::new(StaticOsDriver);
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

    async fn load_model(&self, _model_hash: [u8; 32], _model_path: &std::path::Path) -> Result<(), VmError> {
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

fn escape_xml_attr_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape_xml_attr_value(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn normalize_label(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

fn extract_xml_attribute(fragment: &str, attr: &str) -> Option<String> {
    let prefix = format!(r#"{attr}=""#);
    let start = fragment.find(&prefix)? + prefix.len();
    let rest = &fragment[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_node_fragments(xml: &str) -> Vec<String> {
    xml.split('<')
        .filter_map(|fragment| {
            let trimmed = fragment.trim();
            if trimmed.is_empty() || !trimmed.contains("id=\"") {
                None
            } else {
                Some(format!("<{}", trimmed))
            }
        })
        .collect()
}

fn find_semantic_id_by_name(xml: &str, name: &str) -> Option<String> {
    let target = normalize_label(name);
    let escaped_name = escape_xml_attr_value(name);
    let mut fuzzy_match_id: Option<String> = None;

    for fragment in extract_node_fragments(xml) {
        let Some(id) = extract_xml_attribute(&fragment, "id") else {
            continue;
        };
        let name_attr = extract_xml_attribute(&fragment, "name")
            .or_else(|| extract_xml_attribute(&fragment, "value"))
            .unwrap_or_default();
        let decoded = unescape_xml_attr_value(&name_attr);
        let normalized = normalize_label(&decoded);
        if normalized == target || decoded == escaped_name {
            return Some(id);
        }
        if !normalized.is_empty()
            && (normalized.contains(&target) || target.contains(&normalized))
            && fuzzy_match_id.is_none()
        {
            fuzzy_match_id = Some(id);
        }
    }
    fuzzy_match_id
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
    if query.to_ascii_lowercase().contains("all upper case letters") {
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

fn parse_query_from_snapshot(snapshot: &str) -> String {
    let decoded = unescape_xml_attr_value(snapshot);
    if let Some(start) = decoded.find("Click on the \"") {
        return decoded[start..].to_string();
    }
    decoded
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

struct DirectHarness {
    client: BridgeClient,
    session_id: String,
    session_bytes: [u8; 32],
    exec: ToolExecutor,
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
        headless: bool,
    ) -> Result<Self> {
        let (event_tx, event_rx) = broadcast::channel(512);
        let (exec, browser) = build_executor_with_events(Some(event_tx));
        browser
            .launch(headless)
            .await
            .map_err(|err| anyhow!("launch Chromium: {}", err))?;
        Ok(Self {
            client,
            session_id,
            session_bytes: compute_session_id(seed, mode),
            exec,
            browser,
            step_index: 0,
            bridge_state,
            kernel_events: Vec::new(),
            event_rx,
            tool_steps: Vec::new(),
            oracle_steps: Vec::new(),
        })
    }

    async fn wait_for_state_change(&mut self, previous_sync_ms: Option<u64>) -> Result<BridgeState> {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let state = self.client.state(&self.session_id).await?;
            let sync_advanced = state.last_sync_ms != previous_sync_ms;
            let became_ready = state.info.task_ready.unwrap_or(false) && !state.utterance.is_empty();
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

    async fn wait_for_oracle_progress(&mut self, previous_episode_step: u32) -> Result<BridgeState> {
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
        let (tool_name, arguments) = tool_json_parts(&tool)?;
        self.step_index = self.step_index.saturating_add(1);
        let previous_sync_ms = self.bridge_state.last_sync_ms;
        let result = self
            .exec
            .execute(tool, self.session_bytes, self.step_index, [0u8; 32], None, None, None)
            .await;
        sleep(Duration::from_millis(40)).await;
        drain_events(&mut self.event_rx, &mut self.kernel_events);
        let state = self.wait_for_state_change(previous_sync_ms).await?;
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
        self.oracle_command("click_text", json!({ "text": text })).await
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

    async fn snapshot_xml(&mut self) -> Result<String> {
        let result = self.execute_tool(AgentTool::BrowserSnapshot {}).await?;
        if result.success {
            result
                .history_entry
                .ok_or_else(|| anyhow!("browser__snapshot returned no XML"))
        } else {
            Err(anyhow!(
                "browser__snapshot failed: {}",
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
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

    async fn click_element_by_id(&mut self, id: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserClickElement { id: id.to_string() })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__click_element '{}' failed: {}",
                id,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn click_element_by_label(&mut self, snapshot: &str, label: &str) -> Result<()> {
        let id = find_semantic_id_by_name(snapshot, label)
            .ok_or_else(|| anyhow!("could not find semantic id for '{}'", label))?;
        self.click_element_by_id(&id).await
    }

    async fn click_bridge_label(&mut self, label: &str) -> Result<()> {
        let state = self.refresh_bridge_state().await?;
        let selector = bridge_selector_for_label(&state.info.interactive_elements, label)
            .ok_or_else(|| anyhow!("could not find selector for '{}'", label))?;
        self.click_selector(&selector).await
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

    async fn press_key(&mut self, key: &str) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserKey {
                key: key.to_string(),
            })
            .await?;
        if result.success {
            Ok(())
        } else {
            Err(anyhow!(
                "browser__key '{}' failed: {}",
                key,
                result.error.unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    async fn wait_ms(&mut self, ms: u64) -> Result<()> {
        let result = self
            .execute_tool(AgentTool::BrowserWait {
                ms: Some(ms),
                condition: None,
                selector: None,
                query: None,
                scope: None,
                timeout_ms: None,
            })
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

    async fn stop(mut self) {
        self.browser.stop().await;
        drain_events(&mut self.event_rx, &mut self.kernel_events);
    }
}

async fn scroll_textarea_with_browser_tools(
    harness: &mut DirectHarness,
    go_bottom: bool,
) -> Result<()> {
    let selector = scroll_target_selector(&harness.bridge_state.info.scroll_targets, "text-area")
        .unwrap_or_else(|| "#text-area".to_string());
    let key = if go_bottom { "PageDown" } else { "PageUp" };

    for _ in 0..12 {
        let state = harness.refresh_bridge_state().await?;
        if let Some(target) = scroll_target_by_id(&state.info.scroll_targets, "text-area") {
            if scroll_target_reached(target, go_bottom) {
                return Ok(());
            }
        }
        if !bridge_focus_matches(&state, &selector) {
            harness.click_selector(&selector).await?;
        } else {
            harness.press_key(key).await?;
            harness.wait_ms(80).await?;
        }
    }

    Ok(())
}

fn autocomplete_candidate(
    elements: &[BridgeInteractiveElement],
    prefix: &str,
    suffix: Option<&str>,
) -> Option<String> {
    let normalized_prefix = prefix.to_ascii_lowercase();
    let normalized_suffix = suffix.map(|value| value.to_ascii_lowercase());
    elements
        .iter()
        .filter(|element| element.visible)
        .map(|element| element.text.trim())
        .filter(|text| !text.is_empty())
        .find(|text| {
            let normalized = text.to_ascii_lowercase();
            normalized.starts_with(&normalized_prefix)
                && normalized_suffix
                    .as_ref()
                    .map(|suffix| normalized.ends_with(suffix))
                    .unwrap_or(true)
        })
        .map(str::to_string)
}

fn bridge_element_display_text(element: &BridgeInteractiveElement) -> String {
    if !element.text.trim().is_empty() {
        element.text.trim().to_string()
    } else {
        element.value.clone().unwrap_or_default()
    }
}

fn bridge_selector_for_label(
    elements: &[BridgeInteractiveElement],
    label: &str,
) -> Option<String> {
    let target = normalize_label(label);
    let mut fuzzy_match = None;

    for element in elements
        .iter()
        .filter(|element| element.visible && !element.disabled)
    {
        let Some(selector) = element.selector.clone() else {
            continue;
        };
        let normalized = normalize_label(&bridge_element_display_text(element));
        if normalized == target {
            return Some(selector);
        }
        if fuzzy_match.is_none()
            && !normalized.is_empty()
            && (normalized.contains(&target) || target.contains(&normalized))
        {
            fuzzy_match = Some(selector);
        }
    }

    fuzzy_match
}

fn bridge_selector_for_autocomplete_candidate(
    elements: &[BridgeInteractiveElement],
    prefix: &str,
    suffix: Option<&str>,
) -> Option<String> {
    let normalized_prefix = prefix.to_ascii_lowercase();
    let normalized_suffix = suffix.map(|value| value.to_ascii_lowercase());

    elements
        .iter()
        .filter(|element| element.visible && !element.disabled)
        .filter_map(|element| {
            let selector = element.selector.clone()?;
            let text = bridge_element_display_text(element);
            let normalized = text.to_ascii_lowercase();
            if normalized.starts_with(&normalized_prefix)
                && normalized_suffix
                    .as_ref()
                    .map(|suffix| normalized.ends_with(suffix))
                    .unwrap_or(true)
            {
                Some(selector)
            } else {
                None
            }
        })
        .next()
}

fn bridge_element_by_selector<'a>(
    elements: &'a [BridgeInteractiveElement],
    selector: &str,
) -> Option<&'a BridgeInteractiveElement> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
}

fn bridge_click_point_by_selector(
    elements: &[BridgeInteractiveElement],
    selector: &str,
) -> Option<(i32, i32)> {
    bridge_element_by_selector(elements, selector).and_then(|element| {
        Some((element.center_x?, element.center_y?))
    })
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

fn bridge_focus_matches(bridge_state: &BridgeState, selector: &str) -> bool {
    match selector {
        "#tt" => bridge_state.info.focused_id.as_deref() == Some("tt"),
        "#tt1" => bridge_state.info.focused_id.as_deref() == Some("tt1"),
        "#tt2" => bridge_state.info.focused_id.as_deref() == Some("tt2"),
        "#tt3" => bridge_state.info.focused_id.as_deref() == Some("tt3"),
        "#tags" => bridge_state.info.focused_id.as_deref() == Some("tags"),
        "#text-area" => bridge_state.info.focused_id.as_deref() == Some("text-area"),
        _ => false,
    }
}

fn scroll_target_by_id<'a>(
    targets: &'a [BridgeScrollTarget],
    id: &str,
) -> Option<&'a BridgeScrollTarget> {
    targets.iter().find(|target| target.id.as_deref() == Some(id))
}

fn scroll_target_selector(targets: &[BridgeScrollTarget], id: &str) -> Option<String> {
    targets.iter().find_map(|target| {
        if target.id.as_deref() == Some(id) {
            target.selector.clone().or_else(|| target.id.as_ref().map(|id| format!("#{id}")))
        } else {
            None
        }
    })
}

fn scroll_target_click_point(targets: &[BridgeScrollTarget], id: &str) -> Option<(i32, i32)> {
    targets.iter().find_map(|target| {
        if target.id.as_deref() == Some(id) {
            Some((target.center_x?, target.center_y?))
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
            let number = parse_tab_number(&query).ok_or_else(|| anyhow!("oracle click-tab"))?;
            harness
                .oracle_click_selector(&format!("a[href='#tabs-{}']", number))
                .await?;
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
            let label = parse_submit_target(&query).ok_or_else(|| anyhow!("oracle click-option"))?;
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
            let username = quoted.first().cloned().ok_or_else(|| anyhow!("oracle login-user"))?;
            let password = quoted.get(1).cloned().ok_or_else(|| anyhow!("oracle login-user"))?;
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
            let search_term = quoted.first().cloned().ok_or_else(|| anyhow!("oracle search"))?;
            let position =
                parse_search_result_position(&query).ok_or_else(|| anyhow!("oracle search"))?;
            let page = ((position - 1) / 3) + 1;
            let local_index = ((position - 1) % 3) + 1;
            harness.oracle_type_text("#search-text", &search_term).await?;
            harness.oracle_click_selector("#search").await?;
            if page > 1 {
                harness.oracle_click_text(&page.to_string()).await?;
            }
            harness
                .oracle_click_selector(&format!("#page-content a:nth-of-type({})", local_index))
                .await?;
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
            let number = parse_tab_number(&query).ok_or_else(|| anyhow!("runtime click-tab"))?;
            harness
                .click_selector(&format!("a[href='#tabs-{}']", number))
                .await?;
        }
        RecipeId::UseAutocomplete => {
            let target = infer_autocomplete_target(&query)
                .ok_or_else(|| anyhow!("runtime autocomplete target not found"))?;
            harness.type_text("#tags", &target).await?;
            harness.press_key("Escape").await?;
            harness.wait_ms(80).await?;
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
            let username = quoted.first().cloned().ok_or_else(|| anyhow!("runtime login-user"))?;
            let password = quoted.get(1).cloned().ok_or_else(|| anyhow!("runtime login-user"))?;
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
            for index in 1..=3 {
                let state = harness.refresh_bridge_state().await?;
                if bridge_selector_for_label(&state.info.interactive_elements, &target).is_some() {
                    break;
                }
                harness
                    .click_selector(&format!("#area h3:nth-of-type({})", index))
                    .await?;
            }
            harness.click_bridge_label(&target).await?;
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
            harness
                .click_selector(&format!("#page-content a:nth-of-type({})", local_index))
                .await?;
        }
    }

    Ok(())
}

fn extract_history_block(system_prompt: &str) -> String {
    let Some(start) = system_prompt.find("HISTORY:\n") else {
        return String::new();
    };
    let rest = &system_prompt[start + "HISTORY:\n".len()..];
    let end_markers = ["\n=== LAYER 3:", "\n\n=== LAYER 3:"];
    let mut end = rest.len();
    for marker in end_markers {
        if let Some(idx) = rest.find(marker) {
            end = end.min(idx);
        }
    }
    rest[..end].to_string()
}

#[derive(Debug)]
struct HistoryMessage {
    role: String,
    content: String,
}

fn parse_history_messages(system_prompt: &str) -> Vec<HistoryMessage> {
    let block = extract_history_block(system_prompt);
    let mut messages = Vec::new();
    let mut current_role: Option<String> = None;
    let mut current_content = String::new();

    for line in block.lines() {
        let parsed_role = if let Some(rest) = line.strip_prefix("user: ") {
            Some(("user", rest))
        } else if let Some(rest) = line.strip_prefix("tool: ") {
            Some(("tool", rest))
        } else if let Some(rest) = line.strip_prefix("assistant: ") {
            Some(("assistant", rest))
        } else {
            None
        };

        if let Some((role, rest)) = parsed_role {
            if let Some(existing_role) = current_role.take() {
                messages.push(HistoryMessage {
                    role: existing_role,
                    content: current_content.trim().to_string(),
                });
                current_content.clear();
            }
            current_role = Some(role.to_string());
            current_content.push_str(rest);
        } else if !current_content.is_empty() {
            current_content.push('\n');
            current_content.push_str(line);
        }
    }

    if let Some(role) = current_role {
        messages.push(HistoryMessage {
            role,
            content: current_content.trim().to_string(),
        });
    }

    messages
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

fn pick_incident_recovery_tool(
    system_prompt: &str,
    candidates: &[(&str, Value)],
) -> Option<Vec<u8>> {
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
        Some(inference_tool_call(name, arguments.clone()))
    })
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

fn history_tool_outputs(system_prompt: &str) -> Vec<String> {
    parse_history_messages(system_prompt)
        .into_iter()
        .filter(|message| message.role == "tool")
        .map(|message| message.content)
        .collect()
}

fn latest_snapshot_output(tool_outputs: &[String]) -> Option<String> {
    tool_outputs
        .iter()
        .rev()
        .find(|entry| entry.contains("id=\"") || entry.contains("snapshot_fallback_cause"))
        .cloned()
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

struct MiniwobAgentRuntime {
    case: ComputerUseCase,
    client: BridgeClient,
    session_id: String,
    url: String,
    last_scroll_action: Mutex<Option<String>>,
}

impl MiniwobAgentRuntime {
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
                if let Some(target) = scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
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
                }
                let candidates = match root_tool {
                    "browser__key" => vec![
                        ("browser__type", json!({ "selector": "#text-area", "text": "" })),
                        ("browser__click", json!({ "selector": "#text-area" })),
                        ("browser__scroll", json!({ "delta_x": 0, "delta_y": 40 })),
                        ("browser__scroll", json!({ "delta_x": 0, "delta_y": -40 })),
                        ("browser__snapshot", json!({})),
                    ],
                    "browser__type" => vec![
                        ("browser__click", json!({ "selector": "#text-area" })),
                        ("browser__scroll", json!({ "delta_x": 0, "delta_y": 40 })),
                        ("browser__snapshot", json!({})),
                    ],
                    "browser__click" => vec![
                        ("browser__type", json!({ "selector": "#text-area", "text": "" })),
                        ("browser__scroll", json!({ "delta_x": 0, "delta_y": 40 })),
                        ("browser__snapshot", json!({})),
                    ],
                    _ => vec![
                        ("browser__snapshot", json!({})),
                        ("browser__click", json!({ "selector": "#text-area" })),
                        ("browser__type", json!({ "selector": "#text-area", "text": "" })),
                        ("browser__scroll", json!({ "delta_x": 0, "delta_y": 40 })),
                    ],
                };
                pick_incident_recovery_tool(system_prompt, &candidates)
                    .unwrap_or_else(|| inference_tool_call("browser__snapshot", json!({})))
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
                pick_incident_recovery_tool(system_prompt, &candidates)
                    .unwrap_or_else(|| inference_tool_call("browser__snapshot", json!({})))
            }
            RecipeId::UseAutocomplete => {
                let target = bridge_value_by_selector(&bridge_state.info.interactive_elements, "#tags");
                if target.is_empty() {
                    inference_tool_call("browser__click", json!({ "selector": "#tags" }))
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                }
            }
            _ => pick_incident_recovery_tool(
                system_prompt,
                &[
                    ("browser__snapshot", json!({})),
                    ("browser__click", json!({ "selector": "button" })),
                    ("browser__click", json!({ "selector": "#subbtn" })),
                ],
            )
            .unwrap_or_else(|| inference_tool_call("browser__snapshot", json!({}))),
        }
    }

    fn next_action(&self, bridge_state: &BridgeState) -> Vec<u8> {
        if !bridge_state.info.task_ready.unwrap_or(false) || bridge_state.utterance.is_empty() {
            return inference_tool_call("browser__navigate", json!({ "url": self.url }));
        }
        if bridge_state.terminated
            || bridge_state
                .info
                .raw_reward
                .unwrap_or(bridge_state.reward)
                >= self.case.expected_reward_floor
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

        let click_label = |label: &str| {
            bridge_selector_for_label(elements, label)
                .map(|selector| inference_tool_call("browser__click", json!({ "selector": selector })))
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
                let number = parse_tab_number(&query).unwrap_or(1);
                inference_tool_call(
                    "browser__click",
                    json!({ "selector": format!("a[href='#tabs-{}']", number) }),
                )
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
                let selector = scroll_target_selector(&bridge_state.info.scroll_targets, "text-area")
                    .unwrap_or_else(|| "#text-area".to_string());
                let key = if go_bottom { "PageDown" } else { "PageUp" };
                if let Some(target) = scroll_target_by_id(&bridge_state.info.scroll_targets, "text-area")
                {
                    if scroll_target_reached(target, go_bottom) {
                        self.note_scroll_action("submit");
                        inference_tool_call("browser__click", json!({ "selector": "#subbtn" }))
                    } else if !bridge_focus_matches(bridge_state, &selector) {
                        self.note_scroll_action("focus");
                        inference_tool_call("browser__click", json!({ "selector": selector }))
                    } else if self.last_scroll_action().as_deref() == Some("key") {
                        self.note_scroll_action("wait");
                        inference_wait(80)
                    } else {
                        self.note_scroll_action("key");
                        inference_tool_call("browser__key", json!({ "key": key }))
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
                if stage < targets.len() {
                    let label = targets[stage].clone();
                    click_label(&label).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound checkbox target missing")
                    })
                } else {
                    inference_tool_call("browser__click", json!({ "selector": "button" }))
                }
            }
            RecipeId::EnterPassword => match stage {
                0 => {
                    let password = quoted_values(&query).into_iter().next().unwrap_or_default();
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#password", "text": password }),
                    )
                }
                1 => {
                    let password = quoted_values(&query).into_iter().next().unwrap_or_default();
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#verify", "text": password }),
                    )
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
            },
            RecipeId::LoginUser => match stage {
                0 => {
                    let quoted = quoted_values(&query);
                    let username = quoted.first().cloned().unwrap_or_default();
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#username", "text": username }),
                    )
                }
                1 => {
                    let quoted = quoted_values(&query);
                    let password = quoted.get(1).cloned().unwrap_or_default();
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#password", "text": password }),
                    )
                }
                _ => inference_tool_call("browser__click", json!({ "selector": "#subbtn" })),
            },
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
                    inference_tool_call(
                        "browser__type",
                        json!({ "selector": "#tt", "text": text }),
                    )
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
                } else {
                    match stage {
                        0 => inference_tool_call(
                            "browser__click",
                            json!({ "selector": "#area h3:nth-of-type(1)" }),
                        ),
                        1 => inference_tool_call(
                            "browser__click",
                            json!({ "selector": "#area h3:nth-of-type(2)" }),
                        ),
                        _ => inference_tool_call(
                            "browser__click",
                            json!({ "selector": "#area h3:nth-of-type(3)" }),
                        ),
                    }
                }
            }
            RecipeId::SearchEngine => {
                let position = parse_search_result_position(&query).unwrap_or(1);
                let page = ((position - 1) / 3) + 1;
                let local_index = ((position - 1) % 3) + 1;
                match stage {
                    0 => {
                        let search_term =
                            quoted_values(&query).into_iter().next().unwrap_or_default();
                        inference_tool_call(
                            "browser__type",
                            json!({ "selector": "#search-text", "text": search_term }),
                        )
                    }
                    1 => inference_tool_call("browser__click", json!({ "selector": "#search" })),
                    2 if page > 1 => click_label(&page.to_string()).unwrap_or_else(|| {
                        inference_fail("ERROR_CLASS=TargetNotFound pagination target missing")
                    }),
                    _ => inference_tool_call(
                        "browser__click",
                        json!({ "selector": format!("#page-content a:nth-of-type({})", local_index) }),
                    ),
                }
            }
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
            let debug_path = std::env::temp_dir().join(format!(
                "computer_use_suite_{}_prompt.json",
                self.case.id
            ));
            let _ = fs::write(&debug_path, input_context);
        }
        let system_prompt = extract_system_prompt(input_context);
        let bridge_state = self
            .client
            .state(&self.session_id)
            .await
            .map_err(|err| VmError::HostError(format!("bridge state: {}", err)))?;
        if is_incident_recovery_prompt(&system_prompt) {
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
) -> Result<ComputerUseCaseResult> {
    let created = client.create_session(case).await?;
    let headless = headless_for_run(config)?;
    let mut harness = DirectHarness::new(
        client.clone(),
        created.session_id.clone(),
        created.state,
        mode,
        case.seed,
        headless,
    )
    .await?;

    let started = Instant::now();
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

    let execution_result = match mode {
        ComputerUseMode::Oracle => run_oracle_recipe(&mut harness, case).await,
        ComputerUseMode::Runtime => run_runtime_recipe(&mut harness, case).await,
        ComputerUseMode::Agent => Err(anyhow!("agent mode must use run_agent_case")),
    };

    let mut failure_class = execution_result
        .as_ref()
        .err()
        .and_then(|err| extract_error_class(&err.to_string()));
    let final_state = harness.client.state(&harness.session_id).await?;
    let screenshot_path = artifact_root.join("final.png");
    let bridge_state_path = artifact_root.join("bridge_state.json");
    let kernel_events_path = artifact_root.join("kernel_events.json");
    let should_capture_artifacts =
        config.retain_artifacts_for_all_runs || execution_result.is_err() || !final_state.terminated;
    if should_capture_artifacts {
        let _ = harness.capture_screenshot(&screenshot_path).await;
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
        case_id: case.id.to_string(),
        env_id: case.env_id.to_string(),
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
    };
    harness.client.close(&harness.session_id).await?;
    harness.stop().await;
    Ok(result)
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
        last_scroll_action: Mutex::new(None),
    });
    let (scs, _scs_tmp_dir) = build_scs(&format!("computer_use_suite_{}.scs", case.id))?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        terminal,
        browser.clone(),
        runtime.clone(),
        runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx)
    .with_os_driver(Arc::new(StaticOsDriver));

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
            || live_bridge_state
                .info
                .raw_reward
                .unwrap_or(live_bridge_state.reward)
                >= case.expected_reward_floor
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
    let should_capture_artifacts =
        config.retain_artifacts_for_all_runs || !bridge_state.terminated || bridge_state.reward < case.expected_reward_floor;
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

    let mut tool_steps = Vec::new();
    let mut executed_tools = Vec::new();
    let mut routing_receipt_count = 0usize;
    let mut intent_receipt_count = 0usize;
    let mut execution_contract_receipt_count = 0usize;
    let mut workload_receipt_count = 0usize;
    let mut workload_activity_count = 0usize;
    let mut failure_class = None;
    for event in &kernel_events {
        match event {
            KernelEvent::AgentActionResult {
                step_index,
                tool_name,
                output,
                error_class,
                ..
            } => {
                executed_tools.push(tool_name.clone());
                if failure_class.is_none() {
                    failure_class = error_class.clone();
                }
                tool_steps.push(ToolStepRecord {
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
            KernelEvent::RoutingReceipt(_) => routing_receipt_count = routing_receipt_count.saturating_add(1),
            KernelEvent::IntentResolutionReceipt(_) => {
                intent_receipt_count = intent_receipt_count.saturating_add(1)
            }
            KernelEvent::ExecutionContractReceipt(_) => {
                execution_contract_receipt_count =
                    execution_contract_receipt_count.saturating_add(1)
            }
            KernelEvent::WorkloadReceipt(receipt) => {
                workload_receipt_count = workload_receipt_count.saturating_add(1);
                if failure_class.is_none() {
                    failure_class = match &receipt.receipt {
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
                workload_activity_count = workload_activity_count.saturating_add(1)
            }
            _ => {}
        }
    }

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
        case_id: case.id.to_string(),
        env_id: case.env_id.to_string(),
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
    })
}

pub async fn run_mode(
    config: &SuiteConfig,
    mode: ComputerUseMode,
    cases: &[ComputerUseCase],
) -> Result<ModeRunReport> {
    let mut bridge = BridgeProcess::start(config).await?;
    let mut results = Vec::new();
    for case in cases {
        let case_root = config
            .artifact_root
            .join(mode.as_str())
            .join(case.id.to_string());
        fs::create_dir_all(&case_root)?;
        let result = match mode {
            ComputerUseMode::Oracle | ComputerUseMode::Runtime => {
                run_direct_case(config, mode, bridge.client.clone(), case, case_root).await
            }
            ComputerUseMode::Agent => {
                run_agent_case(config, bridge.client.clone(), case, case_root).await
            }
        };
        match result {
            Ok(result) => results.push(result),
            Err(err) => {
                let case_artifact_root = config.artifact_root.join(mode.as_str()).join(case.id);
                let error_path = case_artifact_root.join("error.txt");
                let _ = write_text_file(&error_path, &format!("{:#}", err));
                results.push(ComputerUseCaseResult {
                    case_id: case.id.to_string(),
                    env_id: case.env_id.to_string(),
                    seed: case.seed,
                    mode,
                    task_set: case.task_set,
                    utterance: String::new(),
                    elapsed_ms: 0,
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
                        artifact_root: case_artifact_root.to_string_lossy().to_string(),
                        bridge_state_path: None,
                        kernel_events_path: None,
                        json_report_path: None,
                        markdown_summary_path: None,
                        csv_summary_path: None,
                        screenshot_paths: Vec::new(),
                        snapshot_paths: Vec::new(),
                    },
                    failure_class: Some(
                        extract_error_class(&err.to_string())
                            .unwrap_or_else(|| "harness_error".to_string()),
                    ),
                })
            }
        }
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

    let mut jsonl = String::new();
    let mut csv = String::from("case_id,env_id,mode,task_set,pass,reward,terminated,elapsed_ms,failure_class\n");
    for result in results {
        jsonl.push_str(&serde_json::to_string(result)?);
        jsonl.push('\n');
        csv.push_str(&format!(
            "{},{},{},{},{},{:.3},{},{},{}\n",
            result.case_id,
            result.env_id,
            result.mode.as_str(),
            result.task_set.as_str(),
            result.overall_pass,
            result.final_reward,
            result.terminated,
            result.elapsed_ms,
            result.failure_class.clone().unwrap_or_default()
        ));
    }

    let passing = results.iter().filter(|result| result.overall_pass).count();
    let markdown = format!(
        "# Computer Use Suite\n\n- mode: `{}`\n- task_set: `{}`\n- passing: `{}` / `{}`\n- artifact_root: `{}`\n\n| case | env | pass | reward | terminated | failure |\n| --- | --- | --- | --- | --- | --- |\n{}",
        mode.as_str(),
        task_set.as_str(),
        passing,
        results.len(),
        config.artifact_root.display(),
        results
            .iter()
            .map(|result| {
                format!(
                    "| {} | {} | {} | {:.3} | {} | {} |",
                    result.case_id,
                    result.env_id,
                    if result.overall_pass { "yes" } else { "no" },
                    result.final_reward,
                    result.terminated,
                    result.failure_class.clone().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    );

    write_text_file(&jsonl_path, &jsonl)?;
    write_text_file(&markdown_path, &markdown)?;
    write_text_file(&csv_path, &csv)?;
    Ok(())
}
