// Path: crates/services/src/agentic/desktop.rs

use image::load_from_memory;
use image_hasher::{HashAlg, HasherConfig};
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;

use ioi_types::app::agentic::{AgentSkill, InferenceOptions, LlmToolDefinition, StepTrace};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::keys::UPGRADE_ACTIVE_SERVICE_PREFIX;
use ioi_types::service_configs::ActiveServiceMeta;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::any::Any;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// [FIX] Imports: remove unused and fix paths
use crate::agentic::grounding::parse_vlm_action;
use crate::agentic::scrub_adapter::RuntimeAsSafetyModel;
use crate::agentic::scrubber::SemanticScrubber;

use ioi_api::ibc::AgentZkVerifier;
// [FIX] Use dcrypt directly for ByteSerializable trait
use dcrypt::algorithms::ByteSerializable; // Needed for copy_from_slice

const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";
const SKILL_INDEX_PREFIX: &[u8] = b"skills::vector::";
const TRACE_PREFIX: &[u8] = b"agent::trace::";

const CHARS_PER_TOKEN: u64 = 4;
// ... (rest of file unchanged)
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed(Option<String>),
    Failed(String),
    Paused(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,
    pub history: Vec<String>,
    pub status: AgentStatus,
    pub step_count: u32,
    pub max_steps: u32,
    pub last_action_type: Option<String>,
    pub parent_session_id: Option<[u8; 32]>,
    pub child_session_ids: Vec<[u8; 32]>,
    pub budget: u64,
    pub tokens_used: u64,
    pub consecutive_failures: u8,
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
    pub parent_session_id: Option<[u8; 32]>,
    pub initial_budget: u64,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
}

#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    pub session_id: [u8; 32],
}

pub struct DesktopAgentService {
    gui: Arc<dyn GuiDriver>,
    fast_inference: Arc<dyn InferenceRuntime>,
    reasoning_inference: Arc<dyn InferenceRuntime>,
    scrubber: SemanticScrubber,
    // [NEW] Optional ZK Verifier for Proof of Meaning
    zk_verifier: Option<Arc<dyn AgentZkVerifier>>,
}

impl DesktopAgentService {
    pub fn new(gui: Arc<dyn GuiDriver>, inference: Arc<dyn InferenceRuntime>) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            fast_inference: inference.clone(),
            reasoning_inference: inference,
            scrubber,
            zk_verifier: None,
        }
    }

    pub fn new_hybrid(
        gui: Arc<dyn GuiDriver>,
        fast_inference: Arc<dyn InferenceRuntime>,
        reasoning_inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(fast_inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            fast_inference,
            reasoning_inference,
            scrubber,
            zk_verifier: None,
        }
    }

    // [NEW] Builder-style setter for ZK Verifier
    pub fn with_zk_verifier(mut self, verifier: Arc<dyn AgentZkVerifier>) -> Self {
        self.zk_verifier = Some(verifier);
        self
    }

    fn get_state_key(session_id: &[u8; 32]) -> Vec<u8> {
        [AGENT_STATE_PREFIX, session_id.as_slice()].concat()
    }

    fn get_trace_key(session_id: &[u8; 32], step: u32) -> Vec<u8> {
        [TRACE_PREFIX, session_id.as_slice(), &step.to_le_bytes()].concat()
    }

    fn compute_phash(image_bytes: &[u8]) -> Result<[u8; 32], TransactionError> {
        let img = load_from_memory(image_bytes)
            .map_err(|e| TransactionError::Invalid(format!("Image decode failed: {}", e)))?;
        let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
        let hash = hasher.hash_image(&img);
        let hash_bytes = hash.as_bytes();

        let mut out = [0u8; 32];
        let len = hash_bytes.len().min(32);
        out[..len].copy_from_slice(&hash_bytes[..len]);
        Ok(out)
    }

    fn discover_tools(&self, state: &dyn StateAccess) -> Vec<LlmToolDefinition> {
        let mut tools = Vec::new();
        if let Ok(iter) = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX) {
            for item in iter {
                if let Ok((_, val_bytes)) = item {
                    if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&val_bytes) {
                        for (method, perm) in &meta.methods {
                            if *perm == ioi_types::service_configs::MethodPermission::User {
                                let simple_name = method.split('@').next().unwrap_or(method);
                                let tool_name = format!("{}__{}", meta.id, simple_name);
                                let params_json = json!({
                                    "type": "object",
                                    "properties": {
                                        "params": { "type": "string", "description": "JSON encoded parameters" }
                                    }
                                });
                                let tool_def = LlmToolDefinition {
                                    name: tool_name,
                                    description: format!(
                                        "Call method {} on service {}",
                                        simple_name, meta.id
                                    ),
                                    parameters: params_json.to_string(),
                                };
                                tools.push(tool_def);
                            }
                        }
                    }
                }
            }
        }
        let gui_params = json!({
            "type": "object",
            "properties": {
                "x": { "type": "integer" },
                "y": { "type": "integer" },
                "button": { "type": "string", "enum": ["left", "right"] }
            },
            "required": ["x", "y"]
        });
        tools.push(LlmToolDefinition {
            name: "gui__click".to_string(),
            description: "Click on UI element at coordinates".to_string(),
            parameters: gui_params.to_string(),
        });
        let delegate_params = json!({
            "type": "object",
            "properties": {
                "goal": { "type": "string" },
                "budget": { "type": "integer" }
            },
            "required": ["goal", "budget"]
        });
        tools.push(LlmToolDefinition {
            name: "agent__delegate".to_string(),
            description: "Spawn a sub-agent to handle a specific subtask.".to_string(),
            parameters: delegate_params.to_string(),
        });

        let await_params = json!({
            "type": "object",
            "properties": {
                "child_session_id_hex": { "type": "string" }
            },
            "required": ["child_session_id_hex"]
        });
        tools.push(LlmToolDefinition {
            name: "agent__await_result".to_string(),
            description:
                "Check if a child agent has completed its task. Returns 'Running' if not finished."
                    .to_string(),
            parameters: await_params.to_string(),
        });

        let pause_params = json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string" }
            },
            "required": ["reason"]
        });
        tools.push(LlmToolDefinition {
            name: "agent__pause".to_string(),
            description: "Pause execution to wait for user input or long-running tasks."
                .to_string(),
            parameters: pause_params.to_string(),
        });

        tools
    }

    async fn recall_skills(
        &self,
        state: &dyn StateAccess,
        goal: &str,
    ) -> Result<Vec<AgentSkill>, TransactionError> {
        let mut relevant_skills = Vec::new();
        let goal_lower = goal.to_lowercase();
        if let Ok(iter) = state.prefix_scan(SKILL_INDEX_PREFIX) {
            for item in iter {
                if let Ok((_, val_bytes)) = item {
                    if let Ok(skill) = codec::from_bytes_canonical::<AgentSkill>(&val_bytes) {
                        let name_lower = skill.name.to_lowercase();
                        let desc_lower = skill.description.to_lowercase();
                        if goal_lower.contains(&name_lower)
                            || name_lower.contains(&goal_lower)
                            || desc_lower.contains(&goal_lower)
                        {
                            relevant_skills.push(skill);
                        }
                    }
                }
            }
        }
        Ok(relevant_skills)
    }

    fn select_runtime(&self, state: &AgentState) -> Arc<dyn InferenceRuntime> {
        if state.consecutive_failures > 0 {
            return self.reasoning_inference.clone();
        }
        if state.step_count == 0 {
            return self.reasoning_inference.clone();
        }
        match state.last_action_type.as_deref() {
            Some("gui__click") | Some("gui__type") => self.fast_inference.clone(),
            _ => self.reasoning_inference.clone(),
        }
    }
}

#[async_trait::async_trait]
impl UpgradableService for DesktopAgentService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl BlockchainService for DesktopAgentService {
    fn id(&self) -> &str {
        "desktop_agent"
    }
    fn abi_version(&self) -> u32 {
        1
    }
    fn state_schema(&self) -> &str {
        "v1"
    }
    fn capabilities(&self) -> ioi_types::service_configs::Capabilities {
        ioi_types::service_configs::Capabilities::empty()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        _ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "start@v1" => {
                let p: StartAgentParams = codec::from_bytes_canonical(params)?;
                let key = Self::get_state_key(&p.session_id);
                if state.get(&key)?.is_some() {
                    return Err(TransactionError::Invalid("Session already exists".into()));
                }

                if let Some(parent_id) = p.parent_session_id {
                    let parent_key = Self::get_state_key(&parent_id);
                    if let Some(parent_bytes) = state.get(&parent_key)? {
                        let mut parent_state: AgentState =
                            codec::from_bytes_canonical(&parent_bytes)?;
                        if parent_state.budget < p.initial_budget {
                            return Err(TransactionError::Invalid(
                                "Insufficient parent budget".into(),
                            ));
                        }
                        parent_state.budget -= p.initial_budget;
                        parent_state.child_session_ids.push(p.session_id);
                        state.insert(&parent_key, &codec::to_bytes_canonical(&parent_state)?)?;
                    } else {
                        return Err(TransactionError::Invalid("Parent session not found".into()));
                    }
                }

                let agent_state = AgentState {
                    session_id: p.session_id,
                    goal: p.goal,
                    history: Vec::new(),
                    status: AgentStatus::Running,
                    step_count: 0,
                    max_steps: p.max_steps,
                    last_action_type: None,
                    parent_session_id: p.parent_session_id,
                    child_session_ids: Vec::new(),
                    budget: p.initial_budget,
                    consecutive_failures: 0,
                    tokens_used: 0,
                };
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                Ok(())
            }
            "resume@v1" => {
                let p: ResumeAgentParams = codec::from_bytes_canonical(params)?;
                let key = Self::get_state_key(&p.session_id);
                let bytes = state
                    .get(&key)?
                    .ok_or(TransactionError::Invalid("Session not found".into()))?;
                let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

                if let AgentStatus::Paused(_) = agent_state.status {
                    agent_state.status = AgentStatus::Running;
                    agent_state
                        .history
                        .push("System: Resumed by user/controller.".to_string());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    Ok(())
                } else {
                    Err(TransactionError::Invalid("Agent is not paused".into()))
                }
            }
            "step@v1" => {
                let p: StepAgentParams = codec::from_bytes_canonical(params)?;
                let key = Self::get_state_key(&p.session_id);
                let bytes = state
                    .get(&key)?
                    .ok_or(TransactionError::Invalid("Session not found".into()))?;
                let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

                match agent_state.status {
                    AgentStatus::Running => {}
                    AgentStatus::Paused(ref r) => {
                        return Err(TransactionError::Invalid(format!("Agent is paused: {}", r)))
                    }
                    _ => return Err(TransactionError::Invalid("Agent not running".into())),
                }

                if agent_state.budget == 0 {
                    agent_state.status = AgentStatus::Failed("Budget Exhausted".into());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    return Err(TransactionError::Invalid("Budget Exhausted".into()));
                }

                if agent_state.consecutive_failures >= 3 {
                    agent_state.status =
                        AgentStatus::Failed("Too many consecutive failures".into());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    return Ok(());
                }

                let observation_intent = ActionRequest {
                    target: ActionTarget::GuiScreenshot,
                    params: agent_state.goal.as_bytes().to_vec(),
                    context: ActionContext {
                        agent_id: "desktop_agent".to_string(),
                        session_id: Some(p.session_id),
                        window_id: None,
                    },
                    nonce: agent_state.step_count as u64,
                };

                let context_slice = self
                    .gui
                    .capture_context(&observation_intent)
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!("Substrate access failed: {}", e))
                    })?;
                let tree_xml = String::from_utf8_lossy(&context_slice.data);

                let screenshot_bytes = self.gui.capture_screen().await.map_err(|e| {
                    TransactionError::Invalid(format!("Visual capture failed: {}", e))
                })?;
                let visual_hash_arr = Self::compute_phash(&screenshot_bytes)?;

                let available_tools = self.discover_tools(state);
                let skills = self.recall_skills(state, &agent_state.goal).await?;
                let mut skills_prompt = String::new();
                if !skills.is_empty() {
                    skills_prompt.push_str("\n### Relevant Agent Skills\n");
                    for skill in skills {
                        skills_prompt.push_str(&format!(
                            "\n#### Skill: {}\n{}\n",
                            skill.name, skill.content
                        ));
                    }
                }

                let mut recovery_guidance = String::new();
                if agent_state.consecutive_failures > 0 {
                    if let Some(last_msg) = agent_state.history.last() {
                        recovery_guidance = format!(
                            "\n⚠️ WARNING: Previous action FAILED: {}\nAnalyze error and retry.",
                            last_msg
                        );
                    }
                }

                let raw_user_prompt = format!(
                    "Goal: {}\n\n{}{}\n\nHistory: {:?}\n{}{}\nContext: {}",
                    agent_state.goal,
                    skills_prompt,
                    "Available Tools: ...",
                    agent_state.history,
                    recovery_guidance,
                    if agent_state.consecutive_failures > 0 {
                        "MODE: RECOVERY"
                    } else {
                        ""
                    },
                    tree_xml
                );

                // [FIX] Explicit type for user_prompt to satisfy E0282
                let (scrubbed_prompt, _redaction_map) =
                    self.scrubber.scrub(&raw_user_prompt).await.map_err(|e| {
                        TransactionError::Invalid(format!("Scrubbing failed: {}", e))
                    })?;
                let user_prompt: String = scrubbed_prompt; // Explicit type

                let estimated_input_tokens = (user_prompt.len() as u64) / CHARS_PER_TOKEN;

                let model_hash = [0u8; 32];
                let options = InferenceOptions {
                    tools: available_tools,
                    temperature: if agent_state.consecutive_failures > 0 {
                        0.5
                    } else {
                        0.0
                    },
                };

                let runtime = self.select_runtime(&agent_state);

                let output_bytes = runtime
                    .execute_inference(model_hash, user_prompt.as_bytes(), options)
                    .await
                    .map_err(|e| TransactionError::Invalid(format!("Inference error: {}", e)))?;

                let output_str = String::from_utf8_lossy(&output_bytes).to_string();

                let estimated_output_tokens = (output_str.len() as u64) / CHARS_PER_TOKEN;
                let total_cost = estimated_input_tokens + estimated_output_tokens;

                agent_state.tokens_used += total_cost;
                if agent_state.budget >= total_cost {
                    agent_state.budget -= total_cost;
                } else {
                    agent_state.budget = 0;
                    agent_state.status = AgentStatus::Failed("Budget Exhausted during step".into());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    return Err(TransactionError::Invalid(
                        "Budget exhausted during inference".into(),
                    ));
                }

                agent_state.history.push(format!("Action: {}", output_str));

                let mut action_success = false;
                let mut action_error = None;
                let mut action_type = "unknown".to_string();

                let execute_click = |x: u32, y: u32| {
                    self.gui.inject_input(InputEvent::Click {
                        button: ioi_api::vm::drivers::gui::MouseButton::Left,
                        x,
                        y,
                        expected_visual_hash: Some(visual_hash_arr),
                    })
                };

                if let Ok(tool_call) = serde_json::from_str::<Value>(&output_str) {
                    if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                        action_type = name.to_string();
                        if name == "agent__delegate" {
                            let goal = tool_call["arguments"]["goal"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            let budget = tool_call["arguments"]["budget"].as_u64().unwrap_or(0);

                            let mut seed = p.session_id.to_vec();
                            seed.extend_from_slice(&agent_state.step_count.to_le_bytes());
                            let child_id_vec = ioi_crypto::algorithms::hash::sha256(&seed)
                                .unwrap()
                                .to_vec();
                            let mut child_id = [0u8; 32];
                            child_id.copy_from_slice(&child_id_vec);

                            let child_params = StartAgentParams {
                                session_id: child_id,
                                goal: goal.clone(),
                                max_steps: 10,
                                parent_session_id: Some(p.session_id),
                                initial_budget: budget,
                            };
                            let params_bytes = codec::to_bytes_canonical(&child_params).unwrap();

                            match self
                                .handle_service_call(state, "start@v1", &params_bytes, _ctx)
                                .await
                            {
                                Ok(_) => action_success = true,
                                Err(e) => action_error = Some(format!("Delegation failed: {}", e)),
                            }
                        } else if name == "agent__await_result" {
                            if let Some(hex_id) =
                                tool_call["arguments"]["child_session_id_hex"].as_str()
                            {
                                if let Ok(child_id_vec) = hex::decode(hex_id) {
                                    let mut child_id = [0u8; 32];
                                    if child_id_vec.len() == 32 {
                                        child_id.copy_from_slice(&child_id_vec);
                                        let child_key = Self::get_state_key(&child_id);

                                        if let Some(child_bytes) = state.get(&child_key)? {
                                            let child_state: AgentState =
                                                codec::from_bytes_canonical(&child_bytes)?;
                                            match child_state.status {
                                                AgentStatus::Completed(res) => {
                                                    action_success = true;
                                                    let res_str = res.unwrap_or_default();
                                                    agent_state
                                                        .history
                                                        .push(format!("Child Result: {}", res_str));
                                                }
                                                AgentStatus::Failed(err) => {
                                                    action_success = false;
                                                    action_error =
                                                        Some(format!("Child failed: {}", err));
                                                }
                                                _ => {
                                                    action_success = true;
                                                    agent_state.history.push(
                                                        "Child is still running.".to_string(),
                                                    );
                                                }
                                            }
                                        } else {
                                            action_error = Some("Child session not found".into());
                                        }
                                    } else {
                                        action_error = Some("Invalid child ID length".into());
                                    }
                                } else {
                                    action_error = Some("Invalid hex ID".into());
                                }
                            }
                        } else if name == "agent__pause" {
                            let reason = tool_call["arguments"]["reason"]
                                .as_str()
                                .unwrap_or("Paused")
                                .to_string();
                            agent_state.status = AgentStatus::Paused(reason);
                            action_success = true;
                        } else if name == "gui__click" {
                            let x = tool_call["arguments"]["x"].as_u64().unwrap_or(0) as u32;
                            let y = tool_call["arguments"]["y"].as_u64().unwrap_or(0) as u32;
                            match execute_click(x, y).await {
                                Ok(_) => action_success = true,
                                Err(e) => action_error = Some(e.to_string()),
                            }
                        }
                    }
                } else if let Some(req) = parse_vlm_action(
                    &output_str,
                    1920,
                    1080,
                    "desktop-agent".into(),
                    Some(p.session_id),
                    agent_state.step_count as u64,
                    Some(visual_hash_arr),
                ) {
                    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();
                    if req.target == ioi_types::app::ActionTarget::GuiClick {
                        action_type = "gui__click".to_string();
                        let x = params["x"].as_u64().unwrap_or(0) as u32;
                        let y = params["y"].as_u64().unwrap_or(0) as u32;
                        match execute_click(x, y).await {
                            Ok(_) => action_success = true,
                            Err(e) => action_error = Some(e.to_string()),
                        }
                    }
                }

                // If ZK Verifier is present, verify the inference
                if let Some(verifier) = &self.zk_verifier {
                    // Construct a mock proof (hash of inputs)
                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(user_prompt.as_bytes());
                    preimage.extend_from_slice(&output_bytes);
                    preimage.extend_from_slice(&model_hash);
                    let proof_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();

                    // Call the verifier
                    let valid = verifier
                        .verify_inference(
                            proof_hash.as_ref(), // Mock proof
                            model_hash,
                            user_prompt.as_bytes(),
                            &output_bytes,
                        )
                        .await
                        .map_err(|e| {
                            TransactionError::Invalid(format!("ZK Verification error: {}", e))
                        })?;

                    if !valid {
                        return Err(TransactionError::Invalid(
                            "ZK Proof of Inference Invalid".into(),
                        ));
                    }
                }

                let trace = StepTrace {
                    session_id: p.session_id,
                    step_index: agent_state.step_count,
                    visual_hash: visual_hash_arr,
                    full_prompt: user_prompt,
                    raw_output: output_str.clone(),
                    success: action_success,
                    error: action_error.clone(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };
                let trace_key = Self::get_trace_key(&p.session_id, agent_state.step_count);
                state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

                if let Some(e) = action_error {
                    agent_state.consecutive_failures += 1;
                    agent_state
                        .history
                        .push(format!("Action: {} -> FAILED: {}", output_str, e));
                } else {
                    agent_state.consecutive_failures = 0;
                    if !agent_state
                        .history
                        .last()
                        .map_or(false, |h| h.starts_with("Action:"))
                    {
                        agent_state.history.push(format!("Action: {}", output_str));
                    }
                }

                agent_state.step_count += 1;
                agent_state.last_action_type = Some(action_type);
                if agent_state.step_count >= agent_state.max_steps {
                    agent_state.status = AgentStatus::Completed(None);
                }

                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}
