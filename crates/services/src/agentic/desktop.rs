// Path: crates/services/src/agentic/desktop.rs

use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
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

use crate::agentic::grounding::parse_vlm_action;

const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";
const SKILL_INDEX_PREFIX: &[u8] = b"skills::vector::";
const TRACE_PREFIX: &[u8] = b"agent::trace::";

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,
    pub history: Vec<String>,
    pub status: AgentStatus,
    pub step_count: u32,
    pub max_steps: u32,
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
}

pub struct DesktopAgentService {
    gui: Arc<dyn GuiDriver>,
    inference: Arc<dyn InferenceRuntime>,
}

impl DesktopAgentService {
    pub fn new(gui: Arc<dyn GuiDriver>, inference: Arc<dyn InferenceRuntime>) -> Self {
        Self { gui, inference }
    }

    fn get_state_key(session_id: &[u8; 32]) -> Vec<u8> {
        [AGENT_STATE_PREFIX, session_id.as_slice()].concat()
    }

    fn get_trace_key(session_id: &[u8; 32], step: u32) -> Vec<u8> {
        [TRACE_PREFIX, session_id.as_slice(), &step.to_le_bytes()].concat()
    }

    /// Dynamically discovers all active services and projects them as LLM tools.
    fn discover_tools(&self, state: &dyn StateAccess) -> Vec<LlmToolDefinition> {
        let mut tools = Vec::new();

        // Scan for all active services
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

        // Add native GUI tools (Drivers)
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

        tools
    }

    /// Simulates semantic search over the Substrate's Skill Index.
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

                        // [FIX] Improved keyword matching for MVP
                        // Match if:
                        // 1. Goal contains Skill Name (Explicit invocation)
                        // 2. Skill Name contains Goal (Keyword search)
                        // 3. Skill Description contains Goal (Keyword search)
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

                let agent_state = AgentState {
                    session_id: p.session_id,
                    goal: p.goal,
                    history: Vec::new(),
                    status: AgentStatus::Running,
                    step_count: 0,
                    max_steps: p.max_steps,
                };

                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                Ok(())
            }
            "step@v1" => {
                let p: StepAgentParams = codec::from_bytes_canonical(params)?;
                let key = Self::get_state_key(&p.session_id);
                let bytes = state
                    .get(&key)?
                    .ok_or(TransactionError::Invalid("Session not found".into()))?;
                let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

                if agent_state.status != AgentStatus::Running {
                    return Err(TransactionError::Invalid("Agent not running".into()));
                }

                // 1. OBSERVE (via The Substrate)
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

                let visual_hash = sha256(&context_slice.data)
                    .map_err(|e| TransactionError::Invalid(format!("Hashing failed: {}", e)))?;
                let mut visual_hash_arr = [0u8; 32];
                visual_hash_arr.copy_from_slice(visual_hash.as_ref());

                // 2. DISCOVER TOOLS (Capabilities)
                let available_tools = self.discover_tools(state);

                // 3. RECALL SKILLS (Procedural Memory)
                let skills = self.recall_skills(state, &agent_state.goal).await?;

                let mut skills_prompt = String::new();
                if !skills.is_empty() {
                    skills_prompt.push_str("\n### Relevant Agent Skills (Procedural Memory)\n");
                    skills_prompt.push_str("Use these patterns to complete the task:\n");
                    for skill in skills {
                        skills_prompt.push_str(&format!(
                            "\n#### Skill: {}\nDescription: {}\nInstructions:\n{}\n",
                            skill.name, skill.description, skill.content
                        ));
                    }
                }

                // 4. ORIENT & DECIDE
                let user_prompt = format!(
                    "Goal: {}\n\n{}{}\n\nHistory: {:?}\nScreen: [IMAGE]\nThe Substrate Context: {}",
                    agent_state.goal,
                    skills_prompt,
                    "Available Tools: (See tool definitions)",
                    agent_state.history,
                    tree_xml
                );

                let model_hash = [0u8; 32];
                let options = InferenceOptions {
                    tools: available_tools,
                    temperature: 0.0,
                };

                let output_bytes = self
                    .inference
                    .execute_inference(model_hash, user_prompt.as_bytes(), options)
                    .await
                    .map_err(|e| TransactionError::Invalid(format!("Inference error: {}", e)))?;

                let output_str = String::from_utf8_lossy(&output_bytes).to_string();
                agent_state.history.push(format!("Action: {}", output_str));

                // 5. ACT (Tool Output Handling)
                let mut action_success = false;
                let mut action_error = None;

                if let Ok(tool_call) = serde_json::from_str::<Value>(&output_str) {
                    if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                        if name == "gui__click" {
                            let x = tool_call["arguments"]["x"].as_u64().unwrap_or(0) as u32;
                            let y = tool_call["arguments"]["y"].as_u64().unwrap_or(0) as u32;
                            match self
                                .gui
                                .inject_input(InputEvent::Click {
                                    button: ioi_api::vm::drivers::gui::MouseButton::Left,
                                    x,
                                    y,
                                    expected_visual_hash: None,
                                })
                                .await
                            {
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
                    None,
                ) {
                    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();
                    if req.target == ioi_types::app::ActionTarget::GuiClick {
                        let x = params["x"].as_u64().unwrap_or(0) as u32;
                        let y = params["y"].as_u64().unwrap_or(0) as u32;

                        match self
                            .gui
                            .inject_input(InputEvent::Click {
                                button: ioi_api::vm::drivers::gui::MouseButton::Left,
                                x,
                                y,
                                expected_visual_hash: None,
                            })
                            .await
                        {
                            Ok(_) => action_success = true,
                            Err(e) => action_error = Some(e.to_string()),
                        }
                    }
                }

                // 6. RECORD TRACE (Black Box Recorder)
                let trace = StepTrace {
                    session_id: p.session_id,
                    step_index: agent_state.step_count,
                    visual_hash: visual_hash_arr,
                    full_prompt: user_prompt,
                    raw_output: output_str,
                    success: action_success,
                    error: action_error.clone(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let trace_key = Self::get_trace_key(&p.session_id, agent_state.step_count);
                state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

                // Fail transaction if action failed, but only after logging trace
                if let Some(e) = action_error {
                    return Err(TransactionError::Invalid(format!("Action failed: {}", e)));
                }

                agent_state.step_count += 1;
                if agent_state.step_count >= agent_state.max_steps {
                    agent_state.status = AgentStatus::Completed;
                }

                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}
