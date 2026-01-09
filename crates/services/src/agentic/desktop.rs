// Path: crates/services/src/agentic/desktop.rs

use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::sync::Arc;
// [FIX] Removed unused import
// use serde_json::json;

use crate::agentic::grounding::parse_vlm_action;

const AGENT_STATE_PREFIX: &[u8] = b"agent::state::";

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

                // 1. OBSERVE
                // Note: We ignore the return value (screenshot bytes) here because
                // in Phase 7 MVP we don't hash/verify it yet.
                let _screenshot = self
                    .gui
                    .capture_screen()
                    .await
                    .map_err(|e| TransactionError::Invalid(format!("Vision error: {}", e)))?;
                let tree_xml = self
                    .gui
                    .capture_tree()
                    .await
                    .map_err(|e| TransactionError::Invalid(format!("A11y error: {}", e)))?;

                // 2. ORIENT (Prompt Construction)
                let user_prompt = format!(
                    "Goal: {}\nHistory: {:?}\nScreen: [IMAGE]\nA11y Tree: {}",
                    agent_state.goal, agent_state.history, tree_xml
                );

                // 3. DECIDE (Inference)
                let model_hash = [0u8; 32];
                let output_bytes = self
                    .inference
                    .execute_inference(model_hash, user_prompt.as_bytes())
                    .await
                    .map_err(|e| TransactionError::Invalid(format!("Inference error: {}", e)))?;

                let output_str = String::from_utf8_lossy(&output_bytes);
                agent_state.history.push(format!("Action: {}", output_str));

                // 4. PARSE & ACT
                let (w, h) = (1920, 1080);

                if let Some(req) = parse_vlm_action(
                    &output_str,
                    w,
                    h,
                    "desktop-agent".into(),
                    Some(p.session_id),
                    agent_state.step_count as u64,
                    None, // [FIX] No visual hash verification for MVP
                ) {
                    let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();

                    if req.target == ioi_types::app::ActionTarget::GuiClick {
                        let x = params["x"].as_u64().unwrap_or(0) as u32;
                        let y = params["y"].as_u64().unwrap_or(0) as u32;

                        self.gui
                            .inject_input(InputEvent::Click {
                                button: ioi_api::vm::drivers::gui::MouseButton::Left,
                                x,
                                y,
                                expected_visual_hash: None, // [FIX]
                            })
                            .await
                            .map_err(|e| {
                                TransactionError::Invalid(format!("Action failed: {}", e))
                            })?;
                    }
                }

                // Update State
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
