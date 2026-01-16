// Path: crates/services/src/agentic/desktop/service.rs
use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent, InferenceOptions}; // [FIX] Added InferenceOptions
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::service_configs::Capabilities;
use serde_json::{json, Value}; // [FIX] Added json macro import
use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ioi_api::ibc::AgentZkVerifier;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{FrameType, SovereignContextStore};

use crate::agentic::grounding::parse_vlm_action;
use crate::agentic::policy::PolicyEngine;
use crate::agentic::rules::{ActionRules, Verdict};
use crate::agentic::scrub_adapter::RuntimeAsSafetyModel;
use crate::agentic::scrubber::SemanticScrubber;

use super::execution::ToolExecutor;
use super::keys::{get_state_key, SKILL_INDEX_PREFIX};
use super::tools::discover_tools;
use super::types::*;
use super::utils::{compute_phash, goto_trace_log};

// Constants
const CHARS_PER_TOKEN: u64 = 4;

pub struct DesktopAgentService {
    gui: Arc<dyn GuiDriver>,
    terminal: Arc<TerminalDriver>,
    browser: Arc<BrowserDriver>,
    fast_inference: Arc<dyn InferenceRuntime>,
    reasoning_inference: Arc<dyn InferenceRuntime>,
    scrubber: SemanticScrubber,
    zk_verifier: Option<Arc<dyn AgentZkVerifier>>,
    scs: Option<Arc<Mutex<SovereignContextStore>>>,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    os_driver: Option<Arc<dyn ioi_api::vm::drivers::os::OsDriver>>,
}

impl DesktopAgentService {
    pub fn new(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            terminal,
            browser,
            fast_inference: inference.clone(),
            reasoning_inference: inference,
            scrubber,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
        }
    }

    pub fn new_hybrid(
        gui: Arc<dyn GuiDriver>,
        terminal: Arc<TerminalDriver>,
        browser: Arc<BrowserDriver>,
        fast_inference: Arc<dyn InferenceRuntime>,
        reasoning_inference: Arc<dyn InferenceRuntime>,
    ) -> Self {
        let safety_adapter = Arc::new(RuntimeAsSafetyModel::new(fast_inference.clone()));
        let scrubber = SemanticScrubber::new(safety_adapter);

        Self {
            gui,
            terminal,
            browser,
            fast_inference,
            reasoning_inference,
            scrubber,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
        }
    }

    pub fn with_zk_verifier(mut self, verifier: Arc<dyn AgentZkVerifier>) -> Self {
        self.zk_verifier = Some(verifier);
        self
    }

    pub fn with_scs(mut self, scs: Arc<Mutex<SovereignContextStore>>) -> Self {
        self.scs = Some(scs);
        self
    }

    pub fn with_event_sender(
        mut self,
        sender: tokio::sync::broadcast::Sender<KernelEvent>,
    ) -> Self {
        self.event_sender = Some(sender);
        self
    }

    pub fn with_os_driver(
        mut self,
        driver: Arc<dyn ioi_api::vm::drivers::os::OsDriver>,
    ) -> Self {
        self.os_driver = Some(driver);
        self
    }

    async fn recall_skills(
        &self,
        state: &dyn StateAccess,
        goal: &str,
    ) -> Result<Vec<ioi_types::app::agentic::AgentSkill>, TransactionError> {
        let mut relevant_skills = Vec::new();
        let goal_lower = goal.to_lowercase();
        if let Ok(iter) = state.prefix_scan(SKILL_INDEX_PREFIX) {
            for item in iter {
                if let Ok((_, val_bytes)) = item {
                    if let Ok(skill) = codec::from_bytes_canonical::<ioi_types::app::agentic::AgentSkill>(&val_bytes) {
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

    async fn retrieve_memory(&self, query: &str) -> String {
        let scs_mutex = match &self.scs {
            Some(m) => m,
            None => return "".to_string(),
        };

        let embedding_res = self.reasoning_inference.embed_text(query).await;
        
        let embedding = match embedding_res {
            Ok(vec) => vec,
            Err(e) => {
                log::warn!("Failed to generate embedding for RAG: {}", e);
                return "".to_string();
            }
        };

        let results = {
            let scs = match scs_mutex.lock() {
                Ok(s) => s,
                Err(_) => return "".to_string(),
            };

            let index_mutex = match scs.get_vector_index() {
                Ok(idx) => idx,
                Err(e) => {
                    log::warn!("Failed to get vector index: {}", e);
                    return "".to_string();
                }
            };
            
            let idx = match index_mutex.lock() {
                Ok(i) => i,
                Err(_) => return "".to_string(),
            };

            if let Some(index) = idx.as_ref() {
                index.search(&embedding, 3)
            } else {
                Ok(vec![])
            }
        };

        let matches = match results {
            Ok(m) => m,
            Err(e) => {
                log::warn!("RAG search failed: {}", e);
                return "".to_string();
            }
        };

        if matches.is_empty() {
            return "".to_string();
        }

        let mut context_str = String::new();
        context_str.push_str("\n### Relevant Memories\n");
        
        {
            let scs = match scs_mutex.lock() {
                Ok(s) => s,
                Err(_) => return "".to_string(),
            };

            for (frame_id, dist) in matches {
                if let Ok(payload) = scs.read_frame_payload(frame_id) {
                    if let Ok(text) = String::from_utf8(payload.to_vec()) {
                        let snippet = if text.len() > 200 {
                            format!("{}...", &text[..200])
                        } else {
                            text
                        };
                        context_str.push_str(&format!("- (Sim: {:.2}) {}\n", 1.0 - dist, snippet));
                    }
                }
            }
        }
        context_str
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

#[async_trait]
impl UpgradableService for DesktopAgentService {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
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
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
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
                let key = get_state_key(&p.session_id);
                if state.get(&key)?.is_some() {
                    return Err(TransactionError::Invalid("Session already exists".into()));
                }

                if let Some(parent_id) = p.parent_session_id {
                    let parent_key = get_state_key(&parent_id);
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
                    pending_approval: None,
                };
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                Ok(())
            }
            "resume@v1" => {
                let p: ResumeAgentParams = codec::from_bytes_canonical(params)?;
                let key = get_state_key(&p.session_id);
                let bytes = state
                    .get(&key)?
                    .ok_or(TransactionError::Invalid("Session not found".into()))?;
                let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

                if let AgentStatus::Paused(_) = agent_state.status {
                    agent_state.status = AgentStatus::Running;
                    agent_state
                        .history
                        .push("System: Resumed by user/controller.".to_string());
                    
                    if let Some(token) = p.approval_token {
                        agent_state.pending_approval = Some(token);
                        agent_state.history.push("System: Approval token staged for retry.".to_string());
                    }

                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    Ok(())
                } else {
                    Err(TransactionError::Invalid("Agent is not paused".into()))
                }
            }

            "step@v1" => {
                let p: StepAgentParams = codec::from_bytes_canonical(params)?;
                let key = get_state_key(&p.session_id);
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
                    agent_state.status = AgentStatus::Failed("Budget Exhausted (Pre-check)".into());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    
                    if let Some(tx) = &self.event_sender {
                         let _ = tx.send(KernelEvent::AgentStep(ioi_types::app::agentic::StepTrace {
                             session_id: p.session_id,
                             step_index: agent_state.step_count,
                             visual_hash: [0; 32],
                             full_prompt: "".into(), // Omit prompt for error
                             raw_output: "Budget Exhausted".into(),
                             success: false,
                             error: Some("Budget Exhausted".into()),
                             timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                         }));
                    }
                    return Ok(());
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
                
                let mut tree_xml_bytes = Vec::new();
                for chunk in &context_slice.chunks {
                    tree_xml_bytes.extend_from_slice(chunk);
                }
                let tree_xml = String::from_utf8_lossy(&tree_xml_bytes);

                let screenshot_bytes = self.gui.capture_screen().await.map_err(|e| {
                    TransactionError::Invalid(format!("Visual capture failed: {}", e))
                })?;
                
                let visual_phash = compute_phash(&screenshot_bytes)?;

                let content_digest = ioi_crypto::algorithms::hash::sha256(&screenshot_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
                let mut content_hash = [0u8; 32];
                content_hash.copy_from_slice(content_digest.as_ref());

                if let Some(scs_arc) = &self.scs {
                    if let Ok(mut store) = scs_arc.lock() {
                        let _ = store.append_frame(
                            FrameType::Observation,
                            &screenshot_bytes,
                            _ctx.block_height,
                            [0u8; 32], // mHNSW root placeholder
                        );
                    }
                }

                let available_tools = discover_tools(state);
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

                let rag_context = self.retrieve_memory(&agent_state.goal).await;

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
                    "Goal: {}\n\n{}{}{}\n\nHistory: {:?}\n{}{}\nContext: {}",
                    agent_state.goal,
                    skills_prompt,
                    rag_context, 
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

                let (scrubbed_prompt, _redaction_map) =
                    self.scrubber.scrub(&raw_user_prompt).await.map_err(|e| {
                        TransactionError::Invalid(format!("Scrubbing failed: {}", e))
                    })?;
                let user_prompt: String = scrubbed_prompt;

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
                println!("[DesktopAgent] Brain Output: {}", output_str); 

                let estimated_output_tokens = (output_str.len() as u64) / CHARS_PER_TOKEN;
                let total_cost = estimated_input_tokens + estimated_output_tokens;
                agent_state.tokens_used += total_cost;
                if agent_state.budget >= total_cost {
                    agent_state.budget -= total_cost;
                } else {
                    agent_state.budget = 0;
                    agent_state.status = AgentStatus::Failed("Budget Exhausted during step".into());
                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    
                    if let Some(tx) = &self.event_sender {
                         let _ = tx.send(KernelEvent::AgentStep(ioi_types::app::agentic::StepTrace {
                             session_id: p.session_id,
                             step_index: agent_state.step_count,
                             visual_hash: [0; 32],
                             full_prompt: user_prompt.clone(),
                             raw_output: "Budget Exhausted".into(),
                             success: false,
                             error: Some("Budget Exhausted".into()),
                             timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                         }));
                    }
                    
                    return Ok(());
                }

                agent_state.history.push(format!("Action: {}", output_str));

                let mut action_success = false;
                let mut action_error = None;
                let mut action_type = "unknown".to_string();

                let executor = ToolExecutor::new(
                    self.gui.clone(),
                    self.terminal.clone(),
                    self.browser.clone(),
                    self.event_sender.clone(),
                );

                // Tool Dispatch Loop
                if let Ok(tool_call) = serde_json::from_str::<Value>(&output_str) {
                    if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                        action_type = name.to_string();

                        // --- Policy Enforcment ---
                        let os_driver = self.os_driver.clone().ok_or_else(|| {
                            TransactionError::Invalid("OS Driver not configured for policy check".into())
                        })?;

                        let request_params = serde_json::to_vec(&tool_call["arguments"]).unwrap_or_default();
                        let dummy_request = ActionRequest {
                            target: ActionTarget::Custom(name.to_string()),
                            params: request_params,
                            context: ActionContext {
                                agent_id: "desktop_agent".into(),
                                session_id: Some(p.session_id),
                                window_id: None,
                            },
                            nonce: agent_state.step_count as u64,
                        };

                        let rules = ActionRules::default();
                        
                        let verdict = PolicyEngine::evaluate(
                            &rules,
                            &dummy_request,
                            &self.scrubber.model,
                            &os_driver,
                            agent_state.pending_approval.as_ref(),
                        ).await;

                        match verdict {
                            Verdict::Allow => {
                                if agent_state.pending_approval.is_some() {
                                     agent_state.pending_approval = None;
                                }
                            }
                            Verdict::Block => {
                                action_error = Some("Blocked by Policy".into());
                                goto_trace_log(&mut agent_state, state, &key, p.session_id, content_hash, user_prompt, output_str, false, action_error, action_type, self.event_sender.clone())?;
                                return Ok(()); 
                            }
                            Verdict::RequireApproval => {
                                agent_state.status = AgentStatus::Paused("Policy Gate: Approval Required".into());
                                
                                if let Some(tx) = &self.event_sender {
                                    let _ = tx.send(KernelEvent::FirewallInterception {
                                        verdict: "REQUIRE_APPROVAL".to_string(),
                                        target: name.to_string(),
                                        request_hash: dummy_request.hash(),
                                    });
                                }
                                
                                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                                return Err(TransactionError::PendingApproval(hex::encode(dummy_request.hash())));
                            }
                        }

                        // Special handling for meta-tools
                        if name == "agent__delegate" {
                            let goal = tool_call["arguments"]["goal"].as_str().unwrap_or("").to_string();
                            let budget = tool_call["arguments"]["budget"].as_u64().unwrap_or(0);
                            let mut seed = p.session_id.to_vec();
                            seed.extend_from_slice(&agent_state.step_count.to_le_bytes());
                            let child_id_vec = ioi_crypto::algorithms::hash::sha256(&seed).unwrap().to_vec();
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

                            match self.handle_service_call(state, "start@v1", &params_bytes, _ctx).await {
                                Ok(_) => action_success = true,
                                Err(e) => action_error = Some(format!("Delegation failed: {}", e)),
                            }
                        } else if name == "agent__await_result" {
                            if let Some(hex_id) = tool_call["arguments"]["child_session_id_hex"].as_str() {
                                if let Ok(child_id_vec) = hex::decode(hex_id) {
                                    let mut child_id = [0u8; 32];
                                    if child_id_vec.len() == 32 {
                                        child_id.copy_from_slice(&child_id_vec);
                                        let child_key = get_state_key(&child_id);

                                        if let Some(child_bytes) = state.get(&child_key)? {
                                            let child_state: AgentState = codec::from_bytes_canonical(&child_bytes)?;
                                            match child_state.status {
                                                AgentStatus::Completed(res) => {
                                                    action_success = true;
                                                    let res_str = res.unwrap_or_default();
                                                    agent_state.history.push(format!("Child Result: {}", res_str));
                                                }
                                                AgentStatus::Failed(err) => {
                                                    action_success = false;
                                                    action_error = Some(format!("Child failed: {}", err));
                                                }
                                                _ => {
                                                    action_success = true;
                                                    agent_state.history.push("Child is still running.".to_string());
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
                            let reason = tool_call["arguments"]["reason"].as_str().unwrap_or("Paused").to_string();
                            agent_state.status = AgentStatus::Paused(reason);
                            action_success = true;
                        } else if name == "agent__complete" {
                            let result = tool_call["arguments"]["result"].as_str().unwrap_or("Done").to_string();
                            agent_state.status = AgentStatus::Completed(Some(result.clone()));
                            action_success = true;
                            agent_state.history.push(format!("System: Task Completed. Result: {}", result));

                            if let Some(tx) = &self.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: p.session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "agent__complete".to_string(),
                                    output: result.clone(),
                                });
                            }
                        } else if name == "commerce__checkout" {
                            action_success = true; 
                            agent_state.history.push("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string());
                        } else {
                            // Driver Execution
                            let result = executor.execute(name, &tool_call, p.session_id, agent_state.step_count, visual_phash).await;
                            action_success = result.success;
                            action_error = result.error;
                            if let Some(entry) = result.history_entry {
                                agent_state.history.push(entry);
                            }
                        }
                    } else {
                         // Valid JSON but not a tool call
                        agent_state.history.push(format!("Thought (JSON): {}", output_str));
                        action_success = true;
                    }
                } else {
                    // Raw text thought/monologue
                    agent_state.history.push(format!("Thought: {}", output_str));
                    
                    if let Some(req) = parse_vlm_action(
                        &output_str,
                        1920,
                        1080,
                        "desktop-agent".into(),
                        Some(p.session_id),
                        agent_state.step_count as u64,
                        Some(visual_phash), 
                    ) {
                        // VLM Parsing Fallback for raw text actions
                        let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();
                        if req.target == ioi_types::app::ActionTarget::GuiClick {
                            action_type = "gui__click".to_string();
                            
                            // Re-use executor logic via JSON construction for consistency
                            let call = json!({
                                "name": "gui__click",
                                "arguments": params
                            });
                            let result = executor.execute("gui__click", &call, p.session_id, agent_state.step_count, visual_phash).await;
                            action_success = result.success;
                            action_error = result.error;
                        }
                    } else {
                         action_success = true;
                    }
                }

                if let Some(verifier) = &self.zk_verifier {
                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(user_prompt.as_bytes());
                    preimage.extend_from_slice(&output_bytes);
                    preimage.extend_from_slice(&model_hash);
                    let proof_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();

                    let valid = verifier
                        .verify_inference(
                            proof_hash.as_ref(),
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

                goto_trace_log(&mut agent_state, state, &key, p.session_id, content_hash, user_prompt, output_str, action_success, action_error, action_type, self.event_sender.clone())?;

                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}