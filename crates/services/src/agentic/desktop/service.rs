// Path: crates/services/src/agentic/desktop/service.rs
use async_trait::async_trait;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent, InferenceOptions, ApprovalToken};
use ioi_types::codec;
use ioi_types::error::{TransactionError, UpgradeError};
use ioi_types::service_configs::Capabilities;
use serde_json::{json, Value};
use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ioi_api::ibc::AgentZkVerifier;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{FrameType, SovereignContextStore};

use ioi_drivers::mcp::McpManager;

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
const AGENT_POLICY_PREFIX: &[u8] = b"agent::policy::";

pub struct DesktopAgentService {
    gui: Arc<dyn GuiDriver>,
    terminal: Arc<TerminalDriver>,
    browser: Arc<BrowserDriver>,
    mcp: Option<Arc<McpManager>>, 
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
            mcp: None,
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
            mcp: None, 
            fast_inference,
            reasoning_inference,
            scrubber,
            zk_verifier: None,
            scs: None,
            event_sender: None,
            os_driver: None,
        }
    }

    pub fn with_mcp_manager(mut self, manager: Arc<McpManager>) -> Self {
        self.mcp = Some(manager);
        self
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

    async fn handle_action_execution(
        &self,
        executor: &ToolExecutor,
        name: &str,
        tool_call: &Value,
        session_id: [u8; 32],
        step_index: u32,
        visual_phash: [u8; 32],
        rules: &ActionRules,
        agent_state: &AgentState,
        os_driver: &Arc<dyn ioi_api::vm::drivers::os::OsDriver>,
    ) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
        
        let request_params = serde_json::to_vec(&tool_call["arguments"]).unwrap_or_default();
        
        let target = if name == "filesystem__write_file" {
             ActionTarget::FsWrite 
        } else if name == "filesystem__read_file" || name == "filesystem__list_allowed_directories" {
             ActionTarget::FsRead
        } else if name == "gui__click" {
             ActionTarget::GuiClick
        } else if name == "gui__type" {
             ActionTarget::GuiType
        } else if name == "browser__navigate" {
             ActionTarget::BrowserNavigate
        } else if name == "sys__exec" {
             ActionTarget::SysExec
        } else {
             ActionTarget::Custom(name.to_string())
        };

        let dummy_request = ActionRequest {
            target, 
            params: request_params,
            context: ActionContext {
                agent_id: "desktop_agent".into(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: step_index as u64,
        };

        // Pass the stored approval token to the policy engine
        let verdict = PolicyEngine::evaluate(
            rules,
            &dummy_request,
            &self.scrubber.model,
            os_driver,
            agent_state.pending_approval.as_ref(), 
        )
        .await;

        match verdict {
            Verdict::Allow => {
                // Proceed
            }
            Verdict::Block => {
                return Err(TransactionError::Invalid("Blocked by Policy".into()));
            }
            Verdict::RequireApproval => {
                let req_hash = hex::encode(dummy_request.hash());
                return Err(TransactionError::PendingApproval(req_hash));
            }
        }

        // Special handling for meta-tools
        if name == "agent__delegate" {
            return Ok((true, None, None));
        } else if name == "agent__await_result" {
            return Ok((true, None, None));
        } else if name == "agent__pause" {
            return Ok((true, None, None));
        } else if name == "agent__complete" {
            return Ok((true, None, None));
        } else if name == "commerce__checkout" {
            return Ok((true, Some("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string()), None));
        } else {
            // Driver Execution
            let result = executor.execute(name, tool_call, session_id, step_index, visual_phash).await;
            return Ok((result.success, result.history_entry, result.error));
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
    fn id(&self) -> &str { "desktop_agent" }
    fn abi_version(&self) -> u32 { 1 }
    fn state_schema(&self) -> &str { "v1" }
    fn capabilities(&self) -> Capabilities { Capabilities::empty() }
    fn as_any(&self) -> &dyn Any { self }

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
                    goal: p.goal.clone(),
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
                    pending_tool_call: None,
                    recent_actions: Vec::new(),
                    mode: p.mode, // [NEW] Set mode from params
                };
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

                // [NEW] Update Global History Index
                // Key: "agent::history"
                let history_key = b"agent::history".to_vec();
                let mut history: Vec<SessionSummary> = 
                    if let Some(bytes) = state.get(&history_key)? {
                        codec::from_bytes_canonical(&bytes).unwrap_or_default()
                    } else {
                        Vec::new()
                    };

                // Prepend new session (newest first)
                history.insert(0, SessionSummary {
                    session_id: p.session_id,
                    title: if agent_state.mode == AgentMode::Chat {
                        // Truncate long prompts for titles
                        let t = p.goal.lines().next().unwrap_or("New Chat");
                        if t.len() > 30 { format!("{}...", &t[..30]) } else { t.to_string() }
                    } else {
                        let t = p.goal.lines().next().unwrap_or("Agent Task");
                        if t.len() > 30 { format!("{}...", &t[..30]) } else { t.to_string() }
                    },
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                });

                // Keep last 50
                if history.len() > 50 { history.truncate(50); }

                state.insert(&history_key, &codec::to_bytes_canonical(&history)?)?;

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
                    
                    // Store the Approval Token provided by the UI
                    if let Some(token) = p.approval_token {
                        log::info!("Resuming session {} with Approval Token for hash {:?}", 
                            hex::encode(&p.session_id[0..4]), 
                            hex::encode(&token.request_hash));
                            
                        agent_state.pending_approval = Some(token);
                        
                        agent_state.history.push("System: Authorization GRANTED. You may retry the action immediately.".to_string());
                    } else {
                        agent_state.history.push("System: Resumed by user/controller without specific approval.".to_string());
                    }

                    // Reset failure counters so the retry doesn't trip the circuit breaker
                    agent_state.consecutive_failures = 0;

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

                // [NEW] Buffer for completion event to ensure correct ordering (Trace -> Result)
                let mut completion_event: Option<KernelEvent> = None;

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
                             full_prompt: "".into(), 
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

                let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
                let rules: ActionRules = if let Some(bytes) = state.get(&policy_key)? {
                    codec::from_bytes_canonical(&bytes)
                        .map_err(|e| TransactionError::Invalid(format!("Invalid policy in state: {}", e)))?
                } else {
                    let global_key = [AGENT_POLICY_PREFIX, [0u8; 32].as_slice()].concat();
                    if let Some(bytes) = state.get(&global_key)? {
                        codec::from_bytes_canonical(&bytes)
                            .map_err(|e| TransactionError::Invalid(format!("Invalid global policy in state: {}", e)))?
                    } else {
                        ActionRules::default() 
                    }
                };

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
                            [0u8; 32], 
                        );
                    }
                }

                // [MODIFIED] Tool Discovery based on Mode
                // [FIX] Use immutable variable
                let available_tools = if agent_state.mode == AgentMode::Chat {
                    // Chat Mode: No tools available. Pure conversation.
                    Vec::new()
                } else {
                    // Agent Mode: Full tool access
                    let mut tools = discover_tools(state);
                    if let Some(mcp) = &self.mcp {
                        let mcp_tools = mcp.get_all_tools().await;
                        tools.extend(mcp_tools);
                    }
                    tools
                };

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

                // Inject Workspace Context
                let workspace_context = format!(
                    "You are running in a secure sandbox.\n\
                     Current Working Directory: ./ioi-data\n\
                     Allowed Paths: ./ioi-data/*"
                );

                // [MODIFIED] System Prompt Construction based on Mode
                let raw_user_prompt = if agent_state.mode == AgentMode::Chat {
                    format!(
                        "SYSTEM: You are a helpful AI assistant.
                        User Input: {}
                        
                        CONTEXT:
                        {}
                        
                        INSTRUCTIONS:
                        1. Answer the user's question directly.
                        2. Do NOT generate tool calls or JSON.
                        3. Be concise and helpful.
                        4. Note: PII has been scrubbed from your input for privacy.
                        ",
                        agent_state.goal, // In chat mode, goal is the prompt
                        tree_xml // We still provide visual context (read-only)
                    )
                } else {
                    format!(
                        "SYSTEM INSTRUCTION: You are an autonomous agent API.
                        Your Goal: {}
                        
                        ENVIRONMENT:
                        {}
                        
                        AVAILABLE TOOLS:
                        {}
                        
                        HISTORY:
                        {:?}
                        
                        CONTEXT:
                        {}
                        
                        CRITICAL RULES:
                        1. You MUST respond with a VALID JSON OBJECT representing the tool call.
                        2. When writing files, ALWAYS use paths starting with './ioi-data/' or absolute paths you have confirmed exist.
                        3. Do NOT use placeholders like '/path/to/file'.
                        4. If the user's specific request is satisfied by the previous action, you MUST call 'agent__complete' immediately.
                        
                        EXAMPLE RESPONSE:
                        {{
                            \"thought\": \"I will save the results to the data directory.\",
                            \"name\": \"filesystem__write_file\",
                            \"arguments\": {{ \"path\": \"./ioi-data/results.txt\", \"content\": \"...\" }}
                        }}
                        ",
                        agent_state.goal,
                        workspace_context, 
                        serde_json::to_string_pretty(&available_tools).unwrap_or_default(),
                        agent_state.history,
                        tree_xml
                    )
                };

                let (scrubbed_prompt, _redaction_map) =
                    self.scrubber.scrub(&raw_user_prompt).await.map_err(|e| {
                        TransactionError::Invalid(format!("Scrubbing failed: {}", e))
                    })?;
                let user_prompt: String = scrubbed_prompt;

                let model_hash = [0u8; 32]; 

                // Deterministic Retry Logic (If pending, use it)
                let output_str = if let Some(stored_call) = &agent_state.pending_tool_call {
                    log::info!("Retrying pending tool call for session {}", hex::encode(&p.session_id[0..4]));
                    stored_call.clone()
                } else {
                    let estimated_input_tokens = (user_prompt.len() as u64) / CHARS_PER_TOKEN;
                    
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
                        return Ok(());
                    }
                    output_str
                };
                
                println!("[DesktopAgent] Brain Output: {}", output_str); 
                
                // [1.1] Deduplication Check
                if let Ok(tool_call) = serde_json::from_str::<Value>(&output_str) {
                    if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                         let signature_obj = json!({
                            "name": name,
                            "arguments": tool_call["arguments"]
                        });
                        
                        let signature = match serde_jcs::to_string(&signature_obj) {
                            Ok(s) => s,
                            Err(_) => signature_obj.to_string(),
                        };

                        if let Some(last) = agent_state.recent_actions.last() {
                            if *last == signature {
                                 // Loop detected
                                 let err_msg = "System: Repetitive Action Detected. Stop or change parameters.";
                                 agent_state.history.push(err_msg.to_string());
                                 agent_state.consecutive_failures += 1;
                                 
                                 // Emit Step for UI visibility
                                 if let Some(tx) = &self.event_sender {
                                     let _ = tx.send(KernelEvent::AgentStep(ioi_types::app::agentic::StepTrace {
                                         session_id: p.session_id,
                                         step_index: agent_state.step_count,
                                         visual_hash: visual_phash,
                                         full_prompt: user_prompt.clone(),
                                         raw_output: output_str.clone(),
                                         success: false,
                                         error: Some("Repetitive Action".into()),
                                         timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                     }));
                                 }
                                 
                                 state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                                 return Ok(());
                            }
                        }
                        
                        // Update rolling window
                        if agent_state.recent_actions.len() >= 3 {
                            agent_state.recent_actions.remove(0);
                        }
                        agent_state.recent_actions.push(signature);
                    }
                }

                agent_state.history.push(format!("Action: {}", output_str));

                let mut action_success = false;
                let mut action_error = None;
                let mut action_type = "unknown".to_string();

                let mcp_handle = self.mcp.clone().unwrap_or_else(|| Arc::new(McpManager::new()));

                let executor = ToolExecutor::new(
                    self.gui.clone(),
                    self.terminal.clone(),
                    self.browser.clone(),
                    mcp_handle,
                    self.event_sender.clone(),
                );

                if let Ok(tool_call) = serde_json::from_str::<Value>(&output_str) {
                    if let Some(name) = tool_call.get("name").and_then(|n| n.as_str()) {
                        action_type = name.to_string();

                        let os_driver = self.os_driver.clone().ok_or_else(|| {
                            TransactionError::Invalid("OS Driver not configured for policy check".into())
                        })?;

                        let result = self.handle_action_execution(
                            &executor,
                            name,
                            &tool_call,
                            p.session_id,
                            agent_state.step_count,
                            visual_phash,
                            &rules,
                            &agent_state,
                            &os_driver,
                        ).await;

                        match result {
                            Ok((success, history_entry, error)) => {
                                action_success = success;
                                action_error = error;
                                if let Some(entry) = history_entry {
                                    agent_state.history.push(entry);
                                }
                                
                                if success {
                                    if agent_state.pending_approval.is_some() {
                                        agent_state.pending_approval = None;
                                    }
                                    if agent_state.pending_tool_call.is_some() {
                                        agent_state.pending_tool_call = None;
                                    }
                                    
                                    // [1.2] Heuristic Auto-Termination
                                    let is_mutator = match name {
                                         "filesystem__write_file" | "gui__click" | "sys__exec" | "browser__click" => true,
                                         _ => false
                                     };
                                     
                                     if is_mutator && agent_state.goal.len() < 60 {
                                         agent_state.status = AgentStatus::Completed(Some("Auto-terminated: Action successful.".into()));
                                          
                                          // [FIX] Buffer event instead of sending immediately
                                          completion_event = Some(KernelEvent::AgentActionResult {
                                                 session_id: p.session_id,
                                                 step_index: agent_state.step_count,
                                                 tool_name: "system::auto_complete".to_string(),
                                                 output: "Goal likely satisfied. Terminating.".to_string(),
                                             });
                                     }
                                }
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                let is_pending_approval = if let TransactionError::PendingApproval(_) = &e {
                                    true
                                } else {
                                    err_str.contains("Approval required") || err_str.contains("PendingApproval")
                                };

                                if is_pending_approval {
                                    agent_state.status = AgentStatus::Paused("Waiting for User Approval".into());
                                    
                                    let mut real_request_hash = [0u8; 32];
                                    if let TransactionError::PendingApproval(hash) = e {
                                         if let Ok(hash_bytes) = hex::decode(&hash) {
                                            if let Ok(hash_arr) = hash_bytes.try_into() {
                                                real_request_hash = hash_arr;
                                                agent_state.pending_approval = Some(ApprovalToken {
                                                    request_hash: hash_arr,
                                                    scope: Default::default(),
                                                    approver_sig: vec![],
                                                    approver_suite: Default::default(),
                                                });
                                            }
                                         }
                                    }

                                    agent_state.pending_tool_call = Some(output_str.clone());
                                    
                                    agent_state.history.push(format!(
                                        "System: Action '{}' halted by Agency Firewall. Requesting authorization.", 
                                        action_type
                                    ));
                                    
                                    if let Some(tx) = &self.event_sender {
                                         let _ = tx.send(KernelEvent::FirewallInterception {
                                             verdict: "REQUIRE_APPROVAL".to_string(),
                                             target: action_type.clone(),
                                             request_hash: real_request_hash, 
                                             session_id: Some(p.session_id),
                                         });
                                    }
                                    
                                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                                    return Ok(()); 
                                } 
                                else if err_str.contains("Blocked by Policy") {
                                    agent_state.history.push(format!(
                                        "System: Action '{}' was BLOCKED by security policy. Do not retry this exact action.", 
                                        action_type
                                    ));
                                    agent_state.consecutive_failures += 1;
                                    action_error = Some("Blocked by Policy".into());
                                    action_success = false;
                                } 
                                else {
                                    action_error = Some(err_str);
                                    action_success = false;
                                }
                            }
                        }
                    } else {
                        // [MODIFIED] Chat Mode handling fallback or unexpected JSON
                        agent_state.history.push(format!("Thought (JSON): {}", output_str));
                        action_success = true;
                    }
                } else {
                    // Fallback: Plain Text (Chat Mode) or VLM
                    agent_state.history.push(format!("Thought: {}", output_str));
                    action_success = true;

                    // [NEW] If Chat Mode, complete immediately after response
                    if agent_state.mode == AgentMode::Chat {
                        agent_state.status = AgentStatus::Completed(Some("Chat response sent.".into()));
                        
                        // [FIX] Buffer event instead of sending immediately
                        completion_event = Some(KernelEvent::AgentActionResult {
                                 session_id: p.session_id,
                                 step_index: agent_state.step_count,
                                 tool_name: "chat::reply".to_string(),
                                 output: output_str.clone(),
                        });
                    } else if let Some(req) = parse_vlm_action(
                        &output_str,
                        1920,
                        1080,
                        "desktop-agent".into(),
                        Some(p.session_id),
                        agent_state.step_count as u64,
                        Some(visual_phash), 
                    ) {
                        // ... (VLM Logic - Truncated for brevity but included implicitly via copy-paste in real world) ...
                        // For the snippet, I assume VLM logic handles its own execution and doesn't need modification for Chat mode fix.
                        // Re-including VLM logic block for completeness.
                        let params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();
                        if req.target == ioi_types::app::ActionTarget::GuiClick {
                            action_type = "gui__click".to_string();
                            
                            let call = json!({
                                "name": "gui__click",
                                "arguments": params
                            });
                            
                             let os_driver = self.os_driver.clone().ok_or_else(|| {
                                TransactionError::Invalid("OS Driver not configured".into())
                            })?;

                            let executor = ToolExecutor::new(
                                self.gui.clone(),
                                self.terminal.clone(),
                                self.browser.clone(),
                                self.mcp.clone().unwrap_or_else(|| Arc::new(McpManager::new())),
                                self.event_sender.clone(),
                            );

                            let result = self.handle_action_execution(
                                &executor,
                                "gui__click",
                                &call,
                                p.session_id,
                                agent_state.step_count,
                                visual_phash,
                                &rules,
                                &agent_state,
                                &os_driver,
                            ).await;
                            
                             match result {
                                Ok((success, _hist, error)) => {
                                    action_success = success;
                                    action_error = error;
                                }
                                Err(e) => {
                                    action_error = Some(e.to_string());
                                    action_success = false;
                                }
                            }
                        }
                    }
                }

                if let Some(verifier) = &self.zk_verifier {
                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(user_prompt.as_bytes());
                    let effective_output_bytes = output_str.as_bytes(); 
                    
                    preimage.extend_from_slice(effective_output_bytes);
                    preimage.extend_from_slice(&model_hash);
                    let proof_hash = ioi_crypto::algorithms::hash::sha256(&preimage).unwrap();

                    let valid = verifier
                        .verify_inference(
                            proof_hash.as_ref(),
                            model_hash,
                            user_prompt.as_bytes(),
                            effective_output_bytes,
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

                // [NEW] Emit buffered completion event after trace log (ensures UI transitions Running -> Complete)
                if let Some(event) = completion_event {
                    if let Some(tx) = &self.event_sender {
                        let _ = tx.send(event);
                    }
                }

                Ok(())
            }
            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}