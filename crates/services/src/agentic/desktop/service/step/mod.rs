// Path: crates/services/src/agentic/desktop/service/step/mod.rs

pub mod helpers;
pub mod visual;

use super::DesktopAgentService;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX, TRACE_PREFIX};
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::compute_phash;
use crate::agentic::rules::{ActionRules}; 
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool; 
use ioi_types::app::{ActionContext, ActionRequest, InferenceOptions, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json; 
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use image::ImageFormat;
use std::io::Cursor;
use crate::agentic::desktop::middleware;
use self::helpers::default_safe_policy;
use serde::Deserialize;

const CHARS_PER_TOKEN: u64 = 4;
const MAX_TOTAL_CHARS: usize = 24_000;
const MAX_HISTORY_ITEMS: usize = 5;

// --- Cognitive Router Types (System 1) ---

/// Defines the "Attention Level" for the current step.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
enum AttentionMode {
    /// Pure conversation. No tools, no vision, no RAG. Fast & Cheap.
    Chat,
    /// Action required, but UI is predictable/simple. No Screenshot.
    BlindAction,
    /// Complex task requiring UI state verification. Full Screenshot.
    VisualAction,
}

impl DesktopAgentService {
    /// The "System 1" Router. 
    /// Classifies the immediate next step requirement based on goal, history, and latest input.
    async fn determine_attention_mode(&self, latest_input: &str, goal: &str, _step: u32, last_output: Option<&str>) -> AttentionMode {
        // 1. Heuristic: Check for explicit output from previous step asking for vision
        if let Some(out) = last_output {
            if out.contains("I need to see") || out.contains("screenshot") {
                return AttentionMode::VisualAction;
            }
        }

        // 2. Cognitive Router (LLM Classifier)
        let prompt = format!(
            "GOAL: \"{}\"\n\
            LATEST USER MESSAGE: \"{}\"\n\
            Classify the required mode for the *immediate next step*:\n\
            - 'Chat': The user is asking a question, saying hello, or giving feedback. No OS actions needed.\n\
            - 'Blind': The task is a simple command (e.g. 'open calculator', 'run ls', 'type hello').\n\
            - 'Visual': The task requires finding/reading something on screen (e.g. 'click the submit button', 'what is on screen?').\n\
            Respond JSON: {{ \"mode\": \"Chat\" | \"Blind\" | \"Visual\" }}",
            goal, latest_input
        );

        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            ..Default::default()
        };

        // Use the fast/local model for routing (cheap)
        match self.fast_inference.execute_inference([0u8; 32], prompt.as_bytes(), options).await {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                    return match val["mode"].as_str() {
                        Some("Chat") => AttentionMode::Chat,
                        Some("Blind") => AttentionMode::BlindAction,
                        Some("Visual") => AttentionMode::VisualAction,
                        _ => AttentionMode::VisualAction // Fail safe to visual
                    };
                }
                AttentionMode::VisualAction
            }
            Err(_) => {
                // Network failure fallback -> Safe Mode (Visual)
                AttentionMode::VisualAction
            }
        }
    }
}

pub async fn handle_step(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    p: StepAgentParams,
    ctx: &mut TxContext<'_>,
) -> Result<(), TransactionError> {
    let key = get_state_key(&p.session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let mut agent_state: AgentState = codec::from_bytes_canonical(&bytes)?;

    // 1. Budget & Status Checks
    if agent_state.status != AgentStatus::Running {
        return Err(TransactionError::Invalid(format!("Agent not running: {:?}", agent_state.status)));
    }
    if agent_state.budget == 0 || agent_state.consecutive_failures >= 3 {
        agent_state.status = AgentStatus::Failed("Resources/Retry limit exceeded".into());
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        return Ok(());
    }

    // 2. Load Policy
    let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
    let rules: ActionRules = state.get(&policy_key)?.and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    // --- COGNITIVE LOOP START (Active Perception) ---
    
    // Check for pending tool call (deterministic retry)
    let (tool_call_result, final_visual_phash, strategy_used) = if let Some(pending) = &agent_state.pending_tool_call {
        log::info!("Resuming pending tool call for session {}", hex::encode(&p.session_id[..4]));
        // Use stored visual hash or zero if missing (policy check depends on params, not vision)
        let phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        (pending.clone(), phash, "Resumed".to_string())
    } else {
        // Hydrate history ONCE for both Router and Prompt
        let full_history = service.hydrate_session_history(p.session_id)?;
        
        // Find latest user message
        let latest_user_msg = full_history.iter()
            .rfind(|m| m.role == "user")
            .map(|m| m.content.as_str())
            .unwrap_or(agent_state.goal.as_str()); // Fallback to goal if history empty

        // [MODIFIED] Router: Determine Mode using LATEST input (Dynamic Classification)
        // We no longer check agent_state.mode; the Router decides every step.
        let mode = service.determine_attention_mode(
            latest_user_msg, 
            &agent_state.goal,
            agent_state.step_count, 
            None 
        ).await;
        
        if mode == AttentionMode::Chat {
            log::info!("Router: Chat Mode selected. Bypassing heavy context.");
            
            // Fast Path: Chat Response
            // We use the latest user message as the direct prompt focus.
            let prompt = format!(
                "SYSTEM: You are a helpful assistant. The user said: \"{}\".\n\
                Respond directly to them using the chat__reply tool.\n\
                Output valid JSON matching this Schema: {{ \"name\": \"chat__reply\", \"arguments\": {{ \"message\": \"...\" }} }}",
                latest_user_msg
            );
            
            let options = InferenceOptions { 
                temperature: 0.7, 
                json_mode: true, 
                ..Default::default() 
            };
            
            let output = service.fast_inference.execute_inference([0u8; 32], prompt.as_bytes(), options).await
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_else(|_| "{\"name\": \"chat__reply\", \"arguments\": {\"message\": \"I'm having trouble thinking right now.\"}}".to_string());
                
            (output, [0u8; 32], "Chat-Fast".to_string())

        } else {
            // Action Mode (Blind or Visual)
            let needs_vision = mode == AttentionMode::VisualAction;
            
            let mut current_vision = needs_vision;
            let mut attempt = 0;
            
            loop {
                attempt += 1;
                log::info!("Step {}: Attempt {} with Vision={}", agent_state.step_count, attempt, current_vision);

                // A. Capture Context
                let (base64_image, window_list, visual_phash) = if current_vision {
                    // [HEAVY PATH] Full Visual Context
                    let raw_img = service.gui.capture_screen().await.map_err(|e| {
                        TransactionError::Invalid(format!("Visual capture failed: {}", e))
                    })?;
                    let phash = compute_phash(&raw_img)?;
                    
                    // Compress
                    let img = image::load_from_memory(&raw_img).map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    let resized = img.resize(512, 512, image::imageops::FilterType::Lanczos3);
                    let mut buf = Vec::new();
                    resized.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg).map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    
                    let intent = ActionRequest { 
                        target: ioi_types::app::ActionTarget::GuiScreenshot, 
                        params: vec![], 
                        context: ActionContext { agent_id: "system".into(), session_id: Some(p.session_id), window_id: None }, 
                        nonce: 0 
                    };
                    let slice = service.gui.capture_context(&intent).await.map_err(|e| TransactionError::Invalid(e.to_string()))?;
                    let wins = crate::agentic::desktop::service::step::helpers::extract_window_titles(&String::from_utf8_lossy(&slice.chunks[0]));
                    
                    (Some(BASE64.encode(&buf)), wins, phash)
                } else {
                    // [FAST PATH] Blind Mode
                    let wins = service.os_driver.as_ref()
                        .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
                        .get_active_window_title().await.unwrap_or(Some("Unknown".into())).unwrap_or("Unknown".into());
                        
                    (None, wins, [0u8; 32])
                };

                // B. RAG Retrieval (Cheap)
                let rag_phash_filter = if current_vision { Some(visual_phash) } else { None };
                let relevant_context = service.retrieve_context(&agent_state.goal, rag_phash_filter).await;

                // C. Construct Prompt
                let tools = discover_tools(state, service.scs.as_deref());
                let tool_desc = tools.iter().map(|t| format!("- {}: {}", t.name, t.description)).collect::<Vec<_>>().join("\n");
                
                // Use the reused full_history variable
                let recent_history = if full_history.len() > MAX_HISTORY_ITEMS {
                    &full_history[full_history.len() - MAX_HISTORY_ITEMS..]
                } else {
                    &full_history[..]
                };
                let hist_str = recent_history.iter().map(|m| format!("{}: {}", m.role, m.content)).collect::<Vec<_>>().join("\n");

                let workspace_context = format!(
                    "Current Working Directory: {}\nAllowed Paths: {}/*",
                    service.workspace_path, service.workspace_path
                );

                let strategy_instruction = if current_vision {
                    ""
                } else {
                    "NOTE: VISION IS DISABLED FOR SPEED. If you cannot proceed blindly, call the 'computer' tool with action='screenshot' to request vision."
                };

                let system_instructions = format!(
    "SYSTEM: You are a local desktop assistant operating inside the IOI runtime.
    IMPORTANT: You do NOT have blanket authority. Every action is mediated by the IOI Policy Engine.

    USER GOAL:
    {}

    ENVIRONMENT:
    - OS: Linux
    - Runtime: IOI Kernel Mode
    {}

    STATE:
    - Active Windows: {}
    - Memory (RAG): {}
    {}

    TOOLS:
    {}

    HISTORY:
    {}

    OPERATING RULES:
    1. Only take actions that directly advance the USER GOAL.
    2. Use the least-privileged tool that works.
    3. Output EXACTLY ONE valid JSON tool call.
    4. When goal achieved, call 'agent__complete'.",
                    agent_state.goal,
                    workspace_context,
                    window_list,
                    relevant_context,
                    strategy_instruction,
                    tool_desc,
                    hist_str
                );

                let messages = if let Some(b64) = base64_image {
                    json!([
                        { "role": "system", "content": system_instructions },
                        { "role": "user", "content": [
                            { "type": "text", "text": "Observe the screen and execute the next step." },
                            { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{}", b64) } }
                        ]}
                    ])
                } else {
                    json!([
                        { "role": "system", "content": system_instructions },
                        { "role": "user", "content": "Execute the next step based on the goal and history." }
                    ])
                };

                // D. Inference
                let model_hash = [0u8; 32];
                let options = InferenceOptions { 
                    temperature: 0.1, 
                    json_mode: true, 
                    tools: tools.clone(),
                    ..Default::default() 
                };
                let input_bytes = serde_json::to_vec(&messages).map_err(|e| TransactionError::Serialization(e.to_string()))?;
                
                let runtime = if current_vision { 
                    service.reasoning_inference.clone() 
                } else { 
                    service.fast_inference.clone() 
                };
                
                let output_bytes = match runtime.execute_inference(model_hash, &input_bytes, options).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        let err_msg = e.to_string();
                        // Handle Refusals (Pause)
                        if err_msg.contains("LLM_REFUSAL") {
                            let reason = err_msg.replace("Host function error: LLM_REFUSAL: ", "").replace("LLM_REFUSAL: ", "");
                            
                            // 1. Record Chat
                            let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content: format!("⚠️ Agent Paused: Model Refused Action.\nReason: {}", reason),
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                            
                            // 2. Pause State
                            let mut agent_state_update = agent_state.clone();
                            agent_state_update.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
                            agent_state_update.consecutive_failures = 0; 
                            state.insert(&key, &codec::to_bytes_canonical(&agent_state_update)?)?;
                            
                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: p.session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "system::refusal".to_string(),
                                    output: reason,
                                });
                            }
                            return Ok(()); 
                        }
                        log::error!("CRITICAL: Agent Inference Failed: {}", e);
                        Vec::new()
                    }
                };

                let output_str = String::from_utf8_lossy(&output_bytes).to_string();

                // E. Escalation Check
                let needs_escalation = output_str.trim().is_empty() 
                    || output_str.contains("screenshot") 
                    || output_str.contains("cannot see");

                if needs_escalation && !current_vision && attempt < 2 {
                    log::warn!("Agent Requesting Vision (Output: '{}'). Escalating.", output_str);
                    current_vision = true;
                    continue; 
                }

                break (output_str, visual_phash, if current_vision { "Visual" } else { "Blind" }.to_string());
            }
        }
    };
    
    // --- END COGNITIVE LOOP ---

    // 4. Parse & Execute
    let tool_call = middleware::normalize_tool_call(&tool_call_result);
    
    let mut success = false;
    let mut error_msg = None;
    let mut is_gated = false;
    let mut is_lifecycle_action = false;
    let mut current_tool_name = "unknown".to_string();

    match tool_call {
        Ok(tool) => {
             // ... (Executor setup) ...
             let mcp = service.mcp.clone().unwrap_or_else(|| Arc::new(McpManager::new()));
             let executor = ToolExecutor::new(
                service.gui.clone(),
                service.terminal.clone(),
                service.browser.clone(),
                mcp,
                service.event_sender.clone()
            );
            let os_driver = service.os_driver.clone().ok_or(TransactionError::Invalid("OS driver missing".into()))?;

            // Capture name for later logic
             if let AgentTool::ChatReply { .. } = &tool {
                 current_tool_name = "chat__reply".to_string();
             } else {
                 // Use a rough approximation or the enum name logic
                 // For now, we only need to detect chat
             }

            match service.handle_action_execution(
                &executor, 
                tool.clone(), 
                p.session_id, 
                agent_state.step_count, 
                final_visual_phash, 
                &rules, 
                &agent_state, 
                &os_driver
            ).await {
                Ok((s, history_entry, e)) => {
                    success = s;
                    error_msg = e;
                    
                    if s {
                        if let Some(entry) = history_entry.clone() {
                            let tool_msg = ioi_types::app::agentic::ChatMessage {
                                role: "tool".to_string(),
                                content: entry,
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service.append_chat_to_scs(p.session_id, &tool_msg, ctx.block_height).await?;
                        }
                    }

                    match &tool {
                        AgentTool::AgentComplete { result } => {
                            agent_state.status = AgentStatus::Completed(Some(result.clone()));
                            is_lifecycle_action = true;
                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: p.session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "agent__complete".to_string(),
                                    output: result.clone(),
                                });
                            }
                        }
                        AgentTool::AgentPause { reason } => {
                            agent_state.status = AgentStatus::Paused(reason.clone());
                            is_lifecycle_action = true;
                        }
                        AgentTool::ChatReply { message } => {
                            // [FIX] Pause execution to wait for user response (Turn-taking)
                            agent_state.status = AgentStatus::Paused("Waiting for user input".to_string());
                            is_lifecycle_action = true; 
                            
                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: p.session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "chat__reply".to_string(),
                                    output: message.clone(),
                                });
                            }
                            log::info!("Agent Sent Chat Reply (Yielding Control)");
                        }
                        AgentTool::SysExec { command, detach, .. } => {
                            // [FIX] Auto-Complete Heuristic restored here
                            if s && *detach {
                                let goal_lower = agent_state.goal.trim().to_lowercase();
                                let cmd_lower = command.to_lowercase();
                                
                                let is_short = goal_lower.len() < 80;
                                let is_simple_launch = is_short && 
                                    (goal_lower.starts_with("open ") || goal_lower.starts_with("start ") || goal_lower.starts_with("run ") || goal_lower.starts_with("launch "));

                                if is_simple_launch && goal_lower.contains(&cmd_lower) {
                                    let result_msg = history_entry.clone().unwrap_or_else(|| format!("Launched {}", command));
                                    agent_state.status = AgentStatus::Completed(Some(result_msg.clone()));
                                    is_lifecycle_action = true;

                                    if let Some(tx) = &service.event_sender {
                                        let _ = tx.send(KernelEvent::AgentActionResult {
                                            session_id: p.session_id,
                                            step_index: agent_state.step_count,
                                            tool_name: "system::auto_complete".to_string(),
                                            output: result_msg,
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(TransactionError::PendingApproval(h)) => {
                    is_gated = true;
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused("Waiting for approval".into());
                    agent_state.pending_tool_call = Some(tool_call_result.clone());
                    agent_state.last_screen_phash = Some(final_visual_phash);
                    
                    let msg = format!("System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.", h);
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                    success = true; 
                }
                Err(e) => {
                    success = false;
                    error_msg = Some(e.to_string());
                }
            }
        }
        Err(e) => {
             error_msg = Some(format!("Failed to parse tool call: {}", e));
             // [FIX] Removed redundant success assignment
        }
    }

    // 5. Record Trace
    let trace = ioi_types::app::agentic::StepTrace {
        session_id: p.session_id,
        step_index: agent_state.step_count,
        visual_hash: final_visual_phash,
        full_prompt: format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        raw_output: tool_call_result,
        success,
        error: error_msg.clone(),
        cost_incurred: 0, 
        fitness_score: None,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };

    let trace_key = [TRACE_PREFIX, p.session_id.as_slice(), &agent_state.step_count.to_le_bytes()].concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;
    
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::AgentStep(trace));
    }

    if success || is_lifecycle_action {
        agent_state.consecutive_failures = 0;
    } else {
        agent_state.consecutive_failures += 1;
    }
    
    if !is_gated {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
    }
    
    // [FIX] Prevent max_step termination if last action was chat
    let is_chat = current_tool_name == "chat__reply" || agent_state.mode == AgentMode::Chat;
    
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running && !is_chat {
        agent_state.status = AgentStatus::Completed(None);
        
        if let Some(tx) = &service.event_sender {
             let _ = tx.send(KernelEvent::AgentActionResult {
                 session_id: p.session_id,
                 step_index: agent_state.step_count,
                 tool_name: "system::max_steps_reached".to_string(),
                 output: "Max steps reached. Task completed.".to_string(),
             });
        }
    }
    
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}