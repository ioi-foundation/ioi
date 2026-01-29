// Path: crates/services/src/agentic/desktop/service/step/mod.rs

pub mod helpers;
pub mod visual;

use super::DesktopAgentService;
use super::utils::merge_tools;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX, TRACE_PREFIX};
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::compute_phash;
use crate::agentic::rules::{ActionRules}; 
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_drivers::mcp::McpManager;
use ioi_scs::FrameType;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition}; 
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, InferenceOptions, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::{json, Value}; 
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use image::ImageFormat;
use std::io::Cursor;
use crate::agentic::desktop::middleware;
use self::helpers::default_safe_policy;
use self::visual::hamming_distance;
use serde::Deserialize;

const CHARS_PER_TOKEN: u64 = 4;
const MAX_TOTAL_CHARS: usize = 24_000;
const MAX_HISTORY_ITEMS: usize = 5;

// --- Cognitive Router Types ---

/// Defines the "Attention Level" for the current step.
#[derive(Debug, Deserialize, Clone, Copy)]
struct ContextStrategy {
    /// Does the agent need to see the screen (Screenshot + pHash)?
    needs_vision: bool,
    /// Does the agent need the semantic Accessibility Tree (DOM)?
    needs_dom: bool,
}

impl DesktopAgentService {
    /// The "System 1" Router. 
    /// Determines the cheapest observation strategy required to achieve the immediate goal.
    async fn determine_context_strategy(&self, goal: &str, step: u32) -> ContextStrategy {
        // Heuristic 1: If we are deep in a task (step > 0), we almost always need to verify 
        // the result of the previous action visually.
        if step > 0 {
            return ContextStrategy { needs_vision: true, needs_dom: true };
        }

        // Heuristic 2: Fast Path for simple launch commands.
        // If the goal is just "Open Calculator" or "Run ls", we can do that blindly via terminal.
        // If the goal implies finding, reading, or verifying, we need vision.
        let prompt = format!(
            "Task: \"{}\"\n\
            Classify the context requirements for this task.\n\
            - 'sys__exec', 'open app', 'type' tasks do NOT need vision (False).\n\
            - 'click', 'find', 'read', 'verify', 'search' tasks DO need vision (True).\n\
            Respond JSON: {{ \"needs_vision\": bool }}",
            goal
        );

        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            ..Default::default()
        };

        // Use the fast/local model for routing (cheap)
        // Use zero-hash for model ID
        match self.fast_inference.execute_inference([0u8; 32], prompt.as_bytes(), options).await {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) {
                    let vision = val["needs_vision"].as_bool().unwrap_or(true);
                    return ContextStrategy { needs_vision: vision, needs_dom: vision };
                }
                // Fallback on parse error
                ContextStrategy { needs_vision: true, needs_dom: true }
            }
            Err(_) => {
                // Network failure fallback -> Safe Mode (Full Context)
                ContextStrategy { needs_vision: true, needs_dom: true }
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
    
    // [FIX] Check for pending tool call to support deterministic retry
    let (tool_call_result, final_visual_phash, strategy_used) = if let Some(pending) = &agent_state.pending_tool_call {
        log::info!("Resuming pending tool call for session {}", hex::encode(&p.session_id[..4]));
        // Use stored visual hash or zero if missing (policy check depends on params, not vision)
        let phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        (pending.clone(), phash, "Resumed".to_string())
    } else {
        // Determine initial strategy via Router
        let initial_strategy = service.determine_context_strategy(&agent_state.goal, agent_state.step_count).await;
        
        let mut current_strategy = initial_strategy;
        let mut attempt = 0;
        
        // We loop up to 2 times: 
        // 1. Try Fast/Blind (if router says ok).
        // 2. If Agent is confused, escalate to Heavy/Visual immediately.
        loop {
            attempt += 1;
            log::info!("Step {}: Attempt {} with Strategy: {:?}", agent_state.step_count, attempt, current_strategy);

            // A. Capture Context based on Strategy
            let (base64_image, window_list, visual_phash) = if current_strategy.needs_vision {
                // [HEAVY PATH] Full Visual Context
                
                // 1. Capture Raw Screenshot
                let raw_img = service.gui.capture_screen().await.map_err(|e| {
                    TransactionError::Invalid(format!("Visual capture failed: {}", e))
                })?;
                
                // 2. Compute pHash (on raw bytes for precision)
                let phash = compute_phash(&raw_img)?;
                
                // 3. Compress for LLM (Resize + JPEG)
                // This prevents the 160k char overflow issue
                let img = image::load_from_memory(&raw_img).map_err(|e| TransactionError::Invalid(e.to_string()))?;
                let resized = img.resize(512, 512, image::imageops::FilterType::Lanczos3);
                let mut buf = Vec::new();
                resized.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg).map_err(|e| TransactionError::Invalid(e.to_string()))?;
                
                // 4. Capture & Prune XML
                let intent = ActionRequest { 
                    target: ioi_types::app::ActionTarget::GuiScreenshot, 
                    params: vec![], 
                    context: ActionContext { agent_id: "system".into(), session_id: Some(p.session_id), window_id: None }, 
                    nonce: 0 
                };
                let slice = service.gui.capture_context(&intent).await.map_err(|e| TransactionError::Invalid(e.to_string()))?;
                let mut tree_bytes = Vec::new();
                for c in slice.chunks { tree_bytes.extend_from_slice(&c); }
                let full_xml = String::from_utf8_lossy(&tree_bytes).to_string();
                
                // Extract lightweight window list for header
                let wins = crate::agentic::desktop::service::step::helpers::extract_window_titles(&full_xml);
                
                (Some(BASE64.encode(&buf)), wins, phash)
            } else {
                // [FAST PATH] Blind Mode
                // Just ask OS driver for active window title (very cheap)
                let wins = service.os_driver.as_ref()
                    .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
                    .get_active_window_title().await.unwrap_or(Some("Unknown".into())).unwrap_or("Unknown".into());
                    
                (None, wins, [0u8; 32])
            };

            // B. RAG Retrieval (Cheap)
            // We only pass the visual phash to RAG if we actually captured it, to filter visual memories.
            let rag_phash_filter = if current_strategy.needs_vision { Some(visual_phash) } else { None };
            let relevant_context = service.retrieve_context(&agent_state.goal, rag_phash_filter).await;

            // C. Construct Prompt
            // FIX: Removed invalid .map(...).ok() chain. discover_tools expects Option<&Mutex<T>>.
            let tools = discover_tools(state, service.scs.as_deref());
            let tool_desc = tools.iter().map(|t| format!("- {}: {}", t.name, t.description)).collect::<Vec<_>>().join("\n");
            
            let full_history = service.hydrate_session_history(p.session_id)?;
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

            let strategy_instruction = if current_strategy.needs_vision {
                ""
            } else {
                "NOTE: VISION IS DISABLED FOR SPEED. If you cannot proceed blindly, call the 'computer' tool with action='screenshot' to request vision."
            };

            // [HARDENED] Gated/Policy-Aware Prompt with Conditional Completion Logic
            let system_instructions = format!(
"SYSTEM: You are a local desktop assistant operating inside the IOI runtime.
IMPORTANT: You do NOT have blanket authority. Every action is mediated by the IOI Policy Engine (Agency Firewall).
Some actions will be blocked and require an explicit user approval token. Treat this as normal and expected.

USER GOAL:
{}

ENVIRONMENT:
- OS: Linux
- Runtime: IOI Kernel Mode (policy-gated tools)
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
2. Use the least-privileged tool that works. Do NOT default to sys__exec.
3. If an action is blocked or would be sensitive/ambiguous, ask the user via chat__reply and wait.
4. When you act, output EXACTLY ONE valid JSON tool call.
5. CRITICAL: When the goal is achieved, you MUST call 'agent__complete(result=...)'.
   - Do NOT call 'chat__reply' just to confirm success. Use 'agent__complete'.
   - If the last action clearly satisfies the USER GOAL (e.g. goal='open calculator', output='calculator launched'), call 'agent__complete' IMMEDIATELY.",
                agent_state.goal,
                workspace_context,
                window_list,
                relevant_context,
                strategy_instruction,
                tool_desc,
                hist_str
            );

            let messages = if let Some(b64) = base64_image {
                // Multimodal Request
                json!([
                    { "role": "system", "content": system_instructions },
                    { "role": "user", "content": [
                        { "type": "text", "text": "Observe the screen and execute the next step." },
                        { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{}", b64) } }
                    ]}
                ])
            } else {
                // Text-Only Request
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
            
            // Use Reasoning model for heavy/visual steps, Fast model for blind steps
            let runtime = if current_strategy.needs_vision { 
                service.reasoning_inference.clone() 
            } else { 
                service.fast_inference.clone() 
            };
            
            // [FIX] Error Handling: Catch Refusals and Pause
            let output_bytes = match runtime.execute_inference(model_hash, &input_bytes, options).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    let err_msg = e.to_string();
                    
                    // Check for our specific refusal prefix or known refusal patterns
                    if err_msg.contains("LLM_REFUSAL") {
                        let reason = err_msg.replace("Host function error: LLM_REFUSAL: ", "").replace("LLM_REFUSAL: ", "");
                        log::warn!("Agent Refused Action: {}", reason);
                        
                        // 1. Record the Refusal as a Chat Message so the user sees it
                        let sys_msg = ioi_types::app::agentic::ChatMessage {
                            role: "system".to_string(),
                            content: format!("⚠️ Agent Paused: Model Refused Action.\nReason: {}", reason),
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                            trace_hash: None,
                        };
                        let _ = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                        
                        // 2. Pause the agent state in the DB
                        let mut agent_state_update = agent_state.clone();
                        agent_state_update.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
                        // Don't count this as a crash/technical failure, it's a "soft" stop
                        agent_state_update.consecutive_failures = 0; 
                        
                        let key = get_state_key(&p.session_id);
                        state.insert(&key, &codec::to_bytes_canonical(&agent_state_update)?)?;
                        
                        // 3. Emit event to UI
                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id: p.session_id,
                                step_index: agent_state.step_count,
                                tool_name: "system::refusal".to_string(),
                                output: reason,
                            });
                        }

                        // Exit the step successfully (state is saved as paused)
                        return Ok(()); 
                    }

                    log::error!("CRITICAL: Agent Inference Failed (Strategy: {:?}): {}", current_strategy, e);
                    // Return empty to fall through to the escalation check or failure handling.
                    Vec::new()
                }
            };

            let output_str = String::from_utf8_lossy(&output_bytes).to_string();

            // E. Escalation Check (The Self-Correction Mechanism)
            // If the output suggests the agent is blind or confused, we force an escalation.
            let needs_escalation = output_str.trim().is_empty() 
                || output_str.contains("screenshot") 
                || output_str.contains("cannot see")
                || output_str.contains("I need to see");

            if needs_escalation && !current_strategy.needs_vision && attempt < 2 {
                log::warn!("Agent Requesting Vision (Output: '{}'). Escalating to Heavy Context.", output_str);
                current_strategy.needs_vision = true;
                current_strategy.needs_dom = true;
                // Loop back to top to retry with full context
                continue; 
            }

            // Success (or we already tried heavy)
            // FIX: Convert string literals to String to match the 'if' branch return type
            let strategy_name = if current_strategy.needs_vision { "Visual".to_string() } else { "Blind".to_string() };
            break (output_str, visual_phash, strategy_name);
        }
    };
    
    // --- END COGNITIVE LOOP ---

    // 4. Parse & Execute
    let tool_call = middleware::normalize_tool_call(&tool_call_result);
    
    let mut success = false;
    let mut error_msg = None;
    let mut is_gated = false; // [FIX] Track if execution was gated
    let mut is_lifecycle_action = false; // [NEW] Track lifecycle to prevent failure counting

    match tool_call {
        Ok(tool) => {
            let mcp = service.mcp.clone().unwrap_or_else(|| Arc::new(McpManager::new()));
            
            // Inject event sender for UI feedback
            let executor = ToolExecutor::new(
                service.gui.clone(),
                service.terminal.clone(),
                service.browser.clone(),
                mcp,
                service.event_sender.clone()
            );
            
            let os_driver = service.os_driver.clone().ok_or(TransactionError::Invalid("OS driver missing".into()))?;
            
            // Delegate execution (handles Policy check, MCP routing, Native drivers)
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
                    
                    // If successful, record the tool output as a chat message for history context
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

                    // Check for lifecycle events and apply heuristics
                    match &tool {
                        AgentTool::AgentComplete { result } => {
                            agent_state.status = AgentStatus::Completed(Some(result.clone()));
                            is_lifecycle_action = true;
                            
                            // [FIX] Emit completion event so UI updates phase
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
                        AgentTool::ChatReply { .. } => {
                            // [FIX] Chat Handoff: Pause execution to wait for user response
                            // This prevents the agent from looping and confusing itself after speaking.
                            agent_state.status = AgentStatus::Paused("Waiting for user response".into());
                            is_lifecycle_action = true;
                            log::info!("Agent Paused (Chat Handoff)");
                        }
                        AgentTool::SysExec { command, detach, .. } => {
                            // [FIX] Safe Auto-Complete Heuristic
                            if s && *detach {
                                let goal_lower = agent_state.goal.trim().to_lowercase();
                                let cmd_lower = command.to_lowercase();
                                
                                // A. Structure Check: Is it a simple "Launch X" goal?
                                let is_short = goal_lower.len() < 80;
                                let is_simple_launch = is_short && 
                                    (goal_lower.starts_with("open ") || goal_lower.starts_with("start ") || goal_lower.starts_with("launch ") || goal_lower.starts_with("run ")) &&
                                    !goal_lower.contains(" and ") && !goal_lower.contains(" then ");

                                // B. Relevance Check: Does the command plausibly match the goal?
                                let matches_intent = goal_lower.contains(&cmd_lower)
                                    || (goal_lower.contains("calculator") && cmd_lower.contains("calc"))
                                    || (goal_lower.contains("terminal") && (cmd_lower.contains("term") || cmd_lower.contains("console") || cmd_lower.contains("sh")))
                                    || (goal_lower.contains("browser") && (cmd_lower.contains("firefox") || cmd_lower.contains("chrome") || cmd_lower.contains("brave")))
                                    || (goal_lower.contains("files") && (cmd_lower.contains("nautilus") || cmd_lower.contains("dolphin") || cmd_lower.contains("thunar")))
                                    || (goal_lower.contains("settings") && (cmd_lower.contains("control") || cmd_lower.contains("settings")))
                                    || (goal_lower.contains("code") && (cmd_lower.contains("code") || cmd_lower.contains("vim") || cmd_lower.contains("nano")));

                                if is_simple_launch && matches_intent {
                                    log::info!("Goal '{}' matched executed command '{}'. Auto-completing.", agent_state.goal, command);
                                    
                                    let result_msg = history_entry.clone().unwrap_or_else(|| format!("Launched {}", command));
                                    agent_state.status = AgentStatus::Completed(Some(result_msg.clone()));
                                    is_lifecycle_action = true; // Mark as lifecycle transition

                                    // [FIX] Emit synthetic completion event so the UI stops the spinner
                                    if let Some(tx) = &service.event_sender {
                                        let _ = tx.send(KernelEvent::AgentActionResult {
                                            session_id: p.session_id,
                                            step_index: agent_state.step_count,
                                            tool_name: "system::auto_complete".to_string(), // <--- The magic string
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
                    // Gate Triggered
                    is_gated = true; // [FIX] Flag as gated
                    is_lifecycle_action = true; // Treat gating as a valid pause state
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
                    
                    // Do not increment consecutive failures for gates
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
             // Don't fail the step entirely, treat as "Agent Confusion"
             success = false; 
        }
    }

    // 5. Record Trace (Immutable Log)
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
    
    // Stream event to UI
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::AgentStep(trace));
    }

    // Update Agent State
    // [FIX] Do not count intentional pauses/handoffs as failures
    if success || is_lifecycle_action {
        agent_state.consecutive_failures = 0;
    } else {
        agent_state.consecutive_failures += 1;
    }
    
    // [FIX] Only increment step count if the action was NOT gated.
    // If gated, we stay on the same step index so the retry uses the same nonce.
    if !is_gated {
        agent_state.step_count += 1;
        // Clear pending call now that it has been processed/attempted fully
        agent_state.pending_tool_call = None;
    }
    
    // Max Steps Check
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running {
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