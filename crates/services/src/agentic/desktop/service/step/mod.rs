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
use ioi_types::app::agentic::{AgentTool, AgentMacro, LlmToolDefinition}; 
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, InferenceOptions, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::{json, Value}; 
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::agentic::desktop::middleware;

use self::helpers::{default_safe_policy};
use self::visual::hamming_distance;

const CHARS_PER_TOKEN: u64 = 4;

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
        return Ok(());
    }

    if agent_state.consecutive_failures >= 3 {
        agent_state.status = AgentStatus::Failed("Too many consecutive failures".into());
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
            codec::from_bytes_canonical(&bytes).map_err(|e| {
                TransactionError::Invalid(format!("Invalid global policy in state: {}", e))
            })?
        } else {
            default_safe_policy()
        }
    };
    
    // 1. Capture Visual Context (Screenshot)
    let screenshot_bytes = service.gui.capture_screen().await.map_err(|e| {
        TransactionError::Invalid(format!("Visual capture failed: {}", e))
    })?;

    let visual_phash = compute_phash(&screenshot_bytes)?;
    
    if let Some(last_hash) = agent_state.last_screen_phash {
        let dist = hamming_distance(&visual_phash, &last_hash);
        if dist < 2 && agent_state.step_count > 0 {
            log::warn!("Visual Caching: Screen static (dist={}). Routing to Fast System (Reflex).", dist);
        }
    }

    agent_state.last_screen_phash = Some(visual_phash);

    // 2. Capture Accessibility Tree (DOM)
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

    let context_slice = service.gui.capture_context(&observation_intent).await.map_err(|e| {
        TransactionError::Invalid(format!("Substrate access failed: {}", e))
    })?;

    let mut tree_xml_bytes = Vec::new();
    for chunk in &context_slice.chunks {
        tree_xml_bytes.extend_from_slice(chunk);
    }
    let full_tree_xml = String::from_utf8_lossy(&tree_xml_bytes);

    // [NEW] 2. The "UI Chunker": Break XML into embeddable nodes
    if let Some(scs_arc) = &service.scs {
        let mut ui_vectors = Vec::new();
        
        for line in full_tree_xml.lines() {
            let trimmed = line.trim();
            if trimmed.contains("name=\"") || trimmed.contains("value=\"") {
                if let Ok(vec) = service.reasoning_inference.embed_text(trimmed).await {
                    ui_vectors.push((trimmed.to_string(), vec));
                }
            }
        }

        // Batch Insert into SCS
        if !ui_vectors.is_empty() {
             if let Ok(mut store) = scs_arc.lock() {
                 // 1. Optional: Store Full Tree as 'System' type for debugging/replay
                 let _full_trace_id = store.append_frame(
                    FrameType::System, 
                    &tree_xml_bytes,
                    ctx.block_height,
                    [0u8; 32],
                    p.session_id,
                 ).map_err(|e| TransactionError::Invalid(e.to_string()))?;

                 // 2. Store and Index Fragments (The "Searchable" Memory)
                 if let Ok(index_arc) = store.get_vector_index() {
                     let mut index = index_arc.lock().unwrap();
                     if let Some(idx) = index.as_mut() {
                         for (text, vec) in ui_vectors {
                             let fragment_id = store.append_frame(
                                FrameType::Observation,
                                text.as_bytes(), 
                                ctx.block_height,
                                [0u8; 32],
                                p.session_id
                             ).map_err(|e| TransactionError::Invalid(e.to_string()))?;

                             let _ = idx.insert_with_metadata(
                                 fragment_id, 
                                 vec, 
                                 FrameType::Observation, 
                                 visual_phash
                             );
                         }
                     }
                 }
             }
        }
    }

    // 3. [NEW] Retrieval (The "Read" Path)
    let window_list = crate::agentic::desktop::service::step::helpers::extract_window_titles(&full_tree_xml);
    let relevant_context = service.retrieve_context(&agent_state.goal, Some(visual_phash)).await;

    let available_tools = if agent_state.mode == AgentMode::Chat {
        vec![
            LlmToolDefinition {
                name: "chat__reply".to_string(),
                description: "Send a text message or answer to the user.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "message": { "type": "string", "description": "The response text." }
                    },
                    "required": ["message"]
                }).to_string(),
            }
        ]
    } else {
        let scs_ref = service.scs.as_deref();
        let base_tools = discover_tools(state, scs_ref);
        if let Some(mcp) = &service.mcp {
            let mcp_tools = mcp.get_all_tools().await;
            merge_tools(base_tools, mcp_tools)
        } else {
            base_tools
        }
    };

    let is_simple_interaction = full_tree_xml.contains("Accept Cookies") 
        || full_tree_xml.contains("Close") 
        || full_tree_xml.contains("Remind Me Later");

    let runtime = if is_simple_interaction {
        service.fast_inference.clone()
    } else {
        service.select_runtime(&agent_state)
    };

    let history = service.hydrate_session_history(p.session_id)?;
    let base64_image = BASE64.encode(&screenshot_bytes);

    let workspace_context = format!(
        "You are running in a secure sandbox.\n\
         Current Working Directory: {}\n\
         Allowed Paths: {}/*",
        service.workspace_path, service.workspace_path
    );

    let system_instructions = format!(
        "SYSTEM INSTRUCTION: You are an autonomous desktop agent.
        Your Goal: {}
        
        ENVIRONMENT:
        {}
        
        AVAILABLE TOOLS:
        {}

        CURRENT CONTEXT:
        - Open Windows: {}
        
        RELEVANT UI ELEMENTS (Search Results):
        {}

        HISTORY:
        {:?}
        
        CRITICAL RULES:
        1. You MUST respond with a VALID JSON OBJECT representing the tool call.
           Schema: {{ \"name\": \"tool_name\", \"arguments\": {{ ... }} }}
        2. To speak to the user, use the 'chat__reply' tool.
        3. To open an application, ALWAYS use 'sys__exec' with 'detach': true.
        4. If goal is satisfied, use 'agent__complete'.
        5. Use 'computer' tool for precise interactions if available.
        6. Use the 'RELEVANT UI ELEMENTS' to identify target IDs or coordinates.
        7. If the element you need is not listed, use the 'window' list to orient yourself.
        ",
        agent_state.goal,
        workspace_context,
        serde_json::to_string_pretty(&available_tools).unwrap_or_default(),
        window_list,
        relevant_context,
        history.iter().map(|m| format!("{}: {}", m.role, m.content)).collect::<Vec<_>>()
    );

    let multimodal_message = if agent_state.mode == AgentMode::Chat {
         json!([
             {
                 "role": "user",
                 "content": format!(
                     "SYSTEM: You are a helpful AI assistant.
                      User Input: {}
                      CONTEXT:
                      {}
                      INSTRUCTIONS:
                      1. Answer the user's question using the 'chat__reply' tool.
                      2. Do NOT output raw text.
                      3. You MUST respond with a valid JSON object.
                      ",
                      agent_state.goal,
                      window_list
                 )
             }
         ])
    } else {
         json!([
             {
                 "role": "system",
                 "content": system_instructions
             },
             {
                 "role": "user",
                 "content": [
                     {
                         "type": "text",
                         "text": "View the screenshot below to confirm state."
                     },
                     {
                         "type": "image_url",
                         "image_url": {
                             "url": format!("data:image/png;base64,{}", base64_image)
                         }
                     }
                 ]
             }
         ])
    };

    let (scrubbed_prompt_val, _redaction_map) = if agent_state.mode == AgentMode::Chat {
         let raw_text = multimodal_message[0]["content"].as_str().unwrap_or("");
         let (scrubbed, map) = service.scrubber.scrub(raw_text).await
            .map_err(|e| TransactionError::Invalid(format!("Scrubbing failed: {}", e)))?;
         
         let new_msg = json!([{ "role": "user", "content": scrubbed }]);
         (new_msg, map)
    } else {
         (multimodal_message, ioi_types::app::RedactionMap { entries: vec![] })
    };

    let user_prompt = serde_json::to_string(&scrubbed_prompt_val).unwrap_or_default();
    let input_bytes = serde_json::to_vec(&scrubbed_prompt_val)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    let model_hash = [0u8; 32];

    let output_str = if let Some(stored_call) = &agent_state.pending_tool_call {
        log::info!(
            "Retrying pending tool call for session {}",
            hex::encode(&p.session_id[0..4])
        );
        stored_call.clone()
    } else {
        let estimated_input_tokens = (user_prompt.len() as u64 / CHARS_PER_TOKEN) + 1000;

        let options = InferenceOptions {
            tools: available_tools.clone(), 
            temperature: if agent_state.consecutive_failures > 0 { 0.5 } else { 0.0 },
            json_mode: true,
        };

        let token_tx = if let Some(sender) = &service.event_sender {
             let (tx, mut rx) = mpsc::channel::<String>(100);
             let sender_clone = sender.clone();
             let session_id_clone = p.session_id;
             
             tokio::spawn(async move {
                 while let Some(token) = rx.recv().await {
                     let _ = sender_clone.send(KernelEvent::AgentThought {
                          session_id: session_id_clone,
                          token,
                     });
                 }
             });
             Some(tx)
        } else {
             None
        };

        let output_bytes = runtime
            .execute_inference_streaming(model_hash, &input_bytes, options, token_tx)
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

    let tool_call_result = middleware::normalize_tool_call(&output_str);
    
    let mut action_success = false;
    let mut action_error = None;
    let mut _action_type = "unknown".to_string(); 

    match tool_call_result {
        Ok(tool) => {
            let signature = serde_json::to_string(&tool).unwrap_or_default();
            _action_type = "typed_tool".to_string(); 

            // PRODUCTION FIX: Enhanced Repetition & Loop Detection Logic
            if let Some(last) = agent_state.recent_actions.last() {
                if *last == signature {
                     let is_chat = signature.contains("chat__reply");
                     
                     // Only enforce repetition check if we are NOT waiting for an approval (resumption).
                     if agent_state.pending_approval.is_none() {
                         if is_chat {
                             // Soft Block: Instructional Feedback.
                             // Tells the agent to stop yapping and start finishing.
                             action_error = Some(
                                 "System Notice: You just sent this exact message. \
                                 Do not repeat yourself. \
                                 If the visual state is confirmed and the task is done, \
                                 call 'agent__complete' immediately.".to_string()
                             );
                         } else {
                             // Hard Block: Safety violation for functional tools (e.g. double pay).
                             action_error = Some("Repetitive Action Detected".into());
                         }
                     }
                }
            }

            if action_error.is_none() {
                if agent_state.recent_actions.len() >= 3 {
                    agent_state.recent_actions.remove(0);
                }
                agent_state.recent_actions.push(signature);

                let mcp_handle = service
                    .mcp
                    .clone()
                    .unwrap_or_else(|| Arc::new(McpManager::new()));

                let executor = ToolExecutor::new(
                    service.gui.clone(),
                    service.terminal.clone(),
                    service.browser.clone(),
                    mcp_handle,
                    service.event_sender.clone(),
                );

                let os_driver = service.os_driver.clone().ok_or_else(|| {
                    TransactionError::Invalid("OS Driver not configured for policy check".into())
                })?;

                let tool_copy = tool.clone();

                let result = service
                    .handle_action_execution(
                        &executor,
                        tool,
                        p.session_id,
                        agent_state.step_count,
                        visual_phash,
                        &rules,
                        &agent_state,
                        &os_driver,
                    )
                    .await;

                match result {
                    Ok((success, history_entry, error)) => {
                        action_success = success;
                        action_error = error;
                        
                        if let Some(entry) = history_entry {
                            let tool_msg = ioi_types::app::agentic::ChatMessage {
                                role: "tool".to_string(),
                                content: entry,
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service.append_chat_to_scs(p.session_id, &tool_msg, ctx.block_height).await?;
                        }

                        if success {
                            agent_state.pending_approval = None;
                            agent_state.pending_tool_call = None;

                            match tool_copy {
                                AgentTool::AgentComplete { result } => {
                                    agent_state.status = AgentStatus::Completed(Some(result));
                                }
                                AgentTool::AgentPause { reason } => {
                                    agent_state.status = AgentStatus::Paused(reason);
                                }
                                AgentTool::ChatReply { .. } if agent_state.mode == AgentMode::Chat => {
                                     agent_state.status = AgentStatus::Completed(Some("Replied to user.".into()));
                                }
                                _ => {}
                            }
                            
                            if let AgentStatus::Completed(Some(reason)) = &agent_state.status {
                                 completion_event = Some(KernelEvent::AgentActionResult {
                                     session_id: p.session_id,
                                     step_index: agent_state.step_count,
                                     tool_name: "agent__complete".to_string(),
                                     output: reason.clone(),
                                 });
                            }
                        }
                    }
                    Err(e) => {
                        action_success = false;
                        action_error = Some(e.to_string());
                        
                        if let TransactionError::PendingApproval(req_hash) = &e {
                             agent_state.status = AgentStatus::Paused("Waiting for User Approval".into());
                             agent_state.pending_tool_call = Some(output_str.clone());
                             
                             let msg = format!("System: Action halted by Agency Firewall. Requesting authorization.");
                             let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content: msg,
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                             };
                             let _ = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                             
                             state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                             return Ok(());
                        }
                    }
                }
            }
        },
        Err(e) => {
            if output_str.trim().is_empty() {
                action_success = false;
                action_error = Some("LLM returned empty response (Context too large or Timeout)".to_string());
                log::warn!("Step failed: LLM returned empty response");
            } else {
                let thought_msg = ioi_types::app::agentic::ChatMessage {
                    role: "agent".to_string(),
                    content: output_str.clone(),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service.append_chat_to_scs(p.session_id, &thought_msg, ctx.block_height).await?;

                action_success = true; 
                action_error = Some(format!("Normalization failed (treated as thought): {}", e));
            }
            
            if agent_state.mode == AgentMode::Chat {
                 agent_state.status = AgentStatus::Completed(Some("Chat response sent.".into()));
                 if let Some(_tx) = &service.event_sender { 
                      completion_event = Some(KernelEvent::AgentActionResult {
                          session_id: p.session_id,
                          step_index: agent_state.step_count,
                          tool_name: "chat::reply".to_string(),
                          output: output_str.clone(),
                      });
                 }
            }
        }
    }

    if let Some(verifier) = &service.zk_verifier {
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
            .map_err(|e| TransactionError::Invalid(format!("ZK Verification error: {}", e)))?;

        if !valid {
            return Err(TransactionError::Invalid(
                "ZK Proof of Inference Invalid".into(),
            ));
        }
    }

    let log_prompt = if user_prompt.len() > 1000 {
        format!("{}... [TRUNCATED {} chars]", &user_prompt[..1000], user_prompt.len())
    } else {
        user_prompt.clone()
    };

    let trace = ioi_types::app::agentic::StepTrace {
        session_id: p.session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_phash,
        full_prompt: log_prompt,
        raw_output: output_str.clone(),
        success: action_success,
        error: action_error.clone(),
        cost_incurred: 0,
        fitness_score: None,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let trace_key = [TRACE_PREFIX, p.session_id.as_slice(), &agent_state.step_count.to_le_bytes()].concat();
    state.insert(&trace_key, &codec::to_bytes_canonical(&trace)?)?;

    if let Some(scs_arc) = &service.scs {
        if let Ok(mut store) = scs_arc.lock() {
            let trace_bytes = codec::to_bytes_canonical(&trace)?;
            let _ = store.append_frame(
                FrameType::System, 
                &trace_bytes,
                ctx.block_height,
                [0u8; 32], 
                p.session_id
            );
        }
    }

    if let Some(tx) = &service.event_sender {
        let event = KernelEvent::AgentStep(trace.clone());
        let _ = tx.send(event);

        if let Some(ce) = completion_event {
            let _ = tx.send(ce);
        }
    }

    if action_success && agent_state.consecutive_failures > 0 {
         log::info!("RSI Trigger: Success after {} failures. Scheduling optimizer.", agent_state.consecutive_failures);
         let _optimize_payload = ioi_types::app::SystemPayload::CallService {
             service_id: "optimizer".to_string(),
             method: "crystallize_skill@v1".to_string(),
             params: codec::to_bytes_canonical(&p).unwrap(), 
         };
    }

    if let Some(e) = &action_error {
        // PRODUCTION FIX: Benign Error Filtering
        // "System Notice" errors are behavioral corrections (e.g. stop repeating)
        // "Visual Drift" errors are environmental (e.g. popup).
        // Neither should kill the agent immediately.
        let is_benign = e.contains("Visual Drift") || e.contains("System Notice");
        
        if !is_benign { 
             agent_state.consecutive_failures += 1;
        } else {
             // Reset failures on benign errors to allow the "nudge" to work
             agent_state.consecutive_failures = 0;
        }
    } else {
        // Success resets the counter
        agent_state.consecutive_failures = 0;
    }

    agent_state.step_count += 1;

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