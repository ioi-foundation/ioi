// Path: crates/services/src/agentic/desktop/service/step.rs

use super::DesktopAgentService;
use super::utils::merge_tools;
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX, TRACE_PREFIX};
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::compute_phash;
// [FIX] Import Verdict and Rule for default policy construction
use crate::agentic::rules::{ActionRules, Rule, Verdict};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_drivers::mcp::McpManager;
use ioi_scs::FrameType;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, InferenceOptions, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::agentic::grounding::parse_vlm_action;
use tokio::sync::mpsc;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

const CHARS_PER_TOKEN: u64 = 4;

// [NEW] Helper to create safe defaults if policy is missing
fn default_safe_policy() -> ActionRules {
    ActionRules {
        policy_id: "default-safe".to_string(),
        defaults: crate::agentic::rules::DefaultPolicy::RequireApproval,
        rules: vec![
             // Lifecycle / Meta-Tools
             Rule {
                rule_id: Some("allow-complete".into()),
                target: "agent__complete".into(), 
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
             Rule {
                rule_id: Some("allow-pause".into()),
                target: "agent__pause".into(), 
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
             Rule {
                rule_id: Some("allow-await".into()),
                target: "agent__await_result".into(), 
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
             // Read-Only Capability Defaults
             Rule {
                rule_id: Some("allow-ui-read".into()),
                target: "gui::screenshot".into(),
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
             Rule {
                rule_id: Some("allow-browser-read".into()),
                target: "browser::extract".into(),
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
             // [NEW] Allow Chat Reply
             Rule {
                rule_id: Some("allow-chat-reply".into()),
                target: "chat__reply".into(),
                conditions: Default::default(),
                action: Verdict::Allow, 
             },
        ],
    }
}

// [FIX] Helper to sanitize LLM output by removing Markdown code blocks
// This solves the issue where models return ```json ... ``` causing parse errors
fn sanitize_llm_json(input: &str) -> String {
    let trimmed = input.trim();
    // Check for markdown code blocks
    if trimmed.starts_with("```") {
        let lines: Vec<&str> = trimmed.lines().collect();
        // Remove first line (```json or ```) and last line (```) if valid
        if lines.len() >= 2 && lines.last().unwrap().trim().starts_with("```") {
            return lines[1..lines.len()-1].join("\n");
        }
    }
    // Also handle raw strings that might just have the json prefix without backticks
    if let Some(json_start) = trimmed.strip_prefix("json") {
         return json_start.to_string();
    }
    
    input.to_string()
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

    // Buffer for completion event to ensure correct ordering (Trace -> Result)
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
        // [FIX] Borrow key for state insert
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        return Ok(());
    }

    if agent_state.consecutive_failures >= 3 {
        agent_state.status = AgentStatus::Failed("Too many consecutive failures".into());
        // [FIX] Borrow key for state insert
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
            // [FIX] Use robust default policy
            default_safe_policy()
        }
    };
    
    // Capture Accessibility Tree (DOM)
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
    let tree_xml = String::from_utf8_lossy(&tree_xml_bytes);

    // Capture Visuals (Screenshot)
    let screenshot_bytes = service.gui.capture_screen().await.map_err(|e| {
        TransactionError::Invalid(format!("Visual capture failed: {}", e))
    })?;

    let visual_phash = compute_phash(&screenshot_bytes)?;

    let content_digest = ioi_crypto::algorithms::hash::sha256(&screenshot_bytes)
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(content_digest.as_ref());

    if let Some(scs_arc) = &service.scs {
        if let Ok(mut store) = scs_arc.lock() {
            let _ = store.append_frame(
                FrameType::Observation,
                &screenshot_bytes,
                ctx.block_height,
                [0u8; 32],
                p.session_id,
            );
        }
    }

    let available_tools = if agent_state.mode == AgentMode::Chat {
        Vec::new()
    } else {
        let base_tools = discover_tools(state);
        if let Some(mcp) = &service.mcp {
            let mcp_tools = mcp.get_all_tools().await;
            merge_tools(base_tools, mcp_tools)
        } else {
            base_tools
        }
    };

    let skills = service.recall_skills(state, &agent_state.goal).await?;
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

    let workspace_context = format!(
        "You are running in a secure sandbox.\n\
         Current Working Directory: {}\n\
         Allowed Paths: {}/*",
        service.workspace_path, service.workspace_path
    );

    let history = service.hydrate_session_history(p.session_id)?;

    // [MODIFIED] Construct Multimodal Input Payload (Vision + Text)
    // This format aligns with OpenAI GPT-4o / Anthropic Claude 3.5 Sonnet vision inputs.
    // The `http_adapter` must handle serializing this JSON array to the provider's API.
    
    // 1. Prepare Base64 Image
    let base64_image = BASE64.encode(&screenshot_bytes);

    // 2. Build System Instructions
    let system_instructions = format!(
        "SYSTEM INSTRUCTION: You are an autonomous desktop agent.
        Your Goal: {}
        
        ENVIRONMENT:
        {}
        
        AVAILABLE TOOLS:
        {}
        
        HISTORY:
        {:?}
        
        CRITICAL RULES:
        1. You MUST respond with a VALID JSON OBJECT representing the tool call.
        2. To speak to the user, use the 'chat__reply' tool.
        3. To open an application (calculator, browser, etc), ALWAYS use 'sys__exec' with 'detach': true. Do NOT try to click icons.
        4. If the user's specific request is satisfied by the previous action, you MUST call 'agent__complete' immediately.
        
        EXAMPLE RESPONSE:
        {{
            \"thought\": \"I will launch the calculator.\",
            \"name\": \"sys__exec\",
            \"arguments\": {{ \"command\": \"gnome-calculator\", \"detach\": true }}
        }}
        ",
        agent_state.goal,
        workspace_context,
        serde_json::to_string_pretty(&available_tools).unwrap_or_default(),
        history
            .iter()
            .map(|m| format!("{}: {}", m.role, m.content))
            .collect::<Vec<_>>()
    );

    // 3. Assemble Multimodal User Message
    // This structure will be passed as the `input_context` bytes to the InferenceRuntime.
    let multimodal_message = if agent_state.mode == AgentMode::Chat {
         // Chat Mode (Text Only or minimal vision if needed)
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
                      ",
                      agent_state.goal,
                      tree_xml
                 )
             }
         ])
    } else {
         // Agent Mode (Vision + Text)
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
                         "text": format!("Here is the current screen state and accessibility tree:\n\nXML Context:\n{}", tree_xml)
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
         // Only scrubbing text content for chat mode prompts for now
         let raw_text = multimodal_message[0]["content"].as_str().unwrap_or("");
         let (scrubbed, map) = service.scrubber.scrub(raw_text).await
            .map_err(|e| TransactionError::Invalid(format!("Scrubbing failed: {}", e)))?;
         
         // Reconstruct message with scrubbed text
         let new_msg = json!([{ "role": "user", "content": scrubbed }]);
         (new_msg, map)
    } else {
         // For multimodal, we assume visual data might contain PII but scrubbing pixels is hard.
         // We rely on the `LocalSafetyModel` in `scrub_adapter` which currently handles text.
         // Pass raw for now; in production, use OCR + Redaction.
         (multimodal_message, ioi_types::app::RedactionMap { entries: vec![] })
    };

    let user_prompt = serde_json::to_string(&scrubbed_prompt_val).unwrap_or_default();
    
    // Serialize complex payload for runtime
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
        // Estimate tokens (Rough approximation including image overhead)
        let estimated_input_tokens = (user_prompt.len() as u64 / CHARS_PER_TOKEN) + 1000; // +1000 for image

        let options = InferenceOptions {
            tools: vec![], // Pass empty to prevent native tool calling conflict
            temperature: if agent_state.consecutive_failures > 0 {
                0.5
            } else {
                0.0
            },
            json_mode: true, // Enforce structured output via HTTP adapter
        };
        let runtime = service.select_runtime(&agent_state);

        // [NEW] Setup streaming channel if event_sender is present
        let token_tx = if let Some(sender) = &service.event_sender {
             let (tx, mut rx) = mpsc::channel::<String>(100);
             let sender_clone = sender.clone();
             let session_id_clone = p.session_id;
             
             // Spawn a task to forward tokens to UI
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
            // [FIX] Borrow key for state insert
            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
            return Ok(());
        }
        output_str
    };

    println!("[DesktopAgent] Brain Output: {}", output_str);
    
    // [FIX] Sanitize output string to remove Markdown code blocks before parsing
    let sanitized_output = sanitize_llm_json(&output_str);

    // [FIX] Robustly detect Tool Call vs Text
    // A valid tool call MUST be JSON AND contain a "name" field.
    let tool_call_opt = serde_json::from_str::<Value>(&sanitized_output)
        .ok()
        .filter(|v| v.get("name").and_then(|n| n.as_str()).is_some());

    let mut action_success = false;
    let mut action_error = None;
    let mut action_type = "unknown".to_string();

    if let Some(tool_call) = tool_call_opt {
        // --- TOOL EXECUTION PATH ---
        let name = tool_call["name"].as_str().unwrap();
        action_type = name.to_string();

        let signature_obj = json!({
            "name": name,
            "arguments": tool_call["arguments"]
        });

        let signature = match serde_jcs::to_string(&signature_obj) {
            Ok(s) => s,
            Err(_) => signature_obj.to_string(),
        };

        // Repetition Check
        if let Some(last) = agent_state.recent_actions.last() {
            if *last == signature {
                let err_msg = "System: Repetitive Action Detected. Stop or change parameters.";
                let sys_msg = ioi_types::app::agentic::ChatMessage {
                    role: "system".to_string(),
                    content: err_msg.to_string(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                
                // [FIX] Await async call
                let new_root = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                agent_state.transcript_root = new_root;

                agent_state.consecutive_failures += 1;

                if let Some(tx) = &service.event_sender {
                    let _ = tx.send(KernelEvent::AgentStep(ioi_types::app::agentic::StepTrace {
                        session_id: p.session_id,
                        step_index: agent_state.step_count,
                        visual_hash: visual_phash,
                        full_prompt: user_prompt.clone(),
                        raw_output: output_str.clone(),
                        success: false,
                        error: Some("Repetitive Action".into()),
                        cost_incurred: 0,
                        fitness_score: None,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    }));
                }

                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                return Ok(());
            }
        }

        if agent_state.recent_actions.len() >= 3 {
            agent_state.recent_actions.remove(0);
        }
        agent_state.recent_actions.push(signature);

        // Execute Tool
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

        let result = service
            .handle_action_execution(
                &executor,
                name,
                &tool_call,
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
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                            trace_hash: None,
                    };
                    let tool_root = service.append_chat_to_scs(p.session_id, &tool_msg, ctx.block_height).await?;
                    agent_state.transcript_root = tool_root;
                }

                if success {
                    if agent_state.pending_approval.is_some() {
                        agent_state.pending_approval = None;
                    }
                    if agent_state.pending_tool_call.is_some() {
                        agent_state.pending_tool_call = None;
                    }

                    if name == "agent__complete" {
                        agent_state.status =
                            AgentStatus::Completed(Some("Task completed successfully.".into()));

                        completion_event = Some(KernelEvent::AgentActionResult {
                            session_id: p.session_id,
                            step_index: agent_state.step_count,
                            tool_name: "agent__complete".to_string(),
                            output: "Task completed.".to_string(),
                        });
                    }

                    let is_mutator = match name {
                        "filesystem__write_file"
                        | "gui__click"
                        | "sys__exec"
                        | "browser__click" => true,
                        _ => false,
                    };

                    if is_mutator && agent_state.goal.len() < 60 {
                        agent_state.status = AgentStatus::Completed(Some(
                            "Auto-terminated: Action successful.".into(),
                        ));
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
                    agent_state.recent_actions.pop();
                    agent_state.status = AgentStatus::Paused("Waiting for User Approval".into());

                    let mut real_request_hash = [0u8; 32];
                    if let TransactionError::PendingApproval(hash) = e {
                        if let Ok(hash_bytes) = hex::decode(&hash) {
                            if let Ok(hash_arr) = hash_bytes.try_into() {
                                real_request_hash = hash_arr;
                                use ioi_types::app::action::{ApprovalToken};
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

                    let msg = format!(
                        "System: Action '{}' halted by Agency Firewall. Requesting authorization.",
                        action_type
                    );
                    
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                            trace_hash: None,
                    };
                    let sys_root = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                    agent_state.transcript_root = sys_root;

                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::FirewallInterception {
                            verdict: "REQUIRE_APPROVAL".to_string(),
                            target: action_type.clone(),
                            request_hash: real_request_hash,
                            session_id: Some(p.session_id),
                        });
                    }

                    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                    return Ok(());
                } else if err_str.contains("Blocked by Policy") {
                    let msg = format!("System: Action '{}' was BLOCKED by security policy.", action_type);
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                        trace_hash: None,
                    };
                    let sys_root = service.append_chat_to_scs(p.session_id, &sys_msg, ctx.block_height).await?;
                    agent_state.transcript_root = sys_root;

                    agent_state.consecutive_failures += 1;
                    action_error = Some("Blocked by Policy".into());
                    action_success = false;
                } else {
                    action_error = Some(err_str);
                    action_success = false;
                }
            }
        }
    } else {
        // --- TEXT / THOUGHT / CHAT FALLBACK ---
        let thought_msg = ioi_types::app::agentic::ChatMessage {
            role: "agent".to_string(),
            content: output_str.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
                trace_hash: None,
        };
        let thought_root = service.append_chat_to_scs(p.session_id, &thought_msg, ctx.block_height).await?;
        agent_state.transcript_root = thought_root;

        action_success = true;

        if agent_state.mode == AgentMode::Chat {
            agent_state.status = AgentStatus::Completed(Some("Chat response sent.".into()));

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
            // Check if VLM action is valid
            let _params: serde_json::Value = serde_json::from_slice(&req.params).unwrap();
            if req.target == ActionTarget::GuiClick {
                // If we parsed a VLM action successfully, mark it
                action_success = true;
            }
        } else {
            // [FIX] Fallback for Agent mode producing raw text (Treat as a reply)
             completion_event = Some(KernelEvent::AgentActionResult {
                 session_id: p.session_id,
                 step_index: agent_state.step_count,
                 tool_name: "chat::reply".to_string(), // Reusing chat::reply logic in UI
                 output: output_str.clone(),
             });
             
             // Mark as completed if it was just a conversational reply
             agent_state.status = AgentStatus::Completed(Some("Agent replied via text.".into()));
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

    let trace = ioi_types::app::agentic::StepTrace {
        session_id: p.session_id,
        step_index: agent_state.step_count,
        visual_hash: visual_phash,
        full_prompt: user_prompt.clone(),
        raw_output: output_str.clone(),
        success: action_success,
        error: action_error.clone(),
        // [FIX] Initialize new evolutionary fields
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

    // Update state failure counters
    if let Some(_e) = action_error {
        agent_state.consecutive_failures += 1;
    } else {
        agent_state.consecutive_failures = 0;
    }

    agent_state.step_count += 1;
    agent_state.last_action_type = Some(action_type);

    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running {
        agent_state.status = AgentStatus::Completed(None);
        
        // [FIX] Use `service.event_sender` instead of local `event_sender` variable
        if let Some(tx) = &service.event_sender {
             let _ = tx.send(KernelEvent::AgentActionResult {
                 session_id: p.session_id,
                 step_index: agent_state.step_count,
                 tool_name: "system::max_steps_reached".to_string(),
                 output: "Max steps reached. Task completed.".to_string(),
             });
        }
    }

    // [FIX] Borrow key for state insert
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
    Ok(())
}