// Path: crates/services/src/agentic/desktop/service/step/action.rs

use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, ToolCallStatus};
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use crate::agentic::desktop::middleware;
use self::super::helpers::default_safe_policy;
use ioi_api::state::StateAccess;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, IntentContract, OutcomeType, OptimizationObjective, ActionRequest, ActionContext};
use ioi_types::error::TransactionError;
use ioi_types::codec;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::json;
use serde_jcs;

pub async fn process_tool_output(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    tool_call_result: String,
    final_visual_phash: [u8; 32],
    strategy_used: String,
    session_id: [u8; 32],
    block_height: u64
) -> Result<(), TransactionError> {
    
    let key = get_state_key(&session_id);
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state.get(&policy_key)?.and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    // 1. Raw Refusal Interceptor (Pre-normalization)
    if tool_call_result.contains("\"name\":\"system::refusal\"") || tool_call_result.contains("\"name\": \"system::refusal\"") {
        let reason = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&tool_call_result) {
            val.get("arguments")
               .and_then(|a| a.get("message").or_else(|| a.get("reason")))
               .and_then(|m| m.as_str())
               .unwrap_or("Model refused.").to_string()
        } else {
            "Model refused (raw match).".to_string()
        };

        handle_refusal(service, state, agent_state, &key, session_id, final_visual_phash, &reason).await?;
        return Ok(());
    }

    // 2. Normalize & Expand
    let tool_call = middleware::normalize_tool_call(&tool_call_result);
    
    // [NEW] Refusal Interceptor (Post-normalization backup)
    if let Ok(AgentTool::Dynamic(ref val)) = tool_call {
        if val.get("name").and_then(|n| n.as_str()) == Some("system::refusal") {
            let reason = val.get("arguments")
                .and_then(|a| a.get("message").or_else(|| a.get("reason")))
                .and_then(|m| m.as_str())
                .unwrap_or("Model refused.");
            
            handle_refusal(service, state, agent_state, &key, session_id, final_visual_phash, reason).await?;
            return Ok(());
        }
    }

    // [NEW] Check for Skill / Macro Match
    if let Ok(AgentTool::Dynamic(ref val)) = tool_call {
        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            if let Some(macro_def) = service.fetch_skill_macro(name) {
                log::info!("Expanding Macro '{}' into execution queue", name);
                
                let args_map = val.get("arguments")
                    .and_then(|a| a.as_object())
                    .cloned()
                    .unwrap_or_default();

                match service.expand_macro(&macro_def, &args_map) {
                    Ok(steps) => {
                        agent_state.execution_queue.extend(steps);
                        
                        // Log the expansion event
                         goto_trace_log(
                            agent_state,
                            state,
                            &key,
                            session_id,
                            final_visual_phash,
                            format!("[Macro Expansion] Loaded skill '{}'", name),
                            format!("Expanded into {} steps", agent_state.execution_queue.len()),
                            true,
                            None,
                            "system::expand_macro".to_string(),
                            service.event_sender.clone(),
                        )?;
                        
                        // [FIX] Increment step manually since trace log doesn't do it anymore
                        agent_state.step_count += 1;
                        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                        
                        return Ok(()); 
                    },
                    Err(e) => {
                        // Log expansion failure
                        goto_trace_log(
                            agent_state,
                            state,
                            &key,
                            session_id,
                            final_visual_phash,
                            format!("Failed to expand skill '{}'", name),
                            "".to_string(),
                            false,
                            Some(e.to_string()),
                            "system::expand_macro_fail".to_string(),
                            service.event_sender.clone(),
                        )?;
                        
                        // [FIX] Increment even on failure to avoid loop
                        agent_state.step_count += 1;
                        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                        return Ok(());
                    }
                }
            }
        }
    }

    // [NEW] Calculate Request Hash for Idempotency
    let (req_hash, req_hash_hex) = if let Ok(ref t) = tool_call {
        let target = t.target();
        let tool_val = serde_json::to_value(t).unwrap_or(json!({}));
        let args_val = tool_val.get("arguments").cloned().unwrap_or(json!({}));
        let params = serde_jcs::to_vec(&args_val).unwrap_or_default();
        
        let req = ActionRequest {
            target,
            params,
            context: ActionContext {
                agent_id: "desktop_agent".into(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: agent_state.step_count as u64,
        };
        let h = req.hash();
        (h, hex::encode(h))
    } else {
        ([0u8;32], String::new())
    };

    // [NEW] Idempotency Check
    if !req_hash_hex.is_empty() {
        if let Some(status) = agent_state.tool_execution_log.get(&req_hash_hex) {
            if matches!(status, ToolCallStatus::Executed(_)) {
                log::info!("Skipping idempotent step {} (Hash: {}). Advancing state.", agent_state.step_count, req_hash_hex);
                
                // [CRITICAL FIX] Advance state exactly like success would, to break loop
                agent_state.step_count += 1;
                agent_state.pending_tool_call = None;
                
                // Check hash match before clearing approval to be safe
                if agent_state
                    .pending_approval
                    .as_ref()
                    .map(|t| t.request_hash == req_hash)
                    .unwrap_or(false)
                {
                    agent_state.pending_approval = None;
                }

                // Ensure agent is running
                agent_state.status = AgentStatus::Running;
                
                // Persist the advance
                state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                return Ok(());
            }
        }
    }
    
    // 3. Execution
    let mut success = false;
    let mut error_msg = None;
    let mut is_gated = false;
    let mut is_lifecycle_action = false;
    let mut current_tool_name = "unknown".to_string();

    match tool_call {
        Ok(tool) => {
             let mcp = service.mcp.clone().unwrap_or_else(|| Arc::new(McpManager::new()));
             let executor = ToolExecutor::new(
                service.gui.clone(),
                service.terminal.clone(),
                service.browser.clone(),
                mcp,
                service.event_sender.clone()
            );
            let os_driver = service.os_driver.clone().ok_or(TransactionError::Invalid("OS driver missing".into()))?;

             if let AgentTool::ChatReply { .. } = &tool {
                 current_tool_name = "chat__reply".to_string();
             }

            match service.handle_action_execution(
                &executor, 
                tool.clone(), 
                session_id, 
                agent_state.step_count, 
                final_visual_phash, 
                &rules, 
                &agent_state, 
                &os_driver
            ).await {
                Ok((s, history_entry, e)) => {
                    success = s;
                    error_msg = e;
                    
                    // [NEW] On Success: Mark Idempotent & Consume Token
                    if s && !req_hash_hex.is_empty() {
                         agent_state.tool_execution_log.insert(req_hash_hex.clone(), ToolCallStatus::Executed("success".into()));
                         
                         // Consume approval if used (One-shot)
                         if let Some(token) = &agent_state.pending_approval {
                             if token.request_hash == req_hash {
                                 agent_state.pending_approval = None;
                             }
                         }
                    }

                    if s {
                        if let Some(entry) = history_entry.clone() {
                            let tool_msg = ioi_types::app::agentic::ChatMessage {
                                role: "tool".to_string(),
                                content: entry,
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service.append_chat_to_scs(session_id, &tool_msg, block_height).await?;
                        }
                    }

                    match &tool {
                        AgentTool::AgentComplete { result } => {
                            agent_state.status = AgentStatus::Completed(Some(result.clone()));
                            is_lifecycle_action = true;
                            
                            // [NEW] RSI LOOP: Evaluation & Crystallization
                            evaluate_and_crystallize(service, agent_state, session_id, result).await;

                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "agent__complete".to_string(),
                                    output: format!("Result: {}\nFitness: {:.2}", result, 0.0), // Placeholder fitness until eval completes
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
                                    session_id: session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "chat__reply".to_string(),
                                    output: message.clone(),
                                });
                            }
                            log::info!("Agent Sent Chat Reply (Yielding Control)");
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
                    let _ = service.append_chat_to_scs(session_id, &sys_msg, block_height).await?;
                    success = true; 
                }
                Err(e) => {
                    success = false;
                    error_msg = Some(e.to_string());
                    
                    // [NEW] Mark as Failed to prevent retry loop if deterministic error
                    if !req_hash_hex.is_empty() {
                        agent_state.tool_execution_log.insert(req_hash_hex.clone(), ToolCallStatus::Failed(e.to_string()));
                    }
                }
            }
        }
        Err(e) => {
             error_msg = Some(format!("Failed to parse tool call: {}", e));
        }
    }

    // 4. Trace Log
    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        final_visual_phash,
        format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        tool_call_result,
        success,
        error_msg.clone(),
        current_tool_name.clone(), // This is a bit loose but works for MVP logging
        service.event_sender.clone(),
    )?;

    if success || is_lifecycle_action {
        agent_state.consecutive_failures = 0;
    } else {
        agent_state.consecutive_failures += 1;
    }
    
    // [FIX] ONLY increment step count if NOT gated.
    // If we are gated, we must stay on the same step index (nonce) so the 
    // ApprovalToken (which signs that nonce) remains valid for the retry.
    // NOTE: This logic works because we removed the automatic increment from utils::goto_trace_log.
    if !is_gated {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None; 
    }
    
    let is_chat = current_tool_name == "chat__reply" || agent_state.mode == crate::agentic::desktop::types::AgentMode::Chat;
    
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running && !is_chat {
        if agent_state.execution_queue.is_empty() {
             agent_state.status = AgentStatus::Completed(None);
             if let Some(tx) = &service.event_sender {
                  let _ = tx.send(KernelEvent::AgentActionResult {
                      session_id: session_id, 
                      step_index: agent_state.step_count,
                      tool_name: "system::max_steps_reached".to_string(),
                      output: "Max steps reached. Task completed.".to_string(),
                  });
             }
        }
    }
    
    Ok(())
}

async fn handle_refusal(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
    session_id: [u8; 32],
    visual_phash: [u8; 32],
    reason: &str,
) -> Result<(), TransactionError> {
    log::warn!("Agent Refusal Intercepted: {}", reason);
    
    goto_trace_log(
        agent_state,
        state,
        key,
        session_id,
        visual_phash,
        "[Refusal Intercepted]".to_string(),
        reason.to_string(),
        true,
        None,
        "system::refusal".to_string(),
        service.event_sender.clone(),
    )?;
    
    // [FIX] Increment step manually for refusal too, to avoid loop
    agent_state.step_count += 1;
    
    agent_state.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
    agent_state.consecutive_failures = 0; 
    state.insert(key, &codec::to_bytes_canonical(agent_state)?)?;
    
    if let Some(tx) = &service.event_sender {
        let _ = tx.send(KernelEvent::AgentActionResult {
            session_id: session_id,
            step_index: agent_state.step_count,
            tool_name: "system::refusal".to_string(),
            output: reason.to_string(),
        });
    }
    Ok(())
}

async fn evaluate_and_crystallize(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    result: &str,
) {
    if let Some(eval) = &service.evaluator {
        log::info!("Agent Complete. Running fitness evaluation...");
        
        let history = service.hydrate_session_history(session_id).unwrap_or_default();
        let reconstructed_trace: Vec<ioi_types::app::agentic::StepTrace> = history.iter().enumerate().map(|(i, msg)| {
             ioi_types::app::agentic::StepTrace {
                 session_id: session_id,
                 step_index: i as u32,
                 visual_hash: [0;32],
                 full_prompt: format!("{}: {}", msg.role, msg.content),
                 raw_output: msg.content.clone(),
                 success: true, 
                 error: None,
                 cost_incurred: 0,
                 fitness_score: None,
                 timestamp: msg.timestamp / 1000,
             }
        }).collect();

        let contract = IntentContract {
            max_price: agent_state.budget + agent_state.tokens_used,
            deadline_epoch: 0,
            min_confidence_score: 80,
            allowed_providers: vec![],
            outcome_type: OutcomeType::Result,
            optimize_for: OptimizationObjective::Reliability,
        };
        
        if let Ok(report) = eval.evaluate(&reconstructed_trace, &contract).await {
            log::info!(
                "Evaluation Complete. Score: {:.2}. Rationale: {}", 
                report.score, report.rationale
            );
            
            if report.score >= 0.8 && report.passed_hard_constraints {
                if let Some(opt) = &service.optimizer {
                    log::info!("High fitness detected! Crystallizing skill...");
                    
                    let trace_hash_bytes = ioi_crypto::algorithms::hash::sha256(result.as_bytes()).unwrap_or([0u8; 32]);
                    let mut trace_hash_arr = [0u8; 32];
                    trace_hash_arr.copy_from_slice(trace_hash_bytes.as_ref());
                    
                    if let Ok(skill) = opt.crystallize_skill_internal(session_id, trace_hash_arr).await {
                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(KernelEvent::SystemUpdate {
                                component: "Optimizer".to_string(),
                                status: format!("Crystallized skill '{}' (Fitness: {:.2})", skill.definition.name, report.score),
                            });
                        }
                    }
                }
            }
        }
    }
}