// Path: crates/services/src/agentic/desktop/service/actions/process.rs

use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::keys::{get_session_result_key, get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::helpers::default_safe_policy;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, SessionResult, ToolCallStatus};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use hex;
use ioi_api::state::StateAccess;
use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionContext, ActionRequest, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_jcs;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::evaluation::evaluate_and_crystallize;

/// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn mark_system_fail_status(status: &mut AgentStatus, reason: impl Into<String>) {
    *status = AgentStatus::Failed(reason.into());
}

fn enforce_system_fail_terminal_status(
    current_tool_name: &str,
    status: &mut AgentStatus,
    error_msg: Option<&str>,
) -> bool {
    if current_tool_name != "system__fail" {
        return false;
    }

    if !matches!(status, AgentStatus::Failed(_)) {
        let fallback_reason = error_msg.unwrap_or("Agent requested explicit failure");
        mark_system_fail_status(status, fallback_reason.to_string());
    }

    true
}

pub async fn handle_refusal(
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
        None,
    )?;
    agent_state.step_count += 1;
    agent_state.status = AgentStatus::Paused(format!("Model Refusal: {}", reason));
    agent_state.consecutive_failures = 0;
    state.insert(key, &codec::to_bytes_canonical(agent_state)?)?;
    Ok(())
}

pub async fn process_tool_output(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    tool_call_result: String,
    final_visual_phash: [u8; 32],
    strategy_used: String,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    let key = get_state_key(&session_id);
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    // 1. Raw Refusal Interceptor
    // This remains string-based because refusals often break JSON structure.
    if tool_call_result.contains("\"name\":\"system::refusal\"")
        || tool_call_result.contains("\"name\": \"system::refusal\"")
    {
        let reason = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&tool_call_result) {
            val.get("arguments")
                .and_then(|a| a.get("message").or_else(|| a.get("reason")))
                .and_then(|m| m.as_str())
                .unwrap_or("Model refused.")
                .to_string()
        } else {
            "Model refused (raw match).".to_string()
        };
        handle_refusal(
            service,
            state,
            agent_state,
            &key,
            session_id,
            final_visual_phash,
            &reason,
        )
        .await?;
        return Ok(());
    }

    // 2. Normalize & Expand
    // This converts the raw string into a strictly typed Rust Enum.
    let tool_call = middleware::normalize_tool_call(&tool_call_result);

    // Check for Skill / Macro Match
    if let Ok(AgentTool::Dynamic(ref val)) = tool_call {
        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            if let Some((macro_def, skill_hash)) = service.fetch_skill_macro(name) {
                let args_map = val
                    .get("arguments")
                    .and_then(|a| a.as_object())
                    .cloned()
                    .unwrap_or_default();
                match service.expand_macro(&macro_def, &args_map) {
                    Ok(steps) => {
                        agent_state.execution_queue.extend(steps);
                        agent_state.active_skill_hash = Some(skill_hash);
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
                            Some(skill_hash),
                        )?;
                        agent_state.step_count += 1;
                        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
                        return Ok(());
                    }
                    Err(e) => {
                        log::error!("Macro expansion error: {}", e);
                        return Ok(());
                    }
                }
            }
        }
    }

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
        ([0u8; 32], String::new())
    };

    if !req_hash_hex.is_empty() {
        if let Some(status) = agent_state.tool_execution_log.get(&req_hash_hex) {
            if matches!(status, ToolCallStatus::Executed(_)) {
                log::info!("Skipping idempotent step");
                agent_state.step_count += 1;
                agent_state.pending_tool_call = None;
                agent_state.pending_tool_jcs = None;
                agent_state.pending_approval = None;
                agent_state.status = AgentStatus::Running;
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

    // We determine the tool name from the type, for logging.
    let mut current_tool_name = "unknown".to_string();

    match tool_call {
        Ok(tool) => {
            let mcp = service
                .mcp
                .clone()
                .unwrap_or_else(|| Arc::new(McpManager::new()));
            let lens_registry_arc = service.lens_registry.clone();
            let os_driver = service
                .os_driver
                .clone()
                .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

            // Set name for logging
            if let AgentTool::ChatReply { .. } = &tool {
                current_tool_name = "chat__reply".to_string();
            }
            if let AgentTool::SystemFail { .. } = &tool {
                current_tool_name = "system__fail".to_string();
            }
            if let AgentTool::AgentComplete { .. } = &tool {
                current_tool_name = "agent__complete".to_string();
            }
            if let AgentTool::SysExec { .. } = &tool {
                current_tool_name = "sys__exec".to_string();
            }
            if let AgentTool::SysChangeDir { .. } = &tool {
                current_tool_name = "sys__change_directory".to_string();
            }
            if let AgentTool::Dynamic(val) = &tool {
                if let Some(n) = val.get("name").and_then(|s| s.as_str()) {
                    current_tool_name = n.to_string();
                }
            }

            let target_hash_opt = agent_state
                .pending_approval
                .as_ref()
                .and_then(|t| t.visual_hash)
                .or(agent_state.last_screen_phash);
            if let Some(target_hash) = target_hash_opt {
                let _ = service.restore_visual_context(target_hash).await;
            }

            // Construct executor
            let executor = ToolExecutor::new(
                service.gui.clone(),
                os_driver.clone(),
                service.terminal.clone(),
                service.browser.clone(),
                mcp,
                service.event_sender.clone(),
                Some(lens_registry_arc),
                service.reasoning_inference.clone(),
            );

            // Execute Action
            match service
                .handle_action_execution(
                    tool.clone(),
                    session_id,
                    agent_state.step_count,
                    final_visual_phash,
                    &rules,
                    &agent_state,
                    &os_driver,
                )
                .await
            {
                Ok((s, history_entry, e)) => {
                    success = s;
                    error_msg = e;

                    if s && !req_hash_hex.is_empty() {
                        agent_state.tool_execution_log.insert(
                            req_hash_hex.clone(),
                            ToolCallStatus::Executed("success".into()),
                        );
                        agent_state.pending_approval = None;
                        agent_state.pending_tool_jcs = None;
                    }

                    if s {
                        if let Some(entry) = history_entry.clone() {
                            let tool_msg = ioi_types::app::agentic::ChatMessage {
                                role: "tool".to_string(),
                                content: entry.clone(),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64,
                                trace_hash: None,
                            };
                            let _ = service
                                .append_chat_to_scs(session_id, &tool_msg, block_height)
                                .await?;

                            // [FIX] Reflexive Agent State Update
                            // If the output of a tool (like sys::exec running a script) contains a completion signal,
                            // update the state immediately. This handles "piggyback" completions authoritatively.
                            if entry.contains("agent_complete")
                                || entry.contains("agent__complete")
                                || entry.contains("system__fail")
                            {
                                if let Some(json_start) = entry.find('{') {
                                    if let Some(json_end) = entry.rfind('}') {
                                        if json_end > json_start {
                                            let potential_json = &entry[json_start..=json_end];
                                            if let Ok(detected_tool) =
                                                middleware::normalize_tool_call(potential_json)
                                            {
                                                match detected_tool {
                                                    AgentTool::AgentComplete { result } => {
                                                        log::info!("Reflexive Agent: Detected completion signal in tool output.");

                                                        // 1. Authoritative State Transition
                                                        agent_state.status = AgentStatus::Completed(
                                                            Some(result.clone()),
                                                        );
                                                        is_lifecycle_action = true;

                                                        // 2. Broadcast Event with STATUS
                                                        if let Some(tx) = &service.event_sender {
                                                            let _ = tx.send(
                                                                KernelEvent::AgentActionResult {
                                                                    session_id: session_id,
                                                                    step_index: agent_state
                                                                        .step_count,
                                                                    tool_name: "agent__complete"
                                                                        .to_string(),
                                                                    output: result.clone(),
                                                                    // [NEW] Authoritative Status
                                                                    agent_status: get_status_str(
                                                                        &agent_state.status,
                                                                    ),
                                                                },
                                                            );
                                                        }

                                                        // 3. Crystallize Skill (Evolution)
                                                        evaluate_and_crystallize(
                                                            service,
                                                            agent_state,
                                                            session_id,
                                                            &result,
                                                        )
                                                        .await;
                                                    }
                                                    AgentTool::SystemFail { reason, .. } => {
                                                        log::info!("Reflexive Agent: Detected failure signal in tool output.");

                                                        mark_system_fail_status(
                                                            &mut agent_state.status,
                                                            reason.clone(),
                                                        );
                                                        is_lifecycle_action = true;

                                                        if let Some(tx) = &service.event_sender {
                                                            let _ = tx.send(
                                                                KernelEvent::AgentActionResult {
                                                                    session_id: session_id,
                                                                    step_index: agent_state
                                                                        .step_count,
                                                                    tool_name: "system__fail"
                                                                        .to_string(),
                                                                    output: format!(
                                                                        "Agent Failed: {}",
                                                                        reason
                                                                    ),
                                                                    agent_status: get_status_str(
                                                                        &agent_state.status,
                                                                    ),
                                                                },
                                                            );
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // --- ROBUST TYPED LIFECYCLE HANDLING ---
                    match &tool {
                        AgentTool::AgentComplete { result } => {
                            // If we already handled it reflexively above, this is just a no-op safety check
                            if !matches!(agent_state.status, AgentStatus::Completed(_)) {
                                agent_state.status = AgentStatus::Completed(Some(result.clone()));
                                is_lifecycle_action = true;

                                if let Some(tx) = &service.event_sender {
                                    let _ = tx.send(KernelEvent::AgentActionResult {
                                        session_id: session_id,
                                        step_index: agent_state.step_count,
                                        tool_name: "agent__complete".to_string(),
                                        output: result.clone(),
                                        // [NEW] Authoritative Status
                                        agent_status: get_status_str(&agent_state.status),
                                    });
                                }

                                evaluate_and_crystallize(service, agent_state, session_id, result)
                                    .await;
                            }
                        }
                        AgentTool::SysChangeDir { .. } => {
                            if s {
                                if let Some(new_cwd) = &history_entry {
                                    agent_state.working_directory = new_cwd.clone();
                                }
                            }
                        }
                        AgentTool::ChatReply { message } => {
                            agent_state.status =
                                AgentStatus::Paused("Waiting for user input".to_string());
                            is_lifecycle_action = true;

                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "chat__reply".to_string(),
                                    output: message.clone(),
                                    // [NEW] Authoritative Status
                                    agent_status: get_status_str(&agent_state.status),
                                });
                            }
                        }
                        AgentTool::SystemFail { reason, .. } => {
                            mark_system_fail_status(&mut agent_state.status, reason.clone());
                            is_lifecycle_action = true;

                            if let Some(tx) = &service.event_sender {
                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: "system__fail".to_string(),
                                    output: format!("Agent Failed: {}", reason),
                                    agent_status: get_status_str(&agent_state.status),
                                });
                            }
                        }
                        _ => {
                            // Standard tool execution, status remains Running (or changed by reflexive check above)
                            // We still emit the event for UI feedback
                            if let Some(tx) = &service.event_sender {
                                let output_str = if success {
                                    history_entry.unwrap_or_default()
                                } else {
                                    error_msg
                                        .clone()
                                        .unwrap_or_else(|| "Unknown error".to_string())
                                };

                                let _ = tx.send(KernelEvent::AgentActionResult {
                                    session_id: session_id,
                                    step_index: agent_state.step_count,
                                    tool_name: current_tool_name.clone(),
                                    output: output_str,
                                    // [NEW] Authoritative Status
                                    agent_status: get_status_str(&agent_state.status),
                                });
                            }
                        }
                    }
                }
                Err(TransactionError::PendingApproval(h)) => {
                    // Capture Canonical Context for Resume
                    let tool_jcs = serde_jcs::to_vec(&tool).unwrap();
                    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
                    let mut hash_arr = [0u8; 32];
                    hash_arr.copy_from_slice(tool_hash_bytes.as_ref());

                    agent_state.pending_tool_jcs = Some(tool_jcs);
                    agent_state.pending_tool_hash = Some(hash_arr);
                    agent_state.pending_visual_hash = Some(final_visual_phash);
                    agent_state.pending_tool_call = Some(tool_call_result.clone());
                    agent_state.last_screen_phash = Some(final_visual_phash);

                    is_gated = true;
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Paused("Waiting for approval".into());

                    let msg = format!("System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.", h);
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(session_id, &sys_msg, block_height)
                        .await?;
                    success = true;

                    // No event emitted here because the Firewall middleware already emitted FirewallInterception
                }
                Err(e) => {
                    success = false;
                    error_msg = Some(e.to_string());
                    if !req_hash_hex.is_empty() {
                        agent_state
                            .tool_execution_log
                            .insert(req_hash_hex.clone(), ToolCallStatus::Failed(e.to_string()));
                    }

                    // Emit failure event
                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::AgentActionResult {
                            session_id: session_id,
                            step_index: agent_state.step_count,
                            tool_name: current_tool_name.clone(),
                            output: format!("Execution Error: {}", e),
                            // [NEW] Authoritative Status
                            agent_status: get_status_str(&agent_state.status),
                        });
                    }
                }
            }
        }
        Err(e) => {
            error_msg = Some(format!("Failed to parse tool call: {}", e));

            // Emit parse failure event
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(KernelEvent::AgentActionResult {
                    session_id: session_id,
                    step_index: agent_state.step_count,
                    tool_name: "parser".to_string(),
                    output: format!("Parse Error: {}", e),
                    agent_status: get_status_str(&agent_state.status),
                });
            }
        }
    }

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
        current_tool_name.clone(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    if success || is_lifecycle_action {
        if current_tool_name != "system__fail" {
            agent_state.consecutive_failures = 0;
        }
    } else {
        agent_state.consecutive_failures += 1;
    }

    if enforce_system_fail_terminal_status(
        &current_tool_name,
        &mut agent_state.status,
        error_msg.as_deref(),
    ) {
        log::info!("SystemFail executed: Forcing IMMEDIATE escalation state (failures=3)");
        agent_state.consecutive_failures = 3;
    }

    if !is_gated {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_approval = None;
    }

    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running
    {
        agent_state.status = AgentStatus::Completed(None);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_fail_sets_failed_status() {
        let mut status = AgentStatus::Running;
        let changed = enforce_system_fail_terminal_status(
            "system__fail",
            &mut status,
            Some("Critical tool missing"),
        );

        assert!(changed);
        assert!(matches!(
            status,
            AgentStatus::Failed(ref reason) if reason.contains("Critical tool missing")
        ));
    }
}
