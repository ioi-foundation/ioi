// Path: crates/services/src/agentic/desktop/service/actions/resume.rs

use super::checks::requires_visual_integrity;
use super::evaluation::evaluate_and_crystallize;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::helpers::default_safe_policy;
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, ExecutionTier};
use crate::agentic::desktop::utils::compute_phash;
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;

use crate::agentic::desktop::middleware;

use hex;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::KernelEvent;
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

/// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    // 1. Load Canonical Request Bytes
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?;

    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    // 2. Deserialize Tool FIRST
    let tool: AgentTool = serde_json::from_slice(tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;

    // 3. Visual Guard: Context Drift Check
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    if requires_visual_integrity(&tool) {
        let current_bytes = service.gui.capture_raw_screen().await.unwrap_or_default();
        let current_phash = compute_phash(&current_bytes).unwrap_or([0u8; 32]);
        let drift = hamming_distance(&pending_vhash, &current_phash);

        if drift > 30 {
            log::warn!("Context Drift Detected (Dist: {}). Aborting Resume.", drift);
            let key = get_state_key(&session_id);
            goto_trace_log(
                agent_state,
                state,
                &key,
                session_id,
                current_phash,
                "[Resumed Action]".to_string(),
                "ABORTED: Visual Context Drifted.".to_string(),
                false,
                Some("Context Drift".to_string()),
                "system::context_drift".to_string(),
                service.event_sender.clone(),
                None,
            )?;

            agent_state.pending_tool_jcs = None;
            agent_state.pending_tool_hash = None;
            agent_state.pending_visual_hash = None;
            agent_state.pending_tool_call = None;
            agent_state.pending_approval = None;
            agent_state.status = AgentStatus::Running;

            state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
            return Ok(());
        }
    } else {
        log::info!(
            "Skipping visual drift check for non-spatial tool (Hash: {}).",
            hex::encode(&tool_hash[0..4])
        );
    }

    service.restore_visual_context(pending_vhash).await?;

    let token = agent_state
        .pending_approval
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing approval token".into()))?;

    if token.request_hash != tool_hash {
        return Err(TransactionError::Invalid(
            "Approval token hash mismatch".into(),
        ));
    }

    agent_state.current_tier = ExecutionTier::VisualForeground;

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // Focus Guard: approval UX can steal focus to Autopilot shell.
    // For resumed spatial actions, force-focus the target surface before clicking.
    if requires_visual_integrity(&tool) {
        if let Some(target) = &agent_state.target {
            let hint = target.app_hint.as_deref().unwrap_or("").trim();
            if !hint.is_empty() {
                let hint_lower = hint.to_lowercase();
                let matches_target = |fg: &ioi_api::vm::drivers::os::WindowInfo| {
                    let fg_title = fg.title.to_lowercase();
                    let fg_app = fg.app_name.to_lowercase();
                    fg_title.contains(&hint_lower) || fg_app.contains(&hint_lower)
                };

                let mut fg_info = os_driver.get_active_window_info().await.unwrap_or(None);
                let mut is_target_focused = fg_info.as_ref().map(matches_target).unwrap_or(false);

                if !is_target_focused {
                    log::info!(
                        "Resume focus guard: foreground drifted. Attempting focus to '{}'",
                        hint
                    );

                    let mut focus_queries = vec![hint.to_string()];
                    if let Some(pattern) = target.title_pattern.as_deref().map(str::trim) {
                        if !pattern.is_empty()
                            && !focus_queries
                                .iter()
                                .any(|q| q.eq_ignore_ascii_case(pattern))
                        {
                            focus_queries.push(pattern.to_string());
                        }
                    }

                    for query in focus_queries {
                        match os_driver.focus_window(&query).await {
                            Ok(true) => {
                                // Give WM time to apply focus before injecting input.
                                sleep(Duration::from_millis(180)).await;
                                fg_info = os_driver.get_active_window_info().await.unwrap_or(None);
                                is_target_focused =
                                    fg_info.as_ref().map(matches_target).unwrap_or(false);
                                if is_target_focused {
                                    break;
                                }
                            }
                            Ok(false) => {
                                log::warn!("Resume focus guard: no window matched '{}'", query);
                            }
                            Err(e) => {
                                log::warn!(
                                    "Resume focus guard: focus_window failed for '{}': {}",
                                    query,
                                    e
                                );
                            }
                        }
                    }

                    if !is_target_focused {
                        if let Some(fg) = fg_info {
                            log::warn!(
                                "Resume focus guard: still unfocused after attempts. Foreground is '{}' ({}) while target is '{}'.",
                                fg.title,
                                fg.app_name,
                                hint
                            );
                        } else {
                            log::warn!(
                                "Resume focus guard: unable to verify foreground window after focus attempts for '{}'.",
                                hint
                            );
                        }
                    }
                }
            }
        }
    }

    // Execute with SNAPSHOT MAP
    let (success, out, err) = match service
        .handle_action_execution(
            tool.clone(),
            session_id,
            agent_state.step_count,
            pending_vhash,
            &rules,
            &agent_state,
            &os_driver,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => (false, None, Some(e.to_string())),
    };

    let output_str = out
        .clone()
        .unwrap_or_else(|| err.clone().unwrap_or_default());
    let key = get_state_key(&session_id);

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        pending_vhash,
        "[Resumed Action]".to_string(),
        output_str.clone(),
        success,
        err.clone(),
        "resumed_action".to_string(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    let content = if success {
        out.unwrap_or_else(|| "Action executed successfully.".to_string())
    } else {
        format!(
            "Action Failed: {}",
            err.unwrap_or("Unknown error".to_string())
        )
    };

    let msg = ioi_types::app::agentic::ChatMessage {
        role: "tool".to_string(),
        content: content.clone(), // Clone for content check
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };
    service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;

    // Clear pending state
    agent_state.pending_tool_jcs = None;
    agent_state.pending_tool_hash = None;
    agent_state.pending_visual_hash = None;
    agent_state.pending_tool_call = None;
    agent_state.pending_approval = None;

    // [FIX] Reflexive Agent State Update (Ported from process.rs)
    // Check if the resumed action output a completion signal
    let mut reflexive_completion = false;
    if success {
        if content.contains("agent_complete") || content.contains("agent__complete") {
            if let Some(json_start) = content.find('{') {
                if let Some(json_end) = content.rfind('}') {
                    if json_end > json_start {
                        let potential_json = &content[json_start..=json_end];
                        if let Ok(detected_tool) = middleware::normalize_tool_call(potential_json) {
                            if let AgentTool::AgentComplete { result } = detected_tool {
                                log::info!("Reflexive Agent (Resume): Detected completion signal in tool output.");

                                agent_state.status = AgentStatus::Completed(Some(result.clone()));
                                reflexive_completion = true;

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

                                evaluate_and_crystallize(service, agent_state, session_id, &result)
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

    if !reflexive_completion {
        match &tool {
            AgentTool::AgentComplete { result } => {
                agent_state.status = AgentStatus::Completed(Some(result.clone()));
                evaluate_and_crystallize(service, agent_state, session_id, result).await;

                if let Some(tx) = &service.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id: session_id,
                        step_index: agent_state.step_count,
                        tool_name: "agent__complete".to_string(),
                        output: format!("Result: {}\nFitness: {:.2}", result, 0.0),
                        // [NEW] Authoritative Status
                        agent_status: get_status_str(&agent_state.status),
                    });
                }
            }
            AgentTool::ChatReply { message } => {
                agent_state.status = AgentStatus::Paused("Waiting for user input".to_string());

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
            _ => {
                // For standard actions, just return to running state
                agent_state.status = AgentStatus::Running;
            }
        }
    }

    agent_state.step_count += 1;

    if success {
        agent_state.consecutive_failures = 0;
    }
    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
