// Path: crates/services/src/agentic/desktop/service/actions/resume.rs

use super::checks::requires_visual_integrity;
use super::evaluation::evaluate_and_crystallize;
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
};
use crate::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, classify_failure,
    emit_routing_receipt, escalation_path_for_failure, extract_artifacts, latest_failure_class,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
    TierRoutingDecision,
};
use crate::agentic::desktop::service::step::helpers::{
    default_safe_policy, should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_gate_approved, mark_incident_wait_for_user, should_enter_incident_recovery,
    start_or_continue_incident_recovery, IncidentDirective,
};
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::desktop::utils::compute_phash;
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;

use crate::agentic::desktop::middleware;

use hex;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, RoutingReceiptEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

const RESUME_DRIFT_THRESHOLD: u32 = 48;

/// Helper to get a string representation of the agent status for event emission.
fn get_status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("error_class=missingdependency")
        || (lower.contains("wmctrl")
            && (lower.contains("no such file")
                || lower.contains("not found")
                || lower.contains("missing dependency")))
}

fn compute_context_phash(
    image_bytes: &[u8],
    window: Option<&ioi_api::vm::drivers::os::WindowInfo>,
) -> [u8; 32] {
    if let Some(cropped) = compute_window_cropped_phash(image_bytes, window) {
        return cropped;
    }
    compute_phash(image_bytes).unwrap_or([0u8; 32])
}

fn compute_window_cropped_phash(
    image_bytes: &[u8],
    window: Option<&ioi_api::vm::drivers::os::WindowInfo>,
) -> Option<[u8; 32]> {
    use image_hasher::{HashAlg, HasherConfig};

    let window = window?;
    if window.width <= 0 || window.height <= 0 {
        return None;
    }

    let img = image::load_from_memory(image_bytes).ok()?;
    let img_w = img.width() as i32;
    let img_h = img.height() as i32;
    if img_w <= 0 || img_h <= 0 {
        return None;
    }

    let x1 = window.x.clamp(0, img_w);
    let y1 = window.y.clamp(0, img_h);
    let x2 = (window.x + window.width).clamp(0, img_w);
    let y2 = (window.y + window.height).clamp(0, img_h);
    if x2 <= x1 || y2 <= y1 {
        return None;
    }

    let cropped = img.crop_imm(x1 as u32, y1 as u32, (x2 - x1) as u32, (y2 - y1) as u32);
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let hash = hasher.hash_image(&cropped);
    let hash_bytes = hash.as_bytes();

    let mut out = [0u8; 32];
    let len = hash_bytes.len().min(32);
    out[..len].copy_from_slice(&hash_bytes[..len]);
    Some(out)
}

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
) -> Result<(), TransactionError> {
    let pre_state_summary = build_state_summary(agent_state);
    let routing_decision = TierRoutingDecision {
        tier: agent_state.current_tier,
        reason_code: "resume_preserve_tier",
        source_failure: latest_failure_class(agent_state),
    };
    let mut policy_decision = "approved".to_string();
    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    let mut verification_checks = Vec::new();
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;

    // 1. Load Canonical Request Bytes
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?
        .clone();

    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    // 2. Deserialize Tool FIRST
    let tool: AgentTool = serde_json::from_slice(&tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;
    let (tool_name, tool_args) = canonical_tool_identity(&tool);
    let action_json = serde_json::to_string(&tool).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        env!("CARGO_PKG_VERSION"),
    );
    let retry_intent_hash = canonical_retry_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        env!("CARGO_PKG_VERSION"),
    );

    // 3. Validate approval token before executing anything.
    // Runtime secret retries for sys__install_package are allowed without approval token.
    if let Some(token) = agent_state.pending_approval.as_ref() {
        if token.request_hash != tool_hash {
            return Err(TransactionError::Invalid(
                "Approval token hash mismatch".into(),
            ));
        }
        mark_gate_approved(state, session_id)?;
    } else if !matches!(tool, AgentTool::SysInstallPackage { .. }) {
        return Err(TransactionError::Invalid("Missing approval token".into()));
    } else {
        verification_checks.push("resume_without_approval_runtime_secret=true".to_string());
    }

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // 4. Visual Guard: Context Drift Check (typed, recoverable).
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    let mut precheck_error: Option<String> = None;
    let mut log_visual_hash = pending_vhash;

    if requires_visual_integrity(&tool) {
        let current_bytes = service.gui.capture_raw_screen().await.unwrap_or_default();
        let active_window = os_driver.get_active_window_info().await.unwrap_or(None);
        let current_phash = compute_context_phash(&current_bytes, active_window.as_ref());
        log_visual_hash = current_phash;
        let drift = hamming_distance(&pending_vhash, &current_phash);
        verification_checks.push(format!("resume_drift_distance={}", drift));

        if drift > RESUME_DRIFT_THRESHOLD {
            log::warn!("Context Drift Detected before resume (Dist: {}).", drift);
            precheck_error = Some(format!(
                "ERROR_CLASS=ContextDrift Visual context drift detected before resume (distance={}).",
                drift
            ));
        }
    } else {
        log::info!(
            "Skipping visual drift check for non-spatial tool (Hash: {}).",
            hex::encode(&tool_hash[0..4])
        );
    }

    if precheck_error.is_none() {
        if let Err(e) = service.restore_visual_context(pending_vhash).await {
            precheck_error = Some(format!(
                "ERROR_CLASS=ContextDrift Failed to restore visual context: {}",
                e
            ));
        }
    }

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);

    // Focus Guard: approval UX can steal focus to Autopilot shell.
    // For resumed spatial actions, force-focus the target surface before clicking.
    if precheck_error.is_none() && requires_visual_integrity(&tool) {
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
                                let err = e.to_string();
                                if is_missing_focus_dependency_error(&err) {
                                    precheck_error = Some(format!(
                                        "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                                        query, err
                                    ));
                                    break;
                                }
                                log::warn!(
                                    "Resume focus guard: focus_window failed for '{}': {}",
                                    query,
                                    err
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

    // Execute with SNAPSHOT MAP unless prechecks failed.
    let (success, out, err) = match precheck_error {
        Some(err) => (false, None, Some(err)),
        None => match service
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
        },
    };
    if let Some(err_msg) = err.as_deref() {
        if err_msg.to_lowercase().contains("blocked by policy") {
            policy_decision = "denied".to_string();
        }
    }
    let is_install_package_tool = matches!(tool, AgentTool::SysInstallPackage { .. });
    let clarification_required = !success
        && err
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && err
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            err.as_deref(),
        )?;
        // Drop any queued remediation actions while awaiting credentials.
        agent_state.execution_queue.clear();
    }

    if clarification_required {
        awaiting_clarification = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            err.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
    }

    let output_str = out
        .clone()
        .unwrap_or_else(|| err.clone().unwrap_or_default());
    let key = get_state_key(&session_id);

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        log_visual_hash,
        "[Resumed Action]".to_string(),
        output_str.clone(),
        success,
        err.clone(),
        "resumed_action".to_string(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
    )?;

    let content = if success {
        out.as_deref()
            .unwrap_or("Action executed successfully.")
            .to_string()
    } else {
        format!(
            "Action Failed: {}",
            err.as_deref().unwrap_or("Unknown error")
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

    if awaiting_sudo_password {
        agent_state.pending_tool_jcs = Some(tool_jcs.clone());
        agent_state.pending_tool_hash = Some(tool_hash);
        agent_state.pending_visual_hash = Some(pending_vhash);
        agent_state.pending_tool_call = Some(action_json.clone());
        agent_state.pending_approval = None;
        agent_state.execution_queue.clear();
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
                .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        if let Some(tx) = &service.event_sender {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: "sys__install_package".to_string(),
                output: err.clone().unwrap_or_default(),
                agent_status: "Paused".to_string(),
            });
        }
        verification_checks.push("awaiting_sudo_password=true".to_string());
    } else if awaiting_clarification {
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
        agent_state.execution_queue.clear();
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content:
                "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
                    .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    } else {
        // Clear pending state
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
    }

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

    if !reflexive_completion && !awaiting_sudo_password && !awaiting_clarification {
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
            AgentTool::SysChangeDir { .. } => {
                if success {
                    agent_state.working_directory = content.clone();
                }
                agent_state.status = AgentStatus::Running;
            }
            AgentTool::OsLaunchApp { app_name } => {
                if success
                    && should_auto_complete_open_app_goal(
                        &agent_state.goal,
                        app_name,
                        agent_state
                            .target
                            .as_ref()
                            .and_then(|target| target.app_hint.as_deref()),
                    )
                {
                    let summary = format!("Opened {}.", app_name);
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    evaluate_and_crystallize(service, agent_state, session_id, &summary).await;
                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::AgentActionResult {
                            session_id,
                            step_index: agent_state.step_count,
                            tool_name: "agent__complete".to_string(),
                            output: summary,
                            agent_status: get_status_str(&agent_state.status),
                        });
                    }
                } else {
                    agent_state.status = AgentStatus::Running;
                }
            }
            _ => {
                // For standard actions, just return to running state
                agent_state.status = AgentStatus::Running;
            }
        }
    }

    if !awaiting_sudo_password && !awaiting_clarification {
        let incident_directive = advance_incident_after_action_outcome(
            service,
            state,
            agent_state,
            session_id,
            &retry_intent_hash,
            &tool_jcs,
            success,
            block_height,
            err.as_deref(),
            &mut verification_checks,
        )
        .await?;
        if matches!(incident_directive, IncidentDirective::QueueActions) {
            remediation_queued = true;
            stop_condition_hit = false;
            escalation_path = None;
            agent_state.status = AgentStatus::Running;
        }
    }

    if success {
        agent_state.recent_actions.clear();
    } else if !awaiting_sudo_password && !awaiting_clarification {
        failure_class = classify_failure(err.as_deref(), &policy_decision);
        if let Some(class) = failure_class {
            let target_id = agent_state.target.as_ref().and_then(|target| {
                target
                    .app_hint
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| {
                        target
                            .title_pattern
                            .as_deref()
                            .filter(|v| !v.trim().is_empty())
                    })
            });
            let window_fingerprint = if log_visual_hash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(log_visual_hash))
            };
            let attempt_key = build_attempt_key(
                &retry_intent_hash,
                routing_decision.tier,
                &tool_name,
                target_id,
                window_fingerprint.as_deref(),
            );
            let (repeat_count, attempt_key_hash) =
                register_failure_attempt(agent_state, class, &attempt_key);
            let budget_remaining = retry_budget_remaining(repeat_count);
            let blocked_without_change = should_block_retry_without_change(class, repeat_count);
            verification_checks.push(format!("attempt_repeat_count={}", repeat_count));
            verification_checks.push(format!("attempt_key_hash={}", attempt_key_hash));
            verification_checks.push(format!(
                "attempt_retry_budget_remaining={}",
                budget_remaining
            ));
            verification_checks.push(format!(
                "attempt_retry_blocked_without_change={}",
                blocked_without_change
            ));
            let incident_state = load_incident_state(state, &session_id)?;
            if should_enter_incident_recovery(
                Some(class),
                &policy_decision,
                stop_condition_hit,
                incident_state.as_ref(),
            ) {
                let (resolved_retry_hash, recovery_tool_name, recovery_tool_jcs): (
                    String,
                    String,
                    Vec<u8>,
                ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active) {
                    (
                        existing.root_retry_hash.clone(),
                        existing.root_tool_name.clone(),
                        existing.root_tool_jcs.clone(),
                    )
                } else {
                    (
                        retry_intent_hash.clone(),
                        tool_name.clone(),
                        tool_jcs.clone(),
                    )
                };
                remediation_queued = matches!(
                    start_or_continue_incident_recovery(
                        service,
                        state,
                        agent_state,
                        session_id,
                        block_height,
                        &rules,
                        &resolved_retry_hash,
                        &recovery_tool_name,
                        &recovery_tool_jcs,
                        class,
                        err.as_deref(),
                        &mut verification_checks,
                    )
                    .await?,
                    IncidentDirective::QueueActions
                );
            }

            let install_lookup_failure = err
                .as_deref()
                .map(|msg| requires_wait_for_clarification(&tool_name, msg))
                .unwrap_or(false);

            if remediation_queued {
                stop_condition_hit = false;
                escalation_path = None;
                agent_state.status = AgentStatus::Running;
            } else if install_lookup_failure {
                stop_condition_hit = true;
                escalation_path = Some("wait_for_clarification".to_string());
                awaiting_clarification = true;
                mark_incident_wait_for_user(
                    state,
                    session_id,
                    "wait_for_clarification",
                    FailureClass::UserInterventionNeeded,
                    err.as_deref(),
                )?;
                agent_state.execution_queue.clear();
                agent_state.status = AgentStatus::Paused(
                    "Waiting for clarification on target identity.".to_string(),
                );
            } else if matches!(class, FailureClass::UserInterventionNeeded) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(
                    "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                );
            } else if blocked_without_change {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry blocked: unchanged AttemptKey for {}",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            } else if should_trip_retry_guard(class, repeat_count) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry guard tripped after repeated {} failures",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            }
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_resume=true"));
    verification_checks.push(format!("awaiting_sudo_password={}", awaiting_sudo_password));
    verification_checks.push(format!("awaiting_clarification={}", awaiting_clarification));
    verification_checks.push(format!("remediation_queued={}", remediation_queued));
    verification_checks.push(format!("stop_condition_hit={}", stop_condition_hit));
    verification_checks.push(format!(
        "routing_tier_selected={}",
        tier_as_str(routing_decision.tier)
    ));
    verification_checks.push(format!(
        "routing_reason_code={}",
        routing_decision.reason_code
    ));
    verification_checks.push(format!(
        "routing_source_failure={}",
        routing_decision
            .source_failure
            .map(|class| class.as_str().to_string())
            .unwrap_or_else(|| "None".to_string())
    ));
    verification_checks.push(format!(
        "routing_tier_matches_pre_state={}",
        pre_state_summary.tier == tier_as_str(routing_decision.tier)
    ));
    if let Some(class) = failure_class {
        verification_checks.push(format!("failure_class={}", class.as_str()));
    }

    if !awaiting_sudo_password && !awaiting_clarification {
        agent_state.step_count += 1;
    }

    if success {
        if !stop_condition_hit {
            agent_state.consecutive_failures = 0;
        }
    } else if requires_visual_integrity(&tool) {
        // Keep resumed spatial failures in a high-observability tier so the next step
        // can recover with fresh visual grounding instead of dropping back to headless.
        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        pre_state: pre_state_summary,
        action_json,
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        failure_class_name,
        intent_class: incident_fields.intent_class,
        incident_id: incident_fields.incident_id,
        incident_stage: incident_fields.incident_stage,
        strategy_name: incident_fields.strategy_name,
        strategy_node: incident_fields.strategy_node,
        gate_state: incident_fields.gate_state,
        resolution_action: incident_fields.resolution_action,
        stop_condition_hit,
        escalation_path,
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
