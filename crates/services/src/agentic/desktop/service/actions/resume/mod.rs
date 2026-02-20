// Path: crates/services/src/agentic/desktop/service/actions/resume/mod.rs

mod approvals;
mod execution;
mod focus;
mod hashing;
mod status;
mod visual;

use super::checks::requires_visual_integrity;
use super::evaluation::evaluate_and_crystallize;
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, pii, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    is_command_probe_intent, summarize_command_probe_output,
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
    default_safe_policy, is_live_external_research_goal, should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_gate_denied, mark_incident_wait_for_user, should_enter_incident_recovery,
    start_or_continue_incident_recovery, IncidentDirective,
};
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;

use crate::agentic::desktop::middleware;

use hex;
use ioi_api::state::StateAccess;
use ioi_pii::resolve_expected_request_hash;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, PiiReviewRequest};
use ioi_types::app::{KernelEvent, RoutingReceiptEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};

fn is_web_research_scope(agent_state: &AgentState) -> bool {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
        || is_live_external_research_goal(&agent_state.goal)
}

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    block_timestamp_ns: u64,
    call_context: ServiceCallContext<'_>,
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

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let mut rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let block_timestamp_ms = block_timestamp_ns / 1_000_000;
    let block_timestamp_secs = block_timestamp_ns / 1_000_000_000;
    let incident_state = load_incident_state(state, &session_id)?;
    let pending_gate_hash = incident_state
        .as_ref()
        .and_then(|incident| incident.pending_gate.as_ref())
        .and_then(|pending| hashing::parse_hash_hex(&pending.request_hash));
    let expected_request_hash = resolve_expected_request_hash(pending_gate_hash, tool_hash);
    let request_key = pii::review::request(&expected_request_hash);
    let pii_request: Option<PiiReviewRequest> = state
        .get(&request_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());

    // 3. Validate approval token before executing anything.
    // Runtime secret retries for sys__install_package are allowed without approval token.
    let approval = approvals::validate_and_apply(
        service,
        state,
        agent_state,
        session_id,
        &tool,
        tool_hash,
        expected_request_hash,
        pii_request.as_ref(),
        block_timestamp_ms,
        block_timestamp_secs,
        &mut rules,
        &mut verification_checks,
    )
    .await?;
    let scoped_exception_override_hash = approval.scoped_exception_override_hash;
    let explicit_pii_deny = approval.explicit_pii_deny;

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

    let (mut precheck_error, log_visual_hash) = visual::run_visual_prechecks(
        service,
        &os_driver,
        &tool,
        pending_vhash,
        &mut verification_checks,
    )
    .await;

    if explicit_pii_deny {
        mark_gate_denied(state, session_id)?;
        let deny_error = if pii_request.is_some() {
            "PII review denied by approver. Step failed closed.".to_string()
        } else {
            "Approval denied by approver. Step failed closed.".to_string()
        };
        let key = get_state_key(&session_id);
        goto_trace_log(
            agent_state,
            state,
            &key,
            session_id,
            pending_vhash,
            "[Resumed Action]".to_string(),
            deny_error.clone(),
            false,
            Some(deny_error.clone()),
            "resumed_action".to_string(),
            service.event_sender.clone(),
            agent_state.active_skill_hash,
        )?;

        let deny_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: if pii_request.is_some() {
                "System: PII review denied. Current step failed closed.".to_string()
            } else {
                "System: Approval denied. Current step failed closed.".to_string()
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        service
            .append_chat_to_scs(session_id, &deny_msg, block_height)
            .await?;

        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
        agent_state.status = AgentStatus::Running;
        agent_state.step_count = agent_state.step_count.saturating_add(1);
        agent_state.consecutive_failures = agent_state.consecutive_failures.saturating_add(1);
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        return Ok(());
    }

    // Focus Guard: approval UX can steal focus to Autopilot shell.
    // For resumed spatial actions, force-focus the target surface before clicking.
    if precheck_error.is_none() && requires_visual_integrity(&tool) {
        if let Some(err) = focus::ensure_target_focused_for_resume(&os_driver, agent_state).await {
            precheck_error = Some(err);
        }
    }

    // Execute with SNAPSHOT MAP unless prechecks failed.
    let has_precheck_error = precheck_error.is_some();
    let exec = execution::execute(
        service,
        state,
        agent_state,
        &os_driver,
        &tool,
        &rules,
        session_id,
        tool_hash,
        pending_vhash,
        scoped_exception_override_hash,
        has_precheck_error,
        precheck_error,
        pre_state_summary.step_index,
        block_height,
        call_context,
    )
    .await;
    let (mut success, mut out, mut err) = (exec.success, exec.out, exec.err);

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
                                        agent_status: status::status_str(&agent_state.status),
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
                        agent_status: status::status_str(&agent_state.status),
                    });
                }
            }
            AgentTool::ChatReply { message } => {
                agent_state.status = AgentStatus::Completed(Some(message.clone()));
                evaluate_and_crystallize(service, agent_state, session_id, message).await;

                if let Some(tx) = &service.event_sender {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id: session_id,
                        step_index: agent_state.step_count,
                        tool_name: "chat__reply".to_string(),
                        output: message.clone(),
                        // [NEW] Authoritative Status
                        agent_status: status::status_str(&agent_state.status),
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
                            agent_status: status::status_str(&agent_state.status),
                        });
                    }
                } else {
                    agent_state.status = AgentStatus::Running;
                }
            }
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
                if success && is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                    if let Some(summary) = out
                        .as_deref()
                        .and_then(|raw| summarize_command_probe_output(&tool, raw))
                    {
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        agent_state.execution_queue.clear();
                        evaluate_and_crystallize(service, agent_state, session_id, &summary).await;
                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index: agent_state.step_count,
                                tool_name: "agent__complete".to_string(),
                                output: summary,
                                agent_status: status::status_str(&agent_state.status),
                            });
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
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
            } else if is_web_research_scope(agent_state)
                && matches!(class, FailureClass::UnexpectedState)
            {
                // Keep web research autonomous under transient tool/schema instability.
                stop_condition_hit = false;
                escalation_path = None;
                success = true;
                err = None;
                out = Some(format!(
                    "Transient unexpected state while executing '{}'; continuing web research.",
                    tool_name
                ));
                agent_state.status = AgentStatus::Running;
                agent_state.recent_actions.clear();
                verification_checks.push("web_unexpected_retry_bypass=true".to_string());
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
