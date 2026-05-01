use super::*;
use crate::agentic::runtime::service::recovery::incident::mark_incident_wait_for_user;

#[derive(Debug)]
pub(super) struct QueueFailureHandlingOutcome {
    pub(super) failure_class: Option<FailureClass>,
    pub(super) stop_condition_hit: bool,
    pub(super) escalation_path: Option<String>,
    pub(super) remediation_queued: bool,
}

fn should_force_consecutive_failure_floor(class: FailureClass) -> bool {
    matches!(
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
    )
}

fn maybe_force_failure_streak_floor(agent_state: &mut AgentState, class: FailureClass) {
    if should_force_consecutive_failure_floor(class) {
        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
    }
}

pub(super) async fn apply_queue_failure_policies(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    routing_decision: &TierRoutingDecision,
    rules: &ActionRules,
    retry_intent_hash: &str,
    tool_name: &str,
    tool_jcs: &[u8],
    policy_decision: &str,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    is_gated: bool,
    awaiting_sudo_password: bool,
    awaiting_clarification: &mut bool,
    verification_checks: &mut Vec<String>,
) -> Result<QueueFailureHandlingOutcome, TransactionError> {
    let mut outcome = QueueFailureHandlingOutcome {
        failure_class: None,
        stop_condition_hit: false,
        escalation_path: None,
        remediation_queued: false,
    };

    if awaiting_sudo_password {
        outcome.failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        outcome.stop_condition_hit = true;
        outcome.escalation_path = Some("wait_for_sudo_password".to_string());
    }

    if !is_gated && !awaiting_sudo_password && !*awaiting_clarification {
        let incident_directive = advance_incident_after_action_outcome(
            service,
            state,
            agent_state,
            p.session_id,
            retry_intent_hash,
            tool_jcs,
            *success,
            block_height,
            err.as_deref(),
            verification_checks,
        )
        .await?;
        if matches!(incident_directive, IncidentDirective::QueueActions) {
            outcome.remediation_queued = true;
            outcome.stop_condition_hit = false;
            outcome.escalation_path = None;
            agent_state.status = AgentStatus::Running;
        }
    }

    if *success && !is_gated {
        agent_state.recent_actions.clear();
    } else if !*success && !awaiting_sudo_password && !*awaiting_clarification {
        let failure_intent_id = resolved_intent_id(agent_state);
        if is_completion_contract_error(err.as_deref()) {
            outcome.stop_condition_hit = true;
            outcome.escalation_path = Some("execution_contract_terminal".to_string());
            outcome.remediation_queued = false;
            agent_state.execution_queue.clear();
            let terminal_reason = err
                .clone()
                .unwrap_or_else(|| "ERROR_CLASS=ExecutionContractViolation".to_string());
            agent_state.status = AgentStatus::Failed(terminal_reason);
            verification_checks.push("cec_terminal_error=true".to_string());
        } else {
            agent_state.execution_ledger.record_execution_failure(
                Some(failure_intent_id),
                ExecutionStage::Execution,
                "ExecutionFailed",
            );
            outcome.failure_class = classify_failure(err.as_deref(), policy_decision);
            if let Some(class) = outcome.failure_class {
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
                let command_scope = agent_state
                    .resolved_intent
                    .as_ref()
                    .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
                    .unwrap_or(false);
                let raw_window_fingerprint = agent_state
                    .last_screen_phash
                    .filter(|hash| *hash != [0u8; 32])
                    .map(hex::encode);
                let window_fingerprint = canonical_attempt_window_fingerprint(
                    class,
                    command_scope,
                    raw_window_fingerprint.as_deref(),
                );
                let attempt_key = build_attempt_key(
                    retry_intent_hash,
                    routing_decision.tier,
                    tool_name,
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
                if is_web_research_scope(agent_state)
                    && matches!(class, FailureClass::TimeoutOrHang)
                {
                    let summary = format!(
                        "Web retrieval timed out while executing '{}'. Retry later or narrow the query/sources.",
                        tool_name
                    );
                    outcome.stop_condition_hit = true;
                    outcome.escalation_path = Some("web_timeout_fail_fast".to_string());
                    outcome.remediation_queued = false;
                    *success = true;
                    *err = None;
                    *out = Some(summary.clone());
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                    agent_state.status = AgentStatus::Completed(Some(summary));
                    verification_checks.push("web_timeout_fail_fast=true".to_string());
                } else {
                    let incident_state = load_incident_state(state, &p.session_id)?;
                    if should_enter_incident_recovery(
                        Some(class),
                        policy_decision,
                        outcome.stop_condition_hit,
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
                                retry_intent_hash.to_string(),
                                tool_name.to_string(),
                                tool_jcs.to_vec(),
                            )
                        };
                        outcome.remediation_queued = matches!(
                            start_or_continue_incident_recovery(
                                service,
                                state,
                                agent_state,
                                p.session_id,
                                block_height,
                                rules,
                                &resolved_retry_hash,
                                &recovery_tool_name,
                                &recovery_tool_jcs,
                                class,
                                err.as_deref(),
                                verification_checks,
                            )
                            .await?,
                            IncidentDirective::QueueActions
                        );
                    }

                    let install_lookup_failure = err
                        .as_deref()
                        .map(|msg| requires_wait_for_clarification(tool_name, msg))
                        .unwrap_or(false);

                    if outcome.remediation_queued {
                        outcome.stop_condition_hit = false;
                        outcome.escalation_path = None;
                        agent_state.status = AgentStatus::Running;
                    } else if install_lookup_failure {
                        outcome.stop_condition_hit = true;
                        outcome.escalation_path = Some("wait_for_clarification".to_string());
                        *awaiting_clarification = true;
                        mark_incident_wait_for_user(
                            state,
                            p.session_id,
                            "wait_for_clarification",
                            FailureClass::UserInterventionNeeded,
                            err.as_deref(),
                        )?;
                        agent_state.execution_queue.clear();
                        agent_state.status = AgentStatus::Paused(
                            "Waiting for clarification on target identity.".to_string(),
                        );
                    } else if matches!(class, FailureClass::UserInterventionNeeded) {
                        outcome.stop_condition_hit = true;
                        outcome.escalation_path =
                            Some(escalation_path_for_failure(class).to_string());
                        agent_state.status = AgentStatus::Paused(
                            "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                        );
                    } else if is_web_research_scope(agent_state)
                        && matches!(class, FailureClass::UnexpectedState)
                    {
                        // Keep web research autonomous under transient tool/schema instability.
                        outcome.stop_condition_hit = false;
                        outcome.escalation_path = None;
                        *success = true;
                        *err = None;
                        *out = Some(format!(
                            "Transient unexpected state while executing '{}'; continuing web research.",
                            tool_name
                        ));
                        agent_state.status = AgentStatus::Running;
                        agent_state.recent_actions.clear();
                        verification_checks.push("web_unexpected_retry_bypass=true".to_string());
                    } else if blocked_without_change {
                        outcome.stop_condition_hit = true;
                        outcome.escalation_path =
                            Some(escalation_path_for_failure(class).to_string());
                        agent_state.status = AgentStatus::Paused(format!(
                            "Retry blocked: unchanged AttemptKey for {}",
                            class.as_str()
                        ));
                        maybe_force_failure_streak_floor(agent_state, class);
                    } else if should_trip_retry_guard(class, repeat_count) {
                        outcome.stop_condition_hit = true;
                        outcome.escalation_path =
                            Some(escalation_path_for_failure(class).to_string());
                        agent_state.status = AgentStatus::Paused(format!(
                            "Retry guard tripped after repeated {} failures",
                            class.as_str()
                        ));
                        maybe_force_failure_streak_floor(agent_state, class);
                    }
                }
            }
        }
    }

    if !*success
        && matches!(agent_state.status, AgentStatus::Paused(_))
        && !outcome.stop_condition_hit
        && !is_gated
        && !awaiting_sudo_password
        && !*awaiting_clarification
    {
        outcome.stop_condition_hit = true;
        if outcome.escalation_path.is_none() {
            outcome.escalation_path = Some("wait_for_user".to_string());
        }
    }

    Ok(outcome)
}
