use super::*;
use crate::agentic::runtime::service::decision_loop::cognition::{
    final_reply_product_handoff_reason, sanitize_product_handoff_internal_markers,
};
use crate::agentic::runtime::service::output::terminal_reply_shape::{
    observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
};
use crate::agentic::runtime::service::queue::web_pipeline::WebPipelineCompletionReason;
use crate::agentic::runtime::service::tool_execution::{
    retained_shell_lifecycle_followup, retained_shell_lifecycle_tool_name,
    retained_shell_obsolete_input_after_stop,
};

#[path = "finalize_action_processing/completion_guards.rs"]
mod completion_guards;
#[path = "finalize_action_processing/toolcat.rs"]
mod toolcat;

use self::completion_guards::*;
use self::toolcat::*;

fn emit_terminal_chat_reply_postcondition_receipts(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    summary: &str,
    verification_checks: &mut Vec<String>,
) {
    let reply_digest = sha256(summary.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_binding",
        true,
        &format!(
            "probe_source=action.chat_reply_binding.v1;observed_value={};evidence_type=sha256",
            reply_digest
        ),
        Some("action.chat_reply_binding.v1"),
        Some(reply_digest.as_str()),
        Some("sha256"),
        None,
        None,
        None,
    );
    verification_checks.push("cec_postcondition_terminal_chat_reply_binding=true".to_string());
    verification_checks.push(format!("terminal_chat_reply_sha256={}", reply_digest));

    let shape_facts = observe_terminal_chat_reply_shape(summary);
    let layout_profile = terminal_chat_reply_layout_profile(&shape_facts);
    let emit_shape_receipt =
        |key: &str, satisfied: bool, observed_value: &str, evidence_type: &str| {
            emit_execution_contract_receipt_event_with_observation(
                service,
                session_id,
                step_index,
                intent_id,
                "postcondition",
                key,
                satisfied,
                &format!(
                    "probe_source=action.chat_reply_shape.v1;observed_value={};evidence_type={}",
                    observed_value, evidence_type
                ),
                Some("action.chat_reply_shape.v1"),
                Some(observed_value),
                Some(evidence_type),
                None,
                None,
                None,
            );
        };

    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        "postcondition",
        "terminal_chat_reply_layout_profile",
        true,
        &format!(
            "probe_source=action.chat_reply_shape.v1;observed_value={};evidence_type=label",
            layout_profile.as_str()
        ),
        Some("action.chat_reply_shape.v1"),
        Some(layout_profile.as_str()),
        Some("label"),
        None,
        None,
        None,
    );

    let legacy_source_cluster_header_count =
        shape_facts.legacy_source_cluster_header_count.to_string();
    emit_shape_receipt(
        "terminal_chat_reply_legacy_source_cluster_headers_absent",
        shape_facts.legacy_source_cluster_header_count == 0,
        legacy_source_cluster_header_count.as_str(),
        "scalar",
    );
    let comparison_label_count = shape_facts.comparison_label_count.to_string();
    emit_shape_receipt(
        "terminal_chat_reply_comparison_absent",
        shape_facts.comparison_label_count == 0,
        comparison_label_count.as_str(),
        "scalar",
    );
    let temporal_anchor_summary = format!(
        "run_date_present={};run_timestamp_present={}",
        shape_facts.run_date_present, shape_facts.run_timestamp_present
    );
    emit_shape_receipt(
        "terminal_chat_reply_temporal_anchor_floor",
        shape_facts.run_date_present && shape_facts.run_timestamp_present,
        temporal_anchor_summary.as_str(),
        "summary",
    );
    let postamble_summary = format!(
        "run_date_present={};run_timestamp_present={};overall_confidence_present={}",
        shape_facts.run_date_present,
        shape_facts.run_timestamp_present,
        shape_facts.overall_confidence_present
    );
    emit_shape_receipt(
        "terminal_chat_reply_postamble_floor",
        shape_facts.run_date_present
            && shape_facts.run_timestamp_present
            && shape_facts.overall_confidence_present,
        postamble_summary.as_str(),
        "summary",
    );
    verification_checks.push(format!(
        "terminal_chat_reply_layout_profile={}",
        layout_profile.as_str()
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_legacy_source_cluster_header_count={}",
        shape_facts.legacy_source_cluster_header_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_comparison_label_count={}",
        shape_facts.comparison_label_count
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_date_present={}",
        shape_facts.run_date_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_run_timestamp_present={}",
        shape_facts.run_timestamp_present
    ));
    verification_checks.push(format!(
        "terminal_chat_reply_overall_confidence_present={}",
        shape_facts.overall_confidence_present
    ));
}

#[allow(unused_assignments)]
pub(crate) async fn finalize_action_processing(
    ctx: FinalizeActionProcessingContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<(), TransactionError> {
    let FinalizeActionProcessingContext {
        service,
        state,
        agent_state,
        rules,
        session_id,
        block_height,
        strategy_used,
        tool_call_result,
        final_visual_phash,
        key,
        routing_decision,
        pre_state_summary,
        tool_version,
    } = ctx;

    let ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        is_gated,
        mut is_lifecycle_action,
        current_tool_name,
        mut history_entry,
        mut action_output,
        trace_visual_hash,
        executed_tool_jcs,
        mut failure_class,
        mut stop_condition_hit,
        mut escalation_path,
        mut remediation_queued,
        mut verification_checks,
        tool_normalization_observation: _tool_normalization_observation,
        awaiting_sudo_password,
        mut awaiting_clarification,
        command_probe_completed: _command_probe_completed,
        invalid_tool_call_fail_fast: _invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web: _invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox: _invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let trace_visual_hash = trace_visual_hash.unwrap_or(final_visual_phash);
    let prior_consecutive_failures = agent_state.consecutive_failures;
    let duplicate_prior_success_noop = duplicate_prior_success_noop(&verification_checks);
    let active_web_pipeline_chat_reply_duplicate_noop =
        active_web_pipeline_chat_reply_duplicate_noop(&verification_checks);
    let benign_workspace_context_duplicate =
        read_only_workspace_context_duplicate_noop(agent_state, &current_tool_name);
    let retained_shell_input_duplicate_noop =
        retained_shell_input_duplicate_noop(&verification_checks, &current_tool_name);
    let governed_shell_failure_terminal_reply_ready = verification_checks
        .iter()
        .any(|check| check == "governed_shell_failure_terminal_reply_ready=true");
    let governed_file_policy_failure_terminal_reply_ready = verification_checks
        .iter()
        .any(|check| check == "governed_file_policy_failure_terminal_reply_ready=true");
    let retained_shell_obsolete_input_after_stop = current_tool_name == "shell__input"
        && retained_shell_obsolete_input_after_stop(&agent_state.goal, error_msg.as_deref());
    if benign_workspace_context_duplicate {
        verification_checks.push("benign_workspace_context_duplicate_noop=true".to_string());
    }
    if retained_shell_input_duplicate_noop {
        success = true;
        error_msg = None;
        failure_class = None;
        history_entry = history_entry.or_else(|| {
            Some("Input was already sent; continuing with retained shell cleanup.".to_string())
        });
        action_output = action_output.or_else(|| {
            Some("Input was already sent; continuing with retained shell cleanup.".to_string())
        });
        agent_state.status = AgentStatus::Running;
        verification_checks.push("retained_shell_input_duplicate_noop_success=true".to_string());
    }
    if retained_shell_obsolete_input_after_stop {
        success = true;
        error_msg = None;
        failure_class = None;
        history_entry = Some(
            "Retained command was already stopped; continuing with retained shell cleanup."
                .to_string(),
        );
        action_output = history_entry.clone();
        agent_state.status = AgentStatus::Running;
        verification_checks
            .push("retained_shell_obsolete_input_after_stop_success=true".to_string());
    }
    if duplicate_prior_success_noop
        && !active_web_pipeline_chat_reply_duplicate_noop
        && !benign_workspace_context_duplicate
        && !retained_shell_input_duplicate_noop
        && !retained_shell_obsolete_input_after_stop
        && failure_class.is_none()
    {
        success = false;
        if error_msg.is_none() {
            error_msg = Some(
                "ERROR_CLASS=NoEffectAfterAction Duplicate replay produced no new effect."
                    .to_string(),
            );
        }
        failure_class = Some(FailureClass::NoEffectAfterAction);
        verification_checks.push(
            "duplicate_action_fingerprint_prior_success_promoted_to_failure=true".to_string(),
        );
    }
    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        if let Some(tool_jcs) = executed_tool_jcs.as_deref() {
            let resolved_retry_hash = retry_intent_hash
                .as_deref()
                .unwrap_or(intent_hash.as_str())
                .to_string();
            let incident_directive = advance_incident_after_action_outcome(
                service,
                state,
                agent_state,
                session_id,
                &resolved_retry_hash,
                tool_jcs,
                success,
                block_height,
                error_msg.as_deref(),
                &mut verification_checks,
            )
            .await?;
            if matches!(incident_directive, IncidentDirective::QueueActions) {
                remediation_queued = true;
                stop_condition_hit = false;
                escalation_path = None;
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Running;
            }
        }
    }

    if success && !is_gated {
        agent_state.recent_actions.clear();
        if let Some(terminal_reason) = install_already_satisfied_terminal_reason(
            &verification_checks,
            history_entry.as_deref(),
            action_output.as_deref(),
        ) {
            let operator_reply = install_already_satisfied_operator_reply(&terminal_reason);
            stop_condition_hit = true;
            escalation_path = Some("install_already_satisfied".to_string());
            is_lifecycle_action = true;
            remediation_queued = false;
            agent_state.execution_queue.clear();
            history_entry = Some(terminal_reason.clone());
            action_output = Some(terminal_reason.clone());
            terminal_chat_reply_output = Some(operator_reply.clone());
            agent_state.status = AgentStatus::Completed(Some(operator_reply));
            verification_checks.push("install_already_satisfied_terminal=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        }
    } else if !success && !awaiting_sudo_password && !awaiting_clarification {
        let governed_policy_failure_terminal_reply = (governed_shell_failure_terminal_reply_ready
            || governed_file_policy_failure_terminal_reply_ready)
            .then(|| {
                terminal_chat_reply_output
                    .as_deref()
                    .map(str::trim)
                    .filter(|reply| !reply.is_empty())
                    .map(str::to_string)
            })
            .flatten();
        if let Some(summary) = governed_policy_failure_terminal_reply {
            stop_condition_hit = true;
            escalation_path = Some(
                if governed_file_policy_failure_terminal_reply_ready {
                    "governed_file_policy_failure_terminal_reply"
                } else {
                    "governed_shell_failure_terminal_reply"
                }
                .to_string(),
            );
            is_lifecycle_action = true;
            remediation_queued = false;
            failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
            agent_state.execution_queue.clear();
            agent_state.status = AgentStatus::Completed(Some(summary));
            if governed_file_policy_failure_terminal_reply_ready {
                verification_checks
                    .push("governed_file_policy_failure_terminalized=true".to_string());
            } else {
                verification_checks.push("governed_shell_failure_terminalized=true".to_string());
            }
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        } else {
            let failure_intent_id = resolved_intent_id(agent_state);
            if let Some(terminal_reason) = install_resolution_terminal_block_reason(
                &verification_checks,
                error_msg.as_deref(),
                history_entry.as_deref(),
                action_output.as_deref(),
            ) {
                stop_condition_hit = true;
                escalation_path = Some("software_install_resolution_blocked".to_string());
                is_lifecycle_action = true;
                remediation_queued = false;
                failure_class = Some(FailureClass::UserInterventionNeeded);
                agent_state.execution_queue.clear();
                agent_state.status = AgentStatus::Failed(terminal_reason);
                verification_checks.push("software_install_terminal_block=true".to_string());
            } else if is_completion_contract_error(error_msg.as_deref())
                && !recoverable_action_completion_contract_error(error_msg.as_deref())
            {
                stop_condition_hit = true;
                escalation_path = Some("execution_contract_terminal".to_string());
                is_lifecycle_action = true;
                remediation_queued = false;
                agent_state.execution_queue.clear();
                let terminal_reason = error_msg
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
                failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
                if let Some(class) = failure_class {
                    let target_id = crate::agentic::runtime::service::recovery::anti_loop::specialized_attempt_target_id(
                    state,
                    service.memory_runtime.as_ref(),
                    &current_tool_name,
                    executed_tool_jcs.as_deref(),
                )
                .or_else(|| {
                    agent_state.target.as_ref().and_then(|target| {
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
                            .map(str::to_string)
                    })
                });
                    let command_scope = agent_state
                        .resolved_intent
                        .as_ref()
                        .map(|resolved| {
                            resolved.scope
                                == ioi_types::app::agentic::IntentScopeProfile::CommandExecution
                        })
                        .unwrap_or(false);
                    let raw_window_fingerprint = if trace_visual_hash == [0u8; 32] {
                        None
                    } else {
                        Some(hex::encode(trace_visual_hash))
                    };
                    let window_fingerprint = crate::agentic::runtime::service::recovery::anti_loop::canonical_attempt_window_fingerprint(
                    class,
                    command_scope,
                    raw_window_fingerprint.as_deref(),
                );
                    let retry_hash = retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
                    let attempt_key = build_attempt_key(
                        retry_hash,
                        routing_decision.tier,
                        &current_tool_name,
                        target_id.as_deref(),
                        window_fingerprint.as_deref(),
                    );
                    let (repeat_count, attempt_key_hash) =
                        register_failure_attempt(agent_state, class, &attempt_key);
                    let budget_remaining = retry_budget_remaining(repeat_count);
                    let blocked_without_change =
                        should_block_retry_without_change(class, repeat_count);
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
                    if is_toolcat_single_tool_probe(&agent_state.goal) {
                        let reply_tool_name = toolcat_single_tool_reply_tool_name(
                            &agent_state.goal,
                            &current_tool_name,
                        );
                        let duplicate_after_prior_success =
                            duplicate_after_prior_success(&verification_checks)
                                && matches!(class, FailureClass::NoEffectAfterAction);
                        let summary = if duplicate_after_prior_success {
                            toolcat_single_tool_duplicate_after_success_reply(&reply_tool_name)
                        } else {
                            toolcat_single_tool_failure_reply(&reply_tool_name)
                        };
                        stop_condition_hit = true;
                        escalation_path = Some(
                            if duplicate_after_prior_success {
                                "toolcat_single_tool_duplicate_after_success"
                            } else {
                                "toolcat_single_tool_failure"
                            }
                            .to_string(),
                        );
                        is_lifecycle_action = true;
                        remediation_queued = false;
                        action_output = error_msg.clone().or_else(|| Some(summary.clone()));
                        terminal_chat_reply_output = Some(summary.clone());
                        agent_state.execution_queue.clear();
                        agent_state.status = AgentStatus::Completed(Some(summary));
                        verification_checks.push(
                            if duplicate_after_prior_success {
                                "toolcat_single_tool_duplicate_after_success_terminalized=true"
                            } else {
                                "toolcat_single_tool_failure_terminalized=true"
                            }
                            .to_string(),
                        );
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                    } else if should_fail_fast_web_timeout(
                        agent_state.resolved_intent.as_ref(),
                        &current_tool_name,
                        class,
                        agent_state.pending_search_completion.is_some(),
                    ) {
                        let summary = format!(
                        "Web retrieval timed out while executing '{}'. Retry later or narrow the query/sources.",
                        current_tool_name
                    );
                        stop_condition_hit = true;
                        escalation_path = Some("web_timeout_fail_fast".to_string());
                        is_lifecycle_action = true;
                        remediation_queued = false;
                        action_output = Some(summary.clone());
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        agent_state.status = AgentStatus::Completed(Some(summary));
                        verification_checks.push("web_timeout_fail_fast=true".to_string());
                    } else if let Some(recovery_tool) =
                        attempt_patch_build_verify_runtime_patch_miss_repair(
                            state,
                            agent_state,
                            session_id,
                            &current_tool_name,
                            error_msg.as_deref(),
                            &tool_call_result,
                            &mut verification_checks,
                        )
                    {
                        if let Some(evidence) = patch_build_verify_patch_miss_receipt_evidence(
                            &current_tool_name,
                            error_msg.as_deref(),
                            executed_tool_jcs.as_deref(),
                            &tool_call_result,
                            pre_state_summary.step_index,
                        ) {
                            crate::agentic::runtime::service::tool_execution::support::record_execution_evidence_with_value(
                            &mut agent_state.tool_execution_log,
                            "workspace_patch_miss_observed",
                            evidence,
                        );
                            verification_checks
                                .push("runtime_patch_miss_observed=true".to_string());
                        }
                        let nonce = agent_state.step_count as u64
                            + agent_state.execution_queue.len() as u64
                            + 1;
                        let request = tool_to_action_request(&recovery_tool, session_id, nonce)?;
                        agent_state.execution_queue.insert(0, request);
                        stop_condition_hit = false;
                        escalation_path = None;
                        is_lifecycle_action = true;
                        remediation_queued = true;
                        success = true;
                        error_msg = None;
                        history_entry =
                            Some("Queued deterministic patch-miss recovery action.".to_string());
                        action_output = history_entry.clone();
                        agent_state.status = AgentStatus::Running;
                        agent_state.recent_actions.clear();
                        verification_checks
                            .push("runtime_patch_miss_recovery_queued=true".to_string());
                    } else {
                        if let Some(evidence) = patch_build_verify_patch_miss_receipt_evidence(
                            &current_tool_name,
                            error_msg.as_deref(),
                            executed_tool_jcs.as_deref(),
                            &tool_call_result,
                            pre_state_summary.step_index,
                        ) {
                            crate::agentic::runtime::service::tool_execution::support::record_execution_evidence_with_value(
                            &mut agent_state.tool_execution_log,
                            "workspace_patch_miss_observed",
                            evidence,
                        );
                            verification_checks
                                .push("runtime_patch_miss_observed=true".to_string());
                        }
                        let incident_state = load_incident_state(state, &session_id)?;
                        if should_enter_incident_recovery(
                            Some(class),
                            &policy_decision,
                            stop_condition_hit,
                            incident_state.as_ref(),
                        ) {
                            if let Some(root_tool_jcs) = executed_tool_jcs.as_deref() {
                                let (resolved_retry_hash, recovery_tool_name, recovery_tool_jcs): (
                                    String,
                                    String,
                                    Vec<u8>,
                                ) = if let Some(existing) =
                                    incident_state.as_ref().filter(|i| i.active)
                                {
                                    (
                                        existing.root_retry_hash.clone(),
                                        existing.root_tool_name.clone(),
                                        existing.root_tool_jcs.clone(),
                                    )
                                } else {
                                    (
                                        retry_intent_hash
                                            .as_deref()
                                            .unwrap_or(intent_hash.as_str())
                                            .to_string(),
                                        current_tool_name.clone(),
                                        root_tool_jcs.to_vec(),
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
                                        error_msg.as_deref(),
                                        &mut verification_checks,
                                    )
                                    .await?,
                                    IncidentDirective::QueueActions
                                );
                            }
                        }

                        let install_lookup_failure = error_msg
                            .as_deref()
                            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
                            .unwrap_or(false);

                        let workspace_manifest_recovery_queued = if !remediation_queued {
                            maybe_enqueue_workspace_package_manifest_recovery(
                                agent_state,
                                session_id,
                                class,
                                &current_tool_name,
                            )?
                        } else {
                            false
                        };

                        if workspace_manifest_recovery_queued {
                            stop_condition_hit = false;
                            escalation_path = None;
                            is_lifecycle_action = true;
                            remediation_queued = true;
                            success = true;
                            error_msg = None;
                            history_entry = Some(
                                "Queued deterministic package-manifest recovery actions."
                                    .to_string(),
                            );
                            action_output = history_entry.clone();
                            agent_state.status = AgentStatus::Running;
                            agent_state.recent_actions.clear();
                            verification_checks.push(
                                "workspace_package_manifest_recovery_queued=true".to_string(),
                            );
                        } else if remediation_queued {
                            stop_condition_hit = false;
                            escalation_path = None;
                            is_lifecycle_action = true;
                            agent_state.status = AgentStatus::Running;
                        } else if install_lookup_failure {
                            stop_condition_hit = true;
                            escalation_path = Some("wait_for_clarification".to_string());
                            is_lifecycle_action = true;
                            awaiting_clarification = true;
                            mark_incident_wait_for_user(
                                state,
                                session_id,
                                "wait_for_clarification",
                                FailureClass::UserInterventionNeeded,
                                error_msg.as_deref(),
                            )?;
                            agent_state.execution_queue.clear();
                            agent_state.status = AgentStatus::Paused(
                                "Waiting for clarification on target identity.".to_string(),
                            );
                        } else if matches!(class, FailureClass::UserInterventionNeeded) {
                            stop_condition_hit = true;
                            escalation_path = Some(escalation_path_for_failure(class).to_string());
                            is_lifecycle_action = true;
                            agent_state.status = AgentStatus::Paused(
                            "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                        );
                        } else if should_use_web_research_path(agent_state)
                            && matches!(class, FailureClass::UnexpectedState)
                        {
                            // Keep web research autonomous under transient tool/schema instability.
                            stop_condition_hit = false;
                            escalation_path = None;
                            is_lifecycle_action = true;
                            success = true;
                            error_msg = None;
                            let note = format!(
                            "Transient unexpected state while executing '{}'; continuing web research.",
                            current_tool_name
                        );
                            history_entry = Some(note.clone());
                            action_output = Some(note);
                            agent_state.status = AgentStatus::Running;
                            agent_state.recent_actions.clear();
                            verification_checks
                                .push("web_unexpected_retry_bypass=true".to_string());
                        } else if blocked_without_change {
                            if maybe_enqueue_lowercase_rename_recovery(
                                agent_state,
                                session_id,
                                class,
                                &current_tool_name,
                            )? {
                                stop_condition_hit = false;
                                escalation_path = None;
                                is_lifecycle_action = true;
                                remediation_queued = true;
                                success = true;
                                error_msg = None;
                                history_entry = Some(
                                    "Queued deterministic lowercase-rename recovery actions."
                                        .to_string(),
                                );
                                action_output = history_entry.clone();
                                agent_state.status = AgentStatus::Running;
                                agent_state.recent_actions.clear();
                                verification_checks.push(
                                    "workspace_lowercase_rename_recovery_queued=true".to_string(),
                                );
                            } else {
                                stop_condition_hit = true;
                                escalation_path =
                                    Some(escalation_path_for_failure(class).to_string());
                                is_lifecycle_action = true;
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
                                    agent_state.consecutive_failures =
                                        agent_state.consecutive_failures.max(3);
                                }
                            }
                        } else if should_trip_retry_guard(class, repeat_count) {
                            stop_condition_hit = true;
                            escalation_path = Some(escalation_path_for_failure(class).to_string());
                            is_lifecycle_action = true;
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
                                agent_state.consecutive_failures =
                                    agent_state.consecutive_failures.max(3);
                            }
                        }
                    }
                }
            }
        }
    }

    if !success
        && matches!(agent_state.status, AgentStatus::Paused(_))
        && !stop_condition_hit
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        stop_condition_hit = true;
        is_lifecycle_action = true;
        if escalation_path.is_none() {
            escalation_path = Some("wait_for_user".to_string());
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_gated={}", is_gated));
    verification_checks.push(format!("awaiting_sudo_password={}", awaiting_sudo_password));
    verification_checks.push(format!("awaiting_clarification={}", awaiting_clarification));

    if success && !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        let retained_output = action_output
            .as_deref()
            .or(history_entry.as_deref())
            .or(Some(tool_call_result.as_str()));
        let executed_tool = executed_tool_jcs
            .as_deref()
            .and_then(|raw| serde_json::from_slice::<AgentTool>(raw).ok());
        let retained_lifecycle_followup = retained_shell_lifecycle_followup(
            &agent_state.goal,
            &current_tool_name,
            executed_tool.as_ref(),
            retained_output,
        );
        let status_allows_followup = matches!(agent_state.status, AgentStatus::Running);
        let followup_tool = if status_allows_followup || retained_lifecycle_followup.is_some() {
            retained_lifecycle_followup
                .or_else(|| {
                    toolcat_single_tool_retained_shell_followup(
                        &agent_state.goal,
                        &current_tool_name,
                        retained_output,
                    )
                })
                .or_else(|| {
                    toolcat_single_tool_agent_await_followup(
                        &agent_state.goal,
                        &current_tool_name,
                        retained_output,
                    )
                })
                .or_else(|| {
                    toolcat_single_tool_chat_reply_recovery_followup(
                        &agent_state.goal,
                        &current_tool_name,
                    )
                })
                .or_else(|| {
                    toolcat_single_tool_browser_setup_followup(
                        &agent_state.goal,
                        &current_tool_name,
                        retained_output,
                    )
                })
                .or_else(|| {
                    toolcat_single_tool_success_followup(&agent_state.goal, &current_tool_name)
                })
        } else {
            None
        };
        if let Some(followup_tool) = followup_tool {
            let followup_name = queue_tool_name(&followup_tool);
            let nonce =
                agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1;
            let request = tool_to_action_request(&followup_tool, session_id, nonce)?;
            if matches!(followup_tool, AgentTool::ChatReply { .. })
                || retained_shell_lifecycle_tool_name(&followup_tool).is_some()
            {
                agent_state.execution_queue.clear();
            }
            agent_state.execution_queue.insert(0, request);
            agent_state.recent_actions.clear();
            stop_condition_hit = false;
            escalation_path = None;
            is_lifecycle_action = true;
            terminal_chat_reply_output = None;
            agent_state.status = AgentStatus::Running;
            if matches!(followup_tool, AgentTool::ChatReply { .. }) {
                verification_checks
                    .push(format!("terminal_lifecycle_reply_queued={}", followup_name));
            } else if retained_shell_lifecycle_tool_name(&followup_tool).is_some() {
                verification_checks.push(format!(
                    "retained_shell_lifecycle_followup_queued={}",
                    followup_name
                ));
            } else {
                verification_checks.push(format!(
                    "toolcat_retained_shell_followup_queued={}",
                    followup_name
                ));
            }
        }
    }

    if success
        && current_tool_name == "chat__reply"
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && matches!(agent_state.status, AgentStatus::Completed(_))
    {
        stop_condition_hit = true;
        agent_state.execution_queue.clear();
        verification_checks.push("terminal_chat_reply_stop_condition_hit=true".to_string());
    }

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

    if success
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && terminal_chat_reply_output.is_some()
    {
        if let Some(reply) = terminal_chat_reply_output.as_mut() {
            *reply = sanitize_product_handoff_internal_markers(reply);
        }
        let reply = terminal_chat_reply_output.as_deref().unwrap_or_default();
        let action_missing = missing_runtime_action_completion_evidence(agent_state);
        if !action_missing.is_empty() {
            for missing in &action_missing {
                verification_checks.push(format!("action_completion_missing={}", missing));
            }
            let missing = action_missing.join(",");
            let blocked_error = execution_contract_violation_error(&missing);
            success = false;
            error_msg = Some(blocked_error.clone());
            history_entry = Some(blocked_error.clone());
            action_output = Some(blocked_error);
            terminal_chat_reply_output = None;
            agent_state.status = AgentStatus::Running;
            stop_condition_hit = false;
            is_lifecycle_action = false;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("terminal_chat_reply_ready=false".to_string());
            let intent_id = resolved_intent_id(agent_state);
            agent_state
                .execution_ledger
                .record_completion_gate(Some(intent_id.clone()), &action_missing);
            emit_completion_gate_status_event(
                service,
                session_id,
                pre_state_summary.step_index,
                intent_id.as_str(),
                false,
                "finalize_terminal_chat_reply_action_completion_blocked",
            );
        } else if let Some(reason) = final_reply_product_handoff_reason(reply, &agent_state.goal) {
            let blocked_error = terminal_product_handoff_violation_error(reason);
            success = false;
            error_msg = Some(blocked_error.clone());
            history_entry = Some(blocked_error.clone());
            action_output = Some(blocked_error);
            terminal_chat_reply_output = None;
            agent_state.status = AgentStatus::Running;
            stop_condition_hit = false;
            is_lifecycle_action = false;
            verification_checks.push(format!(
                "terminal_product_handoff_blocked_at_finalize_reason={}",
                reason
            ));
            verification_checks.push("terminal_chat_reply_ready=false".to_string());
            let intent_id = resolved_intent_id(agent_state);
            emit_completion_gate_status_event(
                service,
                session_id,
                pre_state_summary.step_index,
                intent_id.as_str(),
                false,
                "finalize_terminal_chat_reply_product_handoff_blocked",
            );
        }
    }

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        trace_visual_hash,
        format!("[Strategy: {}]\n{}", strategy_used, tool_call_result),
        tool_call_result,
        success,
        error_msg.clone(),
        current_tool_name.clone(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
        service.memory_runtime.as_ref(),
    )?;

    if !success && !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        let failure_content = error_msg
            .clone()
            .or_else(|| history_entry.clone())
            .or_else(|| action_output.clone());
        if let Some(content) = failure_content {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                let tool_msg = ioi_types::app::agentic::ChatMessage {
                    role: "tool".to_string(),
                    content: format!("Tool Output ({}): {}", current_tool_name, trimmed),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                    .await?;
            }
        }
    }

    // Failure counter is primarily managed in goto_trace_log.
    // We only override it for explicit escalation or lifecycle transitions.
    if enforce_system_fail_terminal_status(
        &current_tool_name,
        &mut agent_state.status,
        error_msg.as_deref(),
    ) {
        log::info!("SystemFail executed: Forcing IMMEDIATE escalation state (failures=3)");
        agent_state.consecutive_failures = 3;
    } else if !stop_condition_hit && (success || is_lifecycle_action) {
        if duplicate_prior_success_noop {
            agent_state.consecutive_failures = prior_consecutive_failures.saturating_add(1);
        } else {
            agent_state.consecutive_failures = 0;
        }
    }

    let max_steps_terminalization_due = !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && agent_state.status == AgentStatus::Running
        && !crate::agentic::runtime::utils::max_steps_completion_blocked_by_active_child(
            state,
            agent_state,
        )
        && agent_state.step_count.saturating_add(1) >= agent_state.max_steps;
    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && agent_state.status == AgentStatus::Running
        && agent_state.step_count.saturating_add(1) >= agent_state.max_steps
        && crate::agentic::runtime::utils::max_steps_completion_blocked_by_active_child(
            state,
            agent_state,
        )
    {
        verification_checks
            .push("max_steps_terminalization_deferred_for_active_child=true".to_string());
    }
    if max_steps_terminalization_due {
        if let Some(pending) = agent_state.pending_search_completion.clone() {
            if let Some(reason) = web_pipeline_completion_reason(&pending, web_pipeline_now_ms()) {
                let intent_id = resolved_intent_id(agent_state);
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    pre_state_summary.step_index,
                    intent_id.as_str(),
                    true,
                    "web_pipeline_evidence_ready_for_model_answer",
                );
                preserve_tool_history_or_fill_ready_note(&mut history_entry, &mut action_output);
                terminal_chat_reply_output = None;
                is_lifecycle_action = false;
                agent_state.pending_search_completion = Some(pending);
                agent_state.status = AgentStatus::Running;
                verification_checks.push("cec_completion_gate_emitted=true".to_string());
                verification_checks.push(format!(
                    "web_pipeline_model_answer_ready_reason={}",
                    web_pipeline_completion_reason_label(reason)
                ));
                verification_checks
                    .push("web_pipeline_max_steps_waiting_for_model_answer=true".to_string());
                verification_checks
                    .push("web_pipeline_waiting_for_model_authored_answer=true".to_string());
                verification_checks.push("web_pipeline_active=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=false".to_string());
                let drained =
                    crate::agentic::runtime::service::queue::drain_queued_web_retrieve_actions(
                        agent_state,
                    );
                verification_checks.push(format!(
                    "web_pipeline_queued_retrievals_drained_for_model_answer={}",
                    drained
                ));
            }
        }
    }

    if !is_gated {
        if success
            && terminal_chat_reply_output.is_none()
            && matches!(agent_state.status, AgentStatus::Running)
        {
            if let Some(summary) = maybe_terminalize_workspace_package_manifest_read(
                agent_state,
                &current_tool_name,
                action_output.as_deref().or(history_entry.as_deref()),
            ) {
                history_entry = Some(summary.clone());
                action_output = Some(summary.clone());
                terminal_chat_reply_output = Some(summary.clone());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(summary));
                verification_checks
                    .push("workspace_package_manifest_read_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            }
        }

        let composed_terminal_chat = terminal_chat_reply_output
            .as_deref()
            .map(compose_terminal_chat_reply);
        let release_browser_after_terminal_reply = should_release_browser_after_terminal_reply(
            agent_state,
            &current_tool_name,
            terminal_chat_reply_output.as_deref(),
        );
        if release_browser_after_terminal_reply {
            service.browser.release_session().await;
            verification_checks
                .push("browser_session_released_before_terminal_reply_event=true".to_string());
        }
        if let Some(tx) = &service.event_sender {
            let mut output_str = action_output
                .or_else(|| if success { history_entry.clone() } else { None })
                .unwrap_or_else(|| {
                    error_msg
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                });
            if success
                && current_tool_name != "chat__reply"
                && composed_terminal_chat.is_some()
                && !output_str.trim().is_empty()
            {
                output_str = "Completed. Final response emitted via chat__reply.".to_string();
                verification_checks
                    .push("terminal_tool_output_suppressed_for_chat_reply=true".to_string());
            }
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: pre_state_summary.step_index,
                tool_name: current_tool_name.clone(),
                output: output_str,
                error_class: extract_error_class_token(error_msg.as_deref()).map(str::to_string),
                agent_status: get_status_str(&agent_state.status),
            });

            if let Some(composed) = composed_terminal_chat {
                verification_checks.push(format!("response_composer_applied={}", composed.applied));
                verification_checks.push(format!(
                    "response_composer_template={}",
                    composed.template_id
                ));
                verification_checks.push(format!(
                    "response_composer_validator_passed={}",
                    composed.validator_passed
                ));
                if let Some(reason) = composed.degradation_reason {
                    verification_checks
                        .push(format!("response_composer_degradation_reason={}", reason));
                }
                verification_checks.push("terminal_chat_reply_emitted=true".to_string());
                let intent_id = resolved_intent_id(agent_state);
                if current_tool_name != "chat__reply"
                    && matches!(agent_state.status, AgentStatus::Completed(_))
                {
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        pre_state_summary.step_index,
                        intent_id.as_str(),
                        true,
                        "finalize_terminal_chat_reply_gate_passed",
                    );
                    verification_checks.push("cec_completion_gate_emitted=true".to_string());
                }
                if matches!(agent_state.status, AgentStatus::Completed(_)) {
                    emit_terminal_chat_reply_postcondition_receipts(
                        service,
                        session_id,
                        pre_state_summary.step_index,
                        intent_id.as_str(),
                        composed.output.as_str(),
                        &mut verification_checks,
                    );
                }
                if current_tool_name != "chat__reply" {
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index: pre_state_summary.step_index,
                        tool_name: "chat__reply".to_string(),
                        output: composed.output,
                        error_class: None,
                        agent_status: get_status_str(&agent_state.status),
                    });
                }
            }
        }
    }

    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        agent_state.step_count += 1;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_request_nonce = None;
        agent_state.pending_approval = None;
    }

    // ... [Max steps check] ...
    if crate::agentic::runtime::utils::should_terminalize_running_agent_after_max_steps(
        state,
        agent_state,
    ) {
        agent_state.status = AgentStatus::Completed(None);
    }

    match agent_state.status {
        AgentStatus::Completed(_) => {
            let _ = service
                .update_skill_reputation(state, session_id, true, block_height)
                .await;
        }
        AgentStatus::Failed(_) => {
            let _ = service
                .update_skill_reputation(state, session_id, false, block_height)
                .await;
        }
        _ => {}
    }

    let mut artifacts = extract_artifacts(error_msg.as_deref(), history_entry.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));

    let intent_id_for_contract = resolved_intent_id(agent_state);
    persist_step_evidence_to_ledger(
        agent_state,
        intent_id_for_contract.as_str(),
        &verification_checks,
    );
    persist_step_evidence(
        state,
        session_id,
        pre_state_summary.step_index,
        intent_id_for_contract.as_str(),
        &verification_checks,
        prior_consecutive_failures,
    )?;

    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
    let route_decision =
        crate::agentic::runtime::service::decision_loop::route_projection::project_route_decision(
            service,
            state,
            agent_state,
            &current_tool_name,
            agent_state.current_tier,
        )
        .await;

    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name: current_tool_name,
        tool_version: tool_version.to_string(),
        pre_state: pre_state_summary,
        action_json: serde_json::to_string(&action_payload).unwrap_or_else(|_| "{}".to_string()),
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
        lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
        route_decision,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    Ok(())
}

fn install_resolution_terminal_block_reason(
    verification_checks: &[String],
    error_msg: Option<&str>,
    history_entry: Option<&str>,
    action_output: Option<&str>,
) -> Option<String> {
    let blocked_before_approval = verification_checks
        .iter()
        .any(|check| check == "software_install_blocked_before_approval=true");
    if !blocked_before_approval {
        return None;
    }

    [error_msg, history_entry, action_output]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            Some(
                "ERROR_CLASS=InstallerResolutionRequired Install target is not executable."
                    .to_string(),
            )
        })
}

fn install_already_satisfied_terminal_reason(
    verification_checks: &[String],
    history_entry: Option<&str>,
    action_output: Option<&str>,
) -> Option<String> {
    let already_satisfied = verification_checks
        .iter()
        .any(|check| check == "install_already_satisfied_before_approval=true");
    if !already_satisfied {
        return None;
    }

    [history_entry, action_output]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            Some(
                "Already available: requested software passed verification before host mutation."
                    .to_string(),
            )
        })
}

fn install_already_satisfied_operator_reply(receipt: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(receipt).ok();
    let receipt_value = parsed
        .as_ref()
        .and_then(|value| value.get("install_final_receipt").or(Some(value)));
    let display_name = receipt_value
        .and_then(|value| value.get("display_name"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("The requested software");
    let status = receipt_value
        .and_then(|value| value.get("status"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let verification = receipt_value
        .and_then(|value| value.get("verification"))
        .and_then(|value| value.get("command"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter(|value| !value.eq_ignore_ascii_case("current_exe_exists"));

    if status == "already_available" {
        return format!(
            "{} is already available as the running IOI product. Verification passed before host mutation, so no installer command or approval was needed.",
            display_name
        );
    }

    match verification {
        Some(command) => format!(
            "{} is already installed. Verification passed with `{}`, so no installer command or approval was needed.",
            display_name, command
        ),
        None => format!(
            "{} is already installed. Verification passed before host mutation, so no installer command or approval was needed.",
            display_name
        ),
    }
}

fn maybe_enqueue_lowercase_rename_recovery(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    failure_class: FailureClass,
    root_tool_name: &str,
) -> Result<bool, TransactionError> {
    if !matches!(failure_class, FailureClass::NoEffectAfterAction) || root_tool_name != "file__list"
    {
        return Ok(false);
    }

    let Some(plan) = parse_lowercase_rename_plan(&agent_state.goal) else {
        return Ok(false);
    };
    if plan.renames.is_empty() {
        return Ok(false);
    }

    let base_dir = plan.target_dir.trim_end_matches('/').to_string();
    let mut recovery_tools: Vec<AgentTool> = Vec::new();
    let mut destination_paths: Vec<String> = Vec::new();
    for (source_name, destination_name) in &plan.renames {
        let source_path = format!("{}/{}", base_dir, source_name);
        let destination_path = format!("{}/{}", base_dir, destination_name);
        destination_paths.push(destination_path.clone());
        recovery_tools.push(AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite: false,
        });
    }

    recovery_tools.push(AgentTool::ChatReply {
        message: format!(
            "Renamed files to lowercase in {}:\n{}",
            base_dir,
            destination_paths.join("\n")
        ),
    });

    let base_nonce = agent_state.step_count as u64 + 1;
    for (offset, tool) in recovery_tools.into_iter().rev().enumerate() {
        let request = tool_to_action_request(&tool, session_id, base_nonce + offset as u64)?;
        agent_state.execution_queue.insert(0, request);
    }

    Ok(true)
}

fn maybe_terminalize_workspace_package_manifest_read(
    agent_state: &AgentState,
    current_tool_name: &str,
    output: Option<&str>,
) -> Option<String> {
    if current_tool_name != "file__read" {
        return None;
    }
    if agent_state.parent_session_id.is_some() {
        return None;
    }
    if agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope)
        != Some(ioi_types::app::agentic::IntentScopeProfile::WorkspaceOps)
    {
        return None;
    }
    if !workspace_goal_prefers_package_manifest_recovery(&agent_state.goal) {
        return None;
    }

    let manifest_raw = output?;
    let manifest_script =
        select_manifest_script_recovery_candidate(&agent_state.goal, manifest_raw)?;
    Some(format!(
        "In `package.json`, the npm script that launches the desktop app is `{}`. It runs `{}`.",
        manifest_script.name, manifest_script.command
    ))
}

fn maybe_enqueue_workspace_package_manifest_recovery(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    failure_class: FailureClass,
    root_tool_name: &str,
) -> Result<bool, TransactionError> {
    if !matches!(failure_class, FailureClass::NoEffectAfterAction) || root_tool_name != "file__list"
    {
        return Ok(false);
    }
    if agent_state.parent_session_id.is_some() {
        return Ok(false);
    }
    if agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope)
        != Some(ioi_types::app::agentic::IntentScopeProfile::WorkspaceOps)
    {
        return Ok(false);
    }
    if !workspace_goal_prefers_package_manifest_recovery(&agent_state.goal) {
        return Ok(false);
    }

    let Some(manifest_path) = workspace_package_manifest_path(agent_state) else {
        return Ok(false);
    };
    let Some(manifest_raw) = std::fs::read_to_string(&manifest_path).ok() else {
        return Ok(false);
    };
    let Some(manifest_script) =
        select_manifest_script_recovery_candidate(&agent_state.goal, &manifest_raw)
    else {
        return Ok(false);
    };

    let read_path = workspace_package_manifest_read_path(agent_state);
    let recovery_tools = vec![
        AgentTool::FsRead { path: read_path },
        AgentTool::ChatReply {
            message: format!(
                "In `package.json`, the npm script that launches the desktop app is `{}`. It runs `{}`.",
                manifest_script.name, manifest_script.command
            ),
        },
    ];

    let base_nonce = agent_state.step_count as u64 + 1;
    for (offset, tool) in recovery_tools.into_iter().rev().enumerate() {
        let request = tool_to_action_request(&tool, session_id, base_nonce + offset as u64)?;
        agent_state.execution_queue.insert(0, request);
    }

    Ok(true)
}

fn tool_to_action_request(
    tool: &AgentTool,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<ActionRequest, TransactionError> {
    let target = tool.target();
    let tool_name = queue_tool_name(tool);
    let tool_value =
        serde_json::to_value(tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let mut args = tool_value
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if should_embed_queue_tool_name_metadata(&target, &tool_name) {
        if let Some(obj) = args.as_object_mut() {
            obj.insert(QUEUE_TOOL_NAME_KEY.to_string(), json!(tool_name));
        }
    }
    let params =
        serde_jcs::to_vec(&args).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    Ok(ActionRequest {
        target,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce,
    })
}

#[derive(Debug)]
struct LowercaseRenamePlan {
    target_dir: String,
    renames: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestScriptRecoveryCandidate {
    name: String,
    command: String,
}

const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

fn should_embed_queue_tool_name_metadata(target: &ActionTarget, tool_name: &str) -> bool {
    matches!(target, ActionTarget::FsRead | ActionTarget::FsWrite)
        || (matches!(target, ActionTarget::GuiClick | ActionTarget::UiClick)
            && tool_name == "screen__click")
        || matches!(
            target,
            ActionTarget::BrowserInteract | ActionTarget::BrowserInspect
        )
        || (matches!(target, ActionTarget::SysExec)
            && matches!(
                tool_name,
                "shell__start"
                    | "shell__reset"
                    | "shell__status"
                    | "shell__input"
                    | "shell__terminate"
            ))
}

fn queue_tool_name(tool: &AgentTool) -> String {
    serde_json::to_value(tool)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{:?}", tool.target()))
}

fn parse_lowercase_rename_plan(goal: &str) -> Option<LowercaseRenamePlan> {
    let goal_lc = goal.to_ascii_lowercase();
    if !goal_lc.contains("rename files in") || !goal_lc.contains("to lowercase") {
        return None;
    }

    let target_re = regex::Regex::new("(?i)rename\\s+files\\s+in\\s+\"([^\"]+)\"")
        .expect("lowercase-rename target regex must compile");
    let target_raw = target_re
        .captures(goal)
        .and_then(|captures| captures.get(1))
        .map(|m| m.as_str().trim().to_string())?;
    let target_dir = expand_runtime_home_alias(&target_raw);

    let pair_re = regex::Regex::new("\"([^\"]+)\"\\s*->\\s*\"([^\"]+)\"")
        .expect("lowercase-rename pair regex must compile");
    let mut renames = Vec::new();
    for captures in pair_re.captures_iter(goal) {
        let source = captures
            .get(1)
            .map(|m| m.as_str().trim())
            .unwrap_or_default();
        let destination = captures
            .get(2)
            .map(|m| m.as_str().trim())
            .unwrap_or_default();
        if source.is_empty()
            || destination.is_empty()
            || source.contains('/')
            || destination.contains('/')
        {
            continue;
        }
        renames.push((source.to_string(), destination.to_string()));
    }

    if renames.is_empty() {
        return None;
    }

    Some(LowercaseRenamePlan {
        target_dir,
        renames,
    })
}

fn expand_runtime_home_alias(path: &str) -> String {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            let home = home.trim_end_matches('/');
            return format!("{home}/{}", rest.trim_start_matches('/'));
        }
    }
    trimmed.to_string()
}

fn workspace_goal_prefers_package_manifest_recovery(goal: &str) -> bool {
    let goal_lc = goal.to_ascii_lowercase();
    goal_lc.contains("npm") && goal_lc.contains("script") && goal_lc.contains("desktop")
}

fn workspace_package_manifest_path(agent_state: &AgentState) -> Option<std::path::PathBuf> {
    let working_directory = agent_state.working_directory.trim();
    let base_path = if working_directory.is_empty() {
        std::path::PathBuf::from(".")
    } else {
        std::path::PathBuf::from(expand_runtime_home_alias(working_directory))
    };
    let manifest_path = base_path.join("package.json");
    std::fs::metadata(&manifest_path)
        .ok()
        .map(|_| manifest_path)
}

fn workspace_package_manifest_read_path(agent_state: &AgentState) -> String {
    let _ = agent_state;
    "./package.json".to_string()
}

fn select_manifest_script_recovery_candidate(
    goal: &str,
    manifest_raw: &str,
) -> Option<ManifestScriptRecoveryCandidate> {
    let manifest = serde_json::from_str::<serde_json::Value>(manifest_raw).ok()?;
    let scripts = manifest.get("scripts")?.as_object()?;
    let goal_lc = goal.to_ascii_lowercase();

    let mut candidates = scripts
        .iter()
        .filter_map(|(name, value)| {
            let command = value.as_str()?.trim();
            if command.is_empty() {
                return None;
            }
            let name_lc = name.to_ascii_lowercase();
            let command_lc = command.to_ascii_lowercase();
            let mut score = 0u32;
            if goal_lc.contains("desktop")
                && (name_lc.contains("desktop") || command_lc.contains("desktop"))
            {
                score += 10;
            }
            if goal_lc.contains("desktop") && name_lc == "dev:desktop" {
                score += 8;
            }
            if goal_lc.contains("launch")
                && (name_lc.contains("start")
                    || name_lc.contains("launch")
                    || name_lc.contains("dev")
                    || command_lc.contains("dev-desktop"))
            {
                score += 4;
            }
            if goal_lc.contains("app")
                && (name_lc.contains("app")
                    || command_lc.contains("autopilot")
                    || command_lc.contains("desktop"))
            {
                score += 2;
            }
            if goal_lc.contains("wayland")
                && (name_lc.contains("wayland") || command_lc.contains("wayland"))
            {
                score += 6;
            } else if name_lc.contains("wayland") || command_lc.contains("wayland") {
                score = score.saturating_sub(3);
            }
            if goal_lc.contains("dry")
                && (name_lc.contains("dryrun") || command_lc.contains("dry-run"))
            {
                score += 4;
            } else if name_lc.contains("dryrun") || command_lc.contains("dry-run") {
                score = score.saturating_sub(4);
            }
            if name_lc.ends_with("desktop") {
                score += 3;
            }
            (score > 0).then_some((score, name.as_str(), command))
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| right.cmp(left));
    let (top_score, top_name, top_command) = *candidates.first()?;
    let ambiguous_top_score = candidates
        .iter()
        .filter(|(score, _, _)| *score == top_score)
        .count();
    if top_score < 10 || ambiguous_top_score > 1 {
        return None;
    }

    Some(ManifestScriptRecoveryCandidate {
        name: top_name.to_string(),
        command: top_command.to_string(),
    })
}

#[cfg(test)]
#[path = "finalize_action_processing/tests.rs"]
mod tests;
