use super::command_contract::{
    capability_route_label, command_arms_deferred_notification_path, compose_terminal_chat_reply,
    enrich_command_scope_summary, evaluate_completion_requirements,
    execution_contract_violation_error, extract_error_class_token,
    is_command_execution_provider_tool, is_completion_contract_error,
    record_provider_selection_evidence, record_timer_notification_contract_requirement,
    record_verification_evidence, requires_timer_notification_contract,
    runtime_host_environment_evidence, synthesize_allowlisted_timer_notification_tool,
    sys_exec_arms_timer_delay_backend, sys_exec_command_preview,
    sys_exec_foreign_absolute_home_path, sys_exec_satisfies_clock_read_contract,
    sys_exec_timer_delay_seconds, CLOCK_TIMESTAMP_SUCCESS_CONDITION,
    PROVIDER_SELECTION_COMMIT_EVIDENCE, TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
    TIMER_SLEEP_BACKEND_SUCCESS_CONDITION, VERIFICATION_COMMIT_EVIDENCE,
};
use super::probe::{
    is_command_probe_intent, is_system_clock_read_intent, summarize_command_probe_output,
    summarize_math_eval_output, summarize_structured_command_receipt_output,
    summarize_system_clock_or_plain_output,
};
use super::refusal_eval::evaluate_and_crystallize;
use super::search::{extract_navigation_url, is_search_results_url, search_query_from_url};
use super::support::{
    action_fingerprint_execution_step, canonical_intent_hash, canonical_retry_intent_hash,
    canonical_tool_identity, drop_legacy_action_fingerprint_receipt,
    enforce_system_fail_terminal_status, execution_evidence_key, execution_evidence_value,
    get_status_str, has_execution_evidence, mark_action_fingerprint_executed_at_step,
    mark_system_fail_status, persist_step_evidence, persist_step_evidence_to_ledger,
    record_execution_evidence, record_execution_evidence_with_value, record_success_condition,
    success_condition_key,
};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::execution::system::is_sudo_password_required_install_error;
use crate::agentic::runtime::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::runtime::middleware;
use crate::agentic::runtime::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, normalize_web_research_tool_call,
    persist_pii_review_request, reconcile_pending_web_research_tool_call,
    resolve_window_binding_for_target, target_requires_window_binding,
};
use crate::agentic::runtime::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::runtime::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
    TierRoutingDecision,
};
use crate::agentic::runtime::service::step::helpers::{
    default_safe_policy, is_mailbox_connector_goal, should_auto_complete_open_app_goal,
};
use crate::agentic::runtime::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_incident_wait_for_user, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::service::step::queue::web_pipeline::{
    append_final_web_completion_receipts_with_rendered_summary,
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    final_web_completion_facts_with_rendered_summary, is_human_challenge_error,
    mark_pending_web_attempted, mark_pending_web_blocked, parse_web_evidence_bundle,
    remaining_pending_web_candidates, render_mailbox_access_limited_reply,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    web_pipeline_completion_reason, web_pipeline_now_ms,
};
use crate::agentic::runtime::service::step::signals::is_mail_connector_tool_name;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{
    AgentState, AgentStatus, ExecutionStage, ToolCallStatus, MAX_COMMAND_HISTORY,
};
use crate::agentic::runtime::utils::{goto_trace_log, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, KernelEvent, RoutingReceiptEvent,
    RoutingStateSummary,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

mod child_session;
mod command_history;
mod duplicate_guard;
mod grounding;
mod phases;
mod refusal;
mod repair;
mod web_helpers;

pub(crate) use self::duplicate_guard::verified_command_probe_completion_summary;
use self::duplicate_guard::{
    duplicate_command_cached_completion_summary, duplicate_command_cached_success_summary,
    duplicate_command_completion_summary, duplicate_command_execution_summary,
    find_matching_command_history_entry,
};
use self::grounding::apply_instruction_contract_grounding;
use self::phases::{
    apply_post_execution_guards, execute_tool_phase, finalize_action_processing,
    ActionProcessingState, ApplyPostExecutionGuardsContext, ExecuteToolPhaseContext,
    FinalizeActionProcessingContext,
};
pub(crate) use self::phases::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event,
    emit_execution_contract_receipt_event_with_observation, record_non_command_success_receipts,
    resolved_intent_id,
};
use self::repair::{
    attempt_invalid_tool_call_repair, attempt_patch_build_verify_runtime_patch_miss_repair,
    attempt_refusal_repair, maybe_rewrite_patch_build_verify_post_command_edit,
    maybe_rewrite_patch_build_verify_post_success_completion,
    maybe_rewrite_patch_build_verify_redundant_refresh_read,
};
use self::web_helpers::{
    extract_web_read_url_from_payload, is_empty_memory_search_output,
    is_transient_browser_snapshot_unexpected_state, queue_web_search_bootstrap,
    should_fail_fast_web_timeout, should_use_web_research_path,
};

pub fn resolve_action_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

fn extract_system_refusal_reason(tool_call_result: &str) -> Option<String> {
    if !tool_call_result.contains("\"name\":\"system::refusal\"") {
        return None;
    }

    serde_json::from_str::<serde_json::Value>(tool_call_result)
        .ok()
        .and_then(|value| {
            value
                .get("arguments")
                .and_then(|arguments| arguments.get("reason"))
                .and_then(|reason| reason.as_str())
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .map(str::to_string)
        })
}

fn tool_normalization_payload(
    observation: &middleware::ToolNormalizationObservation,
) -> serde_json::Value {
    json!({
        "raw_name": observation.raw_name,
        "normalized_name": observation.normalized_name,
        "changed": observation.changed(),
        "labels": observation.labels,
    })
}

fn record_tool_normalization_observation(
    processing_state: &mut ActionProcessingState,
    observation: &middleware::ToolNormalizationObservation,
) {
    processing_state
        .verification_checks
        .push("tool_normalization_observed=true".to_string());
    processing_state.verification_checks.push(format!(
        "tool_normalization_changed={}",
        observation.changed()
    ));
    if let Some(raw_name) = observation.raw_name.as_deref() {
        processing_state
            .verification_checks
            .push(format!("tool_normalization_raw_name={}", raw_name));
    }
    if let Some(normalized_name) = observation.normalized_name.as_deref() {
        processing_state
            .verification_checks
            .push(format!("tool_normalization_name={}", normalized_name));
    }
    for label in &observation.labels {
        processing_state
            .verification_checks
            .push(format!("tool_normalization_label={}", label));
    }
    processing_state.tool_normalization_observation = Some(tool_normalization_payload(observation));
}

fn attach_tool_normalization_observation(
    action_payload: &mut serde_json::Value,
    observation: Option<&serde_json::Value>,
) {
    let Some(observation) = observation else {
        return;
    };
    if let Some(payload) = action_payload.as_object_mut() {
        payload.insert("tool_normalization".to_string(), observation.clone());
    }
}

pub async fn process_tool_output(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    tool_call_result: String,
    final_visual_phash: [u8; 32],
    strategy_used: String,
    session_id: [u8; 32],
    block_height: u64,
    block_timestamp_ns: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<(), TransactionError> {
    let key = get_state_key(&session_id);
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_action_routing_context(agent_state);
    let tool_version = env!("CARGO_PKG_VERSION");
    let mut processing_state = ActionProcessingState::new(&tool_call_result);
    let refusal_reason = extract_system_refusal_reason(&tool_call_result);

    let refusal_repair = if let Some(reason) = refusal_reason.as_deref() {
        if !should_use_web_research_path(agent_state)
            && !is_mailbox_connector_goal(&agent_state.goal)
        {
            Some(attempt_refusal_repair(service, state, agent_state, session_id, reason).await?)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(repair_attempt) = refusal_repair.as_ref() {
        processing_state
            .verification_checks
            .extend(repair_attempt.verification_checks.clone());
    }

    // 1. Raw Refusal Interceptor
    if refusal_repair
        .as_ref()
        .and_then(|attempt| attempt.repaired_tool.as_ref())
        .is_none()
    {
        if refusal::intercept_raw_refusal(
            service,
            state,
            agent_state,
            &key,
            session_id,
            final_visual_phash,
            &tool_call_result,
            &routing_decision,
            &pre_state_summary,
            tool_version,
        )
        .await?
        {
            return Ok(());
        }
    }

    // 2. Normalize & Expand
    let tool_call = if let Some(repaired_tool) =
        refusal_repair.and_then(|attempt| attempt.repaired_tool)
    {
        Ok(repaired_tool)
    } else {
        match middleware::normalize_tool_call_with_observation(&tool_call_result) {
            Ok(result) => {
                record_tool_normalization_observation(&mut processing_state, &result.observation);
                Ok(result.tool)
            }
            Err(error) => {
                if !should_use_web_research_path(agent_state)
                    && !is_mailbox_connector_goal(&agent_state.goal)
                {
                    let repair_attempt = attempt_invalid_tool_call_repair(
                        service,
                        state,
                        agent_state,
                        session_id,
                        &tool_call_result,
                        &error.to_string(),
                    )
                    .await?;
                    processing_state
                        .verification_checks
                        .extend(repair_attempt.verification_checks);
                    if let Some(repaired_tool) = repair_attempt.repaired_tool {
                        Ok(repaired_tool)
                    } else {
                        Err(error)
                    }
                } else {
                    Err(error)
                }
            }
        }
    };

    // Check for Skill / Macro Match
    if let Ok(AgentTool::Dynamic(ref val)) = tool_call {
        if let Some(name) = val.get("name").and_then(|n| n.as_str()) {
            if let Some((macro_def, skill_hash)) = service.fetch_skill_macro(state, name) {
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
                            service.memory_runtime.as_ref(),
                        )?;
                        agent_state.step_count += 1;
                        persist_agent_state(
                            state,
                            &key,
                            &agent_state,
                            service.memory_runtime.as_ref(),
                        )?;
                        return Ok(());
                    }
                    Err(_e) => {
                        // ... handle error ...
                        return Ok(());
                    }
                }
            }
        }
    }

    let tool_call = match tool_call {
        Ok(tool) => {
            let mut tool = apply_instruction_contract_grounding(
                state,
                service,
                agent_state,
                tool,
                &rules,
                session_id,
                pre_state_summary.step_index,
                &resolved_intent_id(agent_state),
                None,
                &mut processing_state.verification_checks,
            )
            .await?;
            normalize_web_research_tool_call(
                &mut tool,
                agent_state.resolved_intent.as_ref(),
                &agent_state.goal,
            );
            if let Some((requested_url, replacement_url)) = reconcile_pending_web_research_tool_call(
                &mut tool,
                agent_state.pending_search_completion.as_ref(),
            ) {
                processing_state
                    .verification_checks
                    .push("web_read_reconciled_from_exhausted_pending_candidate=true".to_string());
                processing_state.verification_checks.push(format!(
                    "web_read_reconciled_requested_url={}",
                    requested_url
                ));
                processing_state.verification_checks.push(format!(
                    "web_read_reconciled_replacement_url={}",
                    replacement_url
                ));
            }
            if let Some(rewritten_tool) = maybe_rewrite_patch_build_verify_redundant_refresh_read(
                state,
                agent_state,
                session_id,
                &tool,
                &mut processing_state.verification_checks,
            ) {
                tool = rewritten_tool;
            }
            if let Some(rewritten_tool) = maybe_rewrite_patch_build_verify_post_command_edit(
                state,
                agent_state,
                session_id,
                &tool,
                &mut processing_state.verification_checks,
            )
            .await?
            {
                tool = rewritten_tool;
            }
            if let Some(rewritten_tool) = maybe_rewrite_patch_build_verify_post_success_completion(
                state,
                agent_state,
                session_id,
                &tool,
                &mut processing_state.verification_checks,
            ) {
                tool = rewritten_tool;
            }
            Ok(tool)
        }
        Err(error) => Err(error),
    };

    let (_req_hash, req_hash_hex) = match tool_call.as_ref() {
        Ok(t) => {
            let target = t.target();
            let window_binding = if target_requires_window_binding(&target) {
                let os_driver = service.os_driver.as_ref().ok_or_else(|| {
                    TransactionError::Invalid(
                        "ERROR_CLASS=DeterminismBoundary Missing OS driver for window-bound action."
                            .to_string(),
                    )
                })?;
                resolve_window_binding_for_target(
                    os_driver,
                    session_id,
                    &target,
                    "pre_action_request_hash",
                )
                .await?
            } else {
                None
            };
            let tool_val = serde_json::to_value(t).unwrap_or(json!({}));
            let args_val = tool_val.get("arguments").cloned().unwrap_or(json!({}));
            let params = serde_jcs::to_vec(&args_val)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;
            let req = ActionRequest {
                target,
                params,
                context: ActionContext {
                    agent_id: "desktop_agent".into(),
                    session_id: Some(session_id),
                    window_id: window_binding,
                },
                nonce: agent_state.step_count as u64,
            };
            let h = req.try_hash().map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=DeterminismBoundary Failed to hash tool request: {}",
                    e
                ))
            })?;
            (h, hex::encode(h))
        }
        Err(_) => ([0u8; 32], String::new()),
    };

    if !req_hash_hex.is_empty() {
        if let Some(status) = agent_state.tool_execution_log.get(&req_hash_hex) {
            if matches!(status, ToolCallStatus::Executed(_)) {
                log::info!("Skipping idempotent step");
                agent_state.step_count += 1;
                agent_state.pending_tool_call = None;
                agent_state.pending_tool_jcs = None;
                agent_state.pending_request_nonce = None;
                agent_state.pending_approval = None;
                agent_state.status = AgentStatus::Running;
                persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
                return Ok(());
            }
        }
    }

    match tool_call {
        Ok(tool) => {
            processing_state.action_payload =
                serde_json::to_value(&tool).unwrap_or_else(|_| json!({}));
            attach_tool_normalization_observation(
                &mut processing_state.action_payload,
                processing_state.tool_normalization_observation.as_ref(),
            );
            let (tool_name, tool_args) = canonical_tool_identity(&tool);
            processing_state.current_tool_name = tool_name;
            processing_state.executed_tool_jcs = Some(
                serde_jcs::to_vec(&tool)
                    .map_err(|e| TransactionError::Serialization(e.to_string()))?,
            );
            processing_state.intent_hash = canonical_intent_hash(
                &processing_state.current_tool_name,
                &tool_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            processing_state.retry_intent_hash = Some(canonical_retry_intent_hash(
                &processing_state.current_tool_name,
                &tool_args,
                routing_decision.tier,
                tool_version,
            ));

            let mailbox_intent = is_mailbox_connector_goal(&agent_state.goal);
            let attempted_web_path_tool =
                processing_state.current_tool_name.starts_with("browser__")
                    || processing_state.current_tool_name.starts_with("web__")
                    || processing_state.current_tool_name == "memory__search";
            let mailbox_connector_tool =
                is_mail_connector_tool_name(&processing_state.current_tool_name);
            if mailbox_intent && attempted_web_path_tool && !mailbox_connector_tool {
                let run_timestamp_ms = block_timestamp_ns / 1_000_000;
                let summary =
                    render_mailbox_access_limited_reply(&agent_state.goal, run_timestamp_ms);
                processing_state.success = true;
                processing_state.error_msg = None;
                processing_state.history_entry = Some(summary.clone());
                processing_state.action_output = Some(summary.clone());
                processing_state.terminal_chat_reply_output = Some(summary.clone());
                processing_state.is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                processing_state
                    .verification_checks
                    .push("mailbox_connector_path_required=true".to_string());
                processing_state
                    .verification_checks
                    .push("mailbox_non_connector_tool_blocked=true".to_string());
                processing_state
                    .verification_checks
                    .push("terminal_chat_reply_ready=true".to_string());
            } else {
                processing_state = execute_tool_phase(
                    ExecuteToolPhaseContext {
                        service,
                        state,
                        agent_state,
                        call_context,
                        tool,
                        tool_args,
                        rules: &rules,
                        session_id,
                        block_height,
                        block_timestamp_ns,
                        final_visual_phash,
                        req_hash_hex: req_hash_hex.clone(),
                        tool_call_result: tool_call_result.clone(),
                        pre_state_summary: pre_state_summary.clone(),
                    },
                    processing_state,
                )
                .await?;
            }
        }
        Err(e) => {
            // Tool-call schema/parse errors are not policy denials. Mark them as deterministic
            // UnexpectedState so anti-loop + evidence don't imply approval/policy gating.
            processing_state.policy_decision = "allowed".to_string();
            processing_state.current_tool_name = "system::invalid_tool_call".to_string();
            let parse_error = format!("Failed to parse tool call: {}", e);
            let parse_args = json!({
                "raw_tool_output": tool_call_result,
                "parse_error": parse_error,
            });

            processing_state
                .verification_checks
                .push("schema_validation_error=true".to_string());

            processing_state.intent_hash = canonical_intent_hash(
                &processing_state.current_tool_name,
                &parse_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            processing_state.retry_intent_hash = Some(canonical_retry_intent_hash(
                &processing_state.current_tool_name,
                &parse_args,
                routing_decision.tier,
                tool_version,
            ));
            processing_state.action_payload = json!({
                "name": processing_state.current_tool_name.clone(),
                "arguments": parse_args,
            });
            attach_tool_normalization_observation(
                &mut processing_state.action_payload,
                processing_state.tool_normalization_observation.as_ref(),
            );
            // Prefix ERROR_CLASS so anti-loop classification is deterministic.
            processing_state.error_msg =
                Some(format!("ERROR_CLASS=UnexpectedState {}", parse_error));
            let empty_output = tool_call_result.trim().is_empty();
            if empty_output && should_use_web_research_path(agent_state) {
                processing_state.invalid_tool_call_bootstrap_web = true;
            } else if should_use_web_research_path(agent_state) {
                processing_state.invalid_tool_call_fail_fast = true;
            } else if is_mailbox_connector_goal(&agent_state.goal) {
                processing_state.invalid_tool_call_fail_fast = true;
                processing_state.invalid_tool_call_fail_fast_mailbox = true;
            }
        }
    }

    processing_state = apply_post_execution_guards(
        ApplyPostExecutionGuardsContext {
            service,
            state,
            agent_state,
            session_id,
            block_height,
            block_timestamp_ns,
            tool_call_result: tool_call_result.clone(),
            final_visual_phash,
        },
        processing_state,
    )
    .await?;

    finalize_action_processing(
        FinalizeActionProcessingContext {
            service,
            state,
            agent_state,
            rules: &rules,
            session_id,
            block_height,
            strategy_used,
            tool_call_result,
            final_visual_phash,
            key,
            routing_decision,
            pre_state_summary,
            tool_version,
        },
        processing_state,
    )
    .await
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
