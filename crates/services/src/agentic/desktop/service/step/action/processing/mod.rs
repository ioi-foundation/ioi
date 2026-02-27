use super::command_contract::{
    capability_route_label, command_arms_deferred_notification_path, compose_terminal_chat_reply,
    enrich_command_scope_summary, execution_contract_violation_error, is_cec_terminal_error,
    missing_execution_contract_markers, record_provider_selection_receipts,
    record_timer_notification_contract_requirement, record_verification_receipts,
    requires_timer_notification_contract, runtime_host_environment_receipt,
    synthesize_allowlisted_timer_notification_tool, sys_exec_arms_timer_delay_backend,
    sys_exec_command_preview, sys_exec_foreign_absolute_home_path,
    sys_exec_satisfies_clock_read_contract, CLOCK_TIMESTAMP_POSTCONDITION,
    PROVIDER_SELECTION_COMMIT_RECEIPT, TIMER_NOTIFICATION_PATH_POSTCONDITION,
    TIMER_SLEEP_BACKEND_POSTCONDITION, VERIFICATION_COMMIT_RECEIPT,
};
use super::probe::{
    is_command_probe_intent, is_system_clock_read_intent, summarize_command_probe_output,
    summarize_system_clock_or_plain_output,
};
use super::refusal_eval::evaluate_and_crystallize;
use super::search::{extract_navigation_url, is_search_results_url, search_query_from_url};
use super::support::{
    action_fingerprint_execution_step, canonical_intent_hash, canonical_retry_intent_hash,
    canonical_tool_identity, drop_legacy_action_fingerprint_receipt,
    enforce_system_fail_terminal_status, execution_receipt_value, get_status_str,
    has_execution_receipt, mark_action_fingerprint_executed_at_step, mark_execution_postcondition,
    mark_execution_receipt, mark_execution_receipt_with_value, mark_system_fail_status,
    postcondition_marker, receipt_marker,
};
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
use crate::agentic::desktop::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
    TierRoutingDecision,
};
use crate::agentic::desktop::service::step::helpers::{
    default_safe_policy, is_mailbox_connector_goal, should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_incident_wait_for_user, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    is_human_challenge_error, mark_pending_web_attempted, mark_pending_web_blocked,
    parse_web_evidence_bundle, remaining_pending_web_candidates,
    render_mailbox_access_limited_reply, synthesize_web_pipeline_reply,
    synthesize_web_pipeline_reply_hybrid, web_pipeline_min_sources, web_pipeline_now_ms,
    WebPipelineCompletionReason,
};
use crate::agentic::desktop::service::step::signals::is_mail_connector_tool_name;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, PendingSearchCompletion, ToolCallStatus, MAX_COMMAND_HISTORY,
};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
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
mod phases;
mod refusal;
mod web_helpers;
mod web_pre_read;

use self::duplicate_guard::{
    duplicate_command_cached_completion_summary, duplicate_command_cached_success_summary,
    duplicate_command_completion_summary, duplicate_command_execution_summary,
    find_matching_command_history_entry,
};
use self::phases::{
    apply_post_execution_guards, execute_tool_phase, finalize_action_processing,
    ActionProcessingState, ApplyPostExecutionGuardsContext, ExecuteToolPhaseContext,
    FinalizeActionProcessingContext,
};
use self::web_helpers::{
    extract_web_read_url_from_payload, is_empty_memory_search_output,
    is_transient_browser_snapshot_unexpected_state, queue_web_search_bootstrap,
    should_fail_fast_web_timeout, should_use_web_research_path,
};
use self::web_pre_read::apply_pre_read_bundle;

pub fn resolve_action_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
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

    // 1. Raw Refusal Interceptor
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

    // 2. Normalize & Expand
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
                    Err(_e) => {
                        // ... handle error ...
                        return Ok(());
                    }
                }
            }
        }
    }

    let (_req_hash, req_hash_hex) = if let Ok(ref t) = tool_call {
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

    match tool_call {
        Ok(tool) => {
            processing_state.action_payload =
                serde_json::to_value(&tool).unwrap_or_else(|_| json!({}));
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
            // UnexpectedState so anti-loop + receipts don't imply approval/policy gating.
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
mod tests {
    use super::{duplicate_command_completion_summary, should_fail_fast_web_timeout};
    use crate::agentic::desktop::service::step::action::command_contract::{
        execution_contract_violation_error, upsert_structured_field, TARGET_UTC_MARKER,
    };
    use crate::agentic::desktop::service::step::anti_loop::FailureClass;
    use crate::agentic::desktop::types::CommandExecution;
    use ioi_types::app::agentic::{
        AgentTool, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "test".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.92,
            top_k: vec![],
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        }
    }

    #[test]
    fn web_research_timeout_tools_fail_fast() {
        let intent = resolved(IntentScopeProfile::WebResearch);
        assert!(should_fail_fast_web_timeout(
            Some(&intent),
            "web__search",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(should_fail_fast_web_timeout(
            Some(&intent),
            "web__read",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(should_fail_fast_web_timeout(
            Some(&intent),
            "browser__navigate",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(!should_fail_fast_web_timeout(
            Some(&intent),
            "web__read",
            FailureClass::TimeoutOrHang,
            true
        ));
    }

    #[test]
    fn non_matching_cases_do_not_fail_fast() {
        let web = resolved(IntentScopeProfile::WebResearch);
        let convo = resolved(IntentScopeProfile::Conversation);

        assert!(!should_fail_fast_web_timeout(
            Some(&web),
            "filesystem__list_directory",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(!should_fail_fast_web_timeout(
            Some(&convo),
            "browser__navigate",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(!should_fail_fast_web_timeout(
            Some(&convo),
            "web__search",
            FailureClass::TimeoutOrHang,
            false
        ));
        assert!(!should_fail_fast_web_timeout(
            Some(&web),
            "web__search",
            FailureClass::UnexpectedState,
            false
        ));
    }

    #[test]
    fn duplicate_timer_exec_terminalizes_with_structured_evidence() {
        let tool = AgentTool::SysExec {
            command: "sleep".to_string(),
            args: vec!["900".to_string()],
            stdin: None,
            detach: true,
        };
        let history = CommandExecution {
            command: "sleep 900".to_string(),
            exit_code: 0,
            stdout: "Launched background process 'sleep' (PID: 167007)".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_771_931_911_073,
            step_index: 0,
        };

        let summary = duplicate_command_completion_summary(&tool, Some(&history))
            .expect("expected deterministic duplicate completion");
        assert!(summary.contains("Timer scheduled."));
        assert!(summary.contains("Mechanism: Detached sys__exec command 'sleep 900'"));
        assert!(summary.contains("Run timestamp (UTC):"));
        assert!(summary.contains("Target UTC:"));
    }

    #[test]
    fn duplicate_timer_exec_terminalizes_with_script_command_and_redacted_history() {
        let tool = AgentTool::SysExec {
            command: "bash".to_string(),
            args: vec![
                "-lc".to_string(),
                "nohup sh -c 'sleep 900 && notify-send Timer Done' &".to_string(),
            ],
            stdin: None,
            detach: true,
        };
        let history = CommandExecution {
            command: "[REDACTED_PII]".to_string(),
            exit_code: 0,
            stdout: "Launched background process 'bash' (PID: 3210)".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_771_931_911_073,
            step_index: 1,
        };

        let summary = duplicate_command_completion_summary(&tool, Some(&history))
            .expect("expected deterministic duplicate completion for script timer");
        assert!(summary.contains("Timer scheduled."));
        assert!(summary.contains("Mechanism: Detached sys__exec command 'bash -lc"));
        assert!(summary.contains("Run timestamp (UTC):"));
        assert!(summary.contains("Target UTC:"));
    }

    #[test]
    fn duplicate_timer_exec_requires_detached_command() {
        let tool = AgentTool::SysExec {
            command: "sleep".to_string(),
            args: vec!["900".to_string()],
            stdin: None,
            detach: false,
        };
        let history = CommandExecution {
            command: "sleep 900".to_string(),
            exit_code: 0,
            stdout: "Launched background process 'sleep' (PID: 167007)".to_string(),
            stderr: String::new(),
            timestamp_ms: 1_771_931_911_073,
            step_index: 0,
        };

        assert!(duplicate_command_completion_summary(&tool, Some(&history)).is_none());
    }

    #[test]
    fn upsert_structured_field_replaces_inline_marker_segment() {
        let summary = "Timer set. Target UTC: 2023-10-05T14:15:00Z.";
        let updated =
            upsert_structured_field(summary, TARGET_UTC_MARKER, "2026-02-24T13:23:28.938Z");

        assert!(!updated.contains("2023-10-05T14:15:00Z"));
        assert!(updated.contains("Target UTC: 2026-02-24T13:23:28.938Z"));
        assert!(updated.contains("Timer set."));
    }

    #[test]
    fn execution_contract_violation_uses_spec_error_class() {
        let message = execution_contract_violation_error("receipt::verification=true");
        assert!(message.starts_with("ERROR_CLASS=VerificationMissing "));
        assert!(message.contains("base_error_class=ExecutionContractViolation"));
    }
}
