use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::execution::system::is_sudo_password_required_install_error;
use crate::agentic::runtime::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use crate::agentic::runtime::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
use crate::agentic::runtime::service::planning::planner::{
    self, PlannerDispatchMatch, PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH,
};
use crate::agentic::runtime::service::recovery::anti_loop::TierRoutingDecision;
use crate::agentic::runtime::service::recovery::anti_loop::{
    build_attempt_key, build_post_state_summary, canonical_attempt_window_fingerprint,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
};
use crate::agentic::runtime::service::recovery::incident::{
    advance_incident_after_action_outcome, clear_incident_state, incident_receipt_fields,
    load_incident_state, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::runtime::service::tool_execution::command_contract::is_completion_contract_error;
use crate::agentic::runtime::service::tool_execution::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    mark_action_fingerprint_executed_at_step, persist_step_evidence_to_ledger, resolved_intent_id,
};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus, ExecutionStage, StepAgentParams};
use crate::agentic::runtime::utils::{goto_trace_log, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::IntentScopeProfile;
use ioi_types::app::{RoutingReceiptEvent, RoutingStateSummary};
use ioi_types::codec;
use ioi_types::error::TransactionError;

mod completion;
mod completion_receipts;
mod execution;
mod failure;
mod messaging;
mod pause_state;
mod routing;
mod terminal_reply;
mod web_pipeline;
mod workspace_receipts;

use self::completion::{
    maybe_complete_agent_complete, maybe_complete_browser_snapshot_interaction,
    maybe_complete_chat_reply, maybe_complete_command_probe, maybe_complete_mail_reply,
    maybe_complete_open_app, maybe_complete_screenshot_capture, normalize_output_only_success,
};
use self::completion_receipts::emit_terminal_chat_reply_receipts;
use self::execution::{execute_queue_tool_request, queue_action_to_tool};
use self::failure::{apply_queue_failure_policies, QueueFailureHandlingOutcome};
use self::messaging::{
    enter_wait_for_clarification, enter_wait_for_sudo_password, record_pending_approval_wait,
    resolve_approval_directive_outcome,
};
use self::pause_state::clear_pending_approval_pause;
use self::routing::{is_web_research_scope, resolve_queue_routing_context as resolve_routing};
use self::terminal_reply::is_absorbed_pending_web_read_gate;
pub(crate) use self::web_pipeline::maybe_handle_web_search as handle_web_search_result;
use self::web_pipeline::{
    maybe_handle_browser_snapshot, maybe_handle_web_read, maybe_handle_web_search,
};
use self::workspace_receipts::record_queue_workspace_success_receipts;

pub fn resolve_queue_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    resolve_routing(agent_state)
}

pub async fn process_queue_item(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    block_timestamp_ns: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<(), TransactionError> {
    log::info!(
        "Draining execution queue for session {} (Pending: {})",
        hex::encode(&p.session_id[..4]),
        agent_state.execution_queue.len()
    );

    let key = get_state_key(&p.session_id);
    let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_queue_routing_context(agent_state);
    let mut policy_decision = "allowed".to_string();

    let action_request = agent_state.execution_queue.remove(0);
    let active_skill = agent_state.active_skill_hash;

    let tool_wrapper = queue_action_to_tool(&action_request)?;
    let tool_jcs = serde_jcs::to_vec(&tool_wrapper)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = sha256(&tool_jcs)
        .map_err(|e| TransactionError::Invalid(format!("Failed to hash queued tool JCS: {}", e)))?;
    let (tool_name, intent_args) = canonical_tool_identity(&tool_wrapper);
    let action_json = serde_json::to_string(&tool_wrapper).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &intent_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        env!("CARGO_PKG_VERSION"),
    );
    let retry_intent_hash = canonical_retry_intent_hash(
        &tool_name,
        &intent_args,
        routing_decision.tier,
        env!("CARGO_PKG_VERSION"),
    );
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    let mut verification_checks = Vec::new();
    let action_request_hash_hex = hex::encode(action_request.hash());
    let resolved_intent_snapshot = agent_state.resolved_intent.clone();
    let mut planner_step_index: Option<usize> = None;

    let mut planner_executor_mismatch_reason: Option<String> = None;
    if let Some(planner_state) = agent_state.planner_state.as_ref() {
        if let Some(dispatch_match) =
            planner::match_dispatched_step_for_execution(planner_state, &tool_name, &intent_args)?
        {
            match dispatch_match {
                PlannerDispatchMatch::Matched {
                    step_index,
                    step_id,
                } => {
                    planner_step_index = Some(step_index);
                    verification_checks.push("planner_executor_match=true".to_string());
                    verification_checks.push(format!("planner_step_id={}", step_id));
                }
                PlannerDispatchMatch::Mismatch {
                    step_index,
                    step_id,
                    expected_tool_name,
                } => {
                    let reason = format!(
                        "ERROR_CLASS=PolicyBlocked {} expected='{}' observed='{}' step_id='{}'",
                        PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH,
                        expected_tool_name,
                        tool_name,
                        step_id
                    );
                    planner_step_index = Some(step_index);
                    planner_executor_mismatch_reason = Some(reason);
                    verification_checks.push("planner_executor_match=false".to_string());
                    verification_checks.push(format!(
                        "planner_executor_expected_tool={}",
                        expected_tool_name
                    ));
                    verification_checks.push(format!("planner_step_id={}", step_id));
                }
            }
        }
    }

    if let Some(reason) = planner_executor_mismatch_reason.as_deref() {
        policy_decision = "denied".to_string();
        if let Some(step_index) = planner_step_index {
            if let Some(planner_state) = agent_state.planner_state.as_mut() {
                planner::record_planner_step_outcome(
                    planner_state,
                    step_index,
                    false,
                    true,
                    true,
                    Some(reason),
                    Some(action_request_hash_hex.as_str()),
                    resolved_intent_snapshot.as_ref(),
                )?;
                planner::mark_planner_fallback(
                    planner_state,
                    PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH,
                    resolved_intent_snapshot.as_ref(),
                );
            }
        }
    }

    let result_tuple = if let Some(reason) = planner_executor_mismatch_reason.clone() {
        Ok((false, None, Some(reason), None))
    } else {
        execute_queue_tool_request(
            service,
            state,
            call_context,
            agent_state,
            tool_wrapper.clone(),
            &tool_name,
            &rules,
            p.session_id,
            tool_hash_bytes,
        )
        .await
    };

    let mut is_gated = false;
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;
    let mut trace_visual_hash = [0u8; 32];
    let (mut success, mut out, mut err, persisted_visual_hash): (
        bool,
        Option<String>,
        Option<String>,
        Option<[u8; 32]>,
    ) = match result_tuple {
        Ok(tuple) => tuple,
        Err(TransactionError::PendingApproval(h)) => {
            policy_decision = "require_approval".to_string();
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            let pending_visual_hash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
            let action_fingerprint = sha256(&tool_jcs)
                .map(hex::encode)
                .unwrap_or_else(|_| String::new());
            if let Ok(bytes) = hex::decode(&h) {
                if bytes.len() == 32 {
                    let mut decision_hash = [0u8; 32];
                    decision_hash.copy_from_slice(&bytes);
                    if let Some(request) = build_pii_review_request_for_tool(
                        service,
                        &rules,
                        p.session_id,
                        &tool_wrapper,
                        decision_hash,
                        block_timestamp_ns / 1_000_000,
                    )
                    .await?
                    {
                        persist_pii_review_request(state, &request)?;
                        emit_pii_review_requested(service, &request);
                    }
                }
            }
            let incident_before = load_incident_state(state, &p.session_id)?;
            let incident_stage_before = incident_before
                .as_ref()
                .map(|incident| incident.stage.clone())
                .unwrap_or_else(|| "None".to_string());

            let approval_directive = register_pending_approval(
                state,
                &rules,
                agent_state,
                p.session_id,
                &retry_intent_hash,
                &tool_name,
                &tool_jcs,
                &action_fingerprint,
                &h,
            )?;
            let incident_after = load_incident_state(state, &p.session_id)?;
            let incident_stage_after = incident_after
                .as_ref()
                .map(|incident| incident.stage.clone())
                .unwrap_or_else(|| "None".to_string());
            verification_checks.push(format!(
                "approval_suppressed_single_pending={}",
                matches!(
                    approval_directive,
                    ApprovalDirective::SuppressDuplicatePrompt
                )
            ));
            verification_checks.push(format!(
                "incident_id_stable={}",
                match (incident_before.as_ref(), incident_after.as_ref()) {
                    (Some(before), Some(after)) => before.incident_id == after.incident_id,
                    _ => true,
                }
            ));
            verification_checks.push(format!("incident_stage_before={}", incident_stage_before));
            verification_checks.push(format!("incident_stage_after={}", incident_stage_after));

            record_pending_approval_wait(
                agent_state,
                &action_json,
                &tool_jcs,
                hash_arr,
                pending_visual_hash,
            );
            is_gated = true;

            if let Some(incident_state) = load_incident_state(state, &p.session_id)? {
                if incident_state.active {
                    log::info!(
                        "incident.approval_intercepted session={} incident_id={} root_tool={} gated_tool={}",
                        hex::encode(&p.session_id[..4]),
                        incident_state.incident_id,
                        incident_state.root_tool_name,
                        tool_name
                    );
                }
            }

            resolve_approval_directive_outcome(
                service,
                agent_state,
                p.session_id,
                block_height,
                &h,
                approval_directive,
                &mut policy_decision,
            )
            .await?
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.to_lowercase().contains("blocked by policy") {
                policy_decision = "denied".to_string();
            }
            (false, None, Some(msg), None)
        }
    };
    if let Some(visual_hash) = persisted_visual_hash {
        trace_visual_hash = visual_hash;
        verification_checks.push(format!(
            "visual_observation_checksum={}",
            hex::encode(visual_hash)
        ));
    }
    normalize_output_only_success(
        &tool_name,
        &mut success,
        &out,
        &err,
        &mut verification_checks,
    );
    if !is_gated
        && command_scope
        && !success
        && matches!(
            &tool_wrapper,
            ioi_types::app::agentic::AgentTool::SysExec { .. }
                | ioi_types::app::agentic::AgentTool::SysExecSession { .. }
        )
    {
        let cause = err
            .clone()
            .unwrap_or_else(|| "unknown execution failure".to_string());
        if !cause.contains("ERROR_CLASS=ExecutionFailedTerminal") {
            err = Some(format!(
                "ERROR_CLASS=ExecutionFailedTerminal stage=execution cause={}",
                cause
            ));
        }
    }
    let is_install_package_tool = tool_name == "package__install"
        || tool_name == "sys::install_package"
        || tool_name.ends_with("install_package");
    let clarification_required = !success
        && err
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&tool_name, msg))
            .unwrap_or(false);

    if !is_gated
        && !success
        && is_install_package_tool
        && err
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        enter_wait_for_sudo_password(
            service,
            state,
            agent_state,
            p.session_id,
            block_height,
            &tool_name,
            err.as_deref(),
            &action_json,
            &tool_jcs,
            &mut verification_checks,
        )
        .await?;
    }

    if !is_gated && clarification_required {
        awaiting_clarification = true;
        enter_wait_for_clarification(
            service,
            state,
            agent_state,
            p.session_id,
            block_height,
            &tool_name,
            err.as_deref(),
            &mut verification_checks,
        )
        .await?;
    }
    let mut completion_summary: Option<String> = None;
    maybe_handle_web_search(
        service,
        agent_state,
        p.session_id,
        pre_state_summary.step_index,
        &tool_name,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
    )
    .await?;
    maybe_handle_web_read(
        service,
        agent_state,
        p.session_id,
        pre_state_summary.step_index,
        &tool_name,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
    )
    .await?;
    let absorbed_pending_web_read_gate =
        is_gated && is_absorbed_pending_web_read_gate(&tool_name, out.as_deref());
    if absorbed_pending_web_read_gate {
        clear_incident_state(state, &p.session_id)?;
        clear_pending_approval_pause(agent_state);
        is_gated = false;
        verification_checks.push("web_pipeline_gated_read_absorbed=true".to_string());
        verification_checks.push("approval_pending_cleared=true".to_string());
    }
    maybe_handle_browser_snapshot(
        agent_state,
        p.session_id,
        &tool_name,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
    );
    maybe_complete_command_probe(
        agent_state,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_agent_complete(
        agent_state,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_open_app(
        agent_state,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_screenshot_capture(
        agent_state,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_browser_snapshot_interaction(
        agent_state,
        &tool_name,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_mail_reply(
        agent_state,
        &tool_name,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );
    maybe_complete_chat_reply(
        agent_state,
        &tool_wrapper,
        is_gated,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        p.session_id,
    );

    let output_str = out.clone().unwrap_or_default();
    let error_str = err.clone();

    if success && !is_gated {
        let intent_id = resolved_intent_id(agent_state);
        record_queue_workspace_success_receipts(
            service,
            agent_state,
            &tool_wrapper,
            p.session_id,
            pre_state_summary.step_index,
            intent_id.as_str(),
            &mut verification_checks,
        );
    }

    if success && !is_gated {
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            &retry_intent_hash,
            pre_state_summary.step_index,
            "success",
        );
    }

    goto_trace_log(
        agent_state,
        state,
        &key,
        p.session_id,
        trace_visual_hash,
        "[Macro Step] Executing queued action".to_string(),
        output_str,
        success,
        error_str,
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill,
        service.memory_runtime.as_ref(),
    )?;

    if let Some(summary) = completion_summary.as_ref() {
        let intent_id = resolved_intent_id(agent_state);
        emit_terminal_chat_reply_receipts(
            service,
            p.session_id,
            pre_state_summary.step_index,
            agent_state.step_count,
            intent_id.as_str(),
            summary,
            &mut verification_checks,
        );
    }

    let QueueFailureHandlingOutcome {
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
    } = apply_queue_failure_policies(
        service,
        state,
        agent_state,
        p,
        block_height,
        &routing_decision,
        &rules,
        &retry_intent_hash,
        &tool_name,
        &tool_jcs,
        &policy_decision,
        &mut success,
        &mut out,
        &mut err,
        is_gated,
        awaiting_sudo_password,
        &mut awaiting_clarification,
        &mut verification_checks,
    )
    .await?;

    if planner_executor_mismatch_reason.is_none() {
        if let Some(step_index) = planner_step_index {
            let planner_blocked = is_gated
                || awaiting_sudo_password
                || awaiting_clarification
                || policy_decision == "denied";
            let planner_terminal_failure = !success && stop_condition_hit;
            if let Some(planner_state) = agent_state.planner_state.as_mut() {
                planner::record_planner_step_outcome(
                    planner_state,
                    step_index,
                    success,
                    planner_blocked,
                    planner_terminal_failure,
                    err.as_deref(),
                    Some(action_request_hash_hex.as_str()),
                    resolved_intent_snapshot.as_ref(),
                )?;
            }
            verification_checks.push("planner_step_outcome_recorded=true".to_string());
            verification_checks.push(format!("planner_step_index={}", step_index));
            verification_checks.push(format!("planner_step_blocked={}", planner_blocked));
            verification_checks.push(format!(
                "planner_step_terminal_failure={}",
                planner_terminal_failure
            ));
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_gated={}", is_gated));
    verification_checks.push(format!("awaiting_sudo_password={}", awaiting_sudo_password));
    verification_checks.push(format!("awaiting_clarification={}", awaiting_clarification));
    verification_checks.push("was_queue=true".to_string());
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

    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        agent_state.step_count += 1;
    }

    if success && !stop_condition_hit && !is_gated {
        agent_state.consecutive_failures = 0;
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!(
        "trace://session/{}",
        hex::encode(&p.session_id[..4])
    ));
    let intent_id_for_contract = resolved_intent_id(agent_state);
    persist_step_evidence_to_ledger(
        agent_state,
        intent_id_for_contract.as_str(),
        &verification_checks,
    );
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &p.session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
    let route_decision =
        crate::agentic::runtime::service::decision_loop::route_projection::project_route_decision(
            service,
            state,
            agent_state,
            &tool_name,
            agent_state.current_tier,
        )
        .await;
    let receipt = RoutingReceiptEvent {
        session_id: p.session_id,
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
        lineage_ptr: lineage_pointer(active_skill),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &p.session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
        route_decision,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;

    Ok(())
}
