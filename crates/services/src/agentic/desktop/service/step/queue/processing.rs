use super::support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    constraint_grounded_probe_query_with_hints, constraint_grounded_search_limit,
    fallback_search_summary, is_human_challenge_error, mark_pending_web_attempted,
    mark_pending_web_blocked, merge_pending_search_completion, next_pending_web_candidate,
    parse_web_evidence_bundle, pre_read_candidate_plan_from_bundle_with_recovery_mode,
    queue_action_request_to_tool, queue_web_read_from_pipeline, queue_web_search_from_pipeline,
    remaining_pending_web_candidates, select_web_pipeline_query_contract, summarize_search_results,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    web_pipeline_can_queue_initial_read, web_pipeline_can_queue_probe_search,
    web_pipeline_can_queue_probe_search_latency_aware, web_pipeline_completion_reason,
    web_pipeline_min_sources, web_pipeline_now_ms, web_pipeline_remaining_budget_ms,
    web_pipeline_requires_metric_probe_followup, WebPipelineCompletionReason,
    WEB_PIPELINE_BUDGET_MS,
};
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
use crate::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    is_command_probe_intent, summarize_command_probe_output,
};
use crate::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
    TierRoutingDecision,
};
use crate::agentic::desktop::service::step::helpers::{
    default_safe_policy, is_live_external_research_goal, is_mailbox_connector_goal,
    should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_incident_wait_for_user, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::{KernelEvent, RoutingReceiptEvent, RoutingStateSummary};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Applies parity routing for queued actions and snapshots the pre-state after
/// tier selection so receipts and executor context stay coherent.
pub fn resolve_queue_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

fn is_web_research_scope(agent_state: &AgentState) -> bool {
    if is_mailbox_connector_goal(&agent_state.goal) {
        return false;
    }
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
        || is_live_external_research_goal(&agent_state.goal)
}

pub async fn process_queue_item(
    service: &DesktopAgentService,
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

    // Pop the first action
    let action_request = agent_state.execution_queue.remove(0);

    // [NEW] Capture the active skill hash for attribution
    let active_skill = agent_state.active_skill_hash;

    // [FIX] Removed manual ToolExecutor construction.
    // The service method now handles it internally.

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // Re-construct a typed AgentTool from ActionRequest.
    let tool_wrapper = queue_action_request_to_tool(&action_request)?;
    let tool_jcs = serde_jcs::to_vec(&tool_wrapper)
        .or_else(|_| serde_json::to_vec(&tool_wrapper))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
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
    let mut verification_checks = Vec::new();

    // Execute
    // [FIX] Updated call: removed executor arg
    let result_tuple =
        if !is_tool_allowed_for_resolution(agent_state.resolved_intent.as_ref(), &tool_name) {
            Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PermissionOrApprovalRequired Tool '{}' blocked by global intent scope.",
            tool_name
        )))
        } else {
            service
                .handle_action_execution_with_state(
                    state,
                    call_context,
                    tool_wrapper.clone(),
                    p.session_id,
                    agent_state.step_count,
                    [0u8; 32],
                    &rules,
                    &agent_state,
                    &os_driver,
                    None,
                )
                .await
        };

    let mut is_gated = false;
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;
    let (mut success, mut out, mut err): (bool, Option<String>, Option<String>) = match result_tuple
    {
        Ok(tuple) => tuple,
        Err(TransactionError::PendingApproval(h)) => {
            policy_decision = "require_approval".to_string();
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash queued tool JCS: {}", e))
            })?;
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

            agent_state.pending_tool_jcs = Some(tool_jcs.clone());
            agent_state.pending_tool_hash = Some(hash_arr);
            agent_state.pending_visual_hash = Some(pending_visual_hash);
            agent_state.pending_tool_call = Some(action_json.clone());
            agent_state.status = AgentStatus::Paused("Waiting for approval".into());
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

            match approval_directive {
                ApprovalDirective::PromptUser => {
                    let msg = format!(
                        "System: Queued action halted by Agency Firewall (Hash: {}). Requesting authorization.",
                        h
                    );
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: msg,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (true, None, None)
                }
                ApprovalDirective::SuppressDuplicatePrompt => {
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content:
                            "System: Approval already pending for this incident/action. Waiting for your decision."
                                .to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (true, None, None)
                }
                ApprovalDirective::PauseLoop => {
                    policy_decision = "denied".to_string();
                    let loop_msg = format!(
                        "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                        h
                    );
                    agent_state.status = AgentStatus::Paused(
                        "Approval loop detected for the same incident/action. Automatic retries paused."
                            .to_string(),
                    );
                    let sys_msg = ioi_types::app::agentic::ChatMessage {
                        role: "system".to_string(),
                        content: format!(
                            "System: {} Please approve, deny, or change policy settings.",
                            loop_msg
                        ),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                        trace_hash: None,
                    };
                    let _ = service
                        .append_chat_to_scs(p.session_id, &sys_msg, block_height)
                        .await?;
                    (false, None, Some(loop_msg))
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.to_lowercase().contains("blocked by policy") {
                policy_decision = "denied".to_string();
            }
            (false, None, Some(msg))
        }
    };
    let is_install_package_tool = tool_name == "sys__install_package"
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
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            p.session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            err.as_deref(),
        )?;
        // Clear queued remedies while waiting for credentials so resume retries
        // the original install action instead of stale fallback actions.
        agent_state.execution_queue.clear();
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = Some(action_json.clone());
        agent_state.pending_tool_jcs = Some(tool_jcs.clone());
        agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
        let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
            TransactionError::Invalid(format!("Failed to hash queued install tool JCS: {}", e))
        })?;
        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
        agent_state.pending_tool_hash = Some(hash_arr);
        if let Some(err_text) = err.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(p.session_id, &tool_msg, block_height)
                .await?;
        }

        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
                .to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(p.session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_sudo_password=true".to_string());
    }

    if !is_gated && clarification_required {
        awaiting_clarification = true;
        mark_incident_wait_for_user(
            state,
            p.session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            err.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.execution_queue.clear();

        if let Some(err_text) = err.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(p.session_id, &tool_msg, block_height)
                .await?;
        }
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
        let _ = service
            .append_chat_to_scs(p.session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    }
    let mut completion_summary: Option<String> = None;
    let parsed_bundle = out.as_deref().and_then(parse_web_evidence_bundle);
    let promoted_memory_search = tool_name == "memory__search"
        && parsed_bundle
            .as_ref()
            .map(|bundle| bundle.tool == "web__search")
            .unwrap_or(false);
    let effective_web_search = tool_name == "web__search" || promoted_memory_search;
    if promoted_memory_search {
        verification_checks.push("memory_search_promoted_to_web_search=true".to_string());
    }
    if !is_gated && effective_web_search && is_web_research_scope(agent_state) && success {
        if let Some(bundle) = parsed_bundle.as_ref() {
            let query_value = bundle
                .query
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| match &tool_wrapper {
                    AgentTool::WebSearch { query, .. } => {
                        let trimmed = query.trim();
                        (!trimmed.is_empty()).then(|| trimmed.to_string())
                    }
                    AgentTool::MemorySearch { query } => {
                        let trimmed = query.trim();
                        (!trimmed.is_empty()).then(|| trimmed.to_string())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| agent_state.goal.clone());
            let query_contract =
                select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value);
            let min_sources = web_pipeline_min_sources(&query_contract);
            let started_at_ms = web_pipeline_now_ms();
            let prior_pending = agent_state.pending_search_completion.clone();
            let allow_floor_recovery_exploration = prior_pending
                .as_ref()
                .map(|existing| {
                    let min_sources_required = existing.min_sources.max(1) as usize;
                    let successful_sources = existing.successful_reads.len();
                    successful_sources > 0 && successful_sources < min_sources_required
                })
                .unwrap_or(false);
            let candidate_plan = pre_read_candidate_plan_from_bundle_with_recovery_mode(
                &query_contract,
                min_sources,
                bundle,
                allow_floor_recovery_exploration,
            );
            let plan_total_candidates = candidate_plan.total_candidates;
            let plan_pruned_candidates = candidate_plan.pruned_candidates;
            let plan_resolvable_candidates = candidate_plan.resolvable_candidates;
            let probe_source_hints = candidate_plan.probe_source_hints.clone();
            let mut plan_requires_probe = candidate_plan.requires_constraint_search_probe;
            let prior_no_progress_probe_cycle = prior_pending
                .as_ref()
                .map(|existing| {
                    existing.successful_reads.is_empty()
                        && existing.blocked_urls.is_empty()
                        && existing.candidate_urls.is_empty()
                        && existing.candidate_source_hints.is_empty()
                })
                .unwrap_or(false);
            let search_url_attempt = bundle
                .url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .into_iter()
                .collect::<Vec<_>>();
            let mut pending = crate::agentic::desktop::types::PendingSearchCompletion {
                query: query_value,
                query_contract: query_contract.clone(),
                url: bundle.url.clone().unwrap_or_default(),
                started_step: pre_state_summary.step_index,
                started_at_ms,
                deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
                candidate_urls: candidate_plan.candidate_urls,
                candidate_source_hints: candidate_plan.candidate_source_hints,
                attempted_urls: search_url_attempt,
                blocked_urls: Vec::new(),
                successful_reads: Vec::new(),
                min_sources,
            };
            if let Some(existing_pending) = agent_state.pending_search_completion.take() {
                pending = merge_pending_search_completion(existing_pending, pending);
            }
            if pending.candidate_urls.is_empty() {
                plan_requires_probe = true;
            }
            let min_sources = pending.min_sources;
            let min_sources_required = min_sources.max(1) as usize;
            if pending.successful_reads.len() < min_sources_required
                && remaining_pending_web_candidates(&pending) == 0
            {
                plan_requires_probe = true;
            }
            if plan_total_candidates == 0 && prior_no_progress_probe_cycle {
                plan_requires_probe = false;
            }

            let queue_now_ms = web_pipeline_now_ms();
            let remaining_budget_ms =
                web_pipeline_remaining_budget_ms(pending.deadline_ms, queue_now_ms);
            let probe_budget_allows =
                web_pipeline_can_queue_probe_search(pending.deadline_ms, queue_now_ms);
            let read_budget_allows =
                web_pipeline_can_queue_initial_read(pending.deadline_ms, queue_now_ms);

            let mut completion_reason = web_pipeline_completion_reason(&pending, queue_now_ms);
            let mut queued_next = false;
            let mut queued_probe = false;
            let remaining_candidates = remaining_pending_web_candidates(&pending);
            let prefer_probe_before_read = plan_requires_probe
                && plan_resolvable_candidates == 0
                && remaining_candidates == 0;
            if completion_reason.is_none() {
                if prefer_probe_before_read && plan_requires_probe && probe_budget_allows {
                    if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                        &query_contract,
                        min_sources,
                        &probe_source_hints,
                        &pending.query,
                    ) {
                        queued_probe = queue_web_search_from_pipeline(
                            agent_state,
                            p.session_id,
                            &probe_query,
                            constraint_grounded_search_limit(&query_contract, min_sources),
                        )?;
                    }
                }
                if !queued_probe && read_budget_allows {
                    if let Some(next_url) = next_pending_web_candidate(&pending) {
                        queued_next =
                            queue_web_read_from_pipeline(agent_state, p.session_id, &next_url)?;
                    }
                }
                if !queued_next && !queued_probe && plan_requires_probe && probe_budget_allows {
                    if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                        &query_contract,
                        min_sources,
                        &probe_source_hints,
                        &pending.query,
                    ) {
                        queued_probe = queue_web_search_from_pipeline(
                            agent_state,
                            p.session_id,
                            &probe_query,
                            constraint_grounded_search_limit(&query_contract, min_sources),
                        )?;
                    }
                }
                if !queued_next && !queued_probe {
                    if remaining_candidates == 0 {
                        completion_reason = Some(WebPipelineCompletionReason::ExhaustedCandidates);
                    } else if !read_budget_allows && (!plan_requires_probe || !probe_budget_allows)
                    {
                        completion_reason = Some(WebPipelineCompletionReason::DeadlineReached);
                    }
                }
            }
            let remaining = remaining_pending_web_candidates(&pending);
            let budget_prevents_followup = completion_reason.is_none()
                && !queued_probe
                && !queued_next
                && remaining > 0
                && (!read_budget_allows || (plan_requires_probe && !probe_budget_allows));

            verification_checks.push(format!(
                "web_pre_read_candidates_total={}",
                plan_total_candidates
            ));
            verification_checks.push(format!(
                "web_pre_read_candidates_pruned={}",
                plan_pruned_candidates
            ));
            verification_checks.push(format!(
                "web_pre_read_candidates_resolvable={}",
                plan_resolvable_candidates
            ));
            verification_checks.push(format!("web_min_sources={}", min_sources));
            verification_checks.push(format!(
                "web_constraint_search_probe_required={}",
                plan_requires_probe
            ));
            verification_checks.push(format!(
                "web_probe_preferred_before_read={}",
                prefer_probe_before_read
            ));
            verification_checks.push(format!(
                "web_constraint_search_probe_queued={}",
                queued_probe
            ));
            verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
            verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
            verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
            verification_checks.push(format!(
                "web_pipeline_active={}",
                queued_probe || queued_next || (remaining > 0 && !budget_prevents_followup)
            ));
            verification_checks.push("web_sources_success=0".to_string());
            verification_checks.push("web_sources_blocked=0".to_string());
            verification_checks.push("web_budget_ms=0".to_string());

            if let Some(reason) = completion_reason {
                let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
                    service.reasoning_inference.clone(),
                    &pending,
                    reason,
                )
                .await
                {
                    hybrid_summary
                } else {
                    synthesize_web_pipeline_reply(&pending, reason)
                };
                completion_summary = Some(summary.clone());
                success = true;
                out = Some(summary.clone());
                err = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else if budget_prevents_followup {
                let reason = WebPipelineCompletionReason::DeadlineReached;
                let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
                    service.reasoning_inference.clone(),
                    &pending,
                    reason,
                )
                .await
                {
                    hybrid_summary
                } else {
                    synthesize_web_pipeline_reply(&pending, reason)
                };
                completion_summary = Some(summary.clone());
                success = true;
                out = Some(summary.clone());
                err = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else if queued_probe || queued_next || remaining > 0 {
                agent_state.pending_search_completion = Some(pending);
                agent_state.status = AgentStatus::Running;
            } else {
                let reason = WebPipelineCompletionReason::ExhaustedCandidates;
                let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
                    service.reasoning_inference.clone(),
                    &pending,
                    reason,
                )
                .await
                {
                    hybrid_summary
                } else {
                    synthesize_web_pipeline_reply(&pending, reason)
                };
                completion_summary = Some(summary.clone());
                success = true;
                out = Some(summary.clone());
                err = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            }
        }
    }

    if !is_gated && tool_name == "web__read" {
        if let Some(mut pending) = agent_state.pending_search_completion.clone() {
            let current_url = match &tool_wrapper {
                AgentTool::WebRead { url, .. } => url.trim().to_string(),
                _ => String::new(),
            };

            if !current_url.is_empty() {
                mark_pending_web_attempted(&mut pending, &current_url);
            }

            if success {
                if let Some(bundle) = out.as_deref().and_then(parse_web_evidence_bundle) {
                    append_pending_web_success_from_bundle(&mut pending, &bundle, &current_url);
                } else {
                    append_pending_web_success_fallback(&mut pending, &current_url, out.as_deref());
                }
            } else if !current_url.is_empty()
                && is_human_challenge_error(err.as_deref().unwrap_or(""))
            {
                mark_pending_web_blocked(&mut pending, &current_url);
            }

            let now_ms = web_pipeline_now_ms();
            let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
            let remaining_budget_ms = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
            let read_budget_allows =
                web_pipeline_can_queue_initial_read(pending.deadline_ms, now_ms);
            let mut completion_reason = web_pipeline_completion_reason(&pending, now_ms);
            let mut queued_next = false;
            let mut queued_probe = false;
            let probe_budget_allows =
                web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
            if completion_reason.is_none() {
                let remaining_candidates = remaining_pending_web_candidates(&pending);
                let min_sources_required = pending.min_sources.max(1) as usize;
                let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
                let metric_probe_followup =
                    web_pipeline_requires_metric_probe_followup(&pending, now_ms);
                let queue_probe =
                    |pending: &mut crate::agentic::desktop::types::PendingSearchCompletion,
                     agent_state: &mut AgentState|
                     -> Result<bool, TransactionError> {
                        let mut probe_hints = pending.successful_reads.clone();
                        for hint in &pending.candidate_source_hints {
                            let hint_url = hint.url.trim();
                            if hint_url.is_empty() {
                                continue;
                            }
                            if probe_hints
                                .iter()
                                .any(|existing| existing.url.trim().eq_ignore_ascii_case(hint_url))
                            {
                                continue;
                            }
                            probe_hints.push(hint.clone());
                        }
                        if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                            &pending.query_contract,
                            pending.min_sources,
                            &probe_hints,
                            &pending.query,
                        ) {
                            let queued = queue_web_search_from_pipeline(
                                agent_state,
                                p.session_id,
                                &probe_query,
                                constraint_grounded_search_limit(
                                    &pending.query_contract,
                                    pending.min_sources,
                                ),
                            )?;
                            if queued {
                                pending.query = probe_query;
                            }
                            return Ok(queued);
                        }
                        Ok(false)
                    };
                if read_budget_allows {
                    if let Some(next_url) = next_pending_web_candidate(&pending) {
                        queued_next =
                            queue_web_read_from_pipeline(agent_state, p.session_id, &next_url)?;
                    }
                }
                if !queued_next && metric_probe_followup && probe_budget_allows {
                    queued_probe = queue_probe(&mut pending, agent_state)?;
                }
                if !queued_next
                    && !queued_probe
                    && source_floor_unmet
                    && remaining_candidates == 0
                    && probe_budget_allows
                {
                    queued_probe = queue_probe(&mut pending, agent_state)?;
                }
                verification_checks.push(format!(
                    "web_metric_probe_followup={}",
                    metric_probe_followup
                ));
                if !queued_next && !queued_probe && !read_budget_allows && remaining_candidates > 0
                {
                    completion_reason = Some(WebPipelineCompletionReason::DeadlineReached);
                }
                if !queued_next && !queued_probe && remaining_candidates == 0 {
                    completion_reason = Some(WebPipelineCompletionReason::ExhaustedCandidates);
                }
            }

            verification_checks.push(format!(
                "web_sources_success={}",
                pending.successful_reads.len()
            ));
            verification_checks.push(format!(
                "web_sources_blocked={}",
                pending.blocked_urls.len()
            ));
            verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
            verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
            verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
            verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
            verification_checks.push(format!(
                "web_constraint_search_probe_queued={}",
                queued_probe
            ));

            if let Some(reason) = completion_reason {
                let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
                    service.reasoning_inference.clone(),
                    &pending,
                    reason,
                )
                .await
                {
                    hybrid_summary
                } else {
                    synthesize_web_pipeline_reply(&pending, reason)
                };
                completion_summary = Some(summary.clone());
                success = true;
                out = Some(summary.clone());
                err = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                log::info!(
                    "Web pipeline completed for session {} (sources_success={} blocked={}).",
                    hex::encode(&p.session_id[..4]),
                    pending.successful_reads.len(),
                    pending.blocked_urls.len()
                );
            } else {
                let challenge = is_human_challenge_error(err.as_deref().unwrap_or(""));
                verification_checks.push("web_pipeline_active=true".to_string());
                agent_state.pending_search_completion = Some(pending);
                if !success {
                    let note = if challenge {
                        format!(
                            "Skipped challenged source and queued next candidate: {}",
                            current_url
                        )
                    } else {
                        format!(
                            "Source read failed; queued alternate candidate: {}",
                            current_url
                        )
                    };
                    success = true;
                    out = Some(note);
                    err = None;
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
    }

    if !is_gated && tool_name == "browser__snapshot" {
        if let Some(pending) = agent_state.pending_search_completion.clone() {
            let summary = if success {
                summarize_search_results(&pending.query, &pending.url, out.as_deref().unwrap_or(""))
            } else {
                fallback_search_summary(&pending.query, &pending.url)
            };
            completion_summary = Some(summary.clone());
            success = true;
            out = Some(summary.clone());
            err = None;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.pending_search_completion = None;
            agent_state.execution_queue.clear();
            agent_state.recent_actions.clear();
            log::info!(
                "Search flow completed after browser__snapshot for session {}.",
                hex::encode(&p.session_id[..4])
            );
        }
    }

    if !is_gated
        && completion_summary.is_none()
        && matches!(
            &tool_wrapper,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        && is_command_probe_intent(agent_state.resolved_intent.as_ref())
    {
        if let Some(raw) = out.as_deref() {
            if let Some(summary) = summarize_command_probe_output(&tool_wrapper, raw) {
                // Probe markers are deterministic completion signals even when the underlying
                // command exits non-zero (e.g. NOT_FOUND_IN_PATH).
                success = true;
                out = Some(summary.clone());
                err = None;
                completion_summary = Some(summary.clone());
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                log::info!(
                    "Auto-completed command probe after shell-command tool for session {}.",
                    hex::encode(&p.session_id[..4])
                );
            }
        }
    }

    if !is_gated && success && completion_summary.is_none() {
        if let AgentTool::OsLaunchApp { app_name } = &tool_wrapper {
            if should_auto_complete_open_app_goal(
                &agent_state.goal,
                app_name,
                agent_state
                    .target
                    .as_ref()
                    .and_then(|target| target.app_hint.as_deref()),
            ) {
                let summary = format!("Opened {}.", app_name);
                completion_summary = Some(summary.clone());
                out = Some(summary.clone());
                err = None;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                log::info!(
                    "Auto-completed app-launch queue flow for session {}.",
                    hex::encode(&p.session_id[..4])
                );
            }
        }
    }

    let output_str = out.clone().unwrap_or_default();
    let error_str = err.clone();

    // Log Trace with Provenance
    goto_trace_log(
        agent_state,
        state,
        &key,
        p.session_id,
        [0u8; 32],
        format!("[Macro Step] Executing queued action"),
        output_str,
        success,
        error_str,
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill, // [NEW] Pass the skill hash
    )?;

    if let Some(summary) = completion_summary.as_ref() {
        if let Some(tx) = &service.event_sender {
            verification_checks.push("terminal_chat_reply_emitted=true".to_string());
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id: p.session_id,
                step_index: agent_state.step_count,
                tool_name: "chat__reply".to_string(),
                output: summary.clone(),
                agent_status: "Completed".to_string(),
            });
        }
    }

    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    if awaiting_sudo_password {
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
    }
    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        let incident_directive = advance_incident_after_action_outcome(
            service,
            state,
            agent_state,
            p.session_id,
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

    if success && !is_gated {
        agent_state.recent_actions.clear();
    } else if !success && !awaiting_sudo_password && !awaiting_clarification {
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
            let window_fingerprint = agent_state
                .last_screen_phash
                .filter(|hash| *hash != [0u8; 32])
                .map(hex::encode);
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
            let incident_state = load_incident_state(state, &p.session_id)?;
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
                        p.session_id,
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

    if !success
        && matches!(agent_state.status, AgentStatus::Paused(_))
        && !stop_condition_hit
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        stop_condition_hit = true;
        if escalation_path.is_none() {
            escalation_path = Some("wait_for_user".to_string());
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
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &p.session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
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
        scs_lineage_ptr: lineage_pointer(active_skill),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &p.session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    // [NEW] If queue is empty, clear the active skill hash to reset context
    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
