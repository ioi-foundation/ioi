use super::probe::{is_command_probe_intent, summarize_command_probe_output};
use super::refusal_eval::evaluate_and_crystallize;
use super::search::{
    extract_navigation_url, is_search_results_url, is_search_scope, search_query_from_url,
};
use super::support::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    enforce_system_fail_terminal_status, get_status_str, mark_system_fail_status,
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
    default_safe_policy, is_live_external_research_goal, should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_incident_wait_for_user, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::service::step::queue::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    candidate_source_hints_from_bundle, candidate_urls_from_bundle, is_human_challenge_error,
    mark_pending_web_attempted, mark_pending_web_blocked, next_pending_web_candidate,
    parse_web_evidence_bundle, queue_web_read_from_pipeline, remaining_pending_web_candidates,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    web_pipeline_completion_reason, web_pipeline_now_ms, WebPipelineCompletionReason,
    WEB_PIPELINE_BUDGET_MS, WEB_PIPELINE_DEFAULT_MIN_SOURCES, WEB_PIPELINE_SEARCH_LIMIT,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, PendingSearchCompletion, ToolCallStatus, MAX_COMMAND_HISTORY,
};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, KernelEvent, RoutingReceiptEvent,
    RoutingStateSummary,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "processing/child_session.rs"]
mod child_session;
#[path = "processing/command_history.rs"]
mod command_history;
#[path = "processing/refusal.rs"]
mod refusal;

pub fn resolve_action_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

fn is_web_retrieval_timeout_tool(tool_name: &str) -> bool {
    matches!(tool_name, "web__search" | "web__read" | "browser__navigate")
}

fn should_fail_fast_web_timeout(
    resolved_intent: Option<&ResolvedIntentState>,
    tool_name: &str,
    class: FailureClass,
    has_active_web_pipeline: bool,
) -> bool {
    if !matches!(class, FailureClass::TimeoutOrHang) {
        return false;
    }
    if !is_web_retrieval_timeout_tool(tool_name) {
        return false;
    }
    if has_active_web_pipeline && tool_name == "web__read" {
        return false;
    }

    let in_web_research_scope = resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false);
    in_web_research_scope || tool_name.starts_with("web__")
}

fn extract_web_read_url_from_payload(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("arguments")
        .and_then(|args| args.get("url"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn is_effective_web_research_scope(agent_state: &AgentState) -> bool {
    is_search_scope(agent_state.resolved_intent.as_ref())
        || is_live_external_research_goal(&agent_state.goal)
}

fn is_empty_memory_search_output(output: &str) -> bool {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return true;
    }
    trimmed
        .to_ascii_lowercase()
        .contains("no matching memories found")
}

fn normalize_web_search_query(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let lower = trimmed.to_ascii_lowercase();
    let mut cut_at = trimmed.len();
    for marker in [
        " provide ",
        " with citations",
        " cite ",
        " include ",
        " summarize ",
        " in a chat reply",
    ] {
        if let Some(idx) = lower.find(marker) {
            cut_at = cut_at.min(idx);
        }
    }

    let base = trimmed[..cut_at]
        .trim()
        .trim_matches(|ch: char| matches!(ch, '?' | '!' | '.' | ':' | ';'))
        .trim();
    if base.is_empty() {
        trimmed.to_string()
    } else {
        base.to_string()
    }
}

fn queue_web_search_bootstrap(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
) -> Result<bool, TransactionError> {
    let normalized_query = normalize_web_search_query(query);
    if normalized_query.trim().is_empty() {
        return Ok(false);
    }

    let params = serde_jcs::to_vec(&json!({
        "query": normalized_query,
        "limit": WEB_PIPELINE_SEARCH_LIMIT
    }))
    .or_else(|_| {
        serde_json::to_vec(&json!({
            "query": normalized_query,
            "limit": WEB_PIPELINE_SEARCH_LIMIT
        }))
    })
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, request);
    Ok(true)
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
) -> Result<(), TransactionError> {
    let key = get_state_key(&session_id);
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_action_routing_context(agent_state);
    let tool_version = env!("CARGO_PKG_VERSION");
    let mut policy_decision = "allowed".to_string();
    let mut action_payload = json!({
        "raw_tool_output": tool_call_result
    });
    let mut intent_hash = "unknown".to_string();
    let mut retry_intent_hash: Option<String> = None;

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

    // 3. Execution
    let mut success = false;
    let mut error_msg = None;
    let mut is_gated = false;
    let mut is_lifecycle_action = false;
    let mut current_tool_name = "unknown".to_string();
    let mut history_entry: Option<String> = None;
    let mut action_output: Option<String> = None;
    let mut executed_tool_jcs: Option<Vec<u8>> = None;
    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    let mut verification_checks = Vec::new();
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;
    let mut command_probe_completed = false;
    let mut invalid_tool_call_fail_fast = false;
    let mut invalid_tool_call_bootstrap_web = false;
    let mut terminal_chat_reply_output: Option<String> = None;

    match tool_call {
        Ok(tool) => {
            let os_driver = service
                .os_driver
                .clone()
                .ok_or(TransactionError::Invalid("OS driver missing".into()))?;
            action_payload = serde_json::to_value(&tool).unwrap_or_else(|_| json!({}));
            let (tool_name, tool_args) = canonical_tool_identity(&tool);
            current_tool_name = tool_name;
            executed_tool_jcs = serde_jcs::to_vec(&tool)
                .or_else(|_| serde_json::to_vec(&tool))
                .ok();
            intent_hash = canonical_intent_hash(
                &current_tool_name,
                &tool_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            retry_intent_hash = Some(canonical_retry_intent_hash(
                &current_tool_name,
                &tool_args,
                routing_decision.tier,
                tool_version,
            ));

            let mut tool_allowed = is_tool_allowed_for_resolution(
                agent_state.resolved_intent.as_ref(),
                &current_tool_name,
            );
            if !tool_allowed {
                let allow_mcp_tools = agent_state
                    .resolved_intent
                    .as_ref()
                    .map(|resolved| {
                        !matches!(
                            resolved.scope,
                            ioi_types::app::agentic::IntentScopeProfile::Conversation
                                | ioi_types::app::agentic::IntentScopeProfile::Unknown
                        )
                    })
                    .unwrap_or(false);
                if allow_mcp_tools {
                    if let Some(mcp) = service.mcp.as_ref() {
                        tool_allowed = mcp
                            .get_all_tools()
                            .await
                            .iter()
                            .any(|tool| tool.name == current_tool_name);
                    }
                }
            }

            if !tool_allowed {
                policy_decision = "denied".to_string();
                success = false;
                error_msg = Some(format!(
                    "ERROR_CLASS=PermissionOrApprovalRequired Tool '{}' blocked by global intent scope.",
                    current_tool_name
                ));
                if !req_hash_hex.is_empty() {
                    agent_state.tool_execution_log.insert(
                        req_hash_hex.clone(),
                        ToolCallStatus::Failed("intent_scope_block".to_string()),
                    );
                }
            } else {
                let target_hash_opt = agent_state
                    .pending_approval
                    .as_ref()
                    .and_then(|t| t.visual_hash)
                    .or(agent_state.last_screen_phash);
                if let Some(target_hash) = target_hash_opt {
                    let _ = service.restore_visual_context(target_hash).await;
                }

                // [FIX] Pass the required InferenceRuntime (reasoning) to ToolExecutor constructor inside handle_action_execution
                match service
                    .handle_action_execution(
                        tool.clone(),
                        session_id,
                        agent_state.step_count,
                        final_visual_phash,
                        &rules,
                        &agent_state,
                        &os_driver,
                        None,
                    )
                    .await
                {
                    Ok((s, entry, e)) => {
                        success = s;
                        error_msg = e;
                        history_entry = entry.clone();

                        // Orchestration meta-tools require access to chain state; execute them
                        // on the primary path here instead of the stateless ToolExecutor.
                        if success {
                            match &tool {
                                AgentTool::AgentDelegate { goal, budget } => {
                                    let tool_jcs = match serde_jcs::to_vec(&tool) {
                                        Ok(bytes) => bytes,
                                        Err(err) => {
                                            success = false;
                                            error_msg = Some(format!(
                                                "ERROR_CLASS=UnexpectedState Failed to encode delegation tool: {}",
                                                err
                                            ));
                                            history_entry = None;
                                            Vec::new()
                                        }
                                    };

                                    if success {
                                        match sha256(&tool_jcs) {
                                            Ok(tool_hash) => match spawn_delegated_child_session(
                                                service,
                                                state,
                                                agent_state,
                                                tool_hash,
                                                goal,
                                                *budget,
                                                pre_state_summary.step_index,
                                                block_height,
                                            )
                                            .await
                                            {
                                                Ok(child_session_id) => {
                                                    history_entry = Some(format!(
                                                        "{{\"child_session_id_hex\":\"{}\"}}",
                                                        hex::encode(child_session_id)
                                                    ));
                                                    error_msg = None;
                                                }
                                                Err(err) => {
                                                    success = false;
                                                    error_msg = Some(err.to_string());
                                                    history_entry = None;
                                                }
                                            },
                                            Err(err) => {
                                                success = false;
                                                error_msg = Some(format!(
                                                    "ERROR_CLASS=UnexpectedState Delegation hash failed: {}",
                                                    err
                                                ));
                                                history_entry = None;
                                            }
                                        }
                                    }
                                }
                                AgentTool::AgentAwait {
                                    child_session_id_hex,
                                } => {
                                    match child_session::await_child_session_status(
                                        state,
                                        child_session_id_hex,
                                    ) {
                                        Ok(out) => {
                                            history_entry = Some(out);
                                            error_msg = None;
                                        }
                                        Err(err) => {
                                            success = false;
                                            error_msg = Some(err);
                                            history_entry = None;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        if matches!(
                            &tool,
                            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                        ) {
                            if let Some(raw_entry) =
                                command_history::extract_command_history(&history_entry)
                            {
                                let history_entry = command_history::scrub_command_history_fields(
                                    &service.scrubber,
                                    raw_entry,
                                )
                                .await;
                                command_history::append_to_bounded_history(
                                    &mut agent_state.command_history,
                                    history_entry,
                                    MAX_COMMAND_HISTORY,
                                );
                            }
                        }

                        if (success || command_probe_completed) && !req_hash_hex.is_empty() {
                            agent_state.tool_execution_log.insert(
                                req_hash_hex.clone(),
                                ToolCallStatus::Executed("success".into()),
                            );
                            agent_state.pending_approval = None;
                            agent_state.pending_tool_jcs = None;
                        }

                        if success {
                            if let Some(entry) = history_entry.clone() {
                                let tool_msg = ioi_types::app::agentic::ChatMessage {
                                    role: "tool".to_string(),
                                    content: entry,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                    trace_hash: None,
                                };
                                let _ = service
                                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                                    .await?;
                            }
                        }

                        match &tool {
                            AgentTool::AgentComplete { result } => {
                                agent_state.status = AgentStatus::Completed(Some(result.clone()));
                                is_lifecycle_action = true;
                                action_output = Some(result.clone());
                                evaluate_and_crystallize(service, agent_state, session_id, result)
                                    .await;
                            }
                            AgentTool::SysChangeDir { .. } => {
                                if success {
                                    if let Some(new_cwd) = history_entry.as_ref() {
                                        agent_state.working_directory = new_cwd.clone();
                                    }
                                }
                            }
                            AgentTool::ChatReply { message } => {
                                agent_state.status = AgentStatus::Completed(Some(message.clone()));
                                is_lifecycle_action = true;
                                action_output = Some(message.clone());
                                terminal_chat_reply_output = Some(message.clone());
                                evaluate_and_crystallize(service, agent_state, session_id, message)
                                    .await;
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
                                    agent_state.status =
                                        AgentStatus::Completed(Some(summary.clone()));
                                    is_lifecycle_action = true;
                                    action_output = Some(summary);
                                    agent_state.execution_queue.clear();
                                    agent_state.pending_search_completion = None;
                                    log::info!(
                                    "Auto-completed app-launch session {} after successful os__launch_app.",
                                    hex::encode(&session_id[..4])
                                );
                                }
                            }
                            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
                                if is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                                    if let Some(raw) = history_entry.as_deref() {
                                        if let Some(summary) =
                                            summarize_command_probe_output(&tool, raw)
                                        {
                                            // Probe markers are deterministic completion signals even
                                            // when the underlying command exits non-zero.
                                            command_probe_completed = true;
                                            success = true;
                                            error_msg = None;
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(summary);
                                            agent_state.execution_queue.clear();
                                            agent_state.pending_search_completion = None;
                                        }
                                    }
                                }
                            }
                            AgentTool::MemorySearch { query } => {
                                if success
                                    && is_effective_web_research_scope(agent_state)
                                    && agent_state.pending_search_completion.is_none()
                                    && history_entry
                                        .as_deref()
                                        .map(is_empty_memory_search_output)
                                        .unwrap_or(true)
                                {
                                    let bootstrap_query = if query.trim().is_empty() {
                                        agent_state.goal.clone()
                                    } else {
                                        query.clone()
                                    };
                                    let queued = queue_web_search_bootstrap(
                                        agent_state,
                                        session_id,
                                        &bootstrap_query,
                                    )?;
                                    verification_checks
                                        .push("web_search_bootstrap_from_memory=true".to_string());
                                    let note = if queued {
                                        "No memory hits for this news query; queued deterministic web__search.".to_string()
                                    } else {
                                        "No memory hits for this news query; deterministic web__search was already queued."
                                            .to_string()
                                    };
                                    history_entry = Some(note.clone());
                                    action_output = Some(note);
                                    agent_state.status = AgentStatus::Running;
                                }
                            }
                            AgentTool::WebSearch { query, .. } => {
                                if success && is_effective_web_research_scope(agent_state) {
                                    if let Some(raw) = history_entry.as_deref() {
                                        if let Some(bundle) = parse_web_evidence_bundle(raw) {
                                            let query_value = bundle
                                                .query
                                                .clone()
                                                .filter(|value| !value.trim().is_empty())
                                                .or_else(|| {
                                                    let trimmed = query.trim();
                                                    (!trimmed.is_empty())
                                                        .then(|| trimmed.to_string())
                                                })
                                                .unwrap_or_else(|| agent_state.goal.clone());
                                            let query_contract = {
                                                let trimmed_goal = agent_state.goal.trim();
                                                if trimmed_goal.is_empty() {
                                                    query_value.clone()
                                                } else {
                                                    trimmed_goal.to_string()
                                                }
                                            };
                                            let started_at_ms = web_pipeline_now_ms();
                                            let mut pending = PendingSearchCompletion {
                                                query: query_value,
                                                query_contract,
                                                url: bundle.url.clone().unwrap_or_default(),
                                                started_step: pre_state_summary.step_index,
                                                started_at_ms,
                                                deadline_ms: started_at_ms
                                                    .saturating_add(WEB_PIPELINE_BUDGET_MS),
                                                candidate_urls: candidate_urls_from_bundle(&bundle),
                                                candidate_source_hints:
                                                    candidate_source_hints_from_bundle(&bundle),
                                                attempted_urls: Vec::new(),
                                                blocked_urls: Vec::new(),
                                                successful_reads: Vec::new(),
                                                min_sources: WEB_PIPELINE_DEFAULT_MIN_SOURCES,
                                            };

                                            let mut queued_next = false;
                                            if let Some(next_url) =
                                                next_pending_web_candidate(&pending)
                                            {
                                                queued_next = queue_web_read_from_pipeline(
                                                    agent_state,
                                                    session_id,
                                                    &next_url,
                                                )?;
                                            }

                                            let remaining =
                                                remaining_pending_web_candidates(&pending);
                                            verification_checks.push(format!(
                                                "web_pipeline_active={}",
                                                queued_next || remaining > 0
                                            ));
                                            verification_checks
                                                .push("web_sources_success=0".to_string());
                                            verification_checks
                                                .push("web_sources_blocked=0".to_string());
                                            verification_checks.push("web_budget_ms=0".to_string());

                                            if queued_next || remaining > 0 {
                                                agent_state.pending_search_completion =
                                                    Some(pending);
                                            } else {
                                                let reason =
                                                    WebPipelineCompletionReason::ExhaustedCandidates;
                                                let summary = if let Some(hybrid_summary) =
                                                    synthesize_web_pipeline_reply_hybrid(
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
                                                action_output = Some(summary.clone());
                                                history_entry = Some(summary.clone());
                                                terminal_chat_reply_output = Some(summary.clone());
                                                is_lifecycle_action = true;
                                                agent_state.status =
                                                    AgentStatus::Completed(Some(summary));
                                                agent_state.pending_search_completion = None;
                                                agent_state.execution_queue.clear();
                                                agent_state.recent_actions.clear();
                                                verification_checks.push(
                                                    "terminal_chat_reply_ready=true".to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            AgentTool::SystemFail { reason, .. } => {
                                mark_system_fail_status(&mut agent_state.status, reason.clone());
                                is_lifecycle_action = true;
                                action_output = Some(format!("Agent Failed: {}", reason));
                            }
                            _ => {}
                        }

                        if success
                            && current_tool_name == "browser__navigate"
                            && agent_state.pending_search_completion.is_none()
                            && is_effective_web_research_scope(agent_state)
                        {
                            if let Some(url) = extract_navigation_url(&tool_args) {
                                if is_search_results_url(&url) {
                                    let query = search_query_from_url(&url)
                                        .filter(|value| !value.trim().is_empty())
                                        .unwrap_or_else(|| agent_state.goal.clone());
                                    let extract_params = serde_jcs::to_vec(&json!({}))
                                        .or_else(|_| serde_json::to_vec(&json!({})))
                                        .unwrap_or_else(|_| b"{}".to_vec());
                                    agent_state.execution_queue.push(ActionRequest {
                                        target: ActionTarget::BrowserInspect,
                                        params: extract_params,
                                        context: ActionContext {
                                            agent_id: "desktop_agent".to_string(),
                                            session_id: Some(session_id),
                                            window_id: None,
                                        },
                                        nonce: agent_state.step_count as u64 + 1,
                                    });
                                    let query_contract = {
                                        let trimmed_goal = agent_state.goal.trim();
                                        if trimmed_goal.is_empty() {
                                            query.clone()
                                        } else {
                                            trimmed_goal.to_string()
                                        }
                                    };
                                    agent_state.pending_search_completion =
                                        Some(PendingSearchCompletion {
                                            query,
                                            query_contract,
                                            url,
                                            started_step: pre_state_summary.step_index,
                                            started_at_ms: web_pipeline_now_ms(),
                                            deadline_ms: 0,
                                            candidate_urls: Vec::new(),
                                            candidate_source_hints: Vec::new(),
                                            attempted_urls: Vec::new(),
                                            blocked_urls: Vec::new(),
                                            successful_reads: Vec::new(),
                                            min_sources: WEB_PIPELINE_DEFAULT_MIN_SOURCES,
                                        });
                                    log::info!(
                                    "Search intent detected after browser__navigate. Queued browser__snapshot for deterministic completion."
                                );
                                }
                            }
                        }
                    }
                    Err(TransactionError::PendingApproval(h)) => {
                        policy_decision = "require_approval".to_string();
                        let tool_jcs = serde_jcs::to_vec(&tool).unwrap();
                        let tool_hash_bytes =
                            ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
                        let mut hash_arr = [0u8; 32];
                        hash_arr.copy_from_slice(tool_hash_bytes.as_ref());

                        let action_fingerprint = sha256(&tool_jcs)
                            .map(hex::encode)
                            .unwrap_or_else(|_| String::new());
                        let root_retry_hash =
                            retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
                        if let Ok(bytes) = hex::decode(&h) {
                            if bytes.len() == 32 {
                                let mut decision_hash = [0u8; 32];
                                decision_hash.copy_from_slice(&bytes);
                                if let Some(request) = build_pii_review_request_for_tool(
                                    service,
                                    &rules,
                                    session_id,
                                    &tool,
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
                        let incident_before = load_incident_state(state, &session_id)?;
                        let incident_stage_before = incident_before
                            .as_ref()
                            .map(|incident| incident.stage.clone())
                            .unwrap_or_else(|| "None".to_string());

                        let approval_directive = register_pending_approval(
                            state,
                            &rules,
                            agent_state,
                            session_id,
                            root_retry_hash,
                            &current_tool_name,
                            &tool_jcs,
                            &action_fingerprint,
                            &h,
                        )?;
                        let incident_after = load_incident_state(state, &session_id)?;
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
                                (Some(before), Some(after)) =>
                                    before.incident_id == after.incident_id,
                                _ => true,
                            }
                        ));
                        verification_checks
                            .push(format!("incident_stage_before={}", incident_stage_before));
                        verification_checks
                            .push(format!("incident_stage_after={}", incident_stage_after));

                        agent_state.pending_tool_jcs = Some(tool_jcs);
                        agent_state.pending_tool_hash = Some(hash_arr);
                        agent_state.pending_visual_hash = Some(final_visual_phash);
                        agent_state.pending_tool_call = Some(tool_call_result.clone());
                        agent_state.last_screen_phash = Some(final_visual_phash);
                        is_gated = true;
                        is_lifecycle_action = true;
                        agent_state.status = AgentStatus::Paused("Waiting for approval".into());

                        if let Some(incident_state) = load_incident_state(state, &session_id)? {
                            if incident_state.active {
                                log::info!(
                                "incident.approval_intercepted session={} incident_id={} root_tool={} gated_tool={}",
                                hex::encode(&session_id[..4]),
                                incident_state.incident_id,
                                incident_state.root_tool_name,
                                current_tool_name
                            );
                            }
                        }

                        match approval_directive {
                            ApprovalDirective::PromptUser => {
                                let msg = format!("System: Action halted by Agency Firewall (Hash: {}). Requesting authorization.", h);
                                let sys_msg = ioi_types::app::agentic::ChatMessage {
                                    role: "system".to_string(),
                                    content: msg,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                    trace_hash: None,
                                };
                                let _ = service
                                    .append_chat_to_scs(session_id, &sys_msg, block_height)
                                    .await?;
                                success = true;
                            }
                            ApprovalDirective::SuppressDuplicatePrompt => {
                                let sys_msg = ioi_types::app::agentic::ChatMessage {
                                role: "system".to_string(),
                                content:
                                    "System: Approval already pending for this incident/action. Waiting for your decision."
                                        .to_string(),
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
                            }
                            ApprovalDirective::PauseLoop => {
                                policy_decision = "denied".to_string();
                                success = false;
                                let loop_msg = format!(
                                "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                                h
                            );
                                error_msg = Some(loop_msg.clone());
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
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                    trace_hash: None,
                                };
                                let _ = service
                                    .append_chat_to_scs(session_id, &sys_msg, block_height)
                                    .await?;
                            }
                        }
                    }
                    Err(e) => {
                        success = false;
                        let msg = e.to_string();
                        if msg.to_lowercase().contains("blocked by policy") {
                            policy_decision = "denied".to_string();
                        }
                        error_msg = Some(msg.clone());
                        if !req_hash_hex.is_empty() {
                            agent_state
                                .tool_execution_log
                                .insert(req_hash_hex.clone(), ToolCallStatus::Failed(msg));
                        }
                    }
                }
            }
        }
        Err(e) => {
            // Tool-call schema/parse errors are not policy denials. Mark them as deterministic
            // UnexpectedState so anti-loop + receipts don't imply approval/policy gating.
            policy_decision = "allowed".to_string();
            current_tool_name = "system::invalid_tool_call".to_string();
            let parse_error = format!("Failed to parse tool call: {}", e);
            let parse_args = json!({
                "raw_tool_output": tool_call_result,
                "parse_error": parse_error,
            });

            verification_checks.push("schema_validation_error=true".to_string());

            intent_hash = canonical_intent_hash(
                &current_tool_name,
                &parse_args,
                routing_decision.tier,
                pre_state_summary.step_index,
                tool_version,
            );
            retry_intent_hash = Some(canonical_retry_intent_hash(
                &current_tool_name,
                &parse_args,
                routing_decision.tier,
                tool_version,
            ));
            action_payload = json!({
                "name": current_tool_name.clone(),
                "arguments": parse_args,
            });
            // Prefix ERROR_CLASS so anti-loop classification is deterministic.
            error_msg = Some(format!("ERROR_CLASS=UnexpectedState {}", parse_error));
            let empty_output = tool_call_result.trim().is_empty();
            if empty_output && is_effective_web_research_scope(agent_state) {
                invalid_tool_call_bootstrap_web = true;
            } else if is_effective_web_research_scope(agent_state) {
                invalid_tool_call_fail_fast = true;
            }
        }
    }

    let is_install_package_tool = current_tool_name == "sys__install_package"
        || current_tool_name == "sys::install_package"
        || current_tool_name.ends_with("install_package");
    let clarification_required = !success
        && error_msg
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && error_msg
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            error_msg.as_deref(),
        )?;
        // Discard any queued remediation actions so resume prioritizes retrying
        // the canonical pending install with user-provided runtime secret.
        agent_state.execution_queue.clear();
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = Some(tool_call_result.clone());
        agent_state.pending_visual_hash = Some(final_visual_phash);
        agent_state.last_screen_phash = Some(final_visual_phash);
        if let Some(tool_jcs) = executed_tool_jcs.clone() {
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash pending install tool: {}", e))
            })?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            agent_state.pending_tool_jcs = Some(tool_jcs);
            agent_state.pending_tool_hash = Some(hash_arr);
        }
        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
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
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_sudo_password=true".to_string());
    }

    if clarification_required {
        awaiting_clarification = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            error_msg.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.execution_queue.clear();

        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
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
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    }

    if invalid_tool_call_fail_fast
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let summary = "Invalid tool call generated during web research. Stopping early to avoid recovery churn.".to_string();
        success = true;
        error_msg = None;
        stop_condition_hit = true;
        escalation_path = Some("invalid_tool_call_fail_fast".to_string());
        is_lifecycle_action = true;
        action_output = Some(summary.clone());
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.execution_queue.clear();
        agent_state.pending_search_completion = None;
        verification_checks.push("invalid_tool_call_fail_fast=true".to_string());
    }

    if invalid_tool_call_bootstrap_web
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let goal = agent_state.goal.clone();
        let queued = queue_web_search_bootstrap(agent_state, session_id, &goal)?;
        success = true;
        error_msg = None;
        stop_condition_hit = false;
        escalation_path = None;
        is_lifecycle_action = true;
        let note = if queued {
            "Model returned empty tool output; bootstrapped deterministic web__search.".to_string()
        } else {
            "Model returned empty tool output; web__search bootstrap already queued.".to_string()
        };
        history_entry = Some(note.clone());
        action_output = Some(note);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_bootstrap_web=true".to_string());
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && current_tool_name == "web__read"
    {
        if let Some(mut pending) = agent_state.pending_search_completion.clone() {
            let read_url = extract_web_read_url_from_payload(&action_payload).unwrap_or_default();
            if !read_url.is_empty() {
                mark_pending_web_attempted(&mut pending, &read_url);
            }

            if success {
                if let Some(bundle) = history_entry.as_deref().and_then(parse_web_evidence_bundle) {
                    append_pending_web_success_from_bundle(&mut pending, &bundle, &read_url);
                } else {
                    append_pending_web_success_fallback(
                        &mut pending,
                        &read_url,
                        history_entry.as_deref(),
                    );
                }
            } else if !read_url.is_empty()
                && is_human_challenge_error(error_msg.as_deref().unwrap_or(""))
            {
                mark_pending_web_blocked(&mut pending, &read_url);
            }

            let now_ms = web_pipeline_now_ms();
            let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
            let mut completion_reason = web_pipeline_completion_reason(&pending, now_ms);
            let mut queued_next = false;
            if completion_reason.is_none() {
                if let Some(next_url) = next_pending_web_candidate(&pending) {
                    queued_next = queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
                }
                if !queued_next && remaining_pending_web_candidates(&pending) == 0 {
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
                success = true;
                error_msg = None;
                action_output = Some(summary.clone());
                history_entry = Some(summary.clone());
                terminal_chat_reply_output = Some(summary.clone());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(summary));
                agent_state.pending_search_completion = None;
                agent_state.execution_queue.clear();
                agent_state.recent_actions.clear();
                verification_checks.push("web_pipeline_active=false".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else {
                let challenge = is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                agent_state.pending_search_completion = Some(pending);
                verification_checks.push("web_pipeline_active=true".to_string());
                if !success {
                    let note = if challenge {
                        format!(
                            "Skipped challenged source and continuing with alternates: {}",
                            read_url
                        )
                    } else {
                        format!(
                            "Source read failed; continuing with alternate sources: {}",
                            read_url
                        )
                    };
                    success = true;
                    error_msg = None;
                    history_entry = Some(note.clone());
                    action_output = Some(note);
                    stop_condition_hit = false;
                    escalation_path = None;
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
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
    } else if !success && !awaiting_sudo_password && !awaiting_clarification {
        failure_class = classify_failure(error_msg.as_deref(), &policy_decision);
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
            let window_fingerprint = if final_visual_phash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(final_visual_phash))
            };
            let retry_hash = retry_intent_hash.as_deref().unwrap_or(intent_hash.as_str());
            let attempt_key = build_attempt_key(
                retry_hash,
                routing_decision.tier,
                &current_tool_name,
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
            if should_fail_fast_web_timeout(
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
            } else {
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
                        ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active) {
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

                if remediation_queued {
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
                } else if is_effective_web_research_scope(agent_state)
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
                    verification_checks.push("web_unexpected_retry_bypass=true".to_string());
                } else if blocked_without_change {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
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
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
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
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
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
        agent_state.consecutive_failures = 0;
    }

    if !is_gated {
        if let Some(tx) = &service.event_sender {
            let output_str = action_output
                .or_else(|| if success { history_entry.clone() } else { None })
                .unwrap_or_else(|| {
                    error_msg
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string())
                });
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: pre_state_summary.step_index,
                tool_name: current_tool_name.clone(),
                output: output_str,
                agent_status: get_status_str(&agent_state.status),
            });

            if let Some(chat_output) = terminal_chat_reply_output {
                if current_tool_name != "chat__reply" {
                    verification_checks.push("terminal_chat_reply_emitted=true".to_string());
                    let _ = tx.send(KernelEvent::AgentActionResult {
                        session_id,
                        step_index: pre_state_summary.step_index,
                        tool_name: "chat__reply".to_string(),
                        output: chat_output,
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
        agent_state.pending_approval = None;
    }

    // ... [Max steps check] ...
    if agent_state.step_count >= agent_state.max_steps && agent_state.status == AgentStatus::Running
    {
        agent_state.status = AgentStatus::Completed(None);
    }

    let mut artifacts = extract_artifacts(error_msg.as_deref(), history_entry.as_deref());
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
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_fail_fast_web_timeout;
    use crate::agentic::desktop::service::step::anti_loop::FailureClass;
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "test".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.92,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
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
        assert!(should_fail_fast_web_timeout(
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
}
