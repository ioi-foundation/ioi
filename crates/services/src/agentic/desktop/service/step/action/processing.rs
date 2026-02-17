use super::probe::{is_command_probe_intent, summarize_command_probe_output};
use super::refusal_eval::{evaluate_and_crystallize, handle_refusal};
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
use crate::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
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
    mark_incident_wait_for_user, register_pending_approval, should_enter_incident_recovery,
    start_or_continue_incident_recovery, ApprovalDirective, IncidentDirective,
};
use crate::agentic::desktop::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::service::lifecycle::spawn_delegated_child_session;
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, CommandExecution, MAX_COMMAND_HISTORY, PendingSearchCompletion,
    ToolCallStatus,
};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, KernelEvent, RoutingReceiptEvent,
    RoutingStateSummary,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use serde_json;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const COMMAND_HISTORY_SCRUBBED_PLACEHOLDER: &str = "[REDACTED_PII]";
static COMMAND_HISTORY_MARKER_MISS_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_PARSE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_SCRUB_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

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
    if tool_call_result.contains("\"name\":\"system::refusal\"") {
        let reason = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&tool_call_result) {
            val.get("arguments")
                .and_then(|a| a.get("reason"))
                .and_then(|m| m.as_str())
                .unwrap_or("Refused")
                .to_string()
        } else {
            "Refused".to_string()
        };
        let refusal_tool_name = "system::refusal".to_string();
        let refusal_args = json!({
            "reason": reason
        });
        let refusal_action_payload = json!({
            "name": refusal_tool_name,
            "arguments": refusal_args
        });
        let refusal_intent_hash = canonical_intent_hash(
            &refusal_tool_name,
            &refusal_args,
            routing_decision.tier,
            pre_state_summary.step_index,
            tool_version,
        );
        let refusal_policy_decision = "denied".to_string();
        let refusal_failure_class = FailureClass::UserInterventionNeeded;
        let refusal_stop_condition_hit = true;
        let refusal_escalation_path =
            Some(escalation_path_for_failure(refusal_failure_class).to_string());

        handle_refusal(
            service,
            state,
            agent_state,
            &key,
            session_id,
            final_visual_phash,
            &reason,
        )
        .await?;

        let verification_checks = vec![
            format!("policy_decision={}", refusal_policy_decision),
            "was_refusal=true".to_string(),
            format!("stop_condition_hit={}", refusal_stop_condition_hit),
            format!(
                "routing_tier_selected={}",
                tier_as_str(routing_decision.tier)
            ),
            format!("routing_reason_code={}", routing_decision.reason_code),
            format!(
                "routing_source_failure={}",
                routing_decision
                    .source_failure
                    .map(|class| class.as_str().to_string())
                    .unwrap_or_else(|| "None".to_string())
            ),
            format!(
                "routing_tier_matches_pre_state={}",
                pre_state_summary.tier == tier_as_str(routing_decision.tier)
            ),
            format!("failure_class={}", refusal_failure_class.as_str()),
        ];
        let mut artifacts = extract_artifacts(
            Some("ERROR_CLASS=HumanChallengeRequired"),
            Some(&tool_call_result),
        );
        artifacts.push(format!(
            "trace://agent_step/{}",
            pre_state_summary.step_index
        ));
        artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
        let post_state = build_post_state_summary(agent_state, false, verification_checks);
        let policy_binding = policy_binding_hash(&refusal_intent_hash, &refusal_policy_decision);
        let incident_fields =
            incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
        let receipt = RoutingReceiptEvent {
            session_id,
            step_index: pre_state_summary.step_index,
            intent_hash: refusal_intent_hash,
            policy_decision: refusal_policy_decision,
            tool_name: refusal_tool_name,
            tool_version: tool_version.to_string(),
            pre_state: pre_state_summary,
            action_json: serde_json::to_string(&refusal_action_payload)
                .unwrap_or_else(|_| "{}".to_string()),
            post_state,
            artifacts,
            failure_class: Some(to_routing_failure_class(refusal_failure_class)),
            failure_class_name: refusal_failure_class.as_str().to_string(),
            intent_class: incident_fields.intent_class,
            incident_id: incident_fields.incident_id,
            incident_stage: incident_fields.incident_stage,
            strategy_name: incident_fields.strategy_name,
            strategy_node: incident_fields.strategy_node,
            gate_state: incident_fields.gate_state,
            resolution_action: incident_fields.resolution_action,
            stop_condition_hit: refusal_stop_condition_hit,
            escalation_path: refusal_escalation_path,
            scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
            mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
            policy_binding_hash: policy_binding,
            policy_binding_sig: None,
            policy_binding_signer: None,
        };
        emit_routing_receipt(service.event_sender.as_ref(), receipt);
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
                                } => match await_child_session_status(state, child_session_id_hex) {
                                    Ok(out) => {
                                        history_entry = Some(out);
                                        error_msg = None;
                                    }
                                    Err(err) => {
                                        success = false;
                                        error_msg = Some(err);
                                        history_entry = None;
                                    }
                                },
                                _ => {}
                            }
                        }

                        if matches!(&tool, AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }) {
                            if let Some(raw_entry) = extract_command_history(&history_entry) {
                                let history_entry = scrub_command_history_fields(
                                    &service.scrubber,
                                    raw_entry,
                                )
                                .await;
                                append_to_bounded_history(
                                    &mut agent_state.command_history,
                                    history_entry,
                                    MAX_COMMAND_HISTORY,
                                );
                            }
                        }

                        if success && !req_hash_hex.is_empty() {
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
                                agent_state.status =
                                    AgentStatus::Paused("Waiting for user input".to_string());
                                is_lifecycle_action = true;
                                action_output = Some(message.clone());
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
                                ) {
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
                                if success
                                    && is_command_probe_intent(
                                    agent_state.resolved_intent.as_ref(),
                                ) {
                                    if let Some(raw) = entry.as_deref() {
                                        if let Some(summary) =
                                            summarize_command_probe_output(&tool, raw)
                                        {
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
                            && is_search_scope(agent_state.resolved_intent.as_ref())
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
                                    agent_state.pending_search_completion =
                                        Some(PendingSearchCompletion {
                                            query,
                                            url,
                                            started_step: pre_state_summary.step_index,
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
            policy_decision = "denied".to_string();
            current_tool_name = "system::invalid_tool_call".to_string();
            let parse_error = format!("Failed to parse tool call: {}", e);
            let parse_args = json!({
                "raw_tool_output": tool_call_result,
                "parse_error": parse_error,
            });
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
            error_msg = Some(
                action_payload
                    .get("arguments")
                    .and_then(|v| v.get("parse_error"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Failed to parse tool call")
                    .to_string(),
            );
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

fn await_child_session_status(
    state: &mut dyn StateAccess,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let child_session_id = parse_session_id_hex(child_session_id_hex)?;
    let key = get_state_key(&child_session_id);
    let bytes = state
        .get(&key)
        .map_err(|e| format!("ERROR_CLASS=UnexpectedState Child state lookup failed: {}", e))?
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                child_session_id_hex
            )
        })?;

    let child_state: AgentState = codec::from_bytes_canonical(&bytes).map_err(|e| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
            child_session_id_hex, e
        )
    })?;

    match child_state.status {
        AgentStatus::Running | AgentStatus::Idle => Ok("Running".to_string()),
        AgentStatus::Paused(reason) => Ok(format!("Running (paused: {})", reason)),
        AgentStatus::Completed(Some(result)) => Ok(result),
        AgentStatus::Completed(None) => Ok("Completed".to_string()),
        AgentStatus::Failed(reason) => Err(format!(
            "ERROR_CLASS=UnexpectedState Child agent failed: {}",
            reason
        )),
        AgentStatus::Terminated => Err("ERROR_CLASS=UnexpectedState Child agent terminated.".to_string()),
    }
}

fn parse_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|e| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, e
        )
    })?;
    if bytes.len() != 32 {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable child_session_id_hex '{}' must be 32 bytes (got {}).",
            input,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn extract_command_history(
    history_entry: &Option<String>,
) -> Option<CommandExecution> {
    let entry = history_entry.as_deref()?;
    if !entry.starts_with(COMMAND_HISTORY_PREFIX) {
        let _ = COMMAND_HISTORY_MARKER_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let suffix = &entry[COMMAND_HISTORY_PREFIX.len()..];
    let json_payload = suffix.find('\n').map_or(suffix, |idx| &suffix[..idx]).trim();
    if json_payload.is_empty() {
        let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    match serde_json::from_str::<CommandExecution>(json_payload) {
        Ok(entry) => Some(entry),
        Err(_) => {
            let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

async fn scrub_command_history_fields(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    mut entry: CommandExecution,
) -> CommandExecution {
    entry.command = scrub_text_field(scrubber, &entry.command).await;
    entry.stdout = scrub_text_field(scrubber, &entry.stdout).await;
    entry.stderr = scrub_text_field(scrubber, &entry.stderr).await;
    entry
}

async fn scrub_text_field(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> String {
    match scrubber.scrub(input).await {
        Ok((scrubbed, _)) => scrubbed,
        Err(_) => {
            let _ = COMMAND_HISTORY_SCRUB_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            COMMAND_HISTORY_SCRUBBED_PLACEHOLDER.to_string()
        }
    }
}

fn append_to_bounded_history(
    history: &mut VecDeque<CommandExecution>,
    entry: CommandExecution,
    max_size: usize,
) {
    history.push_back(entry);
    while history.len() > max_size {
        let _ = history.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::pii_scrubber::PiiScrubber;
    use async_trait::async_trait;
    use ioi_api::vm::inference::{
        LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
    };
    use serde_json;
    use std::sync::Arc;

    struct DetectingSafetyModel;

    #[async_trait]
    impl LocalSafetyModel for DetectingSafetyModel {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            let mut findings = Vec::new();
            if let Some(start) = input.find("API_KEY=") {
                findings.push((start, input.len(), "api_key".to_string()));
            }
            if let Some(start) = input.find("password=") {
                findings.push((start, input.len(), "password".to_string()));
            }
            if let Some(start) = input.find("token=") {
                findings.push((start, input.len(), "token".to_string()));
            }
            Ok(findings)
        }

        async fn inspect_pii(
            &self,
            _input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: Default::default(),
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    struct FailingSafetyModel;

    #[async_trait]
    impl LocalSafetyModel for FailingSafetyModel {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            Err(anyhow::anyhow!("failure"))
        }

        async fn inspect_pii(
            &self,
            _input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: Default::default(),
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    #[test]
    fn command_history_parse_valid_and_invalid_payloads() {
        let valid_entry = CommandExecution {
            command: "echo hi".to_string(),
            exit_code: 0,
            stdout: "ok".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 3,
        };
        let valid = serde_json::to_string(&valid_entry).map_or_else(
            |_| String::new(),
            |serialized| format!("{}{}", COMMAND_HISTORY_PREFIX, serialized),
        );
        let parsed = match extract_command_history(&Some(valid)) {
            Some(payload) => payload,
            None => panic!("valid command history should parse"),
        };
        assert_eq!(parsed.step_index, 3);
        assert_eq!(parsed.exit_code, 0);

        let malformed = Some(format!(
            "{}{}",
            COMMAND_HISTORY_PREFIX, "{ invalid "
        ));
        assert!(extract_command_history(&malformed).is_none());

        let unrelated = Some("no metadata here".to_string());
        assert!(extract_command_history(&unrelated).is_none());
    }

    #[test]
    fn append_to_bounded_history_evictions() {
        let mut history: VecDeque<CommandExecution> = VecDeque::new();
        for step in 0..25 {
            append_to_bounded_history(
                &mut history,
                CommandExecution {
                    command: format!("cmd {step}"),
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    timestamp_ms: step,
                    step_index: step as u32,
                },
                20,
            );
        }

        assert_eq!(history.len(), 20);
        assert_eq!(history.front().map(|entry| entry.step_index), Some(5));
        assert_eq!(history.back().map(|entry| entry.step_index), Some(24));
    }

    #[tokio::test]
    async fn scrub_command_history_fields_uses_pii_scrubber_and_fallback() {
        let raw = CommandExecution {
            command: "echo API_KEY=abc123".to_string(),
            exit_code: 0,
            stdout: "password=xyz".to_string(),
            stderr: "token=secret".to_string(),
            timestamp_ms: 9,
            step_index: 1,
        };
        let tagged = serde_json::to_string(&raw).map_or_else(
            |_| String::new(),
            |serialized| format!("{}{}", COMMAND_HISTORY_PREFIX, serialized),
        );
        let parsed = match extract_command_history(&Some(tagged)) {
            Some(payload) => payload,
            None => panic!("valid payload should parse"),
        };
        let scrubber = PiiScrubber::new(Arc::new(DetectingSafetyModel));
        let scrubbed = scrub_command_history_fields(&scrubber, parsed).await;
        assert!(!scrubbed.command.contains("API_KEY"));
        assert!(!scrubbed.stdout.contains("password"));
        assert!(scrubbed.stderr.contains("<REDACTED"));

        let fallback_scrubber = PiiScrubber::new(Arc::new(FailingSafetyModel));
        let fallback = scrub_command_history_fields(
            &fallback_scrubber,
            CommandExecution {
                command: "token=bad".to_string(),
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timestamp_ms: 10,
                step_index: 2,
            },
        )
        .await;
        assert_eq!(fallback.command, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
        assert_eq!(fallback.stdout, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
        assert_eq!(fallback.stderr, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
    }
}
