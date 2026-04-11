use super::support::queue_action_request_to_tool;
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::execution::system::is_sudo_password_required_install_error;
use crate::agentic::runtime::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::runtime::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
use crate::agentic::runtime::service::lifecycle::{
    await_child_worker_result, spawn_delegated_child_session,
};
use crate::agentic::runtime::service::step::action::command_contract::is_cec_terminal_error;
use crate::agentic::runtime::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    emit_completion_gate_status_event, emit_execution_contract_receipt_event,
    emit_execution_contract_receipt_event_with_observation,
    mark_action_fingerprint_executed_at_step, mark_execution_receipt_with_value, receipt_marker,
    resolved_intent_id,
};
use crate::agentic::runtime::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, canonical_attempt_window_fingerprint,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
};
use crate::agentic::runtime::service::step::helpers::default_safe_policy;
use crate::agentic::runtime::service::step::incident::{
    advance_incident_after_action_outcome, clear_incident_state, incident_receipt_fields,
    load_incident_state, mark_incident_wait_for_user, register_pending_approval,
    should_enter_incident_recovery, start_or_continue_incident_recovery, ApprovalDirective,
    IncidentDirective,
};
use crate::agentic::runtime::service::step::intent_resolver::is_tool_allowed_for_resolution;
use crate::agentic::runtime::service::step::planner::{
    self, PlannerDispatchMatch, PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH,
};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::runtime::utils::{goto_trace_log, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::{KernelEvent, RoutingReceiptEvent, RoutingStateSummary};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod completion;
mod failure;
mod routing;
mod web_pipeline;

use self::completion::{
    maybe_complete_agent_complete, maybe_complete_browser_snapshot_interaction,
    maybe_complete_command_probe, maybe_complete_mail_reply, maybe_complete_open_app,
    maybe_complete_screenshot_capture, normalize_output_only_success,
};
use self::failure::{apply_queue_failure_policies, QueueFailureHandlingOutcome};
use self::routing::{is_web_research_scope, resolve_queue_routing_context as resolve_routing};
pub(crate) use self::web_pipeline::maybe_handle_web_search as handle_web_search_result;
use self::web_pipeline::{
    maybe_handle_browser_snapshot, maybe_handle_web_read, maybe_handle_web_search,
};
use crate::agentic::runtime::service::step::anti_loop::TierRoutingDecision;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalChatReplyLayoutProfile {
    SingleSnapshot,
    DocumentBriefing,
    StoryCollection,
    Other,
}

impl TerminalChatReplyLayoutProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleSnapshot => "single_snapshot",
            Self::DocumentBriefing => "document_briefing",
            Self::StoryCollection => "story_collection",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TerminalChatReplyShapeFacts {
    heading_present: bool,
    single_snapshot_heading_present: bool,
    story_header_count: usize,
    comparison_label_count: usize,
    run_date_present: bool,
    run_timestamp_present: bool,
    overall_confidence_present: bool,
}

fn observe_terminal_chat_reply_shape(summary: &str) -> TerminalChatReplyShapeFacts {
    let lines = summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        line.starts_with("Briefing for '") || line.starts_with("Web briefing (as of ")
    });
    let single_snapshot_heading_present = lines.first().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("right now") && lower.contains("as of ")
    });
    let story_header_count = lines
        .iter()
        .filter(|line| {
            line.strip_prefix("Story ")
                .and_then(|rest| rest.split_once(':'))
                .is_some()
        })
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let run_date_present = lines.iter().any(|line| {
        line.starts_with("Run date (UTC):") && !line["Run date (UTC):".len()..].trim().is_empty()
    });
    let run_timestamp_present = lines.iter().any(|line| {
        line.starts_with("Run timestamp (UTC):")
            && !line["Run timestamp (UTC):".len()..].trim().is_empty()
    });
    let overall_confidence_present = lines.iter().any(|line| {
        line.starts_with("Overall confidence:")
            && !line["Overall confidence:".len()..].trim().is_empty()
    });

    TerminalChatReplyShapeFacts {
        heading_present,
        single_snapshot_heading_present,
        story_header_count,
        comparison_label_count,
        run_date_present,
        run_timestamp_present,
        overall_confidence_present,
    }
}

fn is_absorbed_pending_web_read_gate(tool_name: &str, output: Option<&str>) -> bool {
    tool_name == "web__read"
        && output
            .map(|value| {
                value.starts_with("Recorded gated source in fixed payload (no approval retries): ")
            })
            .unwrap_or(false)
}

fn terminal_chat_reply_layout_profile(
    facts: &TerminalChatReplyShapeFacts,
) -> TerminalChatReplyLayoutProfile {
    if facts.heading_present && facts.story_header_count == 0 && facts.comparison_label_count == 0 {
        return TerminalChatReplyLayoutProfile::DocumentBriefing;
    }
    if facts.story_header_count > 0 || facts.comparison_label_count > 0 {
        return TerminalChatReplyLayoutProfile::StoryCollection;
    }
    if facts.single_snapshot_heading_present {
        return TerminalChatReplyLayoutProfile::SingleSnapshot;
    }
    TerminalChatReplyLayoutProfile::Other
}

fn web_queue_action_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 20;
    std::env::var("IOI_WEB_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn browser_queue_action_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 12;
    std::env::var("IOI_BROWSER_QUEUE_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

fn browser_queue_timeout_for_tool(tool: &AgentTool) -> Duration {
    const WAIT_GRACE_MS: u64 = 5_000;

    let baseline = browser_queue_action_timeout();
    match tool {
        AgentTool::BrowserWait { ms, timeout_ms, .. } => {
            let requested_ms = ms.or(*timeout_ms).unwrap_or(0);
            let requested = Duration::from_millis(requested_ms.saturating_add(WAIT_GRACE_MS));
            requested.max(baseline)
        }
        _ => baseline,
    }
}

fn queue_tool_timeout_policy(
    agent_state: &AgentState,
    tool: &AgentTool,
    tool_name: &str,
) -> Option<(&'static str, Duration)> {
    if is_web_research_scope(agent_state) {
        return Some(("Web", web_queue_action_timeout()));
    }
    if tool_name.starts_with("browser__") {
        return Some(("Browser", browser_queue_timeout_for_tool(tool)));
    }
    None
}

fn queue_workspace_read_receipt(step_index: u32, tool: &AgentTool) -> Option<String> {
    let AgentTool::FsRead { path } = tool else {
        return None;
    };
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(format!("step={step_index};tool=file__read;path={path}"))
}

fn queue_workspace_edit_receipt(step_index: u32, tool: &AgentTool) -> Option<(String, String)> {
    match tool {
        AgentTool::FsWrite {
            path, line_number, ..
        } => {
            let tool_name = if line_number.is_some() {
                "file__replace_line"
            } else {
                "file__write"
            };
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                tool_name.to_string(),
                format!("step={step_index};tool={tool_name};path={path}"),
            ))
        }
        AgentTool::FsPatch { path, .. } => {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            Some((
                "file__edit".to_string(),
                format!("step={step_index};tool=file__edit;path={path}"),
            ))
        }
        _ => None,
    }
}

fn record_queue_workspace_success_receipts(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    verification_checks: &mut Vec<String>,
) {
    if let Some(evidence) = queue_workspace_read_receipt(step_index, tool) {
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            evidence.clone(),
        );
        verification_checks.push(receipt_marker("workspace_read_observed"));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "workspace_read_observed",
            true,
            &evidence,
            None,
            Some("file__read".to_string()),
            None,
        );
    }

    if let Some((tool_name, evidence)) = queue_workspace_edit_receipt(step_index, tool) {
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_edit_applied",
            evidence.clone(),
        );
        verification_checks.push(receipt_marker("workspace_edit_applied"));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "workspace_edit_applied",
            true,
            &evidence,
            None,
            Some(tool_name),
            None,
        );
    }
}

async fn execute_queue_tool_request(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    agent_state: &mut AgentState,
    tool_wrapper: AgentTool,
    tool_name: &str,
    rules: &ActionRules,
    session_id: [u8; 32],
    tool_hash: [u8; 32],
) -> Result<(bool, Option<String>, Option<String>, Option<[u8; 32]>), TransactionError> {
    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    if !is_tool_allowed_for_resolution(agent_state.resolved_intent.as_ref(), tool_name) {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=PolicyBlocked Tool '{}' blocked by global intent scope.",
            tool_name
        )));
    }

    let mut outcome = if let Some((timeout_scope, timeout)) =
        queue_tool_timeout_policy(agent_state, &tool_wrapper, tool_name)
    {
        match tokio::time::timeout(
            timeout,
            service.handle_action_execution_with_state(
                state,
                call_context,
                tool_wrapper.clone(),
                session_id,
                agent_state.step_count,
                [0u8; 32],
                rules,
                agent_state,
                &os_driver,
                None,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "{} queue tool execution timed out after {:?} (session={} tool={}).",
                    timeout_scope,
                    timeout,
                    hex::encode(&session_id[..4]),
                    tool_name
                );
                Err(TransactionError::Invalid(format!(
                    "ERROR_CLASS=TimeoutOrHang {} queue tool '{}' timed out after {}ms.",
                    timeout_scope,
                    tool_name,
                    timeout.as_millis()
                )))
            }
        }
    } else {
        service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool_wrapper.clone(),
                session_id,
                agent_state.step_count,
                [0u8; 32],
                rules,
                agent_state,
                &os_driver,
                None,
            )
            .await
    }?;

    if outcome.0 {
        match &tool_wrapper {
            AgentTool::AgentDelegate {
                goal,
                budget,
                playbook_id,
                template_id,
                workflow_id,
                role,
                success_criteria,
                merge_mode,
                expected_output,
            } => {
                match spawn_delegated_child_session(
                    service,
                    state,
                    agent_state,
                    tool_hash,
                    goal,
                    *budget,
                    playbook_id.as_deref(),
                    template_id.as_deref(),
                    workflow_id.as_deref(),
                    role.as_deref(),
                    success_criteria.as_deref(),
                    merge_mode.as_deref(),
                    expected_output.as_deref(),
                    agent_state.step_count,
                    call_context.block_height,
                )
                .await
                {
                    Ok(spawned) => {
                        let assignment = &spawned.assignment;
                        outcome.1 = Some(
                            json!({
                                "child_session_id_hex": hex::encode(spawned.child_session_id),
                                "budget": assignment.budget,
                                "playbook_id": assignment.playbook_id,
                                "template_id": assignment.template_id,
                                "workflow_id": assignment.workflow_id,
                                "role": assignment.role,
                                "success_criteria": assignment.completion_contract.success_criteria,
                                "merge_mode": assignment.completion_contract.merge_mode.as_label(),
                                "expected_output": assignment.completion_contract.expected_output,
                            })
                            .to_string(),
                        );
                        outcome.2 = None;
                    }
                    Err(error) => {
                        outcome.0 = false;
                        outcome.1 = None;
                        outcome.2 = Some(error.to_string());
                    }
                }
            }
            AgentTool::AgentAwait {
                child_session_id_hex,
            } => {
                match await_child_worker_result(
                    service,
                    state,
                    agent_state,
                    agent_state.step_count,
                    call_context.block_height,
                    call_context,
                    child_session_id_hex,
                )
                .await
                {
                    Ok(child_status) => {
                        outcome.1 = Some(child_status);
                        outcome.2 = None;
                    }
                    Err(error) => {
                        outcome.0 = false;
                        outcome.1 = None;
                        outcome.2 = Some(error);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(outcome)
}

fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn append_chat_message(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    block_height: u64,
    role: &str,
    content: String,
) -> Result<(), TransactionError> {
    let msg = ioi_types::app::agentic::ChatMessage {
        role: role.to_string(),
        content,
        timestamp: current_unix_timestamp_ms(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;
    Ok(())
}

async fn resolve_approval_directive_outcome(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    approval_hash: &str,
    approval_directive: ApprovalDirective,
    policy_decision: &mut String,
) -> Result<(bool, Option<String>, Option<String>, Option<[u8; 32]>), TransactionError> {
    match approval_directive {
        ApprovalDirective::PromptUser => {
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                format!(
                    "System: Queued action halted by Agency Firewall (Hash: {}). Requesting authorization.",
                    approval_hash
                ),
            )
            .await?;
            Ok((true, None, None, None))
        }
        ApprovalDirective::SuppressDuplicatePrompt => {
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                "System: Approval already pending for this incident/action. Waiting for your decision."
                    .to_string(),
            )
            .await?;
            Ok((true, None, None, None))
        }
        ApprovalDirective::PauseLoop => {
            *policy_decision = "denied".to_string();
            let loop_msg = format!(
                "ERROR_CLASS=PermissionOrApprovalRequired Approval loop policy paused this incident for request hash {}.",
                approval_hash
            );
            agent_state.status = AgentStatus::Paused(
                "Approval loop detected for the same incident/action. Automatic retries paused."
                    .to_string(),
            );
            append_chat_message(
                service,
                session_id,
                block_height,
                "system",
                format!(
                    "System: {} Please approve, deny, or change policy settings.",
                    loop_msg
                ),
            )
            .await?;
            Ok((false, None, Some(loop_msg), None))
        }
    }
}

async fn append_tool_output_message_if_present(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
) -> Result<(), TransactionError> {
    if let Some(err_text) = err {
        append_chat_message(
            service,
            session_id,
            block_height,
            "tool",
            format!("Tool Output ({}): {}", tool_name, err_text),
        )
        .await?;
    }
    Ok(())
}

async fn enter_wait_for_sudo_password(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
    action_json: &str,
    tool_jcs: &[u8],
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
    mark_incident_wait_for_user(
        state,
        session_id,
        "wait_for_sudo_password",
        FailureClass::PermissionOrApprovalRequired,
        err,
    )?;
    // Clear queued remedies while waiting for credentials so resume retries
    // the original install action instead of stale fallback actions.
    agent_state.execution_queue.clear();
    agent_state.pending_approval = None;
    agent_state.pending_tool_call = Some(action_json.to_string());
    agent_state.pending_tool_jcs = Some(tool_jcs.to_vec());
    agent_state.pending_request_nonce = Some(agent_state.step_count as u64);
    agent_state.pending_visual_hash = Some(agent_state.last_screen_phash.unwrap_or([0u8; 32]));
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(tool_jcs).map_err(|e| {
        TransactionError::Invalid(format!("Failed to hash queued install tool JCS: {}", e))
    })?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
    agent_state.pending_tool_hash = Some(hash_arr);

    append_tool_output_message_if_present(service, session_id, block_height, tool_name, err)
        .await?;
    append_chat_message(
        service,
        session_id,
        block_height,
        "system",
        "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
            .to_string(),
    )
    .await?;
    verification_checks.push("awaiting_sudo_password=true".to_string());
    Ok(())
}

async fn enter_wait_for_clarification(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    tool_name: &str,
    err: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    mark_incident_wait_for_user(
        state,
        session_id,
        "wait_for_clarification",
        FailureClass::UserInterventionNeeded,
        err,
    )?;
    agent_state.status =
        AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
    agent_state.pending_approval = None;
    agent_state.pending_tool_call = None;
    agent_state.pending_tool_jcs = None;
    agent_state.pending_tool_hash = None;
    agent_state.pending_request_nonce = None;
    agent_state.pending_visual_hash = None;
    agent_state.execution_queue.clear();

    append_tool_output_message_if_present(service, session_id, block_height, tool_name, err)
        .await?;
    append_chat_message(
        service,
        session_id,
        block_height,
        "system",
        "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
            .to_string(),
    )
    .await?;
    verification_checks.push("awaiting_clarification=true".to_string());
    Ok(())
}

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

    // Pop the first action
    let action_request = agent_state.execution_queue.remove(0);

    // Capture the active skill hash for attribution.
    let active_skill = agent_state.active_skill_hash;

    // Re-construct a typed AgentTool from ActionRequest.
    let tool_wrapper = queue_action_request_to_tool(&action_request)?;
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
        .map(|resolved| {
            resolved.scope == ioi_types::app::agentic::IntentScopeProfile::CommandExecution
        })
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

    // Execute
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

            agent_state.pending_tool_jcs = Some(tool_jcs.clone());
            agent_state.pending_tool_hash = Some(hash_arr);
            agent_state.pending_request_nonce = Some(agent_state.step_count as u64);
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
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_request_nonce = None;
        agent_state.pending_visual_hash = None;
        agent_state.status = AgentStatus::Running;
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

    // Log Trace with Provenance
    goto_trace_log(
        agent_state,
        state,
        &key,
        p.session_id,
        trace_visual_hash,
        format!("[Macro Step] Executing queued action"),
        output_str,
        success,
        error_str,
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill,
        service.memory_runtime.as_ref(),
    )?;

    if let Some(summary) = completion_summary.as_ref() {
        if let Some(tx) = &service.event_sender {
            verification_checks.push("terminal_chat_reply_emitted=true".to_string());
            let intent_id = resolved_intent_id(agent_state);
            let reply_digest = sha256(summary.as_bytes())
                .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
                .unwrap_or_else(|_| "sha256:unavailable".to_string());
            emit_completion_gate_status_event(
                service,
                p.session_id,
                pre_state_summary.step_index,
                intent_id.as_str(),
                true,
                "queue_completion_summary_gate_passed",
            );
            verification_checks.push("cec_completion_gate_emitted=true".to_string());
            emit_execution_contract_receipt_event_with_observation(
                service,
                p.session_id,
                pre_state_summary.step_index,
                intent_id.as_str(),
                "postcondition",
                "terminal_chat_reply_binding",
                true,
                &format!(
                    "probe_source=queue.chat_reply_binding.v1;observed_value={};evidence_type=sha256",
                    reply_digest
                ),
                Some("queue.chat_reply_binding.v1"),
                Some(reply_digest.as_str()),
                Some("sha256"),
                None,
                None,
                None,
            );
            verification_checks
                .push("cec_postcondition_terminal_chat_reply_binding=true".to_string());
            verification_checks.push(format!("terminal_chat_reply_sha256={}", reply_digest));
            let shape_facts = observe_terminal_chat_reply_shape(summary);
            let layout_profile = terminal_chat_reply_layout_profile(&shape_facts);
            let emit_postcondition_receipt =
                |key: &str, satisfied: bool, observed_value: &str, evidence_type: &str| {
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        p.session_id,
                        pre_state_summary.step_index,
                        intent_id.as_str(),
                        "postcondition",
                        key,
                        satisfied,
                        &format!(
                            "probe_source=queue.chat_reply_shape.v1;observed_value={};evidence_type={}",
                            observed_value, evidence_type
                        ),
                        Some("queue.chat_reply_shape.v1"),
                        Some(observed_value),
                        Some(evidence_type),
                        None,
                        None,
                        None,
                    );
                };
            emit_execution_contract_receipt_event_with_observation(
                service,
                p.session_id,
                pre_state_summary.step_index,
                intent_id.as_str(),
                "postcondition",
                "terminal_chat_reply_layout_profile",
                true,
                &format!(
                    "probe_source=queue.chat_reply_shape.v1;observed_value={};evidence_type=label",
                    layout_profile.as_str()
                ),
                Some("queue.chat_reply_shape.v1"),
                Some(layout_profile.as_str()),
                Some("label"),
                None,
                None,
                None,
            );
            let story_header_count = shape_facts.story_header_count.to_string();
            emit_postcondition_receipt(
                "terminal_chat_reply_story_headers_absent",
                shape_facts.story_header_count == 0,
                story_header_count.as_str(),
                "scalar",
            );
            let comparison_label_count = shape_facts.comparison_label_count.to_string();
            emit_postcondition_receipt(
                "terminal_chat_reply_comparison_absent",
                shape_facts.comparison_label_count == 0,
                comparison_label_count.as_str(),
                "scalar",
            );
            let temporal_anchor_summary = format!(
                "run_date_present={};run_timestamp_present={}",
                shape_facts.run_date_present, shape_facts.run_timestamp_present
            );
            emit_postcondition_receipt(
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
            emit_postcondition_receipt(
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
                "terminal_chat_reply_story_header_count={}",
                shape_facts.story_header_count
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
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id: p.session_id,
                step_index: agent_state.step_count,
                tool_name: "chat__reply".to_string(),
                output: summary.clone(),
                error_class: None,
                agent_status: "Completed".to_string(),
            });
        }
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
        lineage_ptr: lineage_pointer(active_skill),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &p.session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    // If the queue is empty, clear active skill context.
    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        browser_queue_action_timeout, browser_queue_timeout_for_tool,
        observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
        TerminalChatReplyLayoutProfile,
    };
    use ioi_types::app::agentic::AgentTool;
    use std::time::Duration;

    #[test]
    fn terminal_chat_reply_shape_detects_story_collection_output() {
        let output = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(!facts.heading_present);
        assert_eq!(facts.story_header_count, 1);
        assert_eq!(facts.comparison_label_count, 1);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::StoryCollection
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_document_briefing_output() {
        let output = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nWhat happened:\n- NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- NIST states the standards are mandatory for federal systems.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(facts.heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::DocumentBriefing
        );
    }

    #[test]
    fn terminal_chat_reply_shape_detects_single_snapshot_output() {
        let output = "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high";
        let facts = observe_terminal_chat_reply_shape(output);

        assert!(!facts.heading_present);
        assert!(facts.single_snapshot_heading_present);
        assert_eq!(facts.story_header_count, 0);
        assert_eq!(facts.comparison_label_count, 0);
        assert!(facts.run_date_present);
        assert!(facts.run_timestamp_present);
        assert!(facts.overall_confidence_present);
        assert_eq!(
            terminal_chat_reply_layout_profile(&facts),
            TerminalChatReplyLayoutProfile::SingleSnapshot
        );
    }

    #[test]
    fn browser_queue_timeout_defaults_for_non_wait_tools() {
        let tool = AgentTool::BrowserSnapshot {};
        assert_eq!(
            browser_queue_timeout_for_tool(&tool),
            browser_queue_action_timeout()
        );
    }

    #[test]
    fn browser_wait_timeout_honors_requested_duration_plus_grace() {
        let tool = AgentTool::BrowserWait {
            ms: Some(15_000),
            condition: None,
            selector: None,
            query: None,
            scope: None,
            timeout_ms: None,
            continue_with: None,
        };

        assert_eq!(
            browser_queue_timeout_for_tool(&tool),
            Duration::from_millis(20_000)
        );
    }
}
