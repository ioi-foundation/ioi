use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::execution::system::{
    install_resolution_checks_for_tool, install_resolution_summary_for_tool,
    is_sudo_password_required_install_error,
};
use crate::agentic::runtime::keys::get_state_key;
use crate::agentic::runtime::service::handler::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};
use crate::agentic::runtime::service::planning::planner::{
    self, PlannerDispatchMatch, PLANNER_FALLBACK_REASON_EXECUTOR_MISMATCH,
};
use crate::agentic::runtime::service::policy::load_action_rules_for_session;
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
use crate::agentic::runtime::service::tool_execution::command_contract::{
    extract_error_class_token, is_completion_contract_error,
};
use crate::agentic::runtime::service::tool_execution::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    mark_action_fingerprint_executed_at_step, persist_step_evidence_to_ledger, resolved_intent_id,
};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{
    AgentState, AgentStatus, ExecutionStage, ExecutionTier, StepAgentParams,
};
use crate::agentic::runtime::utils::{goto_trace_log, persist_agent_state};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, KernelEvent, RoutingReceiptEvent,
    RoutingStateSummary,
};
use ioi_types::error::TransactionError;
use serde_json::json;

mod completion;
mod completion_receipts;
mod execution;
mod failure;
mod install_receipts;
mod messaging;
mod pause_state;
mod routing;
mod terminal_reply;
mod web_pipeline;
mod workspace_receipts;

use self::completion::{
    maybe_complete_agent_complete, maybe_complete_browser_snapshot_interaction,
    maybe_complete_chat_reply, maybe_complete_command_probe, maybe_complete_mail_reply,
    maybe_complete_open_app, maybe_complete_screenshot_capture,
    maybe_complete_toolcat_single_tool_probe, normalize_output_only_success,
};
use self::completion_receipts::emit_terminal_chat_reply_receipts;
use self::execution::{execute_queue_tool_request, queue_action_to_tool};
use self::failure::{apply_queue_failure_policies, QueueFailureHandlingOutcome};
use self::install_receipts::record_queue_install_success_receipts;
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

fn queue_tool_tier_override(tool_name: &str) -> Option<(ExecutionTier, &'static str)> {
    match tool_name {
        "screen__click_at" => Some((
            ExecutionTier::VisualForeground,
            "visual_last_coordinate_tool",
        )),
        _ => None,
    }
}

fn install_approval_status_from_tool(tool: &ioi_types::app::agentic::AgentTool) -> Option<String> {
    let summary = install_resolution_summary_for_tool(tool)?;
    let display_name = summary.display_name.as_deref()?;
    let source_kind = summary.source_kind.as_deref().unwrap_or("source");
    let manager = summary.manager.as_deref().unwrap_or("manager");
    Some(format!(
        "Awaiting install approval: {} via {} ({})",
        display_name, manager, source_kind
    ))
}

fn queue_agent_status_label(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

fn queue_tool_action_result_output(
    tool_name: &str,
    raw_tool_output: Option<&str>,
    fallback_output: &str,
    success: bool,
    completion_summary: Option<&str>,
    error: Option<&str>,
) -> String {
    if success
        && tool_name != "chat__reply"
        && completion_summary.is_some()
        && raw_tool_output
            .or(Some(fallback_output))
            .is_some_and(|output| !output.trim().is_empty())
    {
        return "Completed. Final response emitted via chat__reply.".to_string();
    }

    raw_tool_output
        .filter(|output| !output.trim().is_empty())
        .or_else(|| {
            if fallback_output.trim().is_empty() {
                None
            } else {
                Some(fallback_output)
            }
        })
        .or(error)
        .unwrap_or("Unknown error")
        .to_string()
}

struct QueueToolActionResultEvent<'a> {
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &'a str,
    output: &'a str,
    error: Option<&'a str>,
    agent_status: &'a AgentStatus,
}

fn emit_queue_tool_action_result(
    event_sender: Option<&tokio::sync::broadcast::Sender<KernelEvent>>,
    event: QueueToolActionResultEvent<'_>,
) {
    let Some(tx) = event_sender else {
        return;
    };

    let _ = tx.send(KernelEvent::AgentActionResult {
        session_id: event.session_id,
        step_index: event.step_index,
        tool_name: event.tool_name.to_string(),
        output: event.output.to_string(),
        error_class: extract_error_class_token(event.error).map(str::to_string),
        agent_status: queue_agent_status_label(event.agent_status),
    });
}

const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

fn is_toolcat_single_tool_probe(goal: &str) -> bool {
    goal.contains("TOOLCAT_SINGLE_TOOL") || goal.contains("toolcat_tool=")
}

fn toolcat_single_tool_target(goal: &str) -> Option<&str> {
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix("toolcat_tool="))
        .map(str::trim)
        .filter(|tool| !tool.is_empty())
}

fn toolcat_single_tool_marker_value(goal: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn latest_browser_tab_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let json_text = if trimmed.starts_with('{') {
        Some(trimmed)
    } else {
        let start = trimmed.find('{')?;
        let end = trimmed.rfind('}')?;
        (start <= end).then_some(&trimmed[start..=end])
    };
    if let Some(value) =
        json_text.and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
    {
        if let Some(tabs) = value.get("tabs").and_then(|value| value.as_array()) {
            let selected = tabs
                .iter()
                .find(|tab| tab.get("active").and_then(|value| value.as_bool()) == Some(false))
                .or_else(|| tabs.first());
            if let Some(tab_id) = selected.and_then(|tab| {
                tab.get("tab_id")
                    .or_else(|| tab.get("tabId"))
                    .and_then(|value| value.as_str())
            }) {
                let tab_id = tab_id.trim();
                if !tab_id.is_empty() {
                    return Some(tab_id.to_string());
                }
            }
        }
    }
    let re = regex::Regex::new(r#"(?i)\\?"tab_?id\\?"\s*:\s*\\?"([^"\\\s]+)\\?""#).ok()?;
    let tab_id = re
        .captures_iter(text)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .find(|value| !value.is_empty());
    tab_id
}

fn toolcat_browser_subagent_tool(goal: &str) -> AgentTool {
    let target_url = toolcat_single_tool_marker_value(goal, "browser_fixture_url")
        .unwrap_or_else(|| "the current browser fixture page".to_string());
    AgentTool::Dynamic(json!({
        "name": "browser__subagent",
        "arguments": {
            "task_name": "tool catalogue browser fixture",
            "task_summary": "Verify browser subagent packaging reaches the fixture page.",
            "recording_name": "toolcat-browser-subagent",
            "task": format!(
                "Use browser__navigate to open {}, then inspect the browser page and report the TOOLCAT_BROWSER_CANARY text without external actions.",
                target_url
            ),
        }
    }))
}

fn toolcat_browser_target_after_navigation(goal: &str, target: &str) -> Option<AgentTool> {
    match target {
        "browser__inspect" => Some(AgentTool::BrowserSnapshot {}),
        "browser__find_text" => Some(AgentTool::BrowserFindText {
            query: "TOOLCAT_BROWSER_CANARY".to_string(),
            scope: Some("document".to_string()),
            scroll: true,
        }),
        "browser__screenshot" => Some(AgentTool::BrowserScreenshot { full_page: false }),
        "browser__list_options" => Some(AgentTool::BrowserDropdownOptions {
            id: None,
            selector: Some("#toolcat-select".to_string()),
            som_id: None,
        }),
        "browser__select_option" => Some(AgentTool::BrowserSelectDropdown {
            id: None,
            selector: Some("#toolcat-select".to_string()),
            som_id: None,
            value: Some("beta".to_string()),
            label: None,
        }),
        "browser__click" => Some(AgentTool::BrowserClick {
            selector: "#toolcat-input".to_string(),
            id: None,
            ids: vec![],
            delay_ms_between_ids: None,
            continue_with: None,
        }),
        "browser__type" => Some(AgentTool::BrowserType {
            text: "typed through browser__type".to_string(),
            selector: Some("#toolcat-input".to_string()),
        }),
        "browser__press_key" => Some(AgentTool::BrowserKey {
            key: "a".to_string(),
            selector: Some("#toolcat-input".to_string()),
            modifiers: Some(vec!["Control".to_string()]),
            continue_with: None,
        }),
        "browser__select" | "browser__copy" => Some(AgentTool::BrowserSelectText {
            selector: Some("#fixture-copy".to_string()),
            start_offset: Some(0),
            end_offset: Some(23),
        }),
        "browser__wait" => Some(AgentTool::BrowserWait {
            ms: None,
            condition: Some("text_present".to_string()),
            selector: None,
            query: Some("TOOLCAT_BROWSER_CANARY".to_string()),
            scope: Some("document".to_string()),
            timeout_ms: Some(3000),
            continue_with: None,
        }),
        "browser__upload" => Some(AgentTool::BrowserUploadFile {
            paths: vec![
                toolcat_single_tool_marker_value(goal, "workspace_fixture_upload")
                    .filter(|path| !path.is_empty())
                    .unwrap_or_else(|| "toolcat-missing-upload-path".to_string()),
            ],
            selector: Some("#toolcat-file".to_string()),
            som_id: None,
        }),
        "browser__list_tabs" | "browser__switch_tab" | "browser__close_tab" => {
            Some(AgentTool::BrowserTabList {})
        }
        "browser__inspect_canvas" => Some(AgentTool::BrowserCanvasSummary {
            selector: "#toolcat-canvas".to_string(),
        }),
        "browser__hover" => Some(AgentTool::BrowserHover {
            selector: Some("#toolcat-button".to_string()),
            id: None,
            duration_ms: Some(100),
            resample_interval_ms: None,
        }),
        "browser__move_pointer" => Some(AgentTool::BrowserMoveMouse {
            observation_ref: "toolcat-observation".to_string(),
            coordinate_space_id: "viewport_css_px".to_string(),
            semantic_id: "toolcat-canvas".to_string(),
            x: 48.0,
            y: 48.0,
        }),
        _ => None,
    }
}

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

fn queue_tool_to_action_request(
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

fn toolcat_single_tool_queue_followup(
    goal: &str,
    current_tool_name: &str,
    output: Option<&str>,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) || current_tool_name == "chat__reply" {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    match (target, current_tool_name) {
        ("browser__paste", "clipboard__copy") => Some(AgentTool::BrowserPasteClipboard {
            selector: Some("#toolcat-input".to_string()),
        }),
        ("browser__copy" | "browser__paste", "browser__select") => {
            Some(AgentTool::BrowserCopySelection {})
        }
        ("browser__switch_tab", "browser__list_tabs") => {
            let tab_id = latest_browser_tab_id(output?)?;
            Some(AgentTool::BrowserTabSwitch { tab_id })
        }
        ("browser__close_tab", "browser__list_tabs") => {
            let tab_id = latest_browser_tab_id(output?)?;
            Some(AgentTool::BrowserTabClose {
                tab_id,
                close: true,
            })
        }
        ("browser__pointer_down" | "browser__pointer_up", "browser__move_pointer") => {
            Some(AgentTool::BrowserMouseDown {
                button: Some("left".to_string()),
            })
        }
        ("browser__pointer_up", "browser__pointer_down") => Some(AgentTool::BrowserMouseUp {
            button: Some("left".to_string()),
        }),
        ("browser__click_at", "browser__inspect") => Some(AgentTool::BrowserSyntheticClick {
            id: Some("toolcat-canvas".to_string()),
            observation_ref: None,
            coordinate_space_id: None,
            semantic_id: None,
            x: None,
            y: None,
            continue_with: None,
        }),
        ("browser__subagent", "browser__navigate") => Some(toolcat_browser_subagent_tool(goal)),
        (_, "browser__navigate") => toolcat_browser_target_after_navigation(goal, target),
        _ if target == current_tool_name => Some(AgentTool::ChatReply {
            message: format!(
                "TOOLCAT_SINGLE_TOOL {} live IDE probe reached the post-tool final reply path.",
                current_tool_name
            ),
        }),
        _ => None,
    }
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
    let rules: ActionRules = load_action_rules_for_session(state, p.session_id)?;
    let (mut routing_decision, mut pre_state_summary) = resolve_queue_routing_context(agent_state);
    let mut policy_decision = "allowed".to_string();

    let action_request = agent_state.execution_queue.remove(0);
    let active_skill = agent_state.active_skill_hash;

    let tool_wrapper = queue_action_to_tool(&action_request)?;
    let tool_jcs = serde_jcs::to_vec(&tool_wrapper)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = sha256(&tool_jcs)
        .map_err(|e| TransactionError::Invalid(format!("Failed to hash queued tool JCS: {}", e)))?;
    let (tool_name, intent_args) = canonical_tool_identity(&tool_wrapper);
    if let Some((tier, reason_code)) = queue_tool_tier_override(&tool_name) {
        routing_decision = TierRoutingDecision {
            tier,
            reason_code,
            source_failure: routing_decision.source_failure,
        };
        agent_state.current_tier = tier;
        pre_state_summary.tier = tier_as_str(tier).to_string();
    }
    let is_software_install_tool = tool_name == "software_install__execute_plan";
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
    if is_software_install_tool {
        verification_checks.extend(install_resolution_checks_for_tool(&tool_wrapper));
    }
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
            if is_software_install_tool {
                if let Some(status) = install_approval_status_from_tool(&tool_wrapper) {
                    agent_state.status = AgentStatus::Paused(status);
                }
            }
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
    if success && !is_gated && is_software_install_tool {
        let intent_id = resolved_intent_id(agent_state);
        record_queue_install_success_receipts(
            service,
            agent_state,
            &tool_wrapper,
            p.session_id,
            pre_state_summary.step_index,
            intent_id.as_str(),
            &mut verification_checks,
            out.as_deref(),
        );
    }
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
    let clarification_required = !success
        && err
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&tool_name, msg))
            .unwrap_or(false);

    if !is_gated
        && !success
        && is_software_install_tool
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
    let queue_tool_was_executed = planner_executor_mismatch_reason.is_none();
    let pre_terminal_tool_success = success;
    let pre_terminal_tool_output = out.clone();
    let pre_terminal_tool_error = err.clone();
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
    maybe_complete_toolcat_single_tool_probe(
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

    let output_str = out.clone().unwrap_or_default();
    let error_str = err.clone();
    let queue_tool_event_output = queue_tool_action_result_output(
        &tool_name,
        pre_terminal_tool_output.as_deref(),
        &output_str,
        pre_terminal_tool_success,
        completion_summary.as_deref(),
        pre_terminal_tool_error.as_deref().or(error_str.as_deref()),
    );
    let queue_tool_event_error = if pre_terminal_tool_success {
        None
    } else {
        pre_terminal_tool_error.as_deref().or(error_str.as_deref())
    };

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
        output_str.clone(),
        success,
        error_str.clone(),
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill,
        service.memory_runtime.as_ref(),
    )?;

    if queue_tool_was_executed && !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        emit_queue_tool_action_result(
            service.event_sender.as_ref(),
            QueueToolActionResultEvent {
                session_id: p.session_id,
                step_index: pre_state_summary.step_index,
                tool_name: &tool_name,
                output: &queue_tool_event_output,
                error: queue_tool_event_error,
                agent_status: &agent_state.status,
            },
        );
        verification_checks.push("queue_tool_action_result_emitted=true".to_string());
    }

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
        mut stop_condition_hit,
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
    if success
        && !stop_condition_hit
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && matches!(agent_state.status, AgentStatus::Running)
    {
        let output_str = out.clone().unwrap_or_default();
        if let Some(followup_tool) = toolcat_single_tool_queue_followup(
            &agent_state.goal,
            &tool_name,
            Some(output_str.as_str()),
        ) {
            let followup_name = queue_tool_name(&followup_tool);
            let nonce =
                agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1;
            let request = queue_tool_to_action_request(&followup_tool, p.session_id, nonce)?;
            agent_state.execution_queue.insert(0, request);
            agent_state.recent_actions.clear();
            verification_checks.push(format!("toolcat_queue_followup_queued={}", followup_name));
        }
    }
    if success
        && tool_name == "chat__reply"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::execution::system::software_install_plan_ref_for_request;
    use ioi_types::app::agentic::{AgentTool, SoftwareInstallRequestFrame};

    fn software_install_execute_plan_tool(
        target_text: &str,
        manager_preference: Option<&str>,
    ) -> AgentTool {
        let request = SoftwareInstallRequestFrame {
            target_text: target_text.to_string(),
            target_kind: None,
            manager_preference: manager_preference.map(str::to_string),
            launch_after_install: None,
            provenance: Some("test".to_string()),
        };
        AgentTool::SoftwareInstallExecutePlan {
            plan_ref: software_install_plan_ref_for_request(&request),
        }
    }

    #[test]
    fn install_approval_status_uses_resolution_summary() {
        let tool = software_install_execute_plan_tool("generic tool", Some("apt"));

        assert_eq!(
            install_approval_status_from_tool(&tool).as_deref(),
            Some("Awaiting install approval: generic tool via apt-get (package_manager)")
        );
    }

    #[test]
    fn queue_tool_action_result_suppresses_terminalized_tool_output() {
        let output = queue_tool_action_result_output(
            "shell__terminate",
            Some("{\"command_id\":\"shell__start:abc\",\"state\":\"terminated\"}"),
            "TOOLCAT_SINGLE_TOOL shell__terminate live IDE probe reached the post-tool final reply path.",
            true,
            Some("TOOLCAT_SINGLE_TOOL shell__terminate live IDE probe reached the post-tool final reply path."),
            None,
        );

        assert_eq!(output, "Completed. Final response emitted via chat__reply.");
    }

    #[test]
    fn queue_tool_action_result_event_preserves_exact_tool_name() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        let status = AgentStatus::Completed(Some("done".to_string()));
        emit_queue_tool_action_result(
            Some(&tx),
            QueueToolActionResultEvent {
                session_id: [7u8; 32],
                step_index: 42,
                tool_name: "shell__terminate",
                output: "Completed. Final response emitted via chat__reply.",
                error: None,
                agent_status: &status,
            },
        );

        let event = rx.try_recv().expect("event should be emitted");
        match event {
            KernelEvent::AgentActionResult {
                step_index,
                tool_name,
                output,
                error_class,
                agent_status,
                ..
            } => {
                assert_eq!(step_index, 42);
                assert_eq!(tool_name, "shell__terminate");
                assert_eq!(output, "Completed. Final response emitted via chat__reply.");
                assert_eq!(error_class, None);
                assert_eq!(agent_status, "Completed");
            }
            other => panic!("expected AgentActionResult, got {:?}", other),
        }
    }

    #[test]
    fn toolcat_queue_followup_continues_browser_paste_after_clipboard_copy() {
        let followup = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__paste",
            "clipboard__copy",
            None,
        )
        .expect("paste follow-up");

        match followup {
            AgentTool::BrowserPasteClipboard { selector } => {
                assert_eq!(selector.as_deref(), Some("#toolcat-input"));
            }
            other => panic!("expected browser paste follow-up, got {:?}", other),
        }
    }

    #[test]
    fn toolcat_queue_followup_chains_pointer_up_and_exact_success() {
        let pointer_down = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_up",
            "browser__move_pointer",
            None,
        )
        .expect("pointer down setup");
        assert!(matches!(
            pointer_down,
            AgentTool::BrowserMouseDown {
                button: Some(ref button)
            } if button == "left"
        ));

        let pointer_up = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_up",
            "browser__pointer_down",
            None,
        )
        .expect("pointer up follow-up");
        assert!(matches!(
            pointer_up,
            AgentTool::BrowserMouseUp {
                button: Some(ref button)
            } if button == "left"
        ));

        let final_reply = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_up",
            "browser__pointer_up",
            None,
        )
        .expect("terminal chat reply");
        match final_reply {
            AgentTool::ChatReply { message } => {
                assert!(message.contains("browser__pointer_up live IDE probe"));
            }
            other => panic!("expected chat reply follow-up, got {:?}", other),
        }
    }

    #[test]
    fn toolcat_queue_followup_continues_browser_subagent_after_navigation() {
        let followup = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__subagent browser_fixture_url=http://127.0.0.1:12345/",
            "browser__navigate",
            None,
        )
        .expect("browser subagent follow-up");

        match followup {
            AgentTool::Dynamic(value) => {
                assert_eq!(
                    value.get("name").and_then(|name| name.as_str()),
                    Some("browser__subagent")
                );
                let task = value
                    .get("arguments")
                    .and_then(|arguments| arguments.get("task"))
                    .and_then(|task| task.as_str())
                    .unwrap_or_default();
                assert!(task.contains("browser__navigate"));
                assert!(task.contains("http://127.0.0.1:12345/"));
                assert!(task.contains("TOOLCAT_BROWSER_CANARY"));
            }
            other => panic!("expected browser subagent follow-up, got {:?}", other),
        }
    }

    #[test]
    fn toolcat_queue_followup_continues_browser_dom_after_navigation() {
        let list_options = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__list_options",
            "browser__navigate",
            None,
        )
        .expect("list_options follow-up");
        match list_options {
            AgentTool::BrowserDropdownOptions { selector, .. } => {
                assert_eq!(selector.as_deref(), Some("#toolcat-select"));
            }
            other => panic!("expected browser list_options follow-up, got {:?}", other),
        }

        let upload = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__upload workspace_fixture_upload=/tmp/toolcat-upload.txt",
            "browser__navigate",
            None,
        )
        .expect("upload follow-up");
        match upload {
            AgentTool::BrowserUploadFile {
                paths, selector, ..
            } => {
                assert_eq!(paths, vec!["/tmp/toolcat-upload.txt".to_string()]);
                assert_eq!(selector.as_deref(), Some("#toolcat-file"));
            }
            other => panic!("expected browser upload follow-up, got {:?}", other),
        }

        let copy_setup = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__copy",
            "browser__navigate",
            None,
        )
        .expect("copy selection setup");
        assert!(matches!(
            copy_setup,
            AgentTool::BrowserSelectText {
                selector: Some(ref selector),
                start_offset: Some(0),
                end_offset: Some(23),
            } if selector == "#fixture-copy"
        ));

        let copy = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__copy",
            "browser__select",
            None,
        )
        .expect("copy follow-up");
        assert!(matches!(copy, AgentTool::BrowserCopySelection {}));
    }

    #[test]
    fn toolcat_queue_followup_continues_browser_tabs_after_list_tabs_output() {
        let tabs_output = r#"{"tabs":[{"active":true,"tab_id":"ACTIVE_TAB"},{"active":false,"tab_id":"INACTIVE_TAB"}]}"#;

        let switch_tab = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__switch_tab",
            "browser__list_tabs",
            Some(tabs_output),
        )
        .expect("switch_tab follow-up");
        match switch_tab {
            AgentTool::BrowserTabSwitch { tab_id } => {
                assert_eq!(tab_id, "INACTIVE_TAB");
            }
            other => panic!("expected browser switch_tab follow-up, got {:?}", other),
        }

        let close_tab = toolcat_single_tool_queue_followup(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__close_tab",
            "browser__list_tabs",
            Some(tabs_output),
        )
        .expect("close_tab follow-up");
        match close_tab {
            AgentTool::BrowserTabClose { tab_id, close } => {
                assert_eq!(tab_id, "INACTIVE_TAB");
                assert!(close);
            }
            other => panic!("expected browser close_tab follow-up, got {:?}", other),
        }
    }

    #[test]
    fn coordinate_screen_clicks_start_in_visual_foreground() {
        let (tier, reason) =
            queue_tool_tier_override("screen__click_at").expect("coordinate override");
        assert_eq!(tier, ExecutionTier::VisualForeground);
        assert_eq!(reason, "visual_last_coordinate_tool");
        assert!(queue_tool_tier_override("screen__scroll").is_none());
    }

    #[test]
    fn queue_tool_to_action_request_preserves_browser_tool_name_metadata() {
        let request = queue_tool_to_action_request(
            &AgentTool::BrowserPasteClipboard {
                selector: Some("#toolcat-input".to_string()),
            },
            [9u8; 32],
            12,
        )
        .expect("action request");
        assert_eq!(request.target, ActionTarget::BrowserInteract);
        let params = serde_json::from_slice::<serde_json::Value>(&request.params)
            .expect("request params JSON");
        assert_eq!(
            params
                .get(QUEUE_TOOL_NAME_KEY)
                .and_then(|value| value.as_str()),
            Some("browser__paste")
        );
    }

    #[test]
    fn queue_tool_to_action_request_preserves_browser_inspect_tool_name_metadata() {
        let request = queue_tool_to_action_request(
            &AgentTool::BrowserCanvasSummary {
                selector: "#toolcat-canvas".to_string(),
            },
            [9u8; 32],
            13,
        )
        .expect("action request");
        assert_eq!(request.target, ActionTarget::BrowserInspect);
        let params = serde_json::from_slice::<serde_json::Value>(&request.params)
            .expect("request params JSON");
        assert_eq!(
            params
                .get(QUEUE_TOOL_NAME_KEY)
                .and_then(|value| value.as_str()),
            Some("browser__inspect_canvas")
        );
    }
}
