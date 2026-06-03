use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::decision_loop::cognition::{
    final_reply_product_handoff_reason, sanitize_direct_chat_reply_output,
    sanitize_product_handoff_internal_markers,
};
use crate::agentic::runtime::service::decision_loop::helpers::should_auto_complete_open_app_goal;
use crate::agentic::runtime::service::decision_loop::intent_resolver::tool_has_capability;
use crate::agentic::runtime::service::tool_execution::command_contract::{
    compose_terminal_chat_reply, enrich_command_scope_summary, evaluate_completion_requirements,
    execution_contract_violation_error,
};
use crate::agentic::runtime::service::tool_execution::{
    has_success_condition, is_command_probe_intent, is_ui_capture_screenshot_intent,
    missing_runtime_action_completion_evidence, summarize_command_probe_output,
};
use crate::agentic::runtime::service::visual_loop::browser_completion::browser_snapshot_completion;
use crate::agentic::runtime::stop_hook::stop_hook_completion_blocker;
use crate::agentic::runtime::types::{AgentState, AgentStatus};
use ioi_types::app::agentic::{AgentTool, ScreenAction};

pub(super) fn complete_with_summary(
    agent_state: &mut AgentState,
    summary: String,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    clear_pending_search: bool,
) {
    *success = true;
    *out = Some(summary.clone());
    *err = None;
    *completion_summary = Some(summary.clone());
    agent_state.status = AgentStatus::Completed(Some(summary));
    if clear_pending_search {
        agent_state.pending_search_completion = None;
    }
    agent_state.execution_queue.clear();
    agent_state.recent_actions.clear();
}

fn completion_summary_from_output(output: Option<&str>, fallback: &str) -> String {
    output
        .and_then(|value| {
            value
                .split("\n\n")
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn terminal_contract_intent_id(agent_state: &AgentState) -> Option<String> {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id.clone())
}

fn completion_gate_blocks(
    agent_state: &mut AgentState,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
) -> bool {
    if let Some(blocked_error) = stop_hook_completion_blocker(agent_state) {
        let intent_id = terminal_contract_intent_id(agent_state);
        *success = false;
        *out = Some(blocked_error.clone());
        *err = Some(blocked_error);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("stop_hook_completion_blocked=true".to_string());
        verification_checks.push("terminal_chat_reply_ready=false".to_string());
        agent_state
            .execution_ledger
            .record_completion_gate(intent_id, &["stop_hook::validation_failed".to_string()]);
        if let Some(attempt) = agent_state.execution_ledger.attempts.last_mut() {
            attempt.error_class = Some("StopHookBlocked".to_string());
        }
        return true;
    }

    let intent_id = terminal_contract_intent_id(agent_state);
    let mut missing_completion_evidence = evaluate_completion_requirements(
        agent_state,
        intent_id.as_deref().unwrap_or_default(),
        verification_checks,
        rules,
    );
    let action_missing = missing_runtime_action_completion_evidence(agent_state);
    if !action_missing.is_empty() {
        for missing in &action_missing {
            verification_checks.push(format!("action_completion_missing={}", missing));
        }
        missing_completion_evidence.extend(action_missing);
        agent_state
            .execution_ledger
            .record_completion_gate(intent_id, &missing_completion_evidence);
    }
    if missing_completion_evidence.is_empty() {
        return false;
    }

    let missing = missing_completion_evidence.join(",");
    let contract_error = execution_contract_violation_error(&missing);
    *success = false;
    *out = Some(contract_error.clone());
    *err = Some(contract_error);
    agent_state.status = AgentStatus::Running;
    verification_checks.push("execution_contract_gate_blocked=true".to_string());
    verification_checks.push(format!("execution_contract_missing_keys={}", missing));
    true
}

fn product_handoff_violation_error(reason: &str) -> String {
    format!(
        "ERROR_CLASS=UnexpectedState Final reply was not product-safe ({reason}). Return a fresh concise user-facing Markdown answer through the available terminal reply tool. Do not include raw temp paths, fixture/probe markers, raw logs, stdout/stderr dumps, receipt ids, trace ids, JSON payloads, or daemon scaffolding. Summarize the observed work and verification result instead."
    )
}

fn product_handoff_blocks(
    agent_state: &mut AgentState,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    candidate: &str,
    event_label: &'static str,
) -> bool {
    let Some(reason) = final_reply_product_handoff_reason(candidate, &agent_state.goal) else {
        return false;
    };

    let blocked_error = product_handoff_violation_error(reason);
    *success = false;
    *out = Some(blocked_error.clone());
    *err = Some(blocked_error);
    agent_state.status = AgentStatus::Running;
    verification_checks.push(format!(
        "terminal_product_handoff_blocked_reason={}",
        reason
    ));
    verification_checks.push("terminal_chat_reply_ready=false".to_string());
    verification_checks.push(format!("{}_product_handoff_blocked=true", event_label));
    true
}

fn remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state: &AgentState) -> bool {
    let mut saw_mail_reply_fallback = false;
    for request in &agent_state.execution_queue {
        let target = request.target.canonical_label();
        if tool_has_capability(&target, "mail.reply") || tool_has_capability(&target, "mail.send") {
            saw_mail_reply_fallback = true;
            continue;
        }
        return false;
    }
    saw_mail_reply_fallback
}

pub(super) fn normalize_output_only_success(
    tool_name: &str,
    success: &mut bool,
    out: &Option<String>,
    err: &Option<String>,
    verification_checks: &mut Vec<String>,
) {
    if *success || err.is_some() {
        return;
    }
    let has_output = out
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !has_output {
        return;
    }
    *success = true;
    verification_checks.push("queue_output_only_success_normalized=true".to_string());
    verification_checks.push(format!("queue_output_only_success_tool={}", tool_name));
}

pub(super) fn maybe_complete_mail_reply(
    agent_state: &mut AgentState,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    let is_mail_reply_intent = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            resolved.intent_id == "mail.reply"
                || resolved
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "mail.reply")
        })
        .unwrap_or(false);
    let fallback_only_queue = remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state);
    if !tool_has_capability(tool_name, "mail.reply")
        || (!is_mail_reply_intent && !fallback_only_queue)
    {
        return;
    }
    if !has_success_condition(&agent_state.tool_execution_log, "mail.reply.completed") {
        return;
    }
    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }

    let summary = completion_summary_from_output(out.as_deref(), "Email request completed.");
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    log::info!(
        "Auto-completed mail reply after provider action for session {} tool={} fallback_only_queue={}.",
        hex::encode(&session_id[..4]),
        tool_name,
        fallback_only_queue
    );
}

pub(super) fn maybe_complete_chat_reply(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }

    let AgentTool::ChatReply { message } = tool_wrapper else {
        return;
    };

    if agent_state.pending_search_completion.is_some() {
        return;
    }

    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }

    let message = sanitize_product_handoff_internal_markers(&sanitize_direct_chat_reply_output(
        &enrich_command_scope_summary(message, agent_state),
    ));
    let composed = compose_terminal_chat_reply(&message);
    if product_handoff_blocks(
        agent_state,
        success,
        out,
        err,
        verification_checks,
        &composed.output,
        "queued_chat_reply",
    ) {
        return;
    }
    complete_with_summary(
        agent_state,
        composed.output.clone(),
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    verification_checks.push("terminal_chat_reply_ready=true".to_string());
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
        verification_checks.push(format!("response_composer_degradation_reason={}", reason));
    }
    log::info!(
        "Completed queued chat__reply flow for session {}.",
        hex::encode(&session_id[..4])
    );
}

fn is_toolcat_single_tool_probe(goal: &str) -> bool {
    goal.contains("TOOLCAT_SINGLE_TOOL") || goal.contains("toolcat_tool=")
}

fn toolcat_single_tool_target(goal: &str) -> Option<&str> {
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix("toolcat_tool="))
        .map(str::trim)
        .filter(|tool| !tool.is_empty())
}

pub(super) fn maybe_complete_toolcat_single_tool_probe(
    agent_state: &mut AgentState,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    if !is_toolcat_single_tool_probe(&agent_state.goal) {
        return;
    }
    if toolcat_single_tool_target(&agent_state.goal) != Some(tool_name) {
        return;
    }
    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }

    let summary = format!(
        "TOOLCAT_SINGLE_TOOL {} live IDE probe reached the post-tool final reply path.",
        tool_name
    );
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    verification_checks.push("toolcat_single_tool_queue_terminalized=true".to_string());
    verification_checks.push("terminal_chat_reply_ready=true".to_string());
    log::info!(
        "Auto-completed TOOLCAT_SINGLE_TOOL queue flow after {} for session {}.",
        tool_name,
        hex::encode(&session_id[..4])
    );
}

pub(super) fn maybe_complete_command_probe(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated
        || completion_summary.is_some()
        || !matches!(
            tool_wrapper,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        || !is_command_probe_intent(agent_state.resolved_intent.as_ref())
    {
        return;
    }
    let Some(raw) = out.as_deref() else {
        return;
    };
    if let Some(summary) = summarize_command_probe_output(tool_wrapper, raw) {
        if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
            return;
        }
        // Probe markers are deterministic completion signals even when the
        // underlying command exits non-zero (e.g. NOT_FOUND_IN_PATH).
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            false,
        );
        let intent_id = terminal_contract_intent_id(agent_state);
        agent_state
            .execution_ledger
            .record_terminal_success(intent_id);
        log::info!(
            "Auto-completed command probe after shell-command tool for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}

pub(super) fn maybe_complete_open_app(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    let AgentTool::OsLaunchApp { app_name } = tool_wrapper else {
        return;
    };
    if should_auto_complete_open_app_goal(
        &agent_state.goal,
        app_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    ) {
        if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
            return;
        }
        complete_with_summary(
            agent_state,
            format!("Opened {}.", app_name),
            success,
            out,
            err,
            completion_summary,
            false,
        );
        let intent_id = terminal_contract_intent_id(agent_state);
        agent_state
            .execution_ledger
            .record_terminal_success(intent_id);
        log::info!(
            "Auto-completed app-launch queue flow for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}

pub(super) fn maybe_complete_screenshot_capture(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    if !is_ui_capture_screenshot_intent(agent_state.resolved_intent.as_ref()) {
        return;
    }

    let screenshot_tool = matches!(tool_wrapper, AgentTool::Screen(ScreenAction::Screenshot));
    if !screenshot_tool {
        return;
    }

    let output = out.as_deref().unwrap_or_default();
    if !output.trim_start().starts_with("Screenshot captured") {
        return;
    }

    let summary = "Screenshot captured.".to_string();
    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    log::info!(
        "Auto-completed screenshot capture flow for session {}.",
        hex::encode(&session_id[..4])
    );
}

pub(super) fn maybe_complete_browser_snapshot_interaction(
    agent_state: &mut AgentState,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }

    let Some(completion) = browser_snapshot_completion(agent_state, tool_name, out.as_deref())
    else {
        return;
    };
    completion.append_contract_checks(verification_checks);
    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }

    complete_with_summary(
        agent_state,
        completion.summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    log::info!(
        "Auto-completed browser snapshot interaction for session {}.",
        hex::encode(&session_id[..4])
    );
}

pub(super) fn maybe_complete_agent_complete(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    rules: &ActionRules,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }

    let AgentTool::AgentComplete { result } = tool_wrapper else {
        return;
    };

    if completion_gate_blocks(agent_state, success, out, err, verification_checks, rules) {
        return;
    }

    let result = sanitize_product_handoff_internal_markers(&sanitize_direct_chat_reply_output(
        &enrich_command_scope_summary(result, agent_state),
    ));
    if product_handoff_blocks(
        agent_state,
        success,
        out,
        err,
        verification_checks,
        &result,
        "queued_agent_complete",
    ) {
        return;
    }

    complete_with_summary(
        agent_state,
        result,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    let intent_id = terminal_contract_intent_id(agent_state);
    agent_state
        .execution_ledger
        .record_terminal_success(intent_id);
    verification_checks.push("terminal_agent_complete_ready=true".to_string());
    log::info!(
        "Completed queued agent__complete flow for session {}.",
        hex::encode(&session_id[..4])
    );
}

#[cfg(test)]
#[path = "completion/tests.rs"]
mod tests;
