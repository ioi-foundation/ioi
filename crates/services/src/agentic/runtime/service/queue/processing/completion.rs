use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::decision_loop::helpers::should_auto_complete_open_app_goal;
use crate::agentic::runtime::service::decision_loop::intent_resolver::tool_has_capability;
use crate::agentic::runtime::service::tool_execution::command_contract::{
    compose_terminal_chat_reply, enrich_command_scope_summary, evaluate_completion_requirements,
    execution_contract_violation_error,
};
use crate::agentic::runtime::service::tool_execution::{
    has_success_condition, is_command_probe_intent, is_ui_capture_screenshot_intent,
    summarize_command_probe_output,
};
use crate::agentic::runtime::service::visual_loop::browser_completion::browser_snapshot_completion;
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
    let intent_id = terminal_contract_intent_id(agent_state);
    let missing_completion_evidence = evaluate_completion_requirements(
        agent_state,
        intent_id.as_deref().unwrap_or_default(),
        verification_checks,
        rules,
    );
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

    let message = enrich_command_scope_summary(message, agent_state);
    let composed = compose_terminal_chat_reply(&message);
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
    verification_checks.push("browser_snapshot_success_criteria_auto_completed=true".to_string());
    verification_checks.push(format!(
        "browser_snapshot_success_criteria_count={}",
        completion.matched_success_criteria.len()
    ));
    verification_checks.push(format!(
        "browser_snapshot_success_criteria={}",
        completion.matched_success_criteria.join(",")
    ));
    verification_checks.push("terminal_chat_reply_ready=true".to_string());
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

    complete_with_summary(
        agent_state,
        result.clone(),
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
