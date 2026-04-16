use super::events::{emit_completion_gate_status_event, emit_completion_gate_violation_events};
use super::*;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::step::action::execution_receipt_value;
use crate::agentic::runtime::service::step::action::support::action_fingerprint_execution_label;
use crate::agentic::runtime::service::step::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::runtime::service::step::intent_resolver::is_mail_reply_provider_tool;
use ioi_api::state::StateAccess;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(super) struct DuplicateExecutionContext<'a> {
    pub service: &'a RuntimeAgentService,
    pub state: &'a dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub tool: &'a AgentTool,
    pub matching_command_history_entry: Option<crate::agentic::runtime::types::CommandExecution>,
    pub command_scope: bool,
    pub action_fingerprint: &'a str,
    pub session_id: [u8; 32],
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub verification_checks: &'a mut Vec<String>,
}

pub(super) struct DuplicateExecutionOutcome {
    pub success: bool,
    pub error_msg: Option<String>,
    pub history_entry: Option<String>,
    pub action_output: Option<String>,
    pub terminal_chat_reply_output: Option<String>,
    pub is_lifecycle_action: bool,
}

pub(super) fn worker_duplicate_refresh_read_allowed(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
) -> bool {
    let Some(assignment) = load_worker_assignment(state, session_id).ok().flatten() else {
        return false;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }
    let AgentTool::FsRead { path } = tool else {
        return false;
    };
    let post_edit_verifier_rerun_due =
        focused_verifier_rerun_due_after_workspace_edit(agent_state, &assignment.goal).is_some();
    if post_edit_verifier_rerun_due {
        return false;
    }
    if refresh_read_ready_after_workspace_edit(agent_state, path) {
        return true;
    }
    if refresh_read_ready_after_patch_miss(agent_state, path) {
        return true;
    }
    if agent_state.command_history.is_empty() {
        return false;
    }

    matches!(
        latest_failure_class(agent_state),
        Some(FailureClass::UnexpectedState)
    )
}

fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn parse_receipt_path<'a>(value: &'a str) -> Option<&'a str> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("path="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

fn latest_workspace_read_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_read_observed").and_then(
        |value| {
            (parse_receipt_path(value)? == target_path)
                .then(|| parse_receipt_step(value))
                .flatten()
        },
    )
}

fn latest_workspace_patch_miss_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_receipt_value(
        &agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
    )
    .and_then(|value| {
        (parse_receipt_path(value)? == target_path)
            .then(|| parse_receipt_step(value))
            .flatten()
    })
}

fn refresh_read_ready_after_workspace_edit(agent_state: &AgentState, target_path: &str) -> bool {
    let Some(edit_step) = latest_workspace_edit_step(agent_state) else {
        return false;
    };
    latest_workspace_read_step(agent_state, target_path)
        .map(|read_step| edit_step > read_step)
        .unwrap_or(true)
}

fn refresh_read_ready_after_patch_miss(agent_state: &AgentState, target_path: &str) -> bool {
    let Some(patch_miss_step) = latest_workspace_patch_miss_step(agent_state, target_path) else {
        return false;
    };
    latest_workspace_read_step(agent_state, target_path)
        .map(|read_step| patch_miss_step > read_step)
        .unwrap_or(true)
}

fn latest_goal_command(agent_state: &AgentState, command_literal: &str) -> Option<(i32, u32)> {
    let target = normalize_whitespace(command_literal);
    agent_state.command_history.iter().rev().find_map(|entry| {
        let observed = normalize_whitespace(&entry.command);
        ((observed == target || observed.contains(&target)) && !entry.command.trim().is_empty())
            .then_some((entry.exit_code, entry.step_index))
    })
}

fn focused_verifier_rerun_due_after_workspace_edit(
    agent_state: &AgentState,
    goal: &str,
) -> Option<String> {
    let command = first_goal_command_literal(goal)?;
    let (exit_code, command_step) = latest_goal_command(agent_state, &command)?;
    if exit_code == 0 {
        return None;
    }

    let edit_step = latest_workspace_edit_step(agent_state)?;
    (edit_step > command_step).then_some(command)
}

pub(super) fn handle_duplicate_command_execution(
    ctx: DuplicateExecutionContext<'_>,
) -> DuplicateExecutionOutcome {
    let DuplicateExecutionContext {
        service,
        state,
        agent_state,
        rules,
        tool,
        matching_command_history_entry,
        command_scope,
        action_fingerprint,
        session_id,
        step_index,
        resolved_intent_id,
        verification_checks,
    } = ctx;

    let mut success = false;
    let mut error_msg = None;
    let mut history_entry: Option<String> = None;
    let action_output: Option<String>;
    let mut terminal_chat_reply_output = None;
    let mut is_lifecycle_action = false;
    let matching_command_history_entry = matching_command_history_entry.as_ref();
    let is_command_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );

    if let Some(summary) =
        duplicate_command_completion_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.execution_queue.clear();
            agent_state.pending_search_completion = None;
            verification_checks.push("duplicate_action_fingerprint_terminalized=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if let Some(summary) =
        duplicate_command_cached_success_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            if command_scope {
                let completion = duplicate_command_cached_completion_summary(
                    tool,
                    matching_command_history_entry,
                )
                .unwrap_or_else(|| summary.clone());
                let completion = enrich_command_scope_summary(&completion, agent_state);
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion.clone());
                agent_state.status = AgentStatus::Completed(Some(completion));
                is_lifecycle_action = true;
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else {
                action_output = Some(summary);
                agent_state.status = AgentStatus::Running;
            }
            verification_checks.push("duplicate_action_fingerprint_cached=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_cached_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if is_command_tool {
        let summary = duplicate_command_execution_summary(tool);
        let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
        error_msg = Some(duplicate_error.clone());
        history_entry = Some(summary);
        action_output = Some(duplicate_error);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
    } else {
        let tool_name = canonical_tool_identity(tool).0;
        let active_web_pipeline_chat_reply =
            is_active_web_pipeline_chat_reply_duplicate(&tool_name, agent_state);
        let prior_successful_duplicate =
            has_prior_successful_duplicate_action(agent_state, action_fingerprint);
        let worker_duplicate_requires_recovery_error =
            worker_duplicate_requires_recovery_error(state, session_id, tool);
        let noop_duplicate_allowed = is_duplicate_non_command_noop_allowed(
            &tool_name,
            prior_successful_duplicate,
            active_web_pipeline_chat_reply,
        ) && !worker_duplicate_requires_recovery_error;
        let mut summary = if active_web_pipeline_chat_reply {
            "Deferred final reply while web research continues gathering evidence.".to_string()
        } else if tool_name.eq_ignore_ascii_case("browser__inspect") {
            browser_snapshot_immediate_replay_summary()
        } else if prior_successful_duplicate {
            format!(
                "Skipped immediate replay of '{}' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state once or finish with the gathered evidence.",
                tool_name
            )
        } else {
            format!(
                "Skipped immediate replay of '{}' because the same action fingerprint was already executed on the previous step. This fingerprint is now cooled down at the current step; choose a different action or finish with the gathered evidence.",
                tool_name
            )
        };
        summary = worker_duplicate_noop_summary(state, agent_state, session_id, tool, summary);
        summary = workspace_duplicate_noop_summary(agent_state, tool, summary);
        let queued_browser_snapshot_verification = prior_successful_duplicate
            && tool.target() == ActionTarget::BrowserInteract
            && queue_browser_snapshot_verification(agent_state, session_id);
        if queued_browser_snapshot_verification {
            summary
                .push_str(" A browser__inspect verification step has been queued automatically.");
        }
        if worker_duplicate_requires_recovery_error {
            verification_checks
                .push("duplicate_action_fingerprint_worker_recovery_error=true".to_string());
        }
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            action_fingerprint,
            step_index,
            duplicate_skip_execution_label(prior_successful_duplicate, noop_duplicate_allowed),
        );
        if noop_duplicate_allowed {
            success = true;
            error_msg = None;
            if is_mail_reply_tool(&tool_name) {
                let completion = format!(
                    "Email send request already completed: {} Duplicate resend was skipped to avoid duplicate delivery.",
                    agent_state.goal.trim()
                );
                history_entry = Some(completion.clone());
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion.clone());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(completion));
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                verification_checks.push("duplicate_mail_reply_noop_terminalized=true".to_string());
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "duplicate_mail_reply_noop_completion",
                );
            } else if let Some(completion) = maybe_terminalize_duplicate_worker_noop(
                state,
                agent_state,
                rules,
                tool,
                session_id,
                verification_checks,
            ) {
                history_entry = Some(completion.clone());
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion);
                is_lifecycle_action = true;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "duplicate_repo_context_worker_completion",
                );
            } else {
                action_output = Some(summary.clone());
            }
            verification_checks
                .push("duplicate_action_fingerprint_non_command_noop=true".to_string());
            if prior_successful_duplicate {
                verification_checks
                    .push("duplicate_action_fingerprint_prior_success_noop=true".to_string());
            }
            if queued_browser_snapshot_verification {
                verification_checks.push(
                    "duplicate_action_fingerprint_queued_browser_snapshot_verification=true"
                        .to_string(),
                );
            }
            if active_web_pipeline_chat_reply {
                verification_checks
                    .push("terminal_chat_reply_deferred_for_active_web_pipeline=true".to_string());
                verification_checks.push("web_pipeline_active=true".to_string());
            }
        } else {
            let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
            success = false;
            error_msg = Some(duplicate_error.clone());
            action_output = Some(duplicate_error);
        }
        if history_entry.is_none() {
            history_entry = Some(summary.clone());
        }
        if !matches!(agent_state.status, AgentStatus::Completed(_)) {
            agent_state.status = AgentStatus::Running;
        }
        verification_checks
            .push("duplicate_action_fingerprint_non_command_skipped=true".to_string());
        verification_checks
            .push("duplicate_action_fingerprint_non_command_step_advanced=true".to_string());
    }
    verification_checks.push(format!(
        "duplicate_action_fingerprint={}",
        action_fingerprint
    ));
    verification_checks.push(format!(
        "duplicate_action_fingerprint_non_terminal={}",
        !success
    ));

    DuplicateExecutionOutcome {
        success,
        error_msg,
        history_entry,
        action_output,
        terminal_chat_reply_output,
        is_lifecycle_action,
    }
}

fn maybe_terminalize_duplicate_worker_noop(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    tool: &AgentTool,
    session_id: [u8; 32],
    verification_checks: &mut Vec<String>,
) -> Option<String> {
    if agent_state.parent_session_id.is_none() {
        return None;
    }

    let assignment = load_worker_assignment(state, session_id).ok().flatten()?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("repo_context_brief") {
        return None;
    }

    let missing_contract_markers =
        missing_execution_contract_markers_with_rules(agent_state, rules);
    if !missing_contract_markers.is_empty() {
        verification_checks.push(format!(
            "duplicate_worker_completion_missing_execution_contract_keys={}",
            missing_contract_markers.join(",")
        ));
        return None;
    }

    let completion = synthesize_repo_context_brief_from_duplicate(&assignment.goal, tool)?;
    agent_state.status = AgentStatus::Completed(Some(completion.clone()));
    agent_state.execution_queue.clear();
    agent_state.pending_search_completion = None;
    verification_checks.push("duplicate_repo_context_worker_terminalized=true".to_string());
    Some(completion)
}

fn first_goal_command_literal(goal: &str) -> Option<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    if let Some(command) = inherited_context
        .and_then(|text| {
            extract_worker_context_field(
                text,
                &[
                    "targeted_checks",
                    "targeted_check",
                    "verification_plan",
                    "verification",
                ],
            )
        })
        .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|value| looks_like_command_literal(value))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .find(|literal| looks_like_command_literal(literal))
}

fn worker_duplicate_requires_recovery_error(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    tool: &AgentTool,
) -> bool {
    let Some(assignment) = load_worker_assignment(state, session_id).ok().flatten() else {
        return false;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }

    matches!(
        tool,
        AgentTool::FsRead { .. } | AgentTool::FsList { .. } | AgentTool::FsStat { .. }
    )
}

fn worker_duplicate_noop_summary(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    default_summary: String,
) -> String {
    let Some(assignment) = load_worker_assignment(state, session_id).ok().flatten() else {
        return default_summary;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return default_summary;
    }

    match tool {
        AgentTool::FsRead { path } => {
            let target = Path::new(path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(path.as_str());
            let focused_command = first_goal_command_literal(&assignment.goal);
            let post_edit_focused_command =
                focused_verifier_rerun_due_after_workspace_edit(agent_state, &assignment.goal);
            let focused_command_ran = focused_command
                .as_deref()
                .map(|command| command_history_contains_goal_command(agent_state, command))
                .unwrap_or(false);
            let mut summary = format!(
                "Skipped immediate replay of 'file__read' because the likely patch file '{}' was already read successfully. Do not reread it.",
                target
            );
            if let Some(command) = post_edit_focused_command.as_deref() {
                summary.push_str(&format!(
                    " The edit already landed after a failing focused verification run. Your next action must be `shell__start` with the focused verification command `{}` before any reread or additional patching.",
                    command
                ));
            } else if let Some(command) =
                focused_command.as_deref().filter(|_| !focused_command_ran)
            {
                summary.push_str(&format!(
                    " Your next action must be `shell__start` with the focused verification command `{}` so the worker captures failing evidence before patching.",
                    command
                ));
                summary.push_str(
                    " After the command result lands, move to `file__edit`, `file__replace_line`, or `file__write`.",
                );
            } else {
                summary.push_str(
                    " Your next action must be `file__edit`, `file__replace_line`, or `file__write`.",
                );
                if let Some(command) = focused_command {
                    summary.push_str(&format!(
                        " The focused verification command `{}` already has command-history evidence; do not rerun it until after the edit is ready.",
                        command
                    ));
                } else {
                    summary.push_str(
                        " When the edit is ready, run the focused verification command with `shell__start`.",
                    );
                }
            }
            summary
        }
        AgentTool::FsList { path } | AgentTool::FsStat { path } => {
            let target = Path::new(path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(path.as_str());
            let next_file = first_goal_likely_file(&assignment.goal);
            let mut summary = format!(
                "Skipped immediate replay of '{}' because the repo-root probe '{}' already succeeded. Do not inspect the repo root again.",
                match tool {
                    AgentTool::FsList { .. } => "file__list",
                    _ => "file__info",
                },
                target
            );
            if let Some(file) = next_file {
                summary.push_str(&format!(" Read `{}` next with `file__read`.", file));
            } else {
                summary.push_str(" Read the most likely patch file next with `file__read`.");
            }
            if let Some(command) = first_goal_command_literal(&assignment.goal) {
                summary.push_str(&format!(
                    " When the edit is ready, run the focused verification command with `shell__start`: `{}`.",
                    command
                ));
            } else {
                summary.push_str(
                    " When the edit is ready, run the focused verification command with `shell__start`.",
                );
            }
            summary
        }
        _ => default_summary,
    }
}

fn workspace_duplicate_noop_summary(
    agent_state: &AgentState,
    tool: &AgentTool,
    default_summary: String,
) -> String {
    if agent_state.parent_session_id.is_some() {
        return default_summary;
    }
    if agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope)
        != Some(ioi_types::app::agentic::IntentScopeProfile::WorkspaceOps)
    {
        return default_summary;
    }

    match tool {
        AgentTool::FsRead { path } => {
            let target = Path::new(path)
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or(path.as_str());
            let mut summary = default_summary;
            if target.eq_ignore_ascii_case("package.json") {
                summary.push_str(
                    " If the answer is already present in this file, your next action must be `chat__reply` citing the relevant script entry instead of rereading `package.json`.",
                );
            } else {
                summary.push_str(
                    " If the answer is already present in this file, your next action must be `chat__reply` using the gathered evidence instead of rereading it.",
                );
            }
            summary
        }
        _ => default_summary,
    }
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn command_history_contains_goal_command(agent_state: &AgentState, command_literal: &str) -> bool {
    let target = normalize_whitespace(command_literal);
    agent_state.command_history.iter().any(|entry| {
        let observed = normalize_whitespace(&entry.command);
        observed == target || observed.contains(&target)
    })
}

fn collect_goal_literals(goal: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut delimiter: Option<char> = None;

    for ch in goal.chars() {
        if let Some(active) = delimiter {
            if ch == active {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    literals.push(trimmed.to_string());
                }
                current.clear();
                delimiter = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        if matches!(ch, '"' | '\'' | '`') {
            delimiter = Some(ch);
        }
    }

    literals
}

fn split_parent_playbook_context(goal: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = goal.split_once("[PARENT PLAYBOOK CONTEXT]") {
        (head.trim(), Some(tail.trim()))
    } else {
        (goal.trim(), None)
    }
}

fn normalize_worker_context_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn extract_worker_context_field(text: &str, keys: &[&str]) -> Option<String> {
    let normalized_keys = keys
        .iter()
        .map(|key| normalize_worker_context_key(key))
        .collect::<Vec<_>>();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        if normalized_keys
            .iter()
            .any(|candidate| *candidate == normalize_worker_context_key(key))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn first_goal_likely_file(goal: &str) -> Option<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    let value =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))?;
    value
        .split(';')
        .map(str::trim)
        .map(|item| item.trim_matches('`'))
        .find(|item| !item.is_empty() && !item.to_ascii_lowercase().starts_with("repo root:"))
        .map(str::to_string)
}

fn normalize_goal_path_candidate(candidate: &str) -> Option<PathBuf> {
    let trimmed = candidate
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';' | ')'));
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.is_dir() {
        Some(path)
    } else {
        path.parent().map(Path::to_path_buf)
    }
}

fn repo_root_from_duplicate_tool(goal: &str, tool: &AgentTool) -> Option<PathBuf> {
    let tool_path = match tool {
        AgentTool::FsStat { path }
        | AgentTool::FsList { path }
        | AgentTool::FsRead { path }
        | AgentTool::FsSearch { path, .. } => Some(path.as_str()),
        _ => None,
    };

    if let Some(path) = tool_path.and_then(normalize_goal_path_candidate) {
        return Some(path);
    }

    collect_goal_literals(goal)
        .into_iter()
        .find_map(|candidate| normalize_goal_path_candidate(&candidate))
}

fn looks_like_command_literal(literal: &str) -> bool {
    let trimmed = literal.trim();
    if trimmed.is_empty() || !trimmed.contains(' ') {
        return false;
    }

    let first = trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-');
    matches!(
        first,
        "python"
            | "python3"
            | "pytest"
            | "cargo"
            | "npm"
            | "pnpm"
            | "yarn"
            | "node"
            | "uv"
            | "go"
            | "bash"
            | "sh"
            | "make"
            | "just"
    )
}

fn looks_like_file_hint(literal: &str) -> bool {
    let trimmed = literal.trim();
    if trimmed.is_empty() || trimmed.contains('\n') {
        return false;
    }
    if looks_like_command_literal(trimmed) {
        return false;
    }

    trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed
            .rsplit_once('.')
            .map(|(_, ext)| !ext.is_empty() && ext.chars().all(|ch| ch.is_ascii_alphanumeric()))
            .unwrap_or(false)
}

fn repo_relative_display(root: &Path, candidate: &Path) -> Option<String> {
    let display = candidate
        .strip_prefix(root)
        .ok()
        .unwrap_or(candidate)
        .to_string_lossy()
        .replace('\\', "/");
    let trimmed = display.trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_goal_file_hints(repo_root: &Path, goal: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for literal in collect_goal_literals(goal) {
        if !looks_like_file_hint(&literal) {
            continue;
        }

        let candidate = PathBuf::from(literal.trim());
        let resolved = if candidate.is_absolute() {
            Some(candidate)
        } else {
            Some(repo_root.join(&candidate))
        };
        let Some(resolved) = resolved.filter(|path| path.exists() && path.is_file()) else {
            continue;
        };
        let Some(display) = repo_relative_display(repo_root, &resolved) else {
            continue;
        };
        if seen.insert(display.clone()) {
            out.push(display);
        }
    }

    out
}

fn fallback_repo_files(repo_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for relative in ["README.md", "src", "tests"] {
        let path = repo_root.join(relative);
        if !path.exists() {
            continue;
        }
        if path.is_file() {
            let display = relative.replace('\\', "/");
            if seen.insert(display.clone()) {
                out.push(display);
            }
            continue;
        }

        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if !entry_path.is_file() {
                continue;
            }
            let Some(display) = repo_relative_display(repo_root, &entry_path) else {
                continue;
            };
            if seen.insert(display.clone()) {
                out.push(display);
            }
            if out.len() >= 4 {
                return out;
            }
        }
    }

    out
}

fn extract_goal_commands(goal: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for literal in collect_goal_literals(goal) {
        if !looks_like_command_literal(&literal) {
            continue;
        }
        let normalized = literal.trim().to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }

    out
}

fn synthesize_repo_context_brief_from_duplicate(goal: &str, tool: &AgentTool) -> Option<String> {
    let repo_root = repo_root_from_duplicate_tool(goal, tool)?;
    let mut likely_files = extract_goal_file_hints(&repo_root, goal);
    if likely_files.is_empty() {
        likely_files = fallback_repo_files(&repo_root);
    }

    let targeted_checks = extract_goal_commands(goal);
    let open_question = if goal.to_ascii_lowercase().contains("widen only if needed") {
        "Widen only if the focused verification command fails or produces contradictory evidence."
            .to_string()
    } else if likely_files.is_empty() {
        "Confirm the exact patch surface if the repo contains more than one plausible candidate."
            .to_string()
    } else {
        "Confirm hidden postconditions once the focused verification passes.".to_string()
    };

    let likely_files_text = if likely_files.is_empty() {
        format!("repo root: {}", repo_root.to_string_lossy())
    } else {
        likely_files.join("; ")
    };
    let targeted_checks_text = if targeted_checks.is_empty() {
        "No explicit focused command was quoted; verify the smallest named test or probe first."
            .to_string()
    } else {
        targeted_checks.join("; ")
    };

    Some(format!(
        "- likely_files: {}\n- selected_skills: reuse parent-selected coding prep cues; no extra child-local skills were added during fallback.\n- targeted_checks: {}\n- open_questions: {}",
        likely_files_text, targeted_checks_text, open_question
    ))
}

fn is_non_command_duplicate_noop_tool(tool_name: &str) -> bool {
    is_read_only_filesystem_tool(tool_name)
        || is_mail_read_latest_tool(tool_name)
        || is_mail_reply_tool(tool_name)
        || crate::agentic::runtime::connectors::google_workspace::is_google_duplicate_safe_tool_name(
            tool_name,
        )
}

fn is_active_web_pipeline_chat_reply_duplicate(tool_name: &str, agent_state: &AgentState) -> bool {
    tool_name == "chat__reply" && agent_state.pending_search_completion.is_some()
}

fn browser_snapshot_immediate_replay_summary() -> String {
    "Immediate replay of `browser__inspect` is not a valid next step. Do not call `browser__inspect` again yet. Use a different browser action or act on the visible control already named in `RECENT PENDING BROWSER STATE`; if the page still needs time to change, use `browser__wait` before snapshot.".to_string()
}

fn is_duplicate_non_command_noop_allowed(
    tool_name: &str,
    prior_successful_duplicate: bool,
    active_web_pipeline_chat_reply: bool,
) -> bool {
    if active_web_pipeline_chat_reply {
        return true;
    }

    if tool_name.eq_ignore_ascii_case("browser__inspect") {
        return false;
    }

    prior_successful_duplicate || is_non_command_duplicate_noop_tool(tool_name)
}

fn duplicate_skip_execution_label(
    prior_successful_duplicate: bool,
    noop_duplicate_allowed: bool,
) -> &'static str {
    if prior_successful_duplicate && noop_duplicate_allowed {
        "success_duplicate_skip"
    } else {
        "duplicate_skip"
    }
}

fn has_prior_successful_duplicate_action(
    agent_state: &AgentState,
    action_fingerprint: &str,
) -> bool {
    if action_fingerprint.trim().is_empty() {
        return false;
    }

    action_fingerprint_execution_label(&agent_state.tool_execution_log, action_fingerprint)
        .as_deref()
        .map(|label| label.starts_with("success"))
        .unwrap_or(false)
}

fn queue_browser_snapshot_verification(agent_state: &mut AgentState, session_id: [u8; 32]) -> bool {
    let request = ActionRequest {
        target: ActionTarget::BrowserInspect,
        params: match serde_jcs::to_vec(&json!({})) {
            Ok(params) => params,
            Err(_) => return false,
        },
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
        return false;
    }

    agent_state.execution_queue.insert(0, request);
    true
}

fn is_read_only_filesystem_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "file__list" | "file__read" | "file__info" | "file__search"
    )
}

fn is_mail_read_latest_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "wallet_network__mail_read_latest" | "wallet_mail_read_latest" | "mail__read_latest"
    )
}

fn is_mail_reply_tool(tool_name: &str) -> bool {
    is_mail_reply_provider_tool(tool_name)
}

#[cfg(test)]
mod tests {
    use super::{
        duplicate_skip_execution_label, has_prior_successful_duplicate_action,
        is_active_web_pipeline_chat_reply_duplicate, is_duplicate_non_command_noop_allowed,
        is_mail_read_latest_tool, is_mail_reply_tool, is_non_command_duplicate_noop_tool,
        is_read_only_filesystem_tool, maybe_terminalize_duplicate_worker_noop,
        queue_browser_snapshot_verification, synthesize_repo_context_brief_from_duplicate,
        worker_duplicate_noop_summary, worker_duplicate_refresh_read_allowed,
        worker_duplicate_requires_recovery_error, workspace_duplicate_noop_summary,
    };
    use crate::agentic::runtime::service::lifecycle::persist_worker_assignment;
    use crate::agentic::runtime::service::step::action::{
        mark_action_fingerprint_executed_at_step, mark_execution_receipt_with_value,
    };
    use crate::agentic::runtime::service::step::helpers::default_safe_policy;
    use crate::agentic::runtime::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier,
        PendingSearchCompletion, WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
    };
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::AgentTool;
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
    use ioi_types::app::ActionTarget;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    #[test]
    fn read_only_filesystem_tools_are_noop_safe() {
        assert!(is_read_only_filesystem_tool("file__list"));
        assert!(is_read_only_filesystem_tool("file__read"));
        assert!(is_read_only_filesystem_tool("file__info"));
        assert!(is_read_only_filesystem_tool("file__search"));
        assert!(!is_read_only_filesystem_tool("file__move"));
    }

    #[test]
    fn noop_allowlist_includes_read_only_filesystem_tools() {
        assert!(is_non_command_duplicate_noop_tool("file__list"));
        assert!(is_non_command_duplicate_noop_tool("mail__read_latest"));
        assert!(is_non_command_duplicate_noop_tool("mail__reply"));
        assert!(!is_non_command_duplicate_noop_tool("file__create_dir"));
    }

    #[test]
    fn active_web_pipeline_chat_reply_duplicates_are_noop_safe() {
        let mut agent_state = test_agent_state();
        agent_state.pending_search_completion = Some(PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: None,
            url: String::new(),
            started_step: 0,
            started_at_ms: 0,
            deadline_ms: 0,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: Vec::new(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources: 2,
        });

        assert!(is_active_web_pipeline_chat_reply_duplicate(
            "chat__reply",
            &agent_state
        ));
        assert!(!is_active_web_pipeline_chat_reply_duplicate(
            "file__read",
            &agent_state
        ));
    }

    #[test]
    fn workspace_package_read_duplicate_summary_requires_chat_reply() {
        let mut agent_state = test_agent_state();
        agent_state.resolved_intent = Some(ResolvedIntentState {
            intent_id: "workspace.lookup".to_string(),
            scope: IntentScopeProfile::WorkspaceOps,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        });

        let summary = workspace_duplicate_noop_summary(
            &agent_state,
            &AgentTool::FsRead {
                path: "./package.json".to_string(),
            },
            "Skipped immediate replay of 'file__read'.".to_string(),
        );

        assert!(summary.contains("chat__reply"));
        assert!(summary.contains("package.json"));
    }

    #[test]
    fn mail_tool_duplicate_helpers_match_expected_tools() {
        assert!(is_mail_read_latest_tool("wallet_network__mail_read_latest"));
        assert!(is_mail_reply_tool("wallet_network__mail_reply"));
        assert!(is_mail_reply_tool("mail__reply"));
        assert!(is_mail_reply_tool("connector__google__gmail_send_email"));
        assert!(is_mail_reply_tool("connector__google__gmail_draft_email"));
        assert!(!is_mail_reply_tool("wallet_network__mail_read_latest"));
    }

    #[test]
    fn prior_successful_duplicate_action_is_detected() {
        let mut agent_state = test_agent_state();
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            "fp",
            3,
            "success",
        );
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            "fp-noop",
            4,
            "success_duplicate_skip",
        );

        assert!(has_prior_successful_duplicate_action(&agent_state, "fp"));
        assert!(has_prior_successful_duplicate_action(
            &agent_state,
            "fp-noop"
        ));
        assert!(!has_prior_successful_duplicate_action(
            &agent_state,
            "missing"
        ));
    }

    #[test]
    fn browser_snapshot_verification_is_queued_once() {
        let mut agent_state = test_agent_state();

        assert!(queue_browser_snapshot_verification(
            &mut agent_state,
            [7u8; 32]
        ));
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert_eq!(
            agent_state.execution_queue[0].target,
            ActionTarget::BrowserInspect
        );
        assert!(!queue_browser_snapshot_verification(
            &mut agent_state,
            [7u8; 32]
        ));
        assert_eq!(agent_state.execution_queue.len(), 1);
    }

    #[test]
    fn browser_snapshot_duplicate_is_not_noop_safe_after_prior_success() {
        assert!(!is_duplicate_non_command_noop_allowed(
            "browser__inspect",
            true,
            false
        ));
        assert_eq!(
            duplicate_skip_execution_label(true, false),
            "duplicate_skip"
        );
    }

    #[test]
    fn synthesized_repo_context_brief_uses_goal_files_and_targeted_command() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        let tests_dir = repo_root.join("tests");
        std::fs::create_dir_all(&tests_dir).expect("tests dir should exist");
        std::fs::write(
            repo_root.join("path_utils.py"),
            "def normalize_fixture_path():\n    pass\n",
        )
        .expect("source file should exist");
        std::fs::write(
            tests_dir.join("test_path_utils.py"),
            "def test_normalize_fixture_path():\n    pass\n",
        )
        .expect("test file should exist");

        let goal = format!(
            "Inspect repo context for the patch in \"{}\". Patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and run `python3 -m unittest tests.test_path_utils -v` first.",
            repo_root.display()
        );
        let tool = AgentTool::FsStat {
            path: repo_root.to_string_lossy().to_string(),
        };

        let summary = synthesize_repo_context_brief_from_duplicate(&goal, &tool)
            .expect("repo context brief should synthesize");
        assert!(summary.contains("path_utils.py"));
        assert!(summary.contains("tests/test_path_utils.py"));
        assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
    }

    #[test]
    fn duplicate_repo_context_worker_noop_terminalizes_with_fallback_brief() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        let tests_dir = repo_root.join("tests");
        std::fs::create_dir_all(&tests_dir).expect("tests dir should exist");
        std::fs::write(
            repo_root.join("path_utils.py"),
            "def normalize_fixture_path():\n    pass\n",
        )
        .expect("source file should exist");
        std::fs::write(
            tests_dir.join("test_path_utils.py"),
            "def test_normalize_fixture_path():\n    pass\n",
        )
        .expect("test file should exist");

        let session_id = [7u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:repo".to_string(),
            budget: 24,
            goal: format!(
                "Inspect repo context for the patch in \"{}\". Patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and run `python3 -m unittest tests.test_path_utils -v` first.",
                repo_root.display()
            ),
            success_criteria: "Return a deterministic repo context brief.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("context_worker".to_string()),
            workflow_id: Some("repo_context_brief".to_string()),
            role: Some("Context Worker".to_string()),
            allowed_tools: vec![
                "file__info".to_string(),
                "file__search".to_string(),
                "file__read".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a deterministic repo context brief.".to_string(),
                expected_output: "Repo context brief.".to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.session_id = session_id;
        agent_state.parent_session_id = Some([9u8; 32]);
        let mut verification_checks = Vec::new();
        let tool = AgentTool::FsStat {
            path: repo_root.to_string_lossy().to_string(),
        };

        let completion = maybe_terminalize_duplicate_worker_noop(
            &state,
            &mut agent_state,
            &default_safe_policy(),
            &tool,
            session_id,
            &mut verification_checks,
        )
        .expect("duplicate repo-context noop should terminalize");

        assert!(matches!(agent_state.status, AgentStatus::Completed(_)));
        assert!(completion.contains("path_utils.py"));
        assert!(completion.contains("tests/test_path_utils.py"));
        assert!(verification_checks
            .iter()
            .any(|check| check == "duplicate_repo_context_worker_terminalized=true"));
    }

    #[test]
    fn patch_build_verify_duplicate_read_guidance_runs_focused_verifier_before_patch() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [8u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` first.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let summary = worker_duplicate_noop_summary(
            &state,
            &test_agent_state(),
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            },
            "fallback".to_string(),
        );

        assert!(summary.contains("path_utils.py"));
        assert!(summary.contains("before patching"));
        assert!(summary.contains("shell__start"));
        assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
        assert!(summary.contains("file__edit"));
        assert!(summary.contains("file__edit"));
        assert!(summary.contains("file__replace_line"));
    }

    #[test]
    fn patch_build_verify_duplicate_read_requires_recovery_error() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [9u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        assert!(worker_duplicate_requires_recovery_error(
            &state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
        assert!(worker_duplicate_requires_recovery_error(
            &state,
            session_id,
            &AgentTool::FsList {
                path: repo_root.to_string_lossy().to_string(),
            }
        ));
        assert!(!worker_duplicate_requires_recovery_error(
            &state,
            session_id,
            &AgentTool::FsPatch {
                path: source_path.to_string_lossy().to_string(),
                search: "before".to_string(),
                replace: "after".to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_stays_blocked_before_command_history() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [11u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];

        assert!(!worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_is_allowed_after_command_history_unexpected_state() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [12u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec![
            "attempt::NoEffectAfterAction::first".to_string(),
            "attempt::UnexpectedState::second".to_string(),
        ];
        agent_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 0,
        });

        assert!(worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_is_allowed_after_workspace_edit_receipt() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [0x6d; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\", patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and rerun `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display(),
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_edit_applied",
            format!("step=7;tool=file__write;path={}", source_path.display()),
        );
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            format!("step=3;tool=file__read;path={}", source_path.display()),
        );

        assert!(worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_is_allowed_after_patch_miss_receipt() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [0x70; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display(),
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_patch_miss_observed",
            format!(
                "step=7;tool=file__edit;path={};reason=search_block_not_found",
                source_path.display()
            ),
        );
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            format!("step=3;tool=file__read;path={}", source_path.display()),
        );

        assert!(worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_stays_blocked_after_post_edit_refresh_read() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [0x6e; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display(),
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_edit_applied",
            format!("step=7;tool=file__write;path={}", source_path.display()),
        );
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            format!("step=8;tool=file__read;path={}", source_path.display()),
        );

        assert!(!worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_refresh_read_stays_blocked_when_post_edit_verifier_rerun_is_due() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [0x72; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\", preserve the fixture behavior, and rerun the focused verification command `python3 -m unittest tests.test_path_utils -v` after the edit.",
                repo_root.display(),
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec!["attempt::UnexpectedState::first".to_string()];
        agent_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 4,
        });
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_edit_applied",
            format!("step=7;tool=file__write;path={}", source_path.display()),
        );
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            format!("step=3;tool=file__read;path={}", source_path.display()),
        );

        assert!(!worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));

        let summary = worker_duplicate_noop_summary(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            },
            "fallback".to_string(),
        );
        assert!(
            summary.contains("The edit already landed after a failing focused verification run.")
        );
        assert!(summary.contains("shell__start"));
        assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
    }

    #[test]
    fn patch_build_verify_refresh_read_stays_blocked_after_patch_miss_refresh_read() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        let source_path = repo_root.join("path_utils.py");
        std::fs::write(&source_path, "def normalize_fixture_path():\n    pass\n")
            .expect("source file should exist");

        let session_id = [0x71; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and rerun the focused verification command after the edit.",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let mut agent_state = test_agent_state();
        agent_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_patch_miss_observed",
            format!(
                "step=7;tool=file__edit;path={};reason=search_block_not_found",
                source_path.display()
            ),
        );
        mark_execution_receipt_with_value(
            &mut agent_state.tool_execution_log,
            "workspace_read_observed",
            format!("step=8;tool=file__read;path={}", source_path.display()),
        );

        assert!(!worker_duplicate_refresh_read_allowed(
            &state,
            &agent_state,
            session_id,
            &AgentTool::FsRead {
                path: source_path.to_string_lossy().to_string(),
            }
        ));
    }

    #[test]
    fn patch_build_verify_duplicate_root_probe_guidance_points_to_direct_file_read() {
        let temp = tempdir().expect("tempdir should exist");
        let repo_root = temp.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(&repo_root).expect("repo root should exist");
        std::fs::write(
            repo_root.join("path_utils.py"),
            "def normalize_fixture_path():\n    pass\n",
        )
        .expect("source file should exist");

        let session_id = [10u8; 32];
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let assignment = WorkerAssignment {
            step_key: "delegate:0:patch".to_string(),
            budget: 48,
            goal: format!(
                "Implement the parity fix in \"{}\" and run `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py",
                repo_root.display()
            ),
            success_criteria: "Return a bounded implementation handoff.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(session_id),
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__list".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        };
        persist_worker_assignment(&mut state, session_id, &assignment)
            .expect("worker assignment should persist");

        let summary = worker_duplicate_noop_summary(
            &state,
            &test_agent_state(),
            session_id,
            &AgentTool::FsList {
                path: repo_root.to_string_lossy().to_string(),
            },
            "fallback".to_string(),
        );

        assert!(summary.contains("repo-root probe"));
        assert!(summary.contains("path_utils.py"));
        assert!(summary.contains("file__read"));
        assert!(summary.contains("shell__start"));
        assert!(summary.contains("python3 -m unittest tests.test_path_utils -v"));
    }
}
