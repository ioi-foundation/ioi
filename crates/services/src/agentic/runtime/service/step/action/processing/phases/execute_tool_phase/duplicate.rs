use super::events::{emit_completion_gate_status_event, emit_completion_gate_violation_events};
use super::*;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::step::action::execution_evidence_value;
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
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

fn latest_workspace_read_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_read_observed").and_then(
        |value| {
            (parse_receipt_path(value)? == target_path)
                .then(|| parse_receipt_step(value))
                .flatten()
        },
    )
}

fn latest_workspace_patch_miss_step(agent_state: &AgentState, target_path: &str) -> Option<u32> {
    execution_evidence_value(
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
        let missing_completion_evidence = evaluate_completion_requirements(
            agent_state,
            resolved_intent_id,
            verification_checks,
            rules,
        );
        if missing_completion_evidence.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state
                .execution_ledger
                .record_terminal_success(Some(resolved_intent_id.to_string()));
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
            let missing = missing_completion_evidence.join(",");
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
        let missing_completion_evidence = evaluate_completion_requirements(
            agent_state,
            resolved_intent_id,
            verification_checks,
            rules,
        );
        if missing_completion_evidence.is_empty() {
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
                agent_state
                    .execution_ledger
                    .record_terminal_success(Some(resolved_intent_id.to_string()));
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
            let missing = missing_completion_evidence.join(",");
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

    let resolved_intent_id = resolved_intent_id(agent_state);
    let missing_completion_evidence = evaluate_completion_requirements(
        agent_state,
        resolved_intent_id.as_str(),
        verification_checks,
        rules,
    );
    if !missing_completion_evidence.is_empty() {
        verification_checks.push(format!(
            "duplicate_worker_completion_missing_execution_contract_keys={}",
            missing_completion_evidence.join(",")
        ));
        return None;
    }

    let completion = synthesize_repo_context_brief_from_duplicate(&assignment.goal, tool)?;
    agent_state.status = AgentStatus::Completed(Some(completion.clone()));
    agent_state
        .execution_ledger
        .record_terminal_success(Some(resolved_intent_id));
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
        "Confirm hidden success_conditions once the focused verification passes.".to_string()
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
#[path = "duplicate/tests.rs"]
mod tests;
