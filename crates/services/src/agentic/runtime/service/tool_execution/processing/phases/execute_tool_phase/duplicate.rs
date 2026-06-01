use super::events::{emit_completion_gate_status_event, emit_completion_gate_violation_events};
use super::*;
use crate::agentic::runtime::service::decision_loop::intent_resolver::is_mail_reply_provider_tool;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::recovery::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::runtime::service::tool_execution::execution_evidence_value;
use crate::agentic::runtime::service::tool_execution::support::action_fingerprint_execution_label;
use ioi_api::state::StateAccess;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use serde_json::json;
use std::path::Path;

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

pub(super) fn duplicate_refresh_read_allowed(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
) -> bool {
    if root_workspace_duplicate_refresh_read_allowed(agent_state, tool) {
        return true;
    }

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

fn root_workspace_duplicate_refresh_read_allowed(
    agent_state: &AgentState,
    tool: &AgentTool,
) -> bool {
    agent_state.parent_session_id.is_none()
        && matches!(tool, AgentTool::FsRead { .. })
        && goal_suggests_workspace_edit_and_verification(&agent_state.goal)
        && agent_state.last_action_type.as_deref() == Some("file__edit")
        && matches!(
            latest_failure_class(agent_state),
            Some(FailureClass::NoEffectAfterAction)
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
        if prior_successful_duplicate {
            verification_checks.push("duplicate_action_fingerprint_prior_success=true".to_string());
        }
        let worker_duplicate_requires_recovery_error =
            worker_duplicate_requires_recovery_error(state, session_id, tool);
        let command_workspace_read_requires_action_change =
            command_workspace_read_duplicate_requires_action_change(
                agent_state,
                tool,
                prior_successful_duplicate,
            );
        let noop_duplicate_allowed = is_duplicate_non_command_noop_allowed(
            &tool_name,
            prior_successful_duplicate,
            active_web_pipeline_chat_reply,
        ) && !worker_duplicate_requires_recovery_error
            && !command_workspace_read_requires_action_change;
        if command_workspace_read_requires_action_change {
            verification_checks
                .push("duplicate_command_workspace_read_requires_action_change=true".to_string());
        }
        let mut summary = if active_web_pipeline_chat_reply {
            concat!(
                "Rejected duplicate final reply while web research continues. ",
                "Do not repeat the same answer. Rewrite from the typed web__read results, ",
                "preserving observed prices, market caps, 24h volumes, and percentage changes ",
                "for each compared asset when those fields are present."
            )
            .to_string()
        } else if tool_name.eq_ignore_ascii_case("browser__inspect") {
            browser_snapshot_immediate_replay_summary()
        } else if prior_successful_duplicate {
            format!(
                "Skipped immediate replay of '{}' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state or choose a different action.",
                tool_name
            )
        } else {
            format!(
                "Skipped immediate replay of '{}' because the same action fingerprint was already executed on the previous step. This fingerprint is now cooled down at the current step; choose a different action or verify the updated state.",
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
        let duplicate_label = if active_web_pipeline_chat_reply {
            "web_chat_reply_deferred"
        } else {
            duplicate_skip_execution_label(prior_successful_duplicate, noop_duplicate_allowed)
        };
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            action_fingerprint,
            step_index,
            duplicate_label,
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
                action_output = if active_web_pipeline_chat_reply {
                    Some(String::new())
                } else {
                    Some(summary.clone())
                };
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
                verification_checks
                    .push("web_model_chat_reply_duplicate_suppressed=true".to_string());
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

    let _ = tool;
    verification_checks.push("duplicate_repo_context_worker_requires_model_reply=true".to_string());
    verification_checks.push("terminal_chat_reply_ready=false".to_string());
    None
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

fn goal_suggests_workspace_edit_and_verification(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    let wants_change = [
        "fix", "edit", "change", "update", "modify", "repair", "patch",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let has_workspace_target = [
        "src/",
        "test",
        "tests/",
        ".js",
        ".mjs",
        ".ts",
        ".tsx",
        ".rs",
        ".py",
        ".json",
        ".md",
        "file",
        "repo",
        "workspace",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let has_verification = first_goal_command_literal(goal).is_some()
        || [
            "run test",
            "run the test",
            "run tests",
            "verify",
            "verification",
            "node --test",
            "npm test",
            "cargo test",
            "pytest",
        ]
        .iter()
        .any(|needle| lower.contains(needle));

    wants_change && has_workspace_target && has_verification
}

fn command_workspace_read_duplicate_requires_action_change(
    agent_state: &AgentState,
    tool: &AgentTool,
    _prior_successful_duplicate: bool,
) -> bool {
    agent_state.parent_session_id.is_none()
        && matches!(tool, AgentTool::FsRead { .. })
        && goal_suggests_workspace_edit_and_verification(&agent_state.goal)
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
                    " After the command result lands, move to `file__edit` or `file__write`.",
                );
            } else {
                summary.push_str(" Your next action must be `file__edit` or `file__write`.");
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
    let resolved_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope);
    let command_workspace = agent_state
        .resolved_intent
        .as_ref()
        .is_some_and(|resolved| {
            matches!(
                resolved.scope,
                ioi_types::app::agentic::IntentScopeProfile::CommandExecution
            ) && resolved
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "command.exec")
                && resolved.required_capabilities.iter().any(|capability| {
                    matches!(
                        capability.as_str(),
                        "filesystem.read" | "filesystem.write" | "filesystem.metadata"
                    )
                })
        });
    let goal_command_workspace = goal_suggests_workspace_edit_and_verification(&agent_state.goal);
    if resolved_scope != Some(ioi_types::app::agentic::IntentScopeProfile::WorkspaceOps)
        && !command_workspace
        && !goal_command_workspace
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
            if command_workspace || goal_command_workspace {
                summary.push_str(&format!(
                    " `{}` is already in context. Choose `file__edit`, `file__write`, or `file__multi_edit` for the requested change instead of rereading it.",
                    target
                ));
                if let Some(command) = first_goal_command_literal(&agent_state.goal) {
                    summary.push_str(&format!(
                        " After editing, run the focused verification command with `shell__run`: `{}`.",
                        command
                    ));
                } else {
                    summary.push_str(
                        " After editing, run the focused verification command with `shell__run`.",
                    );
                }
            } else if target.eq_ignore_ascii_case("package.json") {
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
