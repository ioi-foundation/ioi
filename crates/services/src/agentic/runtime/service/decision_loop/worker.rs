use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::get_state_key;
use crate::agentic::runtime::middleware::canonical_deterministic_tool_name;
use crate::agentic::runtime::service::lifecycle::load_worker_assignment;
use crate::agentic::runtime::service::recovery::anti_loop::{latest_failure_class, FailureClass};
use crate::agentic::runtime::service::tool_execution::execution_evidence_value;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus, WorkerAssignment};
use crate::agentic::runtime::utils::persist_agent_state;
use crate::agentic::runtime::worker_context::{
    collect_goal_literals, extract_worker_context_field, looks_like_command_literal,
    normalize_whitespace, split_parent_playbook_context,
};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct WorkerExecutionResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub attempts: u8,
}

pub(crate) fn worker_assignment_allows_tool_name(
    assignment: Option<&WorkerAssignment>,
    tool_name: &str,
) -> bool {
    if tool_name == "agent__escalate" {
        return true;
    }
    assignment
        .map(|assignment| {
            assignment.allowed_tools.is_empty()
                || assignment
                    .allowed_tools
                    .iter()
                    .any(|allowed| worker_assignment_tool_names_match(allowed, tool_name))
        })
        .unwrap_or(true)
}

fn worker_assignment_tool_names_match(allowed: &str, candidate: &str) -> bool {
    if allowed == candidate {
        return true;
    }

    if worker_assignment_tool_alias(allowed) == worker_assignment_tool_alias(candidate) {
        return true;
    }

    match (
        canonical_deterministic_tool_name(allowed),
        canonical_deterministic_tool_name(candidate),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn worker_assignment_tool_alias(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "filesystem__write_file" | "file__write" => "file__write".to_string(),
        "filesystem__patch" | "file__edit" => "file__edit".to_string(),
        "filesystem__read_file" | "file__read" | "file__view" => "file__read".to_string(),
        "filesystem__search" | "file__search" => "file__search".to_string(),
        "filesystem__list_directory" | "filesystem__list_dir" | "file__list" => {
            "file__list".to_string()
        }
        "filesystem__stat" | "file__info" => "file__info".to_string(),
        "sys__exec_session" | "shell__run" => "shell__run".to_string(),
        "system__fail" | "agent__escalate" => "agent__escalate".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn worker_assignment_disallowed_tool_error(
    assignment: &WorkerAssignment,
    tool_name: &str,
) -> String {
    format!(
        "ERROR_CLASS=PolicyBlocked Worker playbook disallows tool '{}'. Allowed tools: {}.",
        tool_name,
        assignment.allowed_tools.join(", ")
    )
}

fn worker_assignment_tool_name_suppressed_by_recovery(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    if worker_assignment_should_suppress_redundant_change_directory(
        agent_state,
        Some(assignment),
        tool_name,
    ) {
        return true;
    }
    if worker_assignment_should_suppress_root_probes(Some(assignment), last_failure_class)
        && matches!(tool_name, "file__list" | "file__info")
    {
        return true;
    }
    if (worker_assignment_should_suppress_search_after_no_effect(
        Some(assignment),
        last_failure_class,
    ) || worker_assignment_has_likely_file_context(Some(assignment)))
        && tool_name == "file__search"
    {
        return true;
    }
    if worker_assignment_should_suppress_targeted_exec_until_workspace_edit(
        agent_state,
        Some(assignment),
        last_failure_class,
        tool_name,
    ) {
        return true;
    }
    worker_assignment_should_suppress_reads_after_no_effect(
        agent_state,
        Some(assignment),
        last_failure_class,
    ) && worker_assignment_tool_names_match("file__read", tool_name)
}

fn worker_assignment_allows_tool_name_for_recovery(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    assignment
        .map(|assignment| {
            worker_assignment_allows_tool_name(Some(assignment), tool_name)
                && !worker_assignment_tool_name_suppressed_by_recovery(
                    agent_state,
                    assignment,
                    last_failure_class,
                    tool_name,
                )
        })
        .unwrap_or(true)
}

fn worker_assignment_allowed_tool_names_for_recovery(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
) -> Vec<String> {
    assignment
        .allowed_tools
        .iter()
        .filter(|tool_name| {
            worker_assignment_allows_tool_name_for_recovery(
                agent_state,
                Some(assignment),
                last_failure_class,
                tool_name,
            )
        })
        .cloned()
        .collect()
}

fn worker_assignment_recovery_disallowed_tool_error(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> String {
    let allowed = worker_assignment_allowed_tool_names_for_recovery(
        agent_state,
        assignment,
        last_failure_class,
    );
    format!(
        "ERROR_CLASS=PolicyBlocked Worker recovery disallows tool '{}' after {}. Allowed tools now: {}.",
        tool_name,
        last_failure_class
            .map(FailureClass::as_str)
            .unwrap_or("current state"),
        allowed.join(", ")
    )
}

#[allow(dead_code)]
pub(crate) fn filter_tools_for_worker_assignment(
    tools: &[LlmToolDefinition],
    assignment: Option<&WorkerAssignment>,
) -> Vec<LlmToolDefinition> {
    let Some(assignment) = assignment else {
        return tools.to_vec();
    };
    if assignment.allowed_tools.is_empty() {
        return tools.to_vec();
    }

    tools
        .iter()
        .filter(|tool| worker_assignment_allows_tool_name(Some(assignment), &tool.name))
        .cloned()
        .collect()
}

fn normalize_existing_goal_path(candidate: &str) -> Option<PathBuf> {
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

fn goal_working_directory_matches_agent_state(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> bool {
    let current = agent_state.working_directory.trim();
    if current.is_empty() {
        return false;
    }

    collect_goal_literals(&assignment.goal)
        .into_iter()
        .filter_map(|literal| normalize_existing_goal_path(&literal))
        .any(|path| path == PathBuf::from(current))
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
        .and_then(|value| value.split(';').next().map(str::trim).map(str::to_string))
        .map(|value| normalize_whitespace(&value))
        .filter(|value| looks_like_command_literal(value))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .map(|literal| normalize_whitespace(&literal))
        .find(|literal| looks_like_command_literal(literal))
}

fn is_patch_build_verify_assignment(assignment: Option<&WorkerAssignment>) -> bool {
    assignment
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        == Some("patch_build_verify")
}

fn worker_assignment_has_likely_file_context(assignment: Option<&WorkerAssignment>) -> bool {
    let Some(assignment) = assignment else {
        return false;
    };
    if !is_patch_build_verify_assignment(Some(assignment)) {
        return false;
    }

    let (_, inherited_context) = split_parent_playbook_context(&assignment.goal);
    let Some(value) =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    else {
        return false;
    };
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    !compact.is_empty() && !compact.to_ascii_lowercase().starts_with("repo root:")
}

fn worker_assignment_should_suppress_root_probes(
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && (worker_assignment_has_likely_file_context(assignment)
            || matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction)))
}

fn worker_assignment_should_suppress_search_after_no_effect(
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction))
}

fn worker_assignment_should_suppress_reads_after_no_effect(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> bool {
    is_patch_build_verify_assignment(assignment)
        && matches!(last_failure_class, Some(FailureClass::NoEffectAfterAction))
        && !patch_miss_refresh_read_ready(agent_state)
}

fn latest_workspace_patch_miss_step(agent_state: &AgentState) -> Option<u32> {
    execution_evidence_value(
        &agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
    )
    .and_then(parse_receipt_step)
}

fn latest_workspace_read_step_any(agent_state: &AgentState) -> Option<u32> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_read_observed")
        .and_then(parse_receipt_step)
}

fn patch_miss_refresh_read_ready(agent_state: &AgentState) -> bool {
    let Some(patch_miss_step) = latest_workspace_patch_miss_step(agent_state) else {
        return false;
    };

    latest_workspace_read_step_any(agent_state)
        .map(|read_step| patch_miss_step > read_step)
        .unwrap_or(true)
}

fn latest_goal_command_step(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<u32> {
    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let target = normalize_whitespace(&command_literal);
    agent_state
        .command_history
        .iter()
        .rev()
        .find(|entry| {
            let observed = normalize_whitespace(&entry.command);
            observed == target || observed.contains(&target)
        })
        .map(|entry| entry.step_index)
}

fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

fn worker_assignment_should_suppress_targeted_exec_until_workspace_edit(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
    tool_name: &str,
) -> bool {
    if !matches!(tool_name, "shell__run" | "shell__start") {
        return false;
    }
    if !matches!(
        last_failure_class,
        Some(FailureClass::UnexpectedState) | Some(FailureClass::NoEffectAfterAction)
    ) {
        return false;
    }
    let Some(assignment) = assignment else {
        return false;
    };
    if !is_patch_build_verify_assignment(Some(assignment)) {
        return false;
    }

    let Some(command_step) = latest_goal_command_step(agent_state, assignment) else {
        return false;
    };
    let latest_edit_step = latest_workspace_edit_step(agent_state);
    latest_edit_step.map_or(true, |edit_step| edit_step <= command_step)
}

fn worker_assignment_should_suppress_redundant_change_directory(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    tool_name: &str,
) -> bool {
    if tool_name != "shell__cd" {
        return false;
    }
    let Some(assignment) = assignment else {
        return false;
    };
    is_patch_build_verify_assignment(Some(assignment))
        && goal_working_directory_matches_agent_state(agent_state, assignment)
}

fn parse_recent_failure_class(entry: &str) -> Option<FailureClass> {
    let mut parts = entry.split("::");
    let _scope = parts.next()?;
    let class = parts.next()?;
    FailureClass::from_str(class)
}

pub(crate) fn worker_recovery_failure_class(
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
) -> Option<FailureClass> {
    let latest = latest_failure_class(agent_state);
    if !matches!(latest, Some(FailureClass::UnexpectedState))
        || !is_patch_build_verify_assignment(assignment)
    {
        return latest;
    }

    if !agent_state.command_history.is_empty() {
        return latest;
    }

    let prior_no_effect_boundary = agent_state
        .recent_actions
        .iter()
        .rev()
        .skip(1)
        .take(3)
        .any(|entry| parse_recent_failure_class(entry) == Some(FailureClass::NoEffectAfterAction));

    if prior_no_effect_boundary {
        Some(FailureClass::NoEffectAfterAction)
    } else {
        latest
    }
}

pub(crate) fn filter_tools_for_worker_recovery(
    tools: &[LlmToolDefinition],
    agent_state: &AgentState,
    assignment: Option<&WorkerAssignment>,
    last_failure_class: Option<FailureClass>,
) -> Vec<LlmToolDefinition> {
    tools
        .iter()
        .filter(|tool| {
            worker_assignment_allows_tool_name_for_recovery(
                agent_state,
                assignment,
                last_failure_class,
                &tool.name,
            )
        })
        .cloned()
        .collect()
}

pub async fn execute_worker_step(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    rules: &ActionRules,
    worker_session_id: [u8; 32],
    tool: AgentTool,
    max_retries: u8,
) -> Result<WorkerExecutionResult, TransactionError> {
    let key = get_state_key(&worker_session_id);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Worker session not found: {}",
            hex::encode(worker_session_id)
        ))
    })?;
    let mut worker_state: AgentState = codec::from_bytes_canonical(&bytes)?;
    let os_driver = service.os_driver.clone();
    let worker_assignment =
        load_worker_assignment(state, worker_session_id).map_err(TransactionError::Invalid)?;

    let mut output: Option<String> = None;
    let mut error: Option<String> = None;
    let mut success = false;
    let mut attempts: u8 = 0;

    if let Some(assignment) = worker_assignment.as_ref() {
        let tool_name = tool.name_string();
        let last_failure_class =
            worker_recovery_failure_class(&worker_state, worker_assignment.as_ref());
        if !worker_assignment_allows_tool_name_for_recovery(
            &worker_state,
            Some(assignment),
            last_failure_class,
            &tool_name,
        ) {
            let failure = if worker_assignment_allows_tool_name(Some(assignment), &tool_name) {
                worker_assignment_recovery_disallowed_tool_error(
                    &worker_state,
                    assignment,
                    last_failure_class,
                    &tool_name,
                )
            } else {
                worker_assignment_disallowed_tool_error(assignment, &tool_name)
            };
            worker_state.step_count = worker_state.step_count.saturating_add(1);
            worker_state.status = AgentStatus::Failed(failure.clone());
            persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
            return Ok(WorkerExecutionResult {
                success: false,
                output: None,
                error: Some(failure),
                attempts: 0,
            });
        }
    }

    // A delegated worker must never stay Running because of infrastructure gaps.
    // If no OS driver is configured, mark this worker failed and return a terminal result
    // so the parent planner can complete deterministically instead of retry-spawning.
    let Some(os_driver) = os_driver else {
        worker_state.step_count = worker_state.step_count.saturating_add(1);
        worker_state.status = AgentStatus::Failed("OS driver missing".to_string());
        persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;
        return Ok(WorkerExecutionResult {
            success: false,
            output: None,
            error: Some("OS driver missing".to_string()),
            attempts: 0,
        });
    };

    for attempt in 0..=max_retries {
        attempts = attempt.saturating_add(1);
        match service
            .handle_action_execution_with_state(
                state,
                call_context,
                tool.clone(),
                worker_session_id,
                worker_state.step_count,
                worker_state.last_screen_phash.unwrap_or([0u8; 32]),
                rules,
                &worker_state,
                &os_driver,
                None,
            )
            .await
        {
            Ok((step_success, history_entry, step_error, _step_visual_hash)) => {
                output = history_entry;
                error = step_error;
                if step_success {
                    success = true;
                    break;
                }
            }
            Err(err) => {
                error = Some(err.to_string());
            }
        }
        worker_state.consecutive_failures = worker_state.consecutive_failures.saturating_add(1);
    }

    worker_state.step_count = worker_state.step_count.saturating_add(1);
    worker_state.status = if success {
        AgentStatus::Completed(output.clone())
    } else {
        AgentStatus::Failed(
            error
                .clone()
                .unwrap_or_else(|| "worker step failed".to_string()),
        )
    };
    persist_agent_state(state, &key, &worker_state, service.memory_runtime.as_ref())?;

    Ok(WorkerExecutionResult {
        success,
        output,
        error,
        attempts,
    })
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
