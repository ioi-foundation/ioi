use crate::agentic::desktop::agent_playbooks::builtin_agent_playbook;
use crate::agentic::desktop::keys::{
    get_parent_playbook_run_key, get_session_result_key, get_state_key, get_worker_assignment_key,
};
use crate::agentic::desktop::service::step::action::command_contract::extract_error_class_token;
use crate::agentic::desktop::service::step::action::execution_receipt_value;
use crate::agentic::desktop::service::step::handle_step;
use crate::agentic::desktop::service::step::queue::web_pipeline::merge_pending_search_completion;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, AgentState, AgentStatus,
    ParentPlaybookRun, ParentPlaybookStatus, ParentPlaybookStepRun, ParentPlaybookStepStatus,
    StepAgentParams, WorkerAssignment, WorkerCompletionContract, WorkerMergeMode,
    WorkerSessionResult, WorkerTemplateWorkflowDefinition,
};
use crate::agentic::desktop::utils::{
    load_agent_state_with_runtime_preference, persist_agent_state,
};
use crate::agentic::desktop::worker_context::{
    collect_goal_literals, extract_worker_context_field, looks_like_command_literal,
    normalize_whitespace, split_parent_playbook_context, PARENT_PLAYBOOK_CONTEXT_MARKER,
};
use crate::agentic::desktop::worker_templates::{
    builtin_worker_template, builtin_worker_workflow, default_worker_role_label,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use ioi_types::app::{
    ArtifactGenerationSummary, ArtifactQualityScorecard, ArtifactRepairSummary,
    CodingVerificationScorecard, ComputerUsePerceptionSummary, ComputerUseRecoverySummary,
    ComputerUseVerificationScorecard, KernelEvent, PatchSynthesisSummary,
    ResearchVerificationScorecard, WorkloadParentPlaybookReceipt, WorkloadReceipt,
    WorkloadReceiptEvent, WorkloadWorkerReceipt,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use super::delegation::{spawn_delegated_child_session, DelegatedChildPrepBundle};
use super::parent_playbook_receipts::{
    build_parent_playbook_prep_receipt_metadata, build_parent_playbook_route_receipt_metadata,
};

#[path = "worker_results/await_loop.rs"]
mod await_loop;
#[path = "worker_results/merge.rs"]
mod merge;
#[path = "worker_results/receipts.rs"]
mod receipts;
#[path = "worker_results/scorecards.rs"]
mod scorecards;

pub(crate) use await_loop::await_child_worker_result;
pub(crate) use merge::register_parent_playbook_step_spawn;
use merge::{
    advance_parent_playbook_after_worker_merge, block_parent_playbook_after_worker_failure,
    load_or_materialize_worker_result,
};
use receipts::{
    emit_parent_playbook_blocked_receipt, emit_parent_playbook_completed_receipt,
    emit_parent_playbook_started_receipt,
    emit_parent_playbook_step_completed_receipt, emit_parent_playbook_step_spawned_receipt,
    emit_worker_completion_receipt, emit_worker_merge_receipt, worker_receipt_summary,
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

const MAX_AWAIT_CHILD_BURST_STEPS: usize = 6;
const LIVE_RESEARCH_AWAIT_BURST_STEPS: usize = 4;
// Post-edit follow-through commonly needs a reread, a focused rerun, and a final handoff.
const PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS: usize = 3;

fn parse_child_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|error| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, error
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

fn load_child_state(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    load_agent_state_with_runtime_preference(
        state,
        memory_runtime,
        child_session_id,
        child_session_id_hex,
    )
}

fn retry_blocked_pause_reason(reason: &str) -> bool {
    reason.starts_with("Retry blocked: unchanged AttemptKey for")
        || reason.starts_with("Retry guard tripped after repeated")
}

fn pending_search_completion_has_inventory(state: &AgentState) -> bool {
    let Some(pending) = state.pending_search_completion.as_ref() else {
        return false;
    };

    !pending.query.trim().is_empty()
        || !pending.query_contract.trim().is_empty()
        || pending.retrieval_contract.is_some()
        || !pending.url.trim().is_empty()
        || !pending.candidate_urls.is_empty()
        || !pending.candidate_source_hints.is_empty()
        || !pending.attempted_urls.is_empty()
        || !pending.blocked_urls.is_empty()
        || !pending.successful_reads.is_empty()
}

fn merge_child_pending_search_completion_into_parent(
    parent_state: &mut AgentState,
    child_state: &AgentState,
) {
    if !pending_search_completion_has_inventory(child_state) {
        return;
    }

    let Some(incoming) = child_state.pending_search_completion.clone() else {
        return;
    };

    parent_state.pending_search_completion =
        Some(match parent_state.pending_search_completion.take() {
            Some(existing) => merge_pending_search_completion(existing, incoming),
            None => incoming,
        });
}

fn tool_name_allows_local_await_burst(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "agent__complete"
            | "agent__await_result"
            | "filesystem__read_file"
            | "filesystem__list_directory"
            | "filesystem__search"
            | "filesystem__stat"
            | "filesystem__patch"
            | "filesystem__edit_line"
            | "filesystem__write_file"
            | "memory__search"
            | "memory__inspect"
            | "model__rerank"
            | "sys__change_directory"
            | "sys__exec_session"
    )
}

fn tool_name_allows_research_await_burst(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "agent__complete"
            | "agent__await_result"
            | "memory__search"
            | "memory__inspect"
            | "web__search"
            | "web__read"
    )
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

fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

fn parse_receipt_path<'a>(value: &'a str) -> Option<&'a str> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("path="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

fn latest_workspace_edit_path(agent_state: &AgentState) -> Option<String> {
    execution_receipt_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_path)
        .map(str::to_string)
}

fn looks_like_file_hint(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|ch| ch.is_whitespace()) {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    let path = Path::new(trimmed);
    path.extension().is_some() || normalized.starts_with("tests/") || normalized.contains("/tests/")
}

fn patch_build_verify_goal_likely_files(goal: &str) -> Vec<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    if let Some(value) =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    {
        return value
            .split(';')
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string)
            .collect();
    }

    let mut seen = BTreeSet::new();
    collect_goal_literals(goal)
        .into_iter()
        .filter(|literal| looks_like_file_hint(literal))
        .filter(|literal| seen.insert(literal.to_ascii_lowercase()))
        .collect()
}

fn latest_successful_goal_command(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let edit_step = latest_workspace_edit_step(agent_state);
    let mut latest_success_after_edit: Option<String> = None;
    let mut latest_success_any: Option<String> = None;

    for entry in agent_state.command_history.iter().rev() {
        if entry.exit_code != 0 {
            continue;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            continue;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.command.trim().to_string());
            }
        }
        if latest_success_after_edit.is_none()
            && edit_step
                .map(|step| entry.step_index >= step)
                .unwrap_or(false)
        {
            latest_success_after_edit = Some(entry.command.trim().to_string());
        }
        if latest_success_any.is_none() {
            latest_success_any = Some(entry.command.trim().to_string());
        }
    }

    latest_success_after_edit.or(latest_success_any)
}

fn latest_successful_goal_command_after_edit(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let edit_step = latest_workspace_edit_step(agent_state)?;

    agent_state.command_history.iter().rev().find_map(|entry| {
        if entry.exit_code != 0 || entry.step_index <= edit_step {
            return None;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            return None;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.command.trim().to_string());
            }
        }
        Some(entry.command.trim().to_string())
    })
}

fn latest_failed_goal_command_step(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<u32> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let mut latest_failed_any: Option<u32> = None;

    for entry in agent_state.command_history.iter().rev() {
        if entry.exit_code == 0 {
            continue;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            continue;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.step_index);
            }
        }
        if latest_failed_any.is_none() {
            latest_failed_any = Some(entry.step_index);
        }
    }

    latest_failed_any
}

fn patch_build_verify_post_edit_followup_due(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> bool {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }

    let Some(command_step) = latest_failed_goal_command_step(agent_state, assignment) else {
        return false;
    };
    let Some(edit_step) = latest_workspace_edit_step(agent_state) else {
        return false;
    };

    edit_step > command_step
}

pub(crate) fn resolve_worker_assignment(
    child_session_id: [u8; 32],
    step_index: u32,
    requested_budget: u64,
    goal: &str,
    playbook_id: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
    requested_role: Option<&str>,
    success_criteria: Option<&str>,
    merge_mode: Option<&str>,
    expected_output: Option<&str>,
) -> WorkerAssignment {
    let template = builtin_worker_template(template_id);
    let workflow = builtin_worker_workflow(template_id, workflow_id);
    let mut completion_contract = template
        .as_ref()
        .map(|definition| definition.completion_contract.clone())
        .unwrap_or_default();
    if let Some(workflow_completion_contract) = workflow
        .as_ref()
        .and_then(|definition| definition.completion_contract.clone())
    {
        completion_contract = workflow_completion_contract;
    }

    if let Some(value) = success_criteria
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        completion_contract.success_criteria = value.to_string();
    }
    if let Some(value) = expected_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        completion_contract.expected_output = value.to_string();
    }
    if let Some(mode) = WorkerMergeMode::parse_label(merge_mode) {
        completion_contract.merge_mode = mode;
    }

    if completion_contract.success_criteria.trim().is_empty() {
        completion_contract.success_criteria =
            "Complete the delegated goal and return a deterministic handoff.".to_string();
    }
    if completion_contract.expected_output.trim().is_empty() {
        completion_contract.expected_output =
            "Delegated worker handoff summarizing the completed slice.".to_string();
    }

    let role = requested_role
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| template.as_ref().map(|definition| definition.role.clone()))
        .unwrap_or_else(|| default_worker_role_label(template_id).to_string());
    let effective_budget = workflow
        .as_ref()
        .and_then(|definition| definition.default_budget)
        .map(|workflow_budget| {
            if requested_budget == 0 {
                workflow_budget
            } else {
                requested_budget.min(workflow_budget)
            }
        })
        .unwrap_or(requested_budget);
    let max_retries = workflow
        .as_ref()
        .and_then(|definition| definition.max_retries)
        .or_else(|| template.as_ref().map(|definition| definition.max_retries))
        .unwrap_or(1);
    let allowed_tools = workflow
        .as_ref()
        .filter(|definition| !definition.allowed_tools.is_empty())
        .map(|definition| definition.allowed_tools.clone())
        .or_else(|| {
            template
                .as_ref()
                .map(|definition| definition.allowed_tools.clone())
        })
        .unwrap_or_default();

    WorkerAssignment {
        step_key: format!(
            "delegate:{}:{}",
            step_index,
            hex::encode(&child_session_id[..4])
        ),
        budget: effective_budget,
        goal: resolve_worker_goal(goal, workflow.as_ref()),
        success_criteria: completion_contract.success_criteria.clone(),
        max_retries,
        retries_used: 0,
        assigned_session_id: Some(child_session_id),
        status: "running".to_string(),
        playbook_id: playbook_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        template_id: template_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        workflow_id: workflow.map(|definition| definition.workflow_id),
        role: Some(role),
        allowed_tools,
        completion_contract,
    }
}

fn derive_workflow_topic(raw_goal: &str) -> String {
    let trimmed = raw_goal.trim().trim_end_matches(['.', '!', '?']);
    if trimmed.is_empty() {
        return "the delegated topic".to_string();
    }

    let lowercase = trimmed.to_ascii_lowercase();
    for prefix in [
        "implement ",
        "research ",
        "find ",
        "investigate ",
        "look up ",
        "gather evidence about ",
        "gather evidence for ",
        "summarize ",
        "check ",
        "verify ",
    ] {
        if lowercase.starts_with(prefix) {
            let suffix = trimmed[prefix.len()..]
                .trim_start_matches([':', '-', ' '])
                .trim();
            if !suffix.is_empty() {
                return suffix.to_string();
            }
        }
    }

    trimmed.to_string()
}

fn resolve_worker_goal(
    raw_goal: &str,
    workflow: Option<&WorkerTemplateWorkflowDefinition>,
) -> String {
    let (goal_without_context, inherited_context) =
        if let Some((head, tail)) = raw_goal.split_once(PARENT_PLAYBOOK_CONTEXT_MARKER) {
            (head.trim(), Some(tail.trim()))
        } else {
            (raw_goal.trim(), None)
        };
    let Some(workflow) = workflow else {
        return raw_goal.to_string();
    };
    let goal_template = workflow.goal_template.trim();
    if goal_template.is_empty() {
        return raw_goal.to_string();
    }

    if let Some(context) = inherited_context.filter(|value| !value.is_empty()) {
        return format!(
            "{}\n\n{}\n{}",
            goal_without_context, PARENT_PLAYBOOK_CONTEXT_MARKER, context
        );
    }

    let topic = derive_workflow_topic(goal_without_context);
    let resolved = goal_template.replace("{topic}", &topic);
    resolved
}

pub(crate) fn persist_worker_assignment(
    state: &mut dyn StateAccess,
    child_session_id: [u8; 32],
    assignment: &WorkerAssignment,
) -> Result<(), TransactionError> {
    let key = get_worker_assignment_key(&child_session_id);
    let bytes = codec::to_bytes_canonical(assignment)?;
    state.insert(&key, &bytes)?;
    Ok(())
}

pub(crate) fn load_worker_assignment(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<Option<WorkerAssignment>, String> {
    let key = get_worker_assignment_key(&child_session_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read worker assignment: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<WorkerAssignment>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode worker assignment: {}",
                error
            )
        })
}

fn load_worker_session_result(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<Option<WorkerSessionResult>, String> {
    let key = get_session_result_key(&child_session_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read worker session result: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<WorkerSessionResult>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode worker session result: {}",
                error
            )
        })
}

fn persist_worker_session_result(
    state: &mut dyn StateAccess,
    result: &WorkerSessionResult,
) -> Result<(), String> {
    let key = get_session_result_key(&result.child_session_id);
    let bytes = codec::to_bytes_canonical(result).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to encode worker session result: {}",
            error
        )
    })?;
    state.insert(&key, &bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist worker session result: {}",
            error
        )
    })?;
    Ok(())
}

fn load_parent_playbook_run(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    playbook_id: &str,
) -> Result<Option<ParentPlaybookRun>, String> {
    let key = get_parent_playbook_run_key(&parent_session_id, playbook_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read parent playbook run: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode parent playbook run: {}",
                error
            )
        })
}

fn persist_parent_playbook_run(
    state: &mut dyn StateAccess,
    run: &ParentPlaybookRun,
) -> Result<(), String> {
    let key = get_parent_playbook_run_key(&run.parent_session_id, &run.playbook_id);
    let bytes = codec::to_bytes_canonical(run).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to encode parent playbook run: {}",
            error
        )
    })?;
    state.insert(&key, &bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist parent playbook run: {}",
            error
        )
    })?;
    Ok(())
}

fn build_parent_playbook_run(
    parent_state: &AgentState,
    playbook: &AgentPlaybookDefinition,
    timestamp_ms: u64,
) -> ParentPlaybookRun {
    ParentPlaybookRun {
        parent_session_id: parent_state.session_id,
        playbook_id: playbook.playbook_id.clone(),
        playbook_label: playbook.label.clone(),
        topic: parent_state.goal.trim().to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: None,
        started_at_ms: timestamp_ms,
        updated_at_ms: timestamp_ms,
        completed_at_ms: None,
        steps: playbook
            .steps
            .iter()
            .map(|step| ParentPlaybookStepRun {
                step_id: step.step_id.clone(),
                label: step.label.clone(),
                summary: step.summary.clone(),
                status: ParentPlaybookStepStatus::Pending,
                child_session_id: None,
                template_id: Some(step.worker_template_id.clone()),
                workflow_id: Some(step.worker_workflow_id.clone()),
                goal: None,
                selected_skills: Vec::new(),
                prep_summary: None,
                artifact_generation: None,
                computer_use_perception: None,
                research_scorecard: None,
                artifact_quality: None,
                computer_use_verification: None,
                coding_scorecard: None,
                patch_synthesis: None,
                artifact_repair: None,
                computer_use_recovery: None,
                output_preview: None,
                error: None,
                spawned_at_ms: None,
                completed_at_ms: None,
                merged_at_ms: None,
            })
            .collect(),
    }
}

fn find_playbook_step_index(
    playbook: &AgentPlaybookDefinition,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
) -> Option<usize> {
    playbook.steps.iter().position(|step| {
        let template_matches = template_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value == step.worker_template_id)
            .unwrap_or(false);
        let workflow_matches = workflow_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value == step.worker_workflow_id)
            .unwrap_or(false);
        workflow_matches || template_matches
    })
}

fn find_run_step_index_by_child(
    run: &ParentPlaybookRun,
    child_session_id: [u8; 32],
) -> Option<usize> {
    run.steps
        .iter()
        .position(|step| step.child_session_id == Some(child_session_id))
}

fn summarize_parent_playbook_text(text: &str) -> String {
    worker_receipt_summary(text)
}

const RESEARCH_SOURCE_FLOOR: u32 = 2;
const RESEARCH_DOMAIN_FLOOR: u32 = 2;

fn normalize_research_verifier_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "attention" | "partial" | "warning" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn parse_scorecard_fields(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let normalized_key = key.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        let normalized_value = value.trim();
        if normalized_key.is_empty() || normalized_value.is_empty() {
            continue;
        }
        fields
            .entry(normalized_key)
            .or_insert_with(|| normalized_value.to_string());
    }
    fields
}

fn first_scorecard_note(fields: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        fields
            .get(*key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn extract_http_url_candidates(text: &str) -> BTreeSet<String> {
    let mut urls = BTreeSet::new();
    for token in text.split_whitespace() {
        let Some(start) = token.find("https://").or_else(|| token.find("http://")) else {
            continue;
        };
        let candidate = token[start..]
            .trim_matches(|ch: char| matches!(ch, ')' | ']' | '}' | ',' | ';' | '"' | '\'' | '.'));
        let Ok(parsed) = Url::parse(candidate) else {
            continue;
        };
        if matches!(parsed.scheme(), "http" | "https") {
            urls.insert(parsed.to_string());
        }
    }
    urls
}

fn count_research_brief_sources(text: &str) -> (u32, u32) {
    let urls = extract_http_url_candidates(text);
    let domains = urls
        .iter()
        .filter_map(|url| Url::parse(url).ok())
        .filter_map(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .map(|host| host.trim_start_matches("www.").to_string())
        .collect::<BTreeSet<_>>();
    (urls.len() as u32, domains.len() as u32)
}

fn build_research_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ResearchVerificationScorecard> {
    scorecards::build_research_verification_scorecard(state, run, playbook, step_idx, result)
}

fn parent_playbook_research_scorecard(
    run: &ParentPlaybookRun,
) -> Option<ResearchVerificationScorecard> {
    scorecards::parent_playbook_research_scorecard(run)
}

fn count_compact_list_items(text: &str) -> u32 {
    let items = text
        .split(|ch| matches!(ch, ';' | ',' | '\n'))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if items.is_empty() {
        u32::from(!text.trim().is_empty())
    } else {
        items.len() as u32
    }
}

fn normalize_artifact_generation_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "generated" | "generated_ready" | "ready" | "complete" | "completed" | "success" | "ok" => {
            "generated".to_string()
        }
        "partial" | "repairable" | "needs_attention" => "partial".to_string(),
        "blocked" | "failed" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_artifact_signal_status(value: Option<&str>, fallback: &str) -> String {
    let normalized = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase();
    match normalized.as_str() {
        "retained" | "captured" | "present" | "passed" | "ready" | "yes" => "retained".to_string(),
        "partial" | "incomplete" => "partial".to_string(),
        "missing" | "none" | "no" => "missing".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        _ if normalized.contains("captur")
            || normalized.contains("pass")
            || normalized.contains("verif")
            || normalized.contains("preview")
            || normalized.contains("screenshot") =>
        {
            "retained".to_string()
        }
        other => other.replace('-', "_"),
    }
}

fn normalize_artifact_presentation_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "ready" | "presentation_ready" | "ship" | "shippable" => "ready".to_string(),
        "needs_judge" | "review" | "open" => "needs_judge".to_string(),
        "needs_repair" | "repairable" | "not_ready" | "fix" => "needs_repair".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_artifact_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ready" | "approved" => "passed".to_string(),
        "fail" | "failed" | "open" | "repairable" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_artifact_fidelity_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "faithful" | "grounded" | "matched" | "clear" | "passed" => "faithful".to_string(),
        "partial" | "open" | "needs_attention" | "drift" => "needs_attention".to_string(),
        "blocked" | "failed" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_artifact_repair_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "clear" => "not_needed".to_string(),
        "recommended" | "suggested" | "follow_up" | "needs_judge" => "recommended".to_string(),
        "required" | "needed" | "needs_repair" | "repairable" => "required".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn build_artifact_generation_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactGenerationSummary> {
    scorecards::build_artifact_generation_summary(run, playbook, step_idx, result)
}

fn parent_playbook_artifact_generation(
    run: &ParentPlaybookRun,
) -> Option<ArtifactGenerationSummary> {
    scorecards::parent_playbook_artifact_generation(run)
}

fn build_artifact_quality_scorecard(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactQualityScorecard> {
    scorecards::build_artifact_quality_scorecard(run, playbook, step_idx, result)
}

fn parent_playbook_artifact_quality(run: &ParentPlaybookRun) -> Option<ArtifactQualityScorecard> {
    scorecards::parent_playbook_artifact_quality(run)
}

fn build_artifact_repair_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactRepairSummary> {
    scorecards::build_artifact_repair_summary(run, playbook, step_idx, result)
}

fn parent_playbook_artifact_repair(run: &ParentPlaybookRun) -> Option<ArtifactRepairSummary> {
    scorecards::parent_playbook_artifact_repair(run)
}

fn normalize_computer_use_surface_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "clear" | "observed" | "ready" | "visible" => "clear".to_string(),
        "partial" | "uncertain" => "partial".to_string(),
        "blocked" | "missing" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_computer_use_approval_risk(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "clear" | "low" => "none".to_string(),
        "possible" | "medium" | "watch" => "possible".to_string(),
        "required" | "pending" | "high" => "required".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_computer_use_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_computer_use_postcondition_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "met" | "passed" | "holds" | "verified" | "complete" => "met".to_string(),
        "open" | "not_met" | "missing" | "partial" | "needs_attention" => "open".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_computer_use_approval_state(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pending" | "require_approval" | "approval_required" => "pending".to_string(),
        "approved" => "approved".to_string(),
        "denied" => "denied".to_string(),
        "clear" | "cleared" | "none" | "allowed" | "not_needed" => "clear".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_computer_use_recovery_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "clear" => "not_needed".to_string(),
        "recommended" | "retry" | "retryable" | "suggested" => "recommended".to_string(),
        "required" | "needed" | "needs_recovery" => "required".to_string(),
        "pending_approval" | "approval_pending" => "pending_approval".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn build_computer_use_perception_summary(
    _state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUsePerceptionSummary> {
    scorecards::build_computer_use_perception_summary(_state, run, playbook, step_idx, result)
}

fn parent_playbook_computer_use_perception(
    run: &ParentPlaybookRun,
) -> Option<ComputerUsePerceptionSummary> {
    scorecards::parent_playbook_computer_use_perception(run)
}

fn load_step_raw_output(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    step_id: &str,
) -> Option<String> {
    run.steps
        .iter()
        .find(|step| step.step_id == step_id)
        .and_then(|step| {
            step.child_session_id
                .and_then(|child_session_id| {
                    load_worker_session_result(state, child_session_id)
                        .ok()
                        .flatten()
                })
                .and_then(|result| result.raw_output)
                .or_else(|| step.output_preview.clone())
        })
}

fn extract_prefixed_items(text: &str, prefixes: &[&str]) -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                for item in rest.split(';') {
                    let normalized = item.trim().trim_matches('.');
                    if !normalized.is_empty() {
                        items.insert(normalized.to_string());
                    }
                }
            }
        }
    }
    items
}

fn extract_prefixed_value(text: &str, prefixes: &[&str]) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        for prefix in prefixes {
            if let Some(value) = trimmed.strip_prefix(prefix) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn count_passed_items(items: &BTreeSet<String>) -> u32 {
    items
        .iter()
        .filter(|item| {
            let lower = item.to_ascii_lowercase();
            lower.contains("(passed)")
                || lower.ends_with(" passed")
                || lower.contains(" status=passed")
        })
        .count() as u32
}

fn count_touched_files(text: &str) -> u32 {
    let files = extract_prefixed_items(text, &["Touched files:", "Touched file:"]);
    files.len() as u32
}

fn patch_build_verify_handoff_is_structured(text: &str) -> bool {
    count_touched_files(text) > 0
        && !extract_prefixed_items(text, &["Verification:", "Targeted verification:"]).is_empty()
}

fn synthesize_patch_build_verify_completion_result(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
    explicit_summary: Option<&str>,
) -> Option<String> {
    let command_literal = latest_successful_goal_command(child_state, assignment)?;
    let mut touched_files = Vec::<String>::new();

    if let Some(path) = latest_workspace_edit_path(child_state) {
        let candidate = Path::new(&path)
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
            .unwrap_or(path);
        if !candidate.trim().is_empty() {
            touched_files.push(candidate);
        }
    }

    for hint in patch_build_verify_goal_likely_files(&assignment.goal) {
        if !touched_files
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&hint))
        {
            touched_files.push(hint);
        }
    }

    let touched_files_line = if touched_files.is_empty() {
        "Touched files: none recorded".to_string()
    } else {
        format!("Touched files: {}", touched_files.join("; "))
    };

    let mut lines = vec![
        touched_files_line,
        format!("Verification: {} (passed)", command_literal.trim()),
        "Residual risk: Focused verification passed; broader checks were not rerun.".to_string(),
    ];
    if let Some(summary) = explicit_summary
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("Summary: {}", normalize_whitespace(summary)));
    }

    Some(lines.join("\n"))
}

fn maybe_enrich_patch_build_verify_completion_result(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
    explicit_result: Option<String>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return explicit_result;
    }
    if explicit_result
        .as_deref()
        .map(patch_build_verify_handoff_is_structured)
        .unwrap_or(false)
    {
        return explicit_result;
    }

    synthesize_patch_build_verify_completion_result(
        child_state,
        assignment,
        explicit_result.as_deref(),
    )
}

fn patch_synthesis_handoff_is_structured(text: &str) -> bool {
    let fields = parse_scorecard_fields(text);
    fields.contains_key("status")
        && fields.contains_key("touched_file_count")
        && fields.contains_key("verification_ready")
}

fn synthesize_patch_synthesis_completion_result(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    assignment: &WorkerAssignment,
    explicit_summary: Option<&str>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_synthesis_handoff") {
        return None;
    }

    let playbook_id = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("evidence_audited_patch");
    let run = load_parent_playbook_run(state, parent_session_id, playbook_id)
        .ok()
        .flatten()?;
    if run.playbook_id.trim() != "evidence_audited_patch" {
        return None;
    }

    let implement_output = load_step_raw_output(state, &run, "implement").unwrap_or_default();
    let touched_file_count = count_touched_files(&implement_output);
    if touched_file_count == 0 {
        return None;
    }

    let verifier_scorecard = parent_playbook_coding_scorecard(&run);
    let verification_ready = verifier_scorecard
        .as_ref()
        .map(|scorecard| scorecard.verdict == "passed")
        .unwrap_or(false);
    let status = if verification_ready {
        "ready"
    } else {
        "needs_attention"
    };
    let notes = explicit_summary
        .map(normalize_whitespace)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            verifier_scorecard
                .as_ref()
                .and_then(|scorecard| scorecard.notes.clone())
        })
        .unwrap_or_else(|| {
            if verification_ready {
                "Inherited verifier receipts already mark the focused coding handoff as passed."
                    .to_string()
            } else {
                "Inherited verifier receipts still need attention before the final patch handoff is ready."
                    .to_string()
            }
        });
    let residual_risk = extract_prefixed_value(&implement_output, &["Residual risk:", "Notes:"])
        .unwrap_or_else(|| {
            if verification_ready {
                "Focused verification passed; broader checks were not rerun.".to_string()
            } else {
                "Verifier context is not yet ready, so the final patch handoff remains blocked."
                    .to_string()
            }
        });

    Some(format!(
        "- status: {}\n- touched_file_count: {}\n- verification_ready: {}\n- notes: {}\n- residual_risk: {}",
        status,
        touched_file_count,
        if verification_ready { "yes" } else { "no" },
        notes,
        residual_risk
    ))
}

fn maybe_enrich_patch_synthesis_completion_result(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    assignment: &WorkerAssignment,
    explicit_result: Option<String>,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_synthesis_handoff") {
        return explicit_result;
    }
    if explicit_result
        .as_deref()
        .map(patch_synthesis_handoff_is_structured)
        .unwrap_or(false)
    {
        return explicit_result;
    }

    synthesize_patch_synthesis_completion_result(
        state,
        parent_session_id,
        assignment,
        explicit_result.as_deref(),
    )
    .or(explicit_result)
}

fn synthesize_observed_patch_build_verify_completion(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if child_state.pending_tool_call.is_some() || !child_state.execution_queue.is_empty() {
        return None;
    }
    latest_successful_goal_command_after_edit(child_state, assignment)?;
    synthesize_patch_build_verify_completion_result(child_state, assignment, None)
}

fn normalize_coding_verdict(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "pass" | "passed" | "ok" | "ready" => "passed".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" | "unsafe" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_widening_status(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "not_needed" | "targeted_only" | "contained" => "not_needed".to_string(),
        "performed" | "widened" | "expanded" => "performed".to_string(),
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_regression_status(value: Option<&str>) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "clear" | "clean" | "pass" | "passed" | "ok" => "clear".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn normalize_patch_synthesis_status(value: Option<&str>, fallback: &str) -> String {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_ascii_lowercase()
        .as_str()
    {
        "ready" | "pass" | "passed" | "ok" => "ready".to_string(),
        "fail" | "failed" | "open" | "needs_attention" | "warning" | "partial" => {
            "needs_attention".to_string()
        }
        "blocked" => "blocked".to_string(),
        "unknown" | "" => "unknown".to_string(),
        other => other.replace('-', "_"),
    }
}

fn parse_bool_like(value: Option<&str>) -> Option<bool> {
    match value
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "yes" | "ready" | "accepted" => Some(true),
        "false" | "no" | "open" | "blocked" => Some(false),
        _ => None,
    }
}

fn build_coding_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<CodingVerificationScorecard> {
    scorecards::build_coding_verification_scorecard(state, run, playbook, step_idx, result)
}

fn parent_playbook_coding_scorecard(
    run: &ParentPlaybookRun,
) -> Option<CodingVerificationScorecard> {
    scorecards::parent_playbook_coding_scorecard(run)
}

fn build_computer_use_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseVerificationScorecard> {
    scorecards::build_computer_use_verification_scorecard(state, run, playbook, step_idx, result)
}

fn parent_playbook_computer_use_verification(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseVerificationScorecard> {
    scorecards::parent_playbook_computer_use_verification(run)
}

fn build_patch_synthesis_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<PatchSynthesisSummary> {
    scorecards::build_patch_synthesis_summary(state, run, playbook, step_idx, result)
}

fn parent_playbook_patch_synthesis(run: &ParentPlaybookRun) -> Option<PatchSynthesisSummary> {
    scorecards::parent_playbook_patch_synthesis(run)
}

fn build_computer_use_recovery_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseRecoverySummary> {
    scorecards::build_computer_use_recovery_summary(state, run, playbook, step_idx, result)
}

fn parent_playbook_computer_use_recovery(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseRecoverySummary> {
    scorecards::parent_playbook_computer_use_recovery(run)
}

fn reset_parent_playbook_steps_from(run: &mut ParentPlaybookRun, step_idx: usize) {
    for step in run.steps.iter_mut().skip(step_idx) {
        step.status = ParentPlaybookStepStatus::Pending;
        step.child_session_id = None;
        step.template_id = None;
        step.workflow_id = None;
        step.goal = None;
        step.selected_skills.clear();
        step.prep_summary = None;
        step.artifact_generation = None;
        step.computer_use_perception = None;
        step.research_scorecard = None;
        step.artifact_quality = None;
        step.computer_use_verification = None;
        step.coding_scorecard = None;
        step.patch_synthesis = None;
        step.artifact_repair = None;
        step.computer_use_recovery = None;
        step.output_preview = None;
        step.error = None;
        step.spawned_at_ms = None;
        step.completed_at_ms = None;
        step.merged_at_ms = None;
    }
    run.completed_at_ms = None;
}

fn step_dependencies_satisfied(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    step: &AgentPlaybookStepDefinition,
) -> bool {
    step.depends_on.iter().all(|dependency| {
        playbook
            .steps
            .iter()
            .position(|candidate| candidate.step_id == *dependency)
            .and_then(|index| run.steps.get(index))
            .map(|state| state.status == ParentPlaybookStepStatus::Completed)
            .unwrap_or(false)
    })
}

fn next_ready_playbook_step_index(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
) -> Option<usize> {
    playbook.steps.iter().enumerate().find_map(|(index, step)| {
        let current = run.steps.get(index)?;
        if current.status != ParentPlaybookStepStatus::Pending {
            return None;
        }
        step_dependencies_satisfied(playbook, run, step).then_some(index)
    })
}

fn compact_research_scorecard_text(scorecard: &ResearchVerificationScorecard) -> String {
    format!(
        "research_verification={} sources={} domains={} freshness={} quotes={}",
        scorecard.verdict,
        scorecard.source_count,
        scorecard.distinct_domain_count,
        scorecard.freshness_status,
        scorecard.quote_grounding_status
    )
}

fn compact_artifact_generation_text(summary: &ArtifactGenerationSummary) -> String {
    format!(
        "artifact_generation={} files={} verification={} presentation={}",
        summary.status,
        summary.produced_file_count,
        summary.verification_signal_status,
        summary.presentation_status
    )
}

fn compact_computer_use_perception_text(summary: &ComputerUsePerceptionSummary) -> String {
    format!(
        "computer_use_perception={} ui_state={} approval_risk={}",
        summary.surface_status, summary.ui_state, summary.approval_risk
    )
}

fn compact_artifact_quality_text(scorecard: &ArtifactQualityScorecard) -> String {
    format!(
        "artifact_quality={} fidelity={} presentation={} repair={}",
        scorecard.verdict,
        scorecard.fidelity_status,
        scorecard.presentation_status,
        scorecard.repair_status
    )
}

fn compact_coding_scorecard_text(scorecard: &CodingVerificationScorecard) -> String {
    format!(
        "coding_verification={} targeted_passed={}/{} widening={} regressions={}",
        scorecard.verdict,
        scorecard.targeted_pass_count,
        scorecard.targeted_command_count,
        scorecard.widening_status,
        scorecard.regression_status
    )
}

fn compact_computer_use_verification_text(scorecard: &ComputerUseVerificationScorecard) -> String {
    format!(
        "computer_use_verification={} postcondition={} approval={} recovery={}",
        scorecard.verdict,
        scorecard.postcondition_status,
        scorecard.approval_state,
        scorecard.recovery_status
    )
}

fn compact_patch_synthesis_text(summary: &PatchSynthesisSummary) -> String {
    format!(
        "patch_synthesis={} touched_files={} verification_ready={}",
        summary.status, summary.touched_file_count, summary.verification_ready
    )
}

fn compact_artifact_repair_text(summary: &ArtifactRepairSummary) -> String {
    format!("artifact_repair={}", summary.status)
}

fn compact_computer_use_recovery_text(summary: &ComputerUseRecoverySummary) -> String {
    format!("computer_use_recovery={}", summary.status)
}

fn parent_playbook_step_context(step: &ParentPlaybookStepRun) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(preview) = step
        .output_preview
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        parts.push(preview.trim().to_string());
    }
    if let Some(prep) = step
        .prep_summary
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        parts.push(format!("prep={}", prep.trim()));
    }
    if !step.selected_skills.is_empty() {
        parts.push(format!("skills={}", step.selected_skills.join(", ")));
    }
    if let Some(summary) = step.computer_use_perception.as_ref() {
        parts.push(compact_computer_use_perception_text(summary));
    }
    if let Some(summary) = step.artifact_generation.as_ref() {
        parts.push(compact_artifact_generation_text(summary));
    }
    if let Some(scorecard) = step.research_scorecard.as_ref() {
        parts.push(compact_research_scorecard_text(scorecard));
    }
    if let Some(scorecard) = step.artifact_quality.as_ref() {
        parts.push(compact_artifact_quality_text(scorecard));
    }
    if let Some(scorecard) = step.computer_use_verification.as_ref() {
        parts.push(compact_computer_use_verification_text(scorecard));
    }
    if let Some(scorecard) = step.coding_scorecard.as_ref() {
        parts.push(compact_coding_scorecard_text(scorecard));
    }
    if let Some(summary) = step.patch_synthesis.as_ref() {
        parts.push(compact_patch_synthesis_text(summary));
    }
    if let Some(summary) = step.artifact_repair.as_ref() {
        parts.push(compact_artifact_repair_text(summary));
    }
    if let Some(summary) = step.computer_use_recovery.as_ref() {
        parts.push(compact_computer_use_recovery_text(summary));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    }
}

fn collect_completed_dependency_contexts(
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    step_id: &str,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<String>,
) {
    let Some(step_definition) = playbook.steps.iter().find(|step| step.step_id == step_id) else {
        return;
    };
    for dependency in &step_definition.depends_on {
        if !seen.insert(dependency.clone()) {
            continue;
        }
        collect_completed_dependency_contexts(playbook, run, dependency, seen, out);
        let Some(index) = playbook
            .steps
            .iter()
            .position(|candidate| candidate.step_id == *dependency)
        else {
            continue;
        };
        let Some(step_run) = run.steps.get(index) else {
            continue;
        };
        if step_run.status != ParentPlaybookStepStatus::Completed {
            continue;
        }
        let Some(context) = parent_playbook_step_context(step_run) else {
            continue;
        };
        out.push(format!(
            "- {} ({}): {}",
            step_run.label, step_run.step_id, context
        ));
    }
}

fn compact_parent_playbook_context(text: &str, max_chars: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut summary = trimmed.chars().take(max_chars).collect::<String>();
        summary.push_str("...");
        summary
    }
}

fn inject_parent_playbook_context(
    state: &dyn StateAccess,
    goal: &str,
    playbook: &AgentPlaybookDefinition,
    run: &ParentPlaybookRun,
    next_step: &AgentPlaybookStepDefinition,
) -> String {
    let mut dependency_lines = Vec::new();
    let mut seen = BTreeSet::new();
    collect_completed_dependency_contexts(
        playbook,
        run,
        &next_step.step_id,
        &mut seen,
        &mut dependency_lines,
    );
    if dependency_lines.is_empty() {
        return goal.to_string();
    }
    if run.playbook_id.trim() == "citation_grounded_brief"
        && next_step.worker_workflow_id.trim() == "citation_audit"
    {
        if let Some(research_handoff) = load_step_raw_output(state, run, "research")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Gather current sources full_handoff (research_full): {}",
                research_handoff
            ));
        }
    }
    if run.playbook_id.trim() == "evidence_audited_patch"
        && next_step.worker_workflow_id.trim() == "targeted_test_audit"
    {
        if let Some(implement_handoff) = load_step_raw_output(state, run, "implement")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Patch the workspace full_handoff (implement_full): {}",
                implement_handoff
            ));
        }
    }
    if run.playbook_id.trim() == "evidence_audited_patch"
        && next_step.worker_workflow_id.trim() == "patch_synthesis_handoff"
    {
        if let Some(implement_handoff) = load_step_raw_output(state, run, "implement")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Patch the workspace full_handoff (implement_full):\n{}",
                implement_handoff
            ));
        }
        if let Some(verify_handoff) = load_step_raw_output(state, run, "verify")
            .map(|value| compact_parent_playbook_context(&value, 2400))
            .filter(|value| !value.trim().is_empty())
        {
            dependency_lines.push(format!(
                "- Verify targeted tests full_handoff (verify_full):\n{}",
                verify_handoff
            ));
        }
    }

    format!(
        "{}\n\n{}\n{}",
        goal,
        PARENT_PLAYBOOK_CONTEXT_MARKER,
        dependency_lines.join("\n")
    )
}

fn synthesize_parent_playbook_tool_hash(
    parent_session_id: [u8; 32],
    playbook_id: &str,
    step_id: &str,
    parent_step_index: u32,
) -> Result<[u8; 32], String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ioi::parent_playbook_step::v1::");
    payload.extend_from_slice(parent_session_id.as_slice());
    payload.extend_from_slice(playbook_id.as_bytes());
    payload.extend_from_slice(step_id.as_bytes());
    payload.extend_from_slice(&parent_step_index.to_le_bytes());
    sha256(payload).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to hash parent playbook step payload: {}",
            error
        )
    })
}

fn parent_playbook_completion_output(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    result: &WorkerSessionResult,
) -> String {
    if run.playbook_id.trim() == "citation_grounded_brief" {
        let research_output = load_step_raw_output(state, run, "research").unwrap_or_default();
        let verification_output = load_step_raw_output(state, run, "verify")
            .or_else(|| result.raw_output.clone())
            .unwrap_or_else(|| result.merged_output.clone());
        let research_output = research_output.trim();
        let verification_output = verification_output.trim();
        if !research_output.is_empty() {
            if verification_output.is_empty() {
                return research_output.to_string();
            }
            return format!(
                "{}\n\nVerification verdict\n{}",
                research_output, verification_output
            );
        }
    }

    playbook
        .steps
        .iter()
        .rev()
        .find_map(|step| load_step_raw_output(state, run, &step.step_id))
        .or_else(|| result.raw_output.clone())
        .unwrap_or_else(|| result.merged_output.clone())
}

fn mark_parent_playbook_step_completed_from_result(
    state: &dyn StateAccess,
    run: &mut ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
    timestamp_ms: u64,
) {
    let artifact_generation = build_artifact_generation_summary(run, playbook, step_idx, result);
    let computer_use_perception =
        build_computer_use_perception_summary(state, run, playbook, step_idx, result);
    let research_scorecard =
        build_research_verification_scorecard(state, run, playbook, step_idx, result);
    let artifact_quality = build_artifact_quality_scorecard(run, playbook, step_idx, result);
    let computer_use_verification =
        build_computer_use_verification_scorecard(state, run, playbook, step_idx, result);
    let coding_scorecard =
        build_coding_verification_scorecard(state, run, playbook, step_idx, result);
    let patch_synthesis = build_patch_synthesis_summary(state, run, playbook, step_idx, result);
    let artifact_repair = build_artifact_repair_summary(run, playbook, step_idx, result);
    let computer_use_recovery =
        build_computer_use_recovery_summary(state, run, playbook, step_idx, result);
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Completed;
        step.output_preview = Some(summarize_parent_playbook_text(&result.merged_output));
        step.error = result.error.clone();
        step.artifact_generation = artifact_generation;
        step.computer_use_perception = computer_use_perception;
        step.research_scorecard = research_scorecard;
        step.artifact_quality = artifact_quality;
        step.computer_use_verification = computer_use_verification;
        step.coding_scorecard = coding_scorecard;
        step.patch_synthesis = patch_synthesis;
        step.artifact_repair = artifact_repair;
        step.computer_use_recovery = computer_use_recovery;
        step.completed_at_ms = Some(result.completed_at_ms);
        step.merged_at_ms = Some(timestamp_ms);
    }
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = None;
    run.updated_at_ms = timestamp_ms;
}

#[cfg(test)]
mod tests {
    use super::{
        await_child_worker_result as await_child_worker_result_impl, build_parent_playbook_run,
        execution_receipt_value, inject_parent_playbook_context, latest_failed_goal_command_step,
        load_child_state, load_parent_playbook_run, load_worker_session_result,
        patch_build_verify_post_edit_followup_due, persist_parent_playbook_run,
        persist_worker_assignment, persist_worker_session_result, resolve_worker_assignment,
        resolve_worker_goal, retry_blocked_pause_reason,
        synthesize_observed_patch_build_verify_completion, LIVE_RESEARCH_AWAIT_BURST_STEPS,
        MAX_AWAIT_CHILD_BURST_STEPS, PARENT_PLAYBOOK_CONTEXT_MARKER,
        PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS,
    };
    use super::await_loop::{await_child_burst_step_limit, child_allows_await_burst};
    use super::merge::{materialize_worker_result, merged_worker_output};
    use crate::agentic::desktop::agent_playbooks::builtin_agent_playbook;
    use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
    use crate::agentic::desktop::service::lifecycle::delegation::spawn_delegated_child_session;
    use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ParentPlaybookStatus,
        ParentPlaybookStepStatus, PendingSearchCompletion, PendingSearchReadSummary,
        WorkerCompletionContract, WorkerMergeMode,
    };
    use crate::agentic::desktop::utils::persist_agent_state;
    use crate::agentic::desktop::worker_templates::builtin_worker_workflow;
    use crate::agentic::rules::{ActionRules, DefaultPolicy};
    use crate::agentic::skill_registry::{
        build_skill_archival_metadata_json, canonical_skill_hash, skill_archival_content,
        upsert_skill_record, SKILL_ARCHIVAL_KIND, SKILL_ARCHIVAL_SCOPE,
    };
    use async_trait::async_trait;
    use ioi_api::services::access::ServiceDirectory;
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::{MemoryRuntime, NewArchivalMemoryRecord};
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::{
        AgentMacro, LlmToolDefinition, SkillLifecycleState, SkillRecord, SkillSourceType,
    };
    use ioi_types::app::{
        AccountId, ActionContext, ActionRequest, ActionTarget, ChainId, CodingVerificationScorecard,
    };
    use ioi_types::app::{ContextSlice, KernelEvent, WorkloadReceipt};
    use ioi_types::codec;
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = image::ImageBuffer::<image::Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
                .map_err(|error| {
                    VmError::HostError(format!("mock PNG encode failed: {}", error))
                })?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_parent_state_with_goal(goal: &str, budget: u64) -> AgentState {
        AgentState {
            session_id: [0x91; 32],
            goal: goal.to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
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

    fn build_parent_state() -> AgentState {
        build_parent_state_with_goal("Parent orchestration goal", 8)
    }

    #[test]
    fn worker_goal_resolution_keeps_parent_shaped_goal_when_context_is_present() {
        let workflow = builtin_worker_workflow(Some("coder"), Some("patch_build_verify"))
            .expect("patch_build_verify workflow should exist");
        let raw_goal = format!(
            "Implement the parity fix in \"/tmp/example\" as a narrow workspace patch informed by the repo context brief, run focused executor-side checks, and return touched files, command results, and residual risk.\n\n{}\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            PARENT_PLAYBOOK_CONTEXT_MARKER
        );

        let resolved = resolve_worker_goal(&raw_goal, Some(&workflow));

        assert_eq!(resolved, raw_goal);
        assert_eq!(resolved.matches("Implement the parity fix").count(), 1);
    }

    #[test]
    fn worker_goal_resolution_still_templates_root_kickoff_without_parent_context() {
        let workflow = builtin_worker_workflow(Some("context_worker"), Some("repo_context_brief"))
            .expect("repo_context_brief workflow should exist");
        let raw_goal = "Port the path-normalization parity fix into the repo at \"/tmp/example\".";

        let resolved = resolve_worker_goal(raw_goal, Some(&workflow));

        assert!(resolved.starts_with("Inspect repo context for "));
        assert!(resolved.contains("/tmp/example"));
        assert!(!resolved.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delegated_child_inherits_parent_policy_rules() {
        let (tx, _rx) = tokio::sync::broadcast::channel(4);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state();
        let parent_key = get_state_key(&parent_state.session_id);
        state
            .insert(
                &parent_key,
                &codec::to_bytes_canonical(&parent_state).expect("parent state encode"),
            )
            .expect("parent state insert should succeed");
        let parent_rules = ActionRules {
            policy_id: "capabilities-suite".to_string(),
            defaults: DefaultPolicy::AllowAll,
            ..ActionRules::default()
        };
        let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
        state
            .insert(
                &parent_policy_key,
                &codec::to_bytes_canonical(&parent_rules).expect("parent policy encode"),
            )
            .expect("parent policy insert should succeed");

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x51; 32],
            "Inspect the repo and return a bounded context brief.",
            8,
            None,
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            1,
            0,
        )
        .await
        .expect("delegated child should spawn");

        let child_policy_key = [AGENT_POLICY_PREFIX, spawned.child_session_id.as_slice()].concat();
        let child_policy_bytes = state
            .get(&child_policy_key)
            .expect("child policy lookup should succeed")
            .expect("child policy should exist");
        let child_rules: ActionRules =
            codec::from_bytes_canonical(&child_policy_bytes).expect("child policy should decode");

        assert_eq!(child_rules.policy_id, "capabilities-suite");
        assert_eq!(child_rules.defaults, DefaultPolicy::AllowAll);
    }

    fn build_test_service(
        event_sender: tokio::sync::broadcast::Sender<KernelEvent>,
    ) -> (DesktopAgentService, tempfile::TempDir) {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        let temp_dir = tempdir().expect("tempdir should open");
        let memory_path = temp_dir.path().join("worker-results.sqlite");
        let memory_runtime =
            Arc::new(MemoryRuntime::open_sqlite(&memory_path).expect("sqlite memory should open"));
        let service = DesktopAgentService::new(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime,
        )
        .with_memory_runtime(memory_runtime)
        .with_event_sender(event_sender);
        (service, temp_dir)
    }

    fn test_call_context<'a>(services: &'a ServiceDirectory) -> ServiceCallContext<'a> {
        ServiceCallContext {
            block_height: 1,
            block_timestamp: 1,
            chain_id: ChainId(1),
            signer_account_id: AccountId([7u8; 32]),
            services,
            simulation: false,
            is_internal: false,
        }
    }

    async fn await_child_worker_result(
        service: &DesktopAgentService,
        state: &mut dyn StateAccess,
        parent_state: &mut AgentState,
        parent_step_index: u32,
        block_height: u64,
        child_session_id_hex: &str,
    ) -> Result<String, String> {
        let services = ServiceDirectory::new(Vec::new());
        await_child_worker_result_impl(
            service,
            state,
            parent_state,
            parent_step_index,
            block_height,
            test_call_context(&services),
            child_session_id_hex,
        )
        .await
    }

    async fn seed_runtime_skill(
        service: &DesktopAgentService,
        state: &mut dyn StateAccess,
        query_anchor: &str,
    ) {
        let memory_runtime = service
            .memory_runtime
            .as_ref()
            .expect("memory runtime should be configured");
        let skill = AgentMacro {
            definition: LlmToolDefinition {
                name: "research__benchmark_scorecard".to_string(),
                description:
                    "Assemble a source-grounded benchmark scorecard for the active research route."
                        .to_string(),
                parameters: r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
            },
            steps: vec![ActionRequest {
                target: ActionTarget::BrowserInteract,
                params: br#"{"__ioi_tool_name":"web__search","query":"{{topic}} benchmark scorecard"}"#
                    .to_vec(),
                context: ActionContext {
                    agent_id: "macro".to_string(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            }],
            source_trace_hash: [0x33; 32],
            fitness: 1.0,
        };
        let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
        let content = format!(
            "{} {}",
            skill_archival_content(&skill.definition),
            query_anchor
        );
        let archival_record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: SKILL_ARCHIVAL_SCOPE.to_string(),
                thread_id: None,
                kind: SKILL_ARCHIVAL_KIND.to_string(),
                content: content.clone(),
                metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                    .expect("skill metadata"),
            })
            .expect("insert skill archival record")
            .expect("archival store available");
        let embedding = service
            .reasoning_inference
            .embed_text(&content)
            .await
            .expect("embed skill");
        memory_runtime
            .upsert_archival_embedding(archival_record_id, &embedding)
            .expect("index skill embedding");

        upsert_skill_record(
            state,
            &SkillRecord {
                skill_hash,
                archival_record_id,
                macro_body: skill,
                lifecycle_state: SkillLifecycleState::Validated,
                source_type: SkillSourceType::Imported,
                source_session_id: None,
                source_evidence_hash: None,
                benchmark: None,
                publication: None,
                created_at: 1,
                updated_at: 1,
            },
        )
        .expect("persist skill record");
    }

    async fn seed_runtime_artifact_skill(
        service: &DesktopAgentService,
        state: &mut dyn StateAccess,
        query_anchor: &str,
    ) {
        let memory_runtime = service
            .memory_runtime
            .as_ref()
            .expect("memory runtime should be configured");
        let skill = AgentMacro {
            definition: LlmToolDefinition {
                name: "artifact__frontend_judge_spine".to_string(),
                description:
                    "Shape artifact generation toward bold frontend execution and presentation-first judge checks."
                        .to_string(),
                parameters: r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
            },
            steps: vec![ActionRequest {
                target: ActionTarget::BrowserInteract,
                params: br#"{"__ioi_tool_name":"filesystem__write_file","path":"artifact-preview.html"}"#
                    .to_vec(),
                context: ActionContext {
                    agent_id: "macro".to_string(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            }],
            source_trace_hash: [0x34; 32],
            fitness: 1.0,
        };
        let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
        let content = format!(
            "{} {}",
            skill_archival_content(&skill.definition),
            query_anchor
        );
        let archival_record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: SKILL_ARCHIVAL_SCOPE.to_string(),
                thread_id: None,
                kind: SKILL_ARCHIVAL_KIND.to_string(),
                content: content.clone(),
                metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                    .expect("skill metadata"),
            })
            .expect("insert skill archival record")
            .expect("archival store available");
        let embedding = service
            .reasoning_inference
            .embed_text(&content)
            .await
            .expect("embed skill");
        memory_runtime
            .upsert_archival_embedding(archival_record_id, &embedding)
            .expect("index skill embedding");

        upsert_skill_record(
            state,
            &SkillRecord {
                skill_hash,
                archival_record_id,
                macro_body: skill,
                lifecycle_state: SkillLifecycleState::Validated,
                source_type: SkillSourceType::Imported,
                source_session_id: None,
                source_evidence_hash: None,
                benchmark: None,
                publication: None,
                created_at: 1,
                updated_at: 1,
            },
        )
        .expect("persist skill record");
    }

    async fn seed_runtime_computer_use_skill(
        service: &DesktopAgentService,
        state: &mut dyn StateAccess,
        query_anchor: &str,
    ) {
        let memory_runtime = service
            .memory_runtime
            .as_ref()
            .expect("memory runtime should be configured");
        let skill = AgentMacro {
            definition: LlmToolDefinition {
                name: "computer_use__ui_state_spine".to_string(),
                description:
                    "Prime the computer-use perception lane to identify the live target state, approval risk, and next safe action."
                        .to_string(),
                parameters: r#"{"type":"object","properties":{"topic":{"type":"string"}},"required":["topic"]}"#
                    .to_string(),
            },
            steps: vec![ActionRequest {
                target: ActionTarget::BrowserInteract,
                params: br#"{"__ioi_tool_name":"browser__snapshot"}"#.to_vec(),
                context: ActionContext {
                    agent_id: "macro".to_string(),
                    session_id: None,
                    window_id: None,
                },
                nonce: 0,
            }],
            source_trace_hash: [0x35; 32],
            fitness: 1.0,
        };
        let skill_hash = canonical_skill_hash(&skill).expect("skill hash");
        let content = format!(
            "{} {}",
            skill_archival_content(&skill.definition),
            query_anchor
        );
        let archival_record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: SKILL_ARCHIVAL_SCOPE.to_string(),
                thread_id: None,
                kind: SKILL_ARCHIVAL_KIND.to_string(),
                content: content.clone(),
                metadata_json: build_skill_archival_metadata_json(skill_hash, &skill)
                    .expect("skill metadata"),
            })
            .expect("insert skill archival record")
            .expect("archival store available");
        let embedding = service
            .reasoning_inference
            .embed_text(&content)
            .await
            .expect("embed skill");
        memory_runtime
            .upsert_archival_embedding(archival_record_id, &embedding)
            .expect("index skill embedding");

        upsert_skill_record(
            state,
            &SkillRecord {
                skill_hash,
                archival_record_id,
                macro_body: skill,
                lifecycle_state: SkillLifecycleState::Validated,
                source_type: SkillSourceType::Imported,
                source_session_id: None,
                source_evidence_hash: None,
                benchmark: None,
                publication: None,
                created_at: 1,
                updated_at: 1,
            },
        )
        .expect("persist skill record");
    }

    async fn seed_runtime_fact(service: &DesktopAgentService, content: &str) {
        let memory_runtime = service
            .memory_runtime
            .as_ref()
            .expect("memory runtime should be configured");
        let record_id = memory_runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "desktop.facts".to_string(),
                thread_id: None,
                kind: "fact".to_string(),
                content: content.to_string(),
                metadata_json:
                    r#"{"role":"fact","trust_level":"standard","source":"worker_results_test"}"#
                        .to_string(),
            })
            .expect("insert fact archival record")
            .expect("archival store available");
        let embedding = service
            .reasoning_inference
            .embed_text(content)
            .await
            .expect("embed fact");
        memory_runtime
            .upsert_archival_embedding(record_id, &embedding)
            .expect("index fact embedding");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_child_worker_result_steps_running_child_once() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x31; 32],
            "Inspect the repo and return a bounded context brief.",
            32,
            None,
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("delegated child should spawn");

        let child_key = get_state_key(&spawned.child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        let initial_step_count = child_state.step_count;
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
            }))
            .expect("agent__complete params should encode"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(spawned.child_session_id),
                window_id: None,
            },
            nonce: 1,
        });
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(spawned.child_session_id),
        )
        .await
        .expect("await should step the child result");

        assert!(
            merged == "Running" || merged.contains("Likely files: path_utils.py"),
            "unexpected awaited child output: {merged}"
        );
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let updated_child: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(
            updated_child.step_count > initial_step_count,
            "awaited child step should advance step count"
        );
        match merged.as_str() {
            "Running" => {
                assert!(matches!(
                    updated_child.status,
                    AgentStatus::Running | AgentStatus::Paused(_)
                ));
                assert!(
                    load_worker_session_result(&state, spawned.child_session_id)
                        .expect("worker result lookup should succeed")
                        .is_none(),
                    "worker result should not materialize before the child completes"
                );
            }
            _ => {
                assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
                let worker_result = load_worker_session_result(&state, spawned.child_session_id)
                    .expect("worker result lookup should succeed")
                    .expect("worker result should exist");
                assert!(worker_result.merged_at_ms.is_some());
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn playbook_managed_child_enables_await_burst() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx.clone());
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x33; 32],
            "Inspect the repo and return a bounded context brief.",
            32,
            Some("unit_test_playbook"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("delegated child should spawn");

        assert!(
            child_allows_await_burst(&state, spawned.child_session_id)
                .expect("playbook burst gating should load"),
            "playbook-managed child should be eligible for burst stepping while awaited"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coding_patch_worker_enables_await_burst() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Patch the workspace", 256);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x34; 32],
            "Implement the parity fix as a narrow patch.",
            64,
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
            3,
            0,
        )
        .await
        .expect("coding child should spawn");

        assert!(
            child_allows_await_burst(&state, spawned.child_session_id)
                .expect("coding burst gating should load"),
            "local coding worker should stay eligible for burst stepping"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn generic_patch_build_verify_child_inherits_parent_contract_context() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let repo = temp_dir.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");

        let parent_goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it converts backslashes to forward slashes, collapses duplicate separators, and preserves a leading `./` or `/`. Run the focused verification command `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, verify the final postcondition, and report the touched files plus command results.",
            repo.display()
        );
        let mut parent_state = build_parent_state_with_goal(&parent_goal, 128);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x35; 32],
            "Edit the code in the specified file to match the regex pattern for replacing text blocks.",
            64,
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
            3,
            0,
        )
        .await
        .expect("coding child should spawn");

        assert!(spawned
            .assignment
            .goal
            .contains("[PARENT PLAYBOOK CONTEXT]"));
        assert!(spawned
            .assignment
            .goal
            .contains("delegated_task_contract: Port the path-normalization parity fix"));
        assert!(spawned
            .assignment
            .goal
            .contains("- likely_files: path_utils.py; tests/test_path_utils.py"));
        assert!(spawned
            .assignment
            .goal
            .contains("- targeted_checks: python3 -m unittest tests.test_path_utils -v"));
        assert!(spawned
            .assignment
            .goal
            .contains("converts backslashes to forward slashes"));
        assert!(spawned
            .assignment
            .goal
            .contains("preserves a leading `./` or `/`"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_audit_worker_enables_await_burst() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state =
            build_parent_state_with_goal("Verify the cited brief before merge", 128);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x36; 32],
            "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources.",
            64,
            Some("citation_grounded_brief"),
            Some("verifier"),
            Some("citation_audit"),
            None,
            None,
            None,
            None,
            4,
            0,
        )
        .await
        .expect("citation verifier should spawn");

        assert!(
            child_allows_await_burst(&state, spawned.child_session_id)
                .expect("citation verifier burst gating should load"),
            "receipt-bound citation verifier should stay eligible for burst stepping"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn postcondition_audit_worker_enables_await_burst() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state =
            build_parent_state_with_goal("Verify the claimed postcondition", 128);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x37; 32],
            "Verify whether the parser regression fix satisfies the postcondition.",
            64,
            Some("unit_test_playbook"),
            Some("verifier"),
            Some("postcondition_audit"),
            None,
            None,
            None,
            None,
            4,
            0,
        )
        .await
        .expect("postcondition verifier should spawn");

        assert!(
            child_allows_await_burst(&state, spawned.child_session_id)
                .expect("postcondition verifier burst gating should load"),
            "local postcondition verifier should stay eligible for burst stepping"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn research_worker_uses_bounded_await_burst_for_web_workflow() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Research the current standards", 128);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x35; 32],
            "Research the latest standards and return a cited brief.",
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            4,
            0,
        )
        .await
        .expect("research child should spawn");

        assert!(
            child_allows_await_burst(&state, spawned.child_session_id)
                .expect("research burst gating should load"),
            "web-facing research worker should stay eligible for a bounded await burst"
        );
        let child_state = load_child_state(
            &state,
            service.memory_runtime.as_ref(),
            spawned.child_session_id,
            &hex::encode(spawned.child_session_id),
        )
        .expect("research child state should load");
        assert_eq!(
            await_child_burst_step_limit(&state, spawned.child_session_id, &child_state)
                .expect("research burst limit should load"),
            LIVE_RESEARCH_AWAIT_BURST_STEPS
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_child_worker_result_resumes_retry_blocked_child_once() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x32; 32],
            "Inspect repo context and return a bounded context brief.",
            32,
            None,
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("delegated child should spawn");

        let child_key = get_state_key(&spawned.child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        child_state.status =
            AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".into());
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
            }))
            .expect("agent__complete params should encode"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(spawned.child_session_id),
                window_id: None,
            },
            nonce: 1,
        });
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(spawned.child_session_id),
        )
        .await
        .expect("await should resume and step the child result");

        assert!(
            merged.starts_with("Running") || merged.contains("Likely files: path_utils.py"),
            "unexpected awaited child output after retry-block resume: {merged}"
        );
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let updated_child: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(
            !matches!(
                &updated_child.status,
                AgentStatus::Paused(reason) if retry_blocked_pause_reason(reason)
            ),
            "retry-blocked child should leave the retry-block pause after awaited resume"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_child_worker_result_merges_observed_patch_completion_from_retry_blocked_pause() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Patch the workspace", 256);

        let repo = temp_dir.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");
        std::fs::write(
            repo.join("path_utils.py"),
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
            ),
        )
        .expect("fixture source should exist");
        std::fs::write(repo.join("tests/test_path_utils.py"), "import unittest\n")
            .expect("fixture test should exist");

        let goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            repo.display()
        );
        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x73; 32],
            &goal,
            96,
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("patch child should spawn");

        let child_key = get_state_key(&spawned.child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        child_state.status =
            AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".into());
        child_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "FAILED (failures=2)".to_string(),
            timestamp_ms: 1,
            step_index: 2,
        });
        child_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            timestamp_ms: 2,
            step_index: 5,
        });
        child_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(format!(
                "step=4;tool=filesystem__write_file;path={}",
                repo.join("path_utils.py").display()
            )),
        );
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(spawned.child_session_id),
        )
        .await
        .expect("await should merge observed completion from retry-blocked pause");

        assert!(merged.contains("Touched files: path_utils.py"), "{merged}");
        assert!(
            merged.contains("advanced to 'Verify targeted tests'"),
            "{merged}"
        );

        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let updated_child: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_child_worker_result_extends_burst_for_patch_verify_post_edit_followup() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state_with_goal("Patch the workspace", 128);
        let parent_key = get_state_key(&parent_state.session_id);
        state
            .insert(
                &parent_key,
                &codec::to_bytes_canonical(&parent_state).expect("parent state encode"),
            )
            .expect("parent state insert should succeed");
        let parent_rules = ActionRules {
            policy_id: "capabilities-suite".to_string(),
            defaults: DefaultPolicy::AllowAll,
            ..ActionRules::default()
        };
        let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
        state
            .insert(
                &parent_policy_key,
                &codec::to_bytes_canonical(&parent_rules).expect("parent policy encode"),
            )
            .expect("parent policy insert should succeed");

        let repo = temp_dir.path().join("path-normalizer-fixture");
        std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");
        std::fs::write(
            repo.join("path_utils.py"),
            concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
            ),
        )
        .expect("fixture source should exist");
        std::fs::write(repo.join("tests/test_path_utils.py"), "import unittest\n")
            .expect("fixture test should exist");

        let goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            repo.display()
        );
        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x72; 32],
            &goal,
            96,
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("patch child should spawn");

        let child_key = get_state_key(&spawned.child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        child_state
            .command_history
            .push_back(crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: "targeted tests failed".to_string(),
                stderr: String::new(),
                timestamp_ms: 1,
                step_index: 0,
            });

        let repo_path = repo.to_string_lossy().to_string();
        let tests_path = repo.join("tests").to_string_lossy().to_string();
        let source_path = repo.join("path_utils.py").to_string_lossy().to_string();
        let test_path = repo
            .join("tests/test_path_utils.py")
            .to_string_lossy()
            .to_string();
        let context = ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(spawned.child_session_id),
            window_id: None,
        };

        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_jcs::to_vec(&serde_json::json!({
                "__ioi_tool_name": "filesystem__list_directory",
                "path": repo_path
            }))
            .expect("list repo params should encode"),
            context: context.clone(),
            nonce: 1,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_jcs::to_vec(&serde_json::json!({
                "__ioi_tool_name": "filesystem__list_directory",
                "path": tests_path
            }))
            .expect("list tests params should encode"),
            context: context.clone(),
            nonce: 2,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_jcs::to_vec(&serde_json::json!({ "path": source_path }))
                .expect("read source params should encode"),
            context: context.clone(),
            nonce: 3,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_jcs::to_vec(&serde_json::json!({ "path": test_path }))
                .expect("read test params should encode"),
            context: context.clone(),
            nonce: 4,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsRead,
            params: serde_jcs::to_vec(&serde_json::json!({
                "path": repo.to_string_lossy().to_string(),
                "regex": "normalize_fixture_path"
            }))
            .expect("search params should encode"),
            context: context.clone(),
            nonce: 5,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::FsWrite,
            params: serde_jcs::to_vec(&serde_json::json!({
                "path": "path_utils.py",
                "content": concat!(
                    "def normalize_fixture_path(raw_path: str) -> str:\n",
                    "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                    "    prefix = \"\"\n",
                    "    if raw_path.startswith(\"./\"):\n",
                    "        prefix = \"./\"\n",
                    "        raw_path = raw_path[2:]\n",
                    "    elif raw_path.startswith(\"/\"):\n",
                    "        prefix = \"/\"\n",
                    "        raw_path = raw_path[1:]\n",
                    "    normalized = raw_path.replace(\"\\\\\", \"/\")\n",
                    "    while \"//\" in normalized:\n",
                    "        normalized = normalized.replace(\"//\", \"/\")\n",
                    "    return prefix + normalized\n"
                )
            }))
            .expect("write params should encode"),
            context: context.clone(),
            nonce: 6,
        });
        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (queued after edit)"
            }))
            .expect("complete params should encode"),
            context,
            nonce: 7,
        });
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(spawned.child_session_id),
        )
        .await
        .expect("await should consume post-edit followup burst");

        let child_bytes = state
            .get(&child_key)
            .expect("child lookup should succeed")
            .expect("child state should exist");
        let updated_child: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(
            merged.contains("Touched files: path_utils.py"),
            "unexpected awaited child output: {merged}; status={:?}; step_count={}; queue_len={}; next_targets={:?}; workspace_edit_receipt={:?}; recent_actions={:?}; tool_execution_log_keys={:?}; source_contents={}",
            updated_child.status,
            updated_child.step_count,
            updated_child.execution_queue.len(),
            updated_child
                .execution_queue
                .iter()
                .map(|request| format!("{:?}", request.target))
                .collect::<Vec<_>>(),
            execution_receipt_value(&updated_child.tool_execution_log, "workspace_edit_applied"),
            updated_child.recent_actions,
            updated_child
                .tool_execution_log
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            std::fs::read_to_string(repo.join("path_utils.py"))
                .unwrap_or_else(|error| format!("<read failed: {error}>")),
        );
        assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
        assert!(
            execution_receipt_value(&updated_child.tool_execution_log, "workspace_edit_applied")
                .is_some(),
            "workspace edit receipt should be present after the awaited write"
        );
        let worker_result = load_worker_session_result(&state, spawned.child_session_id)
            .expect("worker result lookup should succeed")
            .expect("worker result should exist");
        assert!(worker_result
            .merged_output
            .contains("Touched files: path_utils.py"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn artifact_generation_gate_surfaces_context_generation_and_quality_receipts() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(64);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic =
            "Generate a launch landing page artifact and verify the retained HTML is ready for presentation.";
        let preview_assignment = resolve_worker_assignment(
            [0x81; 32],
            13,
            96,
            topic,
            Some("artifact_generation_gate"),
            Some("context_worker"),
            Some("artifact_context_brief"),
            None,
            None,
            None,
            None,
        );
        let retrieval_anchor = format!(
            "{} Prior note: strong artifact runs keep the hero contrast crisp and the mobile CTA stack stable.",
            preview_assignment.goal
        );
        seed_runtime_artifact_skill(&service, &mut state, &preview_assignment.goal).await;
        seed_runtime_fact(&service, &retrieval_anchor).await;

        let mut parent_state = build_parent_state_with_goal(topic, 320);
        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x82; 32],
            topic,
            196,
            Some("artifact_generation_gate"),
            Some("context_worker"),
            Some("artifact_context_brief"),
            None,
            None,
            None,
            None,
            13,
            0,
        )
        .await
        .expect("artifact context step should spawn");
        let context_id = context.child_session_id;
        assert_eq!(
            context.assignment.workflow_id.as_deref(),
            Some("artifact_context_brief")
        );

        let run_after_spawn =
            load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
                .expect("artifact playbook run lookup should succeed")
                .expect("artifact playbook run should exist");
        assert_eq!(
            run_after_spawn.steps[0].status,
            ParentPlaybookStepStatus::Running
        );
        assert!(run_after_spawn.steps[0]
            .selected_skills
            .iter()
            .any(|skill| skill == "artifact__frontend_judge_spine"));
        assert!(run_after_spawn.steps[0]
            .prep_summary
            .as_deref()
            .map(str::trim)
            .is_some_and(|summary| !summary.is_empty()));

        let context_key = get_state_key(&context_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "- artifact_goal: Bold editorial landing page with a clear launch narrative.\n- likely_output_files: apps/site/index.html; apps/site/styles.css\n- selected_skills: artifact__frontend_judge_spine\n- verification_plan: Check desktop/mobile hierarchy, hero contrast, and CTA visibility.\n- notes: Keep motion restrained and typography expressive."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            14,
            0,
            &hex::encode(context_id),
        )
        .await
        .expect("context merge should advance artifact playbook");
        assert!(
            merged_context.contains("Playbook: Artifact Context Brief (artifact_context_brief)")
        );
        assert!(merged_context.contains("advanced to 'Generate artifact'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
                .expect("artifact playbook run lookup should succeed")
                .expect("artifact playbook run should exist");
        assert_eq!(
            run_after_context.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_context.steps[1].status,
            ParentPlaybookStepStatus::Running
        );
        let build_id = run_after_context
            .active_child_session_id
            .expect("artifact builder should be active");

        let build_key = get_state_key(&build_id);
        let build_bytes = state
            .get(&build_key)
            .expect("build state lookup should succeed")
            .expect("build state should exist");
        let mut build_state: AgentState =
            codec::from_bytes_canonical(&build_bytes).expect("build state should decode");
        assert!(build_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        assert!(build_state.goal.contains("artifact__frontend_judge_spine"));
        build_state.status = AgentStatus::Completed(Some(
            "- produced_files: apps/site/index.html; apps/site/styles.css\n- verification_signals: Preview build passed; responsive screenshot captured.\n- presentation_status: needs_repair\n- repair_status: required\n- notes: Mobile hero copy overlaps the CTA at the narrow breakpoint."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &build_key,
            &build_state,
            service.memory_runtime.as_ref(),
        )
        .expect("build state update should persist");

        let merged_build = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            15,
            0,
            &hex::encode(build_id),
        )
        .await
        .expect("build merge should advance artifact playbook");
        assert!(merged_build
            .contains("Playbook: Artifact Generate and Repair (artifact_generate_repair)"));
        assert!(merged_build.contains("advanced to 'Judge artifact quality'"));

        let run_after_build =
            load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
                .expect("artifact playbook run lookup should succeed")
                .expect("artifact playbook run should exist");
        assert_eq!(
            run_after_build.steps[1].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_build.steps[1]
                .artifact_generation
                .as_ref()
                .map(|summary| summary.produced_file_count),
            Some(2)
        );
        assert_eq!(
            run_after_build.steps[1]
                .artifact_repair
                .as_ref()
                .map(|summary| summary.status.as_str()),
            Some("required")
        );
        assert_eq!(
            run_after_build.steps[2].status,
            ParentPlaybookStepStatus::Running
        );
        let judge_id = run_after_build
            .active_child_session_id
            .expect("artifact judge should be active");

        let judge_key = get_state_key(&judge_id);
        let judge_bytes = state
            .get(&judge_key)
            .expect("judge state lookup should succeed")
            .expect("judge state should exist");
        let mut judge_state: AgentState =
            codec::from_bytes_canonical(&judge_bytes).expect("judge state should decode");
        assert!(judge_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        assert!(judge_state.goal.contains("artifact_generation="));
        judge_state.status = AgentStatus::Completed(Some(
            "- verdict: needs_attention\n- fidelity_status: faithful\n- presentation_status: needs_repair\n- repair_status: required\n- next_repair_step: Fix the mobile hero stacking before presentation.\n- notes: Layout intent is strong, but mobile CTA overlap blocks presentation readiness."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &judge_key,
            &judge_state,
            service.memory_runtime.as_ref(),
        )
        .expect("judge state update should persist");

        let merged_judge = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            16,
            0,
            &hex::encode(judge_id),
        )
        .await
        .expect("judge merge should complete artifact playbook");
        assert!(merged_judge.contains("Playbook: Artifact Quality Audit (artifact_quality_audit)"));
        assert!(merged_judge.contains("Parent playbook 'Artifact Generation Gate' completed."));

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
                .expect("final artifact playbook run lookup should succeed")
                .expect("final artifact playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
        assert!(final_run
            .steps
            .iter()
            .all(|step| step.status == ParentPlaybookStepStatus::Completed));
        assert_eq!(
            final_run.steps[2]
                .artifact_quality
                .as_ref()
                .map(|scorecard| scorecard.verdict.as_str()),
            Some("needs_attention")
        );
        assert_eq!(
            final_run.steps[2]
                .artifact_repair
                .as_ref()
                .map(|summary| summary.status.as_str()),
            Some("required")
        );

        let mut parent_receipts = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                    parent_receipts.push(receipt);
                }
            }
        }

        let parent_receipt_phases = parent_receipts
            .iter()
            .map(|receipt| receipt.phase.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            parent_receipt_phases,
            vec![
                "started".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "completed".to_string(),
            ]
        );
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.route_family == "artifacts"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.planner_authority == "kernel"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.verifier_role == "artifact_quality_verifier"));
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_spawned" && receipt.step_id.as_deref() == Some("context")
                })
                .map(|receipt| receipt.selected_skills.clone())
                .unwrap_or_default(),
            vec!["artifact__frontend_judge_spine".to_string()]
        );
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("build")
                })
                .and_then(|receipt| receipt.artifact_generation.as_ref())
                .map(|summary| summary.produced_file_count),
            Some(2)
        );
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("judge")
                })
                .and_then(|receipt| receipt.artifact_quality.as_ref())
                .map(|scorecard| scorecard.presentation_status.as_str()),
            Some("needs_repair")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.selected_skills.clone())
                .unwrap_or_default(),
            vec!["artifact__frontend_judge_spine".to_string()]
        );
        assert!(parent_receipts
            .last()
            .and_then(|receipt| receipt.prep_summary.as_deref())
            .map(str::trim)
            .is_some_and(|summary| !summary.is_empty()));
        assert_eq!(
            parent_receipts
                .last()
                .and_then(|receipt| receipt.artifact_repair.as_ref())
                .map(|summary| summary.status.as_str()),
            Some("required")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_state.as_str()),
            Some("passed")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_outcome.as_str()),
            Some("warning")
        );
    }

    #[test]
    fn resolve_researcher_assignment_uses_template_defaults() {
        let assignment = resolve_worker_assignment(
            [0x11; 32],
            4,
            120,
            "Research latest grounding receipts",
            None,
            Some("researcher"),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(assignment.role.as_deref(), Some("Research Worker"));
        assert_eq!(
            assignment.workflow_id.as_deref(),
            Some("live_research_brief")
        );
        assert_eq!(
            assignment.completion_contract.merge_mode,
            WorkerMergeMode::AppendSummaryToParent
        );
        assert!(assignment
            .goal
            .contains("using current web and local memory evidence"));
        assert!(assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "web__search"));
    }

    #[test]
    fn append_as_evidence_merge_renders_stable_handoff() {
        let mut assignment = resolve_worker_assignment(
            [0x22; 32],
            2,
            40,
            "Verify whether the parent claim is supported",
            None,
            Some("verifier"),
            None,
            None,
            None,
            Some("append_as_evidence"),
            None,
        );
        assignment.completion_contract.verification_hint =
            Some("Check whether the cited evidence satisfies the claim.".to_string());

        let merged = merged_worker_output(
            &assignment,
            true,
            Some("The claim is supported by two matching primary sources."),
            None,
        );

        assert!(merged.contains("Worker evidence"));
        assert!(merged.contains("parent claim is supported"));
        assert!(merged.contains("The claim is supported by two matching primary sources."));
        assert!(merged.contains("Verification hint"));
    }

    #[test]
    fn context_worker_playbook_merge_preserves_playbook_identity() {
        let assignment = resolve_worker_assignment(
            [0x33; 32],
            3,
            64,
            "Capture repo context for the routing regression.",
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
        );

        let merged = merged_worker_output(
            &assignment,
            true,
            Some("Likely files: crates/services/src/router.rs\nTargeted checks: cargo test -p ioi-services routing_contracts -- --nocapture"),
            None,
        );

        assert!(merged.contains("Parent playbook: evidence_audited_patch"));
        assert!(merged.contains("Playbook: Repo Context Brief (repo_context_brief)"));
        assert!(merged.contains("Likely files: crates/services/src/router.rs"));
    }

    #[test]
    fn verifier_playbook_overrides_budget_retries_and_tools() {
        let assignment = resolve_worker_assignment(
            [0x34; 32],
            5,
            120,
            "Verify whether the receipt proves the postcondition.",
            None,
            Some("verifier"),
            Some("postcondition_audit"),
            None,
            None,
            None,
            None,
        );

        assert_eq!(
            assignment.workflow_id.as_deref(),
            Some("postcondition_audit")
        );
        assert_eq!(assignment.budget, 48);
        assert_eq!(assignment.max_retries, 0);
        assert!(assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "model__rerank"));
        assert!(assignment
            .allowed_tools
            .iter()
            .all(|tool| tool != "model__responses"));
        assert_eq!(
            assignment.completion_contract.merge_mode,
            WorkerMergeMode::AppendAsEvidence
        );
    }

    #[test]
    fn citation_audit_assignment_uses_research_specific_contract() {
        let assignment = resolve_worker_assignment(
            [0x35; 32],
            5,
            120,
            "Verify whether the cited brief is fresh and quote-grounded.",
            Some("citation_grounded_brief"),
            Some("verifier"),
            Some("citation_audit"),
            None,
            None,
            None,
            None,
        );

        assert_eq!(assignment.workflow_id.as_deref(), Some("citation_audit"));
        assert_eq!(assignment.budget, 48);
        assert_eq!(assignment.max_retries, 0);
        assert!(assignment
            .completion_contract
            .expected_output
            .contains("Citation verifier scorecard"));
        assert!(assignment
            .completion_contract
            .verification_hint
            .as_deref()
            .is_some_and(|hint| hint.contains("freshness")));
    }

    #[test]
    fn coder_playbook_overrides_budget_retries_and_tools() {
        let assignment = resolve_worker_assignment(
            [0x35; 32],
            6,
            140,
            "Patch the parser regression, run focused verification, and summarize the outcome.",
            None,
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );

        assert_eq!(
            assignment.workflow_id.as_deref(),
            Some("patch_build_verify")
        );
        assert_eq!(assignment.budget, 96);
        assert_eq!(assignment.max_retries, 1);
        assert!(assignment
            .goal
            .contains("run focused verification commands"));
        assert!(!assignment.goal.contains("Implement Implement"));
        assert!(assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "filesystem__patch"));
        assert!(assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "sys__exec_session"));
        assert!(assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "agent__complete"));
        assert!(assignment
            .allowed_tools
            .iter()
            .all(|tool| tool != "model__responses"));
        assert_eq!(
            assignment.completion_contract.merge_mode,
            WorkerMergeMode::AppendSummaryToParent
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delegated_research_playbook_flows_through_spawn_and_merge_receipts() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state();

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x44; 32],
            "Research the latest kernel scheduler benchmarks.",
            2,
            None,
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            3,
            0,
        )
        .await
        .expect("delegated child should spawn");
        let child_session_id = spawned.child_session_id;
        assert_eq!(spawned.assignment.budget, 2);
        assert_eq!(
            spawned.assignment.workflow_id.as_deref(),
            Some("live_research_brief")
        );

        let child_key = get_state_key(&child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child state lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(child_state
            .goal
            .contains("using current web and local memory evidence"));

        child_state.status = AgentStatus::Completed(Some(
            "Cited brief with three benchmark sources and one unresolved discrepancy.".to_string(),
        ));
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(child_session_id),
        )
        .await
        .expect("await result should merge");

        assert!(merged.contains("Playbook: Live Research Brief (live_research_brief)"));
        assert!(merged.contains("Cited brief with three benchmark sources"));

        let mut completion_saw_workflow = false;
        let mut merge_saw_workflow = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                    match receipt.phase.as_str() {
                        "completed" => {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                            completion_saw_workflow = true;
                        }
                        "merged" => {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                            merge_saw_workflow = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(
            completion_saw_workflow,
            "completion receipt should preserve workflow id"
        );
        assert!(
            merge_saw_workflow,
            "merge receipt should preserve workflow id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_surfaces_selected_skills_and_prep_summary() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest kernel scheduler benchmark scorecards.";
        let preview_assignment = resolve_worker_assignment(
            [0x71; 32],
            2,
            64,
            topic,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
        );
        let retrieval_anchor = format!(
            "{} Prior note: planner-specialist-verifier routing improved citation coverage on the last comparison pass.",
            preview_assignment.goal
        );
        seed_runtime_skill(&service, &mut state, &preview_assignment.goal).await;
        seed_runtime_fact(&service, &retrieval_anchor).await;

        let mut parent_state = build_parent_state_with_goal(topic, 128);
        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x72; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        assert_eq!(
            spawned.assignment.playbook_id.as_deref(),
            Some("citation_grounded_brief")
        );
        assert_eq!(
            spawned.assignment.workflow_id.as_deref(),
            Some("live_research_brief")
        );

        let run =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("parent playbook load should succeed")
                .expect("parent playbook run should exist");
        assert_eq!(run.steps[0].status, ParentPlaybookStepStatus::Running);
        assert!(run.steps[0]
            .selected_skills
            .iter()
            .any(|skill| skill == "research__benchmark_scorecard"));
        assert!(run.steps[0]
            .prep_summary
            .as_deref()
            .map(str::trim)
            .is_some_and(|summary| !summary.is_empty()));

        let mut saw_memory_receipt = false;
        let mut saw_parent_started = false;
        let mut saw_parent_step_spawn = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::MemoryRetrieve(receipt) => {
                        assert_eq!(receipt.tool_name, "memory__search");
                        saw_memory_receipt = true;
                    }
                    WorkloadReceipt::ParentPlaybook(receipt) => {
                        if receipt.phase == "started" {
                            assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                            assert!(receipt
                                .selected_skills
                                .iter()
                                .any(|skill| skill == "research__benchmark_scorecard"));
                            assert!(receipt
                                .prep_summary
                                .as_deref()
                                .map(str::trim)
                                .is_some_and(|summary| !summary.is_empty()));
                            saw_parent_started = true;
                        } else if receipt.phase == "step_spawned" {
                            assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                            assert!(receipt
                                .selected_skills
                                .iter()
                                .any(|skill| skill == "research__benchmark_scorecard"));
                            assert!(receipt
                                .prep_summary
                                .as_deref()
                                .map(str::trim)
                                .is_some_and(|summary| !summary.is_empty()));
                            saw_parent_step_spawn = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_memory_receipt,
            "research prep should emit a memory receipt"
        );
        assert!(
            saw_parent_started,
            "started receipt should carry selected skills and prep summary"
        );
        assert!(
            saw_parent_step_spawn,
            "step_spawned receipt should carry selected skills and prep summary"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_blocks_parent_playbook_on_failed_research_worker() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest kernel scheduler benchmark scorecards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x7a; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Failed(
            "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
                .to_string(),
        );
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let blocked = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("failed research worker should block playbook instead of pausing parent");

        assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
        assert!(blocked.contains("Cognition inference timed out after 60000ms"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("research playbook run lookup should succeed")
                .expect("research playbook run should exist");
        assert_eq!(run_after_research.status, ParentPlaybookStatus::Blocked);
        assert_eq!(
            run_after_research.steps[0].status,
            ParentPlaybookStepStatus::Blocked
        );
        assert!(run_after_research.active_child_session_id.is_none());
        assert_eq!(
            run_after_research.steps[0].error.as_deref(),
            Some(
                "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
            )
        );
        assert!(matches!(
            &parent_state.status,
            AgentStatus::Failed(reason)
                if reason.contains("Cognition inference timed out after 60000ms")
        ));

        let mut saw_worker_merge = false;
        let mut saw_playbook_blocked = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        assert!(!receipt.success);
                        saw_worker_merge = true;
                    }
                    WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                        assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        assert_eq!(receipt.error_class.as_deref(), Some("TimeoutOrHang"));
                        saw_playbook_blocked = true;
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_worker_merge,
            "failed worker should still emit a merge receipt"
        );
        assert!(
            saw_playbook_blocked,
            "parent playbook should emit a blocked receipt"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_blocks_parent_playbook_on_empty_research_handoff() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest kernel scheduler benchmark scorecards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x7c; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Completed(None);
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let blocked = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("empty research handoff should block playbook");

        assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
        assert!(blocked.contains("IncompleteWorkerResult"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("research playbook run lookup should succeed")
                .expect("research playbook run should exist");
        assert_eq!(run_after_research.status, ParentPlaybookStatus::Blocked);
        assert_eq!(
            run_after_research.steps[0].status,
            ParentPlaybookStepStatus::Blocked
        );
        assert!(run_after_research.active_child_session_id.is_none());
        assert_eq!(
            run_after_research.steps[0].error.as_deref(),
            Some(
                "ERROR_CLASS=IncompleteWorkerResult Delegated worker completed without an explicit result."
            )
        );
        assert!(matches!(
            &parent_state.status,
            AgentStatus::Failed(reason) if reason.contains("IncompleteWorkerResult")
        ));

        let mut saw_worker_merge = false;
        let mut saw_playbook_blocked = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        assert!(!receipt.success);
                        assert_eq!(
                            receipt.error_class.as_deref(),
                            Some("IncompleteWorkerResult")
                        );
                        saw_worker_merge = true;
                    }
                    WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                        assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        assert_eq!(
                            receipt.error_class.as_deref(),
                            Some("IncompleteWorkerResult")
                        );
                        saw_playbook_blocked = true;
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_worker_merge,
            "empty worker handoff should still emit a merge receipt"
        );
        assert!(
            saw_playbook_blocked,
            "parent playbook should emit a blocked receipt for empty worker handoff"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_blocks_parent_playbook_on_system_fail_verifier_worker() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest kernel scheduler benchmark scorecards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x7b; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Completed(Some(
            "Findings:\n- Linux 6.9 scheduler latency improved in recent tests.\nSources:\n- https://www.kernel.org/doc/html/latest/scheduler/index.html\n- https://lwn.net/Articles/123456/\nFreshness note: checked on 2026-03-31."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let merged_research = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("research merge should advance playbook");
        assert!(merged_research.contains("advanced to 'Verify grounding'"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("research playbook run lookup should succeed")
                .expect("research playbook run should exist");
        let verify_id = run_after_research
            .active_child_session_id
            .expect("citation verifier should be active");

        let verify_key = get_state_key(&verify_id);
        let verify_bytes = state
            .get(&verify_key)
            .expect("verifier state lookup should succeed")
            .expect("verifier state should exist");
        let mut verify_state: AgentState =
            codec::from_bytes_canonical(&verify_bytes).expect("verifier state should decode");
        verify_state.status = AgentStatus::Failed(
            "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
                .to_string(),
        );
        persist_agent_state(
            &mut state,
            &verify_key,
            &verify_state,
            service.memory_runtime.as_ref(),
        )
        .expect("verifier state update should persist");

        let blocked = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(verify_id),
        )
        .await
        .expect("failed verifier should block playbook");

        assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
        assert!(blocked.contains("Cognition inference timed out after 60000ms"));

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("final playbook run lookup should succeed")
                .expect("final playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Blocked);
        assert_eq!(final_run.steps[1].status, ParentPlaybookStepStatus::Blocked);
        assert_eq!(
            final_run.steps[1].error.as_deref(),
            Some(
                "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
            )
        );
        assert!(matches!(
            &parent_state.status,
            AgentStatus::Failed(reason)
                if reason.contains("Cognition inference timed out after 60000ms")
        ));

        let mut saw_worker_merge = false;
        let mut saw_playbook_blocked = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::Worker(receipt)
                        if receipt.phase == "merged"
                            && receipt.workflow_id.as_deref() == Some("citation_audit") =>
                    {
                        assert!(!receipt.success);
                        saw_worker_merge = true;
                    }
                    WorkloadReceipt::ParentPlaybook(receipt)
                        if receipt.phase == "blocked"
                            && receipt.workflow_id.as_deref() == Some("citation_audit") =>
                    {
                        assert_eq!(receipt.error_class.as_deref(), Some("TimeoutOrHang"));
                        saw_playbook_blocked = true;
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_worker_merge,
            "failed verifier should emit a merge receipt"
        );
        assert!(
            saw_playbook_blocked,
            "failed verifier should emit a blocked playbook receipt"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evidence_audited_patch_blocks_parent_playbook_on_paused_refusal_worker() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Patch only the targeted repo file and verify the focused test first.";
        let mut parent_state = build_parent_state_with_goal(topic, 256);

        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x63; 32],
            topic,
            96,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("context step should spawn");

        let context_key = get_state_key(&context.child_session_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(context.child_session_id),
        )
        .await
        .expect("context merge should advance to implement");
        assert!(merged_context.contains("advanced to 'Patch the workspace'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        let implement_id = run_after_context
            .active_child_session_id
            .expect("implement child should be active");
        let implement_key = get_state_key(&implement_id);
        let implement_bytes = state
            .get(&implement_key)
            .expect("implement state lookup should succeed")
            .expect("implement state should exist");
        let mut implement_state: AgentState =
            codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
        implement_state.status =
            AgentStatus::Paused("Model Refusal: Empty content (reason: stop)".to_string());
        persist_agent_state(
            &mut state,
            &implement_key,
            &implement_state,
            service.memory_runtime.as_ref(),
        )
        .expect("implement state update should persist");

        let blocked = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(implement_id),
        )
        .await
        .expect("paused refusal worker should block parent playbook");

        assert!(blocked.contains("Parent playbook 'Evidence-Audited Patch' blocked"));
        assert!(blocked.contains("Patch the workspace"));
        assert!(blocked.contains("Model Refusal: Empty content (reason: stop)"));

        let blocked_run =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("blocked playbook run lookup should succeed")
                .expect("blocked playbook run should exist");
        assert_eq!(blocked_run.status, ParentPlaybookStatus::Blocked);
        assert_eq!(
            blocked_run.steps[1].status,
            ParentPlaybookStepStatus::Blocked
        );
        assert!(blocked_run.active_child_session_id.is_none());
        assert_eq!(
            blocked_run.steps[1].error.as_deref(),
            Some("ERROR_CLASS=UserInterventionNeeded Model Refusal: Empty content (reason: stop)")
        );
        assert!(matches!(
            &parent_state.status,
            AgentStatus::Paused(reason)
                if reason.contains("Model Refusal: Empty content (reason: stop)")
        ));

        let materialized = load_worker_session_result(&state, implement_id)
            .expect("worker result lookup should succeed");
        let materialized = materialized.expect("paused worker should materialize a result");
        assert_eq!(materialized.status, "Paused");
        assert!(!materialized.success);
        assert_eq!(
            materialized.error.as_deref(),
            Some("ERROR_CLASS=UserInterventionNeeded Model Refusal: Empty content (reason: stop)")
        );

        let mut saw_worker_merge = false;
        let mut saw_playbook_blocked = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                        if receipt.child_session_id == hex::encode(implement_id) {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                            assert!(!receipt.success);
                            assert_eq!(receipt.status, "Paused");
                            assert_eq!(
                                receipt.error_class.as_deref(),
                                Some("UserInterventionNeeded")
                            );
                            saw_worker_merge = true;
                        }
                    }
                    WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                        if receipt.playbook_id == "evidence_audited_patch" {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                            assert_eq!(
                                receipt.error_class.as_deref(),
                                Some("UserInterventionNeeded")
                            );
                            assert!(receipt
                                .prep_summary
                                .as_deref()
                                .map(str::trim)
                                .is_some_and(|summary| !summary.is_empty()));
                            saw_playbook_blocked = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_worker_merge,
            "paused worker should emit a merge receipt"
        );
        assert!(
            saw_playbook_blocked,
            "parent playbook should emit a blocked receipt for the paused worker"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evidence_audited_patch_recovers_paused_refusal_worker_after_successful_verification() {
        let (tx, _rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Patch only the targeted repo file and verify the focused test first.";
        let mut parent_state = build_parent_state_with_goal(topic, 256);

        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x67; 32],
            topic,
            96,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("context step should spawn");

        let context_key = get_state_key(&context.child_session_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py; tests/test_path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(context.child_session_id),
        )
        .await
        .expect("context merge should advance to implement");
        assert!(merged_context.contains("advanced to 'Patch the workspace'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        let implement_id = run_after_context
            .active_child_session_id
            .expect("implement child should be active");
        let implement_key = get_state_key(&implement_id);
        let implement_bytes = state
            .get(&implement_key)
            .expect("implement state lookup should succeed")
            .expect("implement state should exist");
        let mut implement_state: AgentState =
            codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
        implement_state.status =
            AgentStatus::Paused("Model Refusal: Empty content (reason: length)".to_string());
        implement_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "FAILED (failures=2)".to_string(),
            timestamp_ms: 1,
            step_index: 2,
        });
        implement_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            timestamp_ms: 2,
            step_index: 5,
        });
        implement_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(
                "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        persist_agent_state(
            &mut state,
            &implement_key,
            &implement_state,
            service.memory_runtime.as_ref(),
        )
        .expect("implement state update should persist");

        let merged_implement = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(implement_id),
        )
        .await
        .expect("paused refusal with successful verification should merge");

        assert!(
            merged_implement.contains("advanced to 'Verify targeted tests'"),
            "unexpected implement merge output: {}",
            merged_implement
        );

        let run_after_implement =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        assert_eq!(run_after_implement.status, ParentPlaybookStatus::Completed);
        assert_eq!(
            run_after_implement.steps[1].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_implement.steps[2].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_implement.steps[3].status,
            ParentPlaybookStepStatus::Completed
        );
        assert!(run_after_implement.active_child_session_id.is_none());

        let materialized = load_worker_session_result(&state, implement_id)
            .expect("worker result lookup should succeed")
            .expect("worker result should exist");
        assert_eq!(materialized.status, "Completed");
        assert!(materialized.success);
        let raw_output = materialized
            .raw_output
            .as_deref()
            .expect("completed worker should synthesize raw output");
        assert!(
            raw_output.contains("Touched files: path_utils.py"),
            "{raw_output}"
        );
        assert!(
            raw_output
                .contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"),
            "{raw_output}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_surfaces_research_verifier_scorecard() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest kernel scheduler benchmark scorecards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x73; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Completed(Some(
            "Findings:\n- Linux 6.9 scheduler latency improved in recent tests.\nSources:\n- https://www.kernel.org/doc/html/latest/scheduler/index.html\n- https://lwn.net/Articles/123456/\n- https://benchmark.example.com/kernel-scheduler-2026-03-31\nFreshness note: checked on 2026-03-31."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let merged_research = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("research merge should advance playbook");
        assert!(merged_research.contains("Playbook: Live Research Brief (live_research_brief)"));
        assert!(merged_research.contains("advanced to 'Verify grounding'"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("research playbook run lookup should succeed")
                .expect("research playbook run should exist");
        assert_eq!(
            run_after_research.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_research.steps[1].status,
            ParentPlaybookStepStatus::Running
        );
        assert_eq!(
            run_after_research.steps[1].workflow_id.as_deref(),
            Some("citation_audit")
        );
        let verify_id = run_after_research
            .active_child_session_id
            .expect("citation verifier should be active");

        let verify_key = get_state_key(&verify_id);
        let verify_bytes = state
            .get(&verify_key)
            .expect("verifier state lookup should succeed")
            .expect("verifier state should exist");
        let mut verify_state: AgentState =
            codec::from_bytes_canonical(&verify_bytes).expect("verifier state should decode");
        assert!(verify_state.goal.contains("full_handoff"));
        assert!(verify_state.goal.contains("Sources:"));
        assert!(verify_state
            .goal
            .contains("https://www.kernel.org/doc/html/latest/scheduler/index.html"));
        verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- freshness_status: passed\n- quote_grounding_status: needs_attention\n- notes: One benchmark metric still needs a direct quote read-back from the benchmark source."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &verify_key,
            &verify_state,
            service.memory_runtime.as_ref(),
        )
        .expect("verifier state update should persist");

        let merged_verify = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(verify_id),
        )
        .await
        .expect("citation verifier merge should complete playbook");
        assert!(merged_verify.contains("Playbook: Citation Audit (citation_audit)"));
        assert!(merged_verify.contains("Parent playbook 'Citation-Grounded Brief' completed."));

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("final playbook run lookup should succeed")
                .expect("final playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
        let parent_completion = match &parent_state.status {
            AgentStatus::Completed(Some(output)) => output,
            other => panic!("expected completed parent status, got {:?}", other),
        };
        assert!(parent_completion.contains("Linux 6.9 scheduler latency improved"));
        assert!(parent_completion.contains("Verification verdict"));
        assert!(parent_completion.contains("verdict: passed"));
        let scorecard = final_run.steps[1]
            .research_scorecard
            .as_ref()
            .expect("research verifier scorecard should be captured");
        assert_eq!(scorecard.verdict, "passed");
        assert_eq!(scorecard.source_count, 3);
        assert_eq!(scorecard.distinct_domain_count, 3);
        assert!(scorecard.source_count_floor_met);
        assert!(scorecard.source_independence_floor_met);
        assert_eq!(scorecard.freshness_status, "passed");
        assert_eq!(scorecard.quote_grounding_status, "needs_attention");
        assert!(scorecard
            .notes
            .as_deref()
            .is_some_and(|notes| notes.contains("direct quote read-back")));

        let mut saw_step_completed_scorecard = false;
        let mut saw_completed_scorecard = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                    assert_eq!(receipt.planner_authority, "kernel");
                    assert_eq!(receipt.verifier_role, "citation_verifier");
                    match receipt.phase.as_str() {
                        "step_completed"
                            if receipt.workflow_id.as_deref() == Some("citation_audit") =>
                        {
                            let scorecard = receipt
                                .research_scorecard
                                .as_ref()
                                .expect("step-completed receipt should carry scorecard");
                            assert_eq!(scorecard.verdict, "passed");
                            assert_eq!(scorecard.source_count, 3);
                            assert_eq!(receipt.verifier_outcome, "pass");
                            saw_step_completed_scorecard = true;
                        }
                        "completed" => {
                            let scorecard = receipt
                                .research_scorecard
                                .as_ref()
                                .expect("completed receipt should carry scorecard");
                            assert_eq!(scorecard.quote_grounding_status, "needs_attention");
                            assert_eq!(receipt.verifier_outcome, "pass");
                            saw_completed_scorecard = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(
            saw_step_completed_scorecard,
            "step_completed receipt should carry the research scorecard"
        );
        assert!(
            saw_completed_scorecard,
            "completed receipt should preserve the research scorecard"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_merges_child_pending_search_inventory_into_parent() {
        let (tx, _rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest NIST post-quantum cryptography standards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);
        parent_state.pending_search_completion = Some(PendingSearchCompletion {
            query: topic.to_string(),
            query_contract: "document_briefing".to_string(),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            started_step: 1,
            started_at_ms: 10,
            deadline_ms: 20,
            candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/final".to_string()],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some("NIST IR 8413".to_string()),
                excerpt: "Status report for the PQC standardization process.".to_string(),
            }],
            attempted_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
            blocked_urls: Vec::new(),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some("NIST IR 8413 Update 1".to_string()),
                excerpt: "Official NIST status report for post-quantum cryptography.".to_string(),
            }],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        });

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x75; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.pending_search_completion = Some(PendingSearchCompletion {
            query: topic.to_string(),
            query_contract: "document_briefing".to_string(),
            url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            started_step: 3,
            started_at_ms: 30,
            deadline_ms: 40,
            candidate_urls: vec![
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                    title: Some("FIPS 203".to_string()),
                    excerpt: "Module-Lattice-Based Key-Encapsulation Mechanism Standard.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some("FIPS 204".to_string()),
                    excerpt: "Module-Lattice-Based Digital Signature Standard.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            ],
            blocked_urls: Vec::new(),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                title: Some("Post-Quantum Cryptography Standardization".to_string()),
                excerpt: "FIPS 203, FIPS 204, and FIPS 205 are the initial finalized standards.".to_string(),
            }],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        });
        research_state.status = AgentStatus::Completed(Some(
            "Briefing for NIST PQC standards with citations to IR 8413 and the PQC project page."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let merged_research = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("research merge should advance playbook");
        assert!(merged_research.contains("advanced to 'Verify grounding'"));

        let parent_pending = parent_state
            .pending_search_completion
            .as_ref()
            .expect("parent should inherit merged pending search inventory");
        assert_eq!(parent_pending.query, topic);
        assert!(
            parent_pending
                .successful_reads
                .iter()
                .any(|source| { source.url == "https://csrc.nist.gov/pubs/ir/8413/upd1/final" }),
            "parent should preserve existing official IR read"
        );
        assert!(
            parent_pending.successful_reads.iter().any(|source| {
                source.url
                    == "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            }),
            "parent should inherit the child project-page read"
        );
        assert!(
            parent_pending
                .candidate_source_hints
                .iter()
                .any(|source| { source.url == "https://csrc.nist.gov/pubs/fips/203/final" }),
            "parent should inherit child follow-on authority hints"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn citation_grounded_brief_bootstrapped_verifier_completes_from_inherited_handoff() {
        let (tx, _rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Research the latest NIST post-quantum cryptography standards.";
        let mut parent_state = build_parent_state_with_goal(topic, 128);

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x74; 32],
            topic,
            64,
            Some("citation_grounded_brief"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("research route should spawn");
        let research_id = research.child_session_id;

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Completed(Some(
            "Briefing for 'Research the latest NIST post-quantum cryptography standards.' (as of 2026-04-01T05:16:29Z UTC)\n\nWhat happened:\n- NIST's NCCoE migration draft remains a current official source for PQC migration activity.\n\nKey evidence:\n- NCCoE published the draft migration practice guide and IBM summarized related NIST framework context.\n\nCitations:\n- Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards | https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf | 2026-04-01T05:16:29Z | retrieved_utc\n- IBM NIST cybersecurity framework summary | https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2 | 2026-04-01T05:16:29Z | retrieved_utc\n\nRun date (UTC): 2026-04-01\nRun timestamp (UTC): 2026-04-01T05:16:29Z\nOverall confidence: medium"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &research_key,
            &research_state,
            service.memory_runtime.as_ref(),
        )
        .expect("research state update should persist");

        let merged_research = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(research_id),
        )
        .await
        .expect("research merge should advance playbook");
        assert!(merged_research.contains("advanced to 'Verify grounding'"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("research playbook run lookup should succeed")
                .expect("research playbook run should exist");
        let verify_id = run_after_research
            .active_child_session_id
            .expect("citation verifier should be active");

        let verify_key = get_state_key(&verify_id);
        let verify_bytes = state
            .get(&verify_key)
            .expect("verifier state lookup should succeed")
            .expect("verifier state should exist");
        let verify_state: AgentState =
            codec::from_bytes_canonical(&verify_bytes).expect("verifier state should decode");
        assert!(verify_state.execution_queue.is_empty());
        let verify_output = match &verify_state.status {
            AgentStatus::Completed(Some(output)) => output.as_str(),
            other => panic!("expected completed verifier bootstrap, got {:?}", other),
        };
        assert!(verify_output.contains("- verdict: passed"));
        assert!(verify_output.contains("- freshness_status: passed"));

        let merged_verify = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(verify_id),
        )
        .await
        .expect("bootstrapped verifier merge should complete playbook");
        assert!(!merged_verify.trim().is_empty());

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
                .expect("final playbook run lookup should succeed")
                .expect("final playbook run should exist");
        let scorecard = final_run.steps[1]
            .research_scorecard
            .as_ref()
            .expect("research verifier scorecard should be captured");
        assert_eq!(scorecard.verdict, "passed");
        assert_eq!(scorecard.source_count, 2);
        assert_eq!(scorecard.distinct_domain_count, 2);
        assert_eq!(scorecard.freshness_status, "passed");
        assert_eq!(scorecard.quote_grounding_status, "passed");
        assert!(scorecard.source_count_floor_met);
        assert!(scorecard.source_independence_floor_met);
        let parent_completion = match &parent_state.status {
            AgentStatus::Completed(Some(output)) => output,
            other => panic!("expected completed parent status, got {:?}", other),
        };
        assert!(parent_completion.contains("Verification verdict"));
        assert!(parent_completion.contains("verdict: passed"));
    }

    #[test]
    fn evidence_audited_patch_injects_raw_implement_handoff_into_verifier_goal() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Port the path-normalization parity fix into the kernel-managed control plane.";
        let parent_state = build_parent_state_with_goal(topic, 160);
        let playbook = builtin_agent_playbook(Some("evidence_audited_patch"))
            .expect("coding parent playbook should exist");
        let mut run = build_parent_playbook_run(&parent_state, &playbook, 42);

        run.steps[0].status = ParentPlaybookStepStatus::Completed;
        run.steps[0].output_preview = Some(
            "Likely files: path_utils.py; tests/test_path_utils.py | Targeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        );
        run.steps[0].completed_at_ms = Some(43);

        let implement_id = [0x62; 32];
        run.steps[1].status = ParentPlaybookStepStatus::Completed;
        run.steps[1].child_session_id = Some(implement_id);
        run.steps[1].output_preview = Some(
            "Touched files: path_utils.py | Verification: python3 -m unittest tests.test_path_utils -v (passed)"
                .to_string(),
        );
        run.steps[1].completed_at_ms = Some(44);

        persist_worker_session_result(
            &mut state,
            &crate::agentic::desktop::types::WorkerSessionResult {
                child_session_id: implement_id,
                parent_session_id: parent_state.session_id,
                budget: 64,
                playbook_id: Some("evidence_audited_patch".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                role: "coder".to_string(),
                goal: format!("Implement {}", topic),
                status: "completed".to_string(),
                success: true,
                error: None,
                raw_output: Some(
                    "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun."
                        .to_string(),
                ),
                merged_output: "Touched files: path_utils.py".to_string(),
                completion_contract: WorkerCompletionContract::default(),
                completed_at_ms: 44,
                merged_at_ms: Some(44),
                merged_step_index: Some(1),
            },
        )
        .expect("implement handoff should persist");

        let verify_step = &playbook.steps[2];
        let goal = inject_parent_playbook_context(
            &state,
            &verify_step.goal_template.replace("{topic}", topic),
            &playbook,
            &run,
            verify_step,
        );

        assert!(goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        assert!(goal.contains("Likely files: path_utils.py"));
        assert!(goal.contains("Patch the workspace full_handoff (implement_full):"));
        assert!(goal.contains("Touched files: path_utils.py"));
        assert!(
            goal.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)")
        );
        assert!(goal.contains(
            "Residual risk: Focused verification passed; broader checks were not rerun."
        ));
    }

    #[test]
    fn materialize_patch_build_verify_result_enriches_summary_only_completion() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
        let child_session_id = [0x63; 32];
        let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\". Run `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );
        persist_worker_assignment(&mut state, child_session_id, &assignment)
            .expect("assignment should persist");

        let mut child_state = build_parent_state();
        child_state.session_id = child_session_id;
        child_state.parent_session_id = Some(parent_state.session_id);
        child_state.goal = assignment.goal.clone();
        child_state.status = AgentStatus::Completed(Some(
            "Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'. The focused verification command passed all tests without issues.".to_string(),
        ));
        child_state
            .command_history
            .push_back(crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 0,
                stdout: String::new(),
                stderr: "OK".to_string(),
                timestamp_ms: 1,
                step_index: 7,
            });
        child_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(
                "step=6;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );

        let result =
            materialize_worker_result(&mut state, &child_state).expect("result should materialize");

        let raw_output = result.raw_output.expect("raw output should be present");
        assert!(raw_output.contains("Touched files: path_utils.py"));
        assert!(raw_output
            .contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"));
        assert!(raw_output.contains(
            "Residual risk: Focused verification passed; broader checks were not rerun."
        ));
        assert!(raw_output.contains(
            "Summary: Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'."
        ));
    }

    #[test]
    fn synthesize_observed_patch_build_verify_completion_recovers_running_child_after_successful_rerun(
    ) {
        let repo_root = std::path::PathBuf::from("/tmp/fixture");
        let source_path = repo_root.join("path_utils.py");
        let child_session_id = [0x65; 32];
        let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\". Run `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );

        let mut child_state = build_parent_state();
        child_state.session_id = child_session_id;
        child_state.parent_session_id = Some([0x66; 32]);
        child_state.goal = assignment.goal.clone();
        child_state.working_directory = repo_root.to_string_lossy().to_string();
        child_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "FAILED (failures=2)".to_string(),
            timestamp_ms: 1,
            step_index: 2,
        });
        child_state.command_history.push_back(CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: "OK".to_string(),
            stderr: String::new(),
            timestamp_ms: 2,
            step_index: 5,
        });
        child_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(format!(
                "step=4;tool=filesystem__write_file;path={}",
                source_path.display()
            )),
        );

        let summary = synthesize_observed_patch_build_verify_completion(&child_state, &assignment)
            .expect("observed running completion should synthesize");

        assert!(
            summary.contains("Touched files: path_utils.py"),
            "{summary}"
        );
        assert!(
            summary.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"),
            "{summary}"
        );
        assert!(summary.contains("Residual risk:"), "{summary}");
    }

    #[test]
    fn materialize_patch_synthesis_completion_recovers_from_parent_receipts() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
        let playbook = builtin_agent_playbook(Some("evidence_audited_patch"))
            .expect("coding playbook should exist");
        let mut run = build_parent_playbook_run(&parent_state, &playbook, 1);
        let implement_id = [0x71; 32];
        let verify_id = [0x72; 32];

        run.current_step_index = 3;
        run.steps[1].status = ParentPlaybookStepStatus::Completed;
        run.steps[1].child_session_id = Some(implement_id);
        run.steps[2].status = ParentPlaybookStepStatus::Completed;
        run.steps[2].child_session_id = Some(verify_id);
        run.steps[2].coding_scorecard = Some(CodingVerificationScorecard {
            verdict: "passed".to_string(),
            targeted_command_count: 1,
            targeted_pass_count: 1,
            widening_status: "not_needed".to_string(),
            regression_status: "clear".to_string(),
            notes: Some("Focused unittest verification passed without widening.".to_string()),
        });
        persist_parent_playbook_run(&mut state, &run).expect("parent playbook run should persist");

        persist_worker_session_result(
            &mut state,
            &crate::agentic::desktop::types::WorkerSessionResult {
                child_session_id: implement_id,
                parent_session_id: parent_state.session_id,
                budget: 64,
                playbook_id: Some("evidence_audited_patch".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                role: "Coding Worker".to_string(),
                goal: "Implement the path normalizer fix.".to_string(),
                status: "Completed".to_string(),
                success: true,
                error: None,
                raw_output: Some(
                    "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.".to_string(),
                ),
                merged_output: "Coding Worker completed delegated work: touched files and verification recorded.".to_string(),
                completion_contract: WorkerCompletionContract::default(),
                completed_at_ms: 2,
                merged_at_ms: None,
                merged_step_index: None,
            },
        )
        .expect("implement worker result should persist");

        let child_session_id = [0x73; 32];
        let assignment = resolve_worker_assignment(
            child_session_id,
            6,
            40,
            "Synthesize the verified patch for the path normalizer into a final handoff.",
            Some("evidence_audited_patch"),
            Some("patch_synthesizer"),
            Some("patch_synthesis_handoff"),
            None,
            None,
            None,
            None,
        );
        persist_worker_assignment(&mut state, child_session_id, &assignment)
            .expect("assignment should persist");

        let mut child_state = build_parent_state();
        child_state.session_id = child_session_id;
        child_state.parent_session_id = Some(parent_state.session_id);
        child_state.goal = assignment.goal.clone();
        child_state.status = AgentStatus::Completed(None);

        let result =
            materialize_worker_result(&mut state, &child_state).expect("result should materialize");

        assert!(result.success);
        let raw_output = result.raw_output.expect("raw output should be present");
        assert!(raw_output.contains("- status: ready"), "{raw_output}");
        assert!(
            raw_output.contains("- touched_file_count: 1"),
            "{raw_output}"
        );
        assert!(
            raw_output.contains("- verification_ready: yes"),
            "{raw_output}"
        );
        assert!(
            raw_output.contains("Focused unittest verification passed without widening."),
            "{raw_output}"
        );
        assert!(
            raw_output.contains("Focused verification passed; broader checks were not rerun."),
            "{raw_output}"
        );
    }

    #[test]
    fn patch_build_verify_post_edit_followup_uses_failed_command_history_without_goal_literal() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
        let child_session_id = [0x64; 32];
        let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\" and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- Capture repo context (context): Worker evidence\nRole: Context Worker\nGoal: Inspect repo context for the path normalizer fix.",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );
        persist_worker_assignment(&mut state, child_session_id, &assignment)
            .expect("assignment should persist");

        let mut child_state = build_parent_state();
        child_state.session_id = child_session_id;
        child_state.parent_session_id = Some(parent_state.session_id);
        child_state.goal = assignment.goal.clone();
        child_state
            .command_history
            .push_back(crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 1,
                stdout: String::new(),
                stderr: "FAIL".to_string(),
                timestamp_ms: 1,
                step_index: 2,
            });
        child_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(
                "step=5;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );

        assert_eq!(
            latest_failed_goal_command_step(&child_state, &assignment),
            Some(2)
        );
        assert!(patch_build_verify_post_edit_followup_due(
            &child_state,
            &assignment
        ));
        assert_eq!(
            await_child_burst_step_limit(&state, child_session_id, &child_state)
                .expect("burst limit should resolve"),
            MAX_AWAIT_CHILD_BURST_STEPS + PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delegated_verifier_playbook_flows_through_result_artifact_and_merge_receipts() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state();

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x46; 32],
            "Verify whether the parser regression fix satisfies the postcondition.",
            8,
            None,
            Some("verifier"),
            Some("postcondition_audit"),
            None,
            None,
            None,
            None,
            5,
            0,
        )
        .await
        .expect("delegated child should spawn");
        let child_session_id = spawned.child_session_id;
        assert_eq!(spawned.assignment.budget, 8);
        assert_eq!(
            spawned.assignment.workflow_id.as_deref(),
            Some("postcondition_audit")
        );
        assert_eq!(spawned.assignment.max_retries, 0);
        assert!(spawned
            .assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "model__rerank"));
        assert!(spawned
            .assignment
            .allowed_tools
            .iter()
            .all(|tool| tool != "model__responses"));

        let child_key = get_state_key(&child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child state lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(child_state.goal.contains("return a pass/fail audit"));

        child_state.status = AgentStatus::Completed(Some(
            "Verdict: pass\nEvidence: Receipt 42 and reranked memory fragments both confirm the parser regression path now returns the expected token stream.\nResidual risk: Full parser fuzz coverage still has not been rerun."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            6,
            0,
            &hex::encode(child_session_id),
        )
        .await
        .expect("await result should merge");

        assert!(merged.contains("Worker evidence"));
        assert!(merged.contains("Playbook: Postcondition Audit (postcondition_audit)"));
        assert!(merged.contains("Verdict: pass"));

        let result = load_worker_session_result(&state, child_session_id)
            .expect("worker result load should succeed")
            .expect("worker result artifact should exist");
        assert_eq!(result.workflow_id.as_deref(), Some("postcondition_audit"));
        assert_eq!(result.budget, 8);
        assert_eq!(
            result.completion_contract.merge_mode,
            WorkerMergeMode::AppendAsEvidence
        );
        assert_eq!(result.merged_step_index, Some(6));
        assert!(result.merged_at_ms.is_some());
        assert!(result
            .merged_output
            .contains("Playbook: Postcondition Audit (postcondition_audit)"));

        let mut completion_saw_workflow = false;
        let mut merge_saw_workflow = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                    match receipt.phase.as_str() {
                        "completed" => {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("postcondition_audit"));
                            assert_eq!(receipt.merge_mode, "append_as_evidence");
                            completion_saw_workflow = true;
                        }
                        "merged" => {
                            assert_eq!(receipt.workflow_id.as_deref(), Some("postcondition_audit"));
                            assert_eq!(receipt.merge_mode, "append_as_evidence");
                            merge_saw_workflow = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(
            completion_saw_workflow,
            "completion receipt should preserve verifier workflow id"
        );
        assert!(
            merge_saw_workflow,
            "merge receipt should preserve verifier workflow id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delegated_coder_playbook_flows_through_result_artifact_and_merge_receipts() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let mut parent_state = build_parent_state();

        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x45; 32],
            "Patch the parser regression, run focused verification, and summarize the outcome.",
            8,
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
            6,
            0,
        )
        .await
        .expect("delegated child should spawn");
        let child_session_id = spawned.child_session_id;
        assert_eq!(spawned.assignment.budget, 8);
        assert_eq!(
            spawned.assignment.playbook_id.as_deref(),
            Some("evidence_audited_patch")
        );
        assert_eq!(
            spawned.assignment.workflow_id.as_deref(),
            Some("patch_build_verify")
        );
        assert!(spawned
            .assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "filesystem__patch"));
        assert!(spawned
            .assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "sys__exec_session"));
        assert!(spawned
            .assignment
            .allowed_tools
            .iter()
            .any(|tool| tool == "agent__complete"));

        let child_key = get_state_key(&child_session_id);
        let child_bytes = state
            .get(&child_key)
            .expect("child state lookup should succeed")
            .expect("child state should exist");
        let mut child_state: AgentState =
            codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
        assert!(child_state.goal.contains(
            "Patch the parser regression, run focused verification, and summarize the outcome."
        ));
        assert!(child_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        assert!(child_state
            .goal
            .contains("- delegated_task_contract: Parent orchestration goal"));

        child_state.status = AgentStatus::Completed(Some(
            "Touched files: crates/services/src/parser.rs\nVerification: cargo test -p ioi-services parser_regression -- --nocapture (passed)\nResidual risk: broader parser edge cases still need coverage."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &child_key,
            &child_state,
            service.memory_runtime.as_ref(),
        )
        .expect("child state update should persist");

        let merged = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            7,
            0,
            &hex::encode(child_session_id),
        )
        .await
        .expect("await result should merge");

        assert!(merged.contains("Playbook: Patch, Build, Verify (patch_build_verify)"));
        assert!(merged.contains("Parent playbook: evidence_audited_patch"));
        assert!(merged.contains("Touched files: crates/services/src/parser.rs"));
        assert!(merged.contains("cargo test -p ioi-services parser_regression"));

        let result = load_worker_session_result(&state, child_session_id)
            .expect("worker result load should succeed")
            .expect("worker result artifact should exist");
        assert_eq!(
            result.playbook_id.as_deref(),
            Some("evidence_audited_patch")
        );
        assert_eq!(result.workflow_id.as_deref(), Some("patch_build_verify"));
        assert_eq!(result.budget, 8);
        assert_eq!(
            result.completion_contract.merge_mode,
            WorkerMergeMode::AppendSummaryToParent
        );
        assert_eq!(result.merged_step_index, Some(7));
        assert!(result.merged_at_ms.is_some());
        assert!(result
            .merged_output
            .contains("Parent playbook: evidence_audited_patch"));
        assert!(result
            .merged_output
            .contains("Playbook: Patch, Build, Verify (patch_build_verify)"));

        let mut completion_saw_workflow = false;
        let mut merge_saw_workflow = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                    match receipt.phase.as_str() {
                        "completed" => {
                            assert_eq!(
                                receipt.playbook_id.as_deref(),
                                Some("evidence_audited_patch")
                            );
                            assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                            assert_eq!(receipt.merge_mode, "append_summary_to_parent");
                            completion_saw_workflow = true;
                        }
                        "merged" => {
                            assert_eq!(
                                receipt.playbook_id.as_deref(),
                                Some("evidence_audited_patch")
                            );
                            assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                            assert_eq!(receipt.merge_mode, "append_summary_to_parent");
                            merge_saw_workflow = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        assert!(
            completion_saw_workflow,
            "completion receipt should preserve coder workflow id"
        );
        assert!(
            merge_saw_workflow,
            "merge receipt should preserve coder workflow id"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evidence_audited_parent_playbook_advances_across_all_steps() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(64);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic =
            "Port LocalAI lifecycle parity into the kernel-managed control plane with receipts.";
        let mut parent_state = build_parent_state_with_goal(topic, 320);

        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x52; 32],
            topic,
            196,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("context step should spawn");
        let context_id = context.child_session_id;
        assert_eq!(
            context.assignment.workflow_id.as_deref(),
            Some("repo_context_brief")
        );

        let context_key = get_state_key(&context_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "Likely files: crates/services/src/model.rs; crates/services/src/router.rs\nTargeted checks: cargo test -p ioi-services routing_contracts -- --nocapture\nOpen questions: confirm verifier should stay on targeted checks unless routing receipts disagree."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(context_id),
        )
        .await
        .expect("context merge should advance playbook");
        assert!(merged_context.contains("Playbook: Repo Context Brief (repo_context_brief)"));
        assert!(merged_context.contains("advanced to 'Patch the workspace'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("parent playbook run lookup should succeed")
                .expect("parent playbook run should exist");
        assert_eq!(run_after_context.status, ParentPlaybookStatus::Running);
        assert_eq!(
            run_after_context.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_context.steps[1].status,
            ParentPlaybookStepStatus::Running
        );
        let implement_id = run_after_context
            .active_child_session_id
            .expect("implement child should be active");

        let implement_key = get_state_key(&implement_id);
        let implement_bytes = state
            .get(&implement_key)
            .expect("implement state lookup should succeed")
            .expect("implement state should exist");
        let mut implement_state: AgentState =
            codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
        assert!(implement_state.goal.contains("narrow workspace patch"));
        assert!(implement_state
            .goal
            .contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        implement_state.status = AgentStatus::Completed(Some(
            "Touched files: crates/services/src/model.rs; crates/services/src/router.rs\nVerification: cargo check -p ioi-services (passed); cargo test -p ioi-services routing_contracts -- --nocapture (passed)\nResidual risk: broader end-to-end runtime parity still needs audit."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &implement_key,
            &implement_state,
            service.memory_runtime.as_ref(),
        )
        .expect("implement state update should persist");

        let merged_implement = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(implement_id),
        )
        .await
        .expect("implement merge should advance playbook");
        assert!(merged_implement.contains("Playbook: Patch, Build, Verify (patch_build_verify)"));
        assert!(
            merged_implement.contains("advanced to 'Verify targeted tests'"),
            "unexpected implement merge output: {}",
            merged_implement
        );

        let run_after_implement =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("parent playbook run lookup should succeed")
                .expect("parent playbook run should exist");
        assert_eq!(
            run_after_implement.steps[1].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_implement.steps[2].status,
            ParentPlaybookStepStatus::Running,
            "unexpected playbook statuses: {:?}; active_child={:?}",
            run_after_implement
                .steps
                .iter()
                .map(|step| (
                    step.label.clone(),
                    step.status.clone(),
                    step.child_session_id.map(hex::encode)
                ))
                .collect::<Vec<_>>(),
            run_after_implement.active_child_session_id.map(hex::encode)
        );
        let verify_id = run_after_implement
            .active_child_session_id
            .expect("verify child should be active");

        let verify_key = get_state_key(&verify_id);
        let verify_bytes = state
            .get(&verify_key)
            .expect("verify state lookup should succeed")
            .expect("verify state should exist");
        let mut verify_state: AgentState =
            codec::from_bytes_canonical(&verify_bytes).expect("verify state should decode");
        assert!(verify_state.goal.contains("targeted checks first"));
        assert!(verify_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- targeted_command_count: 2\n- targeted_pass_count: 2\n- widening_status: not_needed\n- regression_status: clear\n- notes: Focused cargo check and routing contract test passed without widening."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &verify_key,
            &verify_state,
            service.memory_runtime.as_ref(),
        )
        .expect("verify state update should persist");

        let merged_verify = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            5,
            0,
            &hex::encode(verify_id),
        )
        .await
        .expect("verify merge should advance playbook");
        assert!(merged_verify.contains("Playbook: Targeted Test Audit (targeted_test_audit)"));
        assert!(merged_verify.contains("advanced to 'Synthesize final patch'"));
        assert!(merged_verify.contains("Patch Synthesis Handoff (patch_synthesis_handoff)"));
        assert!(merged_verify.contains("Parent playbook 'Evidence-Audited Patch' completed."));

        let run_after_verify =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("parent playbook run lookup should succeed")
                .expect("parent playbook run should exist");
        assert_eq!(
            run_after_verify.steps[2].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_verify.steps[2]
                .coding_scorecard
                .as_ref()
                .map(|scorecard| scorecard.verdict.as_str()),
            Some("passed")
        );
        assert_eq!(
            run_after_verify.steps[2]
                .coding_scorecard
                .as_ref()
                .map(|scorecard| scorecard.targeted_pass_count),
            Some(2)
        );
        assert_eq!(
            run_after_verify.steps[3].status,
            ParentPlaybookStepStatus::Completed
        );
        assert!(run_after_verify.active_child_session_id.is_none());

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("final parent playbook run lookup should succeed")
                .expect("final parent playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
        let parent_completion = match &parent_state.status {
            AgentStatus::Completed(Some(output)) => output,
            other => panic!("expected completed parent status, got {:?}", other),
        };
        assert!(parent_completion.contains("status: ready"));
        assert!(final_run.completed_at_ms.is_some());
        assert_eq!(parent_state.child_session_ids.len(), 4);
        assert!(final_run
            .steps
            .iter()
            .all(|step| step.status == ParentPlaybookStepStatus::Completed));
        assert_eq!(
            final_run.steps[3]
                .patch_synthesis
                .as_ref()
                .map(|summary| summary.status.as_str()),
            Some("ready")
        );

        let mut parent_receipts = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                    parent_receipts.push(receipt);
                }
            }
        }

        let parent_receipt_phases = parent_receipts
            .iter()
            .map(|receipt| receipt.phase.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            parent_receipt_phases,
            vec![
                "started".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "completed".to_string(),
            ]
        );
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.route_family == "coding"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.topology == "planner_specialist_verifier"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.planner_authority == "kernel"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.verifier_role == "test_verifier"));
        assert_eq!(
            parent_receipts
                .first()
                .map(|receipt| receipt.verifier_state.as_str()),
            Some("queued")
        );
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_spawned" && receipt.step_id.as_deref() == Some("verify")
                })
                .map(|receipt| receipt.verifier_state.as_str()),
            Some("active")
        );
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_completed"
                        && receipt.step_id.as_deref() == Some("verify")
                })
                .and_then(|receipt| receipt.coding_scorecard.as_ref())
                .map(|scorecard| scorecard.verdict.as_str()),
            Some("passed")
        );
        assert_eq!(
            parent_receipts
                .last()
                .and_then(|receipt| receipt.patch_synthesis.as_ref())
                .map(|summary| summary.status.as_str()),
            Some("ready")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_state.as_str()),
            Some("passed")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_outcome.as_str()),
            Some("pass")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evidence_audited_patch_summary_only_implement_handoff_bootstraps_verifier_child() {
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Port the path-normalization parity fix into the kernel-managed control plane.";
        let mut parent_state = build_parent_state_with_goal(topic, 240);

        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x52; 32],
            topic,
            128,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("context step should spawn");
        let context_key = get_state_key(&context.child_session_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py; tests/test_path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(context.child_session_id),
        )
        .await
        .expect("context merge should advance playbook");
        assert!(merged_context.contains("advanced to 'Patch the workspace'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        let implement_id = run_after_context
            .active_child_session_id
            .expect("implement child should be active");
        let implement_key = get_state_key(&implement_id);
        let implement_bytes = state
            .get(&implement_key)
            .expect("implement state lookup should succeed")
            .expect("implement state should exist");
        let mut implement_state: AgentState =
            codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
        implement_state.status = AgentStatus::Completed(Some(
            "Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'. The focused verification command passed all tests without issues.".to_string(),
        ));
        implement_state.command_history.push_back(
            crate::agentic::desktop::types::CommandExecution {
                command: "python3 -m unittest tests.test_path_utils -v".to_string(),
                exit_code: 0,
                stdout: String::new(),
                stderr: "OK".to_string(),
                timestamp_ms: 1,
                step_index: 8,
            },
        );
        implement_state.tool_execution_log.insert(
            "receipt::workspace_edit_applied=true".to_string(),
            crate::agentic::desktop::types::ToolCallStatus::Executed(
                "step=7;tool=filesystem__write_file;path=path_utils.py".to_string(),
            ),
        );
        persist_agent_state(
            &mut state,
            &implement_key,
            &implement_state,
            service.memory_runtime.as_ref(),
        )
        .expect("implement state update should persist");

        let merged_implement = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(implement_id),
        )
        .await
        .expect("implement merge should advance playbook");
        assert!(
            merged_implement.contains("advanced to 'Verify targeted tests'"),
            "unexpected implement merge output: {}",
            merged_implement
        );

        let run_after_implement =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        assert_eq!(run_after_implement.status, ParentPlaybookStatus::Completed);
        assert_eq!(
            run_after_implement.steps[1].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_implement.steps[2].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_implement.steps[3].status,
            ParentPlaybookStepStatus::Completed
        );
        assert!(run_after_implement.active_child_session_id.is_none());
        assert!(
            merged_implement.contains("Playbook: Targeted Test Audit (targeted_test_audit)"),
            "{merged_implement}"
        );
        assert!(
            merged_implement
                .contains("Playbook: Patch Synthesis Handoff (patch_synthesis_handoff)"),
            "{merged_implement}"
        );
        assert!(
            merged_implement.contains("Parent playbook 'Evidence-Audited Patch' completed."),
            "{merged_implement}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evidence_audited_parent_playbook_replay_resets_downstream_blocked_steps() {
        let (tx, _rx) = tokio::sync::broadcast::channel(64);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic = "Patch only the targeted repo file and verify the focused test first.";
        let mut parent_state = build_parent_state_with_goal(topic, 320);

        let context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x61; 32],
            topic,
            96,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            2,
            0,
        )
        .await
        .expect("context step should spawn");
        let context_key = get_state_key(&context.child_session_id);
        let context_bytes = state
            .get(&context_key)
            .expect("context state lookup should succeed")
            .expect("context state should exist");
        let mut context_state: AgentState =
            codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
        context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &context_key,
            &context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("context state update should persist");

        let merged_context = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            3,
            0,
            &hex::encode(context.child_session_id),
        )
        .await
        .expect("context merge should advance to implement");
        assert!(merged_context.contains("advanced to 'Patch the workspace'"));

        let run_after_context =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("playbook run lookup should succeed")
                .expect("playbook run should exist");
        let implement_id = run_after_context
            .active_child_session_id
            .expect("implement child should be active");
        let implement_key = get_state_key(&implement_id);
        let implement_bytes = state
            .get(&implement_key)
            .expect("implement state lookup should succeed")
            .expect("implement state should exist");
        let mut implement_state: AgentState =
            codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
        implement_state.status =
            AgentStatus::Failed("Agent Failure: Resources/Retry limit exceeded".to_string());
        persist_agent_state(
            &mut state,
            &implement_key,
            &implement_state,
            service.memory_runtime.as_ref(),
        )
        .expect("implement state update should persist");

        let blocked = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            4,
            0,
            &hex::encode(implement_id),
        )
        .await
        .expect("failed implement should block playbook");
        assert!(blocked.contains("blocked at 'Patch the workspace'"));

        let blocked_run =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("blocked playbook run lookup should succeed")
                .expect("blocked playbook run should exist");
        assert_eq!(blocked_run.status, ParentPlaybookStatus::Blocked);
        assert_eq!(
            blocked_run.steps[1].status,
            ParentPlaybookStepStatus::Blocked
        );

        let replay_context = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x62; 32],
            "Capture context for the patch task.",
            96,
            Some("evidence_audited_patch"),
            Some("context_worker"),
            Some("repo_context_brief"),
            None,
            None,
            None,
            None,
            5,
            0,
        )
        .await
        .expect("replayed context step should spawn");

        let run_after_replay_spawn =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("replayed playbook run lookup should succeed")
                .expect("replayed playbook run should exist");
        assert_eq!(run_after_replay_spawn.status, ParentPlaybookStatus::Running);
        assert_eq!(
            run_after_replay_spawn.steps[0].status,
            ParentPlaybookStepStatus::Running
        );
        assert_eq!(
            run_after_replay_spawn.steps[1].status,
            ParentPlaybookStepStatus::Pending
        );
        assert_eq!(
            run_after_replay_spawn.steps[2].status,
            ParentPlaybookStepStatus::Pending
        );
        assert_eq!(
            run_after_replay_spawn.steps[3].status,
            ParentPlaybookStepStatus::Pending
        );
        assert!(run_after_replay_spawn.completed_at_ms.is_none());

        let replay_context_key = get_state_key(&replay_context.child_session_id);
        let replay_context_bytes = state
            .get(&replay_context_key)
            .expect("replayed context state lookup should succeed")
            .expect("replayed context state should exist");
        let mut replay_context_state: AgentState =
            codec::from_bytes_canonical(&replay_context_bytes)
                .expect("replayed context state should decode");
        replay_context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &replay_context_key,
            &replay_context_state,
            service.memory_runtime.as_ref(),
        )
        .expect("replayed context state update should persist");

        let merged_replay = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            6,
            0,
            &hex::encode(replay_context.child_session_id),
        )
        .await
        .expect("replayed context merge should advance to implement again");
        assert!(
            merged_replay.contains("advanced to 'Patch the workspace'"),
            "unexpected replay merge output: {merged_replay}"
        );
        assert!(
            !merged_replay.contains("completed."),
            "replayed context should not complete the playbook: {merged_replay}"
        );

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("final playbook run lookup should succeed")
                .expect("final playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Running);
        assert_eq!(
            final_run.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(final_run.steps[1].status, ParentPlaybookStepStatus::Running);
        assert!(final_run.completed_at_ms.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn browser_postcondition_gate_surfaces_selected_skills_and_prep_summary() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(32);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic =
            "Inspect the billing flow, identify the next safe UI action, and call out approval risk before acting.";
        let preview_assignment = resolve_worker_assignment(
            [0x90; 32],
            7,
            96,
            topic,
            Some("browser_postcondition_gate"),
            Some("perception_worker"),
            Some("ui_state_brief"),
            None,
            None,
            None,
            None,
        );
        let retrieval_anchor = format!(
            "{} Prior note: reliable browser runs identify the active target and modal risk before clicking.",
            preview_assignment.goal
        );
        seed_runtime_computer_use_skill(&service, &mut state, &preview_assignment.goal).await;
        seed_runtime_fact(&service, &retrieval_anchor).await;

        let mut parent_state = build_parent_state_with_goal(topic, 192);
        let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x91; 32],
            topic,
            160,
            Some("browser_postcondition_gate"),
            Some("perception_worker"),
            Some("ui_state_brief"),
            None,
            None,
            None,
            None,
            7,
            0,
        )
        .await
        .expect("computer-use perception step should spawn");
        assert_eq!(
            spawned.assignment.playbook_id.as_deref(),
            Some("browser_postcondition_gate")
        );
        assert_eq!(
            spawned.assignment.workflow_id.as_deref(),
            Some("ui_state_brief")
        );

        let run = load_parent_playbook_run(
            &state,
            parent_state.session_id,
            "browser_postcondition_gate",
        )
        .expect("browser playbook run lookup should succeed")
        .expect("browser playbook run should exist");
        assert_eq!(run.steps[0].status, ParentPlaybookStepStatus::Running);
        assert!(run.steps[0]
            .selected_skills
            .iter()
            .any(|skill| skill == "computer_use__ui_state_spine"));
        assert!(run.steps[0]
            .prep_summary
            .as_deref()
            .map(str::trim)
            .is_some_and(|summary| !summary.is_empty()));

        let mut saw_memory_receipt = false;
        let mut saw_parent_started = false;
        let mut saw_parent_step_spawn = false;
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                match receipt_event.receipt {
                    WorkloadReceipt::MemoryRetrieve(receipt) => {
                        assert_eq!(receipt.tool_name, "memory__search");
                        saw_memory_receipt = true;
                    }
                    WorkloadReceipt::ParentPlaybook(receipt) => {
                        if receipt.phase == "started" {
                            assert_eq!(receipt.playbook_id, "browser_postcondition_gate");
                            assert!(receipt
                                .selected_skills
                                .iter()
                                .any(|skill| skill == "computer_use__ui_state_spine"));
                            assert!(receipt
                                .prep_summary
                                .as_deref()
                                .map(str::trim)
                                .is_some_and(|summary| !summary.is_empty()));
                            saw_parent_started = true;
                        } else if receipt.phase == "step_spawned" {
                            assert_eq!(receipt.playbook_id, "browser_postcondition_gate");
                            assert!(receipt
                                .selected_skills
                                .iter()
                                .any(|skill| skill == "computer_use__ui_state_spine"));
                            assert!(receipt
                                .prep_summary
                                .as_deref()
                                .map(str::trim)
                                .is_some_and(|summary| !summary.is_empty()));
                            saw_parent_step_spawn = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(
            saw_memory_receipt,
            "computer-use prep should emit a memory receipt"
        );
        assert!(
            saw_parent_started,
            "started receipt should carry selected skills and prep summary"
        );
        assert!(
            saw_parent_step_spawn,
            "step_spawned receipt should carry selected skills and prep summary"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn browser_postcondition_gate_surfaces_perception_and_recovery_receipts() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(64);
        let (service, _temp_dir) = build_test_service(tx);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let topic =
            "Open the billing website, submit the confirmation form, and verify the receipt page.";
        let mut parent_state = build_parent_state_with_goal(topic, 240);

        let perception = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x61; 32],
            topic,
            160,
            Some("browser_postcondition_gate"),
            Some("perception_worker"),
            Some("ui_state_brief"),
            None,
            None,
            None,
            None,
            9,
            0,
        )
        .await
        .expect("perception step should spawn");
        let perception_id = perception.child_session_id;
        assert_eq!(
            perception.assignment.workflow_id.as_deref(),
            Some("ui_state_brief")
        );

        let perception_key = get_state_key(&perception_id);
        let perception_bytes = state
            .get(&perception_key)
            .expect("perception state lookup should succeed")
            .expect("perception state should exist");
        let mut perception_state: AgentState =
            codec::from_bytes_canonical(&perception_bytes).expect("perception state should decode");
        perception_state.status = AgentStatus::Completed(Some(
            "- surface_status: clear\n- ui_state: Checkout form is visible with the submit button enabled.\n- target: Submit order button\n- approval_risk: possible\n- next_action: Click submit order\n- notes: A confirmation dialog may appear after submit."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &perception_key,
            &perception_state,
            service.memory_runtime.as_ref(),
        )
        .expect("perception state update should persist");

        let merged_perception = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            10,
            0,
            &hex::encode(perception_id),
        )
        .await
        .expect("perception merge should advance playbook");
        assert!(merged_perception.contains("Playbook: UI State Brief (ui_state_brief)"));
        assert!(merged_perception.contains("advanced to 'Execute in browser'"));

        let run_after_perception = load_parent_playbook_run(
            &state,
            parent_state.session_id,
            "browser_postcondition_gate",
        )
        .expect("browser playbook run lookup should succeed")
        .expect("browser playbook run should exist");
        assert_eq!(
            run_after_perception.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_perception.steps[0]
                .computer_use_perception
                .as_ref()
                .map(|summary| summary.surface_status.as_str()),
            Some("clear")
        );
        assert_eq!(
            run_after_perception.steps[1].status,
            ParentPlaybookStepStatus::Running
        );
        let execute_id = run_after_perception
            .active_child_session_id
            .expect("execute child should be active");

        let execute_key = get_state_key(&execute_id);
        let execute_bytes = state
            .get(&execute_key)
            .expect("execute state lookup should succeed")
            .expect("execute state should exist");
        let mut execute_state: AgentState =
            codec::from_bytes_canonical(&execute_bytes).expect("execute state should decode");
        assert!(execute_state.goal.contains("grounded observations first"));
        assert!(execute_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
        execute_state.status = AgentStatus::Completed(Some(
            "- executed_steps: navigated to billing page; clicked submit order\n- observed_postcondition: Confirmation banner is visible and the URL changed to /receipt.\n- approval_state: approved\n- recovery_status: not_needed\n- next_recovery_step: Return completion to the parent planner.\n- blocker_summary: none\n- notes: Browser submit flow completed without needing fallback."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &execute_key,
            &execute_state,
            service.memory_runtime.as_ref(),
        )
        .expect("execute state update should persist");

        let merged_execute = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            11,
            0,
            &hex::encode(execute_id),
        )
        .await
        .expect("execute merge should advance playbook");
        assert!(merged_execute
            .contains("Playbook: Browser Postcondition Pass (browser_postcondition_pass)"));
        assert!(merged_execute.contains("advanced to 'Verify postcondition'"));

        let run_after_execute = load_parent_playbook_run(
            &state,
            parent_state.session_id,
            "browser_postcondition_gate",
        )
        .expect("browser playbook run lookup should succeed")
        .expect("browser playbook run should exist");
        assert_eq!(
            run_after_execute.steps[1].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_execute.steps[1]
                .computer_use_recovery
                .as_ref()
                .map(|summary| summary.status.as_str()),
            Some("not_needed")
        );
        assert_eq!(
            run_after_execute.steps[2].status,
            ParentPlaybookStepStatus::Running
        );
        let verify_id = run_after_execute
            .active_child_session_id
            .expect("verify child should be active");

        let verify_key = get_state_key(&verify_id);
        let verify_bytes = state
            .get(&verify_key)
            .expect("verify state lookup should succeed")
            .expect("verify state should exist");
        let mut verify_state: AgentState =
            codec::from_bytes_canonical(&verify_bytes).expect("verify state should decode");
        assert!(verify_state
            .goal
            .contains("computer-use verifier scorecard"));
        assert!(verify_state.goal.contains("computer_use_perception=clear"));
        verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- postcondition_status: met\n- approval_state: approved\n- recovery_status: not_needed\n- notes: Confirmation banner and receipt URL match the requested postcondition."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &verify_key,
            &verify_state,
            service.memory_runtime.as_ref(),
        )
        .expect("verify state update should persist");

        let merged_verify = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            12,
            0,
            &hex::encode(verify_id),
        )
        .await
        .expect("verify merge should complete playbook");
        assert!(merged_verify
            .contains("Playbook: Browser Postcondition Audit (browser_postcondition_audit)"));
        assert!(merged_verify.contains("Parent playbook 'Browser Postcondition Gate' completed."));

        let final_run = load_parent_playbook_run(
            &state,
            parent_state.session_id,
            "browser_postcondition_gate",
        )
        .expect("final browser playbook run lookup should succeed")
        .expect("final browser playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
        assert!(final_run
            .steps
            .iter()
            .all(|step| step.status == ParentPlaybookStepStatus::Completed));
        assert_eq!(
            final_run.steps[2]
                .computer_use_verification
                .as_ref()
                .map(|scorecard| scorecard.verdict.as_str()),
            Some("passed")
        );
        assert_eq!(
            final_run.steps[2]
                .computer_use_recovery
                .as_ref()
                .map(|summary| summary.status.as_str()),
            Some("not_needed")
        );

        let mut parent_receipts = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                    parent_receipts.push(receipt);
                }
            }
        }

        let parent_receipt_phases = parent_receipts
            .iter()
            .map(|receipt| receipt.phase.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            parent_receipt_phases,
            vec![
                "started".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "step_spawned".to_string(),
                "step_completed".to_string(),
                "completed".to_string(),
            ]
        );
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.route_family == "computer_use"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.planner_authority == "kernel"));
        assert!(parent_receipts
            .iter()
            .all(|receipt| receipt.verifier_role == "postcondition_verifier"));
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_completed"
                        && receipt.step_id.as_deref() == Some("perceive")
                })
                .and_then(|receipt| receipt.computer_use_perception.as_ref())
                .map(|summary| summary.surface_status.as_str()),
            Some("clear")
        );
        assert_eq!(
            parent_receipts
                .iter()
                .find(|receipt| {
                    receipt.phase == "step_completed"
                        && receipt.step_id.as_deref() == Some("verify")
                })
                .and_then(|receipt| receipt.computer_use_verification.as_ref())
                .map(|summary| summary.postcondition_status.as_str()),
            Some("met")
        );
        assert_eq!(
            parent_receipts
                .last()
                .and_then(|receipt| receipt.computer_use_recovery.as_ref())
                .map(|summary| summary.status.as_str()),
            Some("not_needed")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_state.as_str()),
            Some("passed")
        );
        assert_eq!(
            parent_receipts
                .last()
                .map(|receipt| receipt.verifier_outcome.as_str()),
            Some("pass")
        );
    }
}
