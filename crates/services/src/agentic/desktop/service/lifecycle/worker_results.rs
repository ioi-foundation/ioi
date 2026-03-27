use crate::agentic::desktop::agent_playbooks::builtin_agent_playbook;
use crate::agentic::desktop::keys::{
    get_parent_playbook_run_key, get_session_result_key, get_state_key, get_worker_assignment_key,
};
use crate::agentic::desktop::service::step::action::command_contract::extract_error_class_token;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, AgentState, AgentStatus,
    ParentPlaybookRun, ParentPlaybookStatus, ParentPlaybookStepRun, ParentPlaybookStepStatus,
    WorkerAssignment, WorkerCompletionContract, WorkerMergeMode, WorkerSessionResult,
    WorkerTemplateWorkflowDefinition,
};
use crate::agentic::desktop::utils::load_agent_state_checkpoint;
use crate::agentic::desktop::worker_templates::{
    builtin_worker_template, builtin_worker_workflow, default_worker_role_label,
};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::MemoryRuntime;
use ioi_types::app::{
    KernelEvent, WorkloadParentPlaybookReceipt, WorkloadReceipt, WorkloadReceiptEvent,
    WorkloadWorkerReceipt,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::delegation::spawn_delegated_child_session;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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

fn load_agent_state_from_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Child state lookup failed: {}",
                error
            )
        })?
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=UnexpectedState Child session '{}' not found.",
                child_session_id_hex
            )
        })?;

    codec::from_bytes_canonical::<AgentState>(&bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to decode child session '{}': {}",
            child_session_id_hex, error
        )
    })
}

fn load_child_state(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    if let Some(memory_runtime) = memory_runtime {
        match load_agent_state_checkpoint(memory_runtime.as_ref(), child_session_id) {
            Ok(Some(agent_state)) => Ok(agent_state),
            Ok(None) => load_agent_state_from_state(state, child_session_id, child_session_id_hex),
            Err(error) => Err(format!(
                "ERROR_CLASS=UnexpectedState Failed to load child session '{}' from runtime checkpoint: {}",
                child_session_id_hex, error
            )),
        }
    } else {
        load_agent_state_from_state(state, child_session_id, child_session_id_hex)
    }
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
    let Some(workflow) = workflow else {
        return raw_goal.to_string();
    };
    let goal_template = workflow.goal_template.trim();
    if goal_template.is_empty() {
        return raw_goal.to_string();
    }

    let topic = derive_workflow_topic(raw_goal);
    goal_template.replace("{topic}", &topic)
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

fn emit_parent_playbook_receipt(
    service: &DesktopAgentService,
    parent_session_id: [u8; 32],
    step_index: u32,
    playbook_id: &str,
    receipt: WorkloadParentPlaybookReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
        session_id: parent_session_id,
        step_index,
        workload_id: format!("parent_playbook::{}", playbook_id),
        timestamp_ms: now_ms(),
        receipt: WorkloadReceipt::ParentPlaybook(receipt),
    }));
}

fn emit_parent_playbook_started_receipt(
    service: &DesktopAgentService,
    run: &ParentPlaybookRun,
    step_index: u32,
) {
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "started".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: None,
            step_label: None,
            child_session_id: None,
            template_id: None,
            workflow_id: None,
            summary: summarize_parent_playbook_text(&format!(
                "Started parent playbook '{}' for topic '{}'.",
                run.playbook_label, run.topic
            )),
            error_class: None,
        },
    );
}

fn emit_parent_playbook_step_spawned_receipt(
    service: &DesktopAgentService,
    run: &ParentPlaybookRun,
    step: &ParentPlaybookStepRun,
    step_index: u32,
) {
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "step_spawned".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: Some(step.step_id.clone()),
            step_label: Some(step.label.clone()),
            child_session_id: step.child_session_id.map(hex::encode),
            template_id: step.template_id.clone(),
            workflow_id: step.workflow_id.clone(),
            summary: summarize_parent_playbook_text(&format!(
                "Spawned '{}' step for playbook '{}' with child {}.",
                step.label,
                run.playbook_label,
                step.child_session_id
                    .map(hex::encode)
                    .unwrap_or_else(|| "unknown".to_string())
            )),
            error_class: None,
        },
    );
}

fn emit_parent_playbook_step_completed_receipt(
    service: &DesktopAgentService,
    run: &ParentPlaybookRun,
    step: &ParentPlaybookStepRun,
    step_index: u32,
) {
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "step_completed".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: Some(step.step_id.clone()),
            step_label: Some(step.label.clone()),
            child_session_id: step.child_session_id.map(hex::encode),
            template_id: step.template_id.clone(),
            workflow_id: step.workflow_id.clone(),
            summary: summarize_parent_playbook_text(
                step.output_preview
                    .as_deref()
                    .unwrap_or("Parent playbook step completed."),
            ),
            error_class: None,
        },
    );
}

fn emit_parent_playbook_blocked_receipt(
    service: &DesktopAgentService,
    run: &ParentPlaybookRun,
    step: Option<&ParentPlaybookStepRun>,
    step_index: u32,
    error: &str,
) {
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "blocked".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: false,
            step_id: step.map(|value| value.step_id.clone()),
            step_label: step.map(|value| value.label.clone()),
            child_session_id: step.and_then(|value| value.child_session_id.map(hex::encode)),
            template_id: step.and_then(|value| value.template_id.clone()),
            workflow_id: step.and_then(|value| value.workflow_id.clone()),
            summary: summarize_parent_playbook_text(error),
            error_class: extract_error_class_token(Some(error)).map(str::to_string),
        },
    );
}

fn emit_parent_playbook_completed_receipt(
    service: &DesktopAgentService,
    run: &ParentPlaybookRun,
    step_index: u32,
) {
    emit_parent_playbook_receipt(
        service,
        run.parent_session_id,
        step_index,
        &run.playbook_id,
        WorkloadParentPlaybookReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "completed".to_string(),
            parent_session_id: hex::encode(run.parent_session_id),
            playbook_id: run.playbook_id.clone(),
            playbook_label: run.playbook_label.clone(),
            status: run.status.as_label().to_string(),
            success: true,
            step_id: None,
            step_label: None,
            child_session_id: None,
            template_id: None,
            workflow_id: None,
            summary: summarize_parent_playbook_text(&format!(
                "Completed parent playbook '{}' across {} steps.",
                run.playbook_label,
                run.steps.len()
            )),
            error_class: None,
        },
    );
}

pub(crate) fn register_parent_playbook_step_spawn(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &AgentState,
    parent_step_index: u32,
    child_session_id: [u8; 32],
    assignment: &WorkerAssignment,
) -> Result<(), String> {
    let Some(playbook_id) = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let Some(playbook) = builtin_agent_playbook(Some(playbook_id)) else {
        return Ok(());
    };

    let timestamp_ms = now_ms();
    let mut started = false;
    let mut run = match load_parent_playbook_run(state, parent_state.session_id, playbook_id)? {
        Some(existing) => existing,
        None => {
            started = true;
            build_parent_playbook_run(parent_state, &playbook, timestamp_ms)
        }
    };
    let Some(step_idx) = find_playbook_step_index(
        &playbook,
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    ) else {
        return Ok(());
    };
    if started {
        for prior_step in run.steps.iter_mut().take(step_idx) {
            prior_step.status = ParentPlaybookStepStatus::Completed;
            prior_step.output_preview =
                Some("Bootstrap assumed satisfied before active step.".to_string());
            prior_step.completed_at_ms = Some(timestamp_ms);
            prior_step.merged_at_ms = Some(timestamp_ms);
        }
    }

    let already_registered = run
        .steps
        .get(step_idx)
        .map(|step| step.child_session_id == Some(child_session_id))
        .unwrap_or(false);
    if already_registered {
        return Ok(());
    }

    run.status = ParentPlaybookStatus::Running;
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = Some(child_session_id);
    run.updated_at_ms = timestamp_ms;
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Running;
        step.child_session_id = Some(child_session_id);
        step.template_id = assignment.template_id.clone();
        step.workflow_id = assignment.workflow_id.clone();
        step.goal = Some(assignment.goal.clone());
        step.error = None;
        step.output_preview = None;
        step.spawned_at_ms = Some(timestamp_ms);
        step.completed_at_ms = None;
        step.merged_at_ms = None;
    }
    persist_parent_playbook_run(state, &run)?;
    if started {
        emit_parent_playbook_started_receipt(service, &run, parent_step_index);
    }
    if let Some(step) = run.steps.get(step_idx) {
        emit_parent_playbook_step_spawned_receipt(service, &run, step, parent_step_index);
    }
    Ok(())
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

async fn advance_parent_playbook_after_worker_merge(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    result: &WorkerSessionResult,
) -> Result<Option<String>, String> {
    let Some(playbook_id) = result
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(playbook) = builtin_agent_playbook(Some(playbook_id)) else {
        return Ok(None);
    };
    let Some(mut run) = load_parent_playbook_run(state, parent_state.session_id, playbook_id)?
    else {
        return Ok(None);
    };
    let Some(step_idx) = find_run_step_index_by_child(&run, result.child_session_id) else {
        return Ok(None);
    };
    let timestamp_ms = now_ms();
    if let Some(step) = run.steps.get_mut(step_idx) {
        step.status = ParentPlaybookStepStatus::Completed;
        step.output_preview = Some(summarize_parent_playbook_text(&result.merged_output));
        step.error = result.error.clone();
        step.completed_at_ms = Some(result.completed_at_ms);
        step.merged_at_ms = Some(timestamp_ms);
    }
    run.current_step_index = step_idx as u32;
    run.active_child_session_id = None;
    run.updated_at_ms = timestamp_ms;
    persist_parent_playbook_run(state, &run)?;
    if let Some(step) = run.steps.get(step_idx) {
        emit_parent_playbook_step_completed_receipt(service, &run, step, parent_step_index);
    }

    let Some(next_step_idx) = next_ready_playbook_step_index(&playbook, &run) else {
        run.status = ParentPlaybookStatus::Completed;
        run.completed_at_ms = Some(timestamp_ms);
        run.updated_at_ms = timestamp_ms;
        persist_parent_playbook_run(state, &run)?;
        emit_parent_playbook_completed_receipt(service, &run, parent_step_index);
        return Ok(Some(format!(
            "Parent playbook '{}' completed.",
            run.playbook_label
        )));
    };

    let next_step = playbook.steps.get(next_step_idx).cloned().ok_or_else(|| {
        "ERROR_CLASS=UnexpectedState Next parent playbook step was missing.".to_string()
    })?;
    let topic = run.topic.trim();
    let goal = next_step.goal_template.replace(
        "{topic}",
        if topic.is_empty() {
            parent_state.goal.trim()
        } else {
            topic
        },
    );
    let tool_hash = synthesize_parent_playbook_tool_hash(
        parent_state.session_id,
        &run.playbook_id,
        &next_step.step_id,
        parent_step_index,
    )?;
    match spawn_delegated_child_session(
        service,
        state,
        parent_state,
        tool_hash,
        &goal,
        playbook.default_budget,
        Some(&run.playbook_id),
        Some(&next_step.worker_template_id),
        Some(&next_step.worker_workflow_id),
        None,
        None,
        None,
        None,
        parent_step_index,
        block_height,
    )
    .await
    {
        Ok(spawned) => Ok(Some(format!(
            "Parent playbook '{}' advanced to '{}' (child {}).",
            run.playbook_label,
            next_step.label,
            hex::encode(spawned.child_session_id)
        ))),
        Err(error) => {
            let error_text = error.to_string();
            run.status = ParentPlaybookStatus::Blocked;
            run.current_step_index = next_step_idx as u32;
            run.updated_at_ms = now_ms();
            if let Some(step) = run.steps.get_mut(next_step_idx) {
                step.status = ParentPlaybookStepStatus::Blocked;
                step.error = Some(error_text.clone());
            }
            persist_parent_playbook_run(state, &run)?;
            emit_parent_playbook_blocked_receipt(
                service,
                &run,
                run.steps.get(next_step_idx),
                parent_step_index,
                &error_text,
            );
            Ok(Some(format!(
                "Parent playbook '{}' blocked while advancing to '{}': {}",
                run.playbook_label, next_step.label, error_text
            )))
        }
    }
}

fn merged_worker_output(
    assignment: &WorkerAssignment,
    success: bool,
    raw_output: Option<&str>,
    error: Option<&str>,
) -> String {
    let role = assignment
        .role
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Worker");
    let goal = assignment.goal.trim();
    let body = raw_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if success {
                assignment.completion_contract.expected_output.trim()
            } else {
                error.unwrap_or("Worker completed without an explicit result.")
            }
        });
    let verification = assignment
        .completion_contract
        .verification_hint
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let playbook_line = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|playbook_id| format!("Parent playbook: {}", playbook_id));
    let workflow = builtin_worker_workflow(
        assignment.template_id.as_deref(),
        assignment.workflow_id.as_deref(),
    );
    let workflow_line = workflow
        .as_ref()
        .map(|workflow| format!("Playbook: {} ({})", workflow.label, workflow.workflow_id));

    match assignment.completion_contract.merge_mode {
        WorkerMergeMode::AppendSummaryToParent => {
            let mut out = format!("{role} handoff\nGoal: {goal}");
            if let Some(playbook_line) = playbook_line.as_deref() {
                out.push_str(&format!("\n{playbook_line}"));
            }
            if let Some(workflow_line) = workflow_line.as_deref() {
                out.push_str(&format!("\n{workflow_line}"));
            }
            out.push_str(&format!("\n\n{body}"));
            if let Some(hint) = verification {
                out.push_str(&format!("\n\nVerification: {hint}"));
            }
            out
        }
        WorkerMergeMode::AppendAsEvidence => {
            let mut out = format!("Worker evidence\nRole: {role}\nGoal: {goal}",);
            if let Some(playbook_line) = playbook_line.as_deref() {
                out.push_str(&format!("\n{playbook_line}"));
            }
            if let Some(workflow_line) = workflow_line.as_deref() {
                out.push_str(&format!("\n{workflow_line}"));
            }
            out.push_str(&format!(
                "\nSuccess criteria: {}\n\n{body}",
                assignment.completion_contract.success_criteria
            ));
            if let Some(hint) = verification {
                out.push_str(&format!("\n\nVerification hint: {hint}"));
            }
            out
        }
        WorkerMergeMode::ReplaceParentDraft => body.to_string(),
        WorkerMergeMode::CompletionMessage => {
            if success {
                format!("{role} completed delegated work: {body}")
            } else {
                format!("{role} failed delegated work: {body}")
            }
        }
    }
}

fn materialize_worker_result(
    state: &mut dyn StateAccess,
    child_state: &AgentState,
) -> Result<WorkerSessionResult, String> {
    let child_session_id = child_state.session_id;
    let parent_session_id = child_state.parent_session_id.ok_or_else(|| {
        "ERROR_CLASS=UnexpectedState Child session is missing a parent session.".to_string()
    })?;

    let mut assignment =
        load_worker_assignment(state, child_session_id)?.unwrap_or_else(|| WorkerAssignment {
            step_key: format!("delegate:{}", hex::encode(&child_session_id[..4])),
            budget: child_state.budget,
            goal: child_state.goal.clone(),
            success_criteria: "Complete the delegated goal and return a deterministic handoff."
                .to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: Some(child_session_id),
            status: "running".to_string(),
            playbook_id: None,
            template_id: None,
            workflow_id: None,
            role: Some("Sub-Worker".to_string()),
            allowed_tools: Vec::new(),
            completion_contract: WorkerCompletionContract {
                success_criteria: "Complete the delegated goal and return a deterministic handoff."
                    .to_string(),
                expected_output: "Delegated worker handoff summarizing the completed slice."
                    .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        });

    let (status, success, raw_output, error) = match &child_state.status {
        AgentStatus::Completed(result) => (
            "Completed".to_string(),
            true,
            result.clone(),
            None::<String>,
        ),
        AgentStatus::Failed(reason) => ("Failed".to_string(), false, None, Some(reason.clone())),
        AgentStatus::Terminated => (
            "Terminated".to_string(),
            false,
            None,
            Some("Child agent terminated.".to_string()),
        ),
        AgentStatus::Running | AgentStatus::Idle | AgentStatus::Paused(_) => {
            return Err(
                "ERROR_CLASS=UnexpectedState Child worker is not in a terminal state.".to_string(),
            );
        }
    };

    assignment.status = status.clone();
    persist_worker_assignment(state, child_session_id, &assignment).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist worker assignment update: {}",
            error
        )
    })?;

    Ok(WorkerSessionResult {
        child_session_id,
        parent_session_id,
        budget: assignment.budget,
        playbook_id: assignment.playbook_id.clone(),
        template_id: assignment.template_id.clone(),
        workflow_id: assignment.workflow_id.clone(),
        role: assignment
            .role
            .clone()
            .unwrap_or_else(|| "Sub-Worker".to_string()),
        goal: assignment.goal.clone(),
        status,
        success,
        error: error.clone(),
        raw_output: raw_output.clone(),
        merged_output: merged_worker_output(
            &assignment,
            success,
            raw_output.as_deref(),
            error.as_deref(),
        ),
        completion_contract: assignment.completion_contract.clone(),
        completed_at_ms: now_ms(),
        merged_at_ms: None,
        merged_step_index: None,
    })
}

fn emit_worker_receipt(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    receipt: WorkloadWorkerReceipt,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let _ = tx.send(KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
        session_id,
        step_index,
        workload_id,
        timestamp_ms: now_ms(),
        receipt: WorkloadReceipt::Worker(receipt),
    }));
}

fn worker_receipt_summary(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= 240 {
        trimmed.to_string()
    } else {
        let mut summary = trimmed.chars().take(240).collect::<String>();
        summary.push_str("...");
        summary
    }
}

fn emit_worker_completion_receipt(
    service: &DesktopAgentService,
    result: &WorkerSessionResult,
    step_index: u32,
) {
    emit_worker_receipt(
        service,
        result.child_session_id,
        step_index,
        format!("worker::{}", hex::encode(result.child_session_id)),
        WorkloadWorkerReceipt {
            tool_name: "agent__delegate".to_string(),
            phase: "completed".to_string(),
            child_session_id: hex::encode(result.child_session_id),
            parent_session_id: hex::encode(result.parent_session_id),
            role: result.role.clone(),
            playbook_id: result.playbook_id.clone(),
            template_id: result.template_id.clone(),
            workflow_id: result.workflow_id.clone(),
            merge_mode: result.completion_contract.merge_mode.as_label().to_string(),
            status: result.status.clone(),
            success: result.success,
            summary: worker_receipt_summary(result.raw_output.as_deref().unwrap_or_else(|| {
                result
                    .error
                    .as_deref()
                    .unwrap_or("Worker completed without an explicit result.")
            })),
            verification_hint: result.completion_contract.verification_hint.clone(),
            error_class: extract_error_class_token(result.error.as_deref()).map(str::to_string),
        },
    );
}

fn emit_worker_merge_receipt(
    service: &DesktopAgentService,
    result: &WorkerSessionResult,
    parent_step_index: u32,
) {
    emit_worker_receipt(
        service,
        result.parent_session_id,
        parent_step_index,
        format!("worker::{}::merge", hex::encode(result.child_session_id)),
        WorkloadWorkerReceipt {
            tool_name: "agent__await_result".to_string(),
            phase: "merged".to_string(),
            child_session_id: hex::encode(result.child_session_id),
            parent_session_id: hex::encode(result.parent_session_id),
            role: result.role.clone(),
            playbook_id: result.playbook_id.clone(),
            template_id: result.template_id.clone(),
            workflow_id: result.workflow_id.clone(),
            merge_mode: result.completion_contract.merge_mode.as_label().to_string(),
            status: result.status.clone(),
            success: result.success,
            summary: worker_receipt_summary(&result.merged_output),
            verification_hint: result.completion_contract.verification_hint.clone(),
            error_class: extract_error_class_token(result.error.as_deref()).map(str::to_string),
        },
    );
}

pub(crate) async fn await_child_worker_result(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let child_session_id = parse_child_session_id_hex(child_session_id_hex)?;
    let child_state = load_child_state(
        state,
        service.memory_runtime.as_ref(),
        child_session_id,
        child_session_id_hex,
    )?;

    match &child_state.status {
        AgentStatus::Running | AgentStatus::Idle => Ok("Running".to_string()),
        AgentStatus::Paused(reason) => Ok(format!("Running (paused: {})", reason)),
        AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated => {
            let mut result = match load_worker_session_result(state, child_session_id)? {
                Some(existing) => existing,
                None => {
                    let materialized = materialize_worker_result(state, &child_state)?;
                    persist_worker_session_result(state, &materialized)?;
                    emit_worker_completion_receipt(service, &materialized, child_state.step_count);
                    materialized
                }
            };

            if result.parent_session_id != parent_state.session_id {
                return Err(format!(
                    "ERROR_CLASS=UnexpectedState Child session '{}' does not belong to the awaiting parent session.",
                    child_session_id_hex
                ));
            }

            if !result.success {
                return Err(format!(
                    "ERROR_CLASS={} Child agent failed: {}",
                    extract_error_class_token(result.error.as_deref()).unwrap_or("UnexpectedState"),
                    result.error.as_deref().unwrap_or("worker step failed")
                ));
            }

            if result.merged_at_ms.is_none() {
                result.merged_at_ms = Some(now_ms());
                result.merged_step_index = Some(parent_step_index);
                persist_worker_session_result(state, &result)?;
                emit_worker_merge_receipt(service, &result, parent_step_index);
                if let Some(playbook_update) = advance_parent_playbook_after_worker_merge(
                    service,
                    state,
                    parent_state,
                    parent_step_index,
                    block_height,
                    &result,
                )
                .await?
                {
                    return Ok(format!("{}\n\n{}", result.merged_output, playbook_update));
                }
            }
            Ok(result.merged_output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        await_child_worker_result, load_parent_playbook_run, load_worker_session_result,
        merged_worker_output, resolve_worker_assignment,
    };
    use crate::agentic::desktop::keys::get_state_key;
    use crate::agentic::desktop::service::lifecycle::delegation::spawn_delegated_child_session;
    use crate::agentic::desktop::service::DesktopAgentService;
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookStatus,
        ParentPlaybookStepStatus, WorkerMergeMode,
    };
    use crate::agentic::desktop::utils::persist_agent_state;
    use async_trait::async_trait;
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::MemoryRuntime;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
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
        assert!(merged.contains("Verify whether the parent claim is supported"));
        assert!(merged.contains("The claim is supported by two matching primary sources."));
        assert!(merged.contains("Verification hint"));
    }

    #[test]
    fn researcher_playbook_merge_preserves_playbook_identity() {
        let assignment = resolve_worker_assignment(
            [0x33; 32],
            3,
            64,
            "Research the latest kernel scheduler benchmarks.",
            Some("evidence_audited_patch"),
            Some("researcher"),
            Some("live_research_brief"),
            None,
            None,
            None,
            None,
        );

        let merged = merged_worker_output(
            &assignment,
            true,
            Some("Found three recent benchmark sources and one unresolved discrepancy."),
            None,
        );

        assert!(merged.contains("Parent playbook: evidence_audited_patch"));
        assert!(merged.contains("Playbook: Live Research Brief (live_research_brief)"));
        assert!(merged.contains("Found three recent benchmark sources"));
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
        assert!(child_state
            .goal
            .contains("run focused verification commands"));

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

        let research = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x52; 32],
            topic,
            196,
            Some("evidence_audited_patch"),
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
        .expect("research step should spawn");
        let research_id = research.child_session_id;
        assert_eq!(
            research.assignment.workflow_id.as_deref(),
            Some("live_research_brief")
        );

        let research_key = get_state_key(&research_id);
        let research_bytes = state
            .get(&research_key)
            .expect("research state lookup should succeed")
            .expect("research state should exist");
        let mut research_state: AgentState =
            codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
        research_state.status = AgentStatus::Completed(Some(
            "Cited brief: LocalAI parity requires registry execution, media lifecycle receipts, and bounded worker orchestration."
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
        assert!(merged_research.contains("advanced to 'Patch the workspace'"));

        let run_after_research =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("parent playbook run lookup should succeed")
                .expect("parent playbook run should exist");
        assert_eq!(run_after_research.status, ParentPlaybookStatus::Running);
        assert_eq!(
            run_after_research.steps[0].status,
            ParentPlaybookStepStatus::Completed
        );
        assert_eq!(
            run_after_research.steps[1].status,
            ParentPlaybookStepStatus::Running
        );
        let implement_id = run_after_research
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
        implement_state.status = AgentStatus::Completed(Some(
            "Touched files: crates/services/src/model.rs\nVerification: cargo check -p ioi-services (passed)\nResidual risk: broader end-to-end runtime parity still needs audit."
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
        assert!(merged_implement.contains("advanced to 'Audit the postcondition'"));

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
            ParentPlaybookStepStatus::Running
        );
        let audit_id = run_after_implement
            .active_child_session_id
            .expect("audit child should be active");

        let audit_key = get_state_key(&audit_id);
        let audit_bytes = state
            .get(&audit_key)
            .expect("audit state lookup should succeed")
            .expect("audit state should exist");
        let mut audit_state: AgentState =
            codec::from_bytes_canonical(&audit_bytes).expect("audit state should decode");
        assert!(audit_state.goal.contains("pass/fail audit"));
        audit_state.status = AgentStatus::Completed(Some(
            "Verdict: pass\nEvidence: Research brief captured the right constraints, the patch receipts show the implementation landed cleanly, and cargo check passed."
                .to_string(),
        ));
        persist_agent_state(
            &mut state,
            &audit_key,
            &audit_state,
            service.memory_runtime.as_ref(),
        )
        .expect("audit state update should persist");

        let merged_audit = await_child_worker_result(
            &service,
            &mut state,
            &mut parent_state,
            5,
            0,
            &hex::encode(audit_id),
        )
        .await
        .expect("audit merge should complete playbook");
        assert!(merged_audit.contains("Playbook: Postcondition Audit (postcondition_audit)"));
        assert!(merged_audit.contains("Parent playbook 'Evidence-Audited Patch' completed."));

        let final_run =
            load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
                .expect("final parent playbook run lookup should succeed")
                .expect("final parent playbook run should exist");
        assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
        assert!(final_run.completed_at_ms.is_some());
        assert_eq!(parent_state.child_session_ids.len(), 3);
        assert!(final_run
            .steps
            .iter()
            .all(|step| step.status == ParentPlaybookStepStatus::Completed));

        let mut parent_receipt_phases = Vec::new();
        while let Ok(event) = rx.try_recv() {
            if let KernelEvent::WorkloadReceipt(receipt_event) = event {
                if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                    parent_receipt_phases.push(receipt.phase);
                }
            }
        }

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
    }
}
