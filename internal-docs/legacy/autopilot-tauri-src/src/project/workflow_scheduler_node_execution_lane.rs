// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs

use std::collections::BTreeSet;

use super::workflow_coding_route_lane::WorkflowSkillResolver;
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_node_execution_lane::execute_workflow_node;
use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_node_outcome_lane::workflow_scheduler_handle_node_outcome;
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkflowSchedulerNodeExecutionFlow {
    Continue,
    Stop,
}

pub(super) fn workflow_scheduler_execute_node(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node: &Value,
    node_id: String,
    node_type: String,
    action_kind: &ActionKind,
    input: Value,
    resume_gate: Option<&(String, Value)>,
    skill_resolver: &WorkflowSkillResolver,
    runtime: &WorkflowExecutionRuntime,
    run_id: &str,
    thread_id: &str,
    state: &mut WorkflowStateSnapshot,
    completed: &mut BTreeSet<String>,
    active_queue: &mut Vec<String>,
    node_runs: &mut Vec<WorkflowNodeRun>,
    checkpoints: &mut Vec<WorkflowCheckpoint>,
    events: &mut Vec<WorkflowStreamEvent>,
) -> Result<WorkflowSchedulerNodeExecutionFlow, String> {
    let mut node_run = WorkflowNodeRun {
        node_id: node_id.clone(),
        node_type: node_type.clone(),
        status: "running".to_string(),
        started_at_ms: now_ms(),
        finished_at_ms: None,
        attempt: 1,
        input: Some(input.clone()),
        output: None,
        error: None,
        checkpoint_id: None,
        lifecycle: Vec::new(),
        harness_attempt: None,
    };
    workflow_push_event(
        events,
        run_id,
        thread_id,
        "node_started",
        Some(&node_id),
        Some("running"),
        Some(format!("{} started.", workflow_node_name(node))),
        None,
    );
    let max_attempts = workflow_max_attempts(node);
    let mut execution_result = Err("Node did not execute.".to_string());
    for attempt in 1..=max_attempts {
        node_run.attempt = attempt;
        let resume_value = resume_gate
            .and_then(|(resume_node_id, value)| (resume_node_id == &node_id).then_some(value));
        execution_result = execute_workflow_node(
            workflow_path,
            Some(workflow),
            node,
            input.clone(),
            attempt,
            resume_value,
            skill_resolver,
            runtime,
        );
        if execution_result.is_ok() || attempt == max_attempts {
            break;
        }
        node_runs.push(WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            status: "error".to_string(),
            started_at_ms: node_run.started_at_ms,
            finished_at_ms: Some(now_ms()),
            attempt,
            input: Some(input.clone()),
            output: None,
            error: execution_result.as_ref().err().cloned(),
            checkpoint_id: None,
            lifecycle: workflow_node_lifecycle_steps("error"),
            harness_attempt: None,
        });
        workflow_push_event(
            events,
            run_id,
            thread_id,
            "node_failed",
            Some(&node_id),
            Some("retrying"),
            Some(format!(
                "Retrying '{}' after attempt {}.",
                workflow_node_name(node),
                attempt
            )),
            None,
        );
    }

    workflow_scheduler_handle_node_outcome(
        workflow_path,
        workflow,
        node,
        node_id,
        action_kind,
        execution_result,
        node_run,
        run_id,
        thread_id,
        state,
        completed,
        active_queue,
        node_runs,
        checkpoints,
        events,
    )
}
