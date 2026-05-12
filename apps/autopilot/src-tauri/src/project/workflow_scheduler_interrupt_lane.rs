// apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs

use super::workflow_approval_interrupt_lane::{
    workflow_runtime_interrupt, workflow_runtime_interrupt_notice,
};
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_terminal_result_lane::{
    workflow_scheduler_terminal_result, workflow_scheduler_terminal_summary,
    WorkflowSchedulerTerminalResultParts,
};
use super::*;

pub(super) fn workflow_scheduler_interrupted_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    node: &Value,
    node_id: String,
    node_type: String,
    action_kind: &ActionKind,
    input: Value,
    active_queue: Vec<String>,
    runtime_approval_preview: Option<Value>,
    started_at_ms: u64,
    run_id: &str,
    thread_id: &str,
    mut node_runs: Vec<WorkflowNodeRun>,
    mut checkpoints: Vec<WorkflowCheckpoint>,
    mut events: Vec<WorkflowStreamEvent>,
) -> Result<WorkflowRunResult, String> {
    let interrupt = workflow_runtime_interrupt(
        run_id,
        thread_id,
        node,
        action_kind,
        runtime_approval_preview,
    );
    let interrupt_id = interrupt.id.clone();
    state.interrupted_node_ids.push(node_id.clone());
    state.active_node_ids = active_queue;
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        run_id,
        thread_id,
        Some(&node_id),
        "interrupted",
        format!("Run paused at '{}'.", workflow_node_name(node)),
        &mut checkpoints,
    )?;
    workflow_push_event(
        &mut events,
        run_id,
        thread_id,
        "node_interrupted",
        Some(&node_id),
        Some("interrupted"),
        Some(workflow_runtime_interrupt_notice(action_kind)),
        None,
    );
    node_runs.push(WorkflowNodeRun {
        node_id: node_id.clone(),
        node_type,
        status: "interrupted".to_string(),
        started_at_ms: now_ms(),
        finished_at_ms: Some(now_ms()),
        attempt: 1,
        input: Some(input),
        output: None,
        error: None,
        checkpoint_id: Some(checkpoint_id.clone()),
        lifecycle: workflow_node_lifecycle_steps("interrupted"),
        harness_attempt: None,
    });
    fs::create_dir_all(workflow_interrupts_dir(workflow_path))
        .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
    write_json_pretty(&workflow_interrupt_path(workflow_path, run_id), &interrupt)?;
    let summary = workflow_scheduler_terminal_summary(
        workflow_path,
        workflow,
        test_count,
        started_at_ms,
        run_id,
        thread_id,
        "interrupted",
        checkpoints.len(),
        Some(interrupt_id),
        format!("Run paused at '{}'.", workflow_node_name(node)),
    );
    workflow_scheduler_terminal_result(
        workflow_path,
        workflow,
        thread,
        run_id,
        thread_id,
        WorkflowSchedulerTerminalResultParts {
            summary,
            checkpoint_id,
            run_completed_message: "Run paused for human input.".to_string(),
            final_state: state,
            node_runs,
            checkpoints,
            events,
            completion_requirements: None,
            interrupt: Some(interrupt),
        },
    )
}
