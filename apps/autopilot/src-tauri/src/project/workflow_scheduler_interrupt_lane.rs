// apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs

use super::workflow_approval_interrupt_lane::{
    workflow_runtime_interrupt, workflow_runtime_interrupt_notice,
};
use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_execution_results_lane::{
    workflow_completion_requirements, workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
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
    workflow_push_event(
        &mut events,
        run_id,
        thread_id,
        "run_completed",
        None,
        Some("interrupted"),
        Some("Run paused for human input.".to_string()),
        None,
    );
    fs::create_dir_all(workflow_interrupts_dir(workflow_path))
        .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
    write_json_pretty(&workflow_interrupt_path(workflow_path, run_id), &interrupt)?;
    let summary = WorkflowRunSummary {
        id: run_id.to_string(),
        thread_id: Some(thread_id.to_string()),
        status: "interrupted".to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: workflow.nodes.len(),
        test_count: Some(test_count),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: Some(interrupt_id),
        summary: format!("Run paused at '{}'.", workflow_node_name(node)),
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    let mut final_thread = thread;
    final_thread.status = "interrupted".to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, run_id, &mut node_runs);
    let completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            completion_requirements,
            interrupt: Some(interrupt),
        },
    )
}
