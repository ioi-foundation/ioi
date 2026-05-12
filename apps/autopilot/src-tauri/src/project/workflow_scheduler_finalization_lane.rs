// apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_execution_results_lane::{
    workflow_completion_has_missing, workflow_completion_requirements,
    workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::*;

pub(super) fn workflow_scheduler_finalized_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    started_at_ms: u64,
    run_id: &str,
    thread_id: &str,
    mut node_runs: Vec<WorkflowNodeRun>,
    mut checkpoints: Vec<WorkflowCheckpoint>,
    mut events: Vec<WorkflowStreamEvent>,
) -> Result<WorkflowRunResult, String> {
    let mut status = if !state.blocked_node_ids.is_empty() {
        "failed"
    } else if !state.interrupted_node_ids.is_empty() {
        "interrupted"
    } else {
        "passed"
    };
    let mut completion_requirements =
        workflow_completion_requirements(workflow, &state, &node_runs);
    if status == "passed" && workflow_completion_has_missing(&completion_requirements) {
        status = "failed";
        state
            .blocked_node_ids
            .extend(completion_requirements.iter().filter_map(|requirement| {
                (requirement.status != "satisfied")
                    .then(|| requirement.node_id.clone())
                    .flatten()
            }));
        state.blocked_node_ids.sort();
        state.blocked_node_ids.dedup();
        completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    }
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        run_id,
        thread_id,
        None,
        status,
        format!("Workflow run {}.", status),
        &mut checkpoints,
    )?;
    let summary = WorkflowRunSummary {
        id: run_id.to_string(),
        thread_id: Some(thread_id.to_string()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: workflow.nodes.len(),
        test_count: Some(test_count),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if status == "passed" {
            "Workflow completed with durable checkpoints.".to_string()
        } else {
            format!("Workflow {} with structured blockers.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        run_id,
        thread_id,
        "run_completed",
        None,
        Some(status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread;
    final_thread.status = status.to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, run_id, &mut node_runs);
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
            interrupt: None,
        },
    )
}
