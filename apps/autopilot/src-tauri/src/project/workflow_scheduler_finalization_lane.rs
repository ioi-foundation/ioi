// apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_execution_results_lane::{
    workflow_completion_has_missing, workflow_completion_requirements,
};
use super::workflow_scheduler_terminal_result_lane::{
    workflow_scheduler_terminal_result, workflow_scheduler_terminal_summary,
    WorkflowSchedulerTerminalResultParts,
};
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
    node_runs: Vec<WorkflowNodeRun>,
    mut checkpoints: Vec<WorkflowCheckpoint>,
    events: Vec<WorkflowStreamEvent>,
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
    let summary_text = if status == "passed" {
        "Workflow completed with durable checkpoints.".to_string()
    } else {
        format!("Workflow {} with structured blockers.", status)
    };
    let summary = workflow_scheduler_terminal_summary(
        workflow_path,
        workflow,
        test_count,
        started_at_ms,
        run_id,
        thread_id,
        status,
        checkpoints.len(),
        None,
        summary_text.clone(),
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
            run_completed_message: summary_text,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            completion_requirements: Some(completion_requirements),
            interrupt: None,
        },
    )
}
