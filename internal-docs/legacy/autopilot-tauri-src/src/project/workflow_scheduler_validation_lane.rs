// apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_scheduler_terminal_result_lane::{
    workflow_scheduler_terminal_result, workflow_scheduler_terminal_summary,
    WorkflowSchedulerTerminalResultParts,
};
use super::*;

pub(super) fn workflow_scheduler_validation_blocked_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    validation: WorkflowValidationResult,
    started_at_ms: u64,
    run_id: &str,
    thread_id: &str,
    node_runs: Vec<WorkflowNodeRun>,
    mut checkpoints: Vec<WorkflowCheckpoint>,
    events: Vec<WorkflowStreamEvent>,
) -> Result<WorkflowRunResult, String> {
    state.blocked_node_ids = validation.blocked_nodes.clone();
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        run_id,
        thread_id,
        None,
        &validation.status,
        format!(
            "Workflow blocked by {} validation issue(s).",
            validation.blocked_nodes.len()
        ),
        &mut checkpoints,
    )?;
    let summary_text = format!(
        "Workflow blocked by {} validation issue(s).",
        validation.errors.len() + validation.warnings.len()
    );
    let summary = workflow_scheduler_terminal_summary(
        workflow_path,
        workflow,
        test_count,
        started_at_ms,
        run_id,
        thread_id,
        &validation.status,
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
            completion_requirements: None,
            interrupt: None,
        },
    )
}
