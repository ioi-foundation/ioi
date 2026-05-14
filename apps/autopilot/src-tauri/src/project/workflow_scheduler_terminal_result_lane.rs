// apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs

use super::workflow_execution_results_lane::{
    workflow_completion_requirements, workflow_finalize_run_result, WorkflowRunResultParts,
};
use super::workflow_harness_results_lane::workflow_attach_harness_run_artifacts;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::*;

pub(super) struct WorkflowSchedulerTerminalResultParts {
    pub summary: WorkflowRunSummary,
    pub checkpoint_id: String,
    pub run_completed_message: String,
    pub final_state: WorkflowStateSnapshot,
    pub node_runs: Vec<WorkflowNodeRun>,
    pub checkpoints: Vec<WorkflowCheckpoint>,
    pub events: Vec<WorkflowStreamEvent>,
    pub completion_requirements: Option<Vec<WorkflowCompletionRequirement>>,
    pub interrupt: Option<WorkflowInterrupt>,
}

pub(super) fn workflow_scheduler_terminal_summary(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    test_count: usize,
    started_at_ms: u64,
    run_id: &str,
    thread_id: &str,
    status: &str,
    checkpoint_count: usize,
    interrupt_id: Option<String>,
    summary: String,
) -> WorkflowRunSummary {
    WorkflowRunSummary {
        id: run_id.to_string(),
        thread_id: Some(thread_id.to_string()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: workflow.nodes.len(),
        test_count: Some(test_count),
        checkpoint_count: Some(checkpoint_count),
        interrupt_id,
        summary,
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    }
}

pub(super) fn workflow_scheduler_terminal_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    thread: WorkflowThread,
    run_id: &str,
    thread_id: &str,
    mut parts: WorkflowSchedulerTerminalResultParts,
) -> Result<WorkflowRunResult, String> {
    workflow_push_event(
        &mut parts.events,
        run_id,
        thread_id,
        "run_completed",
        None,
        Some(&parts.summary.status),
        Some(parts.run_completed_message.clone()),
        None,
    );
    let mut final_thread = thread;
    final_thread.status = parts.summary.status.clone();
    final_thread.latest_checkpoint_id = Some(parts.checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let completion_requirements = parts.completion_requirements.unwrap_or_else(|| {
        workflow_completion_requirements(workflow, &parts.final_state, &parts.node_runs)
    });
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, run_id, &mut parts.node_runs);
    workflow_finalize_run_result(
        workflow_path,
        workflow,
        WorkflowRunResultParts {
            summary: parts.summary,
            thread: final_thread,
            final_state: parts.final_state,
            node_runs: parts.node_runs,
            checkpoints: parts.checkpoints,
            events: parts.events,
            runtime_thread_events: Vec::new(),
            tui_control_state: None,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            completion_requirements,
            interrupt: parts.interrupt,
        },
    )
}
