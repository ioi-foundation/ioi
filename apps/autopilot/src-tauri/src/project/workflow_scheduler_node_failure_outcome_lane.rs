// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_node_execution_lane::WorkflowSchedulerNodeExecutionFlow;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn workflow_scheduler_handle_node_failure_outcome(
    workflow_path: &Path,
    node: &Value,
    node_id: String,
    error: String,
    mut node_run: WorkflowNodeRun,
    run_id: &str,
    thread_id: &str,
    state: &mut WorkflowStateSnapshot,
    active_queue: &[String],
    node_runs: &mut Vec<WorkflowNodeRun>,
    checkpoints: &mut Vec<WorkflowCheckpoint>,
    events: &mut Vec<WorkflowStreamEvent>,
) -> Result<WorkflowSchedulerNodeExecutionFlow, String> {
    state.blocked_node_ids.push(node_id.clone());
    state.step_index += 1;
    state.active_node_ids = active_queue.to_vec();
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        state,
        run_id,
        thread_id,
        Some(&node_id),
        "failed",
        format!("{} failed.", workflow_node_name(node)),
        checkpoints,
    )?;
    node_run.status = "error".to_string();
    node_run.finished_at_ms = Some(now_ms());
    node_run.error = Some(error.clone());
    node_run.checkpoint_id = Some(checkpoint_id);
    node_run.lifecycle = workflow_node_lifecycle_steps("error");
    node_runs.push(node_run);
    workflow_push_event(
        events,
        run_id,
        thread_id,
        "node_failed",
        Some(&node_id),
        Some("error"),
        Some(error),
        None,
    );
    Ok(WorkflowSchedulerNodeExecutionFlow::Stop)
}
