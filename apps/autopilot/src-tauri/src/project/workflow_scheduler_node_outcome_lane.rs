// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs

use std::collections::BTreeSet;

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_graph_execution_lane::workflow_node_lifecycle_steps;
use super::workflow_node_metadata_lane::workflow_node_name;
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_node_execution_lane::WorkflowSchedulerNodeExecutionFlow;
use super::workflow_scheduler_node_state_update_lane::workflow_scheduler_apply_node_state_update;
use super::workflow_scheduler_node_success_event_lane::workflow_scheduler_emit_node_success_events;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn workflow_scheduler_handle_node_outcome(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node: &Value,
    node_id: String,
    action_kind: &ActionKind,
    execution_result: Result<Value, String>,
    mut node_run: WorkflowNodeRun,
    run_id: &str,
    thread_id: &str,
    state: &mut WorkflowStateSnapshot,
    completed: &mut BTreeSet<String>,
    active_queue: &mut Vec<String>,
    node_runs: &mut Vec<WorkflowNodeRun>,
    checkpoints: &mut Vec<WorkflowCheckpoint>,
    events: &mut Vec<WorkflowStreamEvent>,
) -> Result<WorkflowSchedulerNodeExecutionFlow, String> {
    match execution_result {
        Ok(output) => {
            let update = workflow_scheduler_apply_node_state_update(
                workflow,
                node,
                &node_id,
                action_kind,
                &output,
                state,
                completed,
                active_queue,
            );
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                state,
                run_id,
                thread_id,
                Some(&node_id),
                "running",
                format!("{} completed.", workflow_node_name(node)),
                checkpoints,
            )?;
            node_run.status = "success".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.output = Some(output.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("success");
            workflow_scheduler_emit_node_success_events(
                events,
                run_id,
                thread_id,
                &node_id,
                node,
                action_kind,
                &output,
                update,
            );
            node_runs.push(node_run);
            Ok(WorkflowSchedulerNodeExecutionFlow::Continue)
        }
        Err(error) => {
            state.blocked_node_ids.push(node_id.clone());
            state.step_index += 1;
            state.active_node_ids = active_queue.clone();
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
    }
}
