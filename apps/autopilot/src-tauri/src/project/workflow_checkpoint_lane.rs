// apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs

use super::sidecars::save_workflow_checkpoint;
use super::*;
use std::path::Path;

pub(super) fn workflow_checkpoint_state(
    workflow_path: &Path,
    state: &mut WorkflowStateSnapshot,
    run_id: &str,
    thread_id: &str,
    node_id: Option<&str>,
    status: &str,
    summary: String,
    checkpoints: &mut Vec<WorkflowCheckpoint>,
) -> Result<String, String> {
    let checkpoint_id = unique_runtime_id("checkpoint");
    state.checkpoint_id = checkpoint_id.clone();
    state.active_node_ids.sort();
    let checkpoint = WorkflowCheckpoint {
        id: checkpoint_id.clone(),
        thread_id: thread_id.to_string(),
        run_id: run_id.to_string(),
        created_at_ms: now_ms(),
        step_index: state.step_index,
        node_id: node_id.map(str::to_string),
        status: status.to_string(),
        summary,
    };
    save_workflow_checkpoint(workflow_path, &checkpoint, state)?;
    checkpoints.push(checkpoint);
    Ok(checkpoint_id)
}
