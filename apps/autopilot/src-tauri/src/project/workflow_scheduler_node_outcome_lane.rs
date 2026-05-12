// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs

use std::collections::BTreeSet;

use super::workflow_checkpoint_lane::workflow_checkpoint_state;
use super::workflow_graph_execution_lane::{
    workflow_next_ready_nodes, workflow_node_lifecycle_steps,
};
use super::workflow_node_metadata_lane::{workflow_node_logic, workflow_node_name};
use super::workflow_run_lifecycle_lane::workflow_push_event;
use super::workflow_scheduler_node_execution_lane::WorkflowSchedulerNodeExecutionFlow;
use super::workflow_state_lane::workflow_selected_output;
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
            let selected_output = workflow_selected_output(node, &output);
            if *action_kind == ActionKind::Decision {
                state
                    .branch_decisions
                    .insert(node_id.clone(), selected_output.clone());
            }
            completed.insert(node_id.clone());
            state.completed_node_ids = completed.iter().cloned().collect();
            state.interrupted_node_ids.retain(|id| id != &node_id);
            state.node_outputs.insert(node_id.clone(), output.clone());
            let update = if *action_kind == ActionKind::State {
                let key = output
                    .get("stateKey")
                    .and_then(Value::as_str)
                    .unwrap_or(&node_id)
                    .to_string();
                let reducer = output
                    .get("reducer")
                    .and_then(Value::as_str)
                    .unwrap_or("replace")
                    .to_string();
                let value = output
                    .get("value")
                    .cloned()
                    .unwrap_or_else(|| output.clone());
                match reducer.as_str() {
                    "merge" => {
                        let mut merged = state
                            .values
                            .get(&key)
                            .cloned()
                            .or_else(|| workflow_node_logic(node).get("initialValue").cloned())
                            .unwrap_or_else(|| json!({}));
                        if let (Some(current), Some(next)) =
                            (merged.as_object_mut(), value.as_object())
                        {
                            for (item_key, item_value) in next {
                                current.insert(item_key.clone(), item_value.clone());
                            }
                            state.values.insert(key.clone(), merged.clone());
                        } else {
                            state.values.insert(key.clone(), value.clone());
                        }
                    }
                    "append" => {
                        let mut list = state
                            .values
                            .get(&key)
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        list.push(value.clone());
                        state.values.insert(key.clone(), Value::Array(list));
                    }
                    _ => {
                        state.values.insert(key.clone(), value.clone());
                    }
                }
                WorkflowStateUpdate {
                    node_id: node_id.clone(),
                    key,
                    value,
                    reducer,
                }
            } else {
                state.values.insert(node_id.clone(), output.clone());
                WorkflowStateUpdate {
                    node_id: node_id.clone(),
                    key: node_id.clone(),
                    value: output.clone(),
                    reducer: "replace".to_string(),
                }
            };
            state.pending_writes.clear();
            state.step_index += 1;
            active_queue.extend(workflow_next_ready_nodes(
                workflow,
                completed,
                active_queue,
                &state.branch_decisions,
            ));
            state.active_node_ids = active_queue.clone();
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
            workflow_push_event(
                events,
                run_id,
                thread_id,
                "node_succeeded",
                Some(&node_id),
                Some("success"),
                Some(format!("{} completed.", workflow_node_name(node))),
                Some(vec![update]),
            );
            if output.get("toolKind").and_then(Value::as_str) == Some("workflow_tool") {
                let child_run_id = output
                    .get("childRunId")
                    .and_then(Value::as_str)
                    .unwrap_or("child run");
                let child_status = output
                    .get("childRunStatus")
                    .and_then(Value::as_str)
                    .unwrap_or("completed");
                workflow_push_event(
                    events,
                    run_id,
                    thread_id,
                    "child_run_completed",
                    Some(&node_id),
                    Some(child_status),
                    Some(format!(
                        "{} completed child workflow run {}.",
                        workflow_node_name(node),
                        child_run_id
                    )),
                    None,
                );
            }
            if *action_kind == ActionKind::Output {
                workflow_push_event(
                    events,
                    run_id,
                    thread_id,
                    "output_created",
                    Some(&node_id),
                    Some("success"),
                    Some(format!(
                        "{} produced an output bundle.",
                        workflow_node_name(node)
                    )),
                    None,
                );
                if output
                    .get("outputBundle")
                    .and_then(|bundle| bundle.get("materializedAssets"))
                    .and_then(Value::as_array)
                    .map(|assets| !assets.is_empty())
                    .unwrap_or(false)
                {
                    workflow_push_event(
                        events,
                        run_id,
                        thread_id,
                        "asset_materialized",
                        Some(&node_id),
                        Some("success"),
                        Some(format!(
                            "{} recorded a materialized asset.",
                            workflow_node_name(node)
                        )),
                        None,
                    );
                }
            }
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
