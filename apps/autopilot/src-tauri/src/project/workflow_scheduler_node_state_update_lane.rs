// apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs

use std::collections::BTreeSet;

use super::workflow_graph_execution_lane::workflow_next_ready_nodes;
use super::workflow_node_metadata_lane::workflow_node_logic;
use super::workflow_state_lane::workflow_selected_output;
use super::*;

pub(super) fn workflow_scheduler_apply_node_state_update(
    workflow: &WorkflowProject,
    node: &Value,
    node_id: &str,
    action_kind: &ActionKind,
    output: &Value,
    state: &mut WorkflowStateSnapshot,
    completed: &mut BTreeSet<String>,
    active_queue: &mut Vec<String>,
) -> WorkflowStateUpdate {
    let selected_output = workflow_selected_output(node, output);
    if *action_kind == ActionKind::Decision {
        state
            .branch_decisions
            .insert(node_id.to_string(), selected_output);
    }
    completed.insert(node_id.to_string());
    state.completed_node_ids = completed.iter().cloned().collect();
    state.interrupted_node_ids.retain(|id| id != node_id);
    state
        .node_outputs
        .insert(node_id.to_string(), output.clone());

    let update = if *action_kind == ActionKind::State {
        let key = output
            .get("stateKey")
            .and_then(Value::as_str)
            .unwrap_or(node_id)
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
                if let (Some(current), Some(next)) = (merged.as_object_mut(), value.as_object()) {
                    for (item_key, item_value) in next {
                        current.insert(item_key.clone(), item_value.clone());
                    }
                    state.values.insert(key.clone(), merged);
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
            node_id: node_id.to_string(),
            key,
            value,
            reducer,
        }
    } else {
        state.values.insert(node_id.to_string(), output.clone());
        WorkflowStateUpdate {
            node_id: node_id.to_string(),
            key: node_id.to_string(),
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

    update
}
