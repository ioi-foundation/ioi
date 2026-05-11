// apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs

use super::*;

fn workflow_graph_execution_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_graph_execution_node_id(node: &Value) -> Option<String> {
    workflow_graph_execution_value_string(node, "id")
}

pub(super) fn workflow_edge_from(edge: &Value) -> Option<String> {
    workflow_graph_execution_value_string(edge, "from")
}

pub(super) fn workflow_edge_to(edge: &Value) -> Option<String> {
    workflow_graph_execution_value_string(edge, "to")
}

pub(super) fn workflow_edge_from_port(edge: &Value) -> String {
    workflow_graph_execution_value_string(edge, "fromPort").unwrap_or_else(|| "output".to_string())
}

pub(super) fn workflow_edge_to_port(edge: &Value) -> String {
    workflow_graph_execution_value_string(edge, "toPort").unwrap_or_else(|| "input".to_string())
}

pub(super) fn workflow_edge_connection_class(edge: &Value) -> Option<String> {
    workflow_graph_execution_value_string(edge, "connectionClass").or_else(|| {
        edge.get("data")
            .and_then(|data| workflow_graph_execution_value_string(data, "connectionClass"))
    })
}

pub(super) fn workflow_has_incoming_connection_class(
    workflow: &WorkflowProject,
    node_id: &str,
    connection_class: &str,
) -> bool {
    workflow.edges.iter().any(|edge| {
        workflow_edge_to(edge).as_deref() == Some(node_id)
            && (workflow_edge_connection_class(edge).as_deref() == Some(connection_class)
                || workflow_edge_to_port(edge) == connection_class)
    })
}

pub(super) fn workflow_edge_is_selected(
    edge: &Value,
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> bool {
    let Some(source_id) = workflow_edge_from(edge) else {
        return false;
    };
    let Some(branch) = branch_decisions.get(&source_id) else {
        return true;
    };
    let from_port = workflow_edge_from_port(edge);
    from_port == *branch || (from_port == "output" && branch == "output")
}

pub(super) fn workflow_node_ready(
    node_id: &str,
    workflow: &WorkflowProject,
    completed: &std::collections::BTreeSet<String>,
    active_queue: &[String],
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> bool {
    if completed.contains(node_id) || active_queue.iter().any(|queued| queued == node_id) {
        return false;
    }
    let incoming = workflow
        .edges
        .iter()
        .filter(|edge| workflow_edge_to(edge).as_deref() == Some(node_id))
        .collect::<Vec<_>>();
    if incoming.is_empty() {
        return true;
    }
    let mut selected_count = 0usize;
    for edge in incoming {
        let Some(source_id) = workflow_edge_from(edge) else {
            continue;
        };
        if !workflow_edge_is_selected(edge, branch_decisions) {
            continue;
        }
        selected_count += 1;
        if !completed.contains(&source_id) {
            return false;
        }
    }
    selected_count > 0
}

pub(super) fn workflow_next_ready_nodes(
    workflow: &WorkflowProject,
    completed: &std::collections::BTreeSet<String>,
    active_queue: &[String],
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    workflow
        .nodes
        .iter()
        .filter_map(workflow_graph_execution_node_id)
        .filter(|node_id| {
            workflow_node_ready(node_id, workflow, completed, active_queue, branch_decisions)
        })
        .collect()
}

pub(super) fn workflow_node_lifecycle_steps(status: &str) -> Vec<String> {
    let mut steps = vec![
        "validate_config",
        "resolve_binding",
        "check_policy",
        "prepare_inputs",
        "execute_attempt",
    ];
    match status {
        "success" => steps.extend([
            "validate_output",
            "record_run",
            "checkpoint",
            "emit_event",
            "evaluate_completion",
        ]),
        "interrupted" => {
            steps.extend(["record_interrupt", "record_run", "checkpoint", "emit_event"])
        }
        "error" | "blocked" => steps.extend(["record_run", "checkpoint", "emit_event"]),
        _ => {}
    }
    steps.into_iter().map(str::to_string).collect()
}
