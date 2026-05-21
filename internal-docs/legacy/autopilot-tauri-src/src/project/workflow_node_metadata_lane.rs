// apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs

use super::*;

pub(super) fn workflow_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(super) fn workflow_node_id(node: &Value) -> Option<String> {
    workflow_value_string(node, "id")
}

pub(super) fn workflow_node_type(node: &Value) -> String {
    workflow_value_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn workflow_node_name(node: &Value) -> String {
    workflow_value_string(node, "name").unwrap_or_else(|| "Workflow step".to_string())
}

pub(super) fn workflow_node_logic(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("logic"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_node_law(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("law"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_node_by_id<'a>(
    workflow: &'a WorkflowProject,
    node_id: &str,
) -> Option<&'a Value> {
    workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some(node_id))
}
