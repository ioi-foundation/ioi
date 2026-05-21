// apps/autopilot/src-tauri/src/project/workflow_node_input_lane.rs

use serde_json::Value;

fn workflow_collect_inputs_by_kind(value: &Value, kind: &str, collected: &mut Vec<Value>) {
    if value.get("kind").and_then(Value::as_str) == Some(kind) {
        collected.push(value.clone());
    }
    match value {
        Value::Array(items) => {
            for item in items {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        Value::Object(object) => {
            for item in object.values() {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        _ => {}
    }
}

pub(super) fn workflow_inputs_by_kind(input: &Value, kind: &str) -> Vec<Value> {
    let mut collected = Vec::new();
    workflow_collect_inputs_by_kind(input, kind, &mut collected);
    collected
}
