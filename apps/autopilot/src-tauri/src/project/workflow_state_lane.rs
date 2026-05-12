// apps/autopilot/src-tauri/src/project/workflow_state_lane.rs

use super::workflow_graph_execution_lane::{
    workflow_edge_connection_class, workflow_edge_from, workflow_edge_from_port, workflow_edge_to,
    workflow_edge_to_port,
};
use super::workflow_node_metadata_lane::{
    workflow_node_by_id, workflow_node_id, workflow_node_logic, workflow_node_name,
    workflow_node_type,
};
use super::workflow_value_helpers::workflow_value_at_path;
use super::*;
use regex::Regex;

pub(super) fn collect_workflow_expression_refs(
    value: &Value,
    refs: &mut Vec<(String, String, String)>,
) {
    match value {
        Value::String(text) => {
            let pattern =
                Regex::new(r"\{\{\s*nodes\.([A-Za-z0-9_.:-]+)\.([A-Za-z0-9_.:-]+)\s*\}\}")
                    .expect("workflow expression regex should compile");
            for capture in pattern.captures_iter(text) {
                let expression = capture
                    .get(0)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                let node_id = capture
                    .get(1)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                let port_id = capture
                    .get(2)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                refs.push((expression, node_id, port_id));
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_workflow_expression_refs(item, refs);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_workflow_expression_refs(item, refs);
            }
        }
        _ => {}
    }
}

pub(super) fn workflow_schema_from_sample(value: &Value) -> Value {
    match value {
        Value::Array(items) => json!({
            "type": "array",
            "items": items.first().map(workflow_schema_from_sample).unwrap_or_else(|| json!({"type": "unknown"}))
        }),
        Value::Object(map) => json!({
            "type": "object",
            "properties": map
                .iter()
                .map(|(key, child)| (key.clone(), workflow_schema_from_sample(child)))
                .collect::<serde_json::Map<String, Value>>()
        }),
        Value::String(_) => json!({"type": "string"}),
        Value::Number(number) if number.is_i64() || number.is_u64() => json!({"type": "integer"}),
        Value::Number(_) => json!({"type": "number"}),
        Value::Bool(_) => json!({"type": "boolean"}),
        Value::Null => json!({"type": "null"}),
    }
}

pub(super) fn workflow_schema_is_object_like(schema: Option<&Value>) -> bool {
    schema
        .and_then(|value| value.as_object())
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub(super) fn workflow_node_declared_output_schema(node: &Value) -> Value {
    let logic = workflow_node_logic(node);
    if workflow_node_type(node) == "skill_context" {
        return workflow_skill_context_output_schema();
    }
    if workflow_node_type(node) == "workflow_package_export" {
        return workflow_package_export_output_schema();
    }
    if workflow_node_type(node) == "workflow_package_import" {
        return workflow_package_import_output_schema();
    }
    if workflow_node_type(node) == "github_pr_create" {
        return workflow_github_pr_create_output_schema();
    }
    workflow_node_output_schema(node)
        .or_else(|| logic.get("schema").cloned())
        .or_else(|| logic.get("payload").map(workflow_schema_from_sample))
        .unwrap_or_else(|| json!({"type": "object"}))
}

pub(super) fn workflow_schema_has_field_path(schema: &Value, path: &str) -> bool {
    let segments = path
        .split('.')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    let mut current = schema;
    for segment in segments {
        if segment == "[]" {
            if current.get("type").and_then(Value::as_str) != Some("array") {
                return false;
            }
            let Some(items) = current.get("items") else {
                return false;
            };
            current = items;
            continue;
        }
        let Some(properties) = current.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let Some(next) = properties.get(segment) else {
            return false;
        };
        current = next;
    }
    true
}

pub(super) fn workflow_node_has_output_port(node: &Value, port_id: &str) -> bool {
    if node
        .get("ports")
        .and_then(Value::as_array)
        .map(|ports| {
            ports.iter().any(|port| {
                port.get("id").and_then(Value::as_str) == Some(port_id)
                    && port.get("direction").and_then(Value::as_str) == Some("output")
            })
        })
        .unwrap_or(false)
    {
        return true;
    }
    node.get("outputs")
        .and_then(Value::as_array)
        .map(|outputs| outputs.iter().any(|item| item.as_str() == Some(port_id)))
        .unwrap_or(false)
}

pub(super) fn validate_workflow_expression_refs(
    workflow: &WorkflowProject,
    node: &Value,
    logic: &Value,
) -> Vec<WorkflowValidationIssue> {
    let Some(node_id) = workflow_node_id(node) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    collect_workflow_expression_refs(logic, &mut refs);
    let mut issues = refs
        .into_iter()
        .filter_map(|(expression, source_id, port_id)| {
            let Some(source_node) = workflow_node_by_id(workflow, &source_id) else {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_expression_node".to_string(),
                    message: format!(
                        "Expression {} references a missing source node.",
                        expression
                    ),
                });
            };
            if !workflow_node_has_output_port(source_node, &port_id) {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_expression_port".to_string(),
                    message: format!(
                        "Expression {} references a missing output port.",
                        expression
                    ),
                });
            }
            let incoming_edge = workflow.edges.iter().find(|edge| {
                workflow_edge_from(edge).as_deref() == Some(source_id.as_str())
                    && workflow_edge_to(edge).as_deref() == Some(node_id.as_str())
                    && workflow_edge_from_port(edge) == port_id
            });
            let Some(edge) = incoming_edge else {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "unconnected_expression_ref".to_string(),
                    message: format!(
                        "Expression {} needs a matching incoming edge from '{}'.",
                        expression,
                        workflow_node_name(source_node)
                    ),
                });
            };
            let source_class = workflow_node_port_connection_class(source_node, &port_id, "output")
                .or_else(|| workflow_edge_connection_class(edge))
                .unwrap_or_else(|| "data".to_string());
            let target_class =
                workflow_node_port_connection_class(node, &workflow_edge_to_port(edge), "input")
                    .or_else(|| workflow_edge_connection_class(edge))
                    .unwrap_or_else(|| "data".to_string());
            validate_workflow_connection_class(Some(node_id.clone()), &source_class, &target_class)
                .err()
                .map(|issue| WorkflowValidationIssue {
                    node_id: issue.action_id,
                    code: "invalid_expression_connection".to_string(),
                    message: format!(
                        "{} cannot use the connected ports: {}",
                        expression, issue.message
                    ),
                })
        })
        .collect::<Vec<_>>();
    if let Some(field_mappings) = logic.get("fieldMappings").and_then(Value::as_object) {
        for (key, mapping) in field_mappings {
            let source = mapping.get("source").and_then(Value::as_str).unwrap_or("");
            let path = mapping.get("path").and_then(Value::as_str).unwrap_or("");
            if source.trim().is_empty() || path.trim().is_empty() {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "invalid_field_mapping_source".to_string(),
                    message: format!(
                        "Field mapping '{}' needs a node output source expression.",
                        key
                    ),
                });
                continue;
            }
            let mut source_refs = Vec::new();
            collect_workflow_expression_refs(&Value::String(source.to_string()), &mut source_refs);
            let Some((_, source_id, _)) = source_refs.first() else {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "invalid_field_mapping_source".to_string(),
                    message: format!(
                        "Field mapping '{}' needs a node output source expression.",
                        key
                    ),
                });
                continue;
            };
            let Some(source_node) = workflow_node_by_id(workflow, source_id) else {
                continue;
            };
            let schema = workflow_node_declared_output_schema(source_node);
            if !workflow_schema_has_field_path(&schema, path) {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_field_mapping_path".to_string(),
                    message: format!(
                        "Field mapping '{}' references '{}', which is not in '{}' output schema.",
                        key,
                        path,
                        workflow_node_name(source_node)
                    ),
                });
            }
        }
    }
    issues
}

pub(super) fn workflow_predecessor_output(
    node_id: &str,
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
) -> Value {
    if let Some(mapped) = workflow_mapped_node_input(node_id, workflow, state) {
        return mapped;
    }
    let mut inputs = serde_json::Map::new();
    for edge in &workflow.edges {
        if workflow_edge_to(edge).as_deref() != Some(node_id) {
            continue;
        }
        if let Some(source_id) = workflow_edge_from(edge) {
            if let Some(output) = state.node_outputs.get(&source_id) {
                inputs.insert(source_id, output.clone());
            }
        }
    }
    if inputs.len() == 1 {
        inputs
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or(Value::Null)
    } else {
        Value::Object(inputs)
    }
}

pub(super) fn workflow_first_expression_source(expression: &str) -> Option<(String, String)> {
    let mut refs = Vec::new();
    collect_workflow_expression_refs(&Value::String(expression.to_string()), &mut refs);
    refs.into_iter()
        .next()
        .map(|(_, node_id, port_id)| (node_id, port_id))
}

pub(super) fn workflow_mapped_node_input(
    node_id: &str,
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
) -> Option<Value> {
    let node = workflow_node_by_id(workflow, node_id)?;
    let logic = workflow_node_logic(node);
    let input_mapping = logic.get("inputMapping").and_then(Value::as_object);
    let field_mappings = logic.get("fieldMappings").and_then(Value::as_object);
    if input_mapping.is_none() && field_mappings.is_none() {
        return None;
    }
    let mut mapped = serde_json::Map::new();
    if let Some(fields) = field_mappings {
        for (key, mapping) in fields {
            let Some(source_expression) = mapping.get("source").and_then(Value::as_str) else {
                continue;
            };
            let Some(path) = mapping.get("path").and_then(Value::as_str) else {
                continue;
            };
            let Some((source_id, _port_id)) = workflow_first_expression_source(source_expression)
            else {
                continue;
            };
            if let Some(source_output) = state.node_outputs.get(&source_id) {
                if let Some(value) = workflow_value_at_path(source_output, path) {
                    mapped.insert(key.clone(), value);
                }
            }
        }
    }
    if let Some(inputs) = input_mapping {
        for (key, expression) in inputs {
            if mapped.contains_key(key) {
                continue;
            }
            let Some(expression_text) = expression.as_str() else {
                continue;
            };
            let Some((source_id, _port_id)) = workflow_first_expression_source(expression_text)
            else {
                continue;
            };
            if let Some(source_output) = state.node_outputs.get(&source_id) {
                mapped.insert(key.clone(), source_output.clone());
            }
        }
    }
    (!mapped.is_empty()).then_some(Value::Object(mapped))
}

pub(super) fn workflow_selected_output(node: &Value, output: &Value) -> String {
    if workflow_node_type(node) != "decision" {
        return "output".to_string();
    }
    output
        .get("branch")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "left".to_string())
}
