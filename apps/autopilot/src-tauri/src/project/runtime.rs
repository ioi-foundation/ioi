// apps/autopilot/src-tauri/src/project/runtime.rs

use super::*;

pub(super) fn workflow_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

pub(super) fn workflow_side_effect_requires_live_runtime(side_effect_class: &str) -> bool {
    !matches!(side_effect_class, "none" | "read")
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

pub(super) fn workflow_action_frame(node: &Value) -> ActionFrame {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    let kind = ActionKind::from_node_type(&workflow_node_type(node));
    let binding = match kind {
        ActionKind::ModelCall => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: false,
        }),
        ActionKind::ModelBinding => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("modelRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("modelRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("sideEffectClass"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            requires_approval: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::Parser => Some(ActionBindingRef {
            binding_type: "parser".to_string(),
            reference: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("parserRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("parserRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: "none".to_string(),
            requires_approval: false,
        }),
        ActionKind::Function => Some(ActionBindingRef {
            binding_type: "function".to_string(),
            reference: logic
                .get("functionBinding")
                .and_then(|binding| binding.get("language"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("language").and_then(Value::as_str))
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::AdapterConnector => {
            logic
                .get("connectorBinding")
                .map(|binding| ActionBindingRef {
                    binding_type: "connector".to_string(),
                    reference: binding
                        .get("connectorRef")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .map(str::to_string),
                    mock_binding: binding
                        .get("mockBinding")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    side_effect_class: binding
                        .get("sideEffectClass")
                        .and_then(Value::as_str)
                        .unwrap_or("read")
                        .to_string(),
                    requires_approval: binding
                        .get("requiresApproval")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
        }
        ActionKind::PluginTool => logic.get("toolBinding").map(|binding| ActionBindingRef {
            binding_type: "tool".to_string(),
            reference: binding
                .get("toolRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: binding
                .get("mockBinding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            side_effect_class: binding
                .get("sideEffectClass")
                .and_then(Value::as_str)
                .unwrap_or("read")
                .to_string(),
            requires_approval: binding
                .get("requiresApproval")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        _ => None,
    };
    let privileged_actions = law
        .get("privilegedActions")
        .or_else(|| logic.get("privilegedActions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let sandbox_permissions = law
        .get("sandboxPolicy")
        .and_then(|policy| policy.get("permissions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ActionFrame {
        id: node_id,
        surface: ActionSurface::Workflow,
        kind,
        label: workflow_node_name(node),
        binding,
        policy: ActionPolicy {
            privileged_actions,
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            sandbox_permissions,
        },
        metadata: std::collections::BTreeMap::new(),
    }
}

pub(super) fn workflow_output_bundle_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind", "nodeId", "outputBundle"],
        "properties": {
            "kind": { "type": "string" },
            "nodeId": { "type": "string" },
            "outputName": { "type": "string" },
            "outputBundle": {
                "type": "object",
                "required": ["id", "nodeId", "format", "value", "createdAtMs"],
                "properties": {
                    "id": { "type": "string" },
                    "nodeId": { "type": "string" },
                    "format": { "type": "string" },
                    "value": { "type": "unknown" },
                    "rendererRef": { "type": "object" },
                    "materializedAssets": { "type": "array" },
                    "deliveryTarget": { "type": "object" },
                    "dependencyRefs": { "type": "array" },
                    "evidenceRefs": { "type": "array" },
                    "version": { "type": "object" },
                    "createdAtMs": { "type": "number" }
                }
            }
        }
    })
}

pub(super) fn workflow_node_schema(node: &Value, logic_key: &str) -> Option<Value> {
    workflow_node_logic(node)
        .get(logic_key)
        .cloned()
        .or_else(|| node.get("schema").cloned())
        .or_else(|| {
            (logic_key == "outputSchema" && workflow_node_type(node) == "output")
                .then(workflow_output_bundle_schema)
        })
}

pub(super) fn workflow_function_binding(node: &Value) -> Result<WorkflowFunctionBinding, String> {
    let logic = workflow_node_logic(node);
    if let Some(binding) = logic.get("functionBinding") {
        return serde_json::from_value(binding.clone())
            .map_err(|error| format!("Function binding is invalid: {}", error));
    }
    let code = logic
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| "Function code is missing.".to_string())?;
    Ok(WorkflowFunctionBinding {
        language: logic
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("javascript")
            .to_string(),
        code: code.to_string(),
        function_ref: None,
        input_schema: workflow_node_schema(node, "inputSchema"),
        output_schema: workflow_node_schema(node, "outputSchema"),
        sandbox_policy: workflow_node_law(node)
            .get("sandboxPolicy")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        test_input: logic.get("testInput").cloned(),
    })
}

pub(super) fn workflow_tool_binding(node: &Value) -> Result<WorkflowToolBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("toolBinding") else {
        return Err("Plugin tool binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Tool binding is invalid: {}", error))
}

pub(super) fn workflow_parser_binding(node: &Value) -> Result<WorkflowParserBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("parserBinding") else {
        return Err("Output Parser binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Output Parser binding is invalid: {}", error))
}

pub(super) fn workflow_model_binding(node: &Value) -> Result<WorkflowModelBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("modelBinding") else {
        return Err("Model Binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Model Binding is invalid: {}", error))
}

pub(super) fn workflow_connector_binding(node: &Value) -> Result<WorkflowConnectorBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("connectorBinding") else {
        return Err("Connector binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Connector binding is invalid: {}", error))
}

pub(super) fn workflow_sandbox_policy(
    binding: &WorkflowFunctionBinding,
    node: &Value,
) -> WorkflowSandboxPolicy {
    binding
        .sandbox_policy
        .clone()
        .or_else(|| {
            workflow_node_law(node)
                .get("sandboxPolicy")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
        })
        .unwrap_or(WorkflowSandboxPolicy {
            timeout_ms: Some(1000),
            memory_mb: Some(64),
            output_limit_bytes: Some(32768),
            permissions: Vec::new(),
        })
}

pub(super) fn workflow_policy_allows(policy: &WorkflowSandboxPolicy, permission: &str) -> bool {
    policy.permissions.iter().any(|item| item == permission)
}

pub(super) fn workflow_function_sandbox_precheck(
    code: &str,
    policy: &WorkflowSandboxPolicy,
) -> Result<(), String> {
    let filesystem_tokens = ["require(", "import ", "fs.", "node:fs"];
    let network_tokens = [
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "require('http",
        "require(\"http",
        "node:http",
        "node:https",
    ];
    let process_tokens = ["process.", "child_process", "spawn(", "exec("];
    if !workflow_policy_allows(policy, "filesystem")
        && filesystem_tokens.iter().any(|token| code.contains(token))
    {
        return Err(
            "Function uses filesystem/module access without sandbox permission.".to_string(),
        );
    }
    if !workflow_policy_allows(policy, "network")
        && network_tokens.iter().any(|token| code.contains(token))
    {
        return Err("Function uses network access without sandbox permission.".to_string());
    }
    if !workflow_policy_allows(policy, "process")
        && process_tokens.iter().any(|token| code.contains(token))
    {
        return Err("Function uses process access without sandbox permission.".to_string());
    }
    Ok(())
}

pub(super) fn workflow_function_dependency_names(binding: &WorkflowFunctionBinding) -> Vec<String> {
    let Some(manifest) = binding
        .function_ref
        .as_ref()
        .and_then(|function_ref| function_ref.dependency_manifest.as_ref())
    else {
        return Vec::new();
    };
    let Some(dependencies) = manifest.get("dependencies") else {
        return Vec::new();
    };
    if let Some(object) = dependencies.as_object() {
        return object
            .keys()
            .filter(|key| !key.trim().is_empty())
            .cloned()
            .collect();
    }
    dependencies
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn workflow_function_dependency_precheck(
    binding: &WorkflowFunctionBinding,
) -> Result<(), String> {
    let dependency_names = workflow_function_dependency_names(binding);
    if dependency_names.is_empty() {
        return Ok(());
    }
    Err(format!(
        "Function dependency manifest declares unsupported external dependencies: {}.",
        dependency_names.join(", ")
    ))
}

fn workflow_function_input_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.input_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.input_schema.as_ref())
    })
}

fn workflow_function_output_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.output_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.output_schema.as_ref())
    })
}

pub(super) fn workflow_edge_from(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "from")
}

pub(super) fn workflow_edge_to(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "to")
}

pub(super) fn workflow_edge_from_port(edge: &Value) -> String {
    workflow_value_string(edge, "fromPort").unwrap_or_else(|| "output".to_string())
}

pub(super) fn workflow_edge_to_port(edge: &Value) -> String {
    workflow_value_string(edge, "toPort").unwrap_or_else(|| "input".to_string())
}

pub(super) fn workflow_edge_connection_class(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "connectionClass").or_else(|| {
        edge.get("data")
            .and_then(|data| workflow_value_string(data, "connectionClass"))
    })
}

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

pub(super) fn workflow_node_port_connection_class(
    node: &Value,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    if let Some(class) = node
        .get("ports")
        .and_then(Value::as_array)
        .and_then(|ports| {
            ports.iter().find(|port| {
                port.get("id").and_then(Value::as_str) == Some(port_id)
                    && port.get("direction").and_then(Value::as_str) == Some(direction)
            })
        })
        .and_then(|port| port.get("connectionClass").and_then(Value::as_str))
        .map(str::to_string)
    {
        return Some(class);
    }
    workflow_default_port_connection_class(&workflow_node_type(node), port_id, direction)
}

pub(super) fn workflow_default_port_connection_class(
    node_type: &str,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    let class = match (node_type, direction, port_id) {
        (_, "output", "error") | (_, "input", "error") => "error",
        (_, "output", "retry") | (_, "input", "retry") => "retry",
        (_, "output", "approval") | (_, "input", "approval") => "approval",
        ("model_call", "input", "model") | ("model_binding", "output", "model") => "model",
        ("model_call", "input", "memory") | ("state", "output", "memory") => "memory",
        ("model_call", "input", "tool")
        | ("plugin_tool", "output", "tool")
        | ("subgraph", "output", "tool") => "tool",
        ("model_call", "input", "parser") | ("parser", "output", "parser") => "parser",
        ("subgraph", "input", "subgraph") | ("subgraph", "output", "subgraph") => "subgraph",
        ("output", "input", "delivery") => "delivery",
        (_, _, "input")
        | (_, _, "context")
        | (_, _, "output")
        | (_, _, "left")
        | (_, _, "right") => "data",
        _ => return None,
    };
    Some(class.to_string())
}

pub(super) fn validate_workflow_edge_ports(
    edge: &Value,
    from_node: &Value,
    to_node: &Value,
) -> Result<(), WorkflowValidationIssue> {
    let edge_id = edge.get("id").and_then(Value::as_str).unwrap_or("unknown");
    let from_port = workflow_edge_from_port(edge);
    let to_port = workflow_edge_to_port(edge);
    let source_class = workflow_node_port_connection_class(from_node, &from_port, "output")
        .or_else(|| workflow_edge_connection_class(edge))
        .unwrap_or_else(|| "data".to_string());
    let target_class = workflow_node_port_connection_class(to_node, &to_port, "input")
        .unwrap_or_else(|| {
            workflow_edge_connection_class(edge).unwrap_or_else(|| "data".to_string())
        });
    validate_workflow_connection_class(Some(edge_id.to_string()), &source_class, &target_class)
        .map_err(|issue| WorkflowValidationIssue {
            node_id: issue.action_id,
            code: issue.code,
            message: issue.message,
        })
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

pub(super) fn workflow_value_at_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.trim().is_empty()) {
        if segment == "[]" {
            current = current.as_array()?.first()?;
            continue;
        }
        current = current.get(segment)?;
    }
    Some(current.clone())
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

pub(super) fn workflow_max_attempts(node: &Value) -> usize {
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    logic
        .get("retry")
        .and_then(|retry| retry.get("maxAttempts"))
        .or_else(|| {
            law.get("retryPolicy")
                .and_then(|retry| retry.get("maxAttempts"))
        })
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 5) as usize)
        .unwrap_or(1)
}

pub(super) fn execute_workflow_tool_binding(
    parent_workflow_path: &Path,
    node_id: &str,
    binding: &WorkflowToolBinding,
    input: Value,
) -> Result<Value, String> {
    let Some(tool) = binding.workflow_tool.as_ref() else {
        return Err("Workflow tool binding is missing a child workflow reference.".to_string());
    };
    let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
    if let Some(schema) = tool.argument_schema.as_ref() {
        workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
            format!(
                "Workflow tool arguments failed schema validation: {}",
                error
            )
        })?;
    }
    let child_path = resolve_workflow_reference_path(parent_workflow_path, &tool.workflow_path)?;
    if child_path == parent_workflow_path {
        return Err("Workflow tools cannot invoke their own workflow.".to_string());
    }
    let child_bundle = load_workflow_bundle_from_path(&child_path)?;
    let child_input = json!({
        "arguments": arguments,
        "input": input
    });
    let max_attempts = tool.max_attempts.unwrap_or(1).clamp(1, 5);
    let mut last_error = None;
    let mut last_child_summary: Option<WorkflowRunSummary> = None;
    for attempt in 1..=max_attempts {
        let child_thread = new_workflow_thread(&child_path, Some(child_input.clone()));
        let child_state = initial_workflow_state(&child_thread, "workflow-tool-start");
        let child_result = execute_workflow_project(
            &child_path,
            child_bundle.clone(),
            child_thread,
            child_state,
            None,
        )?;
        last_child_summary = Some(child_result.summary.clone());
        if child_result.summary.status != "passed" {
            last_error = Some(format!(
                "Workflow tool child run '{}' finished with status {}.",
                child_result.summary.id, child_result.summary.status
            ));
            continue;
        }
        let result = child_result.final_state.values.clone();
        if let Some(schema) = tool.result_schema.as_ref() {
            workflow_json_satisfies_schema(schema, &json!(result)).map_err(|error| {
                format!("Workflow tool result failed schema validation: {}", error)
            })?;
        }
        return Ok(json!({
            "nodeId": node_id,
            "kind": "tool",
            "toolKind": "workflow_tool",
            "toolName": binding.tool_ref,
            "attempt": attempt,
            "maxAttempts": max_attempts,
            "timeoutMs": tool.timeout_ms.unwrap_or(30_000),
            "argumentSchema": tool.argument_schema,
            "resultSchema": tool.result_schema,
            "childWorkflowPath": child_path.display().to_string(),
            "childRunId": child_result.summary.id,
            "childRunStatus": child_result.summary.status,
            "childThreadId": child_result.thread.id,
            "result": result,
            "outputNodeIds": child_result.final_state
                .node_outputs
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        }));
    }
    Err(last_error.unwrap_or_else(|| {
        format!(
            "Workflow tool child workflow failed after {} attempt(s){}.",
            max_attempts,
            last_child_summary
                .map(|summary| format!("; last run was {}", summary.status))
                .unwrap_or_default()
        )
    }))
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

pub(super) fn workflow_model_ref_from_input(input: &Value) -> Option<String> {
    input
        .get("modelRef")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            input.as_object().and_then(|object| {
                object.values().find_map(|value| {
                    value
                        .get("modelRef")
                        .and_then(Value::as_str)
                        .filter(|model_ref| !model_ref.trim().is_empty())
                        .map(str::to_string)
                })
            })
        })
}

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

fn workflow_inputs_by_kind(input: &Value, kind: &str) -> Vec<Value> {
    let mut collected = Vec::new();
    workflow_collect_inputs_by_kind(input, kind, &mut collected);
    collected
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
        .filter_map(workflow_node_id)
        .filter(|node_id| {
            workflow_node_ready(node_id, workflow, completed, active_queue, branch_decisions)
        })
        .collect()
}

pub(super) fn workflow_push_event(
    events: &mut Vec<WorkflowStreamEvent>,
    run_id: &str,
    thread_id: &str,
    kind: &str,
    node_id: Option<&str>,
    status: Option<&str>,
    message: Option<String>,
    state_delta: Option<Vec<WorkflowStateUpdate>>,
) {
    let sequence = events.len();
    events.push(WorkflowStreamEvent {
        id: unique_runtime_id("event"),
        run_id: run_id.to_string(),
        thread_id: thread_id.to_string(),
        sequence,
        kind: kind.to_string(),
        created_at_ms: now_ms(),
        node_id: node_id.map(str::to_string),
        status: status.map(str::to_string),
        message,
        state_delta,
    });
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

pub(super) fn workflow_output_satisfies_schema(node: &Value, output: &Value) -> Result<(), String> {
    let Some(schema) = workflow_node_schema(node, "outputSchema") else {
        return Ok(());
    };
    workflow_output_satisfies_test_schema(&schema, output)
}

pub(super) fn workflow_truncate_output(value: &[u8], limit: usize) -> String {
    let capped = if value.len() > limit {
        &value[..limit]
    } else {
        value
    };
    String::from_utf8_lossy(capped).to_string()
}

pub(super) fn execute_workflow_function_node(node: &Value, input: Value) -> Result<Value, String> {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let binding = workflow_function_binding(node)?;
    workflow_function_dependency_precheck(&binding)?;
    if let Some(schema) = workflow_function_input_schema(&binding) {
        workflow_json_satisfies_schema(schema, &input)
            .map_err(|error| format!("Function input failed schema validation: {}", error))?;
    }
    let mut code_hash = None;
    let function_source = if let Some(function_ref) = binding.function_ref.as_ref() {
        let source_path = PathBuf::from(&function_ref.source_path);
        if source_path.exists() {
            code_hash = workflow_file_sha256(&source_path).ok();
            fs::read_to_string(&source_path).map_err(|error| {
                format!(
                    "Failed to read workflow function source '{}': {}",
                    source_path.display(),
                    error
                )
            })?
        } else {
            binding.code.clone()
        }
    } else {
        binding.code.clone()
    };
    let language = binding.language.trim().to_lowercase();
    if language != "javascript" && language != "typescript" {
        return Err(format!(
            "Function language '{}' is not supported in the local sandbox.",
            binding.language
        ));
    }
    let policy = workflow_sandbox_policy(&binding, node);
    workflow_function_sandbox_precheck(&function_source, &policy)?;
    let timeout_ms = policy.timeout_ms.unwrap_or(1000).clamp(50, 30_000);
    let memory_mb = policy.memory_mb.unwrap_or(64).clamp(16, 256);
    let output_limit = policy
        .output_limit_bytes
        .unwrap_or(32768)
        .clamp(1024, 262_144);
    let script_path =
        std::env::temp_dir().join(format!("{}-function.js", unique_runtime_id("workflow")));
    let script = format!(
        r#"
const vm = require("vm");
const source = {code};
const input = {input};
const stdoutLogs = [];
const stderrLogs = [];
const sandbox = {{
  input,
  context: {{ input }},
  console: {{
    log: (...args) => stdoutLogs.push(args.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join(" ")),
    error: (...args) => stderrLogs.push(args.map(String).join(" "))
  }},
  JSON,
  Math,
  Date,
}};
const wrapped = `(function(){{ "use strict"; const require = undefined; const process = undefined; const fetch = undefined; const Buffer = undefined; ${{source}}\n}})()`;
try {{
  const result = vm.runInNewContext(wrapped, sandbox, {{ timeout: {timeout_ms} }});
  process.stdout.write(JSON.stringify({{ ok: true, result, stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
}} catch (error) {{
  process.stdout.write(JSON.stringify({{ ok: false, error: String(error && error.message ? error.message : error), stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
  process.exitCode = 1;
}}
"#,
        code = serde_json::to_string(&function_source).map_err(|error| error.to_string())?,
        input = serde_json::to_string(&input).map_err(|error| error.to_string())?,
        timeout_ms = timeout_ms,
    );
    fs::write(&script_path, script)
        .map_err(|error| format!("Failed to prepare function sandbox: {}", error))?;
    let mut child = Command::new("node")
        .arg(format!("--max-old-space-size={}", memory_mb))
        .arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed to start JavaScript sandbox: {}", error))?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms + 250);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("Failed to poll JavaScript sandbox: {}", error))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = fs::remove_file(&script_path);
            return Err(format!("Function timed out after {}ms.", timeout_ms));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Failed to collect JavaScript sandbox output: {}", error))?;
    let _ = fs::remove_file(&script_path);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let process_stderr = workflow_truncate_output(&output.stderr, output_limit);
    let payload: Value = serde_json::from_str(&stdout).map_err(|error| {
        format!(
            "Function sandbox returned invalid JSON: {} | stderr={}",
            error, process_stderr
        )
    })?;
    if !payload.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Function execution failed.")
            .to_string());
    }
    let result = payload.get("result").cloned().unwrap_or(Value::Null);
    let function_stdout = payload
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let function_stderr = payload
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let output_bytes = serde_json::to_vec(&result)
        .map_err(|error| format!("Failed to measure function output: {}", error))?
        .len()
        + function_stdout.as_bytes().len()
        + function_stderr.as_bytes().len();
    if output_bytes > output_limit {
        return Err(format!(
            "Function output exceeded sandbox output limit of {} bytes.",
            output_limit
        ));
    }
    if let Some(schema) = workflow_function_output_schema(&binding) {
        let wrapper = json!({ "schema": schema });
        workflow_output_satisfies_schema(&wrapper, &result)?;
    }
    Ok(json!({
        "nodeId": node_id,
        "kind": "function",
        "language": binding.language,
        "result": result,
        "stdout": function_stdout,
        "stderr": if function_stderr.is_empty() { process_stderr } else { function_stderr },
        "codeHash": code_hash.or_else(|| binding.function_ref.as_ref().and_then(|function_ref| function_ref.code_hash.clone())),
        "dependencyManifest": binding.function_ref.as_ref().and_then(|function_ref| function_ref.dependency_manifest.clone()),
        "sandbox": {
            "timeoutMs": timeout_ms,
            "memoryMb": memory_mb,
            "outputLimitBytes": output_limit,
            "permissions": policy.permissions
        }
    }))
}

pub(super) fn workflow_output_bundle(
    node_id: &str,
    node_name: &str,
    logic: &Value,
    input: Value,
) -> Value {
    let format = logic
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("markdown")
        .to_string();
    let renderer_ref = logic
        .get("rendererRef")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowRendererRef>(value).ok());
    let delivery_target = logic
        .get("deliveryTarget")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowDeliveryTarget>(value).ok());
    let version = logic
        .get("versioning")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowOutputVersioning>(value).ok());
    let materialized_assets = logic
        .get("materialization")
        .and_then(Value::as_object)
        .filter(|materialization| {
            materialization
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|materialization| {
            vec![WorkflowMaterializedAsset {
                id: unique_runtime_id("asset"),
                node_id: node_id.to_string(),
                asset_kind: materialization
                    .get("assetKind")
                    .and_then(Value::as_str)
                    .unwrap_or("file")
                    .to_string(),
                path: materialization
                    .get("assetPath")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string),
                hash: None,
                created_at_ms: now_ms(),
            }]
        })
        .unwrap_or_default();
    let bundle = WorkflowOutputBundle {
        id: unique_runtime_id("output"),
        node_id: node_id.to_string(),
        format,
        value: input,
        renderer_ref,
        materialized_assets,
        delivery_target,
        dependency_refs: Vec::new(),
        evidence_refs: Vec::new(),
        version,
        created_at_ms: now_ms(),
    };
    json!({
        "nodeId": node_id,
        "kind": "output",
        "outputName": node_name,
        "outputBundle": bundle
    })
}

pub(super) fn workflow_runtime_approval_binding(
    node: &Value,
    action_kind: &ActionKind,
) -> Option<Value> {
    let logic = workflow_node_logic(node);
    match action_kind {
        ActionKind::AdapterConnector => {
            let binding = workflow_connector_binding(node).ok()?;
            binding.requires_approval.then(|| {
                json!({
                    "bindingKind": "connector",
                    "ref": binding.connector_ref,
                    "operation": binding.operation,
                    "mockBinding": binding.mock_binding,
                    "sideEffectClass": binding.side_effect_class,
                    "capabilityScope": binding.capability_scope
                })
            })
        }
        ActionKind::PluginTool => {
            let binding = workflow_tool_binding(node).ok()?;
            binding.requires_approval.then(|| {
                json!({
                    "bindingKind": binding.binding_kind.unwrap_or_else(|| "plugin_tool".to_string()),
                    "ref": binding.tool_ref,
                    "arguments": binding.arguments,
                    "mockBinding": binding.mock_binding,
                    "sideEffectClass": binding.side_effect_class,
                    "capabilityScope": binding.capability_scope,
                    "workflowTool": binding.workflow_tool
                })
            })
        }
        ActionKind::Output => {
            let delivery_requires_approval = logic
                .get("deliveryTarget")
                .and_then(|target| target.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            delivery_requires_approval.then(|| {
                json!({
                    "bindingKind": "delivery",
                    "target": logic.get("deliveryTarget").cloned().unwrap_or(Value::Null),
                    "materialization": logic.get("materialization").cloned().unwrap_or(Value::Null),
                    "sideEffectClass": logic.get("sideEffectClass").cloned().unwrap_or_else(|| json!("write"))
                })
            })
        }
        _ => None,
    }
}

pub(super) fn workflow_runtime_approval_preview(
    node: &Value,
    action_kind: &ActionKind,
    input: &Value,
) -> Option<Value> {
    let binding = workflow_runtime_approval_binding(node, action_kind)?;
    Some(json!({
        "nodeId": workflow_node_id(node),
        "nodeName": workflow_node_name(node),
        "nodeType": workflow_node_type(node),
        "binding": binding,
        "input": input,
        "reason": "This node is configured to pause before its side effect runs."
    }))
}

pub(super) fn workflow_runtime_interrupt_prompt(node: &Value, action_kind: &ActionKind) -> String {
    if action_kind.is_interrupt() {
        return workflow_node_logic(node)
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("Review and choose how this run should continue.")
            .to_string();
    }
    format!(
        "Approve '{}' before this node runs.",
        workflow_node_name(node)
    )
}

pub(super) fn execute_workflow_node(
    workflow_path: &Path,
    node: &Value,
    input: Value,
    attempt: usize,
    resume_outcome: Option<&Value>,
) -> Result<Value, String> {
    let frame = workflow_action_frame(node);
    let node_id = frame.id.clone();
    let node_name = frame.label.clone();
    let node_type = frame.kind.node_type().to_string();
    let action_kind = frame.kind.clone();
    let logic = workflow_node_logic(node);

    if logic
        .get("failUntilAttempt")
        .and_then(Value::as_u64)
        .map(|limit| attempt as u64 <= limit)
        .unwrap_or(false)
    {
        return Err(format!(
            "Node '{}' failed on attempt {}.",
            node_name, attempt
        ));
    }
    if logic.get("fail").and_then(Value::as_bool).unwrap_or(false) {
        return Err(format!(
            "Node '{}' requested a deterministic failure.",
            node_name
        ));
    }

    let evidence_kind = action_kind.evidence_kind();
    let output = match action_kind {
        ActionKind::SourceInput => {
            let payload = logic
                .get("payload")
                .or_else(|| logic.get("variables"))
                .cloned()
                .unwrap_or_else(|| json!({"source": node_name}));
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "payload": payload
            })
        }
        ActionKind::Trigger => {
            let trigger_kind = logic
                .get("triggerKind")
                .and_then(Value::as_str)
                .unwrap_or("manual");
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "triggerKind": trigger_kind,
                "schedule": logic.get("cronSchedule").cloned().unwrap_or(Value::Null),
                "eventSourceRef": logic.get("eventSourceRef").cloned().unwrap_or(Value::Null),
                "dedupeKey": logic.get("dedupeKey").cloned().unwrap_or(Value::Null),
                "payload": input
            })
        }
        ActionKind::TaskState => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "currentObjective": logic.get("objective").cloned().unwrap_or_else(|| input.clone()),
                "knownFacts": logic.get("knownFacts").cloned().unwrap_or_else(|| json!([])),
                "uncertainFacts": logic.get("uncertainFacts").cloned().unwrap_or_else(|| json!([])),
                "constraints": logic.get("constraints").cloned().unwrap_or_else(|| json!([])),
                "evidenceRefs": logic.get("evidenceRefs").cloned().unwrap_or_else(|| json!([])),
                "input": input
            })
        }
        ActionKind::UncertaintyGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "ambiguityLevel": logic.get("ambiguityLevel").and_then(Value::as_str).unwrap_or("medium"),
                "selectedAction": logic.get("selectedAction").and_then(Value::as_str).unwrap_or("probe"),
                "valueOfProbe": logic.get("valueOfProbe").and_then(Value::as_str).unwrap_or("medium"),
                "input": input
            })
        }
        ActionKind::Probe => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "hypothesis": logic.get("hypothesis").cloned().unwrap_or_else(|| json!("Probe workflow assumption")),
                "cheapestValidationAction": logic.get("cheapestValidationAction").cloned().unwrap_or_else(|| json!("Inspect current workflow evidence")),
                "result": logic.get("result").cloned().unwrap_or_else(|| json!("confirmed")),
                "input": input
            })
        }
        ActionKind::BudgetGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "budget": logic.get("budget").cloned().unwrap_or_else(|| json!({"maxToolCalls": 1, "maxRetries": 0})),
                "decision": logic.get("decision").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::CapabilitySequence => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sequence": logic.get("sequence").cloned().unwrap_or_else(|| json!(["discover", "select", "execute", "verify"])),
                "input": input
            })
        }
        ActionKind::DryRun => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sideEffectPreview": true,
                "mutationExecuted": false,
                "input": input
            })
        }
        ActionKind::Function => execute_workflow_function_node(node, input.clone())?,
        ActionKind::ModelBinding => {
            let binding = workflow_model_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": binding.model_ref,
                "capabilityScope": binding.capability_scope,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding,
                "credentialReady": binding.credential_ready.unwrap_or(false),
                "toolUseMode": binding.tool_use_mode.unwrap_or_else(|| "none".to_string())
            })
        }
        ActionKind::ModelCall => {
            let model_ref = logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .or_else(|| workflow_model_ref_from_input(&input))
                .ok_or_else(|| "Model binding is missing.".to_string())?;
            let parser_attachment = workflow_inputs_by_kind(&input, "parser").into_iter().next();
            let memory_attachment = workflow_inputs_by_kind(&input, "state").into_iter().next();
            let mut tool_attachments = workflow_inputs_by_kind(&input, "plugin_tool");
            tool_attachments.extend(workflow_inputs_by_kind(&input, "tool"));
            let tool_calls = tool_attachments
                .iter()
                .map(|tool| {
                    json!({
                        "toolName": tool
                            .get("toolName")
                            .or_else(|| tool.get("toolKind"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "mockBinding": tool.get("mockBinding").cloned().unwrap_or(Value::Null),
                        "sideEffectClass": tool.get("sideEffectClass").cloned().unwrap_or(Value::Null),
                        "result": tool
                            .get("result")
                            .or_else(|| tool.get("input"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    })
                })
                .collect::<Vec<_>>();
            let parsed_output_schema = parser_attachment
                .as_ref()
                .and_then(|parser| parser.get("resultSchema").cloned())
                .or_else(|| logic.get("outputSchema").cloned());
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": model_ref,
                "message": format!("{} completed with bound model {}.", node_name, model_ref),
                "input": input,
                "attachments": {
                    "parser": parser_attachment,
                    "memory": memory_attachment,
                    "tools": tool_attachments
                },
                "toolCalls": tool_calls,
                "structuredOutputSchema": parsed_output_schema,
                "streaming": {
                    "eventKinds": ["node_started", "state_updated", "node_succeeded"]
                }
            })
        }
        ActionKind::Parser => {
            let binding = workflow_parser_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "parserRef": binding.parser_ref,
                "parserKind": binding.parser_kind,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding.unwrap_or(true)
            })
        }
        ActionKind::AdapterConnector => {
            let binding = workflow_connector_binding(node)?;
            if !binding.mock_binding
                && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
            {
                return Err(
                    "Live connector writes require a configured approval-backed connector runtime."
                        .to_string(),
                );
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "connector": binding.connector_ref,
                "mockBinding": binding.mock_binding,
                "sideEffectClass": binding.side_effect_class,
                "operation": binding.operation,
                "input": input
            })
        }
        ActionKind::PluginTool => {
            let binding = workflow_tool_binding(node)?;
            if binding.binding_kind.as_deref() == Some("workflow_tool") {
                execute_workflow_tool_binding(workflow_path, &node_id, &binding, input.clone())?
            } else {
                if !binding.mock_binding
                    && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
                {
                    return Err(
                    "Live plugin side effects require a configured approval-backed tool runtime."
                        .to_string(),
                );
                }
                let tool_ref = binding.tool_ref.clone();
                let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
                if let Some(schema) = binding.argument_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
                        format!("Tool arguments failed schema validation: {}", error)
                    })?;
                }
                let result = json!({
                    "toolRef": tool_ref,
                    "arguments": arguments.clone(),
                    "input": input
                });
                if let Some(schema) = binding.result_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &result).map_err(|error| {
                        format!("Tool result failed schema validation: {}", error)
                    })?;
                }
                json!({
                    "nodeId": node_id,
                    "kind": evidence_kind,
                    "toolName": tool_ref,
                    "mockBinding": binding.mock_binding,
                    "sideEffectClass": binding.side_effect_class,
                    "arguments": arguments,
                    "argumentSchema": binding.argument_schema,
                    "resultSchema": binding.result_schema,
                    "result": result
                })
            }
        }
        ActionKind::Decision => {
            let branch = logic
                .get("defaultRoute")
                .and_then(Value::as_str)
                .or_else(|| {
                    logic
                        .get("routes")
                        .and_then(Value::as_array)
                        .and_then(|routes| routes.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or("left");
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": branch,
                "input": input
            })
        }
        ActionKind::State => {
            let key = logic
                .get("stateKey")
                .and_then(Value::as_str)
                .unwrap_or("memory");
            let operation = logic
                .get("stateOperation")
                .and_then(Value::as_str)
                .unwrap_or("merge");
            let reducer = logic
                .get("reducer")
                .and_then(Value::as_str)
                .unwrap_or(match operation {
                    "append" => "append",
                    "merge" => "merge",
                    _ => "replace",
                });
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "stateKey": key,
                "operation": operation,
                "reducer": reducer,
                "value": input
            })
        }
        ActionKind::Loop => {
            let max_iterations = logic
                .get("maxIterations")
                .and_then(Value::as_u64)
                .unwrap_or(3);
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": "output",
                "maxIterations": max_iterations,
                "input": input
            })
        }
        ActionKind::Barrier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "strategy": logic.get("barrierStrategy").and_then(Value::as_str).unwrap_or("all"),
                "inputs": input
            })
        }
        ActionKind::Subgraph => {
            let path = logic
                .get("subgraphRef")
                .and_then(|ref_value| ref_value.get("workflowPath"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "Subgraph workflow path is missing.".to_string())?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "childWorkflowPath": path,
                "childRunStatus": "blocked",
                "summary": "Subgraph invocation is bound but deferred to child workflow runtime.",
                "input": input
            })
        }
        ActionKind::HumanGate => {
            let Some(outcome) = resume_outcome else {
                return Err("Human gate requires an interrupt.".to_string());
            };
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "outcome": outcome,
                "input": input
            })
        }
        ActionKind::SemanticImpact => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "changedSymbols": logic.get("changedSymbols").cloned().unwrap_or_else(|| json!([])),
                "changedApis": logic.get("changedApis").cloned().unwrap_or_else(|| json!([])),
                "affectedTests": logic.get("affectedTests").cloned().unwrap_or_else(|| json!([])),
                "riskClass": logic.get("riskClass").and_then(Value::as_str).unwrap_or("bounded"),
                "input": input
            })
        }
        ActionKind::PostconditionSynthesis => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "checks": logic.get("checks").cloned().unwrap_or_else(|| json!([])),
                "minimumEvidence": logic.get("minimumEvidence").cloned().unwrap_or_else(|| json!(["trace", "receipt", "stop_condition"])),
                "input": input
            })
        }
        ActionKind::Verifier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "independent": logic.get("independent").and_then(Value::as_bool).unwrap_or(true),
                "verdict": logic.get("verdict").and_then(Value::as_str).unwrap_or("passed"),
                "input": input
            })
        }
        ActionKind::DriftDetector => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "signals": logic.get("signals").cloned().unwrap_or_else(|| json!([])),
                "driftDetected": logic.get("driftDetected").and_then(Value::as_bool).unwrap_or(false),
                "input": input
            })
        }
        ActionKind::QualityLedger => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "scorecard": logic.get("scorecard").cloned().unwrap_or_else(|| json!({})),
                "taskPassRate": logic.get("taskPassRate").and_then(Value::as_f64).unwrap_or(1.0),
                "input": input
            })
        }
        ActionKind::Handoff => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "objectivePreserved": true,
                "evidencePreserved": true,
                "nextAction": logic.get("nextAction").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::GuiHarnessValidation => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "markdownStatus": logic.get("markdownStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "mermaidStatus": logic.get("mermaidStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "sourceChipStatus": logic.get("sourceChipStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "input": input
            })
        }
        ActionKind::Output => workflow_output_bundle(&node_id, &node_name, &logic, input),
        ActionKind::TestAssertion => {
            let assertion = logic
                .get("assertion")
                .cloned()
                .and_then(|value| serde_json::from_value::<WorkflowTestAssertion>(value).ok())
                .unwrap_or_else(|| WorkflowTestAssertion {
                    kind: logic
                        .get("assertionKind")
                        .and_then(Value::as_str)
                        .unwrap_or("node_exists")
                        .to_string(),
                    expected: logic.get("expected").cloned(),
                    expression: logic
                        .get("expression")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            let (passed, message) = workflow_evaluate_value_assertion(&assertion, &input, None)?;
            if !passed {
                return Err(format!("Test assertion failed: {}", message));
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "assertionKind": assertion.kind,
                "passed": passed,
                "message": message,
                "input": input
            })
        }
        ActionKind::Proposal => {
            let proposal_action = logic.get("proposalAction").cloned().unwrap_or_else(|| {
                json!({
                    "actionKind": "create",
                    "boundedTargets": [],
                    "requiresApproval": true
                })
            });
            let bounded_count = proposal_action
                .get("boundedTargets")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if bounded_count == 0 {
                return Err("Proposal node requires bounded targets.".to_string());
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "proposal": proposal_action,
                "input": input
            })
        }
        ActionKind::Unknown => {
            return Err(format!("Unsupported workflow node type '{}'.", node_type))
        }
    };
    workflow_output_satisfies_schema(node, &output)?;
    Ok(output)
}

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

pub(super) fn workflow_verification_evidence_from_node_runs(
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowVerificationEvidence> {
    node_runs
        .iter()
        .map(|run| WorkflowVerificationEvidence {
            node_id: run.node_id.clone(),
            evidence_type: "execution".to_string(),
            status: if run.status == "success" {
                "passed".to_string()
            } else {
                run.status.clone()
            },
            summary: run
                .error
                .clone()
                .unwrap_or_else(|| format!("{} execution {}", run.node_type, run.status)),
            created_at_ms: run.finished_at_ms.unwrap_or(run.started_at_ms),
        })
        .collect()
}

pub(super) fn workflow_completion_requirements(
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowCompletionRequirement> {
    let mut requirements = Vec::new();
    let run_by_node = node_runs
        .iter()
        .filter(|run| run.status == "success")
        .map(|run| (run.node_id.as_str(), run))
        .collect::<std::collections::BTreeMap<_, _>>();
    for node in &workflow.nodes {
        let Some(node_id) = workflow_node_id(node) else {
            continue;
        };
        let action_kind = ActionKind::from_node_type(&workflow_node_type(node));
        if action_kind.is_entry() {
            continue;
        }
        let incoming = workflow
            .edges
            .iter()
            .filter(|edge| workflow_edge_to(edge).as_deref() == Some(node_id.as_str()))
            .collect::<Vec<_>>();
        let selected = incoming.is_empty()
            || incoming
                .iter()
                .any(|edge| workflow_edge_is_selected(edge, &state.branch_decisions));
        if !selected {
            continue;
        }
        let executed = run_by_node.contains_key(node_id.as_str())
            || state.completed_node_ids.iter().any(|id| id == &node_id);
        for requirement_kind in completion_requirement_kinds(&action_kind) {
            match requirement_kind {
                "execution" => requirements.push(WorkflowCompletionRequirement {
                    id: format!("execution-{}", node_id),
                    node_id: Some(node_id.clone()),
                    requirement_type: "execution".to_string(),
                    status: if executed { "satisfied" } else { "missing" }.to_string(),
                    summary: if executed {
                        "Node produced typed execution evidence.".to_string()
                    } else {
                        "Node is missing typed execution evidence.".to_string()
                    },
                }),
                "verification" => {
                    let verified = state.node_outputs.contains_key(&node_id);
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("verification-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "verification".to_string(),
                        status: if verified { "satisfied" } else { "missing" }.to_string(),
                        summary: if verified {
                            "Node output has verification material.".to_string()
                        } else {
                            "Node output is missing verification material.".to_string()
                        },
                    });
                }
                "output_created" => {
                    let output_created = state
                        .node_outputs
                        .get(&node_id)
                        .and_then(|output| output.get("outputBundle"))
                        .is_some();
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("output-created-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "output_created".to_string(),
                        status: if output_created {
                            "satisfied"
                        } else {
                            "missing"
                        }
                        .to_string(),
                        summary: if output_created {
                            "Output bundle was produced.".to_string()
                        } else {
                            "Output bundle is missing.".to_string()
                        },
                    });
                }
                _ => {}
            }
        }
    }
    requirements
}

pub(super) fn workflow_completion_has_missing(
    requirements: &[WorkflowCompletionRequirement],
) -> bool {
    requirements
        .iter()
        .any(|requirement| requirement.status != "satisfied")
}

pub(super) fn execute_workflow_project(
    workflow_path: &Path,
    bundle: WorkflowWorkbenchBundle,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    resume_gate: Option<(String, Value)>,
) -> Result<WorkflowRunResult, String> {
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    let validation = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let mut node_runs = Vec::new();
    let mut completed = state
        .completed_node_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut active_queue = if state.active_node_ids.is_empty() {
        workflow_next_ready_nodes(&bundle.workflow, &completed, &[], &state.branch_decisions)
    } else {
        state.active_node_ids.clone()
    };

    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_started",
        None,
        Some("running"),
        Some("Workflow run started.".to_string()),
        None,
    );

    if validation.status != "passed" {
        state.blocked_node_ids = validation.blocked_nodes.clone();
        let checkpoint_id = workflow_checkpoint_state(
            workflow_path,
            &mut state,
            &run_id,
            &thread_id,
            None,
            &validation.status,
            format!(
                "Workflow blocked by {} validation issue(s).",
                validation.blocked_nodes.len()
            ),
            &mut checkpoints,
        )?;
        let summary = WorkflowRunSummary {
            id: run_id.clone(),
            thread_id: Some(thread_id.clone()),
            status: validation.status.clone(),
            started_at_ms,
            finished_at_ms: Some(now_ms()),
            node_count: bundle.workflow.nodes.len(),
            test_count: Some(bundle.tests.len()),
            checkpoint_count: Some(checkpoints.len()),
            interrupt_id: None,
            summary: format!(
                "Workflow blocked by {} validation issue(s).",
                validation.errors.len() + validation.warnings.len()
            ),
            evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "run_completed",
            None,
            Some(&summary.status),
            Some(summary.summary.clone()),
            None,
        );
        let mut final_thread = thread.clone();
        final_thread.status = summary.status.clone();
        final_thread.latest_checkpoint_id = Some(checkpoint_id);
        let verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
        let completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
        let result = WorkflowRunResult {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            verification_evidence,
            completion_requirements,
            interrupt: None,
        };
        save_workflow_run_result(workflow_path, &result)?;
        return Ok(result);
    }

    let max_steps = bundle.workflow.nodes.len().saturating_mul(4).max(1);
    let mut steps = 0usize;
    while let Some(node_id) = active_queue.first().cloned() {
        active_queue.remove(0);
        if completed.contains(&node_id) {
            continue;
        }
        steps += 1;
        if steps > max_steps {
            state.blocked_node_ids.push(node_id.clone());
            break;
        }
        let Some(node) = workflow_node_by_id(&bundle.workflow, &node_id) else {
            state.blocked_node_ids.push(node_id.clone());
            continue;
        };
        let node_type = workflow_node_type(node);
        let action_kind = ActionKind::from_node_type(&node_type);
        let input = workflow_predecessor_output(&node_id, &bundle.workflow, &state);
        let resume_matches_node =
            resume_gate.as_ref().map(|(id, _)| id.as_str()) == Some(node_id.as_str());
        let runtime_approval_preview =
            workflow_runtime_approval_preview(node, &action_kind, &input);
        if (action_kind.is_interrupt() || runtime_approval_preview.is_some())
            && !resume_matches_node
        {
            let interrupt_id = unique_runtime_id("interrupt");
            let interrupt = WorkflowInterrupt {
                id: interrupt_id.clone(),
                run_id: run_id.clone(),
                thread_id: thread_id.clone(),
                node_id: node_id.clone(),
                status: "pending".to_string(),
                created_at_ms: now_ms(),
                resolved_at_ms: None,
                prompt: workflow_runtime_interrupt_prompt(node, &action_kind),
                allowed_outcomes: vec![
                    "approve".to_string(),
                    "reject".to_string(),
                    "edit".to_string(),
                ],
                response: runtime_approval_preview,
            };
            state.interrupted_node_ids.push(node_id.clone());
            state.active_node_ids = active_queue.clone();
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread_id,
                Some(&node_id),
                "interrupted",
                format!("Run paused at '{}'.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_interrupted",
                Some(&node_id),
                Some("interrupted"),
                Some(if action_kind.is_interrupt() {
                    "Human input required before continuing.".to_string()
                } else {
                    "Approval required before this node runs.".to_string()
                }),
                None,
            );
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "interrupted".to_string(),
                started_at_ms: now_ms(),
                finished_at_ms: Some(now_ms()),
                attempt: 1,
                input: Some(input.clone()),
                output: None,
                error: None,
                checkpoint_id: Some(checkpoint_id.clone()),
                lifecycle: workflow_node_lifecycle_steps("interrupted"),
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "run_completed",
                None,
                Some("interrupted"),
                Some("Run paused for human input.".to_string()),
                None,
            );
            fs::create_dir_all(workflow_interrupts_dir(workflow_path))
                .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
            write_json_pretty(&workflow_interrupt_path(workflow_path, &run_id), &interrupt)?;
            let summary = WorkflowRunSummary {
                id: run_id.clone(),
                thread_id: Some(thread_id.clone()),
                status: "interrupted".to_string(),
                started_at_ms,
                finished_at_ms: Some(now_ms()),
                node_count: bundle.workflow.nodes.len(),
                test_count: Some(bundle.tests.len()),
                checkpoint_count: Some(checkpoints.len()),
                interrupt_id: Some(interrupt_id.clone()),
                summary: format!("Run paused at '{}'.", workflow_node_name(node)),
                evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
            };
            let mut final_thread = thread.clone();
            final_thread.status = "interrupted".to_string();
            final_thread.latest_checkpoint_id = Some(checkpoint_id);
            save_workflow_thread(workflow_path, &final_thread)?;
            let verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
            let completion_requirements =
                workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
            let result = WorkflowRunResult {
                summary,
                thread: final_thread,
                final_state: state,
                node_runs,
                checkpoints,
                events,
                verification_evidence,
                completion_requirements,
                interrupt: Some(interrupt),
            };
            save_workflow_run_result(workflow_path, &result)?;
            return Ok(result);
        }

        let mut node_run = WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            status: "running".to_string(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
            attempt: 1,
            input: Some(input.clone()),
            output: None,
            error: None,
            checkpoint_id: None,
            lifecycle: Vec::new(),
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "node_started",
            Some(&node_id),
            Some("running"),
            Some(format!("{} started.", workflow_node_name(node))),
            None,
        );
        let max_attempts = workflow_max_attempts(node);
        let mut execution_result = Err("Node did not execute.".to_string());
        for attempt in 1..=max_attempts {
            node_run.attempt = attempt;
            let resume_value = resume_gate
                .as_ref()
                .and_then(|(resume_node_id, value)| (resume_node_id == &node_id).then_some(value));
            execution_result =
                execute_workflow_node(workflow_path, node, input.clone(), attempt, resume_value);
            if execution_result.is_ok() || attempt == max_attempts {
                break;
            }
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "error".to_string(),
                started_at_ms: node_run.started_at_ms,
                finished_at_ms: Some(now_ms()),
                attempt,
                input: Some(input.clone()),
                output: None,
                error: execution_result.as_ref().err().cloned(),
                checkpoint_id: None,
                lifecycle: workflow_node_lifecycle_steps("error"),
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_failed",
                Some(&node_id),
                Some("retrying"),
                Some(format!(
                    "Retrying '{}' after attempt {}.",
                    workflow_node_name(node),
                    attempt
                )),
                None,
            );
        }

        match execution_result {
            Ok(output) => {
                let selected_output = workflow_selected_output(node, &output);
                if action_kind == ActionKind::Decision {
                    state
                        .branch_decisions
                        .insert(node_id.clone(), selected_output.clone());
                }
                completed.insert(node_id.clone());
                state.completed_node_ids = completed.iter().cloned().collect();
                state.interrupted_node_ids.retain(|id| id != &node_id);
                state.node_outputs.insert(node_id.clone(), output.clone());
                let update = if action_kind == ActionKind::State {
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
                    &bundle.workflow,
                    &completed,
                    &active_queue,
                    &state.branch_decisions,
                ));
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "running",
                    format!("{} completed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "success".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.output = Some(output.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("success");
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
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
                        &mut events,
                        &run_id,
                        &thread_id,
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
                if action_kind == ActionKind::Output {
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
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
                            &mut events,
                            &run_id,
                            &thread_id,
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
            }
            Err(error) => {
                state.blocked_node_ids.push(node_id.clone());
                state.step_index += 1;
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "failed",
                    format!("{} failed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "error".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.error = Some(error.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("error");
                node_runs.push(node_run);
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_failed",
                    Some(&node_id),
                    Some("error"),
                    Some(error),
                    None,
                );
                break;
            }
        }
    }

    let mut status = if !state.blocked_node_ids.is_empty() {
        "failed"
    } else if !state.interrupted_node_ids.is_empty() {
        "interrupted"
    } else {
        "passed"
    };
    let mut completion_requirements =
        workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    if status == "passed" && workflow_completion_has_missing(&completion_requirements) {
        status = "failed";
        state
            .blocked_node_ids
            .extend(completion_requirements.iter().filter_map(|requirement| {
                (requirement.status != "satisfied")
                    .then(|| requirement.node_id.clone())
                    .flatten()
            }));
        state.blocked_node_ids.sort();
        state.blocked_node_ids.dedup();
        completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    }
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        None,
        status,
        format!("Workflow run {}.", status),
        &mut checkpoints,
    )?;
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id.clone()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: bundle.workflow.nodes.len(),
        test_count: Some(bundle.tests.len()),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if status == "passed" {
            "Workflow completed with durable checkpoints.".to_string()
        } else {
            format!("Workflow {} with structured blockers.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some(status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status.to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
    let result = WorkflowRunResult {
        summary,
        thread: final_thread,
        final_state: state,
        node_runs,
        checkpoints,
        events,
        verification_evidence,
        completion_requirements,
        interrupt: None,
    };
    save_workflow_run_result(workflow_path, &result)?;
    Ok(result)
}

pub(super) fn new_workflow_thread(workflow_path: &Path, input: Option<Value>) -> WorkflowThread {
    let created_at_ms = now_ms();
    WorkflowThread {
        id: unique_runtime_id("workflow-thread"),
        workflow_path: workflow_path.display().to_string(),
        status: "queued".to_string(),
        created_at_ms,
        latest_checkpoint_id: None,
        input,
    }
}

pub(super) fn initial_workflow_state(
    thread: &WorkflowThread,
    run_id: &str,
) -> WorkflowStateSnapshot {
    let mut values = std::collections::BTreeMap::new();
    if let Some(input) = thread.input.clone() {
        values.insert("input".to_string(), input);
    }
    WorkflowStateSnapshot {
        thread_id: thread.id.clone(),
        checkpoint_id: "start".to_string(),
        run_id: run_id.to_string(),
        step_index: 0,
        values,
        node_outputs: std::collections::BTreeMap::new(),
        completed_node_ids: Vec::new(),
        blocked_node_ids: Vec::new(),
        interrupted_node_ids: Vec::new(),
        active_node_ids: Vec::new(),
        branch_decisions: std::collections::BTreeMap::new(),
        pending_writes: Vec::new(),
    }
}

pub(super) fn workflow_single_node_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node_id: &str,
    input: Option<Value>,
    dry_run: bool,
) -> Result<WorkflowRunResult, String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    let node = workflow_node_by_id(workflow, node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id(if dry_run {
        "workflow-dry-run"
    } else {
        "workflow-node-run"
    });
    let thread = new_workflow_thread(workflow_path, input.clone());
    save_workflow_thread(workflow_path, &thread)?;
    let mut state = initial_workflow_state(&thread, &run_id);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let execution_input = input.unwrap_or_else(|| json!({"dryRun": dry_run}));
    let mut node_run = WorkflowNodeRun {
        node_id: node_id.to_string(),
        node_type: workflow_node_type(node),
        status: "running".to_string(),
        started_at_ms,
        finished_at_ms: None,
        attempt: 1,
        input: Some(execution_input.clone()),
        output: None,
        error: None,
        checkpoint_id: None,
        lifecycle: Vec::new(),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "node_started",
        Some(node_id),
        Some("running"),
        Some(format!("{} started.", workflow_node_name(node))),
        None,
    );
    let execution = execute_workflow_node(workflow_path, node, execution_input, 1, None);
    let status = match execution {
        Ok(output) => {
            state
                .node_outputs
                .insert(node_id.to_string(), output.clone());
            state.values.insert(node_id.to_string(), output.clone());
            state.completed_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "passed",
                format!("{} completed.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "success".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.output = Some(output.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("success");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_succeeded",
                Some(node_id),
                Some("success"),
                Some(format!("{} completed.", workflow_node_name(node))),
                Some(vec![WorkflowStateUpdate {
                    node_id: node_id.to_string(),
                    key: node_id.to_string(),
                    value: output,
                    reducer: "replace".to_string(),
                }]),
            );
            "passed".to_string()
        }
        Err(error) => {
            state.blocked_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "blocked",
                format!("{} blocked.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "blocked".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.error = Some(error.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("blocked");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_blocked",
                Some(node_id),
                Some("blocked"),
                Some(error),
                None,
            );
            "blocked".to_string()
        }
    };
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread.id.clone()),
        status: status.clone(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: 1,
        test_count: None,
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if dry_run {
            format!("Function dry run {}.", status)
        } else {
            format!("Node run {}.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "run_completed",
        None,
        Some(&status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status;
    final_thread.latest_checkpoint_id = checkpoints.last().map(|checkpoint| checkpoint.id.clone());
    save_workflow_thread(workflow_path, &final_thread)?;
    let node_runs = vec![node_run];
    let verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
    let completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    let result = WorkflowRunResult {
        summary,
        thread: final_thread,
        final_state: state,
        node_runs,
        checkpoints,
        events,
        verification_evidence,
        completion_requirements,
        interrupt: None,
    };
    save_workflow_run_result(workflow_path, &result)?;
    append_workflow_evidence(
        workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: if dry_run { "test_run" } else { "run" }.to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}
