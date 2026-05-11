// apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs

use super::*;

fn workflow_binding_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_binding_node_type(node: &Value) -> String {
    workflow_binding_value_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

fn workflow_binding_node_logic(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("logic"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn workflow_binding_node_law(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("law"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn workflow_binding_output_bundle_schema() -> Value {
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
    workflow_binding_node_logic(node)
        .get(logic_key)
        .cloned()
        .or_else(|| node.get("schema").cloned())
        .or_else(|| {
            (logic_key == "outputSchema" && workflow_binding_node_type(node) == "output")
                .then(workflow_binding_output_bundle_schema)
        })
}

pub(super) fn workflow_function_binding(node: &Value) -> Result<WorkflowFunctionBinding, String> {
    let logic = workflow_binding_node_logic(node);
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
        sandbox_policy: workflow_binding_node_law(node)
            .get("sandboxPolicy")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        test_input: logic.get("testInput").cloned(),
    })
}

pub(super) fn workflow_tool_binding(node: &Value) -> Result<WorkflowToolBinding, String> {
    let logic = workflow_binding_node_logic(node);
    let Some(binding) = logic.get("toolBinding") else {
        return Err("Plugin tool binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Tool binding is invalid: {}", error))
}

pub(super) fn workflow_parser_binding(node: &Value) -> Result<WorkflowParserBinding, String> {
    let logic = workflow_binding_node_logic(node);
    let Some(binding) = logic.get("parserBinding") else {
        return Err("Output Parser binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Output Parser binding is invalid: {}", error))
}

pub(super) fn workflow_model_binding(node: &Value) -> Result<WorkflowModelBinding, String> {
    let logic = workflow_binding_node_logic(node);
    let Some(binding) = logic.get("modelBinding") else {
        return Err("Model Binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Model Binding is invalid: {}", error))
}

pub(super) fn workflow_connector_binding(node: &Value) -> Result<WorkflowConnectorBinding, String> {
    let logic = workflow_binding_node_logic(node);
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
            workflow_binding_node_law(node)
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

pub(super) fn workflow_function_input_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.input_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.input_schema.as_ref())
    })
}

pub(super) fn workflow_function_output_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.output_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.output_schema.as_ref())
    })
}
