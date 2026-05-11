// apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs

use super::workflow_binding_lane::{workflow_connector_binding, workflow_tool_binding};
use super::workflow_value_helpers::{
    workflow_logic_string, workflow_value_bool_any, workflow_value_string_any,
};
use super::*;

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
        ActionKind::WorkflowPackageImport => {
            let law = workflow_node_law(node);
            law.get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .then(|| {
                    json!({
                        "bindingKind": "workflow_package",
                        "operation": "import",
                        "packagePath": workflow_logic_string(&logic, "workflowPackagePath"),
                        "projectRoot": workflow_logic_string(&logic, "workflowPackageProjectRoot"),
                        "sideEffectClass": "write",
                        "capabilityScope": ["workflow.package.import", "workflow.package.review"]
                    })
                })
        }
        ActionKind::GithubPrCreate => {
            if workflow_value_bool_any(&logic, &["dryRun", "previewOnly"]).unwrap_or(true) {
                None
            } else {
                Some(json!({
                    "bindingKind": "github",
                    "operation": "pr_create",
                    "toolName": "github__pr_create",
                    "repoFullName": workflow_value_string_any(&logic, &["repoFullName", "repository"]),
                    "sideEffectClass": "external_write",
                    "capabilityScope": ["github.pr.create"]
                }))
            }
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

pub(super) fn workflow_runtime_interrupt_notice(action_kind: &ActionKind) -> String {
    if action_kind.is_interrupt() {
        "Human input required before continuing.".to_string()
    } else {
        "Approval required before this node runs.".to_string()
    }
}

pub(super) fn workflow_runtime_interrupt(
    run_id: &str,
    thread_id: &str,
    node: &Value,
    action_kind: &ActionKind,
    response: Option<Value>,
) -> WorkflowInterrupt {
    WorkflowInterrupt {
        id: unique_runtime_id("interrupt"),
        run_id: run_id.to_string(),
        thread_id: thread_id.to_string(),
        node_id: workflow_node_id(node).unwrap_or_else(|| "unknown".to_string()),
        status: "pending".to_string(),
        created_at_ms: now_ms(),
        resolved_at_ms: None,
        prompt: workflow_runtime_interrupt_prompt(node, action_kind),
        allowed_outcomes: vec![
            "approve".to_string(),
            "reject".to_string(),
            "edit".to_string(),
        ],
        response,
    }
}
