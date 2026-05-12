// apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs

use super::workflow_graph_execution_lane::{
    workflow_edge_connection_class, workflow_edge_from_port, workflow_edge_to_port,
};
use super::workflow_node_metadata_lane::{
    workflow_node_id, workflow_node_law, workflow_node_logic, workflow_node_name,
    workflow_node_type,
};
use super::workflow_value_helpers::{
    workflow_logic_string, workflow_value_bool_any, workflow_value_string_any,
};
use super::*;

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
        ActionKind::WorkflowPackageExport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::WorkflowPackageImport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::GithubPrCreate => Some(ActionBindingRef {
            binding_type: "github".to_string(),
            reference: workflow_value_string_any(&logic, &["repoFullName", "repository"]),
            mock_binding: true,
            side_effect_class: "external_write".to_string(),
            requires_approval: !workflow_value_bool_any(&logic, &["dryRun", "previewOnly"])
                .unwrap_or(true),
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
        ("workflow_package_export", "output", "package")
        | ("workflow_package_import", "input", "package") => "output_bundle",
        ("workflow_package_export", "output", "manifest")
        | ("workflow_package_export", "output", "readiness")
        | ("workflow_package_export", "output", "locale")
        | ("workflow_package_import", "output", "review")
        | ("workflow_package_import", "output", "imported_workflow")
        | ("workflow_package_import", "output", "evidence")
        | ("workflow_package_import", "output", "locale") => "data",
        ("repository_context", "output", "repository")
        | ("branch_policy", "input", "repository")
        | ("branch_policy", "output", "branch_policy")
        | ("github_context", "input", "repository")
        | ("github_context", "input", "branch_policy")
        | ("github_context", "output", "github_context")
        | ("issue_context", "input", "github_context")
        | ("issue_context", "output", "issue_context")
        | ("pr_attempt", "input", "repository")
        | ("pr_attempt", "input", "branch_policy")
        | ("pr_attempt", "input", "github_context")
        | ("pr_attempt", "input", "issue_context")
        | ("pr_attempt", "output", "pr_attempt")
        | ("review_gate", "input", "repository")
        | ("review_gate", "input", "branch_policy")
        | ("review_gate", "input", "github_context")
        | ("review_gate", "input", "issue_context")
        | ("review_gate", "input", "pr_attempt")
        | ("github_pr_create", "input", "repository")
        | ("github_pr_create", "input", "branch_policy")
        | ("github_pr_create", "input", "github_context")
        | ("github_pr_create", "input", "issue_context")
        | ("github_pr_create", "input", "pr_attempt")
        | ("github_pr_create", "output", "blockers") => "state",
        ("review_gate", "output", "review_gate")
        | ("github_pr_create", "input", "review_gate")
        | ("github_pr_create", "output", "plan") => "approval",
        ("github_pr_create", "output", "request") => "data",
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
