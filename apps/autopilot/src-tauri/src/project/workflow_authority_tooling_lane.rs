// apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs

use super::workflow_value_helpers::workflow_hash_value;
use super::*;

pub(super) fn workflow_side_effect_requires_live_runtime(side_effect_class: &str) -> bool {
    !matches!(side_effect_class, "none" | "read")
}

pub(super) fn workflow_live_mcp_provider_catalog(
    binding: &WorkflowConnectorBinding,
    input: &Value,
) -> Option<Value> {
    let operation = binding.operation.as_deref().unwrap_or("catalog");
    if binding.connector_ref != "mcp.capability-provider"
        || binding.mock_binding
        || binding.side_effect_class != "read"
        || operation != "catalog"
    {
        return None;
    }

    Some(json!({
        "schemaVersion": "workflow.mcp-provider.catalog.v1",
        "providerId": binding.connector_ref.clone(),
        "adapterPort": "McpCapabilityProviderCatalogPort",
        "executionMode": "live_read_only_catalog",
        "live": true,
        "catalogVisibilityCredential": "runtime_catalog_visibility",
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "operation": operation,
        "capabilityScope": binding.capability_scope.clone(),
        "providers": [
            {
                "id": "mcp.capability-provider",
                "status": "available",
                "operations": ["catalog"],
                "sideEffectClass": "read"
            }
        ],
        "tools": [
            {
                "toolRef": "mcp.tool.catalog.read",
                "bindingKind": "mcp_tool",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "executionEnabled": false
            }
        ],
        "connectors": [
            {
                "connectorRef": "agent.connector.catalog",
                "operation": "describe",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false
            }
        ],
        "input": input
    }))
}

fn workflow_provider_catalog_from_input(input: &Value) -> Option<&Value> {
    input
        .get("previousAuthorityOutput")
        .and_then(|output| {
            output
                .get("providerCatalog")
                .filter(|value| value.is_object())
        })
        .or_else(|| {
            input.get("previousOutput").and_then(|output| {
                output
                    .get("providerCatalog")
                    .filter(|value| value.is_object())
            })
        })
        .or_else(|| {
            input
                .get("providerCatalog")
                .filter(|value| value.is_object())
        })
}

fn workflow_mcp_tool_catalog_from_input(input: &Value) -> Option<&Value> {
    input
        .get("previousAuthorityOutput")
        .and_then(|output| {
            output
                .get("mcpToolCatalog")
                .filter(|value| value.is_object())
        })
        .or_else(|| {
            input.get("previousOutput").and_then(|output| {
                output
                    .get("mcpToolCatalog")
                    .filter(|value| value.is_object())
            })
        })
        .or_else(|| {
            input
                .get("mcpToolCatalog")
                .filter(|value| value.is_object())
        })
}

pub(super) fn workflow_live_mcp_tool_catalog(
    binding: &WorkflowToolBinding,
    arguments: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_catalog_read = binding.binding_kind.as_deref() == Some("mcp_tool")
        && binding.tool_ref == "mcp.tool.catalog.read"
        && !binding.mock_binding
        && binding.side_effect_class == "read";
    if !is_catalog_read {
        return Ok(None);
    }

    let provider_catalog = workflow_provider_catalog_from_input(input)
        .ok_or_else(|| "MCP tool catalog read requires live provider catalog input.".to_string())?;
    let tool_listed = provider_catalog
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools.iter().any(|tool| {
                tool.get("toolRef").and_then(Value::as_str) == Some("mcp.tool.catalog.read")
            })
        })
        .unwrap_or(false);
    if !tool_listed {
        return Err("MCP tool catalog read is not present in the provider catalog.".to_string());
    }

    let provider_id = provider_catalog
        .get("providerId")
        .and_then(Value::as_str)
        .unwrap_or("mcp.capability-provider");
    Ok(Some(json!({
        "schemaVersion": "workflow.mcp-tool.catalog-read.v1",
        "toolRef": binding.tool_ref.clone(),
        "bindingKind": "mcp_tool",
        "providerId": provider_id,
        "providerCatalogHash": workflow_hash_value(provider_catalog),
        "executionMode": "live_read_only_catalog_consumer",
        "live": true,
        "providerCatalogLinked": true,
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "arguments": arguments,
        "providerCatalog": {
            "schemaVersion": provider_catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
            "providerId": provider_catalog.get("providerId").cloned().unwrap_or(Value::Null),
            "toolRef": "mcp.tool.catalog.read"
        },
        "input": input
    })))
}

pub(super) fn workflow_live_native_tool_catalog(
    binding: &WorkflowToolBinding,
    arguments: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_catalog_read = binding.binding_kind.as_deref() == Some("native_tool")
        && binding.tool_ref == "agent.runtime.native-tool.catalog.read"
        && !binding.mock_binding
        && binding.side_effect_class == "read";
    if !is_catalog_read {
        return Ok(None);
    }

    if arguments.get("mutation").and_then(Value::as_bool) == Some(true) {
        return Err(
            "Native tool catalog read requires non-mutating catalog arguments.".to_string(),
        );
    }
    let mcp_tool_catalog = workflow_mcp_tool_catalog_from_input(input);
    if let Some(catalog) = mcp_tool_catalog {
        if catalog.get("toolExecutionEnabled").and_then(Value::as_bool) != Some(false) {
            return Err(
                "Native tool catalog read requires a non-executing MCP tool catalog when linked."
                    .to_string(),
            );
        }
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.native-tool.catalog-read.v1",
        "toolRef": binding.tool_ref.clone(),
        "bindingKind": "native_tool",
        "adapterPort": "NativeToolCatalogReadPort",
        "executionMode": "live_read_only_native_tool_catalog",
        "live": true,
        "mcpToolCatalogLinked": mcp_tool_catalog.is_some(),
        "mcpToolCatalogHash": mcp_tool_catalog.map(workflow_hash_value),
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "nativeToolExecutionEnabled": false,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "arguments": arguments,
        "tools": [
            {
                "toolRef": "agent.runtime.native-tool.catalog.read",
                "bindingKind": "native_tool",
                "capabilityScope": ["native.tool.catalog.read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false,
                "executionEnabled": false
            },
            {
                "toolRef": "agent.runtime.noop.read",
                "bindingKind": "native_tool",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": true,
                "executionEnabled": false
            },
            {
                "toolRef": "agent.runtime.tool.invoke",
                "bindingKind": "native_tool",
                "capabilityScope": ["tool.invoke"],
                "sideEffectClass": "external_write",
                "requiresApproval": true,
                "mockBinding": true,
                "executionEnabled": false
            }
        ],
        "mcpToolCatalog": mcp_tool_catalog.map(|catalog| {
            json!({
                "schemaVersion": catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
                "toolRef": catalog.get("toolRef").cloned().unwrap_or(Value::Null),
                "providerId": catalog.get("providerId").cloned().unwrap_or(Value::Null)
            })
        }),
        "input": input
    })))
}

pub(super) fn workflow_live_wallet_capability_dry_run(
    logic: &Value,
    outcome: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let approval_mode = logic
        .get("approvalMode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let capability_scope = logic
        .get("capabilityScope")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let requests_wallet_capability = capability_scope.iter().any(|scope| {
        scope
            .as_str()
            .map(|value| value == "wallet.request" || value == "capability.grant")
            .unwrap_or(false)
    });
    let is_wallet_dry_run = requests_wallet_capability
        && matches!(
            approval_mode,
            "wallet_capability_dry_run" | "read_only_capability_denial"
        );
    if !is_wallet_dry_run {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Wallet capability dry-run cannot execute side effects or mutations.".to_string(),
        );
    }
    if logic.get("capabilityGranted").and_then(Value::as_bool) == Some(true)
        || logic.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
        || outcome.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Wallet capability dry-run cannot materialize a grant or transfer authority."
                .to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.wallet-capability.dry-run.v1",
        "componentKind": "wallet_capability",
        "adapterPort": "WalletCapabilityDryRunPort",
        "executionMode": "live_non_mutating_capability_dry_run",
        "live": true,
        "approvalMode": approval_mode,
        "approvalObserved": outcome.get("approved").and_then(Value::as_bool).unwrap_or(false),
        "approvalDecision": outcome.get("decision").cloned().unwrap_or_else(|| json!("unknown")),
        "dryRunApprovalGranted": logic
            .get("syntheticApprovalGranted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "capabilityRequested": true,
        "capabilityScope": capability_scope,
        "capabilityGranted": false,
        "grantMaterialized": false,
        "grantRef": Value::Null,
        "authorityTransferred": false,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("retain_wallet_capability_without_grant"),
        "walletAuthority": "dry_run_only",
        "receiptKind": "wallet_capability_dry_run_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

pub(super) fn workflow_live_authority_policy_gate(
    logic: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_policy_gate = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("policy_gate")
        || logic
            .get("policyGateLiveExecution")
            .and_then(Value::as_bool)
            == Some(true);
    if !is_policy_gate {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err("Authority policy gate cannot execute side effects or mutations.".to_string());
    }
    if logic
        .get("mutatingToolCallsBlocked")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Authority policy gate must block mutating tool calls.".to_string());
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.policy-gate.v1",
        "componentKind": "policy_gate",
        "adapterPort": "AuthorityPolicyGatePort",
        "executionMode": "live_read_only_policy_gate",
        "live": true,
        "readOnlyRouteAccepted": logic
            .get("readOnlyRouteAccepted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "destructiveRouteDenied": logic
            .get("destructiveRouteDenied")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "mutatingToolCallsBlocked": true,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("allow_read_only_route_through_workflow_authority"),
        "receiptKind": "authority_policy_gate_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

pub(super) fn workflow_live_authority_destructive_denial(
    logic: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_destructive_denial = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("destructive_denial")
        || logic.get("denialClass").and_then(Value::as_str)
            == Some("policy_destructive_without_approval");
    if !is_destructive_denial {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Authority destructive denial cannot execute side effects or mutations.".to_string(),
        );
    }
    if logic.get("destructiveRouteDenied").and_then(Value::as_bool) != Some(true) {
        return Err("Authority destructive denial must deny the destructive route.".to_string());
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.destructive-denial.v1",
        "componentKind": "policy_gate",
        "adapterPort": "AuthorityDestructiveDenialPort",
        "executionMode": "live_destructive_denial_gate",
        "live": true,
        "simulatedRequest": logic.get("simulatedRequest").cloned().unwrap_or(Value::Null),
        "destructiveRouteDenied": true,
        "mutatingToolCallsBlocked": true,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "denialReceiptReady": true,
        "denialClass": logic
            .get("denialClass")
            .and_then(Value::as_str)
            .unwrap_or("policy_destructive_without_approval"),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("deny_destructive_request_without_side_effect"),
        "receiptKind": "authority_destructive_denial_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

pub(super) fn workflow_live_authority_approval_gate(
    logic: &Value,
    outcome: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let approval_mode = logic
        .get("approvalMode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_authority_approval_gate = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("approval_gate")
        || approval_mode == "workflow_recovery_required";
    if !is_authority_approval_gate {
        return Ok(None);
    }

    if logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
        || outcome.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Authority approval gate dry-run cannot transfer authority or execute mutations."
                .to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.approval-gate.v1",
        "componentKind": "approval_gate",
        "adapterPort": "AuthorityApprovalGatePort",
        "executionMode": "live_approval_gate_denial",
        "live": true,
        "approvalMode": approval_mode,
        "approvalObserved": outcome.get("approved").and_then(Value::as_bool).unwrap_or(false),
        "approvalDecision": outcome.get("decision").cloned().unwrap_or_else(|| json!("unknown")),
        "approvalGranted": false,
        "syntheticApprovalGranted": logic
            .get("syntheticApprovalGranted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "authorityTransferred": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("require_workflow_approval_for_mutating_tooling"),
        "receiptKind": "authority_approval_gate_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

pub(super) fn workflow_live_connector_catalog_describe(
    binding: &WorkflowConnectorBinding,
    input: &Value,
) -> Result<Option<Value>, String> {
    let operation = binding.operation.as_deref().unwrap_or("describe");
    let is_catalog_describe = binding.connector_ref == "agent.connector.catalog"
        && !binding.mock_binding
        && binding.side_effect_class == "read"
        && operation == "describe";
    if !is_catalog_describe {
        return Ok(None);
    }

    let mcp_tool_catalog = workflow_mcp_tool_catalog_from_input(input).ok_or_else(|| {
        "Connector catalog describe requires live MCP tool catalog input.".to_string()
    })?;
    if mcp_tool_catalog
        .get("toolExecutionEnabled")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(
            "Connector catalog describe requires a non-executing MCP tool catalog.".to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.connector.catalog-describe.v1",
        "connectorRef": binding.connector_ref.clone(),
        "adapterPort": "ConnectorCatalogDescribePort",
        "executionMode": "live_read_only_connector_describe",
        "live": true,
        "mcpToolCatalogLinked": true,
        "mcpToolCatalogHash": workflow_hash_value(mcp_tool_catalog),
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "connectorExecutionEnabled": false,
        "externalRequestEnabled": false,
        "operation": operation,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "connectors": [
            {
                "connectorRef": "agent.connector.catalog",
                "operation": "describe",
                "capabilityScope": ["connector.catalog.read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false,
                "executionEnabled": false
            },
            {
                "connectorRef": "agent.connector.invoke",
                "operation": "invoke",
                "capabilityScope": ["connector.invoke"],
                "sideEffectClass": "external_write",
                "requiresApproval": true,
                "mockBinding": true,
                "executionEnabled": false
            }
        ],
        "mcpToolCatalog": {
            "schemaVersion": mcp_tool_catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
            "toolRef": mcp_tool_catalog.get("toolRef").cloned().unwrap_or(Value::Null),
            "providerId": mcp_tool_catalog.get("providerId").cloned().unwrap_or(Value::Null)
        },
        "input": input
    })))
}
