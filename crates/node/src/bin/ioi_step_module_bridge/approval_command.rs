use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalDecisionStateUpdateCore, ApprovalDecisionStateUpdateRequest,
    ApprovalRequestStateUpdateCore, ApprovalRequestStateUpdateRequest,
    ApprovalRevokeStateUpdateCore, ApprovalRevokeStateUpdateRequest, CodingToolApprovalCore,
    CodingToolApprovalRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct CodingToolApprovalBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: CodingToolApprovalRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalRequestStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalRequestStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalDecisionStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalDecisionStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalRevokeStateUpdateBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: ApprovalRevokeStateUpdateRequest,
}

pub(super) fn plan_coding_tool_approval_manifest(
    request: CodingToolApprovalBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_coding_tool_approval_manifest" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let plan = CodingToolApprovalCore
        .plan_manifest(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "coding_tool_approval_manifest_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_coding_tool_approval_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "plan": plan.clone(),
        "approval_required": plan.approval_required,
        "workflow_policy": plan.workflow_policy.clone(),
        "manifest": plan.manifest.clone(),
        "input_hash": plan.input_hash.clone(),
    }))
}

pub(super) fn plan_approval_request_state_update(
    request: ApprovalRequestStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_request_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalRequestStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "approval_request_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_approval_request_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_approval_decision_state_update(
    request: ApprovalDecisionStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_decision_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalDecisionStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "approval_decision_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_approval_decision_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_approval_revoke_state_update(
    request: ApprovalRevokeStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "plan_approval_revoke_state_update" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = ApprovalRevokeStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("approval_revoke_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_approval_revoke_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "target_kind": record.target_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "operator_control": record.operator_control.clone(),
        "run": record.run.clone(),
        "agent": record.agent.clone(),
    }))
}
