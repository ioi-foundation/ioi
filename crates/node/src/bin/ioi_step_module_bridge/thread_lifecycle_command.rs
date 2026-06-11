use ioi_services::agentic::runtime::kernel::policy::{
    AgentCreateStateUpdateCore, AgentCreateStateUpdateRequest, AgentStatusStateUpdateCore,
    AgentStatusStateUpdateRequest, RunCreateStateUpdateCore, RunCreateStateUpdateRequest,
    RuntimeBridgeThreadStartAgentStateUpdateCore, RuntimeBridgeThreadStartAgentStateUpdateRequest,
    RuntimeBridgeTurnRunStateUpdateCore, RuntimeBridgeTurnRunStateUpdateRequest,
    SubagentRecordStateUpdateCore, SubagentRecordStateUpdateRequest,
    ThreadControlAgentStateUpdateCore, ThreadControlAgentStateUpdateRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct ThreadControlAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeThreadStartAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeBridgeTurnRunStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeTurnRunStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubagentRecordStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: SubagentRecordStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct AgentCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: AgentCreateStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct AgentStatusStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: AgentStatusStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RunCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RunCreateStateUpdateRequest,
}

pub(super) fn plan_runtime_bridge_thread_start_agent_state_update(
    request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = RuntimeBridgeThreadStartAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_bridge_thread_start_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_thread_start_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "bridge_start": record.bridge_start.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_runtime_bridge_turn_run_state_update(
    request: RuntimeBridgeTurnRunStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = RuntimeBridgeTurnRunStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_bridge_turn_run_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_turn_run_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}

pub(super) fn plan_subagent_record_state_update(
    request: SubagentRecordStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = SubagentRecordStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("subagent_record_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_subagent_record_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "subagent": record.subagent.clone(),
    }))
}

pub(super) fn plan_thread_control_agent_state_update(
    request: ThreadControlAgentStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = ThreadControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "thread_control_agent_state_update_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_thread_control_agent_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_agent_create_state_update(
    request: AgentCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("agent_create_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_agent_create_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_agent_status_state_update(
    request: AgentStatusStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentStatusStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("agent_status_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_agent_status_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

pub(super) fn plan_run_create_state_update(
    request: RunCreateStateUpdateBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = RunCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            BridgeError::new("run_create_state_update_invalid", format!("{error:?}"))
        })?;
    Ok(json!({
        "source": "rust_run_create_state_update_command",
        "backend": request.backend.unwrap_or_else(|| "rust_policy".to_string()),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}
