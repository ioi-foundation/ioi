use ioi_services::agentic::runtime::kernel::agentgres_command::{
    admit_storage_backend_write_response as core_admit_storage_backend_write,
    commit_runtime_agent_state_response as core_commit_runtime_agent_state,
    commit_runtime_artifact_state_response as core_commit_runtime_artifact_state,
    commit_runtime_memory_state_response as core_commit_runtime_memory_state,
    commit_runtime_model_mount_receipt_state_response as core_commit_runtime_model_mount_receipt_state,
    commit_runtime_model_mount_record_state_response as core_commit_runtime_model_mount_record_state,
    commit_runtime_run_state_response as core_commit_runtime_run_state,
    commit_runtime_subagent_state_response as core_commit_runtime_subagent_state,
    AgentgresCommandError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::agentgres_command::{
    RuntimeAgentStateCommitBridgeRequest, RuntimeArtifactStateCommitBridgeRequest,
    RuntimeMemoryStateCommitBridgeRequest, RuntimeModelMountReceiptStateCommitBridgeRequest,
    RuntimeModelMountRecordStateCommitBridgeRequest, RuntimeRunStateCommitBridgeRequest,
    RuntimeSubagentStateCommitBridgeRequest, StorageBackendWriteBridgeRequest,
};

pub(super) fn admit_storage_backend_write(
    request: StorageBackendWriteBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_storage_backend_write(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_run_state(
    request: RuntimeRunStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_run_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_agent_state(
    request: RuntimeAgentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_agent_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_memory_state(
    request: RuntimeMemoryStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_memory_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_subagent_state(
    request: RuntimeSubagentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_subagent_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_artifact_state(
    request: RuntimeArtifactStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_artifact_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_model_mount_record_state(
    request: RuntimeModelMountRecordStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_model_mount_record_state(request).map_err(bridge_error)
}

pub(super) fn commit_runtime_model_mount_receipt_state(
    request: RuntimeModelMountReceiptStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    core_commit_runtime_model_mount_receipt_state(request).map_err(bridge_error)
}

fn bridge_error(error: AgentgresCommandError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
