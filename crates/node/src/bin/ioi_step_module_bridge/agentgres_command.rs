use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, RuntimeAgentStateCommitRequest, RuntimeArtifactStateCommitRequest,
    RuntimeMemoryStateCommitRequest, RuntimeModelMountReceiptStateCommitRequest,
    RuntimeModelMountRecordStateCommitRequest, RuntimeRunStateCommitRequest,
    RuntimeStateStorageWriteRecord, RuntimeStateWrittenRecord, RuntimeSubagentStateCommitRequest,
    StorageBackendWriteProposal,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::BridgeError;

#[derive(Debug, Deserialize)]
pub(super) struct StorageBackendWriteBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: StorageBackendWriteProposal,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeRunStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeRunStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeAgentStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeAgentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeMemoryStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeMemoryStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeSubagentStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeSubagentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeArtifactStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeArtifactStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeModelMountRecordStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountRecordStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeModelMountReceiptStateCommitBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountReceiptStateCommitRequest,
}

pub(super) fn admit_storage_backend_write(
    request: StorageBackendWriteBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .admit_storage_backend_write(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "storage_backend_write_admission_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_agentgres_storage_write_admission_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "admission_hash": record.admission_hash.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.object_ref.clone(),
        "content_hash": record.content_hash.clone(),
        "artifact_refs": record.artifact_refs.clone(),
        "payload_refs": record.payload_refs.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "evidence_refs": [
            "rust_agentgres_storage_write_admission",
            record.admission_hash,
        ],
    }))
}

pub(super) fn commit_runtime_run_state(
    request: RuntimeRunStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let persisted = AgentgresAdmissionCore
        .commit_runtime_run_state_to_dir(&request.state_dir, &request.request)
        .map_err(|error| {
            BridgeError::new("runtime_run_state_commit_invalid", format!("{error:?}"))
        })?;
    let record = persisted.commit;
    Ok(json!({
        "source": "rust_agentgres_runtime_run_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "transition": record.transition.clone(),
        "persistence": record.persistence.clone(),
        "operation_ref": record.transition.operation_ref.clone(),
        "state_root_after": record.transition.state_root_after.clone(),
        "resulting_head": record.transition.resulting_head.clone(),
        "transition_hash": record.transition.transition_hash.clone(),
        "materialization_hash": record.persistence.materialization.materialization_hash.clone(),
        "write_set_hash": record.persistence.storage_write_set.write_set_hash.clone(),
        "persistence_hash": record.persistence.persistence_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "records": record.persistence.storage_write_set.records.clone(),
        "written_records": persisted.written_records,
        "evidence_refs": [
            "rust_agentgres_runtime_run_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_agent_state(
    request: RuntimeAgentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_agent_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_agent_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.agent,
        "runtime_agent_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_agent_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "agent_id": record.agent_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_agent_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_memory_state(
    request: RuntimeMemoryStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_memory_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_memory_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.payload,
        "runtime_memory_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_memory_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "memory_state_kind": record.memory_state_kind.clone(),
        "state_id": record.state_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_memory_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_subagent_state(
    request: RuntimeSubagentStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_subagent_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_subagent_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.subagent,
        "runtime_subagent_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_subagent_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "subagent_id": record.subagent_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_subagent_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_artifact_state(
    request: RuntimeArtifactStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_artifact_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.artifact,
        "runtime_artifact_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_artifact_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "artifact_id": record.artifact_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_artifact_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_model_mount_record_state(
    request: RuntimeModelMountRecordStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_record_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_record_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.record,
        "runtime_model_mount_record_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_model_mount_record_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "record_dir": record.record_dir.clone(),
        "record_id": record.record_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_model_mount_record_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_model_mount_receipt_state(
    request: RuntimeModelMountReceiptStateCommitBridgeRequest,
) -> Result<Value, BridgeError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_receipt_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_receipt_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.receipt,
        "runtime_model_mount_receipt_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
        "backend": request.backend.unwrap_or_else(|| "rust_agentgres_storage".to_string()),
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "receipt_id": record.receipt_id.clone(),
        "operation_kind": record.operation_kind.clone(),
        "storage_backend_ref": record.storage_backend_ref.clone(),
        "object_ref": record.record.object_ref.clone(),
        "content_hash": record.record.content_hash.clone(),
        "payload_refs": record.record.payload_refs.clone(),
        "receipt_refs": record.record.receipt_refs.clone(),
        "admission_hash": record.record.admission.admission_hash.clone(),
        "commit_hash": record.commit_hash.clone(),
        "written_record": written_record,
        "evidence_refs": [
            "rust_agentgres_runtime_model_mount_receipt_state_commit",
            record.commit_hash,
        ],
    }))
}

fn persist_runtime_state_storage_record(
    state_dir: &str,
    record: &RuntimeStateStorageWriteRecord,
    payload: &Value,
    error_code: &'static str,
) -> Result<RuntimeStateWrittenRecord, BridgeError> {
    let state_root = AgentgresAdmissionCore
        .ensure_runtime_state_dir(state_dir)
        .map_err(|error| BridgeError::new(error_code, format!("{error:?}")))?;
    AgentgresAdmissionCore
        .persist_runtime_state_storage_record(&state_root, record, payload)
        .map_err(|error| BridgeError::new(error_code, format!("{error:?}")))
}
