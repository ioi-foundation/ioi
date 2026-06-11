use serde::Deserialize;
use serde_json::{json, Value};

use super::agentgres_admission::{
    AgentgresAdmissionCore, RuntimeAgentStateCommitRequest, RuntimeArtifactStateCommitRequest,
    RuntimeMemoryStateCommitRequest, RuntimeModelMountReceiptStateCommitRequest,
    RuntimeModelMountRecordStateCommitRequest, RuntimeRunStateCommitRequest,
    RuntimeStateStorageWriteRecord, RuntimeStateWrittenRecord, RuntimeSubagentStateCommitRequest,
    StorageBackendWriteProposal,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentgresCommandError {
    code: &'static str,
    message: String,
}

impl AgentgresCommandError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Deserialize)]
pub struct StorageBackendWriteBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: StorageBackendWriteProposal,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeRunStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeRunStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeAgentStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeAgentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeMemoryStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeMemoryStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeSubagentStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeSubagentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeArtifactStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeArtifactStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeModelMountRecordStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeModelMountRecordStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeModelMountReceiptStateCommitBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub state_dir: String,
    pub request: RuntimeModelMountReceiptStateCommitRequest,
}

pub fn admit_storage_backend_write_response(
    request: StorageBackendWriteBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .admit_storage_backend_write(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new(
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

pub fn commit_runtime_run_state_response(
    request: RuntimeRunStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let persisted = AgentgresAdmissionCore
        .commit_runtime_run_state_to_dir(&request.state_dir, &request.request)
        .map_err(|error| {
            AgentgresCommandError::new("runtime_run_state_commit_invalid", format!("{error:?}"))
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

pub fn commit_runtime_agent_state_response(
    request: RuntimeAgentStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_agent_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new("runtime_agent_state_commit_invalid", format!("{error:?}"))
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

pub fn commit_runtime_memory_state_response(
    request: RuntimeMemoryStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_memory_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new("runtime_memory_state_commit_invalid", format!("{error:?}"))
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

pub fn commit_runtime_subagent_state_response(
    request: RuntimeSubagentStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_subagent_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new(
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

pub fn commit_runtime_artifact_state_response(
    request: RuntimeArtifactStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new(
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

pub fn commit_runtime_model_mount_record_state_response(
    request: RuntimeModelMountRecordStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_record_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new(
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

pub fn commit_runtime_model_mount_receipt_state_response(
    request: RuntimeModelMountReceiptStateCommitBridgeRequest,
) -> Result<Value, AgentgresCommandError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_receipt_state(&request.request)
        .map_err(|error| {
            AgentgresCommandError::new(
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
) -> Result<RuntimeStateWrittenRecord, AgentgresCommandError> {
    let state_root = AgentgresAdmissionCore
        .ensure_runtime_state_dir(state_dir)
        .map_err(|error| AgentgresCommandError::new(error_code, format!("{error:?}")))?;
    AgentgresAdmissionCore
        .persist_runtime_state_storage_record(&state_root, record, payload)
        .map_err(|error| AgentgresCommandError::new(error_code, format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_core_shapes_storage_backend_write_response() {
        let response = admit_storage_backend_write_response(StorageBackendWriteBridgeRequest {
            backend: Some("rust_agentgres_storage".to_string()),
            request: StorageBackendWriteProposal {
                schema_version: "ioi.storage_backend_write_admission.v1".to_string(),
                storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
                object_ref: "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
                    .to_string(),
                content_hash: "sha256:runtime-state-write".to_string(),
                artifact_refs: vec![],
                payload_refs: vec![
                    "payload://runtime/runs/run_1/records/runs/run_1.json".to_string()
                ],
                receipt_refs: vec!["receipt_policy".to_string()],
            },
        })
        .expect("storage write response");

        assert_eq!(
            response["source"],
            "rust_agentgres_storage_write_admission_command"
        );
        assert_eq!(response["backend"], "rust_agentgres_storage");
        assert_eq!(
            response["object_ref"],
            "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
    }
}
