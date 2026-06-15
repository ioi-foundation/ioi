use serde::Deserialize;
use serde_json::{json, Value};

use super::agentgres_admission::{
    AgentgresAdmissionCore, RuntimeAgentStateCommitRequest, RuntimeArtifactStateCommitRequest,
    RuntimeMcpLiveResultStateCommitRequest, RuntimeMemoryStateCommitRequest,
    RuntimeModelMountReceiptStateCommitRequest, RuntimeModelMountRecordStateCommitRequest,
    RuntimeReceiptStateCommitRequest, RuntimeRunStateCommitRequest, RuntimeStateStorageWriteRecord,
    RuntimeStateWrittenRecord, RuntimeSubagentStateCommitRequest, StorageBackendWriteProposal,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentgresProtocolError {
    code: &'static str,
    message: String,
}

impl AgentgresProtocolError {
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
#[serde(deny_unknown_fields)]
pub struct StorageBackendWriteProtocolRequest {
    pub request: StorageBackendWriteProposal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRunStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeRunStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAgentStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeAgentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMemoryStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeMemoryStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubagentStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeSubagentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeArtifactStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceiptStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeReceiptStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMcpLiveResultStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeMcpLiveResultStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModelMountRecordStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeModelMountRecordStateCommitRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModelMountReceiptStateCommitProtocolRequest {
    pub state_dir: String,
    pub request: RuntimeModelMountReceiptStateCommitRequest,
}

pub fn admit_storage_backend_write_response(
    request: StorageBackendWriteProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .admit_storage_backend_write(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
                "storage_backend_write_admission_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_agentgres_storage_write_admission_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeRunStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let persisted = AgentgresAdmissionCore
        .commit_runtime_run_state_to_dir(&request.state_dir, &request.request)
        .map_err(|error| {
            AgentgresProtocolError::new("runtime_run_state_commit_invalid", format!("{error:?}"))
        })?;
    let record = persisted.commit;
    Ok(json!({
        "source": "rust_agentgres_runtime_run_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeAgentStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_agent_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new("runtime_agent_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.agent,
        "runtime_agent_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_agent_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeMemoryStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_memory_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new("runtime_memory_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.payload,
        "runtime_memory_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_memory_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeSubagentStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_subagent_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
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
        "source": "rust_agentgres_runtime_subagent_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeArtifactStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
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
        "source": "rust_agentgres_runtime_artifact_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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

pub fn commit_runtime_receipt_state_response(
    request: RuntimeReceiptStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_receipt_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
                "runtime_receipt_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.receipt,
        "runtime_receipt_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_receipt_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
            "rust_agentgres_runtime_receipt_state_commit",
            record.commit_hash,
        ],
    }))
}

pub fn commit_runtime_mcp_live_result_state_response(
    request: RuntimeMcpLiveResultStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_mcp_live_result_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
                "runtime_mcp_live_result_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = persist_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.result,
        "runtime_mcp_live_result_state_commit_invalid",
    )?;
    Ok(json!({
        "source": "rust_agentgres_runtime_mcp_live_result_state_commit_protocol",
        "backend": "rust_agentgres_storage",
        "record": record.clone(),
        "storage_record": record.record.clone(),
        "result_id": record.result_id.clone(),
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
            "rust_agentgres_runtime_mcp_live_result_state_commit",
            record.commit_hash,
        ],
    }))
}

pub fn commit_runtime_model_mount_record_state_response(
    request: RuntimeModelMountRecordStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_record_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
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
        "source": "rust_agentgres_runtime_model_mount_record_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
    request: RuntimeModelMountReceiptStateCommitProtocolRequest,
) -> Result<Value, AgentgresProtocolError> {
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_receipt_state(&request.request)
        .map_err(|error| {
            AgentgresProtocolError::new(
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
        "source": "rust_agentgres_runtime_model_mount_receipt_state_commit_protocol",
        "backend": "rust_agentgres_storage",
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
) -> Result<RuntimeStateWrittenRecord, AgentgresProtocolError> {
    let state_root = AgentgresAdmissionCore
        .ensure_runtime_state_dir(state_dir)
        .map_err(|error| AgentgresProtocolError::new(error_code, format!("{error:?}")))?;
    AgentgresAdmissionCore
        .persist_runtime_state_storage_record(&state_root, record, payload)
        .map_err(|error| AgentgresProtocolError::new(error_code, format!("{error:?}")))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn agentgres_protocol_admits_storage_backend_write_through_rust_core() {
        let request: StorageBackendWriteProtocolRequest = serde_json::from_value(json!({
            "request": {
                "schema_version": "ioi.storage_backend_write_admission.v1",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "object_ref": "agentgres://runtime-state/runs/run_1/records/runs/run_1.json",
                "content_hash": "sha256:runtime-state-write",
                "artifact_refs": [],
                "payload_refs": ["payload://runtime/runs/run_1/records/runs/run_1.json"],
                "receipt_refs": ["receipt_policy"]
            }
        }))
        .expect("storage write protocol request");

        let response =
            admit_storage_backend_write_response(request).expect("storage write admitted");

        assert_eq!(
            response["source"],
            "rust_agentgres_storage_write_admission_protocol"
        );
        assert_eq!(response["backend"], "rust_agentgres_storage");
        assert_eq!(
            response["record"]["storage_backend_ref"],
            "storage://runtime-agentgres/local-json"
        );
        assert_eq!(
            response["object_ref"],
            "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
        );
        assert!(response["admission_hash"]
            .as_str()
            .expect("admission hash")
            .starts_with("sha256:"));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_storage_write_admission"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_run_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        fs::create_dir_all(state_dir.join("tasks")).expect("tasks dir");
        fs::write(
            state_dir.join("tasks/run_1.json"),
            serde_json::to_string_pretty(&json!({
                "runId": "run_1",
                "agentgresTransition": {
                    "state_root_after": "sha256:previous-state-root",
                    "resulting_head": "agentgres://runtime-state/runs/run_1/head/previous"
                }
            }))
            .expect("previous transition"),
        )
        .expect("previous transition file");
        let request: RuntimeRunStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_run_state_commit.v1",
                "run_id": "run_1",
                "operation_kind": "run.cancel",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "run": {
                    "id": "run_1",
                    "agentId": "agent_1",
                    "status": "canceled",
                    "mode": "send",
                    "objective": "Ship the runtime state slice",
                    "createdAt": "2026-06-04T00:00:00.000Z",
                    "updatedAt": "2026-06-04T00:00:01.000Z",
                    "events": [
                        { "type": "started" },
                        { "type": "canceled" }
                    ],
                    "receipts": [
                        {
                            "id": "receipt_cancel",
                            "kind": "run_cancel"
                        }
                    ],
                    "artifacts": [],
                    "trace": {
                        "traceBundleId": "trace_bundle_1",
                        "taskState": {
                            "state": "canceled"
                        },
                        "postconditions": [],
                        "semanticImpact": {
                            "impact": "local"
                        },
                        "stopCondition": {
                            "reason": "operator_cancel"
                        },
                        "scorecard": {
                            "score": 1
                        },
                        "qualityLedger": {
                            "entries": []
                        }
                    }
                },
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updatedAt": "2026-06-04T00:00:01.000Z"
                },
                "canonical_projection": {
                    "runId": "run_1",
                    "projection": "canonical"
                }
            }
        }))
        .expect("runtime run-state commit protocol request");

        let response = commit_runtime_run_state_response(request).expect("run state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_run_state_commit_protocol"
        );
        assert_eq!(
            response["transition"]["expected_heads"][0],
            "agentgres://runtime-state/runs/run_1/head/previous"
        );
        assert_eq!(
            response["transition"]["state_root_before"],
            "sha256:previous-state-root"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("tasks/run_1.json").exists());
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        let task_record =
            fs::read_to_string(state_dir.join("tasks/run_1.json")).expect("task record");
        assert!(task_record.contains("\"agentgresTransition\""));
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_run_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_agent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeAgentStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_agent_state_commit.v1",
                "agent_id": "agent_1",
                "operation_kind": "agent.create",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "agent": {
                    "id": "agent_1",
                    "status": "active",
                    "runtime": "local",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_agent"]
                }
            }
        }))
        .expect("runtime agent-state commit protocol request");

        let response = commit_runtime_agent_state_response(request).expect("agent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_agent_state_commit_protocol"
        );
        assert_eq!(response["agent_id"], "agent_1");
        assert_eq!(response["operation_kind"], "agent.create");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("agents/agent_1.json").exists());
        let agent_record =
            fs::read_to_string(state_dir.join("agents/agent_1.json")).expect("agent record");
        assert!(agent_record.contains("\"id\": \"agent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_agent_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_memory_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeMemoryStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_memory_state_commit.v1",
                "memory_state_kind": "record",
                "state_id": "memory_1",
                "operation_kind": "memory.write",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "payload": {
                    "schemaVersion": "ioi.agent-runtime.memory.v1",
                    "id": "memory_1",
                    "object": "ioi.agent_memory_record",
                    "fact": "Remember the launch checklist.",
                    "threadId": "thread_1",
                    "agentId": "agent_1",
                    "receipt_refs": ["receipt_memory"]
                }
            }
        }))
        .expect("runtime memory-state commit protocol request");

        let response =
            commit_runtime_memory_state_response(request).expect("memory state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_memory_state_commit_protocol"
        );
        assert_eq!(response["memory_state_kind"], "record");
        assert_eq!(response["state_id"], "memory_1");
        assert_eq!(response["operation_kind"], "memory.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("memory-records/memory_1.json").exists());
        let memory_record = fs::read_to_string(state_dir.join("memory-records/memory_1.json"))
            .expect("memory record");
        assert!(memory_record.contains("\"id\": \"memory_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_memory_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_subagent_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeSubagentStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_subagent_state_commit.v1",
                "subagent_id": "subagent_1",
                "operation_kind": "subagent.wait",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "subagent": {
                    "subagent_id": "subagent_1",
                    "parent_thread_id": "thread_1",
                    "agent_id": "agent_1",
                    "role": "research",
                    "lifecycle_status": "completed",
                    "updated_at": "2026-06-06T00:00:00.000Z",
                    "receipt_refs": ["receipt_subagent"]
                }
            }
        }))
        .expect("runtime subagent-state commit protocol request");

        let response =
            commit_runtime_subagent_state_response(request).expect("subagent state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_subagent_state_commit_protocol"
        );
        assert_eq!(response["subagent_id"], "subagent_1");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("subagents/subagent_1.json").exists());
        let subagent_record = fs::read_to_string(state_dir.join("subagents/subagent_1.json"))
            .expect("subagent record");
        assert!(subagent_record.contains("\"subagent_id\": \"subagent_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_subagent_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_artifact_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeArtifactStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_artifact_state_commit.v1",
                "artifact_id": "artifact_1",
                "operation_kind": "artifact.coding_tool_draft",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "artifact": {
                    "schema_version": "ioi.runtime.coding-tool-artifact.v1",
                    "id": "artifact_1",
                    "thread_id": "thread_1",
                    "tool_name": "file.read",
                    "tool_call_id": "tool_call_1",
                    "channel": "stdout",
                    "media_type": "text/plain",
                    "receipt_id": "receipt_artifact",
                    "content": "hello",
                    "content_bytes": 5,
                    "content_hash": "sha256:content"
                }
            }
        }))
        .expect("runtime artifact-state commit protocol request");

        let response =
            commit_runtime_artifact_state_response(request).expect("artifact state committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_artifact_state_commit_protocol"
        );
        assert_eq!(response["artifact_id"], "artifact_1");
        assert_eq!(response["operation_kind"], "artifact.coding_tool_draft");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir.join("artifacts/artifact_1.json").exists());
        let artifact_record = fs::read_to_string(state_dir.join("artifacts/artifact_1.json"))
            .expect("artifact record");
        assert!(artifact_record.contains("\"id\": \"artifact_1\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_artifact_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_receipt_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeReceiptStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_receipt_state_commit.v1",
                "receipt_id": "receipt_runtime_mcp_live_exit",
                "operation_kind": "runtime.mcp_live_exit.receipt.write",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "receipt": {
                    "schema_version": "ioi.runtime.mcp-live-exit-receipt.v1",
                    "id": "receipt_runtime_mcp_live_exit",
                    "kind": "runtime_mcp_live_exit",
                    "redaction": "redacted",
                    "evidence_refs": [
                        "runtime_mcp_live_exit_rust_receipt",
                        "agentgres_runtime_mcp_live_receipt_truth_required"
                    ],
                    "details": {
                        "rust_daemon_core_receipt_author": "runtime.mcp_control",
                        "runtime_mcp_agentgres_operation_ref": "agentgres://runtime-state/agents/agent_1/operations/mcp_invoke/event_1",
                        "runtime_mcp_agent_state_root_before": "sha256:before",
                        "runtime_mcp_agent_state_root_after": "sha256:after",
                        "runtime_mcp_resulting_head": "agentgres://runtime-state/agents/agent_1/head/sha256_after"
                    }
                }
            }
        }))
        .expect("runtime receipt-state commit protocol request");

        let response =
            commit_runtime_receipt_state_response(request).expect("runtime receipt committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_receipt_state_commit_protocol"
        );
        assert_eq!(response["receipt_id"], "receipt_runtime_mcp_live_exit");
        assert_eq!(
            response["operation_kind"],
            "runtime.mcp_live_exit.receipt.write"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("receipts/receipt_runtime_mcp_live_exit.json")
            .exists());
        let receipt_record =
            fs::read_to_string(state_dir.join("receipts/receipt_runtime_mcp_live_exit.json"))
                .expect("runtime receipt record");
        assert!(receipt_record.contains("\"id\": \"receipt_runtime_mcp_live_exit\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/receipts/receipt_runtime_mcp_live_exit/records/receipts/receipt_runtime_mcp_live_exit.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_receipt_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_mcp_live_result_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeMcpLiveResultStateCommitProtocolRequest = serde_json::from_value(json!({
            "state_dir": state_dir,
            "request": {
                "schema_version": "ioi.runtime_mcp_live_result_state_commit.v1",
                "result_id": "result_runtime_mcp_live_exit",
                "operation_kind": "runtime.mcp_live_exit.result.write",
                "storage_backend_ref": "storage://runtime-agentgres/local-json",
                "result": {
                    "schema_version": "ioi.runtime.mcp-live-result.v1",
                    "id": "result_runtime_mcp_live_exit",
                    "kind": "runtime_mcp_live_result",
                    "status": "rust_materialized",
                    "receipt_id": "receipt_runtime_mcp_live_exit",
                    "receipt_refs": ["receipt_runtime_mcp_live_exit"],
                    "evidence_refs": [
                        "runtime_mcp_live_result_rust_projection",
                        "agentgres_runtime_mcp_live_result_truth_required",
                        "runtime_mcp_live_result_payload_rust_materialized",
                        "runtime_mcp_no_js_transport_result"
                    ],
                    "details": {
                        "rust_daemon_core_result_author": "runtime.mcp_control",
                        "runtime_mcp_agentgres_operation_ref": "agentgres://runtime-state/agents/agent_1/operations/mcp_invoke/event_1",
                        "runtime_mcp_agent_state_root_before": "sha256:before",
                        "runtime_mcp_agent_state_root_after": "sha256:after",
                        "runtime_mcp_resulting_head": "agentgres://runtime-state/agents/agent_1/head/sha256_after",
                        "result_materialized": true,
                        "backend_materialization_status": "rust_driver_contract_bound",
                        "js_transport_invocation": false,
                        "command_transport_fallback": false,
                        "binary_bridge_fallback": false,
                        "compatibility_fallback": false
                    }
                }
            }
        }))
        .expect("runtime MCP live-result state commit protocol request");

        let response = commit_runtime_mcp_live_result_state_response(request)
            .expect("runtime MCP live result committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_mcp_live_result_state_commit_protocol"
        );
        assert_eq!(response["result_id"], "result_runtime_mcp_live_exit");
        assert_eq!(
            response["operation_kind"],
            "runtime.mcp_live_exit.result.write"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("mcp-live-results/result_runtime_mcp_live_exit.json")
            .exists());
        let result_record = fs::read_to_string(
            state_dir.join("mcp-live-results/result_runtime_mcp_live_exit.json"),
        )
        .expect("runtime MCP live result record");
        assert!(result_record.contains("\"id\": \"result_runtime_mcp_live_exit\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://runtime-state/mcp-live-results/result_runtime_mcp_live_exit/records/mcp-live-results/result_runtime_mcp_live_exit.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_mcp_live_result_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_model_mount_record_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountRecordStateCommitProtocolRequest =
            serde_json::from_value(json!({
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_record_state_commit.v1",
                    "record_dir": "provider-health",
                    "record_id": "health.provider_openai",
                    "operation_kind": "model_mount.provider_health.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "record": {
                        "id": "health.provider_openai",
                        "provider_id": "provider.openai",
                        "status": "available",
                        "checked_at": "2026-06-04T00:00:00.000Z",
                        "receipt_id": "receipt_provider_health",
                        "evidence_refs": ["provider_http_health"]
                    }
                }
            }))
            .expect("runtime model-mount record-state commit protocol request");

        let response = commit_runtime_model_mount_record_state_response(request)
            .expect("model-mount record committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_record_state_commit_protocol"
        );
        assert_eq!(response["record_dir"], "provider-health");
        assert_eq!(response["record_id"], "health.provider_openai");
        assert_eq!(
            response["operation_kind"],
            "model_mount.provider_health.write"
        );
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("provider-health/health.provider_openai.json")
            .exists());
        let health_record =
            fs::read_to_string(state_dir.join("provider-health/health.provider_openai.json"))
                .expect("provider health record");
        assert!(health_record.contains("\"id\": \"health.provider_openai\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_record_state_commit"));
    }

    #[test]
    fn agentgres_protocol_commits_runtime_model_mount_receipt_state_through_rust_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("runtime-state");
        let request: RuntimeModelMountReceiptStateCommitProtocolRequest =
            serde_json::from_value(json!({
                "state_dir": state_dir,
                "request": {
                    "schema_version": "ioi.runtime_model_mount_receipt_state_commit.v1",
                    "receipt_id": "receipt_model_invocation",
                    "operation_kind": "model_mount.receipt.write",
                    "storage_backend_ref": "storage://runtime-agentgres/local-json",
                    "receipt": {
                        "id": "receipt_model_invocation",
                        "kind": "model_invocation",
                        "redaction": "redacted",
                        "evidenceRefs": ["rust_receipt_binder_core", "rust_agentgres_admission"],
                        "details": {
                            "model_mount_receipt_binding_ref": "sha256:binding",
                            "model_mount_accepted_receipt_append_hash": "sha256:append",
                            "model_mount_agentgres_operation_ref": "agentgres://model-mounting/accepted-receipts/op_1",
                            "model_mount_agentgres_admission_hash": "sha256:agentgres"
                        }
                    }
                }
            }))
            .expect("runtime model-mount receipt-state commit protocol request");

        let response = commit_runtime_model_mount_receipt_state_response(request)
            .expect("model-mount receipt committed");

        assert_eq!(
            response["source"],
            "rust_agentgres_runtime_model_mount_receipt_state_commit_protocol"
        );
        assert_eq!(response["receipt_id"], "receipt_model_invocation");
        assert_eq!(response["operation_kind"], "model_mount.receipt.write");
        assert!(response["commit_hash"]
            .as_str()
            .expect("commit hash")
            .starts_with("sha256:"));
        assert!(state_dir
            .join("receipts/receipt_model_invocation.json")
            .exists());
        let receipt_record =
            fs::read_to_string(state_dir.join("receipts/receipt_model_invocation.json"))
                .expect("model-mount receipt record");
        assert!(receipt_record.contains("\"id\": \"receipt_model_invocation\""));
        assert_eq!(
            response["written_record"]["object_ref"],
            "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json"
        );
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_agentgres_runtime_model_mount_receipt_state_commit"));
    }
}
