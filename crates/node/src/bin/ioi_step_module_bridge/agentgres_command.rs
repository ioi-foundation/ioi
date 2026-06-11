use ioi_services::agentic::runtime::kernel::agentgres_admission::{
    AgentgresAdmissionCore, RuntimeAgentStateCommitRequest, RuntimeArtifactStateCommitRequest,
    RuntimeMemoryStateCommitRequest, RuntimeModelMountReceiptStateCommitRequest,
    RuntimeModelMountRecordStateCommitRequest, RuntimeRunStateCommitRequest,
    RuntimeStatePersistenceRecord, RuntimeStateStorageWriteRecord,
    RuntimeSubagentStateCommitRequest, StorageBackendWriteProposal,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{BridgeError, DAEMON_CORE_COMMAND_SCHEMA_VERSION};

#[derive(Debug, Deserialize)]
pub(super) struct StorageBackendWriteBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    request: StorageBackendWriteProposal,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeRunStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeRunStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeAgentStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeAgentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeMemoryStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeMemoryStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeSubagentStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeSubagentStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeArtifactStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeArtifactStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeModelMountRecordStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountRecordStateCommitRequest,
}

#[derive(Debug, Deserialize)]
pub(super) struct RuntimeModelMountReceiptStateCommitBridgeRequest {
    #[serde(rename = "schema_version")]
    schema_version: String,
    operation: String,
    #[serde(default)]
    backend: Option<String>,
    state_dir: String,
    request: RuntimeModelMountReceiptStateCommitRequest,
}

pub(super) fn admit_storage_backend_write(
    request: StorageBackendWriteBridgeRequest,
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
    if request.operation != "admit_storage_backend_write" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_run_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let state_root = ensure_runtime_state_dir(&request.state_dir)?;
    let mut commit_request = request.request;
    if commit_request.previous_transition.is_none() {
        commit_request.previous_transition =
            read_runtime_state_previous_transition(&state_root, &commit_request.run_id)?;
    }
    if commit_request.projection_watermark.is_none() {
        commit_request.projection_watermark = Some(runtime_state_projection_watermark(
            &state_root,
            &commit_request.run_id,
        )?);
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_run_state(&commit_request)
        .map_err(|error| {
            BridgeError::new("runtime_run_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_records =
        write_runtime_state_persistence_records(&request.state_dir, &record.persistence)?;
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
        "written_records": written_records,
        "evidence_refs": [
            "rust_agentgres_runtime_run_state_commit",
            record.commit_hash,
        ],
    }))
}

pub(super) fn commit_runtime_agent_state(
    request: RuntimeAgentStateCommitBridgeRequest,
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
    if request.operation != "commit_runtime_agent_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_agent_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_agent_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.agent,
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_memory_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_memory_state(&request.request)
        .map_err(|error| {
            BridgeError::new("runtime_memory_state_commit_invalid", format!("{error:?}"))
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.payload,
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_subagent_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_subagent_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_subagent_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.subagent,
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_artifact_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_artifact_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_artifact_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.artifact,
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_model_mount_record_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_record_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_record_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.record,
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
    if request.schema_version != DAEMON_CORE_COMMAND_SCHEMA_VERSION {
        return Err(BridgeError::new(
            "schema_version_invalid",
            format!(
                "expected {} but received {}",
                DAEMON_CORE_COMMAND_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.operation != "commit_runtime_model_mount_receipt_state" {
        return Err(BridgeError::new(
            "operation_unsupported",
            format!("unsupported operation {}", request.operation),
        ));
    }
    let record = AgentgresAdmissionCore
        .commit_runtime_model_mount_receipt_state(&request.request)
        .map_err(|error| {
            BridgeError::new(
                "runtime_model_mount_receipt_state_commit_invalid",
                format!("{error:?}"),
            )
        })?;
    let written_record = write_runtime_state_storage_record(
        &request.state_dir,
        &record.record,
        &request.request.receipt,
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

fn write_runtime_state_persistence_records(
    state_dir: &str,
    record: &RuntimeStatePersistenceRecord,
) -> Result<Vec<Value>, BridgeError> {
    let state_root = ensure_runtime_state_dir(state_dir)?;
    let mut written_records = Vec::with_capacity(record.materialization.records.len());
    for materialized in &record.materialization.records {
        let planned = record
            .storage_write_set
            .records
            .iter()
            .find(|entry| entry.record_path == materialized.record_path)
            .ok_or_else(|| {
                BridgeError::new(
                    "runtime_state_storage_plan_missing_record",
                    format!(
                        "storage write set is missing record {}",
                        materialized.record_path
                    ),
                )
            })?;
        let target = runtime_state_record_path(&state_root, &materialized.record_path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                BridgeError::new("runtime_state_record_dir_create_failed", error.to_string())
            })?;
        }
        let payload = serde_json::to_string_pretty(&materialized.payload).map_err(|error| {
            BridgeError::new("runtime_state_record_json_failed", error.to_string())
        })?;
        let file_content = format!("{payload}\n");
        fs::write(&target, file_content.as_bytes()).map_err(|error| {
            BridgeError::new("runtime_state_record_write_failed", error.to_string())
        })?;
        written_records.push(json!({
            "record_path": materialized.record_path,
            "absolute_path": target.to_string_lossy(),
            "object_ref": planned.object_ref,
            "content_hash": planned.content_hash,
            "payload_refs": planned.payload_refs,
            "receipt_refs": planned.receipt_refs,
            "admission_hash": planned.admission.admission_hash,
        }));
    }
    Ok(written_records)
}

fn write_runtime_state_storage_record(
    state_dir: &str,
    record: &RuntimeStateStorageWriteRecord,
    payload: &Value,
) -> Result<Value, BridgeError> {
    let state_root = ensure_runtime_state_dir(state_dir)?;
    let target = runtime_state_record_path(&state_root, &record.record_path)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            BridgeError::new("runtime_state_record_dir_create_failed", error.to_string())
        })?;
    }
    let payload = serde_json::to_string_pretty(payload)
        .map_err(|error| BridgeError::new("runtime_state_record_json_failed", error.to_string()))?;
    let file_content = format!("{payload}\n");
    fs::write(&target, file_content.as_bytes()).map_err(|error| {
        BridgeError::new("runtime_state_record_write_failed", error.to_string())
    })?;
    Ok(json!({
        "record_path": record.record_path,
        "absolute_path": target.to_string_lossy(),
        "object_ref": record.object_ref,
        "content_hash": record.content_hash,
        "payload_refs": record.payload_refs,
        "receipt_refs": record.receipt_refs,
        "admission_hash": record.admission.admission_hash,
    }))
}

fn ensure_runtime_state_dir(state_dir: &str) -> Result<PathBuf, BridgeError> {
    let state_root_input = Path::new(state_dir);
    fs::create_dir_all(state_root_input)
        .map_err(|error| BridgeError::new("runtime_state_dir_create_failed", error.to_string()))?;
    fs::canonicalize(state_root_input)
        .map_err(|error| BridgeError::new("runtime_state_dir_invalid", error.to_string()))
}

fn read_runtime_state_previous_transition(
    state_root: &Path,
    run_id: &str,
) -> Result<Option<Value>, BridgeError> {
    let task_path = runtime_state_record_path(state_root, &format!("tasks/{run_id}.json"))?;
    if !task_path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&task_path).map_err(|error| {
        BridgeError::new(
            "runtime_state_previous_transition_read_failed",
            error.to_string(),
        )
    })?;
    let task_record: Value = serde_json::from_str(&content).map_err(|error| {
        BridgeError::new(
            "runtime_state_previous_transition_json_invalid",
            error.to_string(),
        )
    })?;
    match task_record.get("agentgresTransition") {
        Some(value) if value.is_object() => Ok(Some(value.clone())),
        _ => Ok(None),
    }
}

fn runtime_state_projection_watermark(
    state_root: &Path,
    run_id: &str,
) -> Result<String, BridgeError> {
    let runs_dir = state_root.join("runs");
    let mut run_count = 0usize;
    if runs_dir.exists() {
        for entry in fs::read_dir(&runs_dir).map_err(|error| {
            BridgeError::new("runtime_state_runs_dir_read_failed", error.to_string())
        })? {
            let entry = entry.map_err(|error| {
                BridgeError::new("runtime_state_runs_dir_entry_failed", error.to_string())
            })?;
            if entry
                .file_type()
                .map_err(|error| {
                    BridgeError::new("runtime_state_runs_dir_entry_failed", error.to_string())
                })?
                .is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            {
                run_count += 1;
            }
        }
    }
    let watermark = run_count.max(if run_id.trim().is_empty() { 0 } else { 1 });
    Ok(format!("runtime-state:{watermark}"))
}

fn runtime_state_record_path(root: &Path, record_path: &str) -> Result<PathBuf, BridgeError> {
    if record_path.trim().is_empty() {
        return Err(BridgeError::new(
            "runtime_state_record_path_invalid",
            "runtime state record path is required".to_string(),
        ));
    }
    let mut target = root.to_path_buf();
    let mut saw_component = false;
    for component in Path::new(record_path).components() {
        match component {
            Component::Normal(segment) => {
                target.push(segment);
                saw_component = true;
            }
            Component::CurDir => {}
            _ => {
                return Err(BridgeError::new(
                    "runtime_state_record_path_invalid",
                    format!("runtime state record path cannot escape state dir: {record_path}"),
                ));
            }
        }
    }
    if !saw_component || !target.starts_with(root) {
        return Err(BridgeError::new(
            "runtime_state_record_path_invalid",
            format!("runtime state record path cannot escape state dir: {record_path}"),
        ));
    }
    Ok(target)
}
