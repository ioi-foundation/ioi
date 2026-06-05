use super::receipt_binder::StepModuleReceiptBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const AGENTGRES_ADMISSION_SCHEMA_VERSION: &str = "ioi.agentgres_admission.v1";
pub const STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.storage_backend_write_admission.v1";
pub const RUNTIME_STATE_TRANSITION_SCHEMA_VERSION: &str =
    "ioi.agentgres_runtime_state_transition.v1";
pub const RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION: &str =
    "ioi.runtime_state_storage_write_set.v1";
pub const AGENTGRES_OPERATION_EXPECTED_HEADS_NEGATIVE_CONFORMANCE: &str =
    "Agentgres operation append without expected heads/state-root binding fails";
pub const STORAGE_BACKEND_WRITE_AGENTGRES_REF_NEGATIVE_CONFORMANCE: &str =
    "storage backend write without Agentgres ArtifactRef/PayloadRef fails";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentgresAdmissionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingExpectedHeads,
    MissingStateRootBefore,
    MissingStateRootAfter,
    MissingResultingHead,
    MissingReceiptBinding,
    ReceiptBindingInvocationMismatch,
    ReceiptBindingHashMismatch,
    ReceiptBindingExpectedHeadsMismatch,
    ReceiptBindingStateRootMismatch,
    ReceiptBindingReceiptRefsMismatch,
    ReceiptBindingArtifactRefsMismatch,
    ReceiptBindingPayloadRefsMismatch,
    MissingReceiptRefs,
    StorageBackendWriteMissingAgentgresRef,
    StorageBackendWriteMissingReceipt,
    MissingStorageWriteRecords,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentgresOperationProposal {
    pub schema_version: String,
    pub operation_ref: String,
    pub invocation_id: String,
    pub receipt_binding_ref: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default)]
    pub expected_heads: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_head: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentgresAdmissionRecord {
    pub schema_version: String,
    pub operation_ref: String,
    pub invocation_id: String,
    pub receipt_binding_ref: String,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_watermark: Option<String>,
    pub admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackendWriteProposal {
    pub schema_version: String,
    pub storage_backend_ref: String,
    pub object_ref: String,
    pub content_hash: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBackendWriteAdmissionRecord {
    pub schema_version: String,
    pub storage_backend_ref: String,
    pub object_ref: String,
    pub content_hash: String,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub admission_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateTransitionRequest {
    pub schema_version: String,
    pub run_id: String,
    pub operation_kind: String,
    #[serde(default)]
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub run_state_hash: String,
    pub task_state_hash: String,
    pub projection_ref: String,
    pub projection_watermark: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateTransitionRecord {
    pub schema_version: String,
    pub run_id: String,
    pub operation_kind: String,
    pub operation_ref: String,
    pub expected_heads: Vec<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub resulting_head: String,
    pub run_state_hash: String,
    pub task_state_hash: String,
    pub projection_ref: String,
    pub projection_watermark: String,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub transition_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStateStorageWriteSetRequest {
    pub schema_version: String,
    pub run_id: String,
    pub storage_backend_ref: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub records: Vec<RuntimeStateStorageWriteInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStateStorageWriteInput {
    pub record_path: String,
    pub payload: Value,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateStorageWriteSetRecord {
    pub schema_version: String,
    pub run_id: String,
    pub storage_backend_ref: String,
    pub receipt_refs: Vec<String>,
    pub records: Vec<RuntimeStateStorageWriteRecord>,
    pub write_set_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateStorageWriteRecord {
    pub record_path: String,
    pub object_ref: String,
    pub content_hash: String,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub admission: StorageBackendWriteAdmissionRecord,
}

#[derive(Debug, Default, Clone)]
pub struct AgentgresAdmissionCore;

impl AgentgresAdmissionCore {
    pub fn admit(
        &self,
        proposal: &AgentgresOperationProposal,
        binding: &StepModuleReceiptBinding,
    ) -> Result<AgentgresAdmissionRecord, AgentgresAdmissionError> {
        proposal.validate()?;
        validate_against_binding(proposal, binding)?;

        let mut record = AgentgresAdmissionRecord {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: proposal.operation_ref.clone(),
            invocation_id: proposal.invocation_id.clone(),
            receipt_binding_ref: proposal.receipt_binding_ref.clone(),
            receipt_refs: proposal.receipt_refs.clone(),
            artifact_refs: proposal.artifact_refs.clone(),
            payload_refs: proposal.payload_refs.clone(),
            expected_heads: proposal.expected_heads.clone(),
            state_root_before: proposal
                .state_root_before
                .clone()
                .expect("validated state_root_before"),
            state_root_after: proposal
                .state_root_after
                .clone()
                .expect("validated state_root_after"),
            resulting_head: proposal
                .resulting_head
                .clone()
                .expect("validated resulting_head"),
            projection_watermark: binding.projection_watermark.clone(),
            admission_hash: String::new(),
        };
        record.admission_hash = admission_hash(&record)?;
        Ok(record)
    }

    pub fn admit_storage_backend_write(
        &self,
        proposal: &StorageBackendWriteProposal,
    ) -> Result<StorageBackendWriteAdmissionRecord, AgentgresAdmissionError> {
        proposal.validate()?;

        let mut record = StorageBackendWriteAdmissionRecord {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: proposal.storage_backend_ref.clone(),
            object_ref: proposal.object_ref.clone(),
            content_hash: proposal.content_hash.clone(),
            artifact_refs: proposal.artifact_refs.clone(),
            payload_refs: proposal.payload_refs.clone(),
            receipt_refs: proposal.receipt_refs.clone(),
            admission_hash: String::new(),
        };
        record.admission_hash = storage_write_admission_hash(&record)?;
        Ok(record)
    }

    pub fn plan_runtime_state_transition(
        &self,
        request: &RuntimeStateTransitionRequest,
    ) -> Result<RuntimeStateTransitionRecord, AgentgresAdmissionError> {
        request.validate()?;
        let state_root_after = runtime_state_root_after(request)?;
        let head_suffix = state_root_after
            .trim_start_matches("sha256:")
            .chars()
            .take(24)
            .collect::<String>();
        let operation_ref = format!(
            "agentgres://runtime-state/runs/{}/operations/{}_{}",
            safe_agentgres_component(&request.run_id),
            safe_agentgres_component(&request.operation_kind),
            head_suffix,
        );
        let resulting_head = format!(
            "agentgres://runtime-state/runs/{}/head/{}",
            safe_agentgres_component(&request.run_id),
            head_suffix,
        );
        let mut record = RuntimeStateTransitionRecord {
            schema_version: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            operation_kind: request.operation_kind.clone(),
            operation_ref,
            expected_heads: request.expected_heads.clone(),
            state_root_before: request.state_root_before.clone(),
            state_root_after,
            resulting_head,
            run_state_hash: request.run_state_hash.clone(),
            task_state_hash: request.task_state_hash.clone(),
            projection_ref: request.projection_ref.clone(),
            projection_watermark: request.projection_watermark.clone(),
            receipt_refs: request.receipt_refs.clone(),
            artifact_refs: request.artifact_refs.clone(),
            payload_refs: request.payload_refs.clone(),
            transition_hash: String::new(),
        };
        record.transition_hash = runtime_state_transition_hash(&record)?;
        Ok(record)
    }

    pub fn plan_runtime_state_storage_writes(
        &self,
        request: &RuntimeStateStorageWriteSetRequest,
    ) -> Result<RuntimeStateStorageWriteSetRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_run_id = safe_agentgres_component(&request.run_id);
        let mut records = Vec::with_capacity(request.records.len());
        for input in &request.records {
            let safe_record_path = safe_agentgres_path(&input.record_path);
            let payload_refs = if input.payload_refs.is_empty() {
                vec![format!(
                    "payload://runtime/runs/{safe_run_id}/records/{safe_record_path}"
                )]
            } else {
                input.payload_refs.clone()
            };
            let proposal = StorageBackendWriteProposal {
                schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
                storage_backend_ref: request.storage_backend_ref.clone(),
                object_ref: format!(
                    "agentgres://runtime-state/runs/{safe_run_id}/records/{safe_record_path}"
                ),
                content_hash: runtime_state_payload_hash(&input.payload)?,
                artifact_refs: input.artifact_refs.clone(),
                payload_refs,
                receipt_refs: request.receipt_refs.clone(),
            };
            let admission = self.admit_storage_backend_write(&proposal)?;
            records.push(RuntimeStateStorageWriteRecord {
                record_path: input.record_path.clone(),
                object_ref: proposal.object_ref,
                content_hash: proposal.content_hash,
                artifact_refs: proposal.artifact_refs,
                payload_refs: proposal.payload_refs,
                receipt_refs: proposal.receipt_refs,
                admission,
            });
        }
        let mut record = RuntimeStateStorageWriteSetRecord {
            schema_version: RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            receipt_refs: request.receipt_refs.clone(),
            records,
            write_set_hash: String::new(),
        };
        record.write_set_hash = runtime_state_storage_write_set_hash(&record)?;
        Ok(record)
    }
}

impl AgentgresOperationProposal {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != AGENTGRES_ADMISSION_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: AGENTGRES_ADMISSION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_ref", &self.operation_ref)?;
        require_non_empty("invocation_id", &self.invocation_id)?;
        require_non_empty("receipt_binding_ref", &self.receipt_binding_ref)?;
        if self.receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptBinding);
        }
        if self.expected_heads.is_empty() {
            return Err(AgentgresAdmissionError::MissingExpectedHeads);
        }
        require_present("state_root_before", &self.state_root_before)
            .map_err(|_| AgentgresAdmissionError::MissingStateRootBefore)?;
        require_present("state_root_after", &self.state_root_after)
            .map_err(|_| AgentgresAdmissionError::MissingStateRootAfter)?;
        require_present("resulting_head", &self.resulting_head)
            .map_err(|_| AgentgresAdmissionError::MissingResultingHead)?;
        Ok(())
    }
}

impl StorageBackendWriteProposal {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        require_non_empty("object_ref", &self.object_ref)?;
        require_non_empty("content_hash", &self.content_hash)?;
        if self.artifact_refs.is_empty() && self.payload_refs.is_empty() {
            return Err(AgentgresAdmissionError::StorageBackendWriteMissingAgentgresRef);
        }
        if self.receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::StorageBackendWriteMissingReceipt);
        }
        Ok(())
    }
}

impl RuntimeStateTransitionRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_STATE_TRANSITION_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("run_id", &self.run_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("state_root_before", &self.state_root_before)
            .map_err(|_| AgentgresAdmissionError::MissingStateRootBefore)?;
        require_non_empty("run_state_hash", &self.run_state_hash)?;
        require_non_empty("task_state_hash", &self.task_state_hash)?;
        require_non_empty("projection_ref", &self.projection_ref)?;
        require_non_empty("projection_watermark", &self.projection_watermark)?;
        if self.expected_heads.is_empty() {
            return Err(AgentgresAdmissionError::MissingExpectedHeads);
        }
        if self.receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        Ok(())
    }
}

impl RuntimeStateStorageWriteSetRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("run_id", &self.run_id)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        if self.receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        if self.records.is_empty() {
            return Err(AgentgresAdmissionError::MissingStorageWriteRecords);
        }
        for record in &self.records {
            require_non_empty("record_path", &record.record_path)?;
        }
        Ok(())
    }
}

fn validate_against_binding(
    proposal: &AgentgresOperationProposal,
    binding: &StepModuleReceiptBinding,
) -> Result<(), AgentgresAdmissionError> {
    if proposal.invocation_id != binding.invocation_id {
        return Err(AgentgresAdmissionError::ReceiptBindingInvocationMismatch);
    }
    if proposal.receipt_binding_ref != binding.binding_hash {
        return Err(AgentgresAdmissionError::ReceiptBindingHashMismatch);
    }
    if proposal.expected_heads != binding.expected_heads {
        return Err(AgentgresAdmissionError::ReceiptBindingExpectedHeadsMismatch);
    }
    if proposal.state_root_before != binding.state_root_before
        || proposal.state_root_after != binding.state_root_after
        || proposal.resulting_head != binding.resulting_head
    {
        return Err(AgentgresAdmissionError::ReceiptBindingStateRootMismatch);
    }
    if proposal.receipt_refs != binding.receipt_refs {
        return Err(AgentgresAdmissionError::ReceiptBindingReceiptRefsMismatch);
    }
    if proposal.artifact_refs != binding.artifact_refs {
        return Err(AgentgresAdmissionError::ReceiptBindingArtifactRefsMismatch);
    }
    if proposal.payload_refs != binding.payload_refs {
        return Err(AgentgresAdmissionError::ReceiptBindingPayloadRefsMismatch);
    }
    Ok(())
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), AgentgresAdmissionError> {
    if value.trim().is_empty() {
        Err(AgentgresAdmissionError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_present(field: &'static str, value: &Option<String>) -> Result<(), &'static str> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(field),
    }
}

fn admission_hash(record: &AgentgresAdmissionRecord) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.admission_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn storage_write_admission_hash(
    record: &StorageBackendWriteAdmissionRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.admission_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_state_root_after(
    request: &RuntimeStateTransitionRequest,
) -> Result<String, AgentgresAdmissionError> {
    let canonical = serde_json::json!({
        "schema_version": RUNTIME_STATE_TRANSITION_SCHEMA_VERSION,
        "run_id": &request.run_id,
        "operation_kind": &request.operation_kind,
        "expected_heads": &request.expected_heads,
        "state_root_before": &request.state_root_before,
        "run_state_hash": &request.run_state_hash,
        "task_state_hash": &request.task_state_hash,
        "projection_ref": &request.projection_ref,
        "projection_watermark": &request.projection_watermark,
        "receipt_refs": &request.receipt_refs,
        "artifact_refs": &request.artifact_refs,
        "payload_refs": &request.payload_refs,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_state_transition_hash(
    record: &RuntimeStateTransitionRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.transition_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_state_payload_hash(payload: &Value) -> Result<String, AgentgresAdmissionError> {
    let canonical = stable_json_value(payload)?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    ))
}

fn runtime_state_storage_write_set_hash(
    record: &RuntimeStateStorageWriteSetRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.write_set_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn stable_json_value(value: &Value) -> Result<String, AgentgresAdmissionError> {
    match value {
        Value::Array(entries) => Ok(format!(
            "[{}]",
            entries
                .iter()
                .map(stable_json_value)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut entries = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = serde_json::to_string(key)
                    .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
                let value_json = stable_json_value(&map[key])?;
                entries.push(format!("{key_json}:{value_json}"));
            }
            Ok(format!("{{{}}}", entries.join(",")))
        }
        _ => serde_json::to_string(value)
            .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string())),
    }
}

fn safe_agentgres_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "runtime".to_string()
    } else {
        safe
    }
}

fn safe_agentgres_path(value: &str) -> String {
    value
        .split('/')
        .map(safe_agentgres_component)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> StepModuleReceiptBinding {
        StepModuleReceiptBinding {
            schema_version: "ioi.step_module_receipt_binding.v1".to_string(),
            invocation_id: "invocation://agentgres-admission-test".to_string(),
            receipt_refs: vec!["receipt://step-module/test".to_string()],
            artifact_refs: vec!["artifact://agentgres/test".to_string()],
            payload_refs: vec!["payload://agentgres/test".to_string()],
            agentgres_operation_refs: vec!["agentgres://operation/test".to_string()],
            expected_heads: vec!["sha256:head-before".to_string()],
            state_root_before: Some("sha256:state-before".to_string()),
            state_root_after: Some("sha256:state-after".to_string()),
            resulting_head: Some("sha256:head-after".to_string()),
            projection_watermark: Some("agentgres:watermark:7".to_string()),
            binding_hash: "sha256:receipt-binding".to_string(),
        }
    }

    fn proposal() -> AgentgresOperationProposal {
        AgentgresOperationProposal {
            schema_version: AGENTGRES_ADMISSION_SCHEMA_VERSION.to_string(),
            operation_ref: "agentgres://operation/test".to_string(),
            invocation_id: "invocation://agentgres-admission-test".to_string(),
            receipt_binding_ref: "sha256:receipt-binding".to_string(),
            receipt_refs: vec!["receipt://step-module/test".to_string()],
            artifact_refs: vec!["artifact://agentgres/test".to_string()],
            payload_refs: vec!["payload://agentgres/test".to_string()],
            expected_heads: vec!["sha256:head-before".to_string()],
            state_root_before: Some("sha256:state-before".to_string()),
            state_root_after: Some("sha256:state-after".to_string()),
            resulting_head: Some("sha256:head-after".to_string()),
        }
    }

    fn storage_write() -> StorageBackendWriteProposal {
        StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: "storage://local-cas/default".to_string(),
            object_ref: "cas://sha256/storage-test".to_string(),
            content_hash: "sha256:storage-test".to_string(),
            artifact_refs: vec!["artifact://agentgres/storage-test".to_string()],
            payload_refs: vec![],
            receipt_refs: vec!["receipt://storage/write".to_string()],
        }
    }

    fn runtime_state_transition() -> RuntimeStateTransitionRequest {
        RuntimeStateTransitionRequest {
            schema_version: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            operation_kind: "run.create".to_string(),
            expected_heads: vec!["agentgres://runtime-state/runs/run_1/head/0".to_string()],
            state_root_before: "sha256:runtime-state-before".to_string(),
            run_state_hash: "sha256:run-state".to_string(),
            task_state_hash: "sha256:task-state".to_string(),
            projection_ref: "projection://runtime/runs/run_1".to_string(),
            projection_watermark: "runtime-state:1".to_string(),
            receipt_refs: vec!["receipt_policy".to_string()],
            artifact_refs: vec!["artifact_1".to_string()],
            payload_refs: vec!["payload://runtime/runs/run_1".to_string()],
        }
    }

    fn runtime_state_storage_write_set() -> RuntimeStateStorageWriteSetRequest {
        RuntimeStateStorageWriteSetRequest {
            schema_version: RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            receipt_refs: vec!["receipt_policy".to_string()],
            records: vec![
                RuntimeStateStorageWriteInput {
                    record_path: "runs/run_1.json".to_string(),
                    payload: json!({
                        "id": "run_1",
                        "status": "completed",
                    }),
                    artifact_refs: vec![],
                    payload_refs: vec![],
                },
                RuntimeStateStorageWriteInput {
                    record_path: "tasks/run_1.json".to_string(),
                    payload: json!({
                        "runId": "run_1",
                        "taskState": {
                            "state": "done"
                        },
                    }),
                    artifact_refs: vec![],
                    payload_refs: vec![],
                },
            ],
        }
    }

    #[test]
    fn admits_receipt_bound_agentgres_operation() {
        let record = AgentgresAdmissionCore
            .admit(&proposal(), &binding())
            .expect("admitted operation");

        assert_eq!(record.schema_version, AGENTGRES_ADMISSION_SCHEMA_VERSION);
        assert_eq!(record.expected_heads, vec!["sha256:head-before"]);
        assert_eq!(record.state_root_before, "sha256:state-before");
        assert_eq!(record.state_root_after, "sha256:state-after");
        assert_eq!(record.resulting_head, "sha256:head-after");
        assert_eq!(
            record.projection_watermark.as_deref(),
            Some("agentgres:watermark:7")
        );
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn agentgres_operation_append_without_expected_heads_state_root_binding_fails() {
        assert_eq!(
            AGENTGRES_OPERATION_EXPECTED_HEADS_NEGATIVE_CONFORMANCE,
            "Agentgres operation append without expected heads/state-root binding fails"
        );

        let mut proposal = proposal();
        proposal.expected_heads.clear();
        let error = AgentgresAdmissionCore
            .admit(&proposal, &binding())
            .expect_err("expected heads are required");

        assert_eq!(error, AgentgresAdmissionError::MissingExpectedHeads);
    }

    #[test]
    fn rejects_missing_state_roots() {
        let mut proposal = proposal();
        proposal.state_root_after = None;
        let error = AgentgresAdmissionCore
            .admit(&proposal, &binding())
            .expect_err("state root after is required");

        assert_eq!(error, AgentgresAdmissionError::MissingStateRootAfter);

        proposal.state_root_after = Some("sha256:state-after".to_string());
        proposal.state_root_before = None;
        let error = AgentgresAdmissionCore
            .admit(&proposal, &binding())
            .expect_err("state root before is required");

        assert_eq!(error, AgentgresAdmissionError::MissingStateRootBefore);
    }

    #[test]
    fn rejects_missing_receipt_binding() {
        let mut proposal = proposal();
        proposal.receipt_binding_ref.clear();
        let error = AgentgresAdmissionCore
            .admit(&proposal, &binding())
            .expect_err("receipt binding is required");

        assert_eq!(
            error,
            AgentgresAdmissionError::MissingField("receipt_binding_ref")
        );
    }

    #[test]
    fn rejects_binding_drift() {
        let mut proposal = proposal();
        proposal.resulting_head = Some("sha256:drifted-head".to_string());
        let error = AgentgresAdmissionCore
            .admit(&proposal, &binding())
            .expect_err("proposal must match receipt binding");

        assert_eq!(
            error,
            AgentgresAdmissionError::ReceiptBindingStateRootMismatch
        );
    }

    #[test]
    fn admits_storage_backend_write_with_agentgres_refs() {
        let record = AgentgresAdmissionCore
            .admit_storage_backend_write(&storage_write())
            .expect("storage write admission");

        assert_eq!(
            record.schema_version,
            STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(
            record.artifact_refs,
            vec!["artifact://agentgres/storage-test"]
        );
        assert!(record.payload_refs.is_empty());
        assert!(record.admission_hash.starts_with("sha256:"));
    }

    #[test]
    fn storage_backend_write_without_agentgres_artifactref_payloadref_fails() {
        assert_eq!(
            STORAGE_BACKEND_WRITE_AGENTGRES_REF_NEGATIVE_CONFORMANCE,
            "storage backend write without Agentgres ArtifactRef/PayloadRef fails"
        );

        let mut proposal = storage_write();
        proposal.artifact_refs.clear();
        proposal.payload_refs.clear();
        let error = AgentgresAdmissionCore
            .admit_storage_backend_write(&proposal)
            .expect_err("Agentgres ArtifactRef or PayloadRef is required");

        assert_eq!(
            error,
            AgentgresAdmissionError::StorageBackendWriteMissingAgentgresRef
        );
    }

    #[test]
    fn storage_backend_write_requires_receipt() {
        let mut proposal = storage_write();
        proposal.receipt_refs.clear();
        let error = AgentgresAdmissionCore
            .admit_storage_backend_write(&proposal)
            .expect_err("receipt binding is required");

        assert_eq!(
            error,
            AgentgresAdmissionError::StorageBackendWriteMissingReceipt
        );
    }

    #[test]
    fn plans_runtime_state_transition_with_expected_head_and_state_roots() {
        let record = AgentgresAdmissionCore
            .plan_runtime_state_transition(&runtime_state_transition())
            .expect("runtime transition planned");

        assert_eq!(
            record.schema_version,
            RUNTIME_STATE_TRANSITION_SCHEMA_VERSION
        );
        assert_eq!(
            record.expected_heads,
            vec!["agentgres://runtime-state/runs/run_1/head/0"]
        );
        assert_eq!(record.state_root_before, "sha256:runtime-state-before");
        assert_eq!(record.projection_watermark, "runtime-state:1");
        assert!(record.state_root_after.starts_with("sha256:"));
        assert!(record
            .resulting_head
            .starts_with("agentgres://runtime-state/runs/run_1/head/"));
        assert!(record.operation_ref.contains("/operations/run.create_"));
        assert!(record.transition_hash.starts_with("sha256:"));
    }

    #[test]
    fn runtime_state_transition_requires_expected_heads_state_root_and_receipts() {
        let mut request = runtime_state_transition();
        request.expected_heads.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_transition(&request)
            .expect_err("expected heads are required");
        assert_eq!(error, AgentgresAdmissionError::MissingExpectedHeads);

        request = runtime_state_transition();
        request.state_root_before.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_transition(&request)
            .expect_err("state root before is required");
        assert_eq!(error, AgentgresAdmissionError::MissingStateRootBefore);

        request = runtime_state_transition();
        request.receipt_refs.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_transition(&request)
            .expect_err("receipt refs are required");
        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn plans_runtime_state_storage_write_set_with_rust_content_hash_and_admissions() {
        let record = AgentgresAdmissionCore
            .plan_runtime_state_storage_writes(&runtime_state_storage_write_set())
            .expect("runtime storage writes planned");

        assert_eq!(
            record.schema_version,
            RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION
        );
        assert_eq!(record.run_id, "run_1");
        assert_eq!(record.records.len(), 2);
        assert!(record.write_set_hash.starts_with("sha256:"));
        assert_eq!(record.records[0].record_path, "runs/run_1.json");
        assert_eq!(
            record.records[0].object_ref,
            "agentgres://runtime-state/runs/run_1/records/runs/run_1.json"
        );
        assert_eq!(
            record.records[0].payload_refs,
            vec!["payload://runtime/runs/run_1/records/runs/run_1.json"]
        );
        assert!(record.records[0].content_hash.starts_with("sha256:"));
        assert_eq!(
            record.records[0].content_hash,
            record.records[0].admission.content_hash
        );
        assert!(record.records[0]
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_state_storage_write_set_requires_receipts_and_records() {
        let mut request = runtime_state_storage_write_set();
        request.receipt_refs.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_storage_writes(&request)
            .expect_err("receipt refs are required");
        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);

        request = runtime_state_storage_write_set();
        request.records.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_storage_writes(&request)
            .expect_err("records are required");
        assert_eq!(error, AgentgresAdmissionError::MissingStorageWriteRecords);
    }
}
