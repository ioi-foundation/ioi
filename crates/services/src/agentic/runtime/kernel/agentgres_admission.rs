use super::receipt_binder::StepModuleReceiptBinding;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const AGENTGRES_ADMISSION_SCHEMA_VERSION: &str = "ioi.agentgres_admission.v1";
pub const STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.storage_backend_write_admission.v1";
pub const RUNTIME_STATE_TRANSITION_SCHEMA_VERSION: &str =
    "ioi.agentgres_runtime_state_transition.v1";
pub const RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION: &str =
    "ioi.runtime_state_storage_write_set.v1";
pub const RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION: &str =
    "ioi.runtime_state_record_materialization.v1";
pub const RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION: &str = "ioi.runtime_state_persistence.v1";
pub const RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION: &str = "ioi.runtime_run_state_commit.v1";
pub const RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION: &str = "ioi.runtime_agent_state_commit.v1";
pub const RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION: &str = "ioi.runtime_memory_state_commit.v1";
pub const RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION: &str =
    "ioi.runtime_subagent_state_commit.v1";
pub const RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION: &str =
    "ioi.runtime_artifact_state_commit.v1";
pub const RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION: &str =
    "ioi.runtime_model_mount_record_state_commit.v1";
pub const RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION: &str =
    "ioi.runtime_model_mount_receipt_state_commit.v1";
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
    RuntimeStateRecordRunIdMismatch,
    RuntimeStateRecordAgentIdMismatch,
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
    pub run: Value,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStateRecordMaterializationRequest {
    pub schema_version: String,
    pub run_id: String,
    pub run: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub canonical_projection: Value,
    pub agentgres_transition: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStateRecordMaterializationRecord {
    pub schema_version: String,
    pub run_id: String,
    pub records: Vec<RuntimeStateStorageWriteInput>,
    pub materialization_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatePersistenceRequest {
    pub schema_version: String,
    pub run_id: String,
    pub storage_backend_ref: String,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    pub run: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub canonical_projection: Value,
    pub agentgres_transition: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatePersistenceRecord {
    pub schema_version: String,
    pub run_id: String,
    pub materialization: RuntimeStateRecordMaterializationRecord,
    pub storage_write_set: RuntimeStateStorageWriteSetRecord,
    pub persistence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRunStateCommitRequest {
    pub schema_version: String,
    pub run_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub run: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Value>,
    pub canonical_projection: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_transition: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_watermark: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeRunStateCommitRecord {
    pub schema_version: String,
    pub run_id: String,
    pub transition: RuntimeStateTransitionRecord,
    pub persistence: RuntimeStatePersistenceRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAgentStateCommitRequest {
    pub schema_version: String,
    pub agent_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub agent: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAgentStateCommitRecord {
    pub schema_version: String,
    pub agent_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMemoryStateCommitRequest {
    pub schema_version: String,
    pub memory_state_kind: String,
    pub state_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub payload: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeMemoryStateCommitRecord {
    pub schema_version: String,
    pub memory_state_kind: String,
    pub state_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSubagentStateCommitRequest {
    pub schema_version: String,
    pub subagent_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub subagent: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSubagentStateCommitRecord {
    pub schema_version: String,
    pub subagent_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeArtifactStateCommitRequest {
    pub schema_version: String,
    pub artifact_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub artifact: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeArtifactStateCommitRecord {
    pub schema_version: String,
    pub artifact_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModelMountRecordStateCommitRequest {
    pub schema_version: String,
    pub record_dir: String,
    pub record_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModelMountRecordStateCommitRecord {
    pub schema_version: String,
    pub record_dir: String,
    pub record_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModelMountReceiptStateCommitRequest {
    pub schema_version: String,
    pub receipt_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub receipt: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeModelMountReceiptStateCommitRecord {
    pub schema_version: String,
    pub receipt_id: String,
    pub operation_kind: String,
    pub storage_backend_ref: String,
    pub record: RuntimeStateStorageWriteRecord,
    pub commit_hash: String,
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
        let run_state_hash = runtime_run_state_hash(&request.run)?;
        let task_state_hash = runtime_task_state_hash(&request.run)?;
        let state_root_after =
            runtime_state_root_after(request, &run_state_hash, &task_state_hash)?;
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
            run_state_hash,
            task_state_hash,
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

    pub fn materialize_runtime_state_records(
        &self,
        request: &RuntimeStateRecordMaterializationRequest,
    ) -> Result<RuntimeStateRecordMaterializationRecord, AgentgresAdmissionError> {
        request.validate()?;
        let runtime_task = runtime_task_record_for_run(&request.run)?;
        let runtime_job = runtime_job_record_for_run(&request.run, &runtime_task)?;
        let runtime_checklist =
            runtime_checklist_record_for_run(&request.run, &runtime_task, &runtime_job)?;
        let mut records = vec![RuntimeStateStorageWriteInput {
            record_path: format!("runs/{}.json", safe_agentgres_component(&request.run_id)),
            payload: request.run.clone(),
            artifact_refs: vec![],
            payload_refs: vec![],
        }];
        if let Some(agent) = &request.agent {
            let agent_id = required_json_string(agent, "id")?;
            records.push(RuntimeStateStorageWriteInput {
                record_path: format!("agents/{}.json", safe_agentgres_component(agent_id)),
                payload: agent.clone(),
                artifact_refs: vec![],
                payload_refs: vec![],
            });
        }

        records.push(RuntimeStateStorageWriteInput {
            record_path: format!("tasks/{}.json", safe_agentgres_component(&request.run_id)),
            payload: json!({
                "runId": &request.run_id,
                "agentId": json_field(&request.run, "agentId"),
                "runtimeTask": &runtime_task,
                "runtimeChecklist": &runtime_checklist,
                "taskState": json_path(&request.run, &["trace", "taskState"]),
                "postconditions": json_path(&request.run, &["trace", "postconditions"]),
                "semanticImpact": json_path(&request.run, &["trace", "semanticImpact"]),
                "projectionWatermark": json_field(&request.agentgres_transition, "projection_watermark"),
                "agentgresTransition": &request.agentgres_transition,
            }),
            artifact_refs: vec![],
            payload_refs: vec![],
        });

        records.push(RuntimeStateStorageWriteInput {
            record_path: format!("jobs/{}.json", required_json_string(&runtime_job, "jobId")?),
            payload: runtime_job.clone(),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "checklists/{}.json",
                required_json_string(&runtime_checklist, "checklistId")?
            ),
            payload: runtime_checklist.clone(),
            artifact_refs: vec![],
            payload_refs: vec![],
        });

        for receipt in json_array(&request.run, "receipts") {
            if let Some(receipt_id) = json_string(receipt, "id") {
                let mut payload = object_payload(receipt);
                payload.insert("runId".to_string(), Value::String(request.run_id.clone()));
                records.push(RuntimeStateStorageWriteInput {
                    record_path: format!("receipts/{}.json", safe_agentgres_component(receipt_id)),
                    payload: Value::Object(payload),
                    artifact_refs: vec![],
                    payload_refs: vec![],
                });
            }
        }
        for artifact in json_array(&request.run, "artifacts") {
            if let Some(artifact_id) = json_string(artifact, "id") {
                records.push(RuntimeStateStorageWriteInput {
                    record_path: format!(
                        "artifacts/{}.json",
                        safe_agentgres_component(artifact_id)
                    ),
                    payload: artifact.clone(),
                    artifact_refs: vec![],
                    payload_refs: vec![],
                });
            }
        }

        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "policy-decisions/{}.json",
                safe_agentgres_component(&request.run_id)
            ),
            payload: json!({
                "runId": &request.run_id,
                "decision": "allowed",
                "rationale": "Local daemon run stayed inside bounded local/private runtime contract.",
                "primitiveCapabilities": ["prim:model.invoke"],
                "authorityScopes": [],
                "receiptId": receipt_id_for_kind(&request.run, "policy_decision"),
            }),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "authority-decisions/{}.json",
                safe_agentgres_component(&request.run_id)
            ),
            payload: json!({
                "runId": &request.run_id,
                "decision": "allowed",
                "authorityScopes": [],
                "walletLayer": "wallet.network",
                "receiptId": receipt_id_for_kind(&request.run, "authority_decision"),
            }),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "stop-conditions/{}.json",
                safe_agentgres_component(&request.run_id)
            ),
            payload: json_path(&request.run, &["trace", "stopCondition"]),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "scorecards/{}.json",
                safe_agentgres_component(&request.run_id)
            ),
            payload: json_path(&request.run, &["trace", "scorecard"]),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!("ledgers/{}.json", safe_agentgres_component(&request.run_id)),
            payload: json_path(&request.run, &["trace", "qualityLedger"]),
            artifact_refs: vec![],
            payload_refs: vec![],
        });
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!("quality/{}.json", safe_agentgres_component(&request.run_id)),
            payload: json!({
                "runId": &request.run_id,
                "scorecard": json_path(&request.run, &["trace", "scorecard"]),
                "qualityLedger": json_path(&request.run, &["trace", "qualityLedger"]),
                "stopCondition": json_path(&request.run, &["trace", "stopCondition"]),
                "verifierIndependencePolicy": {
                    "sameModelAllowed": false,
                    "evidenceOnlyMode": true,
                    "humanReviewThreshold": "high_risk",
                },
            }),
            artifact_refs: vec![],
            payload_refs: vec![],
        });

        let mut projection = object_payload(&request.canonical_projection);
        projection.insert(
            "agentgresTransition".to_string(),
            request.agentgres_transition.clone(),
        );
        records.push(RuntimeStateStorageWriteInput {
            record_path: format!(
                "projections/{}.json",
                safe_agentgres_component(&request.run_id)
            ),
            payload: Value::Object(projection),
            artifact_refs: vec![],
            payload_refs: vec![],
        });

        let mut record = RuntimeStateRecordMaterializationRecord {
            schema_version: RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            records,
            materialization_hash: String::new(),
        };
        record.materialization_hash = runtime_state_record_materialization_hash(&record)?;
        Ok(record)
    }

    pub fn plan_runtime_state_persistence(
        &self,
        request: &RuntimeStatePersistenceRequest,
    ) -> Result<RuntimeStatePersistenceRecord, AgentgresAdmissionError> {
        request.validate()?;
        let materialization =
            self.materialize_runtime_state_records(&RuntimeStateRecordMaterializationRequest {
                schema_version: RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION.to_string(),
                run_id: request.run_id.clone(),
                run: request.run.clone(),
                agent: request.agent.clone(),
                canonical_projection: request.canonical_projection.clone(),
                agentgres_transition: request.agentgres_transition.clone(),
            })?;
        let storage_write_set =
            self.plan_runtime_state_storage_writes(&RuntimeStateStorageWriteSetRequest {
                schema_version: RUNTIME_STATE_STORAGE_WRITE_SET_SCHEMA_VERSION.to_string(),
                run_id: request.run_id.clone(),
                storage_backend_ref: request.storage_backend_ref.clone(),
                receipt_refs: request.receipt_refs.clone(),
                records: materialization.records.clone(),
            })?;
        let mut record = RuntimeStatePersistenceRecord {
            schema_version: RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            materialization,
            storage_write_set,
            persistence_hash: String::new(),
        };
        record.persistence_hash = runtime_state_persistence_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_run_state(
        &self,
        request: &RuntimeRunStateCommitRequest,
    ) -> Result<RuntimeRunStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_run_id = safe_agentgres_component(&request.run_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            receipt_ids(&request.run)
        } else {
            request.receipt_refs.clone()
        };
        let artifact_refs = if request.artifact_refs.is_empty() {
            artifact_ids(&request.run)
        } else {
            request.artifact_refs.clone()
        };
        let payload_refs = if request.payload_refs.is_empty() {
            vec![format!("payload://runtime/runs/{safe_run_id}")]
        } else {
            request.payload_refs.clone()
        };
        let projection_watermark = request
            .projection_watermark
            .clone()
            .unwrap_or_else(|| "runtime-state:1".to_string());
        let transition = self.plan_runtime_state_transition(&RuntimeStateTransitionRequest {
            schema_version: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            operation_kind: request.operation_kind.clone(),
            expected_heads: vec![runtime_previous_resulting_head(
                &request.run_id,
                request.previous_transition.as_ref(),
            )],
            state_root_before: runtime_previous_state_root(
                &request.run_id,
                request.previous_transition.as_ref(),
            )?,
            run: request.run.clone(),
            projection_ref: format!("projection://runtime/runs/{safe_run_id}"),
            projection_watermark,
            receipt_refs: receipt_refs.clone(),
            artifact_refs: artifact_refs.clone(),
            payload_refs,
        })?;
        let persistence = self.plan_runtime_state_persistence(&RuntimeStatePersistenceRequest {
            schema_version: RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            receipt_refs,
            run: request.run.clone(),
            agent: request.agent.clone(),
            canonical_projection: request.canonical_projection.clone(),
            agentgres_transition: serde_json::to_value(&transition)
                .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?,
        })?;
        let mut record = RuntimeRunStateCommitRecord {
            schema_version: RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            run_id: request.run_id.clone(),
            transition,
            persistence,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_run_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_agent_state(
        &self,
        request: &RuntimeAgentStateCommitRequest,
    ) -> Result<RuntimeAgentStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_agent_id = safe_agentgres_component(&request.agent_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            json_string_array(&request.agent, "receipt_refs")
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("agents/{safe_agent_id}.json");
        let payload_refs = vec![format!(
            "payload://runtime/agents/{safe_agent_id}/records/{record_path}"
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://runtime-state/agents/{safe_agent_id}/records/{record_path}"
            ),
            content_hash: runtime_state_payload_hash(&request.agent)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeAgentStateCommitRecord {
            schema_version: RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            agent_id: request.agent_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_agent_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_memory_state(
        &self,
        request: &RuntimeMemoryStateCommitRequest,
    ) -> Result<RuntimeMemoryStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_state_id = safe_agentgres_component(&request.state_id);
        let record_dir = match request.memory_state_kind.as_str() {
            "record" => "memory-records",
            "policy" => "memory-policies",
            _ => return Err(AgentgresAdmissionError::MissingField("memory_state_kind")),
        };
        let receipt_refs = if request.receipt_refs.is_empty() {
            json_string_array(&request.payload, "receipt_refs")
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("{record_dir}/{safe_state_id}.json");
        let payload_refs = vec![format!(
            "payload://runtime/memory/{}/{safe_state_id}/records/{record_path}",
            request.memory_state_kind
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://runtime-state/memory/{}/{safe_state_id}/records/{record_path}",
                request.memory_state_kind
            ),
            content_hash: runtime_state_payload_hash(&request.payload)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeMemoryStateCommitRecord {
            schema_version: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            memory_state_kind: request.memory_state_kind.clone(),
            state_id: request.state_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_memory_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_subagent_state(
        &self,
        request: &RuntimeSubagentStateCommitRequest,
    ) -> Result<RuntimeSubagentStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_subagent_id = safe_agentgres_component(&request.subagent_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            json_string_array(&request.subagent, "receipt_refs")
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("subagents/{safe_subagent_id}.json");
        let payload_refs = vec![format!(
            "payload://runtime/subagents/{safe_subagent_id}/records/{record_path}"
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://runtime-state/subagents/{safe_subagent_id}/records/{record_path}"
            ),
            content_hash: runtime_state_payload_hash(&request.subagent)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeSubagentStateCommitRecord {
            schema_version: RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            subagent_id: request.subagent_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_subagent_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_artifact_state(
        &self,
        request: &RuntimeArtifactStateCommitRequest,
    ) -> Result<RuntimeArtifactStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_artifact_id = safe_agentgres_component(&request.artifact_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            runtime_artifact_receipt_refs(&request.artifact)
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("artifacts/{safe_artifact_id}.json");
        let payload_refs = vec![format!(
            "payload://runtime/artifacts/{safe_artifact_id}/records/{record_path}"
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://runtime-state/artifacts/{safe_artifact_id}/records/{record_path}"
            ),
            content_hash: runtime_state_payload_hash(&request.artifact)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeArtifactStateCommitRecord {
            schema_version: RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            artifact_id: request.artifact_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_artifact_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_model_mount_record_state(
        &self,
        request: &RuntimeModelMountRecordStateCommitRequest,
    ) -> Result<RuntimeModelMountRecordStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_record_dir = safe_agentgres_component(&request.record_dir);
        let safe_record_id = safe_agentgres_component(&request.record_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            runtime_model_mount_record_receipt_refs(&request.record)
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("{safe_record_dir}/{safe_record_id}.json");
        let payload_refs = vec![format!(
            "payload://model-mounting/records/{safe_record_dir}/{safe_record_id}/records/{record_path}"
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://model-mounting/records/{safe_record_dir}/{safe_record_id}/records/{record_path}"
            ),
            content_hash: runtime_state_payload_hash(&request.record)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeModelMountRecordStateCommitRecord {
            schema_version: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            record_dir: request.record_dir.clone(),
            record_id: request.record_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_model_mount_record_state_commit_hash(&record)?;
        Ok(record)
    }

    pub fn commit_runtime_model_mount_receipt_state(
        &self,
        request: &RuntimeModelMountReceiptStateCommitRequest,
    ) -> Result<RuntimeModelMountReceiptStateCommitRecord, AgentgresAdmissionError> {
        request.validate()?;
        let safe_receipt_id = safe_agentgres_component(&request.receipt_id);
        let receipt_refs = if request.receipt_refs.is_empty() {
            runtime_model_mount_receipt_refs(&request.receipt)
        } else {
            request.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        let record_path = format!("receipts/{safe_receipt_id}.json");
        let payload_refs = vec![format!(
            "payload://model-mounting/receipts/{safe_receipt_id}/records/{record_path}"
        )];
        let proposal = StorageBackendWriteProposal {
            schema_version: STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION.to_string(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            object_ref: format!(
                "agentgres://model-mounting/receipts/{safe_receipt_id}/records/{record_path}"
            ),
            content_hash: runtime_state_payload_hash(&request.receipt)?,
            artifact_refs: vec![],
            payload_refs,
            receipt_refs,
        };
        let admission = self.admit_storage_backend_write(&proposal)?;
        let storage_record = RuntimeStateStorageWriteRecord {
            record_path,
            object_ref: proposal.object_ref,
            content_hash: proposal.content_hash,
            artifact_refs: proposal.artifact_refs,
            payload_refs: proposal.payload_refs,
            receipt_refs: proposal.receipt_refs,
            admission,
        };
        let mut record = RuntimeModelMountReceiptStateCommitRecord {
            schema_version: RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            receipt_id: request.receipt_id.clone(),
            operation_kind: request.operation_kind.clone(),
            storage_backend_ref: request.storage_backend_ref.clone(),
            record: storage_record,
            commit_hash: String::new(),
        };
        record.commit_hash = runtime_model_mount_receipt_state_commit_hash(&record)?;
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
        validate_runtime_run_id(&self.run, &self.run_id)?;
        require_non_empty("state_root_before", &self.state_root_before)
            .map_err(|_| AgentgresAdmissionError::MissingStateRootBefore)?;
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

impl RuntimeStateRecordMaterializationRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("run_id", &self.run_id)?;
        validate_runtime_run_id(&self.run, &self.run_id)?;
        validate_optional_runtime_agent_id(&self.run, self.agent.as_ref())?;
        Ok(())
    }
}

impl RuntimeStatePersistenceRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("run_id", &self.run_id)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_run_id(&self.run, &self.run_id)?;
        validate_optional_runtime_agent_id(&self.run, self.agent.as_ref())?;
        required_json_string(&self.agentgres_transition, "operation_ref")?;
        required_json_string(&self.agentgres_transition, "state_root_after")?;
        required_json_string(&self.agentgres_transition, "resulting_head")?;
        required_json_string(&self.agentgres_transition, "projection_watermark")?;
        required_json_string(&self.agentgres_transition, "transition_hash")?;
        if self.receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        Ok(())
    }
}

impl RuntimeRunStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("run_id", &self.run_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_run_id(&self.run, &self.run_id)?;
        validate_optional_runtime_agent_id(&self.run, self.agent.as_ref())?;
        let receipt_refs = if self.receipt_refs.is_empty() {
            receipt_ids(&self.run)
        } else {
            self.receipt_refs.clone()
        };
        if receipt_refs.is_empty() {
            return Err(AgentgresAdmissionError::MissingReceiptRefs);
        }
        Ok(())
    }
}

impl RuntimeAgentStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("agent_id", &self.agent_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_agent_id(&self.agent, &self.agent_id)?;
        Ok(())
    }
}

impl RuntimeMemoryStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("memory_state_kind", &self.memory_state_kind)?;
        require_non_empty("state_id", &self.state_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_memory_payload_id(&self.payload, &self.state_id)?;
        Ok(())
    }
}

impl RuntimeSubagentStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("subagent_id", &self.subagent_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_subagent_id(&self.subagent, &self.subagent_id)?;
        Ok(())
    }
}

impl RuntimeArtifactStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("artifact_id", &self.artifact_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_artifact_id(&self.artifact, &self.artifact_id)?;
        Ok(())
    }
}

impl RuntimeModelMountRecordStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("record_dir", &self.record_dir)?;
        require_non_empty("record_id", &self.record_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_model_mount_record_id(&self.record, &self.record_id)?;
        Ok(())
    }
}

impl RuntimeModelMountReceiptStateCommitRequest {
    pub fn validate(&self) -> Result<(), AgentgresAdmissionError> {
        if self.schema_version != RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION {
            return Err(AgentgresAdmissionError::InvalidSchemaVersion {
                expected: RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("storage_backend_ref", &self.storage_backend_ref)?;
        validate_runtime_model_mount_receipt_id(&self.receipt, &self.receipt_id)?;
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
    run_state_hash: &str,
    task_state_hash: &str,
) -> Result<String, AgentgresAdmissionError> {
    let canonical = serde_json::json!({
        "schema_version": RUNTIME_STATE_TRANSITION_SCHEMA_VERSION,
        "run_id": &request.run_id,
        "operation_kind": &request.operation_kind,
        "expected_heads": &request.expected_heads,
        "state_root_before": &request.state_root_before,
        "run_state_hash": run_state_hash,
        "task_state_hash": task_state_hash,
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

fn runtime_state_record_materialization_hash(
    record: &RuntimeStateRecordMaterializationRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.materialization_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_state_persistence_hash(
    record: &RuntimeStatePersistenceRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.persistence_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_run_state_commit_hash(
    record: &RuntimeRunStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_agent_state_commit_hash(
    record: &RuntimeAgentStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_memory_state_commit_hash(
    record: &RuntimeMemoryStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_subagent_state_commit_hash(
    record: &RuntimeSubagentStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_artifact_state_commit_hash(
    record: &RuntimeArtifactStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_model_mount_record_state_commit_hash(
    record: &RuntimeModelMountRecordStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_model_mount_receipt_state_commit_hash(
    record: &RuntimeModelMountReceiptStateCommitRecord,
) -> Result<String, AgentgresAdmissionError> {
    let mut canonical = record.clone();
    canonical.commit_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| AgentgresAdmissionError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn runtime_initial_head(run_id: &str) -> String {
    format!(
        "agentgres://runtime-state/runs/{}/head/0",
        safe_agentgres_component(run_id)
    )
}

fn runtime_initial_state_root(run_id: &str) -> Result<String, AgentgresAdmissionError> {
    runtime_state_hash(&json!({
        "schema": "ioi.agentgres.runtime_state_root.v1",
        "runId": run_id,
        "sequence": 0,
    }))
}

fn runtime_previous_resulting_head(run_id: &str, previous_transition: Option<&Value>) -> String {
    previous_transition
        .and_then(|transition| {
            json_string(transition, "resulting_head")
                .or_else(|| json_string(transition, "resultingHead"))
        })
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| runtime_initial_head(run_id))
}

fn runtime_previous_state_root(
    run_id: &str,
    previous_transition: Option<&Value>,
) -> Result<String, AgentgresAdmissionError> {
    match previous_transition
        .and_then(|transition| {
            json_string(transition, "state_root_after")
                .or_else(|| json_string(transition, "stateRootAfter"))
        })
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => Ok(value.to_string()),
        None => runtime_initial_state_root(run_id),
    }
}

fn receipt_ids(run: &Value) -> Vec<String> {
    json_array(run, "receipts")
        .into_iter()
        .filter_map(|receipt| json_string(receipt, "id").map(str::to_string))
        .collect()
}

fn artifact_ids(run: &Value) -> Vec<String> {
    json_array(run, "artifacts")
        .into_iter()
        .filter_map(|artifact| json_string(artifact, "id").map(str::to_string))
        .collect()
}

fn runtime_run_state_hash(run: &Value) -> Result<String, AgentgresAdmissionError> {
    let state = json!({
        "id": json_field(run, "id"),
        "agentId": json_field(run, "agentId"),
        "status": json_field(run, "status"),
        "mode": json_field(run, "mode"),
        "createdAt": json_field(run, "createdAt"),
        "updatedAt": json_field(run, "updatedAt"),
        "eventCount": json_array(run, "events").len(),
        "terminalEventCount": terminal_event_count(run),
        "traceBundleId": json_path(run, &["trace", "traceBundleId"]),
    });
    runtime_state_hash(&state)
}

fn runtime_task_state_hash(run: &Value) -> Result<String, AgentgresAdmissionError> {
    let runtime_task = runtime_task_record_for_run(run)?;
    let runtime_job = runtime_job_record_for_run(run, &runtime_task)?;
    let runtime_checklist = runtime_checklist_record_for_run(run, &runtime_task, &runtime_job)?;
    let state = json!({
        "runtimeTask": runtime_task,
        "runtimeJob": runtime_job,
        "runtimeChecklist": runtime_checklist,
        "taskState": json_path(run, &["trace", "taskState"]),
        "postconditions": json_path(run, &["trace", "postconditions"]),
        "semanticImpact": json_path(run, &["trace", "semanticImpact"]),
        "stopCondition": json_path(run, &["trace", "stopCondition"]),
        "scorecard": json_path(run, &["trace", "scorecard"]),
        "qualityLedger": json_path(run, &["trace", "qualityLedger"]),
    });
    runtime_state_hash(&state)
}

fn runtime_state_hash(value: &Value) -> Result<String, AgentgresAdmissionError> {
    let canonical = stable_json_value(value)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}

fn runtime_task_record_for_run(run: &Value) -> Result<Value, AgentgresAdmissionError> {
    if let Some(task) = run.get("runtimeTask").filter(|value| value.is_object()) {
        return Ok(task.clone());
    }
    let run_id = required_json_string(run, "id")?;
    let mode = json_string(run, "mode").unwrap_or("send");
    let status = job_status_for_run_status(json_string(run, "status"));
    let task_family = json_path(run, &["trace", "qualityLedger", "taskFamily"])
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| task_family_for_mode(mode).to_string());
    let selected_strategy = json_path(run, &["trace", "qualityLedger", "selectedStrategy"])
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| strategy_for_mode(mode).to_string());
    let agent_id = json_string(run, "agentId").map(str::to_string);
    let model_route_decision = run.get("modelRouteDecision").or_else(|| {
        run.get("trace")
            .and_then(|trace| trace.get("modelRouteDecision"))
    });
    let active_skill_hook_manifest = run.get("activeSkillHookManifest").or_else(|| {
        run.get("trace")
            .and_then(|trace| trace.get("activeSkillHookManifest"))
    });
    Ok(json!({
        "schemaVersion": "ioi.agent-runtime.task-record.v1",
        "object": "ioi.runtime_task",
        "taskId": format!("task_{run_id}"),
        "runId": run_id,
        "agentId": string_or_null(agent_id.as_deref()),
        "threadId": agent_id.as_deref().map(thread_id_for_agent).map(Value::String).unwrap_or(Value::Null),
        "turnId": turn_id_for_run(run_id),
        "status": status,
        "mode": mode,
        "taskFamily": task_family,
        "selectedStrategy": selected_strategy,
        "summary": format!("Runtime task for {task_family} is {status}."),
        "promptHash": sha256_hex(json_string(run, "objective").unwrap_or("")),
        "promptIncluded": false,
        "objectivePreviewIncluded": false,
        "modelRouteDecisionId": model_route_decision.and_then(|value| json_string(value, "decision_id")).map(|value| Value::String(value.to_string())).unwrap_or(Value::Null),
        "activeSkillHookManifestId": active_skill_hook_manifest.and_then(|value| json_string(value, "manifestId")).map(|value| Value::String(value.to_string())).unwrap_or(Value::Null),
        "createdAt": json_field(run, "createdAt"),
        "updatedAt": if run.get("updatedAt").is_some() { json_field(run, "updatedAt") } else { json_field(run, "createdAt") },
        "durable": true,
        "replayable": true,
        "cancelable": status != "canceled",
        "cancelEndpoint": format!("/v1/tasks/task_{run_id}/cancel"),
        "endpoints": {
            "self": format!("/v1/tasks/task_{run_id}"),
            "cancel": format!("/v1/tasks/task_{run_id}/cancel"),
            "run": format!("/v1/runs/{run_id}"),
            "job": format!("/v1/jobs/job_{run_id}"),
            "events": format!("/v1/runs/{run_id}/events"),
            "trace": format!("/v1/runs/{run_id}/trace"),
        },
        "workflowNodeId": "runtime.runtime-task",
        "redaction": {
            "profile": "runtime_task_safe",
            "promptIncluded": false,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": compact_strings(vec![
            Some("runtime_task".to_string()),
            Some("runtime.tasks.durable_projection".to_string()),
            Some("RuntimeTaskNode".to_string()),
            Some(format!("run:{run_id}")),
            active_skill_hook_manifest.and_then(|value| json_string(value, "manifestId")).map(str::to_string),
        ]),
    }))
}

fn runtime_job_record_for_run(
    run: &Value,
    runtime_task: &Value,
) -> Result<Value, AgentgresAdmissionError> {
    if let Some(job) = run.get("runtimeJob").filter(|value| value.is_object()) {
        return Ok(job.clone());
    }
    let run_id = required_json_string(runtime_task, "runId")?;
    let task_id = required_json_string(runtime_task, "taskId")?;
    let status = job_status_for_run_status(json_string(run, "status"));
    let terminal = matches!(status, "completed" | "failed" | "canceled");
    let event_count = json_array(run, "events").len();
    let terminal_count = terminal_event_count(run);
    let job_id = format!("job_{run_id}");
    let progress = json!({
        "completedSteps": if terminal { 1 } else { 0 },
        "totalSteps": 1,
        "percent": if terminal { 100 } else if status == "running" { 50 } else { 0 },
    });
    let failure = if status == "failed" {
        json!({ "reason": "runtime_failed", "message": "Runtime job failed." })
    } else {
        Value::Null
    };
    let cancellation = if status == "canceled" {
        json!({ "reason": "operator_cancel" })
    } else {
        Value::Null
    };
    let endpoints = json!({
        "self": format!("/v1/jobs/{job_id}"),
        "cancel": format!("/v1/jobs/{job_id}/cancel"),
        "run": format!("/v1/runs/{run_id}"),
        "events": format!("/v1/runs/{run_id}/events"),
        "trace": format!("/v1/runs/{run_id}/trace"),
    });
    let redaction = json!({
        "profile": "runtime_job_safe",
        "promptIncluded": false,
        "secretValuesIncluded": false,
    });
    let evidence_refs = json!([
        "runtime_job",
        "runtime.jobs.durable_projection",
        "RuntimeJobNode",
        task_id,
        format!("run:{run_id}"),
    ]);
    Ok(json!({
        "schemaVersion": "ioi.agent-runtime.job-record.v1",
        "object": "ioi.runtime_job",
        "jobId": job_id,
        "taskId": task_id,
        "runId": run_id,
        "agentId": json_field(runtime_task, "agentId"),
        "threadId": json_field(runtime_task, "threadId"),
        "turnId": json_field(runtime_task, "turnId"),
        "status": status,
        "lifecycle": job_lifecycle_for_status(status),
        "summary": format!("Runtime job job_{run_id} is {status}."),
        "queueName": "local-agentgres",
        "runner": "local-daemon-agentgres",
        "jobType": "agent_run",
        "priority": "normal",
        "background": true,
        "durable": true,
        "replayable": true,
        "createdAt": json_field(run, "createdAt"),
        "updatedAt": json_field(run, "updatedAt"),
        "queuedAt": json_field(run, "createdAt"),
        "startedAt": json_field(run, "createdAt"),
        "completedAt": if terminal { json_field(run, "updatedAt") } else { Value::Null },
        "progress": progress,
        "eventCount": if event_count == 0 { Value::Null } else { json!(event_count) },
        "terminalEventCount": if terminal_count == 0 { Value::Null } else { json!(terminal_count) },
        "artifactNames": artifact_names(run),
        "receiptKinds": receipt_kinds(run),
        "checklistId": Value::Null,
        "checklistStatus": Value::Null,
        "checklistItemCount": Value::Null,
        "checklistCompletedItemCount": Value::Null,
        "failure": failure,
        "cancellation": cancellation,
        "retryCount": 0,
        "cancelable": status != "canceled",
        "cancelEndpoint": format!("/v1/jobs/{job_id}/cancel"),
        "endpoints": endpoints,
        "workflowNodeId": "runtime.runtime-job",
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    }))
}

fn runtime_checklist_record_for_run(
    run: &Value,
    runtime_task: &Value,
    runtime_job: &Value,
) -> Result<Value, AgentgresAdmissionError> {
    if let Some(checklist) = run
        .get("runtimeChecklist")
        .filter(|value| value.is_object())
    {
        return Ok(checklist.clone());
    }
    let run_id = required_json_string(runtime_task, "runId")?;
    let task_id = required_json_string(runtime_task, "taskId")?;
    let job_id = required_json_string(runtime_job, "jobId")?;
    let status = json_string(runtime_job, "status")
        .or_else(|| json_string(runtime_task, "status"))
        .unwrap_or("completed");
    let checklist_id = format!("checklist_{run_id}");
    let (terminal_label, terminal_kind, terminal_status) = match status {
        "canceled" => ("Job canceled event emitted", "JobCanceled", "canceled"),
        "failed" => ("Job failed event emitted", "JobFailed", "failed"),
        "blocked" => ("Job blocked by policy gate", "PolicyBlocked", "blocked"),
        _ => ("Job completed event emitted", "JobCompleted", "passed"),
    };
    let items = vec![
        checklist_item(
            &checklist_id,
            "task_record",
            "Runtime task record durable",
            "passed",
            vec![
                task_id,
                "RuntimeTaskNode",
                "runtime.tasks.durable_projection",
            ],
        ),
        checklist_item(
            &checklist_id,
            "job_record",
            "Runtime job record durable",
            "passed",
            vec![job_id, "RuntimeJobNode", "runtime.jobs.durable_projection"],
        ),
        checklist_item(
            &checklist_id,
            "job_queued",
            "Job queued event emitted",
            "passed",
            vec!["JobQueued"],
        ),
        checklist_item(
            &checklist_id,
            "job_started",
            "Job started event emitted",
            "passed",
            vec!["JobStarted"],
        ),
        checklist_item(
            &checklist_id,
            "job_terminal",
            terminal_label,
            terminal_status,
            vec![terminal_kind],
        ),
        checklist_item(
            &checklist_id,
            "artifacts",
            "Runtime task/job/checklist artifacts attached",
            "passed",
            vec![
                "runtime-task.json",
                "runtime-job.json",
                "runtime-checklist.json",
            ],
        ),
    ];
    let completed = items
        .iter()
        .filter(|item| json_string(item, "status") == Some("passed"))
        .count();
    let canceled = items
        .iter()
        .filter(|item| json_string(item, "status") == Some("canceled"))
        .count();
    let failed = items
        .iter()
        .filter(|item| json_string(item, "status") == Some("failed"))
        .count();
    let blocked = items
        .iter()
        .filter(|item| json_string(item, "status") == Some("blocked"))
        .count();
    Ok(json!({
        "schemaVersion": "ioi.agent-runtime.checklist-record.v1",
        "object": "ioi.runtime_checklist",
        "checklistId": checklist_id,
        "taskId": task_id,
        "jobId": job_id,
        "runId": run_id,
        "agentId": json_field(runtime_task, "agentId"),
        "threadId": json_field(runtime_task, "threadId"),
        "turnId": json_field(runtime_task, "turnId"),
        "status": status,
        "summary": format!("Runtime checklist for {job_id} is {status}."),
        "durable": true,
        "replayable": true,
        "readOnly": true,
        "itemCount": items.len(),
        "completedItemCount": completed,
        "canceledItemCount": canceled,
        "failedItemCount": failed,
        "blockedItemCount": blocked,
        "items": items,
        "requiredItemIds": [
            format!("{checklist_id}:task_record"),
            format!("{checklist_id}:job_record"),
            format!("{checklist_id}:job_queued"),
            format!("{checklist_id}:job_started"),
            format!("{checklist_id}:job_terminal"),
            format!("{checklist_id}:artifacts"),
        ],
        "createdAt": json_field(run, "createdAt"),
        "updatedAt": json_field(run, "updatedAt"),
        "workflowNodeId": "runtime.runtime-checklist",
        "redaction": {
            "profile": "runtime_checklist_safe",
            "promptIncluded": false,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": [
            "runtime_checklist",
            "runtime.checklists.durable_projection",
            "RuntimeChecklistNode",
            task_id,
            job_id,
            format!("run:{run_id}"),
        ],
    }))
}

fn checklist_item(
    checklist_id: &str,
    suffix: &str,
    label: &str,
    status: &str,
    evidence_refs: Vec<&str>,
) -> Value {
    json!({
        "itemId": format!("{checklist_id}:{suffix}"),
        "label": label,
        "status": status,
        "evidenceRefs": unique_string_values(evidence_refs),
    })
}

fn validate_runtime_run_id(
    run: &Value,
    expected_run_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(run, "id") {
        Some(run_id) if run_id == expected_run_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordRunIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("run.id")),
    }
}

fn validate_optional_runtime_agent_id(
    run: &Value,
    agent: Option<&Value>,
) -> Result<(), AgentgresAdmissionError> {
    let Some(agent) = agent else {
        return Ok(());
    };
    let run_agent_id = json_string(run, "agentId")
        .or_else(|| json_string(run, "agent_id"))
        .ok_or(AgentgresAdmissionError::MissingField("run.agentId"))?;
    match json_string(agent, "id").or_else(|| json_string(agent, "agent_id")) {
        Some(agent_id) if agent_id == run_agent_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("agent.id")),
    }
}

fn validate_runtime_agent_id(
    agent: &Value,
    expected_agent_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(agent, "id").or_else(|| json_string(agent, "agent_id")) {
        Some(agent_id) if agent_id == expected_agent_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("agent.id")),
    }
}

fn validate_runtime_memory_payload_id(
    payload: &Value,
    expected_state_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(payload, "id") {
        Some(state_id) if state_id == expected_state_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("payload.id")),
    }
}

fn validate_runtime_subagent_id(
    subagent: &Value,
    expected_subagent_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(subagent, "subagent_id").or_else(|| json_string(subagent, "subagentId")) {
        Some(subagent_id) if subagent_id == expected_subagent_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField(
            "subagent.subagent_id",
        )),
    }
}

fn validate_runtime_artifact_id(
    artifact: &Value,
    expected_artifact_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(artifact, "id").or_else(|| json_string(artifact, "artifact_id")) {
        Some(artifact_id) if artifact_id == expected_artifact_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("artifact.id")),
    }
}

fn runtime_artifact_receipt_refs(artifact: &Value) -> Vec<String> {
    let mut refs = json_string_array(artifact, "receipt_refs");
    if let Some(receipt_id) = json_string(artifact, "receipt_id")
        .or_else(|| json_string(artifact, "receiptId"))
        .filter(|entry| !entry.trim().is_empty())
    {
        refs.push(receipt_id.to_string());
    }
    refs.sort();
    refs.dedup();
    refs
}

fn validate_runtime_model_mount_record_id(
    record: &Value,
    expected_record_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(record, "id") {
        Some(record_id) if record_id == expected_record_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("record.id")),
    }
}

fn runtime_model_mount_record_receipt_refs(record: &Value) -> Vec<String> {
    let mut refs = json_string_array(record, "receipt_refs");
    if let Some(receipt_id) = json_string(record, "receipt_id")
        .or_else(|| json_string(record, "receiptId"))
        .filter(|entry| !entry.trim().is_empty())
    {
        refs.push(receipt_id.to_string());
    }
    refs.sort();
    refs.dedup();
    refs
}

fn validate_runtime_model_mount_receipt_id(
    receipt: &Value,
    expected_receipt_id: &str,
) -> Result<(), AgentgresAdmissionError> {
    match json_string(receipt, "id").or_else(|| json_string(receipt, "receipt_id")) {
        Some(receipt_id) if receipt_id == expected_receipt_id => Ok(()),
        Some(_) => Err(AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch),
        None => Err(AgentgresAdmissionError::MissingField("receipt.id")),
    }
}

fn runtime_model_mount_receipt_refs(receipt: &Value) -> Vec<String> {
    let mut refs = json_string_array(receipt, "receipt_refs");
    if let Some(receipt_id) = json_string(receipt, "id")
        .or_else(|| json_string(receipt, "receipt_id"))
        .filter(|entry| !entry.trim().is_empty())
    {
        refs.push(receipt_id.to_string());
    }
    refs.sort();
    refs.dedup();
    refs
}

fn terminal_event_count(run: &Value) -> usize {
    json_array(run, "events")
        .into_iter()
        .filter(|event| {
            matches!(
                json_string(event, "type"),
                Some("completed" | "canceled" | "failed" | "error")
            )
        })
        .count()
}

fn task_family_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "planning",
        "dry_run" => "safety_preview",
        "handoff" => "delegation",
        "learn" => "learning",
        _ => "local_daemon_agentgres",
    }
}

fn strategy_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "daemon_plan_with_postconditions",
        "dry_run" => "daemon_dry_run_before_effect",
        "handoff" => "daemon_handoff_with_state_preservation",
        "learn" => "daemon_bounded_learning_gate",
        _ => "local_daemon_agentgres_execution",
    }
}

fn job_status_for_run_status(status: Option<&str>) -> &'static str {
    match status {
        Some("canceled") => "canceled",
        Some("failed" | "error") => "failed",
        Some("blocked") => "blocked",
        Some("running" | "active") => "running",
        Some("queued" | "pending") => "queued",
        _ => "completed",
    }
}

fn job_lifecycle_for_status(status: &str) -> Vec<&'static str> {
    match status {
        "queued" => vec!["queued"],
        "running" => vec!["queued", "started"],
        "failed" => vec!["queued", "started", "failed"],
        "canceled" => vec!["queued", "started", "canceled"],
        "blocked" => vec!["queued", "started", "blocked"],
        _ => vec!["queued", "started", "completed"],
    }
}

fn thread_id_for_agent(agent_id: &str) -> String {
    agent_id
        .strip_prefix("agent_")
        .map(|suffix| format!("thread_{suffix}"))
        .unwrap_or_else(|| format!("thread_{agent_id}"))
}

fn turn_id_for_run(run_id: &str) -> String {
    run_id
        .strip_prefix("run_")
        .map(|suffix| format!("turn_{suffix}"))
        .unwrap_or_else(|| format!("turn_{run_id}"))
}

fn artifact_names(run: &Value) -> Vec<Value> {
    json_array(run, "artifacts")
        .into_iter()
        .filter_map(|artifact| json_string(artifact, "name"))
        .filter(|name| !name.trim().is_empty())
        .map(|name| Value::String(name.to_string()))
        .collect()
}

fn receipt_kinds(run: &Value) -> Vec<Value> {
    json_array(run, "receipts")
        .into_iter()
        .filter_map(|receipt| json_string(receipt, "kind"))
        .filter(|kind| !kind.trim().is_empty())
        .map(|kind| Value::String(kind.to_string()))
        .collect()
}

fn unique_string_values(values: Vec<&str>) -> Vec<Value> {
    let mut unique = Vec::<String>::new();
    for value in values {
        let text = value.trim();
        if !text.is_empty() && !unique.iter().any(|candidate| candidate == text) {
            unique.push(text.to_string());
        }
    }
    unique.into_iter().map(Value::String).collect()
}

fn compact_strings(values: Vec<Option<String>>) -> Vec<Value> {
    values
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .collect()
}

fn string_or_null(value: Option<&str>) -> Value {
    value
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| Value::String(entry.to_string()))
        .unwrap_or(Value::Null)
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
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

fn json_field(value: &Value, field: &str) -> Value {
    value.get(field).cloned().unwrap_or(Value::Null)
}

fn json_path(value: &Value, path: &[&str]) -> Value {
    let mut current = value;
    for field in path {
        match current.get(*field) {
            Some(next) => current = next,
            None => return Value::Null,
        }
    }
    current.clone()
}

fn json_array<'a>(value: &'a Value, field: &str) -> Vec<&'a Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|entries| entries.iter().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn json_string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .filter(|entry| !entry.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn json_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn required_json_string<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str, AgentgresAdmissionError> {
    json_string(value, field)
        .filter(|entry| !entry.trim().is_empty())
        .ok_or(AgentgresAdmissionError::MissingField(field))
}

fn object_payload(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn receipt_id_for_kind(run: &Value, kind: &str) -> Value {
    json_array(run, "receipts")
        .into_iter()
        .find(|receipt| json_string(receipt, "kind") == Some(kind))
        .and_then(|receipt| json_string(receipt, "id"))
        .map(|id| Value::String(id.to_string()))
        .unwrap_or(Value::Null)
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

    fn runtime_run() -> Value {
        json!({
            "id": "run_1",
            "agentId": "agent_1",
            "status": "completed",
            "mode": "send",
            "objective": "Ship the runtime state slice",
            "createdAt": "2026-06-04T00:00:00.000Z",
            "updatedAt": "2026-06-04T00:00:01.000Z",
            "events": [
                { "type": "started" },
                { "type": "completed" }
            ],
            "receipts": [
                {
                    "id": "receipt_policy",
                    "kind": "policy_decision"
                },
                {
                    "id": "receipt_authority",
                    "kind": "authority_decision"
                }
            ],
            "artifacts": [
                {
                    "id": "artifact_1",
                    "name": "result.txt",
                    "kind": "text"
                }
            ],
            "trace": {
                "traceBundleId": "trace_bundle_1",
                "taskState": {
                    "state": "done"
                },
                "postconditions": [
                    {
                        "id": "postcondition_1"
                    }
                ],
                "semanticImpact": {
                    "impact": "local"
                },
                "stopCondition": {
                    "reason": "done"
                },
                "scorecard": {
                    "score": 1
                },
                "qualityLedger": {
                    "entries": []
                }
            }
        })
    }

    fn runtime_agent() -> Value {
        json!({
            "id": "agent_1",
            "status": "active",
            "runtime": "local",
            "createdAt": "2026-06-04T00:00:00.000Z",
            "updatedAt": "2026-06-04T00:00:01.000Z"
        })
    }

    fn runtime_subagent() -> Value {
        json!({
            "subagent_id": "subagent_1",
            "parent_thread_id": "thread_1",
            "agent_id": "agent_1",
            "role": "research",
            "lifecycle_status": "completed",
            "updated_at": "2026-06-04T00:00:02.000Z",
            "receipt_refs": ["receipt_subagent"]
        })
    }

    fn runtime_committed_agent() -> Value {
        json!({
            "id": "agent_1",
            "status": "active",
            "runtime": "local",
            "updated_at": "2026-06-06T00:00:00.000Z",
            "receipt_refs": ["receipt_agent"]
        })
    }

    fn runtime_agent_state_commit() -> RuntimeAgentStateCommitRequest {
        RuntimeAgentStateCommitRequest {
            schema_version: RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            agent_id: "agent_1".to_string(),
            operation_kind: "agent.create".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            agent: runtime_committed_agent(),
            receipt_refs: vec![],
        }
    }

    fn runtime_memory_record() -> Value {
        json!({
            "schemaVersion": "ioi.agent-runtime.memory.v1",
            "id": "memory_1",
            "object": "ioi.agent_memory_record",
            "scope": "thread",
            "fact": "Remember the launch checklist.",
            "threadId": "thread_1",
            "agentId": "agent_1",
            "updatedAt": "2026-06-06T00:00:00.000Z",
            "receipt_refs": ["receipt_memory"]
        })
    }

    fn runtime_memory_policy() -> Value {
        json!({
            "schemaVersion": "ioi.agent-runtime.memory-policy.v1",
            "id": "thread_thread_1",
            "object": "ioi.agent_memory_policy",
            "targetType": "thread",
            "targetId": "thread_1",
            "readOnly": true,
            "updatedAt": "2026-06-06T00:00:00.000Z",
            "receipt_refs": ["receipt_memory_policy"]
        })
    }

    fn runtime_memory_state_commit() -> RuntimeMemoryStateCommitRequest {
        RuntimeMemoryStateCommitRequest {
            schema_version: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            memory_state_kind: "record".to_string(),
            state_id: "memory_1".to_string(),
            operation_kind: "memory.write".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            payload: runtime_memory_record(),
            receipt_refs: vec![],
        }
    }

    fn runtime_memory_policy_state_commit() -> RuntimeMemoryStateCommitRequest {
        RuntimeMemoryStateCommitRequest {
            schema_version: RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            memory_state_kind: "policy".to_string(),
            state_id: "thread_thread_1".to_string(),
            operation_kind: "memory.policy".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            payload: runtime_memory_policy(),
            receipt_refs: vec![],
        }
    }

    fn runtime_subagent_state_commit() -> RuntimeSubagentStateCommitRequest {
        RuntimeSubagentStateCommitRequest {
            schema_version: RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            subagent_id: "subagent_1".to_string(),
            operation_kind: "subagent.wait".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            subagent: runtime_subagent(),
            receipt_refs: vec![],
        }
    }

    fn runtime_artifact_record() -> Value {
        json!({
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
        })
    }

    fn runtime_artifact_state_commit() -> RuntimeArtifactStateCommitRequest {
        RuntimeArtifactStateCommitRequest {
            schema_version: RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            artifact_id: "artifact_1".to_string(),
            operation_kind: "artifact.coding_tool_draft".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            artifact: runtime_artifact_record(),
            receipt_refs: vec![],
        }
    }

    fn runtime_model_mount_provider_health_record() -> Value {
        json!({
            "id": "health.provider_openai",
            "provider_id": "provider.openai",
            "status": "available",
            "checked_at": "2026-06-04T00:00:00.000Z",
            "receipt_id": "receipt_provider_health",
            "evidence_refs": ["provider_http_health"]
        })
    }

    fn runtime_model_mount_record_state_commit() -> RuntimeModelMountRecordStateCommitRequest {
        RuntimeModelMountRecordStateCommitRequest {
            schema_version: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            record_dir: "provider-health".to_string(),
            record_id: "health.provider_openai".to_string(),
            operation_kind: "model_mount.provider_health.write".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            record: runtime_model_mount_provider_health_record(),
            receipt_refs: vec![],
        }
    }

    fn runtime_model_mount_receipt() -> Value {
        json!({
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
        })
    }

    fn runtime_model_mount_receipt_state_commit() -> RuntimeModelMountReceiptStateCommitRequest {
        RuntimeModelMountReceiptStateCommitRequest {
            schema_version: RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            receipt_id: "receipt_model_invocation".to_string(),
            operation_kind: "model_mount.receipt.write".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            receipt: runtime_model_mount_receipt(),
            receipt_refs: vec![],
        }
    }

    fn runtime_state_transition() -> RuntimeStateTransitionRequest {
        RuntimeStateTransitionRequest {
            schema_version: RUNTIME_STATE_TRANSITION_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            operation_kind: "run.create".to_string(),
            expected_heads: vec!["agentgres://runtime-state/runs/run_1/head/0".to_string()],
            state_root_before: "sha256:runtime-state-before".to_string(),
            run: runtime_run(),
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

    fn runtime_state_record_materialization() -> RuntimeStateRecordMaterializationRequest {
        RuntimeStateRecordMaterializationRequest {
            schema_version: RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            run: runtime_run(),
            agent: None,
            canonical_projection: json!({
                "runId": "run_1",
                "projection": "canonical"
            }),
            agentgres_transition: json!({
                "projection_watermark": "runtime-state:1",
                "transition_hash": "sha256:transition"
            }),
        }
    }

    fn runtime_state_persistence() -> RuntimeStatePersistenceRequest {
        RuntimeStatePersistenceRequest {
            schema_version: RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            receipt_refs: vec![
                "receipt_policy".to_string(),
                "receipt_authority".to_string(),
            ],
            run: runtime_run(),
            agent: None,
            canonical_projection: json!({
                "runId": "run_1",
                "projection": "canonical"
            }),
            agentgres_transition: json!({
                "schema_version": "ioi.agentgres_runtime_state_transition.v1",
                "operation_ref": "agentgres://runtime-state/runs/run_1/operations/run.create_mock",
                "expected_heads": ["agentgres://runtime-state/runs/run_1/head/0"],
                "state_root_before": "sha256:runtime-state-before",
                "state_root_after": "sha256:runtime-state-after",
                "resulting_head": "agentgres://runtime-state/runs/run_1/head/mock",
                "projection_watermark": "runtime-state:1",
                "transition_hash": "sha256:transition"
            }),
        }
    }

    fn runtime_run_state_commit() -> RuntimeRunStateCommitRequest {
        RuntimeRunStateCommitRequest {
            schema_version: RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION.to_string(),
            run_id: "run_1".to_string(),
            operation_kind: "run.create".to_string(),
            storage_backend_ref: "storage://runtime-agentgres/local-json".to_string(),
            run: runtime_run(),
            agent: Some(runtime_agent()),
            canonical_projection: json!({
                "runId": "run_1",
                "projection": "canonical"
            }),
            previous_transition: None,
            projection_watermark: Some("runtime-state:1".to_string()),
            receipt_refs: vec![],
            artifact_refs: vec![],
            payload_refs: vec![],
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

    #[test]
    fn materializes_runtime_state_records_in_rust() {
        let record = AgentgresAdmissionCore
            .materialize_runtime_state_records(&runtime_state_record_materialization())
            .expect("runtime state records materialized");

        assert_eq!(
            record.schema_version,
            RUNTIME_STATE_RECORD_MATERIALIZATION_SCHEMA_VERSION
        );
        assert_eq!(record.records.len(), 14);
        assert!(record.materialization_hash.starts_with("sha256:"));
        assert_eq!(record.records[0].record_path, "runs/run_1.json");
        assert_eq!(record.records[1].record_path, "tasks/run_1.json");
        assert_eq!(record.records[2].record_path, "jobs/job_run_1.json");
        assert_eq!(
            record.records[3].record_path,
            "checklists/checklist_run_1.json"
        );
        assert_eq!(
            record.records[4].record_path,
            "receipts/receipt_policy.json"
        );
        assert_eq!(
            record.records[1].payload["runtimeTask"]["schemaVersion"],
            json!("ioi.agent-runtime.task-record.v1")
        );
        assert_eq!(
            record.records[1].payload["runtimeTask"]["threadId"],
            json!("thread_1")
        );
        assert_eq!(record.records[2].payload["eventCount"], json!(2));
        assert_eq!(record.records[3].payload["completedItemCount"], json!(6));
        assert_eq!(record.records[6].record_path, "artifacts/artifact_1.json");
        assert_eq!(
            record.records[7].payload["receiptId"],
            json!("receipt_policy")
        );
        assert_eq!(
            record.records[8].payload["walletLayer"],
            json!("wallet.network")
        );
        assert_eq!(
            record.records[13].payload["agentgresTransition"]["transition_hash"],
            json!("sha256:transition")
        );
    }

    #[test]
    fn runtime_state_record_materialization_requires_matching_run_id() {
        let mut request = runtime_state_record_materialization();
        request.run["id"] = json!("other_run");
        let error = AgentgresAdmissionCore
            .materialize_runtime_state_records(&request)
            .expect_err("run payload id must match request id");
        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordRunIdMismatch
        );
    }

    #[test]
    fn materializes_runtime_agent_snapshot_when_committed_with_run_state() {
        let mut request = runtime_state_record_materialization();
        request.agent = Some(runtime_agent());

        let record = AgentgresAdmissionCore
            .materialize_runtime_state_records(&request)
            .expect("runtime state records materialized with agent snapshot");

        assert_eq!(record.records.len(), 15);
        assert_eq!(record.records[1].record_path, "agents/agent_1.json");
        assert_eq!(record.records[1].payload["id"], json!("agent_1"));
        assert_eq!(record.records[2].record_path, "tasks/run_1.json");
        assert_eq!(
            record.records[14].payload["agentgresTransition"]["transition_hash"],
            json!("sha256:transition")
        );
    }

    #[test]
    fn runtime_state_record_materialization_rejects_mismatched_agent_snapshot() {
        let mut request = runtime_state_record_materialization();
        request.agent = Some(runtime_agent());
        request.agent.as_mut().expect("agent")["id"] = json!("agent_other");

        let error = AgentgresAdmissionCore
            .materialize_runtime_state_records(&request)
            .expect_err("agent payload id must match run agent id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_agent_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_agent_state(&runtime_agent_state_commit())
            .expect("runtime agent state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_AGENT_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.operation_kind, "agent.create");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(record.record.record_path, "agents/agent_1.json");
        assert_eq!(
            record.record.object_ref,
            "agentgres://runtime-state/agents/agent_1/records/agents/agent_1.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://runtime/agents/agent_1/records/agents/agent_1.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_agent"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_agent_state_commit_requires_receipts() {
        let mut request = runtime_agent_state_commit();
        request.agent["receipt_refs"] = json!([]);

        let error = AgentgresAdmissionCore
            .commit_runtime_agent_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_agent_state_commit_rejects_retired_receipt_refs_alias() {
        let mut request = runtime_agent_state_commit();
        request.agent["receipt_refs"] = json!([]);
        request.agent["receiptRefs"] = json!(["receipt_agent_retired"]);

        let error = AgentgresAdmissionCore
            .commit_runtime_agent_state(&request)
            .expect_err("retired receiptRefs must not satisfy Rust Agentgres admission");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_agent_state_commit_rejects_mismatched_agent_id() {
        let mut request = runtime_agent_state_commit();
        request.agent["id"] = json!("agent_other");

        let error = AgentgresAdmissionCore
            .commit_runtime_agent_state(&request)
            .expect_err("agent payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_memory_record_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_memory_state(&runtime_memory_state_commit())
            .expect("runtime memory record state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_MEMORY_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.memory_state_kind, "record");
        assert_eq!(record.state_id, "memory_1");
        assert_eq!(record.operation_kind, "memory.write");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(record.record.record_path, "memory-records/memory_1.json");
        assert_eq!(
            record.record.object_ref,
            "agentgres://runtime-state/memory/record/memory_1/records/memory-records/memory_1.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://runtime/memory/record/memory_1/records/memory-records/memory_1.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_memory"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn commits_runtime_memory_policy_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_memory_state(&runtime_memory_policy_state_commit())
            .expect("runtime memory policy state committed");

        assert_eq!(record.memory_state_kind, "policy");
        assert_eq!(record.state_id, "thread_thread_1");
        assert_eq!(record.operation_kind, "memory.policy");
        assert_eq!(
            record.record.record_path,
            "memory-policies/thread_thread_1.json"
        );
        assert_eq!(
            record.record.object_ref,
            "agentgres://runtime-state/memory/policy/thread_thread_1/records/memory-policies/thread_thread_1.json"
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_memory_policy"]);
    }

    #[test]
    fn runtime_memory_state_commit_requires_receipts() {
        let mut request = runtime_memory_state_commit();
        request.payload["receipt_refs"] = json!([]);

        let error = AgentgresAdmissionCore
            .commit_runtime_memory_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_memory_state_commit_rejects_retired_receipt_refs_alias() {
        let mut request = runtime_memory_state_commit();
        request.payload["receipt_refs"] = json!([]);
        request.payload["receiptRefs"] = json!(["receipt_memory_retired"]);

        let error = AgentgresAdmissionCore
            .commit_runtime_memory_state(&request)
            .expect_err("retired receiptRefs must not satisfy Rust Agentgres admission");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_memory_state_commit_rejects_mismatched_payload_id() {
        let mut request = runtime_memory_state_commit();
        request.payload["id"] = json!("memory_other");

        let error = AgentgresAdmissionCore
            .commit_runtime_memory_state(&request)
            .expect_err("memory payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_subagent_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_subagent_state(&runtime_subagent_state_commit())
            .expect("runtime subagent state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_SUBAGENT_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.subagent_id, "subagent_1");
        assert_eq!(record.operation_kind, "subagent.wait");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(record.record.record_path, "subagents/subagent_1.json");
        assert_eq!(
            record.record.object_ref,
            "agentgres://runtime-state/subagents/subagent_1/records/subagents/subagent_1.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://runtime/subagents/subagent_1/records/subagents/subagent_1.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_subagent"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_subagent_state_commit_requires_receipts() {
        let mut request = runtime_subagent_state_commit();
        request.subagent["receipt_refs"] = json!([]);

        let error = AgentgresAdmissionCore
            .commit_runtime_subagent_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_subagent_state_commit_rejects_retired_receipt_refs_alias() {
        let mut request = runtime_subagent_state_commit();
        request.subagent["receipt_refs"] = json!([]);
        request.subagent["receiptRefs"] = json!(["receipt_subagent_retired"]);

        let error = AgentgresAdmissionCore
            .commit_runtime_subagent_state(&request)
            .expect_err("retired receiptRefs must not satisfy Rust Agentgres admission");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_subagent_state_commit_rejects_mismatched_subagent_id() {
        let mut request = runtime_subagent_state_commit();
        request.subagent["subagent_id"] = json!("subagent_other");

        let error = AgentgresAdmissionCore
            .commit_runtime_subagent_state(&request)
            .expect_err("subagent payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_artifact_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_artifact_state(&runtime_artifact_state_commit())
            .expect("runtime artifact state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_ARTIFACT_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.artifact_id, "artifact_1");
        assert_eq!(record.operation_kind, "artifact.coding_tool_draft");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(record.record.record_path, "artifacts/artifact_1.json");
        assert_eq!(
            record.record.object_ref,
            "agentgres://runtime-state/artifacts/artifact_1/records/artifacts/artifact_1.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://runtime/artifacts/artifact_1/records/artifacts/artifact_1.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_artifact"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_artifact_state_commit_requires_receipts() {
        let mut request = runtime_artifact_state_commit();
        request.artifact["receipt_id"] = json!("");

        let error = AgentgresAdmissionCore
            .commit_runtime_artifact_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_artifact_state_commit_rejects_retired_receipt_refs_alias() {
        let mut request = runtime_artifact_state_commit();
        request.artifact["receipt_refs"] = json!([]);
        request.artifact["receipt_id"] = json!("");
        request.artifact["receiptRefs"] = json!(["receipt_artifact_retired"]);

        let error = AgentgresAdmissionCore
            .commit_runtime_artifact_state(&request)
            .expect_err("retired receiptRefs must not satisfy Rust Agentgres admission");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_artifact_state_commit_rejects_mismatched_artifact_id() {
        let mut request = runtime_artifact_state_commit();
        request.artifact["id"] = json!("artifact_other");

        let error = AgentgresAdmissionCore
            .commit_runtime_artifact_state(&request)
            .expect_err("artifact payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_model_mount_record_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_model_mount_record_state(&runtime_model_mount_record_state_commit())
            .expect("runtime model-mount record state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.record_dir, "provider-health");
        assert_eq!(record.record_id, "health.provider_openai");
        assert_eq!(record.operation_kind, "model_mount.provider_health.write");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(
            record.record.record_path,
            "provider-health/health.provider_openai.json"
        );
        assert_eq!(
            record.record.object_ref,
            "agentgres://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://model-mounting/records/provider-health/health.provider_openai/records/provider-health/health.provider_openai.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_provider_health"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_model_mount_record_state_commit_requires_receipts() {
        let mut request = runtime_model_mount_record_state_commit();
        request.record["receipt_id"] = json!("");

        let error = AgentgresAdmissionCore
            .commit_runtime_model_mount_record_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_model_mount_record_state_commit_rejects_retired_receipt_refs_alias() {
        let mut request = runtime_model_mount_record_state_commit();
        request.record["receipt_refs"] = json!([]);
        request.record["receipt_id"] = json!("");
        request.record["receiptRefs"] = json!(["receipt_provider_health_retired"]);

        let error = AgentgresAdmissionCore
            .commit_runtime_model_mount_record_state(&request)
            .expect_err("retired receiptRefs must not satisfy Rust Agentgres admission");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn runtime_model_mount_record_state_commit_rejects_mismatched_record_id() {
        let mut request = runtime_model_mount_record_state_commit();
        request.record["id"] = json!("health.other");

        let error = AgentgresAdmissionCore
            .commit_runtime_model_mount_record_state(&request)
            .expect_err("record payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn commits_runtime_model_mount_receipt_state_with_storage_admission() {
        let record = AgentgresAdmissionCore
            .commit_runtime_model_mount_receipt_state(&runtime_model_mount_receipt_state_commit())
            .expect("runtime model-mount receipt state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_MODEL_MOUNT_RECEIPT_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.receipt_id, "receipt_model_invocation");
        assert_eq!(record.operation_kind, "model_mount.receipt.write");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(
            record.record.record_path,
            "receipts/receipt_model_invocation.json"
        );
        assert_eq!(
            record.record.object_ref,
            "agentgres://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json"
        );
        assert_eq!(
            record.record.payload_refs,
            vec!["payload://model-mounting/receipts/receipt_model_invocation/records/receipts/receipt_model_invocation.json"]
        );
        assert_eq!(record.record.receipt_refs, vec!["receipt_model_invocation"]);
        assert!(record
            .record
            .admission
            .admission_hash
            .starts_with("sha256:"));
    }

    #[test]
    fn runtime_model_mount_receipt_state_commit_ignores_retired_receipt_refs_alias() {
        let mut request = runtime_model_mount_receipt_state_commit();
        request.receipt["receipt_refs"] = json!([]);
        request.receipt["receiptRefs"] = json!(["receipt_model_invocation_retired"]);

        let record = AgentgresAdmissionCore
            .commit_runtime_model_mount_receipt_state(&request)
            .expect("canonical receipt id satisfies Rust Agentgres admission");

        assert_eq!(record.record.receipt_refs, vec!["receipt_model_invocation"]);
    }

    #[test]
    fn runtime_model_mount_receipt_state_commit_requires_receipts() {
        let mut request = runtime_model_mount_receipt_state_commit();
        request.receipt["id"] = Value::Null;

        let error = AgentgresAdmissionCore
            .commit_runtime_model_mount_receipt_state(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingField("receipt.id"));
    }

    #[test]
    fn runtime_model_mount_receipt_state_commit_rejects_mismatched_receipt_id() {
        let mut request = runtime_model_mount_receipt_state_commit();
        request.receipt["id"] = json!("receipt_other");

        let error = AgentgresAdmissionCore
            .commit_runtime_model_mount_receipt_state(&request)
            .expect_err("receipt payload id must match request id");

        assert_eq!(
            error,
            AgentgresAdmissionError::RuntimeStateRecordAgentIdMismatch
        );
    }

    #[test]
    fn plans_runtime_state_persistence_with_materialization_and_storage_write_set() {
        let record = AgentgresAdmissionCore
            .plan_runtime_state_persistence(&runtime_state_persistence())
            .expect("runtime state persistence planned");

        assert_eq!(
            record.schema_version,
            RUNTIME_STATE_PERSISTENCE_SCHEMA_VERSION
        );
        assert_eq!(record.run_id, "run_1");
        assert!(record.persistence_hash.starts_with("sha256:"));
        assert_eq!(record.materialization.records.len(), 14);
        assert_eq!(record.storage_write_set.records.len(), 14);
        assert_eq!(
            record.storage_write_set.records[0].record_path,
            "runs/run_1.json"
        );
        assert_eq!(
            record.storage_write_set.records[1].object_ref,
            "agentgres://runtime-state/runs/run_1/records/tasks/run_1.json"
        );
        assert_eq!(
            record.storage_write_set.records[1].payload_refs,
            vec!["payload://runtime/runs/run_1/records/tasks/run_1.json"]
        );
        assert_eq!(
            record.storage_write_set.records[1].admission.receipt_refs,
            vec!["receipt_policy", "receipt_authority"]
        );
        assert_eq!(
            record.materialization.records[13].payload["agentgresTransition"]["resulting_head"],
            json!("agentgres://runtime-state/runs/run_1/head/mock")
        );
    }

    #[test]
    fn runtime_state_persistence_requires_receipts() {
        let mut request = runtime_state_persistence();
        request.receipt_refs.clear();
        let error = AgentgresAdmissionCore
            .plan_runtime_state_persistence(&request)
            .expect_err("receipt refs are required");

        assert_eq!(error, AgentgresAdmissionError::MissingReceiptRefs);
    }

    #[test]
    fn commits_runtime_run_state_with_rust_derived_transition_and_persistence() {
        let record = AgentgresAdmissionCore
            .commit_runtime_run_state(&runtime_run_state_commit())
            .expect("runtime run state committed");

        assert_eq!(
            record.schema_version,
            RUNTIME_RUN_STATE_COMMIT_SCHEMA_VERSION
        );
        assert_eq!(record.run_id, "run_1");
        assert!(record.commit_hash.starts_with("sha256:"));
        assert_eq!(
            record.transition.expected_heads,
            vec!["agentgres://runtime-state/runs/run_1/head/0"]
        );
        assert!(record.transition.state_root_before.starts_with("sha256:"));
        assert_eq!(record.transition.projection_watermark, "runtime-state:1");
        assert_eq!(
            record.transition.receipt_refs,
            vec!["receipt_policy", "receipt_authority"]
        );
        assert_eq!(record.transition.artifact_refs, vec!["artifact_1"]);
        assert_eq!(
            record.transition.payload_refs,
            vec!["payload://runtime/runs/run_1"]
        );
        assert_eq!(
            record.persistence.storage_write_set.records[1].object_ref,
            "agentgres://runtime-state/runs/run_1/records/agents/agent_1.json"
        );
        assert_eq!(
            record.persistence.storage_write_set.records[2].object_ref,
            "agentgres://runtime-state/runs/run_1/records/tasks/run_1.json"
        );
        assert_eq!(
            record.persistence.materialization.records[14].payload["agentgresTransition"]
                ["transition_hash"],
            json!(record.transition.transition_hash)
        );
    }

    #[test]
    fn commits_runtime_run_state_from_previous_transition_head() {
        let mut request = runtime_run_state_commit();
        request.operation_kind = "run.cancel".to_string();
        request.previous_transition = Some(json!({
            "state_root_after": "sha256:previous-state-root",
            "resulting_head": "agentgres://runtime-state/runs/run_1/head/previous"
        }));

        let record = AgentgresAdmissionCore
            .commit_runtime_run_state(&request)
            .expect("runtime run state committed");

        assert_eq!(
            record.transition.expected_heads,
            vec!["agentgres://runtime-state/runs/run_1/head/previous"]
        );
        assert_eq!(
            record.transition.state_root_before,
            "sha256:previous-state-root"
        );
        assert!(record
            .transition
            .operation_ref
            .contains("/operations/run.cancel_"));
    }
}
