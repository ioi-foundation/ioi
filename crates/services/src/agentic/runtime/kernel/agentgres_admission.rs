use super::receipt_binder::StepModuleReceiptBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENTGRES_ADMISSION_SCHEMA_VERSION: &str = "ioi.agentgres_admission.v1";
pub const STORAGE_BACKEND_WRITE_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.storage_backend_write_admission.v1";
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
    StorageBackendWriteMissingAgentgresRef,
    StorageBackendWriteMissingReceipt,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
