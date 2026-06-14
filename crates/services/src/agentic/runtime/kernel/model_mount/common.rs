use sha2::{Digest, Sha256};

pub const MODEL_MOUNT_RUNTIME_SCHEMA_VERSION: &str = "ioi.model-mounting.runtime.v1";
pub const MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION: &str = "ioi.model_mount.route_decision.v1";
pub const MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION: &str =
    "ioi.model_mount.invocation_admission.v1";
pub const MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_execution.v1";
pub const MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_invocation.v1";
pub const MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_stream_invocation.v1";
pub const MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_lifecycle.v1";
pub const MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_lifecycle_plan.v1";
pub const MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_inventory.v1";
pub const MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION: &str =
    "ioi.model_mount.instance_lifecycle.v1";
pub const MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION: &str = "ioi.model_mount.provider_result.v1";
pub const MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.backend_process_plan.v1";
pub const MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION: &str =
    "ioi.model_mount.backend_lifecycle.v1";
pub const MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.backend_lifecycle_plan.v1";
pub const MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION: &str = "ioi.model_mount.server_control.v1";
pub const MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.server_control_plan.v1";
pub const MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION: &str = "ioi.model_mount.runtime_engine.v1";
pub const MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.runtime_engine_plan.v1";
pub const MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION: &str = "ioi.model_mount.runtime_survey.v1";
pub const MODEL_MOUNT_RUNTIME_SURVEY_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.runtime_survey_plan.v1";
pub const MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.model_mount.tokenizer_required.v1";
pub const MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.model_mount.tokenizer_required_result.v1";
pub const MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION: &str = "ioi.model_mount.tokenizer.v1";
pub const MODEL_MOUNT_TOKENIZER_PLAN_SCHEMA_VERSION: &str = "ioi.model_mount.tokenizer_plan.v1";
pub const MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION: &str =
    "ioi.model_mount.route_control_required.v1";
pub const MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION: &str =
    "ioi.model_mount.route_control_required_result.v1";
pub const MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION: &str = "ioi.model_mount.route_control.v1";
pub const MODEL_MOUNT_ROUTE_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.route_control_plan.v1";
pub const MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION: &str =
    "ioi.model_mount.accepted_receipt_head.v1";
pub const MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION: &str =
    "ioi.model_mount.accepted_receipt_transition.v1";
pub const MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION: &str =
    "ioi.model_mount.conversation_state.v1";
pub const MODEL_MOUNT_CONVERSATION_STATE_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.conversation_state_plan.v1";
pub const MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION: &str =
    "ioi.model_mount.stream_completion.v1";
pub const MODEL_MOUNT_STREAM_COMPLETION_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.stream_completion_plan.v1";
pub const MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION: &str = "ioi.model_mount.stream_cancel.v1";
pub const MODEL_MOUNT_STREAM_CANCEL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.stream_cancel_plan.v1";
pub const MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION: &str =
    "ioi.model_mount.catalog_provider_control.v1";
pub const MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.catalog_provider_control_plan.v1";
pub const MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION: &str = "ioi.model_mount.provider_control.v1";
pub const MODEL_MOUNT_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.provider_control_plan.v1";
pub const MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION: &str =
    "ioi.model_mount.capability_token_control.v1";
pub const MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.capability_token_control_plan.v1";
pub const MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION: &str = "ioi.model_mount.vault_control.v1";
pub const MODEL_MOUNT_VAULT_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.vault_control_plan.v1";
pub const MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION: &str = "ioi.model_mount.receipt_gate.v1";
pub const MODEL_MOUNT_RECEIPT_GATE_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.receipt_gate_plan.v1";
pub const MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION: &str =
    "ioi.model_mount.artifact_endpoint.v1";
pub const MODEL_MOUNT_ARTIFACT_ENDPOINT_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.artifact_endpoint_plan.v1";
pub const MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION: &str = "ioi.model_mount.storage_control.v1";
pub const MODEL_MOUNT_STORAGE_CONTROL_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.storage_control_plan.v1";
pub const MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION: &str = "ioi.model_mount.mcp_workflow.v1";
pub const MODEL_MOUNT_MCP_WORKFLOW_PLAN_SCHEMA_VERSION: &str =
    "ioi.model_mount.mcp_workflow_plan.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelMountError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingReceiptRef,
    MissingRouteReceiptRef,
    MissingInvocationReceiptRef,
    MissingProviderExecutionRouteReceiptRef,
    MissingProviderExecutionAdmission,
    ProviderExecutionHashMismatch,
    ProviderExecutionRefMismatch,
    ProviderResultOutputHashMismatch,
    UnsupportedProviderResultBackend,
    UnsupportedProviderInvocationBackend,
    UnsupportedProviderLifecycleAction,
    UnsupportedProviderLifecycleBackend,
    UnsupportedProviderInventoryAction,
    UnsupportedProviderInventoryBackend,
    UnsupportedInstanceLifecycleAction,
    UnsupportedInstanceLifecycleBackend,
    UnsupportedBackendProcessKind,
    UnsupportedBackendLifecycleOperation,
    UnsupportedRouteControlKind,
    UnsupportedTokenizerOperation,
    UnsupportedConversationOperation,
    UnsupportedCatalogProviderControlOperation,
    UnsupportedProviderControlOperation,
    ProviderControlRetiredAlias,
    ProviderControlPlaintextMaterial,
    UnsupportedCapabilityTokenControlOperation,
    UnsupportedVaultControlOperation,
    UnsupportedServerControlOperation,
    UnsupportedRuntimeEngineOperation,
    UnsupportedRuntimeSurveyOperation,
    UnsupportedReceiptGateOperation,
    UnsupportedArtifactEndpointOperation,
    UnsupportedStorageControlOperation,
    UnsupportedMcpWorkflowOperation,
    CatalogProviderNotConfigurable,
    CapabilityTokenNotFound,
    CapabilityTokenUnauthorized,
    NoRouteCandidate,
    InstanceLifecycleStatusMismatch,
    InvalidAcceptedReceiptSequence,
    InvalidAcceptedReceiptTransitionHash,
    StreamProviderInvocationUnsupported,
    UnresolvedAutoModel,
    PrivateWorkspaceMissingCustodyRef,
    PrivateWorkspacePlaintextNotAllowed,
    RuntimeSurveyProjectionFailed(String),
    HashFailed(String),
}

pub(crate) fn option_trimmed(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn push_unique_ref(refs: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !refs.iter().any(|existing| existing == value) {
        refs.push(value.to_string());
    }
}

pub(crate) fn validate_receipt_refs(receipt_refs: &[String]) -> Result<(), ModelMountError> {
    if receipt_refs.iter().all(|value| value.trim().is_empty()) {
        return Err(ModelMountError::MissingReceiptRef);
    }
    for receipt_ref in receipt_refs {
        require_non_empty("receipt_refs[]", receipt_ref)?;
    }
    Ok(())
}

pub(crate) fn require_non_empty(field: &'static str, value: &str) -> Result<(), ModelMountError> {
    if value.trim().is_empty() {
        Err(ModelMountError::MissingField(field))
    } else {
        Ok(())
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> Result<String, ModelMountError> {
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn trimmed_string(value: &str, field: &'static str) -> Result<String, ModelMountError> {
    non_empty_string(value).ok_or(ModelMountError::MissingField(field))
}

pub(crate) fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
