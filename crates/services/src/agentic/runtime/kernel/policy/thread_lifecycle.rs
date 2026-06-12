use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_DELETE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    LIFECYCLE_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    THREAD_TURN_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedControlKind(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadTurnAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedOperationKind(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum LifecycleAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedOperationKind(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatusStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentDeleteStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeBridgeThreadStartAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeBridgeTurnRunStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SubagentRecordStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MismatchedField {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub control_kind: String,
    pub controls: Value,
    pub event_id: String,
    pub seq: u64,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub workspace_trust_warning_event_id: Option<String>,
    #[serde(default)]
    pub workspace_trust_warning_created_at: Option<String>,
    #[serde(default)]
    pub model_route: Option<Value>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadTurnAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub runtime_profile: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadTurnAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub requested_status: Option<String>,
    #[serde(default)]
    pub requested_operation_kind: Option<String>,
    #[serde(default)]
    pub requested_cwd: Option<String>,
    #[serde(default)]
    pub requested_runtime: Option<String>,
    #[serde(default)]
    pub requested_mode: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadCreateStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
    pub thread: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub agent: Value,
    pub thread: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCreateStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCreateStateUpdateRequest {
    pub schema_version: String,
    pub run: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub run_id: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentStatusStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
    pub status: String,
    pub operation_kind: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentStatusStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub agent_id: String,
    pub updated_at: String,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDeleteStateUpdateRequest {
    pub schema_version: String,
    pub agent: Value,
    pub operation_kind: String,
    pub deleted_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDeleteStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub agent_id: String,
    pub deleted_at: String,
    pub updated_at: String,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub runtime_profile: String,
    pub session_id: String,
    pub bridge_id: String,
    pub status: String,
    pub source: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub bridge_start: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeTurnRunStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub projection: Value,
    pub run: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeTurnRunStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub run_id: String,
    pub agent_id: String,
    pub updated_at: String,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentRecordStateUpdateRequest {
    pub schema_version: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub subagent: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentRecordStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub subagent_id: String,
    pub updated_at: String,
    pub subagent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreadLifecycleCommandError {
    code: &'static str,
    message: String,
}

impl ThreadLifecycleCommandError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    fn from_debug<E: std::fmt::Debug>(code: &'static str, error: E) -> Self {
        Self {
            code,
            message: format!("{error:?}"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ThreadControlAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadControlAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct ThreadTurnAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadTurnAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct LifecycleAdmissionRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: LifecycleAdmissionRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct ThreadCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ThreadCreateStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeThreadStartAgentStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeBridgeTurnRunStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeBridgeTurnRunStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct SubagentRecordStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: SubagentRecordStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct AgentCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: AgentCreateStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct AgentStatusStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: AgentStatusStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct AgentDeleteStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: AgentDeleteStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct RunCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RunCreateStateUpdateRequest,
}

pub fn plan_runtime_bridge_thread_start_agent_state_update_response(
    request: RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = RuntimeBridgeThreadStartAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug(
                "runtime_bridge_thread_start_agent_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_thread_start_agent_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "bridge_start": record.bridge_start.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn plan_runtime_bridge_turn_run_state_update_response(
    request: RuntimeBridgeTurnRunStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = RuntimeBridgeTurnRunStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug(
                "runtime_bridge_turn_run_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_bridge_turn_run_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}

pub fn plan_subagent_record_state_update_response(
    request: SubagentRecordStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = SubagentRecordStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("subagent_record_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_subagent_record_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "subagent": record.subagent.clone(),
    }))
}

pub fn plan_thread_control_agent_state_update_response(
    request: ThreadControlAgentStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = ThreadControlAgentStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug(
                "thread_control_agent_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_thread_control_agent_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "receipt_refs": record.receipt_refs.clone(),
        "policy_decision_refs": record.policy_decision_refs.clone(),
        "control": record.control.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn plan_thread_turn_admission_required_response(
    request: ThreadTurnAdmissionRequiredBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = ThreadTurnAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("thread_turn_admission_required_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_thread_turn_admission_required_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation": record.operation.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub fn plan_lifecycle_admission_required_response(
    request: LifecycleAdmissionRequiredBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = LifecycleAdmissionRequiredCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("lifecycle_admission_required_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_lifecycle_admission_required_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "status_code": record.status_code,
        "code": record.code.clone(),
        "message": record.message.clone(),
        "rust_core_boundary": record.rust_core_boundary.clone(),
        "operation": record.operation.clone(),
        "operation_kind": record.operation_kind.clone(),
        "details": record.details.clone(),
    }))
}

pub fn plan_thread_create_state_update_response(
    request: ThreadCreateStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = ThreadCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("thread_create_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_thread_create_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "thread_id": record.thread_id.clone(),
        "agent_id": record.agent_id.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
        "thread": record.thread.clone(),
    }))
}

pub fn plan_agent_create_state_update_response(
    request: AgentCreateStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = AgentCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("agent_create_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_agent_create_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn plan_agent_status_state_update_response(
    request: AgentStatusStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = AgentStatusStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("agent_status_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_agent_status_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn plan_agent_delete_state_update_response(
    request: AgentDeleteStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = AgentDeleteStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("agent_delete_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_agent_delete_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "deleted_at": record.deleted_at.clone(),
        "updated_at": record.updated_at.clone(),
        "agent": record.agent.clone(),
    }))
}

pub fn plan_run_create_state_update_response(
    request: RunCreateStateUpdateBridgeRequest,
) -> Result<Value, ThreadLifecycleCommandError> {
    let record = RunCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            ThreadLifecycleCommandError::from_debug("run_create_state_update_invalid", error)
        })?;
    Ok(json!({
        "source": "rust_run_create_state_update_command",
        "backend": rust_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "run": record.run.clone(),
    }))
}

fn rust_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
}

#[derive(Debug, Default, Clone)]
pub struct ThreadControlAgentStateUpdateCore;

#[derive(Debug, Default, Clone)]
pub struct LifecycleAdmissionRequiredCore;

impl LifecycleAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &LifecycleAdmissionRequiredRequest,
    ) -> Result<LifecycleAdmissionRequiredRecord, LifecycleAdmissionRequiredError> {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let profile = lifecycle_required_profile(operation.as_str(), operation_kind.as_str())?;
        let evidence_refs = if request.evidence_refs.is_empty() {
            profile.evidence_refs
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": profile.boundary,
            "operation": operation,
            "operation_kind": operation_kind,
            "agent_id": optional_trimmed(request.agent_id.as_deref()),
            "requested_status": optional_trimmed(request.requested_status.as_deref()),
            "requested_operation_kind": optional_trimmed(request.requested_operation_kind.as_deref()),
            "requested_cwd": optional_trimmed(request.requested_cwd.as_deref()),
            "requested_runtime": optional_trimmed(request.requested_runtime.as_deref()),
            "requested_mode": optional_trimmed(request.requested_mode.as_deref()),
            "evidence_refs": evidence_refs,
        });

        Ok(LifecycleAdmissionRequiredRecord {
            schema_version: LIFECYCLE_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_lifecycle_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: profile.code.to_string(),
            message: profile.message.to_string(),
            rust_core_boundary: profile.boundary.to_string(),
            operation,
            operation_kind,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadTurnAdmissionRequiredCore;

impl ThreadTurnAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &ThreadTurnAdmissionRequiredRequest,
    ) -> Result<ThreadTurnAdmissionRequiredRecord, ThreadTurnAdmissionRequiredError> {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let agent_id = optional_trimmed(request.agent_id.as_deref());
        let runtime_profile = optional_trimmed(request.runtime_profile.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            default_thread_turn_evidence_refs(operation.as_str())
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.thread_turn",
            "operation": operation,
            "operation_kind": operation_kind,
            "thread_id": thread_id,
            "agent_id": agent_id,
            "runtime_profile": runtime_profile,
            "evidence_refs": evidence_refs,
        });

        Ok(ThreadTurnAdmissionRequiredRecord {
            schema_version: THREAD_TURN_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_turn_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_thread_turn_rust_core_required".to_string(),
            message: "Thread resume and turn creation require direct Rust daemon-core admission and persistence.".to_string(),
            rust_core_boundary: "runtime.thread_turn".to_string(),
            operation,
            operation_kind,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl ThreadControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadControlAgentStateUpdateRequest,
    ) -> Result<ThreadControlAgentStateUpdateRecord, ThreadControlAgentStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("agent.id"))?;
        let control_kind = normalized_thread_control_kind(request.control_kind.as_str())?;
        let controls = object_value(&request.controls)
            .ok_or(ThreadControlAgentStateUpdateError::MissingField("controls"))?;
        let updated_at = optional_trimmed(request.updated_at.as_deref())
            .or_else(|| optional_trimmed(request.workspace_trust_warning_created_at.as_deref()))
            .unwrap_or_else(|| request.created_at.clone());
        let mut receipt_refs = unique_string_vec(request.receipt_refs.clone());
        let policy_decision_refs = unique_string_vec(request.policy_decision_refs.clone());

        if control_kind != "mode" {
            let model_route = request.model_route.as_ref().and_then(object_value).ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route"),
            )?;
            let model_route_value = Value::Object(model_route.clone());
            let selected_model = optional_json_string(&model_route_value, "selected_model").ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route.selected_model"),
            )?;
            let requested_model_id = optional_json_string(&model_route_value, "requested_model_id")
                .ok_or(ThreadControlAgentStateUpdateError::MissingField(
                    "model_route.requested_model_id",
                ))?;
            let route_id = optional_json_string(&model_route_value, "route_id").ok_or(
                ThreadControlAgentStateUpdateError::MissingField("model_route.route_id"),
            )?;

            agent.insert("modelId".to_string(), Value::String(selected_model));
            agent.insert(
                "requestedModelId".to_string(),
                Value::String(requested_model_id),
            );
            agent.insert("modelRouteId".to_string(), Value::String(route_id));
            insert_optional_string_field(
                &mut agent,
                "modelRouteEndpointId",
                optional_json_string(&model_route_value, "endpoint_id"),
            );
            insert_optional_string_field(
                &mut agent,
                "modelRouteProviderId",
                optional_json_string(&model_route_value, "provider_id"),
            );
            insert_optional_string_field(
                &mut agent,
                "modelRouteReceiptId",
                optional_json_string(&model_route_value, "receipt_id"),
            );
            if let Some(receipt_id) = optional_json_string(&model_route_value, "receipt_id") {
                receipt_refs.push(receipt_id);
            }
            agent.insert(
                "modelRouteDecision".to_string(),
                model_route.get("decision").cloned().unwrap_or(Value::Null),
            );
        }

        let mut receipt_refs = unique_string_vec(receipt_refs);
        if receipt_refs.is_empty() {
            receipt_refs.push(generated_thread_control_receipt_ref(
                &request.thread_id,
                &request.event_id,
                control_kind.as_str(),
            ));
        }
        agent.insert("runtimeControls".to_string(), Value::Object(controls));
        agent.insert("updatedAt".to_string(), Value::String(updated_at.clone()));
        agent.insert(
            "receipt_refs".to_string(),
            string_array_value(&receipt_refs),
        );
        if !policy_decision_refs.is_empty() {
            agent.insert(
                "policy_decision_refs".to_string(),
                string_array_value(&policy_decision_refs),
            );
        }
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
            "workspace_trust_warning_event_id": request.workspace_trust_warning_event_id,
            "receipt_refs": receipt_refs.clone(),
            "policy_decision_refs": policy_decision_refs.clone(),
        });

        Ok(ThreadControlAgentStateUpdateRecord {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at,
            receipt_refs,
            policy_decision_refs,
            control,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct ThreadCreateStateUpdateCore;

impl ThreadCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &ThreadCreateStateUpdateRequest,
    ) -> Result<ThreadCreateStateUpdateRecord, ThreadCreateStateUpdateError> {
        request.validate()?;
        let agent = object_value(&request.agent)
            .ok_or(ThreadCreateStateUpdateError::MissingField("agent"))?;
        let thread = object_value(&request.thread)
            .ok_or(ThreadCreateStateUpdateError::MissingField("thread"))?;
        let agent_value = Value::Object(agent.clone());
        let thread_value = Value::Object(thread.clone());
        let agent_id = optional_json_string(&agent_value, "id")
            .ok_or(ThreadCreateStateUpdateError::MissingField("agent.id"))?;
        let thread_agent_id = optional_json_string(&thread_value, "agent_id").ok_or(
            ThreadCreateStateUpdateError::MissingField("thread.agent_id"),
        )?;
        if thread_agent_id != agent_id {
            return Err(ThreadCreateStateUpdateError::MismatchedField {
                field: "thread.agent_id",
                expected: agent_id,
                actual: thread_agent_id,
            });
        }
        let thread_id = optional_json_string(&thread_value, "thread_id").ok_or(
            ThreadCreateStateUpdateError::MissingField("thread.thread_id"),
        )?;
        let created_at = optional_json_string(&agent_value, "createdAt").ok_or(
            ThreadCreateStateUpdateError::MissingField("agent.createdAt"),
        )?;
        let updated_at = optional_json_string(&agent_value, "updatedAt").ok_or(
            ThreadCreateStateUpdateError::MissingField("agent.updatedAt"),
        )?;

        Ok(ThreadCreateStateUpdateRecord {
            schema_version: THREAD_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "thread.create".to_string(),
            thread_id,
            agent_id,
            created_at,
            updated_at,
            agent: Value::Object(agent),
            thread: Value::Object(thread),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AgentCreateStateUpdateCore;

impl AgentCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &AgentCreateStateUpdateRequest,
    ) -> Result<AgentCreateStateUpdateRecord, AgentCreateStateUpdateError> {
        request.validate()?;
        let agent = object_value(&request.agent)
            .ok_or(AgentCreateStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent.clone());
        let agent_id = optional_json_string(&agent_value, "id")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.id"))?;
        let created_at = optional_json_string(&agent_value, "createdAt")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.createdAt"))?;
        let updated_at = optional_json_string(&agent_value, "updatedAt")
            .ok_or(AgentCreateStateUpdateError::MissingField("agent.updatedAt"))?;

        Ok(AgentCreateStateUpdateRecord {
            schema_version: AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_agent_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "agent.create".to_string(),
            agent_id,
            created_at,
            updated_at,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunCreateStateUpdateCore;

impl RunCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &RunCreateStateUpdateRequest,
    ) -> Result<RunCreateStateUpdateRecord, RunCreateStateUpdateError> {
        request.validate()?;
        let run =
            object_value(&request.run).ok_or(RunCreateStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run.clone());
        let run_id = optional_json_string(&run_value, "id")
            .ok_or(RunCreateStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&run_value, "agentId")
            .ok_or(RunCreateStateUpdateError::MissingField("run.agentId"))?;
        let created_at = optional_json_string(&run_value, "createdAt")
            .ok_or(RunCreateStateUpdateError::MissingField("run.createdAt"))?;
        let updated_at = optional_json_string(&run_value, "updatedAt")
            .ok_or(RunCreateStateUpdateError::MissingField("run.updatedAt"))?;

        Ok(RunCreateStateUpdateRecord {
            schema_version: RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_run_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "run.create".to_string(),
            run_id,
            agent_id,
            created_at,
            updated_at,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AgentStatusStateUpdateCore;

impl AgentStatusStateUpdateCore {
    pub fn plan(
        &self,
        request: &AgentStatusStateUpdateRequest,
    ) -> Result<AgentStatusStateUpdateRecord, AgentStatusStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(AgentStatusStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(AgentStatusStateUpdateError::MissingField("agent.id"))?;
        agent.insert("status".to_string(), Value::String(request.status.clone()));
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.updated_at.clone()),
        );

        Ok(AgentStatusStateUpdateRecord {
            schema_version: AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_agent_status_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            agent_id,
            updated_at: request.updated_at.clone(),
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct AgentDeleteStateUpdateCore;

impl AgentDeleteStateUpdateCore {
    pub fn plan(
        &self,
        request: &AgentDeleteStateUpdateRequest,
    ) -> Result<AgentDeleteStateUpdateRecord, AgentDeleteStateUpdateError> {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(AgentDeleteStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(AgentDeleteStateUpdateError::MissingField("agent.id"))?;
        agent.insert("status".to_string(), Value::String("deleted".to_string()));
        agent.insert(
            "deletedAt".to_string(),
            Value::String(request.deleted_at.clone()),
        );
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.deleted_at.clone()),
        );

        Ok(AgentDeleteStateUpdateRecord {
            schema_version: AGENT_DELETE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_agent_delete_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            agent_id,
            deleted_at: request.deleted_at.clone(),
            updated_at: request.deleted_at.clone(),
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeBridgeThreadStartAgentStateUpdateCore;

impl RuntimeBridgeThreadStartAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeBridgeThreadStartAgentStateUpdateRequest,
    ) -> Result<
        RuntimeBridgeThreadStartAgentStateUpdateRecord,
        RuntimeBridgeThreadStartAgentStateUpdateError,
    > {
        request.validate()?;
        let mut agent = object_value(&request.agent).ok_or(
            RuntimeBridgeThreadStartAgentStateUpdateError::MissingField("agent"),
        )?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id").ok_or(
            RuntimeBridgeThreadStartAgentStateUpdateError::MissingField("agent.id"),
        )?;
        agent.insert(
            "runtimeProfile".to_string(),
            Value::String(request.runtime_profile.clone()),
        );
        agent.insert(
            "runtimeSessionId".to_string(),
            Value::String(request.session_id.clone()),
        );
        agent.insert(
            "runtimeBridgeId".to_string(),
            Value::String(request.bridge_id.clone()),
        );
        agent.insert(
            "runtimeBridgeStatus".to_string(),
            Value::String(request.status.clone()),
        );
        agent.insert(
            "runtimeBridgeSource".to_string(),
            Value::String(request.source.clone()),
        );
        agent.insert("fixtureProfile".to_string(), Value::Null);
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.updated_at.clone()),
        );
        let bridge_start = json!({
            "runtime_profile": request.runtime_profile,
            "session_id": request.session_id,
            "bridge_id": request.bridge_id,
            "status": request.status,
            "source": request.source,
            "updated_at": request.updated_at,
        });

        Ok(RuntimeBridgeThreadStartAgentStateUpdateRecord {
            schema_version: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_bridge_thread_start_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "thread.runtime_bridge.start".to_string(),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at: request.updated_at.clone(),
            bridge_start,
            agent: Value::Object(agent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeBridgeTurnRunStateUpdateCore;

impl RuntimeBridgeTurnRunStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeBridgeTurnRunStateUpdateRequest,
    ) -> Result<RuntimeBridgeTurnRunStateUpdateRecord, RuntimeBridgeTurnRunStateUpdateError> {
        request.validate()?;
        let run = object_value(&request.run)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run.clone());
        let projection = object_value(&request.projection).ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection"),
        )?;
        let projection_value = Value::Object(projection);
        let run_id = optional_json_string(&run_value, "id")
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&run_value, "agentId").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.agentId"),
        )?;
        let updated_at = optional_json_string(&run_value, "updatedAt").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.updatedAt"),
        )?;
        let projection_run_id = optional_json_string(&projection_value, "run_id").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection.run_id"),
        )?;
        if projection_run_id != run_id {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MismatchedField {
                field: "projection.run_id",
                expected: run_id,
                actual: projection_run_id,
            });
        }

        Ok(RuntimeBridgeTurnRunStateUpdateRecord {
            schema_version: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_bridge_turn_run_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "turn.runtime_bridge.submit".to_string(),
            thread_id: request.thread_id.clone(),
            run_id,
            agent_id,
            updated_at,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct SubagentRecordStateUpdateCore;

impl SubagentRecordStateUpdateCore {
    pub fn plan(
        &self,
        request: &SubagentRecordStateUpdateRequest,
    ) -> Result<SubagentRecordStateUpdateRecord, SubagentRecordStateUpdateError> {
        request.validate()?;
        let subagent = object_value(&request.subagent)
            .ok_or(SubagentRecordStateUpdateError::MissingField("subagent"))?;
        let subagent_value = Value::Object(subagent.clone());
        let subagent_id = optional_json_string(&subagent_value, "subagent_id").ok_or(
            SubagentRecordStateUpdateError::MissingField("subagent.subagent_id"),
        )?;
        let updated_at = optional_json_string(&subagent_value, "updated_at").ok_or(
            SubagentRecordStateUpdateError::MissingField("subagent.updated_at"),
        )?;

        Ok(SubagentRecordStateUpdateRecord {
            schema_version: SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_subagent_record_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: request.operation_kind.clone(),
            thread_id: request.thread_id.clone(),
            subagent_id,
            updated_at,
            subagent: Value::Object(subagent),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl ThreadControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadControlAgentStateUpdateError> {
        if self.schema_version != THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        if !self.agent.is_object() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("agent"));
        }
        if !self.controls.is_object() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("controls"));
        }
        let control_kind = normalized_thread_control_kind(self.control_kind.as_str())?;
        if optional_trimmed(Some(self.event_id.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField("event_id"));
        }
        if self.seq == 0 {
            return Err(ThreadControlAgentStateUpdateError::MissingField("seq"));
        }
        if optional_trimmed(Some(self.created_at.as_str())).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "created_at",
            ));
        }
        if control_kind != "mode" && self.model_route.as_ref().and_then(object_value).is_none() {
            return Err(ThreadControlAgentStateUpdateError::MissingField(
                "model_route",
            ));
        }
        Ok(())
    }
}

impl ThreadTurnAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), ThreadTurnAdmissionRequiredError> {
        if self.schema_version != THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ThreadTurnAdmissionRequiredError::InvalidSchemaVersion {
                expected: THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(ThreadTurnAdmissionRequiredError::MissingField("operation"));
        }
        let operation_kind = optional_trimmed(Some(self.operation_kind.as_str())).ok_or(
            ThreadTurnAdmissionRequiredError::MissingField("operation_kind"),
        )?;
        if operation_kind != "thread.resume"
            && operation_kind != "turn.create"
            && operation_kind != "turn.diagnostics_block"
        {
            return Err(ThreadTurnAdmissionRequiredError::UnsupportedOperationKind(
                operation_kind,
            ));
        }
        if optional_trimmed(self.thread_id.as_deref()).is_none() {
            return Err(ThreadTurnAdmissionRequiredError::MissingField("thread_id"));
        }
        Ok(())
    }
}

impl LifecycleAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), LifecycleAdmissionRequiredError> {
        if self.schema_version != LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(LifecycleAdmissionRequiredError::InvalidSchemaVersion {
                expected: LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let operation = optional_trimmed(Some(self.operation.as_str()))
            .ok_or(LifecycleAdmissionRequiredError::MissingField("operation"))?;
        let operation_kind = optional_trimmed(Some(self.operation_kind.as_str())).ok_or(
            LifecycleAdmissionRequiredError::MissingField("operation_kind"),
        )?;
        lifecycle_required_profile(operation.as_str(), operation_kind.as_str())?;
        Ok(())
    }
}

impl ThreadCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), ThreadCreateStateUpdateError> {
        if self.schema_version != THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(ThreadCreateStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(ThreadCreateStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        for field in ["id", "status", "runtime", "cwd", "createdAt", "updatedAt"] {
            if optional_json_string(&agent_value, field).is_none() {
                return Err(ThreadCreateStateUpdateError::MissingField(match field {
                    "id" => "agent.id",
                    "status" => "agent.status",
                    "runtime" => "agent.runtime",
                    "cwd" => "agent.cwd",
                    "createdAt" => "agent.createdAt",
                    "updatedAt" => "agent.updatedAt",
                    _ => "agent",
                }));
            }
        }
        if !agent_value
            .get("runtimeControls")
            .is_some_and(Value::is_object)
        {
            return Err(ThreadCreateStateUpdateError::MissingField(
                "agent.runtimeControls",
            ));
        }
        let thread = object_value(&self.thread)
            .ok_or(ThreadCreateStateUpdateError::MissingField("thread"))?;
        let thread_value = Value::Object(thread);
        for field in [
            "thread_id",
            "agent_id",
            "event_stream_id",
            "status",
            "created_at",
            "updated_at",
        ] {
            if optional_json_string(&thread_value, field).is_none() {
                return Err(ThreadCreateStateUpdateError::MissingField(match field {
                    "thread_id" => "thread.thread_id",
                    "agent_id" => "thread.agent_id",
                    "event_stream_id" => "thread.event_stream_id",
                    "status" => "thread.status",
                    "created_at" => "thread.created_at",
                    "updated_at" => "thread.updated_at",
                    _ => "thread",
                }));
            }
        }
        Ok(())
    }
}

impl AgentCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), AgentCreateStateUpdateError> {
        if self.schema_version != AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(AgentCreateStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(AgentCreateStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        for field in ["id", "status", "runtime", "cwd", "createdAt", "updatedAt"] {
            if optional_json_string(&agent_value, field).is_none() {
                return Err(AgentCreateStateUpdateError::MissingField(match field {
                    "id" => "agent.id",
                    "status" => "agent.status",
                    "runtime" => "agent.runtime",
                    "cwd" => "agent.cwd",
                    "createdAt" => "agent.createdAt",
                    "updatedAt" => "agent.updatedAt",
                    _ => "agent",
                }));
            }
        }
        if !agent_value
            .get("runtimeControls")
            .is_some_and(Value::is_object)
        {
            return Err(AgentCreateStateUpdateError::MissingField(
                "agent.runtimeControls",
            ));
        }
        Ok(())
    }
}

impl RunCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RunCreateStateUpdateError> {
        if self.schema_version != RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RunCreateStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let run = object_value(&self.run).ok_or(RunCreateStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run);
        for field in ["id", "agentId", "status", "mode", "createdAt", "updatedAt"] {
            if optional_json_string(&run_value, field).is_none() {
                return Err(RunCreateStateUpdateError::MissingField(match field {
                    "id" => "run.id",
                    "agentId" => "run.agentId",
                    "status" => "run.status",
                    "mode" => "run.mode",
                    "createdAt" => "run.createdAt",
                    "updatedAt" => "run.updatedAt",
                    _ => "run",
                }));
            }
        }
        if !run_value.get("usage").is_some_and(Value::is_object) {
            return Err(RunCreateStateUpdateError::MissingField("run.usage"));
        }
        if !run_value
            .get("usage_telemetry")
            .is_some_and(Value::is_object)
        {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.usage_telemetry",
            ));
        }
        let trace = run_value
            .get("trace")
            .and_then(Value::as_object)
            .ok_or(RunCreateStateUpdateError::MissingField("run.trace"))?;
        if !trace.get("usage_telemetry").is_some_and(Value::is_object) {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.trace.usage_telemetry",
            ));
        }
        Ok(())
    }
}

impl AgentStatusStateUpdateRequest {
    pub fn validate(&self) -> Result<(), AgentStatusStateUpdateError> {
        if self.schema_version != AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(AgentStatusStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(AgentStatusStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("agent.id"));
        }
        if optional_trimmed(Some(self.status.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("status"));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("operation_kind"));
        }
        if optional_trimmed(Some(self.updated_at.as_str())).is_none() {
            return Err(AgentStatusStateUpdateError::MissingField("updated_at"));
        }
        Ok(())
    }
}

impl AgentDeleteStateUpdateRequest {
    pub fn validate(&self) -> Result<(), AgentDeleteStateUpdateError> {
        if self.schema_version != AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(AgentDeleteStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let agent =
            object_value(&self.agent).ok_or(AgentDeleteStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(AgentDeleteStateUpdateError::MissingField("agent.id"));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(AgentDeleteStateUpdateError::MissingField("operation_kind"));
        }
        if optional_trimmed(Some(self.deleted_at.as_str())).is_none() {
            return Err(AgentDeleteStateUpdateError::MissingField("deleted_at"));
        }
        Ok(())
    }
}

impl RuntimeBridgeThreadStartAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeBridgeThreadStartAgentStateUpdateError> {
        if self.schema_version
            != RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
        {
            return Err(
                RuntimeBridgeThreadStartAgentStateUpdateError::InvalidSchemaVersion {
                    expected: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        if !self.agent.is_object() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "agent",
            ));
        }
        for (field, value) in [
            ("runtime_profile", self.runtime_profile.as_str()),
            ("session_id", self.session_id.as_str()),
            ("bridge_id", self.bridge_id.as_str()),
            ("status", self.status.as_str()),
            ("source", self.source.as_str()),
            ("updated_at", self.updated_at.as_str()),
        ] {
            if optional_trimmed(Some(value)).is_none() {
                return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                    field,
                ));
            }
        }
        let agent_value = Value::Object(object_value(&self.agent).unwrap_or_default());
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(RuntimeBridgeThreadStartAgentStateUpdateError::MissingField(
                "agent.id",
            ));
        }
        Ok(())
    }
}

impl RuntimeBridgeTurnRunStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeBridgeTurnRunStateUpdateError> {
        if self.schema_version != RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeBridgeTurnRunStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                "thread_id",
            ));
        }
        let agent = object_value(&self.agent)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        let agent_id = optional_json_string(&agent_value, "id").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("agent.id"),
        )?;
        let projection = object_value(&self.projection).ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("projection"),
        )?;
        let projection_value = Value::Object(projection);
        let run = object_value(&self.run)
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run"))?;
        let run_value = Value::Object(run);
        for field in ["id", "agentId", "mode", "status", "createdAt", "updatedAt"] {
            if optional_json_string(&run_value, field).is_none() {
                return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                    match field {
                        "id" => "run.id",
                        "agentId" => "run.agentId",
                        "mode" => "run.mode",
                        "status" => "run.status",
                        "createdAt" => "run.createdAt",
                        "updatedAt" => "run.updatedAt",
                        _ => "run",
                    },
                ));
            }
        }
        let run_agent_id = optional_json_string(&run_value, "agentId").unwrap_or_default();
        if run_agent_id != agent_id {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MismatchedField {
                field: "run.agentId",
                expected: agent_id,
                actual: run_agent_id,
            });
        }
        if optional_json_string(&projection_value, "run_id").is_none() {
            return Err(RuntimeBridgeTurnRunStateUpdateError::MissingField(
                "projection.run_id",
            ));
        }
        Ok(())
    }
}

impl SubagentRecordStateUpdateRequest {
    pub fn validate(&self) -> Result<(), SubagentRecordStateUpdateError> {
        if self.schema_version != SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(SubagentRecordStateUpdateError::InvalidSchemaVersion {
                expected: SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !matches!(
            self.operation_kind.as_str(),
            "subagent.spawn"
                | "subagent.wait"
                | "subagent.input"
                | "subagent.resume"
                | "subagent.assign"
                | "subagent.cancel"
        ) {
            return Err(SubagentRecordStateUpdateError::MissingField(
                "operation_kind",
            ));
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(SubagentRecordStateUpdateError::MissingField("thread_id"));
        }
        let subagent = object_value(&self.subagent)
            .ok_or(SubagentRecordStateUpdateError::MissingField("subagent"))?;
        let subagent_value = Value::Object(subagent);
        for field in ["subagent_id", "parent_thread_id", "status", "updated_at"] {
            if optional_json_string(&subagent_value, field).is_none() {
                return Err(SubagentRecordStateUpdateError::MissingField(match field {
                    "subagent_id" => "subagent.subagent_id",
                    "parent_thread_id" => "subagent.parent_thread_id",
                    "status" => "subagent.status",
                    "updated_at" => "subagent.updated_at",
                    _ => "subagent",
                }));
            }
        }
        let parent_thread_id =
            optional_json_string(&subagent_value, "parent_thread_id").unwrap_or_default();
        if parent_thread_id != self.thread_id {
            return Err(SubagentRecordStateUpdateError::MismatchedField {
                field: "subagent.parent_thread_id",
                expected: self.thread_id.clone(),
                actual: parent_thread_id,
            });
        }
        Ok(())
    }
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn object_value(value: &Value) -> Option<serde_json::Map<String, Value>> {
    value.as_object().cloned()
}

fn insert_optional_string_field(
    target: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<String>,
) {
    target.insert(
        key.to_string(),
        value.map(Value::String).unwrap_or(Value::Null),
    );
}

fn string_array_value(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn unique_string_vec(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_string();
        if !unique.contains(&normalized) {
            unique.push(normalized);
        }
    }
    unique
}

fn generated_thread_control_receipt_ref(
    thread_id: &str,
    event_id: &str,
    control_kind: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(thread_id.as_bytes());
    hasher.update(b":");
    hasher.update(event_id.as_bytes());
    hasher.update(b":");
    hasher.update(control_kind.as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::new();
    for byte in digest.iter().take(8) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    format!("receipt_thread_control_{suffix}")
}

fn normalized_thread_control_kind(
    value: &str,
) -> Result<String, ThreadControlAgentStateUpdateError> {
    match optional_trimmed(Some(value))
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "mode" => Ok("mode".to_string()),
        "model" => Ok("model".to_string()),
        "thinking" => Ok("thinking".to_string()),
        other => Err(ThreadControlAgentStateUpdateError::UnsupportedControlKind(
            other.to_string(),
        )),
    }
}

fn default_thread_turn_evidence_refs(operation: &str) -> Vec<String> {
    match operation {
        "thread_resume" => vec![
            "thread_resume_js_state_mutation_retired".to_string(),
            "rust_daemon_core_thread_resume_required".to_string(),
            "agentgres_thread_resume_truth_required".to_string(),
        ],
        "thread_turn_diagnostics_block" => vec![
            "thread_turn_diagnostics_block_js_run_creation_retired".to_string(),
            "rust_daemon_core_thread_turn_create_required".to_string(),
            "agentgres_thread_turn_create_truth_required".to_string(),
        ],
        _ => vec![
            "thread_turn_create_js_run_creation_retired".to_string(),
            "rust_daemon_core_thread_turn_create_required".to_string(),
            "agentgres_thread_turn_create_truth_required".to_string(),
        ],
    }
}

struct LifecycleRequiredProfile {
    code: &'static str,
    message: &'static str,
    boundary: &'static str,
    evidence_refs: Vec<String>,
}

fn lifecycle_required_profile(
    operation: &str,
    operation_kind: &str,
) -> Result<LifecycleRequiredProfile, LifecycleAdmissionRequiredError> {
    match (operation, operation_kind) {
        ("agent_create", "agent.create") => Ok(LifecycleRequiredProfile {
            code: "runtime_agent_create_rust_core_required",
            message: "Agent creation requires direct Rust daemon-core state admission and persistence.",
            boundary: "runtime.agent_create",
            evidence_refs: vec![
                "runtime_agent_create_js_facade_retired".to_string(),
                "rust_daemon_core_agent_create_required".to_string(),
                "agentgres_agent_create_state_truth_required".to_string(),
            ],
        }),
        ("run_create", "run.create") => Ok(LifecycleRequiredProfile {
            code: "runtime_run_create_rust_core_required",
            message: "Run creation requires direct Rust daemon-core state admission and persistence.",
            boundary: "runtime.run_create",
            evidence_refs: vec![
                "runtime_run_create_js_facade_retired".to_string(),
                "rust_daemon_core_run_create_required".to_string(),
                "agentgres_run_create_state_truth_required".to_string(),
            ],
        }),
        ("thread_create", "thread.create") => Ok(LifecycleRequiredProfile {
            code: "runtime_thread_create_rust_core_required",
            message: "Thread creation requires direct Rust daemon-core state admission and persistence.",
            boundary: "runtime.thread_create",
            evidence_refs: vec![
                "runtime_thread_create_js_facade_retired".to_string(),
                "rust_daemon_core_thread_create_required".to_string(),
                "agentgres_thread_create_state_truth_required".to_string(),
            ],
        }),
        ("agent_status_control", "agent_status_update") => Ok(LifecycleRequiredProfile {
            code: "runtime_agent_status_control_rust_core_required",
            message: "Agent lifecycle/status control requires direct Rust daemon-core admission and projection.",
            boundary: "runtime.agent_status_control",
            evidence_refs: vec![
                "runtime_agent_status_control_js_facade_retired".to_string(),
                "runtime_agent_archive_js_facade_retired".to_string(),
                "runtime_agent_unarchive_js_facade_retired".to_string(),
                "runtime_agent_resume_js_facade_retired".to_string(),
                "runtime_agent_close_js_facade_retired".to_string(),
                "runtime_agent_reload_js_facade_retired".to_string(),
                "rust_daemon_core_agent_status_control_required".to_string(),
                "agentgres_agent_status_state_truth_required".to_string(),
            ],
        }),
        ("agent_delete", "agent_deletion") => Ok(LifecycleRequiredProfile {
            code: "runtime_agent_delete_rust_core_required",
            message: "Permanent agent deletion requires direct Rust daemon-core admission and persistence.",
            boundary: "runtime.agent_delete",
            evidence_refs: vec![
                "runtime_agent_delete_js_facade_retired".to_string(),
                "rust_daemon_core_agent_delete_required".to_string(),
                "agentgres_agent_delete_state_truth_required".to_string(),
            ],
        }),
        _ => Err(LifecycleAdmissionRequiredError::UnsupportedOperationKind(
            operation_kind.to_string(),
        )),
    }
}

fn json_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    json_string_value(value, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread_control_agent_state_update_request(
        control_kind: &str,
    ) -> ThreadControlAgentStateUpdateRequest {
        ThreadControlAgentStateUpdateRequest {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "modelId": "previous-model",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest",
                    "model": {
                        "id": "auto",
                        "routeId": "route.local-first"
                    }
                }
            }),
            control_kind: control_kind.to_string(),
            controls: json!({
                "mode": "review",
                "approvalMode": "human_required",
                "model": {
                    "id": "auto",
                    "routeId": "route.local-first",
                    "selectedModel": "local-model",
                    "endpointId": "endpoint_1",
                    "providerId": "provider_1",
                    "receiptId": "receipt_route_1"
                },
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            event_id: "evt_thread_control".to_string(),
            seq: 7,
            created_at: "2026-06-06T05:00:00.000Z".to_string(),
            updated_at: None,
            workspace_trust_warning_event_id: None,
            workspace_trust_warning_created_at: None,
            model_route: Some(json!({
                "requested_model_id": "auto",
                "selected_model": "local-model",
                "route_id": "route.local-first",
                "endpoint_id": "endpoint_1",
                "provider_id": "provider_1",
                "receipt_id": "receipt_route_1",
                "decision": {
                    "route_id": "route.local-first",
                    "workflow_node_id": "runtime.model-router.custom"
                }
            })),
            receipt_refs: vec![],
            policy_decision_refs: vec![],
        }
    }

    fn agent_create_state_update_request() -> AgentCreateStateUpdateRequest {
        AgentCreateStateUpdateRequest {
            schema_version: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_create_one",
                "status": "active",
                "runtime": "local",
                "cwd": "/workspace",
                "modelId": "local-model",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest"
                },
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
        }
    }

    fn thread_create_state_update_request() -> ThreadCreateStateUpdateRequest {
        ThreadCreateStateUpdateRequest {
            schema_version: THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_create_one",
                "status": "active",
                "runtime": "local",
                "cwd": "/workspace",
                "modelId": "local-model",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest"
                },
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
            thread: json!({
                "schema_version": "ioi.runtime.thread.v1",
                "thread_id": "thread_create_one",
                "agent_id": "agent_create_one",
                "event_stream_id": "thread_create_one:events",
                "status": "active",
                "created_at": "2026-06-06T05:15:00.000Z",
                "updated_at": "2026-06-06T05:15:00.000Z"
            }),
        }
    }

    fn thread_turn_admission_required_request() -> ThreadTurnAdmissionRequiredRequest {
        ThreadTurnAdmissionRequiredRequest {
            schema_version: THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
            operation: "thread_turn_create".to_string(),
            operation_kind: "turn.create".to_string(),
            thread_id: Some("thread_1".to_string()),
            agent_id: Some("agent_1".to_string()),
            runtime_profile: Some("fixture".to_string()),
            evidence_refs: vec![],
        }
    }

    fn lifecycle_admission_required_request(
        operation: &str,
        operation_kind: &str,
    ) -> LifecycleAdmissionRequiredRequest {
        LifecycleAdmissionRequiredRequest {
            schema_version: LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
            operation: operation.to_string(),
            operation_kind: operation_kind.to_string(),
            agent_id: Some("agent_1".to_string()),
            requested_status: Some("archived".to_string()),
            requested_operation_kind: Some("agent.archive".to_string()),
            requested_cwd: Some("/workspace".to_string()),
            requested_runtime: Some("hosted".to_string()),
            requested_mode: Some("learn".to_string()),
            evidence_refs: vec![],
        }
    }

    fn run_create_state_update_request() -> RunCreateStateUpdateRequest {
        RunCreateStateUpdateRequest {
            schema_version: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            run: json!({
                "id": "run_create_one",
                "agentId": "agent_create_one",
                "status": "completed",
                "mode": "send",
                "createdAt": "2026-06-06T05:16:00.000Z",
                "updatedAt": "2026-06-06T05:16:00.000Z",
                "usage": {
                    "total_tokens": 7
                },
                "usage_telemetry": {
                    "total_tokens": 7
                },
                "trace": {
                    "usage_telemetry": {
                        "total_tokens": 7
                    }
                }
            }),
        }
    }

    fn agent_status_state_update_request() -> AgentStatusStateUpdateRequest {
        AgentStatusStateUpdateRequest {
            schema_version: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_status_one",
                "status": "active",
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
            status: "archived".to_string(),
            operation_kind: "agent.archive".to_string(),
            updated_at: "2026-06-06T06:25:00.000Z".to_string(),
        }
    }

    fn agent_delete_state_update_request() -> AgentDeleteStateUpdateRequest {
        AgentDeleteStateUpdateRequest {
            schema_version: AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent: json!({
                "id": "agent_delete_one",
                "status": "active",
                "createdAt": "2026-06-06T05:15:00.000Z",
                "updatedAt": "2026-06-06T05:15:00.000Z"
            }),
            operation_kind: "agent.delete".to_string(),
            deleted_at: "2026-06-06T06:40:00.000Z".to_string(),
        }
    }

    fn runtime_bridge_thread_start_agent_state_update_request(
    ) -> RuntimeBridgeThreadStartAgentStateUpdateRequest {
        RuntimeBridgeThreadStartAgentStateUpdateRequest {
            schema_version: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "fixtureProfile": "fixture.local",
                "updatedAt": "2026-06-06T05:00:00.000Z"
            }),
            runtime_profile: "runtime_service".to_string(),
            session_id: "session_runtime".to_string(),
            bridge_id: "bridge_runtime".to_string(),
            status: "active".to_string(),
            source: "runtime_service".to_string(),
            updated_at: "2026-06-06T06:15:00.000Z".to_string(),
        }
    }

    fn runtime_bridge_turn_run_state_update_request() -> RuntimeBridgeTurnRunStateUpdateRequest {
        RuntimeBridgeTurnRunStateUpdateRequest {
            schema_version: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace"
            }),
            projection: json!({
                "run_id": "run_runtime_bridge",
                "turn_id": "turn_runtime_bridge"
            }),
            run: json!({
                "id": "run_runtime_bridge",
                "agentId": "agent_1",
                "mode": "send",
                "status": "completed",
                "createdAt": "2026-06-06T06:34:00.000Z",
                "updatedAt": "2026-06-06T06:35:00.000Z"
            }),
        }
    }

    fn subagent_record_state_update_request() -> SubagentRecordStateUpdateRequest {
        SubagentRecordStateUpdateRequest {
            schema_version: SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            operation_kind: "subagent.wait".to_string(),
            thread_id: "thread_1".to_string(),
            subagent: json!({
                "schema_version": "ioi.runtime.subagent.v1",
                "object": "ioi.runtime_subagent",
                "subagent_id": "subagent_1",
                "parent_thread_id": "thread_1",
                "status": "completed",
                "lifecycle_status": "completed",
                "updated_at": "2026-06-06T07:04:00.000Z"
            }),
        }
    }

    #[test]
    fn rust_policy_plans_thread_mode_agent_state_update() {
        let mut request = thread_control_agent_state_update_request("mode");
        request.model_route = None;
        request.workspace_trust_warning_event_id = Some("evt_workspace_warning".to_string());
        request.workspace_trust_warning_created_at = Some("2026-06-06T05:00:01.000Z".to_string());

        let record = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect("thread mode agent state update");

        assert_eq!(
            record.schema_version,
            THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.mode");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T05:00:01.000Z");
        assert_eq!(record.control["control_kind"], "mode");
        assert_eq!(record.control["event_id"], "evt_thread_control");
        assert!(record.control.get("controlKind").is_none());
        assert!(record.control.get("eventId").is_none());
        assert!(record.control.get("createdAt").is_none());
        assert_eq!(
            record.control["workspace_trust_warning_event_id"],
            "evt_workspace_warning"
        );
        assert!(record.receipt_refs[0].starts_with("receipt_thread_control_"));
        assert_eq!(
            record.control["receipt_refs"],
            string_array_value(&record.receipt_refs)
        );
        assert_eq!(
            record.agent["receipt_refs"],
            string_array_value(&record.receipt_refs)
        );
        assert!(record.control.get("workspaceTrustWarningEventId").is_none());
        assert!(record.control.get("receiptRefs").is_none());
        assert_eq!(record.agent["runtimeControls"]["mode"], "review");
        assert_eq!(record.agent["updatedAt"], "2026-06-06T05:00:01.000Z");
        assert_eq!(record.agent["modelId"], "previous-model");
    }

    #[test]
    fn rust_policy_plans_thread_model_agent_state_update() {
        let request = thread_control_agent_state_update_request("thinking");

        let record = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect("thread model agent state update");

        assert_eq!(record.operation_kind, "thread.thinking");
        assert_eq!(record.updated_at, "2026-06-06T05:00:00.000Z");
        assert_eq!(
            record.agent["runtimeControls"]["model"]["selectedModel"],
            "local-model"
        );
        assert_eq!(record.receipt_refs, vec!["receipt_route_1".to_string()]);
        assert_eq!(record.agent["receipt_refs"], json!(["receipt_route_1"]));
        assert_eq!(record.agent["modelId"], "local-model");
        assert_eq!(record.agent["requestedModelId"], "auto");
        assert_eq!(record.agent["modelRouteId"], "route.local-first");
        assert_eq!(record.agent["modelRouteEndpointId"], "endpoint_1");
        assert_eq!(record.agent["modelRouteProviderId"], "provider_1");
        assert_eq!(record.agent["modelRouteReceiptId"], "receipt_route_1");
        assert_eq!(
            record.agent["modelRouteDecision"]["workflow_node_id"],
            "runtime.model-router.custom"
        );
    }

    #[test]
    fn rust_policy_shapes_thread_control_agent_state_update_command_response() {
        let response = plan_thread_control_agent_state_update_response(
            ThreadControlAgentStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: thread_control_agent_state_update_request("thinking"),
            },
        )
        .expect("thread control agent state update command response");

        assert_eq!(
            response["source"],
            "rust_thread_control_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.thinking");
        assert_eq!(response["control"]["control_kind"], "thinking");
        assert_eq!(response["control"]["event_id"], "evt_thread_control");
        assert_eq!(response["receipt_refs"], json!(["receipt_route_1"]));
        assert_eq!(
            response["control"]["receipt_refs"],
            json!(["receipt_route_1"])
        );
        for field in [
            "controlKind",
            "eventId",
            "createdAt",
            "workspaceTrustWarningEventId",
            "receiptRefs",
        ] {
            assert!(response["control"].get(field).is_none());
        }
        assert_eq!(
            response["agent"]["runtimeControls"]["model"]["selectedModel"],
            "local-model"
        );
        assert_eq!(response["agent"]["modelId"], "local-model");
        assert_eq!(response["agent"]["modelRouteReceiptId"], "receipt_route_1");
    }

    #[test]
    fn rust_policy_plans_thread_turn_admission_required() {
        let record = ThreadTurnAdmissionRequiredCore
            .plan(&thread_turn_admission_required_request())
            .expect("thread turn admission-required record");

        assert_eq!(
            record.schema_version,
            THREAD_TURN_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "runtime_thread_turn_rust_core_required");
        assert_eq!(record.operation, "thread_turn_create");
        assert_eq!(record.operation_kind, "turn.create");
        assert_eq!(record.details["rust_core_boundary"], "runtime.thread_turn");
        assert_eq!(record.details["thread_id"], "thread_1");
        assert_eq!(record.details["agent_id"], "agent_1");
        assert_eq!(record.details["runtime_profile"], "fixture");
        assert!(record.details["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "thread_turn_create_js_run_creation_retired"));
        for field in [
            "rustCoreBoundary",
            "operationKind",
            "threadId",
            "agentId",
            "runtimeProfile",
            "evidenceRefs",
        ] {
            assert!(record.details.get(field).is_none());
        }
    }

    #[test]
    fn rust_policy_shapes_thread_turn_admission_required_command_response() {
        let response = plan_thread_turn_admission_required_response(
            ThreadTurnAdmissionRequiredBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: thread_turn_admission_required_request(),
            },
        )
        .expect("thread turn admission-required command response");

        assert_eq!(
            response["source"],
            "rust_thread_turn_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "runtime_thread_turn_rust_core_required");
        assert_eq!(response["operation"], "thread_turn_create");
        assert_eq!(response["operation_kind"], "turn.create");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.thread_turn"
        );
        assert_eq!(response["details"]["thread_id"], "thread_1");
        assert_eq!(response["details"]["agent_id"], "agent_1");
        assert_eq!(response["details"]["runtime_profile"], "fixture");
        for field in [
            "rustCoreBoundary",
            "operationKind",
            "threadId",
            "agentId",
            "runtimeProfile",
            "evidenceRefs",
        ] {
            assert!(response["details"].get(field).is_none());
        }
    }

    #[test]
    fn rust_policy_plans_lifecycle_admission_required() {
        let cases = [
            (
                "agent_create",
                "agent.create",
                "runtime_agent_create_rust_core_required",
                "runtime.agent_create",
            ),
            (
                "run_create",
                "run.create",
                "runtime_run_create_rust_core_required",
                "runtime.run_create",
            ),
            (
                "thread_create",
                "thread.create",
                "runtime_thread_create_rust_core_required",
                "runtime.thread_create",
            ),
            (
                "agent_status_control",
                "agent_status_update",
                "runtime_agent_status_control_rust_core_required",
                "runtime.agent_status_control",
            ),
            (
                "agent_delete",
                "agent_deletion",
                "runtime_agent_delete_rust_core_required",
                "runtime.agent_delete",
            ),
        ];

        for (operation, operation_kind, code, boundary) in cases {
            let record = LifecycleAdmissionRequiredCore
                .plan(&lifecycle_admission_required_request(
                    operation,
                    operation_kind,
                ))
                .expect("lifecycle admission-required record");

            assert_eq!(
                record.schema_version,
                LIFECYCLE_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
            );
            assert_eq!(record.status, "rust_core_required");
            assert_eq!(record.status_code, 501);
            assert_eq!(record.code, code);
            assert_eq!(record.rust_core_boundary, boundary);
            assert_eq!(record.operation, operation);
            assert_eq!(record.operation_kind, operation_kind);
            assert_eq!(record.details["rust_core_boundary"], boundary);
            assert_eq!(record.details["agent_id"], "agent_1");
            assert!(record.details["evidence_refs"]
                .as_array()
                .expect("evidence refs")
                .iter()
                .all(Value::is_string));
            for field in [
                "rustCoreBoundary",
                "operationKind",
                "agentId",
                "requestedStatus",
                "requestedOperationKind",
                "requestedCwd",
                "requestedRuntime",
                "requestedMode",
                "evidenceRefs",
            ] {
                assert!(record.details.get(field).is_none());
            }
        }
    }

    #[test]
    fn rust_policy_shapes_lifecycle_admission_required_command_response() {
        let response =
            plan_lifecycle_admission_required_response(LifecycleAdmissionRequiredBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: lifecycle_admission_required_request(
                    "agent_status_control",
                    "agent_status_update",
                ),
            })
            .expect("lifecycle admission-required command response");

        assert_eq!(
            response["source"],
            "rust_lifecycle_admission_required_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "runtime_agent_status_control_rust_core_required"
        );
        assert_eq!(response["operation"], "agent_status_control");
        assert_eq!(response["operation_kind"], "agent_status_update");
        assert_eq!(
            response["details"]["rust_core_boundary"],
            "runtime.agent_status_control"
        );
        assert_eq!(response["details"]["agent_id"], "agent_1");
        assert_eq!(response["details"]["requested_status"], "archived");
        assert_eq!(
            response["details"]["requested_operation_kind"],
            "agent.archive"
        );
        for field in [
            "rustCoreBoundary",
            "operationKind",
            "agentId",
            "requestedStatus",
            "requestedOperationKind",
            "requestedCwd",
            "requestedRuntime",
            "requestedMode",
            "evidenceRefs",
        ] {
            assert!(response["details"].get(field).is_none());
        }
    }

    #[test]
    fn rust_policy_rejects_retired_thread_control_model_route_aliases() {
        let mut request = thread_control_agent_state_update_request("thinking");
        request.model_route = Some(json!({
            "requestedModelId": "auto",
            "selectedModel": "retired-model",
            "routeId": "route.retired",
            "endpointId": "endpoint_retired",
            "providerId": "provider_retired",
            "receiptId": "receipt_retired",
        }));

        let error = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("retired thread-control model-route aliases must not plan state");

        assert_eq!(
            error,
            ThreadControlAgentStateUpdateError::MissingField("model_route.selected_model")
        );
    }

    #[test]
    fn rust_policy_rejects_retired_thread_control_model_route_request_alias() {
        let request: ThreadControlAgentStateUpdateRequest = serde_json::from_value(json!({
            "schema_version": THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
            "thread_id": "thread_1",
            "agent": {
                "id": "agent_1",
                "cwd": "/workspace",
                "runtimeControls": {
                    "mode": "agent",
                    "approvalMode": "suggest"
                }
            },
            "control_kind": "thinking",
            "controls": {
                "mode": "agent",
                "approvalMode": "suggest",
                "model": {
                    "id": "auto",
                    "route_id": "route.local-first"
                }
            },
            "event_id": "evt_thread_control",
            "seq": 7,
            "created_at": "2026-06-06T05:00:00.000Z",
            "modelRoute": {
                "requested_model_id": "auto",
                "selected_model": "retired-model",
                "route_id": "route.retired"
            }
        }))
        .expect("retired alias request still deserializes as unknown input");

        assert!(request.model_route.is_none());
        let error = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("retired modelRoute request alias must not satisfy model_route");

        assert_eq!(
            error,
            ThreadControlAgentStateUpdateError::MissingField("model_route")
        );
    }

    #[test]
    fn rust_policy_plans_agent_create_state_update() {
        let record = AgentCreateStateUpdateCore
            .plan(&agent_create_state_update_request())
            .expect("agent create state update");

        assert_eq!(
            record.schema_version,
            AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "agent.create");
        assert_eq!(record.agent_id, "agent_create_one");
        assert_eq!(record.created_at, "2026-06-06T05:15:00.000Z");
        assert_eq!(record.updated_at, "2026-06-06T05:15:00.000Z");
        assert_eq!(record.agent["runtimeControls"]["mode"], "agent");
    }

    #[test]
    fn rust_policy_shapes_agent_create_state_update_command_response() {
        let response =
            plan_agent_create_state_update_response(AgentCreateStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: agent_create_state_update_request(),
            })
            .expect("agent create state update command response");

        assert_eq!(response["source"], "rust_agent_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.create");
        assert_eq!(response["agent"]["id"], "agent_create_one");
    }

    #[test]
    fn rust_policy_plans_thread_create_state_update() {
        let record = ThreadCreateStateUpdateCore
            .plan(&thread_create_state_update_request())
            .expect("thread create state update");

        assert_eq!(
            record.schema_version,
            THREAD_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.create");
        assert_eq!(record.thread_id, "thread_create_one");
        assert_eq!(record.agent_id, "agent_create_one");
        assert_eq!(record.created_at, "2026-06-06T05:15:00.000Z");
        assert_eq!(record.thread["event_stream_id"], "thread_create_one:events");
    }

    #[test]
    fn rust_policy_shapes_thread_create_state_update_command_response() {
        let response =
            plan_thread_create_state_update_response(ThreadCreateStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: thread_create_state_update_request(),
            })
            .expect("thread create state update command response");

        assert_eq!(
            response["source"],
            "rust_thread_create_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.create");
        assert_eq!(response["thread_id"], "thread_create_one");
        assert_eq!(response["agent"]["id"], "agent_create_one");
        assert_eq!(
            response["thread"]["event_stream_id"],
            "thread_create_one:events"
        );
    }

    #[test]
    fn rust_policy_plans_run_create_state_update() {
        let record = RunCreateStateUpdateCore
            .plan(&run_create_state_update_request())
            .expect("run create state update");

        assert_eq!(
            record.schema_version,
            RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "run.create");
        assert_eq!(record.run_id, "run_create_one");
        assert_eq!(record.agent_id, "agent_create_one");
        assert_eq!(record.created_at, "2026-06-06T05:16:00.000Z");
        assert_eq!(record.run["usage_telemetry"]["total_tokens"], 7);
        assert_eq!(record.run["trace"]["usage_telemetry"]["total_tokens"], 7);
    }

    #[test]
    fn rust_policy_shapes_run_create_state_update_command_response() {
        let response = plan_run_create_state_update_response(RunCreateStateUpdateBridgeRequest {
            backend: Some("rust_policy".to_string()),
            request: run_create_state_update_request(),
        })
        .expect("run create state update command response");

        assert_eq!(response["source"], "rust_run_create_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.create");
        assert_eq!(response["run"]["id"], "run_create_one");
        assert_eq!(
            response["run"]["trace"]["usage_telemetry"]["total_tokens"],
            7
        );
    }

    #[test]
    fn rust_policy_plans_agent_status_state_update() {
        let record = AgentStatusStateUpdateCore
            .plan(&agent_status_state_update_request())
            .expect("agent status state update");

        assert_eq!(
            record.schema_version,
            AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "agent.archive");
        assert_eq!(record.agent_id, "agent_status_one");
        assert_eq!(record.updated_at, "2026-06-06T06:25:00.000Z");
        assert_eq!(record.agent["status"], "archived");
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:25:00.000Z");
    }

    #[test]
    fn rust_policy_shapes_agent_status_state_update_command_response() {
        let response =
            plan_agent_status_state_update_response(AgentStatusStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: agent_status_state_update_request(),
            })
            .expect("agent status state update command response");

        assert_eq!(response["source"], "rust_agent_status_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.archive");
        assert_eq!(response["agent"]["id"], "agent_status_one");
        assert_eq!(response["agent"]["status"], "archived");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:25:00.000Z");
    }

    #[test]
    fn rust_policy_plans_agent_delete_state_update() {
        let record = AgentDeleteStateUpdateCore
            .plan(&agent_delete_state_update_request())
            .expect("agent delete state update");

        assert_eq!(
            record.schema_version,
            AGENT_DELETE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "agent.delete");
        assert_eq!(record.agent_id, "agent_delete_one");
        assert_eq!(record.deleted_at, "2026-06-06T06:40:00.000Z");
        assert_eq!(record.updated_at, "2026-06-06T06:40:00.000Z");
        assert_eq!(record.agent["status"], "deleted");
        assert_eq!(record.agent["deletedAt"], "2026-06-06T06:40:00.000Z");
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:40:00.000Z");
    }

    #[test]
    fn rust_policy_shapes_agent_delete_state_update_command_response() {
        let response =
            plan_agent_delete_state_update_response(AgentDeleteStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: agent_delete_state_update_request(),
            })
            .expect("agent delete state update command response");

        assert_eq!(response["source"], "rust_agent_delete_state_update_command");
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.delete");
        assert_eq!(response["agent"]["id"], "agent_delete_one");
        assert_eq!(response["agent"]["status"], "deleted");
        assert_eq!(response["agent"]["deletedAt"], "2026-06-06T06:40:00.000Z");
    }

    #[test]
    fn rust_policy_plans_runtime_bridge_thread_start_agent_state_update() {
        let record = RuntimeBridgeThreadStartAgentStateUpdateCore
            .plan(&runtime_bridge_thread_start_agent_state_update_request())
            .expect("runtime bridge thread start agent state update");

        assert_eq!(
            record.schema_version,
            RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.runtime_bridge.start");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:15:00.000Z");
        assert_eq!(record.bridge_start["session_id"], "session_runtime");
        assert_eq!(record.bridge_start["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(record.bridge_start.get(field).is_none());
        }
        assert_eq!(record.agent["runtimeProfile"], "runtime_service");
        assert_eq!(record.agent["runtimeSessionId"], "session_runtime");
        assert_eq!(record.agent["runtimeBridgeId"], "bridge_runtime");
        assert_eq!(record.agent["fixtureProfile"], Value::Null);
    }

    #[test]
    fn rust_policy_shapes_runtime_bridge_thread_start_agent_state_update_command_response() {
        let response = plan_runtime_bridge_thread_start_agent_state_update_response(
            RuntimeBridgeThreadStartAgentStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: runtime_bridge_thread_start_agent_state_update_request(),
            },
        )
        .expect("runtime bridge thread start agent state update command response");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_thread_start_agent_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.runtime_bridge.start");
        assert_eq!(response["bridge_start"]["session_id"], "session_runtime");
        assert_eq!(response["bridge_start"]["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(response["bridge_start"].get(field).is_none());
        }
        assert_eq!(response["agent"]["runtimeSessionId"], "session_runtime");
        assert_eq!(response["agent"]["runtimeBridgeId"], "bridge_runtime");
        assert_eq!(response["agent"]["fixtureProfile"], Value::Null);
    }

    #[test]
    fn rust_policy_plans_runtime_bridge_turn_run_state_update() {
        let record = RuntimeBridgeTurnRunStateUpdateCore
            .plan(&runtime_bridge_turn_run_state_update_request())
            .expect("runtime bridge turn run state update");

        assert_eq!(
            record.schema_version,
            RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "turn.runtime_bridge.submit");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.run_id, "run_runtime_bridge");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.updated_at, "2026-06-06T06:35:00.000Z");
        assert_eq!(record.run["id"], "run_runtime_bridge");
    }

    #[test]
    fn rust_policy_shapes_runtime_bridge_turn_run_state_update_command_response() {
        let response = plan_runtime_bridge_turn_run_state_update_response(
            RuntimeBridgeTurnRunStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: runtime_bridge_turn_run_state_update_request(),
            },
        )
        .expect("runtime bridge turn run state update command response");

        assert_eq!(
            response["source"],
            "rust_runtime_bridge_turn_run_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.runtime_bridge.submit");
        assert_eq!(response["run"]["id"], "run_runtime_bridge");
        assert_eq!(response["run"]["agentId"], "agent_1");
    }

    #[test]
    fn rust_policy_plans_subagent_record_state_update() {
        let record = SubagentRecordStateUpdateCore
            .plan(&subagent_record_state_update_request())
            .expect("subagent record state update");

        assert_eq!(
            record.schema_version,
            SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "subagent.wait");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.subagent_id, "subagent_1");
        assert_eq!(record.updated_at, "2026-06-06T07:04:00.000Z");
        assert_eq!(record.subagent["subagent_id"], "subagent_1");
    }

    #[test]
    fn rust_policy_shapes_subagent_record_state_update_command_response() {
        let response =
            plan_subagent_record_state_update_response(SubagentRecordStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: subagent_record_state_update_request(),
            })
            .expect("subagent record state update command response");

        assert_eq!(
            response["source"],
            "rust_subagent_record_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert_eq!(response["subagent"]["subagent_id"], "subagent_1");
    }

    #[test]
    fn rust_policy_rejects_subagent_record_state_update_thread_mismatch() {
        let mut request = subagent_record_state_update_request();
        request.thread_id = "thread_other".to_string();

        let error = SubagentRecordStateUpdateCore
            .plan(&request)
            .expect_err("thread mismatch should be rejected");

        assert_eq!(
            error,
            SubagentRecordStateUpdateError::MismatchedField {
                field: "subagent.parent_thread_id",
                expected: "thread_other".to_string(),
                actual: "thread_1".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_control_agent_state_update_schema() {
        let mut request = thread_control_agent_state_update_request("mode");
        request.schema_version = "legacy.schema".to_string();

        let error = ThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_turn_admission_required_schema() {
        let mut request = thread_turn_admission_required_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ThreadTurnAdmissionRequiredCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ThreadTurnAdmissionRequiredError::InvalidSchemaVersion {
                expected: THREAD_TURN_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_lifecycle_admission_required_schema() {
        let mut request = lifecycle_admission_required_request("agent_create", "agent.create");
        request.schema_version = "legacy.schema".to_string();

        let error = LifecycleAdmissionRequiredCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            LifecycleAdmissionRequiredError::InvalidSchemaVersion {
                expected: LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_agent_create_state_update_schema() {
        let mut request = agent_create_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = AgentCreateStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            AgentCreateStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_thread_create_state_update_schema() {
        let mut request = thread_create_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = ThreadCreateStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            ThreadCreateStateUpdateError::InvalidSchemaVersion {
                expected: THREAD_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_thread_create_agent_mismatch() {
        let mut request = thread_create_state_update_request();
        request.thread["agent_id"] = json!("agent_other");

        let error = ThreadCreateStateUpdateCore
            .plan(&request)
            .expect_err("agent mismatch should fail");

        assert_eq!(
            error,
            ThreadCreateStateUpdateError::MismatchedField {
                field: "thread.agent_id",
                expected: "agent_create_one".to_string(),
                actual: "agent_other".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_run_create_state_update_schema() {
        let mut request = run_create_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = RunCreateStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            RunCreateStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_agent_status_state_update_schema() {
        let mut request = agent_status_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = AgentStatusStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            AgentStatusStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_agent_delete_state_update_schema() {
        let mut request = agent_delete_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = AgentDeleteStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            AgentDeleteStateUpdateError::InvalidSchemaVersion {
                expected: AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_runtime_bridge_thread_start_agent_state_update_schema() {
        let mut request = runtime_bridge_thread_start_agent_state_update_request();
        request.schema_version = "legacy.runtime-bridge-start-state-update".to_string();

        let error = RuntimeBridgeThreadStartAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            RuntimeBridgeThreadStartAgentStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.runtime-bridge-start-state-update".to_string(),
            }
        );
    }

    #[test]
    fn rust_policy_rejects_invalid_runtime_bridge_turn_run_state_update_schema() {
        let mut request = runtime_bridge_turn_run_state_update_request();
        request.schema_version = "legacy.runtime-bridge-turn-run-state-update".to_string();

        let error = RuntimeBridgeTurnRunStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            RuntimeBridgeTurnRunStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.runtime-bridge-turn-run-state-update".to_string(),
            }
        );
    }
}
