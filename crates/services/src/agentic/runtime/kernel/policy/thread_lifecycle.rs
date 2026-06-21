use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::agentic::runtime::kernel::skill_hook_registry::discover_skill_hook_catalog;

use super::{
    AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    AGENT_DELETE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_DELETE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    LIFECYCLE_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    LIFECYCLE_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
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
    RetiredField(&'static str),
    StateDirRequired,
    ReplayReadFailed(String),
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
    RetiredComputerUseProjectionCandidate,
    RetiredSkillHookMaterializationCandidate,
    RetiredRuntimeTaskJobProjectionCandidate,
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
pub enum RuntimeBridgeThreadControlAgentStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    UnsupportedAction(String),
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
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub event_stream_id: Option<String>,
    pub agent: Value,
    pub control_kind: String,
    pub controls: Value,
    pub event_id: String,
    #[serde(default)]
    pub seq: Option<u64>,
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
pub struct RuntimeBridgeThreadControlAgentStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
    pub action: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub updated_at: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBridgeThreadControlAgentStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub thread_id: String,
    pub agent_id: String,
    pub action: String,
    pub updated_at: String,
    pub control: Value,
    pub agent: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBridgeTurnRunStateUpdateRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub agent: Value,
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
        let seq = super::latest_runtime_event_seq_from_state_dir(
            request.state_dir.as_deref(),
            Some(request.thread_id.as_str()),
            request.event_stream_id.as_deref(),
        )
        .map_err(ThreadControlAgentStateUpdateError::ReplayReadFailed)?
            + 1;
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
            "seq": seq,
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
        let mut run =
            object_value(&request.run).ok_or(RunCreateStateUpdateError::MissingField("run"))?;
        materialize_computer_use_run(&mut run)?;
        materialize_runtime_task_job_run(&mut run)?;
        materialize_skill_hook_run(&mut run)?;
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
        remove_runtime_service_agent_aliases(&mut agent);
        agent.insert(
            "runtime_profile".to_string(),
            Value::String(request.runtime_profile.clone()),
        );
        agent.insert(
            "runtime_session_id".to_string(),
            Value::String(request.session_id.clone()),
        );
        agent.insert(
            "runtime_bridge_id".to_string(),
            Value::String(request.bridge_id.clone()),
        );
        agent.insert(
            "runtime_bridge_status".to_string(),
            Value::String(request.status.clone()),
        );
        agent.insert(
            "runtime_bridge_source".to_string(),
            Value::String(request.source.clone()),
        );
        agent.insert("fixture_profile".to_string(), Value::Null);
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
pub struct RuntimeBridgeThreadControlAgentStateUpdateCore;

impl RuntimeBridgeThreadControlAgentStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeBridgeThreadControlAgentStateUpdateRequest,
    ) -> Result<
        RuntimeBridgeThreadControlAgentStateUpdateRecord,
        RuntimeBridgeThreadControlAgentStateUpdateError,
    > {
        request.validate()?;
        let mut agent = object_value(&request.agent)
            .ok_or(RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_id = optional_json_string(&Value::Object(agent.clone()), "id")
            .ok_or(RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("agent.id"))?;
        let action = normalized_runtime_bridge_thread_control_action(request.action.as_str())?;
        let bridge_status = runtime_bridge_thread_status_for_action(action.as_str());
        remove_runtime_service_agent_aliases(&mut agent);
        agent.insert(
            "status".to_string(),
            Value::String(bridge_status.to_string()),
        );
        agent.insert(
            "runtime_bridge_status".to_string(),
            Value::String(bridge_status.to_string()),
        );
        agent.insert(
            "updatedAt".to_string(),
            Value::String(request.updated_at.clone()),
        );

        let evidence_refs = unique_string_vec(request.evidence_refs.clone());
        let control = json!({
            "action": action,
            "reason": optional_trimmed(request.reason.as_deref()),
            "runtime_bridge_status": bridge_status,
            "updated_at": request.updated_at,
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeBridgeThreadControlAgentStateUpdateRecord {
            schema_version: RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_bridge_thread_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "thread.runtime_bridge.control".to_string(),
            thread_id: request.thread_id.clone(),
            agent_id,
            action,
            updated_at: request.updated_at.clone(),
            control,
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
        let run_id = optional_json_string(&run_value, "id")
            .ok_or(RuntimeBridgeTurnRunStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&run_value, "agentId").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.agentId"),
        )?;
        let updated_at = optional_json_string(&run_value, "updatedAt").ok_or(
            RuntimeBridgeTurnRunStateUpdateError::MissingField("run.updatedAt"),
        )?;
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
        if self.seq.is_some() {
            return Err(ThreadControlAgentStateUpdateError::RetiredField("seq"));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(ThreadControlAgentStateUpdateError::StateDirRequired);
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
        if operation_kind != "thread.resume" && operation_kind != "turn.create" {
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

impl RuntimeBridgeThreadControlAgentStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeBridgeThreadControlAgentStateUpdateError> {
        if self.schema_version
            != RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
        {
            return Err(
                RuntimeBridgeThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                    expected:
                        RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.thread_id.as_str())).is_none() {
            return Err(RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("thread_id"));
        }
        let agent = object_value(&self.agent)
            .ok_or(RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("agent"))?;
        let agent_value = Value::Object(agent);
        if optional_json_string(&agent_value, "id").is_none() {
            return Err(RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("agent.id"));
        }
        normalized_runtime_bridge_thread_control_action(self.action.as_str())?;
        if optional_trimmed(Some(self.updated_at.as_str())).is_none() {
            return Err(
                RuntimeBridgeThreadControlAgentStateUpdateError::MissingField("updated_at"),
            );
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
                | "subagent.cancel.propagate"
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

const COMPUTER_USE_CONTRACT_SCHEMA_VERSION: &str = "ioi.computer-use.harness.v1";
const COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.computer-use-run-materialization-request.v1";
const SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.skill-hook-run-materialization-request.v1";

fn materialize_skill_hook_run(
    run: &mut serde_json::Map<String, Value>,
) -> Result<(), RunCreateStateUpdateError> {
    if run.contains_key("activeSkillHookManifest")
        || run.contains_key("hookDryRunPlan")
        || run.contains_key("hookInvocationLedger")
        || run
            .get("trace")
            .and_then(Value::as_object)
            .is_some_and(|trace| {
                trace.contains_key("activeSkillHookManifest")
                    || trace.contains_key("hookDryRunPlan")
                    || trace.contains_key("hookInvocationLedger")
            })
    {
        return Err(RunCreateStateUpdateError::RetiredSkillHookMaterializationCandidate);
    }
    let request_value = match run.remove("skill_hook_materialization_request") {
        Some(Value::Object(request)) => Value::Object(request),
        Some(Value::Null) | None => return Ok(()),
        Some(_) => {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.skill_hook_materialization_request",
            ))
        }
    };
    let request = request_value
        .as_object()
        .ok_or(RunCreateStateUpdateError::MissingField(
            "run.skill_hook_materialization_request",
        ))?;
    let schema_version = optional_json_string(&request_value, "schema_version").ok_or(
        RunCreateStateUpdateError::MissingField(
            "run.skill_hook_materialization_request.schema_version",
        ),
    )?;
    if schema_version != SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION {
        return Err(RunCreateStateUpdateError::InvalidSchemaVersion {
            expected: SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
            actual: schema_version,
        });
    }

    let run_value = Value::Object(run.clone());
    let run_id = optional_json_string(&run_value, "id")
        .ok_or(RunCreateStateUpdateError::MissingField("run.id"))?;
    let agent_id = optional_json_string(&run_value, "agentId")
        .ok_or(RunCreateStateUpdateError::MissingField("run.agentId"))?;
    let workspace_root = optional_json_string(&request_value, "workspace_root")
        .or_else(|| optional_json_string(&run_value, "workspaceRoot"))
        .unwrap_or_else(|| ".".to_string());
    let home_dir = optional_json_string(&request_value, "home_dir")
        .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| workspace_root.clone()));
    let catalog = discover_skill_hook_catalog(&workspace_root, &home_dir);
    let skills = json_array(&catalog["skills"]);
    let hooks = json_array(&catalog["hooks"]);
    let request_options = request.get("request_options").and_then(Value::as_object);
    let agent_options = request.get("agent_options").and_then(Value::as_object);
    let requested_skill_refs = manifest_selection_refs(
        &[request_options, agent_options],
        &[
            "skills",
            "skillIds",
            "skill_ids",
            "skillNames",
            "skill_names",
        ],
    );
    let requested_hook_refs = manifest_selection_refs(
        &[request_options, agent_options],
        &["hooks", "hookIds", "hook_ids", "hookNames", "hook_names"],
    );
    let selected_skills = select_manifest_records(&skills, &requested_skill_refs, "skillHash");
    let enabled_hooks: Vec<Value> = hooks
        .into_iter()
        .filter(|hook| hook.get("enabled").and_then(Value::as_bool) != Some(false))
        .collect();
    let selected_hooks =
        select_manifest_records(&enabled_hooks, &requested_hook_refs, "definitionHash");
    let mut skill_hashes: Vec<String> = selected_skills
        .iter()
        .filter_map(|skill| string_value_from_json(skill, "skillHash"))
        .collect();
    skill_hashes.sort();
    let mut hook_hashes: Vec<String> = selected_hooks
        .iter()
        .filter_map(|hook| string_value_from_json(hook, "definitionHash"))
        .collect();
    hook_hashes.sort();
    let blocked_hooks: Vec<Value> = selected_hooks
        .iter()
        .filter(|hook| {
            hook.get("commandConfigured").and_then(Value::as_bool) == Some(true)
                && (string_array_from_json(hook.get("authorityScopes")).is_empty()
                    || string_array_from_json(hook.get("toolContracts")).is_empty())
        })
        .cloned()
        .collect();
    let mut blocked_hook_ids: Vec<String> = blocked_hooks
        .iter()
        .filter_map(|hook| string_value_from_json(hook, "id"))
        .collect();
    blocked_hook_ids.sort();
    let manifest_payload = json!({
        "skillHashes": skill_hashes,
        "hookHashes": hook_hashes,
        "catalogSkillSetHash": string_value_from_json(&catalog, "activeSkillSetHash").unwrap_or_else(|| sha256_text("")),
        "catalogHookSetHash": string_value_from_json(&catalog, "activeHookSetHash").unwrap_or_else(|| sha256_text("")),
        "blockedHookIds": blocked_hook_ids,
    });
    let manifest_hash = sha256_text(&serde_json::to_string(&manifest_payload).unwrap_or_default());
    let mut validation_issues = Vec::new();
    for record in selected_skills.iter().chain(selected_hooks.iter()) {
        validation_issues.extend(string_array_from_json(
            record
                .get("validation")
                .and_then(|value| value.get("issues")),
        ));
    }
    validation_issues.sort();
    validation_issues.dedup();
    let selected_skill_ids: Vec<String> = selected_skills
        .iter()
        .filter_map(|skill| string_value_from_json(skill, "id"))
        .collect();
    let selected_hook_ids: Vec<String> = selected_hooks
        .iter()
        .filter_map(|hook| string_value_from_json(hook, "id"))
        .collect();
    let mutation_allowed_hook_ids: Vec<String> = selected_hooks
        .iter()
        .filter(|hook| {
            hook.get("commandConfigured").and_then(Value::as_bool) == Some(true)
                && !string_array_from_json(hook.get("authorityScopes")).is_empty()
                && !string_array_from_json(hook.get("toolContracts")).is_empty()
        })
        .filter_map(|hook| string_value_from_json(hook, "id"))
        .collect();
    let manifest_id = format!("skill_hook_manifest_{run_id}_{}", &manifest_hash[..12]);
    let manifest = json!({
        "schemaVersion": "ioi.agent-runtime.active-skill-hook-manifest.v1",
        "object": "ioi.agent_active_skill_hook_manifest",
        "manifestId": manifest_id,
        "runId": run_id,
        "agentId": agent_id,
        "generatedAt": "rust_policy_core",
        "workspace": workspace_root,
        "selectionMode": if requested_skill_refs.is_empty() && requested_hook_refs.is_empty() { "catalog_snapshot_read_only" } else { "explicit_or_configured" },
        "catalog": {
            "schemaVersion": catalog["schemaVersion"],
            "generatedAt": catalog["generatedAt"],
            "status": catalog["status"],
            "activeSkillSetHash": catalog["activeSkillSetHash"],
            "activeHookSetHash": catalog["activeHookSetHash"],
            "skillCount": catalog["skillCount"],
            "hookCount": catalog["hookCount"],
        },
        "activeSkillSetHash": sha256_text(&skill_hashes.join("\n")),
        "activeHookSetHash": sha256_text(&hook_hashes.join("\n")),
        "manifestHash": manifest_hash,
        "selectedSkillIds": selected_skill_ids,
        "selectedHookIds": selected_hook_ids,
        "requestedSkillRefs": requested_skill_refs,
        "requestedHookRefs": requested_hook_refs,
        "skills": selected_skills.iter().map(skill_manifest_record).collect::<Vec<Value>>(),
        "hooks": selected_hooks.iter().map(hook_manifest_record).collect::<Vec<Value>>(),
        "validation": {
            "status": if validation_issues.is_empty() { "pass" } else { "degraded" },
            "issueCount": validation_issues.len(),
            "issues": validation_issues,
        },
        "hookExecution": {
            "enabled": false,
            "disabledReason": "hook_execution_policy_slice_pending",
            "mutationBlockedWithoutDeclaredCapabilities": true,
            "mutationAllowedHookIds": mutation_allowed_hook_ids,
            "mutationBlockedHookIds": blocked_hook_ids,
        },
        "mutationBlockedHookIds": blocked_hook_ids,
        "redaction": {
            "profile": "active_skill_hook_manifest_safe",
            "skillBodiesIncluded": false,
            "hookCommandsIncluded": false,
            "hookCommandsHashed": true,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": [
            "rust_daemon_core_active_skill_hook_manifest",
            "runtime_skill_hook_discovery",
            "prompt_audit",
            "hook_execution_disabled_until_policy",
        ],
    });
    let dry_run_plan = rust_hook_dry_run_plan(&run_id, &manifest);
    let invocation_ledger = rust_hook_invocation_ledger(&run_id, &manifest, &dry_run_plan);
    let skill_hook_receipt = json!({
        "id": format!("receipt_{run_id}_skill_hook_manifest"),
        "kind": "active_skill_hook_manifest",
        "summary": format!(
            "Rust daemon-core recorded active skill/hook manifest with {} skill(s) and {} hook(s).",
            json_array(&manifest["selectedSkillIds"]).len(),
            json_array(&manifest["selectedHookIds"]).len(),
        ),
        "redaction": "redacted",
        "evidenceRefs": [
            manifest["manifestId"].as_str().unwrap_or_default(),
            "runtime_skill_hook_discovery",
            "rust_daemon_core_active_skill_hook_manifest",
            "hook_execution_disabled_until_policy",
        ],
    });
    let hook_dry_run_receipt = json!({
        "id": format!("receipt_{run_id}_hook_dry_run_plan"),
        "kind": "hook_dry_run_plan",
        "summary": format!(
            "Rust daemon-core previewed {} hook(s): {} would run, {} blocked, {} skipped.",
            dry_run_plan["decisionCount"].as_u64().unwrap_or(0),
            dry_run_plan["wouldRunCount"].as_u64().unwrap_or(0),
            dry_run_plan["blockedCount"].as_u64().unwrap_or(0),
            dry_run_plan["skippedCount"].as_u64().unwrap_or(0),
        ),
        "redaction": "redacted",
        "evidenceRefs": [
            dry_run_plan["planId"].as_str().unwrap_or_default(),
            manifest["manifestId"].as_str().unwrap_or_default(),
            "hook_preview_only",
        ],
    });
    let hook_policy_receipt = json!({
        "id": format!("receipt_{run_id}_hook_policy_decision"),
        "kind": "hook_policy_decision",
        "summary": dry_run_plan["policyDecision"]["summary"],
        "redaction": "redacted",
        "evidenceRefs": [
            dry_run_plan["planId"].as_str().unwrap_or_default(),
            "hook_policy_decision",
            "hook_execution_disabled_until_policy",
        ],
    });
    let hook_invocation_receipt = json!({
        "id": format!("receipt_{run_id}_hook_invocation_ledger"),
        "kind": "hook_invocation_ledger",
        "summary": format!(
            "Rust daemon-core recorded {} preview hook invocation(s): {} would run, {} blocked, {} skipped, {} escalated.",
            invocation_ledger["invocationCount"].as_u64().unwrap_or(0),
            invocation_ledger["wouldRunCount"].as_u64().unwrap_or(0),
            invocation_ledger["blockedCount"].as_u64().unwrap_or(0),
            invocation_ledger["skippedCount"].as_u64().unwrap_or(0),
            invocation_ledger["escalationCount"].as_u64().unwrap_or(0),
        ),
        "redaction": "redacted",
        "evidenceRefs": [
            invocation_ledger["ledgerId"].as_str().unwrap_or_default(),
            dry_run_plan["planId"].as_str().unwrap_or_default(),
            manifest["manifestId"].as_str().unwrap_or_default(),
            "hook_invocation_preview_only",
        ],
    });
    let escalation_receipts = rust_hook_escalation_receipts(&invocation_ledger);
    let mut receipts = vec![
        skill_hook_receipt.clone(),
        hook_dry_run_receipt.clone(),
        hook_policy_receipt.clone(),
        hook_invocation_receipt.clone(),
    ];
    receipts.extend(escalation_receipts.clone());
    let events = rust_skill_hook_run_events(
        &run_id,
        &agent_id,
        &manifest,
        &dry_run_plan,
        &invocation_ledger,
        &skill_hook_receipt,
        &hook_dry_run_receipt,
        &hook_policy_receipt,
        &hook_invocation_receipt,
        &escalation_receipts,
    );
    let artifacts = vec![
        json_artifact(
            &run_id,
            "active-skill-hook-manifest.json",
            &skill_hook_receipt,
            &manifest,
        ),
        json_artifact(
            &run_id,
            "hook-dry-run-plan.json",
            &hook_dry_run_receipt,
            &dry_run_plan,
        ),
        json_artifact(
            &run_id,
            "hook-invocations.json",
            &hook_invocation_receipt,
            &invocation_ledger,
        ),
    ];

    run.insert("activeSkillHookManifest".to_string(), manifest.clone());
    run.insert("hookDryRunPlan".to_string(), dry_run_plan.clone());
    run.insert(
        "hookInvocationLedger".to_string(),
        invocation_ledger.clone(),
    );
    append_array_field(run, "receipts", receipts.clone());
    // Splice before the terminal event so a terminal-bearing candidate keeps turn.completed LAST.
    insert_array_field_before_terminal(run, "events", events.clone());
    append_array_field(run, "artifacts", artifacts.clone());
    update_runtime_task_skill_hook_binding(run, &manifest);
    if let Some(trace) = run.get_mut("trace").and_then(Value::as_object_mut) {
        trace.insert("activeSkillHookManifest".to_string(), manifest.clone());
        trace.insert("hookDryRunPlan".to_string(), dry_run_plan.clone());
        trace.insert(
            "hookInvocationLedger".to_string(),
            invocation_ledger.clone(),
        );
        append_array_field(trace, "receipts", receipts);
        insert_array_field_before_terminal(trace, "events", events);
        append_array_field(trace, "artifacts", artifacts);
        if let Some(task_state) = trace.get_mut("taskState").and_then(Value::as_object_mut) {
            append_string_array_field(
                task_state,
                "knownFacts",
                vec![
                    format!(
                        "Rust daemon-core active skill/hook manifest: skills={}, hooks={}, skillSet={}, hookSet={}",
                        json_array(&manifest["selectedSkillIds"]).len(),
                        json_array(&manifest["selectedHookIds"]).len(),
                        manifest["activeSkillSetHash"].as_str().unwrap_or_default().chars().take(12).collect::<String>(),
                        manifest["activeHookSetHash"].as_str().unwrap_or_default().chars().take(12).collect::<String>(),
                    ),
                    format!(
                        "Rust daemon-core hook dry-run plan: wouldRun={}, blocked={}, skipped={}",
                        dry_run_plan["wouldRunCount"].as_u64().unwrap_or(0),
                        dry_run_plan["blockedCount"].as_u64().unwrap_or(0),
                        dry_run_plan["skippedCount"].as_u64().unwrap_or(0),
                    ),
                    format!(
                        "Rust daemon-core hook invocation ledger: invocations={}, wouldRun={}, blocked={}, skipped={}",
                        invocation_ledger["invocationCount"].as_u64().unwrap_or(0),
                        invocation_ledger["wouldRunCount"].as_u64().unwrap_or(0),
                        invocation_ledger["blockedCount"].as_u64().unwrap_or(0),
                        invocation_ledger["skippedCount"].as_u64().unwrap_or(0),
                    ),
                ],
            );
            append_string_array_field(
                task_state,
                "evidenceRefs",
                vec![
                    manifest["manifestId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    dry_run_plan["planId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    invocation_ledger["ledgerId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    "rust_daemon_core_skill_hook_run_materialization".to_string(),
                    "skill_hook_manifest_js_authoring_retired".to_string(),
                ],
            );
        }
        if let Some(prompt_audit) = trace.get_mut("promptAudit").and_then(Value::as_object_mut) {
            prompt_audit.insert(
                "activeSkillHookManifestId".to_string(),
                manifest["manifestId"].clone(),
            );
            prompt_audit.insert(
                "activeSkillSetHash".to_string(),
                manifest["activeSkillSetHash"].clone(),
            );
            prompt_audit.insert(
                "activeHookSetHash".to_string(),
                manifest["activeHookSetHash"].clone(),
            );
            prompt_audit.insert(
                "selectedSkillIds".to_string(),
                manifest["selectedSkillIds"].clone(),
            );
            prompt_audit.insert(
                "selectedHookIds".to_string(),
                manifest["selectedHookIds"].clone(),
            );
            prompt_audit.insert("hookExecutionEnabled".to_string(), Value::Bool(false));
            prompt_audit.insert(
                "hookDryRunPlanId".to_string(),
                dry_run_plan["planId"].clone(),
            );
            prompt_audit.insert(
                "hookInvocationLedgerId".to_string(),
                invocation_ledger["ledgerId"].clone(),
            );
            append_string_array_field(
                prompt_audit,
                "evidenceRefs",
                vec![
                    manifest["manifestId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    dry_run_plan["planId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    invocation_ledger["ledgerId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    "rust_daemon_core_skill_hook_run_materialization".to_string(),
                ],
            );
        }
    }
    Ok(())
}

fn rust_hook_dry_run_plan(run_id: &str, manifest: &Value) -> Value {
    let decisions: Vec<Value> = json_array(&manifest["hooks"])
        .iter()
        .map(|hook| {
            let authority_scopes = string_array_from_json(hook.get("authorityScopes"));
            let tool_contracts = string_array_from_json(hook.get("toolContracts"));
            let command_configured =
                hook.get("commandConfigured").and_then(Value::as_bool) == Some(true);
            let mut blockers = Vec::new();
            let mut decision = "skipped";
            let mut reason = "no_command_configured";
            if command_configured {
                if authority_scopes.is_empty() {
                    blockers.push("missing_authority_scope".to_string());
                }
                if tool_contracts.is_empty() {
                    blockers.push("missing_tool_contract".to_string());
                }
                if blockers.is_empty() {
                    decision = "would_run";
                    reason = "preview_only_authority_and_tool_contract_declared";
                } else {
                    decision = "blocked";
                    reason = "missing_declared_capabilities";
                }
            }
            json!({
                "hookId": hook["id"],
                "name": hook["name"],
                "eventKinds": hook["eventKinds"],
                "failurePolicy": hook["failurePolicy"],
                "sideEffectClass": hook["sideEffectClass"],
                "commandConfigured": command_configured,
                "commandHash": hook["commandHash"],
                "commandRedacted": hook["commandRedacted"],
                "authorityScopes": authority_scopes,
                "toolContracts": tool_contracts,
                "decision": decision,
                "reason": reason,
                "blockers": blockers,
                "execution": {
                    "previewOnly": true,
                    "commandExecuted": false,
                    "mutationAllowed": false,
                },
                "evidenceRefs": hook["evidenceRefs"],
            })
        })
        .collect();
    let would_run_count = decisions
        .iter()
        .filter(|decision| decision["decision"] == "would_run")
        .count();
    let blocked_count = decisions
        .iter()
        .filter(|decision| decision["decision"] == "blocked")
        .count();
    let skipped_count = decisions
        .iter()
        .filter(|decision| decision["decision"] == "skipped")
        .count();
    let plan_payload = json!({
        "manifestId": manifest["manifestId"],
        "decisions": decisions.iter().map(|decision| json!({
            "hookId": decision["hookId"],
            "decision": decision["decision"],
            "blockers": decision["blockers"],
        })).collect::<Vec<Value>>(),
    });
    let plan_hash = sha256_text(&serde_json::to_string(&plan_payload).unwrap_or_default());
    let plan_id = format!("hook_dry_run_{run_id}_{}", &plan_hash[..12]);
    json!({
        "schemaVersion": "ioi.agent-runtime.hook-dry-run-plan.v1",
        "object": "ioi.agent_hook_dry_run_plan",
        "planId": plan_id,
        "runId": run_id,
        "manifestId": manifest["manifestId"],
        "activeHookSetHash": manifest["activeHookSetHash"],
        "generatedAt": "rust_policy_core",
        "mode": "preview_only",
        "hookExecutionEnabled": false,
        "commandExecutionEnabled": false,
        "decisionCount": decisions.len(),
        "wouldRunCount": would_run_count,
        "blockedCount": blocked_count,
        "skippedCount": skipped_count,
        "decisions": decisions,
        "policyDecision": {
            "status": if blocked_count > 0 { "blocked" } else { "passed" },
            "summary": if blocked_count > 0 {
                format!("{blocked_count} hook(s) blocked by missing declared capabilities; no commands executed.")
            } else {
                "All command-backed hooks are eligible for dry-run preview; no commands executed.".to_string()
            },
            "previewOnly": true,
            "hookExecutionEnabled": false,
            "commandExecutionEnabled": false,
        },
        "redaction": {
            "profile": "hook_dry_run_safe",
            "hookCommandsIncluded": false,
            "hookCommandsHashed": true,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": [
            "rust_daemon_core_hook_dry_run_plan",
            "hook_policy_decision",
            manifest["manifestId"].as_str().unwrap_or_default(),
        ],
    })
}

fn rust_hook_invocation_ledger(run_id: &str, manifest: &Value, dry_run_plan: &Value) -> Value {
    let events = [
        (
            "workflow_activation",
            "run_started",
            "activation",
            "runtime.runtime-thread",
        ),
        (
            "pre_model",
            "model_route_decision",
            "before_model",
            "runtime.model-router",
        ),
        (
            "post_model",
            "delta",
            "after_model",
            "runtime.output-writer",
        ),
    ];
    let decisions = json_array(&dry_run_plan["decisions"]);
    let hooks = json_array(&manifest["hooks"]);
    let mut records = Vec::new();
    for (event_kind, runtime_event_type, phase, workflow_node_id) in events {
        for hook in &hooks {
            if !string_array_from_json(hook.get("eventKinds"))
                .iter()
                .any(|value| value == event_kind)
            {
                continue;
            }
            let hook_id = string_value_from_json(hook, "id").unwrap_or_default();
            let plan_decision = decisions
                .iter()
                .find(|decision| decision["hookId"].as_str() == Some(hook_id.as_str()));
            let decision = plan_decision
                .and_then(|value| value["decision"].as_str())
                .unwrap_or("skipped");
            let blockers =
                string_array_from_json(plan_decision.and_then(|value| value.get("blockers")));
            let invocation_hash = sha256_text(
                &serde_json::to_string(&json!({
                    "runId": run_id,
                    "eventKind": event_kind,
                    "hookId": hook_id,
                    "decision": decision,
                    "blockers": blockers,
                }))
                .unwrap_or_default(),
            );
            let escalation = if decision == "blocked" {
                rust_hook_escalation(run_id, &invocation_hash, event_kind, hook, blockers.clone())
            } else {
                json!({
                    "required": false,
                    "receiptId": Value::Null,
                    "missingAuthorityScopes": [],
                    "missingToolContracts": [],
                    "recommendedNextAction": "No hook escalation is required for this preview invocation.",
                })
            };
            records.push(json!({
                "schemaVersion": "ioi.agent-runtime.hook-invocation-record.v1",
                "object": "ioi.agent_hook_invocation_record",
                "invocationId": format!("hook_invocation_{run_id}_{}", &invocation_hash[..12]),
                "runId": run_id,
                "manifestId": manifest["manifestId"],
                "dryRunPlanId": dry_run_plan["planId"],
                "eventKind": event_kind,
                "runtimeEventType": runtime_event_type,
                "runtimeEventPhase": phase,
                "hookId": hook["id"],
                "hookName": hook["name"],
                "hookDefinitionHash": hook["definitionHash"],
                "hookEventKinds": hook["eventKinds"],
                "failurePolicy": hook["failurePolicy"],
                "sideEffectClass": hook["sideEffectClass"],
                "authorityScopes": hook["authorityScopes"],
                "toolContracts": hook["toolContracts"],
                "commandConfigured": hook["commandConfigured"],
                "commandHash": hook["commandHash"],
                "commandRedacted": hook["commandRedacted"],
                "state": decision,
                "decision": decision,
                "reason": plan_decision.and_then(|value| value["reason"].as_str()).unwrap_or("preview_only_event_subscription_matched"),
                "blockers": blockers,
                "escalation": escalation,
                "policyDecisionStatus": dry_run_plan["policyDecision"]["status"],
                "execution": {
                    "previewOnly": true,
                    "commandExecuted": false,
                    "mutationAllowed": false,
                },
                "workflowNodeId": workflow_node_id,
                "hookPolicyNodeId": "runtime.hook-policy",
                "evidenceRefs": [
                    "rust_daemon_core_hook_invocation_record",
                    dry_run_plan["planId"].as_str().unwrap_or_default(),
                    manifest["manifestId"].as_str().unwrap_or_default(),
                    hook["id"].as_str().unwrap_or_default(),
                    event_kind,
                ],
            }));
        }
    }
    let would_run_count = records
        .iter()
        .filter(|record| record["state"] == "would_run")
        .count();
    let blocked_count = records
        .iter()
        .filter(|record| record["state"] == "blocked")
        .count();
    let skipped_count = records
        .iter()
        .filter(|record| record["state"] == "skipped")
        .count();
    let escalations: Vec<Value> = records
        .iter()
        .filter(|record| record["escalation"]["required"] == true)
        .map(|record| {
            let mut escalation = record["escalation"].clone();
            if let Some(object) = escalation.as_object_mut() {
                object.insert("invocationId".to_string(), record["invocationId"].clone());
                object.insert("hookId".to_string(), record["hookId"].clone());
                object.insert("hookName".to_string(), record["hookName"].clone());
                object.insert("eventKind".to_string(), record["eventKind"].clone());
                object.insert("failurePolicy".to_string(), record["failurePolicy"].clone());
                object.insert(
                    "workflowNodeId".to_string(),
                    record["workflowNodeId"].clone(),
                );
            }
            escalation
        })
        .collect();
    let ledger_hash = sha256_text(
        &serde_json::to_string(&json!({
            "manifestId": manifest["manifestId"],
            "planId": dry_run_plan["planId"],
            "records": records.iter().map(|record| json!({
                "eventKind": record["eventKind"],
                "hookId": record["hookId"],
                "state": record["state"],
            })).collect::<Vec<Value>>(),
        }))
        .unwrap_or_default(),
    );
    json!({
        "schemaVersion": "ioi.agent-runtime.hook-invocation-ledger.v1",
        "object": "ioi.agent_hook_invocation_ledger",
        "ledgerId": format!("hook_invocations_{run_id}_{}", &ledger_hash[..12]),
        "runId": run_id,
        "manifestId": manifest["manifestId"],
        "dryRunPlanId": dry_run_plan["planId"],
        "activeHookSetHash": manifest["activeHookSetHash"],
        "generatedAt": "rust_policy_core",
        "mode": "preview_only",
        "hookExecutionEnabled": false,
        "commandExecutionEnabled": false,
        "emittedEventKinds": ["workflow_activation", "pre_model", "post_model"],
        "invocationCount": records.len(),
        "wouldRunCount": would_run_count,
        "blockedCount": blocked_count,
        "skippedCount": skipped_count,
        "escalationCount": escalations.len(),
        "escalations": escalations,
        "records": records,
        "redaction": {
            "profile": "hook_invocation_ledger_safe",
            "hookCommandsIncluded": false,
            "hookCommandsHashed": true,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": [
            "rust_daemon_core_hook_invocation_ledger",
            "hook_invocation_preview_only",
            dry_run_plan["planId"].as_str().unwrap_or_default(),
            manifest["manifestId"].as_str().unwrap_or_default(),
        ],
    })
}

fn rust_hook_escalation(
    run_id: &str,
    invocation_hash: &str,
    event_kind: &str,
    hook: &Value,
    blockers: Vec<String>,
) -> Value {
    let missing_authority_scopes = if blockers
        .iter()
        .any(|blocker| blocker == "missing_authority_scope")
    {
        vec!["declare_at_least_one_authority_scope".to_string()]
    } else {
        Vec::new()
    };
    let missing_tool_contracts = if blockers
        .iter()
        .any(|blocker| blocker == "missing_tool_contract")
    {
        vec!["declare_at_least_one_tool_contract".to_string()]
    } else {
        Vec::new()
    };
    let mut missing_declarations = Vec::new();
    if !missing_authority_scopes.is_empty() {
        missing_declarations.push("authorityScopes".to_string());
    }
    if !missing_tool_contracts.is_empty() {
        missing_declarations.push("toolContracts".to_string());
    }
    json!({
        "required": true,
        "receiptId": format!("receipt_{run_id}_hook_escalation_{}", &invocation_hash[..12]),
        "escalationKind": "missing_declared_capabilities",
        "missingDeclarations": missing_declarations,
        "missingAuthorityScopes": missing_authority_scopes,
        "missingToolContracts": missing_tool_contracts,
        "eventKind": event_kind,
        "hookId": hook["id"],
        "hookName": hook["name"],
        "failurePolicy": hook["failurePolicy"],
        "blockers": blockers,
        "recommendedNextAction": "Declare authorityScopes and toolContracts for this hook before requesting execution.",
        "commandExecuted": false,
        "approvalGrantCreated": false,
        "evidenceRefs": [
            "hook_escalation_receipt",
            hook["id"].as_str().unwrap_or_default(),
            event_kind,
            "blocked",
        ],
    })
}

fn rust_hook_escalation_receipts(ledger: &Value) -> Vec<Value> {
    json_array(&ledger["records"])
        .iter()
        .filter(|record| record["escalation"]["required"] == true)
        .map(|record| {
            let missing_declarations = string_array_from_json(
                record
                    .get("escalation")
                    .and_then(|value| value.get("missingDeclarations")),
            );
            json!({
                "id": record["escalation"]["receiptId"],
                "kind": "hook_escalation",
                "summary": format!(
                    "Hook {} on {} is blocked until {} are declared.",
                    record["hookName"].as_str().unwrap_or("hook"),
                    record["eventKind"].as_str().unwrap_or("event"),
                    if missing_declarations.is_empty() { "policy".to_string() } else { missing_declarations.join(" and ") },
                ),
                "redaction": "redacted",
                "evidenceRefs": [
                    ledger["ledgerId"].as_str().unwrap_or_default(),
                    record["invocationId"].as_str().unwrap_or_default(),
                    record["dryRunPlanId"].as_str().unwrap_or_default(),
                    record["manifestId"].as_str().unwrap_or_default(),
                    "hook_escalation_receipt",
                ],
                "details": {
                    "schemaVersion": "ioi.agent-runtime.hook-escalation-receipt.v1",
                    "object": "ioi.agent_hook_escalation_receipt",
                    "receiptId": record["escalation"]["receiptId"],
                    "invocationId": record["invocationId"],
                    "hookId": record["hookId"],
                    "hookName": record["hookName"],
                    "eventKind": record["eventKind"],
                    "failurePolicy": record["failurePolicy"],
                    "blockers": record["blockers"],
                    "missingDeclarations": record["escalation"]["missingDeclarations"],
                    "missingAuthorityScopes": record["escalation"]["missingAuthorityScopes"],
                    "missingToolContracts": record["escalation"]["missingToolContracts"],
                    "recommendedNextAction": record["escalation"]["recommendedNextAction"],
                    "workflowNodeId": record["workflowNodeId"],
                    "hookPolicyNodeId": record["hookPolicyNodeId"],
                    "commandExecuted": false,
                    "approvalGrantCreated": false,
                },
            })
        })
        .collect()
}

fn rust_skill_hook_run_events(
    run_id: &str,
    agent_id: &str,
    manifest: &Value,
    dry_run_plan: &Value,
    invocation_ledger: &Value,
    skill_hook_receipt: &Value,
    hook_dry_run_receipt: &Value,
    hook_policy_receipt: &Value,
    hook_invocation_receipt: &Value,
    escalation_receipts: &[Value],
) -> Vec<Value> {
    vec![
        json!({
            "id": format!("{run_id}:event:rust-skill-hook:000:skill_hook_manifest"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "skill_hook_manifest",
            "cursor": format!("{run_id}:rust-skill-hook:0"),
            "created_at": "rust_policy_core",
            "summary": "Active skill and hook manifest recorded by Rust daemon-core",
            "data": {
                "event_kind": "ActiveSkillHookManifest",
                "manifest_id": manifest["manifestId"],
                "active_skill_set_hash": manifest["activeSkillSetHash"],
                "active_hook_set_hash": manifest["activeHookSetHash"],
                "selected_skill_ids": manifest["selectedSkillIds"],
                "selected_hook_ids": manifest["selectedHookIds"],
                "mutation_blocked_hook_ids": manifest["mutationBlockedHookIds"],
                "hook_execution": {
                    "enabled": manifest["hookExecution"]["enabled"],
                },
                "receipt_id": skill_hook_receipt["id"],
                "workflow_node_id": "runtime.skill-hook-manifest",
                "redaction": manifest["redaction"],
                "rust_daemon_core_materialized": true,
            },
        }),
        json!({
            "id": format!("{run_id}:event:rust-skill-hook:001:hook_dry_run_plan"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "hook_dry_run_plan",
            "cursor": format!("{run_id}:rust-skill-hook:1"),
            "created_at": "rust_policy_core",
            "summary": "Hook dry-run plan recorded by Rust daemon-core",
            "data": {
                "event_kind": "HookDryRunPlan",
                "plan_id": dry_run_plan["planId"],
                "manifest_id": dry_run_plan["manifestId"],
                "decision_count": dry_run_plan["decisionCount"],
                "would_run_count": dry_run_plan["wouldRunCount"],
                "blocked_count": dry_run_plan["blockedCount"],
                "skipped_count": dry_run_plan["skippedCount"],
                "policy_decision": {
                    "status": dry_run_plan["policyDecision"]["status"],
                },
                "hook_execution_enabled": dry_run_plan["hookExecutionEnabled"],
                "command_execution_enabled": dry_run_plan["commandExecutionEnabled"],
                "receipt_id": hook_dry_run_receipt["id"],
                "policy_receipt_id": hook_policy_receipt["id"],
                "workflow_node_id": "runtime.hook-policy",
                "redaction": dry_run_plan["redaction"],
                "rust_daemon_core_materialized": true,
            },
        }),
        json!({
            "id": format!("{run_id}:event:rust-skill-hook:002:hook_invocation_ledger"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "hook_invocation_ledger",
            "cursor": format!("{run_id}:rust-skill-hook:2"),
            "created_at": "rust_policy_core",
            "summary": "Hook invocation ledger recorded by Rust daemon-core",
            "data": {
                "event_kind": "HookInvocationLedger",
                "ledger_id": invocation_ledger["ledgerId"],
                "manifest_id": invocation_ledger["manifestId"],
                "dry_run_plan_id": invocation_ledger["dryRunPlanId"],
                "emitted_event_kinds": invocation_ledger["emittedEventKinds"],
                "invocation_count": invocation_ledger["invocationCount"],
                "would_run_count": invocation_ledger["wouldRunCount"],
                "blocked_count": invocation_ledger["blockedCount"],
                "skipped_count": invocation_ledger["skippedCount"],
                "escalation_count": invocation_ledger["escalationCount"],
                "hook_execution_enabled": invocation_ledger["hookExecutionEnabled"],
                "command_execution_enabled": invocation_ledger["commandExecutionEnabled"],
                "receipt_id": hook_invocation_receipt["id"],
                "escalation_receipt_ids": escalation_receipts.iter().map(|receipt| receipt["id"].clone()).collect::<Vec<Value>>(),
                "workflow_node_id": "runtime.hook-invocations",
                "redaction": invocation_ledger["redaction"],
                "rust_daemon_core_materialized": true,
            },
        }),
    ]
}

fn update_runtime_task_skill_hook_binding(
    run: &mut serde_json::Map<String, Value>,
    manifest: &Value,
) {
    for key in ["runtimeTask"] {
        if let Some(task) = run.get_mut(key).and_then(Value::as_object_mut) {
            task.insert(
                "activeSkillHookManifestId".to_string(),
                manifest["manifestId"].clone(),
            );
            append_string_array_field(
                task,
                "evidenceRefs",
                vec![
                    manifest["manifestId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    "rust_daemon_core_skill_hook_run_materialization".to_string(),
                ],
            );
        }
    }
    if let Some(trace_task) = run
        .get_mut("trace")
        .and_then(Value::as_object_mut)
        .and_then(|trace| trace.get_mut("runtimeTask"))
        .and_then(Value::as_object_mut)
    {
        trace_task.insert(
            "activeSkillHookManifestId".to_string(),
            manifest["manifestId"].clone(),
        );
        append_string_array_field(
            trace_task,
            "evidenceRefs",
            vec![
                manifest["manifestId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                "rust_daemon_core_skill_hook_run_materialization".to_string(),
            ],
        );
    }
}

fn json_artifact(run_id: &str, name: &str, receipt: &Value, content: &Value) -> Value {
    json!({
        "id": format!("artifact_{run_id}_{}", artifact_slug(name)),
        "runId": run_id,
        "name": name,
        "mediaType": "application/json",
        "redaction": "redacted",
        "receiptId": receipt["id"],
        "content": serde_json::to_string_pretty(content).unwrap_or_else(|_| "{}".to_string()),
    })
}

fn artifact_slug(value: &str) -> String {
    let mut slug = String::new();
    let mut last_was_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_sep = false;
        } else if !last_was_sep {
            slug.push('_');
            last_was_sep = true;
        }
    }
    let trimmed = slug.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "artifact".to_string()
    } else {
        trimmed
    }
}

fn skill_manifest_record(skill: &Value) -> Value {
    json!({
        "id": skill["id"],
        "name": skill["name"],
        "skillHash": skill["skillHash"],
        "sourceId": skill["sourceId"],
        "compatibility": skill["compatibility"],
        "trustLevel": skill["trustLevel"],
        "activationMode": skill["activationMode"],
        "validationStatus": skill["validation"]["status"],
        "provenance": skill["provenance"],
        "evidenceRefs": skill["evidenceRefs"],
    })
}

fn hook_manifest_record(hook: &Value) -> Value {
    json!({
        "id": hook["id"],
        "name": hook["name"],
        "enabled": hook.get("enabled").and_then(Value::as_bool) != Some(false),
        "definitionHash": hook["definitionHash"],
        "sourceId": hook["sourceId"],
        "compatibility": hook["compatibility"],
        "trustLevel": hook["trustLevel"],
        "eventKinds": hook["eventKinds"],
        "failurePolicy": hook["failurePolicy"],
        "sideEffectClass": hook["sideEffectClass"],
        "authorityScopes": hook["authorityScopes"],
        "toolContracts": hook["toolContracts"],
        "commandConfigured": hook["commandConfigured"],
        "commandHash": hook["commandHash"],
        "commandRedacted": hook["commandRedacted"],
        "validationStatus": hook["validation"]["status"],
        "mutationPolicy": hook["mutationPolicy"],
        "evidenceRefs": hook["evidenceRefs"],
    })
}

fn manifest_selection_refs(
    objects: &[Option<&serde_json::Map<String, Value>>],
    keys: &[&str],
) -> Vec<String> {
    let mut refs = Vec::new();
    for object in objects.iter().flatten() {
        for key in keys {
            collect_manifest_selection_refs(object.get(*key), &mut refs);
        }
    }
    unique_string_vec(refs)
}

fn collect_manifest_selection_refs(value: Option<&Value>, refs: &mut Vec<String>) {
    match value {
        Some(Value::Array(items)) => {
            for item in items {
                collect_manifest_selection_refs(Some(item), refs);
            }
        }
        Some(Value::Object(object)) => {
            for key in ["id", "name", "skillHash", "definitionHash"] {
                if let Some(value) = object.get(key).and_then(Value::as_str) {
                    if let Some(value) = optional_trimmed(Some(value)) {
                        refs.push(value);
                    }
                }
            }
        }
        Some(Value::String(value)) => {
            if let Some(value) = optional_trimmed(Some(value)) {
                refs.push(value);
            }
        }
        Some(value) if !value.is_null() => refs.push(value.to_string()),
        _ => {}
    }
}

fn select_manifest_records(
    records: &[Value],
    requested_refs: &[String],
    hash_field: &str,
) -> Vec<Value> {
    if requested_refs.is_empty() {
        return records.to_vec();
    }
    let requested: Vec<String> = requested_refs
        .iter()
        .map(|value| normalize_manifest_token(value))
        .collect();
    records
        .iter()
        .filter(|record| {
            ["id", "name", hash_field, "sourceId"]
                .iter()
                .filter_map(|key| string_value_from_json(record, key))
                .map(|value| normalize_manifest_token(&value))
                .any(|candidate| requested.contains(&candidate))
        })
        .cloned()
        .collect()
}

fn normalize_manifest_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join("-")
}

fn json_array(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

fn string_array_from_json(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| optional_trimmed(Some(value)))
                .collect()
        })
        .unwrap_or_default()
}

fn string_value_from_json(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn materialize_runtime_task_job_run(
    run: &mut serde_json::Map<String, Value>,
) -> Result<(), RunCreateStateUpdateError> {
    if runtime_task_job_candidate_present(run) {
        return Err(RunCreateStateUpdateError::RetiredRuntimeTaskJobProjectionCandidate);
    }
    let run_value = Value::Object(run.clone());
    let run_id = optional_json_string(&run_value, "id")
        .ok_or(RunCreateStateUpdateError::MissingField("run.id"))?;
    let agent_id = optional_json_string(&run_value, "agentId")
        .ok_or(RunCreateStateUpdateError::MissingField("run.agentId"))?;
    let mode = optional_json_string(&run_value, "mode")
        .ok_or(RunCreateStateUpdateError::MissingField("run.mode"))?;
    let created_at = optional_json_string(&run_value, "createdAt")
        .ok_or(RunCreateStateUpdateError::MissingField("run.createdAt"))?;
    let updated_at = optional_json_string(&run_value, "updatedAt")
        .ok_or(RunCreateStateUpdateError::MissingField("run.updatedAt"))?;
    let status = runtime_task_job_status(json_string_value(&run_value, "status").as_deref());
    let task_family = trace_quality_string(&run_value, "taskFamily")
        .unwrap_or_else(|| runtime_task_family_for_mode(&mode).to_string());
    let selected_strategy = trace_quality_string(&run_value, "selectedStrategy")
        .unwrap_or_else(|| runtime_strategy_for_mode(&mode).to_string());
    let runtime_task = runtime_task_record(
        &run_value,
        &run_id,
        &agent_id,
        &mode,
        &status,
        &task_family,
        &selected_strategy,
        &created_at,
        &updated_at,
    );
    let mut runtime_job =
        runtime_job_record(&run_value, &runtime_task, &status, &created_at, &updated_at);
    let runtime_checklist = runtime_checklist_record(
        &runtime_task,
        &runtime_job,
        &status,
        &created_at,
        &updated_at,
    );
    runtime_job = attach_runtime_checklist_to_job(runtime_job, &runtime_checklist);

    let receipts =
        runtime_task_job_receipts(&run_id, &runtime_task, &runtime_job, &runtime_checklist);
    let events = runtime_task_job_events(
        &run_id,
        &agent_id,
        &runtime_task,
        &runtime_job,
        &runtime_checklist,
        &receipts,
    );
    let artifacts = vec![
        json_artifact(&run_id, "runtime-task.json", &receipts[0], &runtime_task),
        json_artifact(&run_id, "runtime-job.json", &receipts[1], &runtime_job),
        json_artifact(
            &run_id,
            "runtime-checklist.json",
            &receipts[2],
            &runtime_checklist,
        ),
    ];

    run.insert("runtimeTask".to_string(), runtime_task.clone());
    run.insert("runtimeJob".to_string(), runtime_job.clone());
    run.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
    append_array_field(run, "receipts", receipts.clone());
    // Splice the materialized task/job/checklist events BEFORE the terminal `completed`
    // event so the projected `turn.completed` is LAST in the runtime event stream.
    insert_array_field_before_terminal(run, "events", events.clone());
    append_array_field(run, "artifacts", artifacts.clone());

    if let Some(trace) = run.get_mut("trace").and_then(Value::as_object_mut) {
        trace.insert("runtimeTask".to_string(), runtime_task.clone());
        trace.insert("runtimeJob".to_string(), runtime_job.clone());
        trace.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        append_array_field(trace, "receipts", receipts);
        insert_array_field_before_terminal(trace, "events", events);
        append_array_field(trace, "artifacts", artifacts);
        if let Some(task_state) = trace.get_mut("taskState").and_then(Value::as_object_mut) {
            append_string_array_field(
                task_state,
                "knownFacts",
                vec![
                    format!(
                        "Rust daemon-core runtime task: id={}, family={}, status={}",
                        runtime_task["taskId"].as_str().unwrap_or_default(),
                        task_family,
                        status,
                    ),
                    format!(
                        "Rust daemon-core runtime job: id={}, status={}, queue={}",
                        runtime_job["jobId"].as_str().unwrap_or_default(),
                        status,
                        runtime_job["queueName"].as_str().unwrap_or_default(),
                    ),
                    format!(
                        "Rust daemon-core runtime checklist: id={}, status={}, items={}/{}",
                        runtime_checklist["checklistId"]
                            .as_str()
                            .unwrap_or_default(),
                        status,
                        runtime_checklist["completedItemCount"]
                            .as_u64()
                            .unwrap_or_default(),
                        runtime_checklist["itemCount"].as_u64().unwrap_or_default(),
                    ),
                ],
            );
            append_string_array_field(
                task_state,
                "evidenceRefs",
                vec![
                    runtime_task["taskId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    runtime_job["jobId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    runtime_checklist["checklistId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    "rust_daemon_core_runtime_task_job_materialization".to_string(),
                ],
            );
        }
        if let Some(prompt_audit) = trace.get_mut("promptAudit").and_then(Value::as_object_mut) {
            prompt_audit.insert("runtimeTaskId".to_string(), runtime_task["taskId"].clone());
            prompt_audit.insert("runtimeJobId".to_string(), runtime_job["jobId"].clone());
            prompt_audit.insert(
                "runtimeChecklistId".to_string(),
                runtime_checklist["checklistId"].clone(),
            );
            append_string_array_field(
                prompt_audit,
                "evidenceRefs",
                vec![
                    runtime_task["taskId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    runtime_job["jobId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    runtime_checklist["checklistId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    "rust_daemon_core_runtime_task_job_materialization".to_string(),
                ],
            );
        }
    }

    Ok(())
}

fn runtime_task_job_candidate_present(run: &serde_json::Map<String, Value>) -> bool {
    ["runtimeTask", "runtimeJob", "runtimeChecklist"]
        .iter()
        .any(|field| run.get(*field).is_some())
        || run
            .get("trace")
            .and_then(Value::as_object)
            .is_some_and(|trace| {
                ["runtimeTask", "runtimeJob", "runtimeChecklist"]
                    .iter()
                    .any(|field| trace.get(*field).is_some())
            })
}

fn runtime_task_record(
    run: &Value,
    run_id: &str,
    agent_id: &str,
    mode: &str,
    status: &str,
    task_family: &str,
    selected_strategy: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let prompt = json_string_value(run, "objective").unwrap_or_default();
    let model_route_decision = run.get("modelRouteDecision").or_else(|| {
        run.get("trace")
            .and_then(|trace| trace.get("modelRouteDecision"))
    });
    json!({
        "schemaVersion": "ioi.agent-runtime.task-record.v1",
        "object": "ioi.runtime_task",
        "taskId": format!("task_{run_id}"),
        "runId": run_id,
        "agentId": agent_id,
        "threadId": thread_id_for_agent(agent_id),
        "turnId": turn_id_for_run(run_id),
        "status": status,
        "mode": mode,
        "taskFamily": task_family,
        "selectedStrategy": selected_strategy,
        "summary": format!("Runtime task for {task_family} is {status}."),
        "promptHash": sha256_text(&prompt),
        "promptIncluded": false,
        "objectivePreviewIncluded": false,
        "modelRouteDecisionId": model_route_decision
            .and_then(|value| json_string_value(value, "decision_id"))
            .map(Value::String)
            .unwrap_or(Value::Null),
        "activeSkillHookManifestId": Value::Null,
        "createdAt": created_at,
        "updatedAt": updated_at,
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
        "evidenceRefs": [
            "runtime_task",
            "runtime.tasks.durable_projection",
            "RuntimeTaskNode",
            format!("run:{run_id}"),
            "rust_daemon_core_runtime_task_job_materialization",
        ],
    })
}

fn runtime_job_record(
    run: &Value,
    runtime_task: &Value,
    status: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let run_id = runtime_task["runId"].as_str().unwrap_or_default();
    let job_id = format!("job_{run_id}");
    let terminal = matches!(status, "completed" | "failed" | "canceled");
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
        runtime_task["taskId"],
        format!("run:{run_id}"),
        "rust_daemon_core_runtime_task_job_materialization",
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.job-record.v1",
        "object": "ioi.runtime_job",
        "jobId": job_id,
        "taskId": runtime_task["taskId"],
        "runId": run_id,
        "agentId": runtime_task["agentId"],
        "threadId": runtime_task["threadId"],
        "turnId": runtime_task["turnId"],
        "status": status,
        "lifecycle": runtime_job_lifecycle_for_status(status),
        "summary": format!("Runtime job job_{run_id} is {status}."),
        "queueName": "local-agentgres",
        "runner": "local-daemon-agentgres",
        "jobType": "agent_run",
        "priority": "normal",
        "background": true,
        "durable": true,
        "replayable": true,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "queuedAt": created_at,
        "startedAt": created_at,
        "completedAt": if terminal { Value::String(updated_at.to_string()) } else { Value::Null },
        "progress": progress,
        "eventCount": json_array(run.get("events").unwrap_or(&Value::Null)).len(),
        "terminalEventCount": Value::Null,
        "artifactNames": [
            "runtime-task.json",
            "runtime-job.json",
            "runtime-checklist.json",
            "trace.json",
            "agentgres-projection.json",
        ],
        "receiptKinds": [
            "runtime_task",
            "runtime_job",
            "runtime_checklist",
            "agentgres_canonical_write",
        ],
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
    })
}

fn runtime_checklist_record(
    runtime_task: &Value,
    runtime_job: &Value,
    status: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let run_id = runtime_task["runId"].as_str().unwrap_or_default();
    let task_id = runtime_task["taskId"].as_str().unwrap_or_default();
    let job_id = runtime_job["jobId"].as_str().unwrap_or_default();
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
        .filter(|item| json_string_value(item, "status").as_deref() == Some("passed"))
        .count();
    let canceled = items
        .iter()
        .filter(|item| json_string_value(item, "status").as_deref() == Some("canceled"))
        .count();
    let failed = items
        .iter()
        .filter(|item| json_string_value(item, "status").as_deref() == Some("failed"))
        .count();
    let blocked = items
        .iter()
        .filter(|item| json_string_value(item, "status").as_deref() == Some("blocked"))
        .count();
    json!({
        "schemaVersion": "ioi.agent-runtime.checklist-record.v1",
        "object": "ioi.runtime_checklist",
        "checklistId": checklist_id,
        "taskId": task_id,
        "jobId": job_id,
        "runId": run_id,
        "agentId": runtime_task["agentId"],
        "threadId": runtime_task["threadId"],
        "turnId": runtime_task["turnId"],
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
        "createdAt": created_at,
        "updatedAt": updated_at,
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
            "rust_daemon_core_runtime_task_job_materialization",
        ],
    })
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
        "evidenceRefs": evidence_refs,
    })
}

fn attach_runtime_checklist_to_job(mut runtime_job: Value, runtime_checklist: &Value) -> Value {
    if let Some(job) = runtime_job.as_object_mut() {
        job.insert(
            "checklistId".to_string(),
            runtime_checklist["checklistId"].clone(),
        );
        job.insert(
            "checklistStatus".to_string(),
            runtime_checklist["status"].clone(),
        );
        job.insert(
            "checklistItemCount".to_string(),
            runtime_checklist["itemCount"].clone(),
        );
        job.insert(
            "checklistCompletedItemCount".to_string(),
            runtime_checklist["completedItemCount"].clone(),
        );
        append_string_array_field(
            job,
            "artifactNames",
            vec!["runtime-checklist.json".to_string()],
        );
        append_string_array_field(job, "receiptKinds", vec!["runtime_checklist".to_string()]);
        append_string_array_field(
            job,
            "evidenceRefs",
            vec![
                runtime_checklist["checklistId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                "runtime_checklist".to_string(),
            ],
        );
    }
    runtime_job
}

fn runtime_task_job_receipts(
    run_id: &str,
    runtime_task: &Value,
    runtime_job: &Value,
    runtime_checklist: &Value,
) -> Vec<Value> {
    vec![
        json!({
            "id": format!("receipt_{run_id}_runtime_task"),
            "kind": "runtime_task",
            "summary": runtime_task["summary"],
            "redaction": "redacted",
            "evidenceRefs": [
                runtime_task["taskId"].as_str().unwrap_or_default(),
                runtime_task["threadId"].as_str().unwrap_or_default(),
                runtime_task["turnId"].as_str().unwrap_or_default(),
                "RuntimeTaskNode",
                "runtime.tasks.durable_projection",
                "rust_daemon_core_runtime_task_job_materialization",
            ],
        }),
        json!({
            "id": format!("receipt_{run_id}_runtime_job"),
            "kind": "runtime_job",
            "summary": runtime_job["summary"],
            "redaction": "redacted",
            "evidenceRefs": [
                runtime_job["jobId"].as_str().unwrap_or_default(),
                runtime_task["taskId"].as_str().unwrap_or_default(),
                format!("run:{run_id}"),
                "RuntimeJobNode",
                "runtime.jobs.durable_projection",
                "rust_daemon_core_runtime_task_job_materialization",
            ],
        }),
        json!({
            "id": format!("receipt_{run_id}_runtime_checklist"),
            "kind": "runtime_checklist",
            "summary": runtime_checklist["summary"],
            "redaction": "redacted",
            "evidenceRefs": [
                runtime_checklist["checklistId"].as_str().unwrap_or_default(),
                runtime_task["taskId"].as_str().unwrap_or_default(),
                runtime_job["jobId"].as_str().unwrap_or_default(),
                "RuntimeChecklistNode",
                "runtime.checklists.durable_projection",
                "rust_daemon_core_runtime_task_job_materialization",
            ],
        }),
    ]
}

fn runtime_task_job_events(
    run_id: &str,
    agent_id: &str,
    runtime_task: &Value,
    runtime_job: &Value,
    runtime_checklist: &Value,
    receipts: &[Value],
) -> Vec<Value> {
    let mut events = vec![
        json!({
            "id": format!("{run_id}:event:rust-runtime-ledger:000:runtime_task"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "runtime_task",
            "cursor": format!("{run_id}:rust-runtime-ledger:0"),
            "created_at": "rust_policy_core",
            "summary": "Runtime task record written by Rust daemon-core",
            "data": {
                "event_kind": "RuntimeTaskRecord",
                "task_id": runtime_task["taskId"],
                "run_id": runtime_task["runId"],
                "agent_id": runtime_task["agentId"],
                "thread_id": runtime_task["threadId"],
                "turn_id": runtime_task["turnId"],
                "status": runtime_task["status"],
                "mode": runtime_task["mode"],
                "task_family": runtime_task["taskFamily"],
                "selected_strategy": runtime_task["selectedStrategy"],
                "durable": true,
                "replayable": true,
                "prompt_included": false,
                "receipt_id": receipts[0]["id"],
                "workflow_node_id": "runtime.runtime-task",
                "redaction": runtime_task["redaction"],
                "rust_daemon_core_materialized": true,
            },
        }),
        json!({
            "id": format!("{run_id}:event:rust-runtime-ledger:001:job_queued"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "job_queued",
            "cursor": format!("{run_id}:rust-runtime-ledger:1"),
            "created_at": "rust_policy_core",
            "summary": "Runtime job queued by Rust daemon-core",
            "data": runtime_job_event_data("JobQueued", "queued", runtime_job, &receipts[1]),
        }),
        json!({
            "id": format!("{run_id}:event:rust-runtime-ledger:002:job_started"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "job_started",
            "cursor": format!("{run_id}:rust-runtime-ledger:2"),
            "created_at": "rust_policy_core",
            "summary": "Runtime job started by Rust daemon-core",
            "data": runtime_job_event_data("JobStarted", "started", runtime_job, &receipts[1]),
        }),
        json!({
            "id": format!("{run_id}:event:rust-runtime-ledger:003:runtime_checklist"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": "runtime_checklist",
            "cursor": format!("{run_id}:rust-runtime-ledger:3"),
            "created_at": "rust_policy_core",
            "summary": "Runtime checklist recorded by Rust daemon-core",
            "data": {
                "event_kind": "RuntimeChecklistRecord",
                "checklist_id": runtime_checklist["checklistId"],
                "task_id": runtime_checklist["taskId"],
                "job_id": runtime_checklist["jobId"],
                "run_id": runtime_checklist["runId"],
                "status": runtime_checklist["status"],
                "item_count": runtime_checklist["itemCount"],
                "completed_item_count": runtime_checklist["completedItemCount"],
                "failed_item_count": runtime_checklist["failedItemCount"],
                "canceled_item_count": runtime_checklist["canceledItemCount"],
                "blocked_item_count": runtime_checklist["blockedItemCount"],
                "required_item_ids": runtime_checklist["requiredItemIds"],
                "durable": true,
                "replayable": true,
                "receipt_id": receipts[2]["id"],
                "workflow_node_id": "runtime.runtime-checklist",
                "redaction": runtime_checklist["redaction"],
                "rust_daemon_core_materialized": true,
            },
        }),
    ];
    if runtime_job["status"] == "completed" || runtime_job["status"] == "failed" {
        let status = runtime_job["status"].as_str().unwrap_or("completed");
        events.push(json!({
            "id": format!("{run_id}:event:rust-runtime-ledger:004:job_{status}"),
            "run_id": run_id,
            "agent_id": agent_id,
            "type": if status == "failed" { "job_failed" } else { "job_completed" },
            "cursor": format!("{run_id}:rust-runtime-ledger:4"),
            "created_at": "rust_policy_core",
            "summary": format!("Runtime job {status} by Rust daemon-core"),
            "data": runtime_job_event_data(
                if status == "failed" { "JobFailed" } else { "JobCompleted" },
                status,
                runtime_job,
                &receipts[1],
            ),
        }));
    }
    events
}

fn runtime_job_event_data(
    event_kind: &str,
    lifecycle_status: &str,
    runtime_job: &Value,
    receipt: &Value,
) -> Value {
    json!({
        "event_kind": event_kind,
        "job_id": runtime_job["jobId"],
        "task_id": runtime_job["taskId"],
        "run_id": runtime_job["runId"],
        "agent_id": runtime_job["agentId"],
        "thread_id": runtime_job["threadId"],
        "turn_id": runtime_job["turnId"],
        "status": runtime_job["status"],
        "lifecycle_status": lifecycle_status,
        "queue_name": runtime_job["queueName"],
        "runner": runtime_job["runner"],
        "job_type": runtime_job["jobType"],
        "background": true,
        "durable": true,
        "replayable": true,
        "queued_at": runtime_job["queuedAt"],
        "started_at": runtime_job["startedAt"],
        "completed_at": runtime_job["completedAt"],
        "progress": runtime_job["progress"],
        "receipt_id": receipt["id"],
        "workflow_node_id": "runtime.runtime-job",
        "redaction": runtime_job["redaction"],
        "rust_daemon_core_materialized": true,
    })
}

fn runtime_task_job_status(status: Option<&str>) -> String {
    match status {
        Some("canceled") => "canceled",
        Some("failed") | Some("error") => "failed",
        Some("blocked") => "blocked",
        Some("running") | Some("active") => "running",
        Some("queued") | Some("pending") => "queued",
        _ => "completed",
    }
    .to_string()
}

fn runtime_job_lifecycle_for_status(status: &str) -> Vec<&'static str> {
    match status {
        "queued" => vec!["queued"],
        "running" => vec!["queued", "started"],
        "failed" => vec!["queued", "started", "failed"],
        "canceled" => vec!["queued", "started", "canceled"],
        "blocked" => vec!["queued", "started", "blocked"],
        _ => vec!["queued", "started", "completed"],
    }
}

fn runtime_task_family_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "planning",
        "dry_run" => "safety_preview",
        "handoff" => "delegation",
        "learn" => "learning",
        _ => "local_daemon_agentgres",
    }
}

fn runtime_strategy_for_mode(mode: &str) -> &'static str {
    match mode {
        "plan" => "daemon_plan_with_postconditions",
        "dry_run" => "daemon_dry_run_before_effect",
        "handoff" => "daemon_handoff_with_state_preservation",
        "learn" => "daemon_bounded_learning_gate",
        _ => "local_daemon_agentgres_execution",
    }
}

fn trace_quality_string(run: &Value, key: &str) -> Option<String> {
    run.get("trace")
        .and_then(|trace| trace.get("qualityLedger"))
        .and_then(|ledger| ledger.get(key))
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
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

fn materialize_computer_use_run(
    run: &mut serde_json::Map<String, Value>,
) -> Result<(), RunCreateStateUpdateError> {
    if run.contains_key("computerUse") || run.contains_key("computer_use_projection") {
        return Err(RunCreateStateUpdateError::RetiredComputerUseProjectionCandidate);
    }
    let request_value = match run.remove("computer_use_materialization_request") {
        Some(Value::Object(request)) => Value::Object(request),
        Some(Value::Null) | None => return Ok(()),
        Some(_) => {
            return Err(RunCreateStateUpdateError::MissingField(
                "run.computer_use_materialization_request",
            ))
        }
    };
    let request = request_value
        .as_object()
        .ok_or(RunCreateStateUpdateError::MissingField(
            "run.computer_use_materialization_request",
        ))?;
    let schema_version = optional_json_string(&request_value, "schema_version").ok_or(
        RunCreateStateUpdateError::MissingField(
            "run.computer_use_materialization_request.schema_version",
        ),
    )?;
    if schema_version != COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION {
        return Err(RunCreateStateUpdateError::InvalidSchemaVersion {
            expected: COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
            actual: schema_version,
        });
    }
    if !computer_use_materialization_requested(request, run) {
        return Ok(());
    }

    let run_value = Value::Object(run.clone());
    let run_id = optional_json_string(&run_value, "id")
        .ok_or(RunCreateStateUpdateError::MissingField("run.id"))?;
    let agent_id = optional_json_string(&run_value, "agentId")
        .ok_or(RunCreateStateUpdateError::MissingField("run.agentId"))?;
    let prompt = optional_json_string(&request_value, "prompt")
        .or_else(|| optional_json_string(&run_value, "objective"))
        .unwrap_or_else(|| "Governed computer-use run".to_string());
    let _mode = optional_json_string(&request_value, "mode")
        .or_else(|| optional_json_string(&run_value, "mode"))
        .unwrap_or_else(|| "send".to_string());
    let selected_model = optional_json_string(&request_value, "selected_model")
        .or_else(|| optional_json_string(&run_value, "modelRouteReceiptId"))
        .unwrap_or_else(|| "runtime_daemon".to_string());
    let request_body = request
        .get("request")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let request_body_value = Value::Object(request_body.clone());
    let lane = canonical_computer_use_lane(optional_json_string(
        &request_body_value,
        "computer_use_lane",
    ));
    let session_mode = canonical_computer_use_session_mode(
        optional_json_string(&request_body_value, "computer_use_session_mode"),
        &lane,
    );
    let action_kind = canonical_computer_use_action_kind(optional_json_string(
        &request_body_value,
        "computer_use_action_kind",
    ));
    let action_read_only = computer_use_action_is_read_only(&action_kind);
    let approval_ref = optional_json_string(&request_body_value, "computer_use_approval_ref");
    let target_ref = optional_json_string(&request_body_value, "computer_use_target_ref")
        .unwrap_or_else(|| format!("target_{run_id}_document"));
    let retention_mode = optional_json_string(&request_body_value, "observation_retention_mode")
        .unwrap_or_else(|| {
            if lane == "sandboxed_hosted" {
                "no_persistence".to_string()
            } else {
                "prompt_visible_summary_only".to_string()
            }
        });
    let workflow_graph_id = optional_json_string(&request_body_value, "workflow_graph_id");
    let workflow_node_id = optional_json_string(&request_body_value, "workflow_node_id")
        .unwrap_or_else(|| "computer-use.run-materialization".to_string());
    let authority_scope = if action_read_only {
        format!("computer_use.{lane}.read")
    } else {
        format!("computer_use.{lane}.act")
    };
    let approval_satisfied = action_read_only || approval_ref.is_some();
    let execution_completed = request_body
        .get("computer_use_execution_result")
        .and_then(Value::as_object)
        .and_then(|result| result.get("status"))
        .and_then(Value::as_str)
        == Some("completed");
    let action_executed = action_read_only || execution_completed;

    let lease_id = format!("lease_{run_id}_{}", lane.replace('_', "-"));
    let observation_ref = format!("observation_{run_id}_computer_use_initial");
    let target_index_ref = format!("target_index_{run_id}_computer_use_initial");
    let affordance_graph_ref = format!("affordance_{run_id}_computer_use_initial");
    let proposal_ref = format!("proposal_{run_id}_{action_kind}");
    let action_ref = format!("action_{run_id}_{action_kind}");
    let verification_ref = format!("verification_{run_id}_{action_kind}");
    let commit_gate_ref = format!("commit_gate_{run_id}_{action_kind}");
    let trajectory_ref = format!("trajectory_{run_id}_computer_use");
    let cleanup_ref = format!("cleanup_{run_id}_computer_use");
    let trace_receipt_id = format!("receipt_{run_id}_computer_use_trace");
    let environment_receipt_ref = format!("receipt_{run_id}_computer_use_environment");
    let policy_decision_ref = approval_ref.clone().unwrap_or_else(|| {
        if action_read_only {
            format!("policy_{run_id}_computer_use_read_only")
        } else {
            format!("policy_{run_id}_computer_use_requires_approval")
        }
    });

    let environment_selection = json!({
        "receipt_ref": environment_receipt_ref,
        "run_id": run_id,
        "selected_lane": lane,
        "selected_session_mode": session_mode,
        "rejected_options": [],
        "reasons": [
            "Rust daemon-core run-create materialized the governed computer-use lane from canonical request facts.",
            "JS computer-use projection authoring is retired for run materialization."
        ],
        "risk_posture": if action_read_only { "read_only_probe" } else if execution_completed { "approved_external_effect" } else { "commit_confirmation_required" },
        "authority_required": authority_scope,
        "privacy_impact": retention_mode,
        "expected_cleanup": "rust_daemon_core_cleanup_receipt_and_redacted_trace"
    });
    let lease = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "lease_id": lease_id,
        "lane": lane,
        "session_mode": session_mode,
        "status": "active",
        "authority_scope": authority_scope,
        "consent_scope": "operator_prompt",
        "target_hint": prompt.chars().take(160).collect::<String>(),
        "environment_ref": format!("{}:{}", lane, stable_suffix(&run_id)),
        "profile_provenance": "rust_daemon_core_run_materialization",
        "retention_mode": retention_mode,
        "cleanup_required": true,
        "evidence_refs": [
            environment_receipt_ref,
            "rust_daemon_core_computer_use_run_materialization",
            "wallet.network.authority_boundary"
        ]
    });
    let run_state = json!({
        "run_id": run_id,
        "lease_id": lease_id,
        "user_goal": prompt,
        "current_subgoal": "Observe the requested surface, index targets, and produce a governed computer-use trace.",
        "current_observation_ref": observation_ref,
        "current_target_index_ref": target_index_ref,
        "verification_status": if action_executed { "passed" } else { "requires_human" },
        "blocker_state": if action_executed { Value::Null } else { json!("commit_gate_requires_confirmation") },
        "risk_posture": if action_read_only { "read_only_probe" } else { "external_effect_gate_required" },
        "cleanup_state": "cleanup_required"
    });
    let observation = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "observation_ref": observation_ref,
        "lease_id": lease_id,
        "lane": lane,
        "session_mode": session_mode,
        "title": "IOI Rust daemon-core computer-use observation",
        "target_index_ref": target_index_ref,
        "retention_mode": retention_mode,
        "detected_patterns": ["rust_daemon_core_materialized", "computer_use_trace"]
    });
    let target_index = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "target_index_ref": target_index_ref,
        "observation_ref": observation_ref,
        "coordinate_space_id": format!("viewport_{run_id}"),
        "drift_state": "fresh",
        "targets": [{
            "target_ref": target_ref,
            "label": "Requested computer-use target",
            "role": "document",
            "confidence": 92,
            "available_actions": unique_string_vec(vec!["inspect".to_string(), "scroll".to_string(), action_kind.clone()])
        }]
    });
    let affordance_graph = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "graph_ref": affordance_graph_ref,
        "target_index_ref": target_index_ref,
        "observation_ref": observation_ref,
        "affordances": [{
            "target_ref": target_ref,
            "possible_action": action_kind,
            "confidence": if action_read_only { 95 } else { 86 },
            "risk_class": if action_read_only { "read_only" } else { "possible_external_effect" },
            "required_authority": authority_scope,
            "confirmation_required": !action_read_only
        }]
    });
    let action_proposal = json!({
        "proposal_ref": proposal_ref,
        "proposed_by": selected_model,
        "model_role": "grounder",
        "normalized_action_candidate": if action_kind == "inspect" { "inspect current surface and summarize actionable targets".to_string() } else { format!("{action_kind} {target_ref}") },
        "target_ref": target_ref,
        "confidence": if action_read_only { 92 } else { 86 },
        "rationale_summary": "Rust daemon-core materialized the governed computer-use proposal from canonical run-create facts.",
        "predicted_postcondition": if action_read_only { "A redacted observation and target index exist without external side effects." } else { "The action remains gated unless wallet.network approval and executor evidence are present." },
        "risk_assessment": if action_read_only { "read_only" } else { "possible_external_effect" },
        "policy_decision_ref": policy_decision_ref
    });
    let action = if action_executed {
        json!({
            "action_ref": action_ref,
            "proposal_ref": proposal_ref,
            "action_kind": action_kind,
            "target_ref": target_ref,
            "observation_ref": observation_ref,
            "coordinate_space_id": format!("viewport_{run_id}"),
            "payload_summary": if action_read_only { "Read-only inspect of the current computer-use target." } else { "Approved computer-use action executed with Rust-bound evidence." },
            "approval_ref": approval_ref
        })
    } else {
        Value::Null
    };
    let action_receipt = if action_executed {
        json!({
            "receipt_ref": format!("receipt_{run_id}_computer_use_action"),
            "action_ref": action_ref,
            "status": "completed",
            "grounding_ref": target_index_ref,
            "verification_ref": verification_ref,
            "evidence_refs": [observation_ref, target_index_ref, proposal_ref]
        })
    } else {
        Value::Null
    };
    let verification = json!({
        "verification_ref": verification_ref,
        "action_ref": if action_executed { Value::String(action_ref.clone()) } else { Value::Null },
        "status": if action_executed { "passed" } else { "requires_human" },
        "expected_postcondition": if action_read_only { "Read-only computer-use trace exists." } else { "Mutating action requires explicit authority before external effects." },
        "observed_postcondition": if action_executed { "Rust daemon-core materialized the computer-use trace and action evidence." } else { "No external-effect action executed before authority was present." },
        "verifier": "rust_daemon_core_computer_use_run_materializer",
        "evidence_refs": [environment_receipt_ref, observation_ref, target_index_ref, proposal_ref]
    });
    let outcome_contract = json!({
        "outcome_ref": format!("outcome_{run_id}_computer_use"),
        "requested_outcome": "Produce a Rust-owned governed computer-use trace.",
        "success_criteria": ["Rust-owned computer-use events, receipt, artifact, and trace projection exist."],
        "external_effect_policy": if action_read_only { "read_only" } else { "wallet_network_authority_required" }
    });
    let policy_decision = json!({
        "policy_decision_ref": policy_decision_ref,
        "proposal_ref": proposal_ref,
        "action_kind": action_kind,
        "outcome": if action_read_only { "approved_for_read_only_probe" } else if approval_satisfied && execution_completed { "approved_after_confirmation" } else { "requires_confirmation_before_execution" },
        "authority_scope": authority_scope,
        "approval_ref": approval_ref,
        "external_effect": !action_read_only,
        "fail_closed": !action_read_only && !execution_completed,
        "evidence_refs": [observation_ref, target_index_ref, proposal_ref]
    });
    let commit_gate = json!({
        "commit_gate_ref": commit_gate_ref,
        "final_action_ref": if action_executed { Value::String(action_ref.clone()) } else { Value::Null },
        "outcome_ref": format!("outcome_{run_id}_computer_use"),
        "external_effect": !action_read_only,
        "user_confirmation_required": !action_read_only && !execution_completed,
        "authority_required": authority_scope,
        "policy_decision_ref": policy_decision_ref,
        "status": if action_executed { "completed" } else { "pending_confirmation" }
    });
    let trajectory = json!({
        "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        "trajectory_ref": trajectory_ref,
        "run_id": run_id,
        "lease_id": lease_id,
        "retention_mode": retention_mode,
        "entries": [
            {"sequence": 1, "event_kind": "select_environment", "receipt_ref": environment_receipt_ref},
            {"sequence": 2, "event_kind": "observe", "observation_ref": observation_ref},
            {"sequence": 3, "event_kind": "propose_action", "proposal_ref": proposal_ref},
            {"sequence": 4, "event_kind": "verify_postcondition", "verification_ref": verification_ref},
            {"sequence": 5, "event_kind": "commit_or_handoff", "receipt_ref": commit_gate_ref}
        ]
    });
    let cleanup = json!({
        "cleanup_ref": cleanup_ref,
        "lease_id": lease_id,
        "status": "completed",
        "retained_artifact_refs": ["computer-use-trace.json"],
        "warnings": []
    });
    let adapter_contract = json!({
        "adapter_id": format!("ioi.{lane}.rust_daemon_core"),
        "lane": lane,
        "supported_session_modes": [session_mode],
        "capabilities": ["observe", "target_index", "action_proposal", "verification", "cleanup"],
        "emits_observation_bundle": true,
        "emits_action_receipts": action_executed,
        "emits_cleanup_receipts": true,
        "fail_closed_when_unavailable": true
    });
    let computer_use = json!({
        "source": "rust_daemon_core_run_create",
        "environmentSelection": environment_selection,
        "lease": lease,
        "runState": run_state,
        "observation": observation,
        "targetIndex": target_index,
        "affordanceGraph": affordance_graph,
        "actionProposal": action_proposal,
        "action": action,
        "actionReceipt": action_receipt,
        "verification": verification,
        "outcomeContract": outcome_contract,
        "policyDecision": policy_decision,
        "commitGate": commit_gate,
        "trajectory": trajectory,
        "cleanup": cleanup,
        "adapterContract": adapter_contract
    });
    let receipt = json!({
        "id": trace_receipt_id,
        "kind": "computer_use_trace",
        "summary": "Rust daemon-core materialized computer-use trace, events, receipt, and artifact during run-create planning.",
        "redaction": "redacted",
        "evidenceRefs": [
            "rust_daemon_core_computer_use_run_materialization",
            "computer_use_projection_js_facade_retired",
            environment_receipt_ref,
            observation_ref,
            target_index_ref,
            trajectory_ref,
            cleanup_ref
        ]
    });
    let artifact = json!({
        "id": format!("artifact_{run_id}_computer_use_trace_json"),
        "runId": run_id,
        "name": "computer-use-trace.json",
        "mediaType": "application/json",
        "redaction": "redacted",
        "receiptId": trace_receipt_id,
        "content": serde_json::to_string_pretty(&computer_use).unwrap_or_else(|_| "{}".to_string())
    });
    let events = rust_computer_use_run_events(
        &run_id,
        &agent_id,
        &workflow_graph_id,
        &workflow_node_id,
        &computer_use,
        &trace_receipt_id,
    );
    append_array_field(run, "receipts", vec![receipt.clone()]);
    append_array_field(run, "artifacts", vec![artifact.clone()]);
    // Splice before the terminal event so a terminal-bearing candidate keeps turn.completed LAST.
    insert_array_field_before_terminal(run, "events", events.clone());
    if let Some(trace) = run.get_mut("trace").and_then(Value::as_object_mut) {
        trace.insert("computerUse".to_string(), computer_use.clone());
        append_array_field(trace, "receipts", vec![receipt]);
        append_array_field(trace, "artifacts", vec![artifact]);
        insert_array_field_before_terminal(trace, "events", events);
        if let Some(task_state) = trace.get_mut("taskState").and_then(Value::as_object_mut) {
            append_string_array_field(
                task_state,
                "knownFacts",
                vec![
                    "Computer-use run materialization was authored by Rust daemon-core run-create planning.".to_string(),
                    "JS computer-use projection authoring is retired for this run hot path.".to_string(),
                ],
            );
            append_string_array_field(
                task_state,
                "evidenceRefs",
                vec![
                    "rust_daemon_core_computer_use_run_materialization".to_string(),
                    "computer_use_projection_js_facade_retired".to_string(),
                ],
            );
        }
    }
    Ok(())
}

fn computer_use_materialization_requested(
    request: &serde_json::Map<String, Value>,
    run: &serde_json::Map<String, Value>,
) -> bool {
    let request_value = Value::Object(request.clone());
    let request_body = request
        .get("request")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let request_body_value = Value::Object(request_body);
    request_body_value
        .get("computer_use")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || optional_json_string(&request_body_value, "computer_use_lane").is_some()
        || optional_json_string(&request_body_value, "computer_use_action_kind").is_some()
        || optional_json_string(&request_value, "prompt")
            .or_else(|| optional_json_string(&Value::Object(run.clone()), "objective"))
            .is_some_and(|prompt| prompt_requests_computer_use(&prompt))
}

fn prompt_requests_computer_use(prompt: &str) -> bool {
    let text = prompt.to_ascii_lowercase();
    [
        "browser",
        "web page",
        "website",
        "computer use",
        "computer-use",
        "screen",
        "click",
        "type",
        "scroll",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn canonical_computer_use_lane(value: Option<String>) -> String {
    match value.as_deref() {
        Some("visual_gui") => "visual_gui".to_string(),
        Some("sandboxed_hosted") => "sandboxed_hosted".to_string(),
        _ => "native_browser".to_string(),
    }
}

fn canonical_computer_use_session_mode(value: Option<String>, lane: &str) -> String {
    if let Some(value) = value {
        return value;
    }
    match lane {
        "visual_gui" => "visual_fallback".to_string(),
        "sandboxed_hosted" => "local_sandbox".to_string(),
        _ => "owned_hermetic_browser".to_string(),
    }
}

fn canonical_computer_use_action_kind(value: Option<String>) -> String {
    let normalized = value
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace([' ', '-'], "_");
    match normalized.as_str() {
        "" => "inspect".to_string(),
        "type" | "input_text" => "type_text".to_string(),
        "keypress" => "key_press".to_string(),
        "click" | "type_text" | "key_press" | "scroll" | "drag" | "hover" | "select" | "upload"
        | "clipboard" | "wait" | "shell" | "mobile_gesture" | "navigate" | "inspect" => normalized,
        _ => "inspect".to_string(),
    }
}

fn computer_use_action_is_read_only(action_kind: &str) -> bool {
    matches!(action_kind, "inspect" | "hover" | "wait" | "scroll")
}

fn rust_computer_use_run_events(
    run_id: &str,
    agent_id: &str,
    workflow_graph_id: &Option<String>,
    workflow_node_id: &str,
    computer_use: &Value,
    trace_receipt_id: &str,
) -> Vec<Value> {
    let steps = [
        (
            "computer_use_environment_selected",
            "Computer-use environment selected by Rust daemon-core",
            "select_environment",
            "environmentSelection",
        ),
        (
            "computer_use_lease_acquired",
            "Computer-use lease materialized by Rust daemon-core",
            "acquire_lease",
            "lease",
        ),
        (
            "computer_use_observation",
            "Computer-use observation materialized by Rust daemon-core",
            "observe",
            "observation",
        ),
        (
            "computer_use_action_proposed",
            "Computer-use action proposal policy-gated by Rust daemon-core",
            "propose_action",
            "actionProposal",
        ),
        (
            "computer_use_verification",
            "Computer-use postcondition verified by Rust daemon-core",
            "verify_postcondition",
            "verification",
        ),
        (
            "computer_use_commit_gate",
            "Computer-use commit gate evaluated by Rust daemon-core",
            "commit_or_handoff",
            "commitGate",
        ),
        (
            "computer_use_trajectory_written",
            "Computer-use trajectory written by Rust daemon-core",
            "write_trajectory",
            "trajectory",
        ),
        (
            "computer_use_cleanup",
            "Computer-use cleanup completed by Rust daemon-core",
            "cleanup",
            "cleanup",
        ),
    ];
    steps
        .iter()
        .enumerate()
        .map(|(index, (event_type, summary, step, payload_key))| {
            let payload = computer_use.get(*payload_key).cloned().unwrap_or(Value::Null);
            let data = json!({
                "schema_version": COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
                "event_kind": computer_use_source_event_kind(event_type),
                "computer_use_step": step,
                "computer_use_lane": computer_use["lease"]["lane"],
                "computer_use_session_mode": computer_use["lease"]["session_mode"],
                "computer_use_lease_id": computer_use["lease"]["lease_id"],
                "computer_use_observation_ref": computer_use["observation"]["observation_ref"],
                "computer_use_target_index_ref": computer_use["targetIndex"]["target_index_ref"],
                "computer_use_affordance_graph_ref": computer_use["affordanceGraph"]["graph_ref"],
                "computer_use_proposal_ref": computer_use["actionProposal"]["proposal_ref"],
                "computer_use_action_ref": computer_use["action"]["action_ref"],
                "computer_use_policy_decision_ref": computer_use["policyDecision"]["policy_decision_ref"],
                "computer_use_verification_ref": computer_use["verification"]["verification_ref"],
                "computer_use_commit_gate_ref": computer_use["commitGate"]["commit_gate_ref"],
                "computer_use_trajectory_ref": computer_use["trajectory"]["trajectory_ref"],
                "computer_use_cleanup_ref": computer_use["cleanup"]["cleanup_ref"],
                "workflow_graph_id": workflow_graph_id,
                "workflow_node_id": workflow_node_id,
                "rust_daemon_core_materialized": true,
                "trace_receipt_id": trace_receipt_id,
                (*payload_key): payload
            });
            json!({
                "id": format!("event_{run_id}_{event_type}_{:08}", index + 1),
                "run_id": run_id,
                "agent_id": agent_id,
                "type": event_type,
                "summary": summary,
                "created_at": "rust_policy_core",
                "data": data
            })
        })
        .collect()
}

fn computer_use_source_event_kind(event_type: &str) -> &'static str {
    match event_type {
        "computer_use_environment_selected" => "ComputerUse.EnvironmentSelected",
        "computer_use_lease_acquired" => "ComputerUse.LeaseAcquired",
        "computer_use_observation" => "ComputerUse.Observation",
        "computer_use_action_proposed" => "ComputerUse.ActionProposed",
        "computer_use_verification" => "ComputerUse.Verification",
        "computer_use_commit_gate" => "ComputerUse.CommitGate",
        "computer_use_trajectory_written" => "ComputerUse.TrajectoryWritten",
        "computer_use_cleanup" => "ComputerUse.Cleanup",
        _ => "ComputerUse.Event",
    }
}

fn append_array_field(target: &mut serde_json::Map<String, Value>, key: &str, values: Vec<Value>) {
    if values.is_empty() {
        return;
    }
    let entry = target
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(existing) = entry {
        existing.extend(values);
    }
}

/// Insert `values` into `target[key]` immediately BEFORE the terminal run event
/// (`type` completed/canceled/failed/error) so the projected `turn.completed` (or
/// `turn.canceled`) stays LAST in the event stream while the materialized task/job/
/// checklist items land ahead of it. Falls back to a plain append when there is no
/// terminal event yet (the field is created if absent).
fn insert_array_field_before_terminal(
    target: &mut serde_json::Map<String, Value>,
    key: &str,
    values: Vec<Value>,
) {
    if values.is_empty() {
        return;
    }
    let entry = target
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(existing) = entry else {
        return;
    };
    let terminal_index = existing.iter().position(|event| {
        matches!(
            event.get("type").and_then(Value::as_str),
            Some("completed") | Some("canceled") | Some("failed") | Some("error")
        )
    });
    match terminal_index {
        Some(index) => {
            for (offset, value) in values.into_iter().enumerate() {
                existing.insert(index + offset, value);
            }
        }
        None => existing.extend(values),
    }
}

fn append_string_array_field(
    target: &mut serde_json::Map<String, Value>,
    key: &str,
    values: Vec<String>,
) {
    if values.is_empty() {
        return;
    }
    let entry = target
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(existing) = entry {
        existing.extend(values.into_iter().map(Value::String));
    }
}

fn stable_suffix(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::new();
    for byte in digest.iter().take(8) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    suffix
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

fn normalized_runtime_bridge_thread_control_action(
    value: &str,
) -> Result<String, RuntimeBridgeThreadControlAgentStateUpdateError> {
    match optional_trimmed(Some(value))
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "resume" => Ok("resume".to_string()),
        other => Err(
            RuntimeBridgeThreadControlAgentStateUpdateError::UnsupportedAction(other.to_string()),
        ),
    }
}

fn runtime_bridge_thread_status_for_action(action: &str) -> &'static str {
    match action {
        "resume" => "active",
        _ => "active",
    }
}

fn remove_runtime_service_agent_aliases(agent: &mut serde_json::Map<String, Value>) {
    for field in [
        "runtimeProfile",
        "runtimeSessionId",
        "runtimeBridgeId",
        "runtimeBridgeStatus",
        "runtimeBridgeSource",
        "fixtureProfile",
    ] {
        agent.remove(field);
    }
}

fn default_thread_turn_evidence_refs(operation: &str) -> Vec<String> {
    match operation {
        "thread_resume" => vec![
            "thread_resume_js_state_mutation_retired".to_string(),
            "rust_daemon_core_thread_resume_required".to_string(),
            "agentgres_thread_resume_truth_required".to_string(),
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn thread_control_agent_state_update_request(
        control_kind: &str,
    ) -> ThreadControlAgentStateUpdateRequest {
        ThreadControlAgentStateUpdateRequest {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            thread_id: "thread_1".to_string(),
            state_dir: Some("/tmp/ioi-thread-control-state".to_string()),
            event_stream_id: Some("thread_1:events".to_string()),
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
            seq: None,
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

    fn skill_hook_fixture_roots(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("ioi-thread-lifecycle-{label}-{seed}"));
        let workspace = root.join("workspace");
        let home = root.join("home");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        (workspace, home)
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

    fn runtime_bridge_thread_control_agent_state_update_request(
    ) -> RuntimeBridgeThreadControlAgentStateUpdateRequest {
        RuntimeBridgeThreadControlAgentStateUpdateRequest {
            schema_version: RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION
                .to_string(),
            thread_id: "thread_1".to_string(),
            agent: json!({
                "id": "agent_1",
                "cwd": "/workspace",
                "runtimeProfile": "runtime_service",
                "runtime_profile": "runtime_service",
                "runtimeBridgeStatus": "paused",
                "runtime_bridge_status": "paused",
                "updatedAt": "2026-06-06T06:15:00.000Z"
            }),
            action: "resume".to_string(),
            reason: Some("operator requested resume".to_string()),
            updated_at: "2026-06-06T06:20:00.000Z".to_string(),
            evidence_refs: vec![
                "runtime_bridge_thread_control_rust_owned".to_string(),
                "agentgres_runtime_bridge_thread_control_truth_required".to_string(),
            ],
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
    fn rust_policy_shapes_thread_control_agent_state_update_direct_record() {
        let record = ThreadControlAgentStateUpdateCore
            .plan(&thread_control_agent_state_update_request("thinking"))
            .expect("thread control agent state update record");
        let response = serde_json::to_value(record).expect("record serializes");

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
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_shapes_thread_turn_admission_required_direct_record() {
        let record = ThreadTurnAdmissionRequiredCore
            .plan(&thread_turn_admission_required_request())
            .expect("thread turn admission-required direct record");
        let response = serde_json::to_value(record).expect("record serializes");

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
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_shapes_lifecycle_admission_required_direct_record() {
        let record = LifecycleAdmissionRequiredCore
            .plan(&lifecycle_admission_required_request(
                "agent_status_control",
                "agent_status_update",
            ))
            .expect("lifecycle admission-required direct record");
        let response = serde_json::to_value(record).expect("record serializes");

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
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
            "state_dir": "/tmp/ioi-thread-control-state",
            "event_stream_id": "thread_1:events",
            "controls": {
                "mode": "agent",
                "approvalMode": "suggest",
                "model": {
                    "id": "auto",
                    "route_id": "route.local-first"
                }
            },
            "event_id": "evt_thread_control",
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
    fn rust_policy_shapes_agent_create_state_update_direct_record() {
        let record = AgentCreateStateUpdateCore
            .plan(&agent_create_state_update_request())
            .expect("agent create state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.create");
        assert_eq!(response["agent"]["id"], "agent_create_one");
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_shapes_thread_create_state_update_direct_record() {
        let record = ThreadCreateStateUpdateCore
            .plan(&thread_create_state_update_request())
            .expect("thread create state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.create");
        assert_eq!(response["thread_id"], "thread_create_one");
        assert_eq!(response["agent"]["id"], "agent_create_one");
        assert_eq!(
            response["thread"]["event_stream_id"],
            "thread_create_one:events"
        );
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
        assert_eq!(record.run["runtimeTask"]["taskId"], "task_run_create_one");
        assert_eq!(record.run["runtimeJob"]["jobId"], "job_run_create_one");
        assert_eq!(
            record.run["runtimeChecklist"]["checklistId"],
            "checklist_run_create_one"
        );
        assert_eq!(
            record.run["trace"]["runtimeTask"]["taskId"],
            "task_run_create_one"
        );
        assert!(record.run["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["type"] == "runtime_task"
                && event["data"]["rust_daemon_core_materialized"] == true));
        assert!(record.run["receipts"]
            .as_array()
            .expect("receipts")
            .iter()
            .any(|receipt| receipt["kind"] == "runtime_checklist"));
        assert!(record.run["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["name"] == "runtime-checklist.json"));
    }

    #[test]
    fn rust_policy_shapes_run_create_state_update_direct_record() {
        let record = RunCreateStateUpdateCore
            .plan(&run_create_state_update_request())
            .expect("run create state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "run.create");
        assert_eq!(response["run"]["id"], "run_create_one");
        assert_eq!(
            response["run"]["trace"]["usage_telemetry"]["total_tokens"],
            7
        );
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
    }

    #[test]
    fn rust_policy_materializes_computer_use_run_create_truth() {
        let mut request = run_create_state_update_request();
        request.run["objective"] = json!("Inspect the browser page without side effects.");
        request.run["trace"]["taskState"] = json!({
            "knownFacts": [],
            "evidenceRefs": []
        });
        request.run["computer_use_materialization_request"] = json!({
            "schema_version": COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
            "object": "ioi.runtime_computer_use_run_materialization_request",
            "run_id": "run_create_one",
            "agent_id": "agent_create_one",
            "prompt": "Inspect the browser page without side effects.",
            "mode": "send",
            "selected_model": "model_rust",
            "request": {
                "computer_use": true,
                "computer_use_lane": "native_browser",
                "computer_use_action_kind": "inspect",
                "computer_use_target_ref": "target_browser",
                "workflow_graph_id": "graph_browser",
                "workflow_node_id": "node_browser"
            }
        });

        let record = RunCreateStateUpdateCore
            .plan(&request)
            .expect("run create state update");

        assert!(record
            .run
            .get("computer_use_materialization_request")
            .is_none());
        assert_eq!(
            record.run["trace"]["computerUse"]["source"],
            "rust_daemon_core_run_create"
        );
        assert_eq!(
            record.run["trace"]["computerUse"]["lease"]["lane"],
            "native_browser"
        );
        assert_eq!(
            record.run["trace"]["computerUse"]["actionProposal"]["target_ref"],
            "target_browser"
        );
        assert!(record.run["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["type"] == "computer_use_observation"));
        assert!(record.run["receipts"]
            .as_array()
            .expect("receipts")
            .iter()
            .any(|receipt| receipt["kind"] == "computer_use_trace"));
        assert!(record.run["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["name"] == "computer-use-trace.json"));
        assert!(record.run["trace"]["taskState"]["evidenceRefs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_daemon_core_computer_use_run_materialization"));
    }

    // Regression: a run-create candidate that ALREADY carries a terminal `completed` event
    // and ALSO requests computer-use materialization must keep the terminal LAST (the
    // materialized computer-use events splice ahead of it). Before the splice fix the
    // materializer plain-appended, landing computer_use_cleanup after `completed`.
    #[test]
    fn rust_policy_keeps_turn_completed_last_when_computer_use_materializes() {
        let mut request = run_create_state_update_request();
        request.run["events"] = json!([
            { "type": "run_started", "receipt_refs": ["r_terminal_last"], "data": {} },
            { "type": "completed", "receipt_refs": ["r_terminal_last"], "data": {} },
        ]);
        request.run["computer_use_materialization_request"] = json!({
            "schema_version": COMPUTER_USE_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
            "object": "ioi.runtime_computer_use_run_materialization_request",
            "run_id": "run_create_one",
            "agent_id": "agent_create_one",
            "prompt": "Inspect the browser page without side effects.",
            "mode": "send",
            "selected_model": "model_rust",
            "request": {
                "computer_use": true,
                "computer_use_lane": "native_browser",
                "computer_use_action_kind": "inspect",
                "computer_use_target_ref": "target_browser",
                "workflow_graph_id": "graph_browser",
                "workflow_node_id": "node_browser"
            }
        });

        let record = RunCreateStateUpdateCore
            .plan(&request)
            .expect("run create state update");
        let events = record.run["events"].as_array().expect("events");
        assert!(
            events.iter().any(|event| event["type"] == "computer_use_observation"),
            "computer-use events must be materialized",
        );
        assert_eq!(
            events.last().expect("last event")["type"],
            "completed",
            "turn.completed must remain LAST after computer-use materialization",
        );
    }

    #[test]
    fn rust_policy_materializes_skill_hook_run_create_truth() {
        let (workspace, home) = skill_hook_fixture_roots("run-create");
        std::fs::create_dir_all(workspace.join(".cursor/skills/repo-cartographer")).unwrap();
        std::fs::write(
            workspace.join(".cursor/skills/repo-cartographer/SKILL.md"),
            "---\nname: Repo Cartographer\ndescription: Maps code\n---\n# Repo Cartographer\n",
        )
        .unwrap();
        std::fs::write(
            workspace.join(".cursor/hooks.json"),
            json!({
                "hooks": [
                    {
                        "name": "workflow-observer",
                        "event_kinds": ["workflow_activation"],
                        "side_effect_class": "none"
                    },
                    {
                        "name": "pre-model-redaction",
                        "event_kinds": ["pre_model"],
                        "authority_scopes": ["runtime.read"],
                        "tool_contracts": ["fs.read"],
                        "command": "redacted-command",
                        "failure_policy": "block"
                    },
                    {
                        "name": "post-model-blocked",
                        "event_kinds": ["post_model"],
                        "command": "blocked-command"
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let mut request = run_create_state_update_request();
        request.run["trace"]["taskState"] = json!({
            "knownFacts": [],
            "evidenceRefs": []
        });
        request.run["trace"]["promptAudit"] = json!({
            "evidenceRefs": []
        });
        request.run["skill_hook_materialization_request"] = json!({
            "schema_version": SKILL_HOOK_RUN_MATERIALIZATION_REQUEST_SCHEMA_VERSION,
            "object": "ioi.runtime_skill_hook_run_materialization_request",
            "run_id": "run_create_one",
            "agent_id": "agent_create_one",
            "workspace_root": workspace.to_string_lossy(),
            "home_dir": home.to_string_lossy(),
            "agent_options": {
                "skillNames": [],
                "hookNames": []
            },
            "request_options": {}
        });

        let record = RunCreateStateUpdateCore
            .plan(&request)
            .expect("run create state update");

        assert!(record
            .run
            .get("skill_hook_materialization_request")
            .is_none());
        assert_eq!(
            record.run["runtimeTask"]["activeSkillHookManifestId"],
            "skill_hook_manifest_run_create_one"
        );
        assert!(record.run["runtimeTask"]["evidenceRefs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "rust_daemon_core_runtime_task_job_materialization"));
        assert_eq!(
            record.run["activeSkillHookManifest"]["schemaVersion"],
            "ioi.agent-runtime.active-skill-hook-manifest.v1"
        );
        assert_eq!(
            record.run["activeSkillHookManifest"]["selectedSkillIds"]
                .as_array()
                .expect("selected skills")
                .len(),
            1
        );
        assert_eq!(
            record.run["activeSkillHookManifest"]["selectedHookIds"]
                .as_array()
                .expect("selected hooks")
                .len(),
            3
        );
        assert_eq!(record.run["hookDryRunPlan"]["decisionCount"], 3);
        assert_eq!(record.run["hookDryRunPlan"]["wouldRunCount"], 1);
        assert_eq!(record.run["hookDryRunPlan"]["blockedCount"], 1);
        assert_eq!(record.run["hookDryRunPlan"]["skippedCount"], 1);
        assert_eq!(record.run["hookInvocationLedger"]["invocationCount"], 3);
        assert_eq!(record.run["hookInvocationLedger"]["escalationCount"], 1);
        assert_eq!(
            record.run["trace"]["promptAudit"]["activeSkillHookManifestId"],
            record.run["activeSkillHookManifest"]["manifestId"]
        );
        assert!(record.run["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["type"] == "skill_hook_manifest"
                && event["data"]["rust_daemon_core_materialized"] == true));
        assert!(record.run["receipts"]
            .as_array()
            .expect("receipts")
            .iter()
            .any(|receipt| receipt["kind"] == "hook_invocation_ledger"));
        assert!(record.run["artifacts"]
            .as_array()
            .expect("artifacts")
            .iter()
            .any(|artifact| artifact["name"] == "active-skill-hook-manifest.json"));
        assert!(record.run["trace"]["taskState"]["evidenceRefs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_daemon_core_skill_hook_run_materialization"));
    }

    #[test]
    fn rust_policy_rejects_js_skill_hook_materialization_candidate() {
        let mut request = run_create_state_update_request();
        request.run["activeSkillHookManifest"] = json!({
            "source": "js_skill_hook_manifest"
        });

        let error = RunCreateStateUpdateCore
            .plan(&request)
            .expect_err("retired JS skill hook materialization candidate rejected");

        assert_eq!(
            error,
            RunCreateStateUpdateError::RetiredSkillHookMaterializationCandidate
        );
    }

    #[test]
    fn rust_policy_rejects_js_runtime_task_job_projection_candidate() {
        let mut request = run_create_state_update_request();
        request.run["runtimeTask"] = json!({
            "source": "js_runtime_record_projection"
        });

        let error = RunCreateStateUpdateCore
            .plan(&request)
            .expect_err("retired JS runtime task/job projection candidate rejected");

        assert_eq!(
            error,
            RunCreateStateUpdateError::RetiredRuntimeTaskJobProjectionCandidate
        );

        let mut trace_request = run_create_state_update_request();
        trace_request.run["trace"]["runtimeJob"] = json!({
            "source": "js_trace_runtime_job_projection"
        });

        let trace_error = RunCreateStateUpdateCore
            .plan(&trace_request)
            .expect_err("retired trace runtime task/job projection candidate rejected");

        assert_eq!(
            trace_error,
            RunCreateStateUpdateError::RetiredRuntimeTaskJobProjectionCandidate
        );
    }

    #[test]
    fn rust_policy_rejects_js_computer_use_projection_candidate() {
        let mut request = run_create_state_update_request();
        request.run["computerUse"] = json!({
            "source": "js_computer_use_projection"
        });

        let error = RunCreateStateUpdateCore
            .plan(&request)
            .expect_err("retired JS projection candidate rejected");

        assert_eq!(
            error,
            RunCreateStateUpdateError::RetiredComputerUseProjectionCandidate
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
    fn rust_policy_shapes_agent_status_state_update_direct_record() {
        let record = AgentStatusStateUpdateCore
            .plan(&agent_status_state_update_request())
            .expect("agent status state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.archive");
        assert_eq!(response["agent"]["id"], "agent_status_one");
        assert_eq!(response["agent"]["status"], "archived");
        assert_eq!(response["agent"]["updatedAt"], "2026-06-06T06:25:00.000Z");
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_shapes_agent_delete_state_update_direct_record() {
        let record = AgentDeleteStateUpdateCore
            .plan(&agent_delete_state_update_request())
            .expect("agent delete state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "agent.delete");
        assert_eq!(response["agent"]["id"], "agent_delete_one");
        assert_eq!(response["agent"]["status"], "deleted");
        assert_eq!(response["agent"]["deletedAt"], "2026-06-06T06:40:00.000Z");
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
        assert_eq!(record.agent["runtime_profile"], "runtime_service");
        assert_eq!(record.agent["runtime_session_id"], "session_runtime");
        assert_eq!(record.agent["runtime_bridge_id"], "bridge_runtime");
        assert_eq!(record.agent["runtime_bridge_source"], "runtime_service");
        assert_eq!(record.agent["fixture_profile"], Value::Null);
        for field in [
            "runtimeProfile",
            "runtimeSessionId",
            "runtimeBridgeId",
            "runtimeBridgeStatus",
            "runtimeBridgeSource",
            "fixtureProfile",
        ] {
            assert!(record.agent.get(field).is_none());
        }
    }

    #[test]
    fn rust_policy_shapes_runtime_bridge_thread_start_agent_state_update_direct_record() {
        let record = RuntimeBridgeThreadStartAgentStateUpdateCore
            .plan(&runtime_bridge_thread_start_agent_state_update_request())
            .expect("runtime bridge thread start agent state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.runtime_bridge.start");
        assert_eq!(response["bridge_start"]["session_id"], "session_runtime");
        assert_eq!(response["bridge_start"]["bridge_id"], "bridge_runtime");
        for field in ["runtimeProfile", "sessionId", "bridgeId", "updatedAt"] {
            assert!(response["bridge_start"].get(field).is_none());
        }
        assert_eq!(response["agent"]["runtime_session_id"], "session_runtime");
        assert_eq!(response["agent"]["runtime_bridge_id"], "bridge_runtime");
        assert_eq!(
            response["agent"]["runtime_bridge_source"],
            "runtime_service"
        );
        assert_eq!(response["agent"]["fixture_profile"], Value::Null);
        for field in [
            "runtimeProfile",
            "runtimeSessionId",
            "runtimeBridgeId",
            "runtimeBridgeStatus",
            "runtimeBridgeSource",
            "fixtureProfile",
        ] {
            assert!(response["agent"].get(field).is_none());
        }
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
    }

    #[test]
    fn rust_policy_plans_runtime_bridge_thread_control_agent_state_update() {
        let record = RuntimeBridgeThreadControlAgentStateUpdateCore
            .plan(&runtime_bridge_thread_control_agent_state_update_request())
            .expect("runtime bridge thread control agent state update");

        assert_eq!(
            record.schema_version,
            RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "thread.runtime_bridge.control");
        assert_eq!(record.thread_id, "thread_1");
        assert_eq!(record.agent_id, "agent_1");
        assert_eq!(record.action, "resume");
        assert_eq!(record.updated_at, "2026-06-06T06:20:00.000Z");
        assert_eq!(record.control["action"], "resume");
        assert_eq!(record.control["reason"], "operator requested resume");
        assert_eq!(record.control["runtime_bridge_status"], "active");
        assert_eq!(
            record.control["evidence_refs"],
            json!([
                "runtime_bridge_thread_control_rust_owned",
                "agentgres_runtime_bridge_thread_control_truth_required"
            ])
        );
        assert!(record.control.get("runtimeBridgeStatus").is_none());
        assert_eq!(record.agent["status"], "active");
        assert_eq!(record.agent["runtime_bridge_status"], "active");
        for field in [
            "runtimeProfile",
            "runtimeSessionId",
            "runtimeBridgeId",
            "runtimeBridgeStatus",
            "runtimeBridgeSource",
            "fixtureProfile",
        ] {
            assert!(record.agent.get(field).is_none());
        }
        assert_eq!(record.agent["updatedAt"], "2026-06-06T06:20:00.000Z");
    }

    #[test]
    fn rust_policy_shapes_runtime_bridge_thread_control_agent_state_update_direct_record() {
        let record = RuntimeBridgeThreadControlAgentStateUpdateCore
            .plan(&runtime_bridge_thread_control_agent_state_update_request())
            .expect("runtime bridge thread control agent state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "thread.runtime_bridge.control");
        assert_eq!(response["control"]["action"], "resume");
        assert_eq!(response["control"]["runtime_bridge_status"], "active");
        assert_eq!(response["agent"]["id"], "agent_1");
        assert_eq!(response["agent"]["runtime_bridge_status"], "active");
        for field in [
            "runtimeProfile",
            "runtimeSessionId",
            "runtimeBridgeId",
            "runtimeBridgeStatus",
            "runtimeBridgeSource",
            "fixtureProfile",
        ] {
            assert!(response["agent"].get(field).is_none());
        }
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_shapes_runtime_bridge_turn_run_state_update_direct_record() {
        let record = RuntimeBridgeTurnRunStateUpdateCore
            .plan(&runtime_bridge_turn_run_state_update_request())
            .expect("runtime bridge turn run state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "turn.runtime_bridge.submit");
        assert_eq!(response["run"]["id"], "run_runtime_bridge");
        assert_eq!(response["run"]["agentId"], "agent_1");
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_plans_subagent_propagated_cancel_record_state_update() {
        let mut request = subagent_record_state_update_request();
        request.operation_kind = "subagent.cancel.propagate".to_string();
        request.subagent["status"] = json!("canceled");
        request.subagent["lifecycle_status"] = json!("canceled");
        request.subagent["cancellation_inherited"] = json!(true);
        request.subagent["propagated_from_thread_id"] = json!("thread_1");

        let record = SubagentRecordStateUpdateCore
            .plan(&request)
            .expect("subagent propagated cancel record state update");

        assert_eq!(record.operation_kind, "subagent.cancel.propagate");
        assert_eq!(record.subagent["status"], "canceled");
        assert_eq!(record.subagent["cancellation_inherited"], true);
        assert_eq!(record.subagent["propagated_from_thread_id"], "thread_1");
    }

    #[test]
    fn rust_policy_shapes_subagent_record_state_update_direct_record() {
        let record = SubagentRecordStateUpdateCore
            .plan(&subagent_record_state_update_request())
            .expect("subagent record state update record");
        let response = serde_json::to_value(record).expect("record serializes");

        assert_eq!(response["status"], "planned");
        assert_eq!(response["operation_kind"], "subagent.wait");
        assert_eq!(response["subagent"]["subagent_id"], "subagent_1");
        assert!(response.get("source").is_none());
        assert!(response.get("backend").is_none());
        assert!(response.get("record").is_none());
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
    fn rust_policy_rejects_retired_diagnostics_block_thread_turn_admission() {
        let mut request = thread_turn_admission_required_request();
        request.operation = "thread_turn_diagnostics_block".to_string();
        request.operation_kind = "turn.diagnostics_block".to_string();

        let error = ThreadTurnAdmissionRequiredCore
            .plan(&request)
            .expect_err("retired diagnostics block admission path should fail");

        assert_eq!(
            error,
            ThreadTurnAdmissionRequiredError::UnsupportedOperationKind(
                "turn.diagnostics_block".to_string(),
            )
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
    fn rust_policy_rejects_invalid_runtime_bridge_thread_control_agent_state_update_schema() {
        let mut request = runtime_bridge_thread_control_agent_state_update_request();
        request.schema_version = "legacy.runtime-bridge-control-state-update".to_string();

        let error = RuntimeBridgeThreadControlAgentStateUpdateCore
            .plan(&request)
            .expect_err("invalid schema should be rejected");

        assert_eq!(
            error,
            RuntimeBridgeThreadControlAgentStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_BRIDGE_THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.runtime-bridge-control-state-update".to_string(),
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

    #[test]
    fn rust_policy_rejects_runtime_bridge_turn_projection_candidate_transport() {
        let request = json!({
            "schema_version": RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
            "thread_id": "thread_1",
            "agent": {
                "id": "agent_1",
                "cwd": "/workspace"
            },
            "projection": {
                "run_id": "run_runtime_bridge",
                "turn_id": "turn_runtime_bridge"
            },
            "run": {
                "id": "run_runtime_bridge",
                "agentId": "agent_1",
                "mode": "send",
                "status": "completed",
                "createdAt": "2026-06-06T06:34:00.000Z",
                "updatedAt": "2026-06-06T06:35:00.000Z"
            }
        });

        let error = serde_json::from_value::<RuntimeBridgeTurnRunStateUpdateRequest>(request)
            .expect_err("retired projection candidate transport should be rejected");

        assert!(error.to_string().contains("unknown field `projection`"));
    }
}
