use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    AGENT_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    AGENT_STATUS_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_BRIDGE_THREAD_START_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_BRIDGE_TURN_RUN_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    SUBAGENT_RECORD_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION,
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
    pub control: Value,
    pub agent: Value,
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

#[derive(Debug, Default, Clone)]
pub struct ThreadControlAgentStateUpdateCore;

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
            agent.insert(
                "modelRouteDecision".to_string(),
                model_route.get("decision").cloned().unwrap_or(Value::Null),
            );
        }

        agent.insert("runtimeControls".to_string(), Value::Object(controls));
        agent.insert("updatedAt".to_string(), Value::String(updated_at.clone()));
        let control = json!({
            "control_kind": control_kind,
            "event_id": request.event_id,
            "seq": request.seq,
            "created_at": request.created_at,
            "workspace_trust_warning_event_id": request.workspace_trust_warning_event_id,
        });

        Ok(ThreadControlAgentStateUpdateRecord {
            schema_version: THREAD_CONTROL_AGENT_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_thread_control_agent_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: format!("thread.{control_kind}"),
            thread_id: request.thread_id.clone(),
            agent_id,
            updated_at,
            control,
            agent: Value::Object(agent),
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
        assert!(record.control.get("workspaceTrustWarningEventId").is_none());
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
