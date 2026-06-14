use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    run_cancel::{RunCancelStateUpdateCore, RunCancelStateUpdateRequest},
    thread_lifecycle::{RunCreateStateUpdateCore, RunCreateStateUpdateRequest},
    RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
    RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION,
    RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
    RUNTIME_TASK_JOB_PROJECTION_RESULT_SCHEMA_VERSION,
    RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeTaskJobCancelStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    InvalidCancelKind(String),
    PublicIdMismatch {
        expected: String,
        actual: String,
    },
    RunIdMismatch {
        expected: String,
        actual: String,
    },
    RunCancelInvalid(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeTaskJobProjectionError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    InvalidProjectionKind(String),
    PublicIdMismatch {
        expected: String,
        actual: String,
    },
    ReplayReadFailed(String),
    ReplayRecordInvalid(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeTaskJobCreateStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    AgentIdMismatch {
        expected: String,
        actual: String,
    },
    RunCreateInvalid(String),
    ProjectionUnavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTaskJobCancelStateUpdateRequest {
    pub schema_version: String,
    pub cancel_kind: String,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub canceled_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTaskJobCancelStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub cancel_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    pub run_id: String,
    pub updated_at: String,
    pub runtime_task: Value,
    pub runtime_job: Value,
    pub runtime_checklist: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTaskJobCreateStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub run: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTaskJobCreateStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub task_id: String,
    pub job_id: String,
    pub run_id: String,
    pub agent_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub runtime_task: Value,
    pub runtime_job: Value,
    pub runtime_checklist: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTaskJobProjectionRequest {
    pub schema_version: String,
    pub projection_kind: String,
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTaskJobProjectionRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    pub projection_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    pub records: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_task: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_job: Option<Value>,
    pub record_count: usize,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeTaskJobCancelCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeTaskJobCancelCommandError {
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

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeTaskJobProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeTaskJobProjectionCommandError {
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

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeTaskJobCreateCommandError {
    code: &'static str,
    message: String,
}

impl RuntimeTaskJobCreateCommandError {
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
pub struct RuntimeTaskJobCancelStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeTaskJobCancelStateUpdateRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeTaskJobProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeTaskJobProjectionRequest,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeTaskJobCreateStateUpdateBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: RuntimeTaskJobCreateStateUpdateRequest,
}

pub fn plan_runtime_task_job_cancel_state_update_response(
    request: RuntimeTaskJobCancelStateUpdateBridgeRequest,
) -> Result<Value, RuntimeTaskJobCancelCommandError> {
    let record = RuntimeTaskJobCancelStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            RuntimeTaskJobCancelCommandError::from_debug(
                "runtime_task_job_cancel_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_task_job_cancel_state_update_command",
        "backend": runtime_task_job_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "cancel_kind": record.cancel_kind.clone(),
        "task_id": record.task_id.clone(),
        "job_id": record.job_id.clone(),
        "run_id": record.run_id.clone(),
        "updated_at": record.updated_at.clone(),
        "runtime_task": record.runtime_task.clone(),
        "runtime_job": record.runtime_job.clone(),
        "runtime_checklist": record.runtime_checklist.clone(),
        "run": record.run.clone(),
    }))
}

pub fn plan_runtime_task_job_create_state_update_response(
    request: RuntimeTaskJobCreateStateUpdateBridgeRequest,
) -> Result<Value, RuntimeTaskJobCreateCommandError> {
    let record = RuntimeTaskJobCreateStateUpdateCore
        .plan(&request.request)
        .map_err(|error| {
            RuntimeTaskJobCreateCommandError::from_debug(
                "runtime_task_job_create_state_update_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_task_job_create_state_update_command",
        "backend": runtime_task_job_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "task_id": record.task_id.clone(),
        "job_id": record.job_id.clone(),
        "run_id": record.run_id.clone(),
        "agent_id": record.agent_id.clone(),
        "created_at": record.created_at.clone(),
        "updated_at": record.updated_at.clone(),
        "runtime_task": record.runtime_task.clone(),
        "runtime_job": record.runtime_job.clone(),
        "runtime_checklist": record.runtime_checklist.clone(),
        "run": record.run.clone(),
    }))
}

pub fn project_runtime_task_job_projection_response(
    request: RuntimeTaskJobProjectionBridgeRequest,
) -> Result<Value, RuntimeTaskJobProjectionCommandError> {
    let record = RuntimeTaskJobProjectionCore
        .project(&request.request)
        .map_err(|error| {
            RuntimeTaskJobProjectionCommandError::from_debug(
                "runtime_task_job_projection_invalid",
                error,
            )
        })?;
    Ok(json!({
        "source": "rust_runtime_task_job_projection_command",
        "backend": runtime_task_job_policy_backend(request.backend),
        "record": record.clone(),
        "status": record.status.clone(),
        "operation_kind": record.operation_kind.clone(),
        "projection_kind": record.projection_kind.clone(),
        "agent_id": record.agent_id.clone(),
        "status_filter": record.status_filter.clone(),
        "task_id": record.task_id.clone(),
        "job_id": record.job_id.clone(),
        "records": record.records.clone(),
        "runtime_task": record.runtime_task.clone(),
        "runtime_job": record.runtime_job.clone(),
        "record_count": record.record_count,
    }))
}

fn runtime_task_job_policy_backend(backend: Option<String>) -> String {
    backend.unwrap_or_else(|| "rust_policy".to_string())
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeTaskJobCancelStateUpdateCore;

impl RuntimeTaskJobCancelStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeTaskJobCancelStateUpdateRequest,
    ) -> Result<RuntimeTaskJobCancelStateUpdateRecord, RuntimeTaskJobCancelStateUpdateError> {
        request.validate()?;
        let run_id = optional_trimmed(request.run_id.as_deref())
            .or_else(|| json_string_value(&request.run, "id"))
            .ok_or(RuntimeTaskJobCancelStateUpdateError::MissingField("run.id"))?;
        let run_record_id = json_string_value(&request.run, "id")
            .ok_or(RuntimeTaskJobCancelStateUpdateError::MissingField("run.id"))?;
        if run_record_id != run_id {
            return Err(RuntimeTaskJobCancelStateUpdateError::RunIdMismatch {
                expected: run_id,
                actual: run_record_id,
            });
        }
        let cancel_kind = optional_trimmed(Some(request.cancel_kind.as_str())).unwrap();
        let expected_task_id = format!("task_{run_id}");
        let expected_job_id = format!("job_{run_id}");
        let (operation_kind, task_id, job_id) = match cancel_kind.as_str() {
            "task" => {
                let task_id = optional_trimmed(request.task_id.as_deref()).ok_or(
                    RuntimeTaskJobCancelStateUpdateError::MissingField("task_id"),
                )?;
                if task_id != expected_task_id {
                    return Err(RuntimeTaskJobCancelStateUpdateError::PublicIdMismatch {
                        expected: expected_task_id,
                        actual: task_id,
                    });
                }
                ("task.cancel", Some(task_id), None)
            }
            "job" => {
                let job_id = optional_trimmed(request.job_id.as_deref())
                    .ok_or(RuntimeTaskJobCancelStateUpdateError::MissingField("job_id"))?;
                if job_id != expected_job_id {
                    return Err(RuntimeTaskJobCancelStateUpdateError::PublicIdMismatch {
                        expected: expected_job_id,
                        actual: job_id,
                    });
                }
                ("job.cancel", None, Some(job_id))
            }
            other => {
                return Err(RuntimeTaskJobCancelStateUpdateError::InvalidCancelKind(
                    other.to_string(),
                ))
            }
        };
        let run_cancel = RunCancelStateUpdateCore
            .plan(&RunCancelStateUpdateRequest {
                schema_version: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
                run_id: Some(run_id.clone()),
                run: request.run.clone(),
                canceled_at: request.canceled_at.clone(),
            })
            .map_err(|error| {
                RuntimeTaskJobCancelStateUpdateError::RunCancelInvalid(format!("{error:?}"))
            })?;
        Ok(RuntimeTaskJobCancelStateUpdateRecord {
            schema_version: RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_task_job_cancel_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: operation_kind.to_string(),
            cancel_kind,
            task_id,
            job_id,
            run_id,
            updated_at: run_cancel.updated_at.clone(),
            runtime_task: run_cancel.runtime_task,
            runtime_job: run_cancel.runtime_job,
            runtime_checklist: run_cancel.runtime_checklist,
            run: run_cancel.run,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeTaskJobCreateStateUpdateCore;

impl RuntimeTaskJobCreateStateUpdateCore {
    pub fn plan(
        &self,
        request: &RuntimeTaskJobCreateStateUpdateRequest,
    ) -> Result<RuntimeTaskJobCreateStateUpdateRecord, RuntimeTaskJobCreateStateUpdateError> {
        request.validate()?;
        let requested_agent_id = optional_trimmed(request.agent_id.as_deref());
        let planned_run_create = RunCreateStateUpdateCore
            .plan(&RunCreateStateUpdateRequest {
                schema_version: RUN_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
                run: request.run.clone(),
            })
            .map_err(|error| {
                RuntimeTaskJobCreateStateUpdateError::RunCreateInvalid(format!("{error:?}"))
            })?;
        let run_id = planned_run_create.run_id;
        let agent_id = planned_run_create.agent_id;
        if let Some(expected_agent_id) = requested_agent_id {
            if expected_agent_id != agent_id {
                return Err(RuntimeTaskJobCreateStateUpdateError::AgentIdMismatch {
                    expected: expected_agent_id,
                    actual: agent_id,
                });
            }
        }
        let projected = project_runtime_task_job_records_for_run(&planned_run_create.run)
            .ok_or(RuntimeTaskJobCreateStateUpdateError::ProjectionUnavailable)?;
        let status = runtime_task_job_status_for_run_status(
            json_string_value(&planned_run_create.run, "status").as_deref(),
        );
        let created_at = planned_run_create.created_at;
        let updated_at = planned_run_create.updated_at;
        let runtime_checklist = runtime_checklist_record_for_run(
            &projected.runtime_task,
            &projected.runtime_job,
            &run_id,
            status,
            &created_at,
            &updated_at,
        );
        let runtime_job =
            attach_runtime_checklist_to_job(projected.runtime_job, &runtime_checklist);
        let mut run = object_value(&planned_run_create.run)
            .ok_or(RuntimeTaskJobCreateStateUpdateError::MissingField("run"))?;
        run.insert("runtimeTask".to_string(), projected.runtime_task.clone());
        run.insert("runtimeJob".to_string(), runtime_job.clone());
        run.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        let task_id = json_string_value(&projected.runtime_task, "taskId").ok_or(
            RuntimeTaskJobCreateStateUpdateError::MissingField("runtime_task.taskId"),
        )?;
        let job_id = json_string_value(&runtime_job, "jobId").ok_or(
            RuntimeTaskJobCreateStateUpdateError::MissingField("runtime_job.jobId"),
        )?;

        Ok(RuntimeTaskJobCreateStateUpdateRecord {
            schema_version: RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_task_job_create_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "task.create".to_string(),
            task_id,
            job_id,
            run_id,
            agent_id,
            created_at,
            updated_at,
            runtime_task: projected.runtime_task,
            runtime_job,
            runtime_checklist,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeTaskJobProjectionCore;

impl RuntimeTaskJobProjectionCore {
    pub fn project(
        &self,
        request: &RuntimeTaskJobProjectionRequest,
    ) -> Result<RuntimeTaskJobProjectionRecord, RuntimeTaskJobProjectionError> {
        request.validate()?;
        let projection_kind = optional_trimmed(Some(request.projection_kind.as_str())).unwrap();
        let agent_id = optional_trimmed(request.agent_id.as_deref());
        let status_filter = optional_trimmed(request.status.as_deref());
        let replayed_runs = runtime_task_job_runs_from_state_dir(request.state_dir.as_deref())?;
        let projected = replayed_runs
            .iter()
            .filter_map(project_runtime_task_job_records_for_run)
            .collect::<Vec<_>>();

        let mut records = Vec::<Value>::new();
        let mut runtime_task = None;
        let mut runtime_job = None;
        let mut task_id = optional_trimmed(request.task_id.as_deref());
        let mut job_id = optional_trimmed(request.job_id.as_deref());

        match projection_kind.as_str() {
            "task.list" => {
                records = projected
                    .iter()
                    .map(|entry| entry.runtime_task.clone())
                    .filter(|record| {
                        runtime_task_job_record_matches(record, &agent_id, &status_filter)
                    })
                    .collect();
            }
            "job.list" => {
                records = projected
                    .iter()
                    .map(|entry| entry.runtime_job.clone())
                    .filter(|record| {
                        runtime_task_job_record_matches(record, &agent_id, &status_filter)
                    })
                    .collect();
            }
            "task.get" => {
                let requested_task_id = task_id
                    .clone()
                    .ok_or(RuntimeTaskJobProjectionError::MissingField("task_id"))?;
                let expected_run_id = public_id_suffix("task", &requested_task_id).ok_or(
                    RuntimeTaskJobProjectionError::PublicIdMismatch {
                        expected: "task_<run_id>".to_string(),
                        actual: requested_task_id.clone(),
                    },
                )?;
                runtime_task = projected
                    .iter()
                    .map(|entry| entry.runtime_task.clone())
                    .find(|record| {
                        json_string_value(record, "taskId").as_deref()
                            == Some(requested_task_id.as_str())
                            && json_string_value(record, "runId").as_deref()
                                == Some(expected_run_id.as_str())
                    });
                if let Some(record) = runtime_task.clone() {
                    records.push(record);
                }
            }
            "job.get" => {
                let requested_job_id = job_id
                    .clone()
                    .ok_or(RuntimeTaskJobProjectionError::MissingField("job_id"))?;
                let expected_run_id = public_id_suffix("job", &requested_job_id).ok_or(
                    RuntimeTaskJobProjectionError::PublicIdMismatch {
                        expected: "job_<run_id>".to_string(),
                        actual: requested_job_id.clone(),
                    },
                )?;
                runtime_job = projected
                    .iter()
                    .map(|entry| entry.runtime_job.clone())
                    .find(|record| {
                        json_string_value(record, "jobId").as_deref()
                            == Some(requested_job_id.as_str())
                            && json_string_value(record, "runId").as_deref()
                                == Some(expected_run_id.as_str())
                    });
                if let Some(record) = runtime_job.clone() {
                    records.push(record);
                }
            }
            other => {
                return Err(RuntimeTaskJobProjectionError::InvalidProjectionKind(
                    other.to_string(),
                ))
            }
        }

        if projection_kind == "task.list" {
            task_id = None;
        }
        if projection_kind == "job.list" {
            job_id = None;
        }

        Ok(RuntimeTaskJobProjectionRecord {
            schema_version: RUNTIME_TASK_JOB_PROJECTION_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_task_job_projection".to_string(),
            status: "projected".to_string(),
            operation_kind: projection_kind.clone(),
            projection_kind,
            agent_id,
            status_filter,
            task_id,
            job_id,
            record_count: records.len(),
            records,
            runtime_task,
            runtime_job,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl RuntimeTaskJobCancelStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeTaskJobCancelStateUpdateError> {
        if self.schema_version != RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeTaskJobCancelStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.cancel_kind.as_str())).is_none() {
            return Err(RuntimeTaskJobCancelStateUpdateError::MissingField(
                "cancel_kind",
            ));
        }
        if !self.run.is_object() {
            return Err(RuntimeTaskJobCancelStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(Some(self.canceled_at.as_str())).is_none() {
            return Err(RuntimeTaskJobCancelStateUpdateError::MissingField(
                "canceled_at",
            ));
        }
        Ok(())
    }
}

impl RuntimeTaskJobProjectionRequest {
    pub fn validate(&self) -> Result<(), RuntimeTaskJobProjectionError> {
        if self.schema_version != RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeTaskJobProjectionError::InvalidSchemaVersion {
                expected: RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        let Some(projection_kind) = optional_trimmed(Some(self.projection_kind.as_str())) else {
            return Err(RuntimeTaskJobProjectionError::MissingField(
                "projection_kind",
            ));
        };
        match projection_kind.as_str() {
            "task.list" | "job.list" | "task.get" | "job.get" => {}
            other => {
                return Err(RuntimeTaskJobProjectionError::InvalidProjectionKind(
                    other.to_string(),
                ))
            }
        }
        if projection_kind == "task.get" && optional_trimmed(self.task_id.as_deref()).is_none() {
            return Err(RuntimeTaskJobProjectionError::MissingField("task_id"));
        }
        if projection_kind == "job.get" && optional_trimmed(self.job_id.as_deref()).is_none() {
            return Err(RuntimeTaskJobProjectionError::MissingField("job_id"));
        }
        if optional_trimmed(self.state_dir.as_deref()).is_none() {
            return Err(RuntimeTaskJobProjectionError::MissingField("state_dir"));
        }
        Ok(())
    }
}

fn runtime_task_job_runs_from_state_dir(
    state_dir: Option<&str>,
) -> Result<Vec<Value>, RuntimeTaskJobProjectionError> {
    let state_dir = optional_trimmed(state_dir)
        .ok_or(RuntimeTaskJobProjectionError::MissingField("state_dir"))?;
    let runs_dir = Path::new(&state_dir).join("runs");
    if !runs_dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&runs_dir).map_err(|error| {
        RuntimeTaskJobProjectionError::ReplayReadFailed(format!(
            "runtime task/job projection could not read Agentgres runs: {error}"
        ))
    })?;
    let mut paths = Vec::<PathBuf>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            RuntimeTaskJobProjectionError::ReplayReadFailed(format!(
                "runtime task/job projection could not inspect Agentgres run entry: {error}"
            ))
        })?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut runs = Vec::new();
    for path in paths.into_iter().take(1000) {
        let contents = fs::read_to_string(&path).map_err(|error| {
            RuntimeTaskJobProjectionError::ReplayReadFailed(format!(
                "runtime task/job projection could not read Agentgres run record {}: {error}",
                path.display()
            ))
        })?;
        let value: Value = serde_json::from_str(&contents).map_err(|error| {
            RuntimeTaskJobProjectionError::ReplayRecordInvalid(format!(
                "runtime task/job projection found invalid Agentgres run record {}: {error}",
                path.display()
            ))
        })?;
        runs.push(value);
    }
    Ok(runs)
}

impl RuntimeTaskJobCreateStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RuntimeTaskJobCreateStateUpdateError> {
        if self.schema_version != RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RuntimeTaskJobCreateStateUpdateError::InvalidSchemaVersion {
                expected: RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(RuntimeTaskJobCreateStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(self.agent_id.as_deref()).is_none() {
            return Err(RuntimeTaskJobCreateStateUpdateError::MissingField(
                "agent_id",
            ));
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

fn json_string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| optional_trimmed(Some(value)))
}

fn json_path_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current
        .as_str()
        .and_then(|entry| optional_trimmed(Some(entry)))
}

fn json_array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn public_id_suffix(kind: &str, public_id: &str) -> Option<String> {
    let prefix = match kind {
        "task" => "task_",
        "job" => "job_",
        _ => return None,
    };
    public_id
        .strip_prefix(prefix)
        .and_then(|suffix| optional_trimmed(Some(suffix)))
}

#[derive(Debug, Clone)]
struct ProjectedRuntimeTaskJobRecords {
    runtime_task: Value,
    runtime_job: Value,
}

fn project_runtime_task_job_records_for_run(run: &Value) -> Option<ProjectedRuntimeTaskJobRecords> {
    if !run.is_object() {
        return None;
    }
    let run_id = json_string_value(run, "id")?;
    let agent_id = json_string_value(run, "agentId");
    let mode = json_string_value(run, "mode").unwrap_or_else(|| "send".to_string());
    let status =
        runtime_task_job_status_for_run_status(json_string_value(run, "status").as_deref());
    let created_at =
        json_string_value(run, "createdAt").unwrap_or_else(|| "rust_policy_core".to_string());
    let updated_at = json_string_value(run, "updatedAt").unwrap_or_else(|| created_at.clone());
    let runtime_task = runtime_task_record_for_run(
        run,
        &run_id,
        agent_id.as_deref(),
        &mode,
        status,
        &created_at,
        &updated_at,
    );
    let runtime_job = runtime_job_record_for_run(
        run,
        &runtime_task,
        &run_id,
        status,
        &created_at,
        &updated_at,
    );
    Some(ProjectedRuntimeTaskJobRecords {
        runtime_task,
        runtime_job,
    })
}

fn runtime_task_job_record_matches(
    record: &Value,
    agent_id: &Option<String>,
    status_filter: &Option<String>,
) -> bool {
    agent_id
        .as_deref()
        .map(|expected| json_string_value(record, "agentId").as_deref() == Some(expected))
        .unwrap_or(true)
        && status_filter
            .as_deref()
            .map(|expected| json_string_value(record, "status").as_deref() == Some(expected))
            .unwrap_or(true)
}

fn runtime_task_job_status_for_run_status(status: Option<&str>) -> &'static str {
    match status {
        Some("canceled") => "canceled",
        Some("failed" | "error") => "failed",
        Some("blocked") => "blocked",
        Some("running" | "active") => "running",
        Some("queued" | "pending") => "queued",
        _ => "completed",
    }
}

fn runtime_job_lifecycle_for_status(status: &str) -> Vec<Value> {
    let lifecycle = match status {
        "queued" => vec!["queued"],
        "running" => vec!["queued", "started"],
        "failed" => vec!["queued", "started", "failed"],
        "canceled" => vec!["queued", "started", "canceled"],
        "blocked" => vec!["queued", "started", "blocked"],
        _ => vec!["queued", "started", "completed"],
    };
    lifecycle
        .into_iter()
        .map(|entry| Value::String(entry.to_string()))
        .collect()
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

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn compact_string_values(values: Vec<Option<String>>) -> Vec<Value> {
    values
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .collect()
}

fn compact_unique_string_values(values: Vec<Option<String>>) -> Vec<Value> {
    let mut unique = Vec::<String>::new();
    for value in values.into_iter().flatten() {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_string();
        if !unique.contains(&normalized) {
            unique.push(normalized);
        }
    }
    unique.into_iter().map(Value::String).collect()
}

fn runtime_task_record_for_run(
    run: &Value,
    run_id: &str,
    agent_id: Option<&str>,
    mode: &str,
    status: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let task_family = json_path_string(run, &["trace", "qualityLedger", "taskFamily"])
        .unwrap_or_else(|| task_family_for_mode(mode).to_string());
    let selected_strategy = json_path_string(run, &["trace", "qualityLedger", "selectedStrategy"])
        .unwrap_or_else(|| strategy_for_mode(mode).to_string());
    let model_route_decision_id = run
        .get("modelRouteDecision")
        .or_else(|| {
            run.get("trace")
                .and_then(|trace| trace.get("modelRouteDecision"))
        })
        .and_then(|value| json_string_value(value, "decision_id"));
    let active_skill_hook_manifest_id = run
        .get("activeSkillHookManifest")
        .or_else(|| {
            run.get("trace")
                .and_then(|trace| trace.get("activeSkillHookManifest"))
        })
        .and_then(|value| json_string_value(value, "manifestId"));
    let agent_value = agent_id
        .map(|value| Value::String(value.to_string()))
        .unwrap_or(Value::Null);
    let thread_value = agent_id
        .map(|value| Value::String(thread_id_for_agent(value)))
        .unwrap_or(Value::Null);
    json!({
        "schemaVersion": "ioi.agent-runtime.task-record.v1",
        "object": "ioi.runtime_task",
        "taskId": format!("task_{run_id}"),
        "runId": run_id,
        "agentId": agent_value,
        "threadId": thread_value,
        "turnId": turn_id_for_run(run_id),
        "status": status,
        "mode": mode,
        "taskFamily": task_family,
        "selectedStrategy": selected_strategy,
        "summary": format!("Runtime task for {task_family} is {status}."),
        "promptHash": sha256_hex(json_string_value(run, "objective").unwrap_or_default().as_str()),
        "promptIncluded": false,
        "objectivePreviewIncluded": false,
        "modelRouteDecisionId": model_route_decision_id,
        "activeSkillHookManifestId": active_skill_hook_manifest_id,
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
        "evidenceRefs": compact_string_values(vec![
            Some("runtime_task".to_string()),
            Some("runtime.tasks.durable_projection".to_string()),
            Some("RuntimeTaskNode".to_string()),
            Some(format!("run:{run_id}")),
            active_skill_hook_manifest_id,
        ]),
    })
}

fn runtime_checklist_record_for_run(
    runtime_task: &Value,
    runtime_job: &Value,
    run_id: &str,
    status: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let job_id = json_string_value(runtime_job, "jobId").unwrap_or_else(|| format!("job_{run_id}"));
    let checklist_id = format!("checklist_{run_id}");
    let terminal = match status {
        "canceled" => ("Job canceled event emitted", "JobCanceled", "canceled"),
        "failed" => ("Job failed event emitted", "JobFailed", "failed"),
        "blocked" => ("Job blocked by policy gate", "PolicyBlocked", "blocked"),
        _ => ("Job completed event emitted", "JobCompleted", "passed"),
    };
    let items = vec![
        json!({
            "itemId": format!("{checklist_id}:task_record"),
            "label": "Runtime task record durable",
            "status": "passed",
            "evidenceRefs": compact_unique_string_values(vec![
                Some(task_id.clone()),
                Some("RuntimeTaskNode".to_string()),
                Some("runtime.tasks.durable_projection".to_string()),
            ]),
        }),
        json!({
            "itemId": format!("{checklist_id}:job_record"),
            "label": "Runtime job record durable",
            "status": "passed",
            "evidenceRefs": compact_unique_string_values(vec![
                Some(job_id.clone()),
                Some("RuntimeJobNode".to_string()),
                Some("runtime.jobs.durable_projection".to_string()),
            ]),
        }),
        json!({
            "itemId": format!("{checklist_id}:job_queued"),
            "label": "Job queued event emitted",
            "status": "passed",
            "evidenceRefs": ["JobQueued"],
        }),
        json!({
            "itemId": format!("{checklist_id}:job_started"),
            "label": "Job started event emitted",
            "status": "passed",
            "evidenceRefs": ["JobStarted"],
        }),
        json!({
            "itemId": format!("{checklist_id}:job_terminal"),
            "label": terminal.0,
            "status": terminal.2,
            "evidenceRefs": [terminal.1],
        }),
        json!({
            "itemId": format!("{checklist_id}:artifacts"),
            "label": "Runtime task/job/checklist artifacts attached",
            "status": "passed",
            "evidenceRefs": [
                "runtime-task.json",
                "runtime-job.json",
                "runtime-checklist.json",
            ],
        }),
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
    let required_item_ids = items
        .iter()
        .filter_map(|item| json_string_value(item, "itemId"))
        .map(Value::String)
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": "ioi.agent-runtime.checklist-record.v1",
        "object": "ioi.runtime_checklist",
        "checklistId": checklist_id,
        "taskId": task_id,
        "jobId": job_id,
        "runId": run_id,
        "agentId": runtime_task.get("agentId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_task.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_task.get("turnId").cloned().unwrap_or(Value::Null),
        "status": status,
        "summary": format!("Runtime checklist for job_{run_id} is {status}."),
        "durable": true,
        "replayable": true,
        "readOnly": true,
        "itemCount": items.len(),
        "completedItemCount": completed,
        "canceledItemCount": canceled,
        "failedItemCount": failed,
        "blockedItemCount": blocked,
        "items": items,
        "requiredItemIds": required_item_ids,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "workflowNodeId": "runtime.runtime-checklist",
        "redaction": {
            "profile": "runtime_checklist_safe",
            "promptIncluded": false,
            "secretValuesIncluded": false,
        },
        "evidenceRefs": compact_unique_string_values(vec![
            Some("runtime_checklist".to_string()),
            Some("runtime.checklists.durable_projection".to_string()),
            Some("RuntimeChecklistNode".to_string()),
            Some(format!("task_{run_id}")),
            Some(format!("job_{run_id}")),
            Some(format!("run:{run_id}")),
        ]),
    })
}

fn attach_runtime_checklist_to_job(runtime_job: Value, runtime_checklist: &Value) -> Value {
    let mut job = object_value(&runtime_job).unwrap_or_default();
    job.insert(
        "checklistId".to_string(),
        runtime_checklist
            .get("checklistId")
            .cloned()
            .unwrap_or(Value::Null),
    );
    job.insert(
        "checklistStatus".to_string(),
        runtime_checklist
            .get("status")
            .cloned()
            .unwrap_or(Value::Null),
    );
    job.insert(
        "checklistItemCount".to_string(),
        runtime_checklist
            .get("itemCount")
            .cloned()
            .unwrap_or(Value::Null),
    );
    job.insert(
        "checklistCompletedItemCount".to_string(),
        runtime_checklist
            .get("completedItemCount")
            .cloned()
            .unwrap_or(Value::Null),
    );
    Value::Object(job)
}

fn runtime_job_record_for_run(
    run: &Value,
    runtime_task: &Value,
    run_id: &str,
    status: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let completed = matches!(status, "completed" | "failed" | "canceled");
    let progress = json!({
        "completedSteps": if completed { 1 } else { 0 },
        "totalSteps": 1,
        "percent": if completed { 100 } else if status == "running" { 50 } else { 0 },
    });
    let artifact_names = json_array(run, "artifacts")
        .into_iter()
        .filter_map(|artifact| json_string_value(&artifact, "name"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let receipt_kinds = json_array(run, "receipts")
        .into_iter()
        .filter_map(|receipt| json_string_value(&receipt, "kind"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let terminal_event_count = json_array(run, "events")
        .iter()
        .filter(|event| {
            matches!(
                json_string_value(event, "type").as_deref(),
                Some("completed" | "canceled" | "failed" | "error")
            )
        })
        .count();
    let event_count = json_array(run, "events").len();
    let event_count_value = if event_count == 0 {
        Value::Null
    } else {
        json!(event_count)
    };
    let terminal_event_count_value = if terminal_event_count == 0 {
        Value::Null
    } else {
        json!(terminal_event_count)
    };
    let completed_at = if completed {
        Value::String(updated_at.to_string())
    } else {
        Value::Null
    };
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
        "self": format!("/v1/jobs/job_{run_id}"),
        "cancel": format!("/v1/jobs/job_{run_id}/cancel"),
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
        task_id.clone(),
        format!("run:{run_id}"),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.job-record.v1",
        "object": "ioi.runtime_job",
        "jobId": format!("job_{run_id}"),
        "taskId": task_id,
        "runId": run_id,
        "agentId": runtime_task.get("agentId").cloned().unwrap_or(Value::Null),
        "threadId": runtime_task.get("threadId").cloned().unwrap_or(Value::Null),
        "turnId": runtime_task.get("turnId").cloned().unwrap_or(Value::Null),
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
        "completedAt": completed_at,
        "progress": progress,
        "eventCount": event_count_value,
        "terminalEventCount": terminal_event_count_value,
        "artifactNames": artifact_names,
        "receiptKinds": receipt_kinds,
        "checklistId": Value::Null,
        "checklistStatus": Value::Null,
        "checklistItemCount": Value::Null,
        "checklistCompletedItemCount": Value::Null,
        "failure": failure,
        "cancellation": cancellation,
        "retryCount": 0,
        "cancelable": status != "canceled",
        "cancelEndpoint": format!("/v1/jobs/job_{run_id}/cancel"),
        "endpoints": endpoints,
        "workflowNodeId": "runtime.runtime-job",
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn task_job_cancel_request(cancel_kind: &str) -> RuntimeTaskJobCancelStateUpdateRequest {
        RuntimeTaskJobCancelStateUpdateRequest {
            schema_version: RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            cancel_kind: cancel_kind.to_string(),
            task_id: (cancel_kind == "task").then(|| "task_run_task_job_cancel".to_string()),
            job_id: (cancel_kind == "job").then(|| "job_run_task_job_cancel".to_string()),
            run_id: Some("run_task_job_cancel".to_string()),
            canceled_at: "2026-06-06T05:00:00.000Z".to_string(),
            run: json!({
                "id": "run_task_job_cancel",
                "agentId": "agent_task_job",
                "status": "running",
                "objective": "Cancel via task job public route",
                "mode": "send",
                "createdAt": "2026-06-06T04:59:00.000Z",
                "updatedAt": "2026-06-06T04:59:30.000Z",
                "events": [{ "id": "event_delta", "type": "delta", "data": { "text": "partial" } }],
                "trace": { "events": [], "receipts": [], "qualityLedger": {} },
                "receipts": [],
                "artifacts": []
            }),
        }
    }

    fn task_job_projection_request(
        projection_kind: &str,
    ) -> (RuntimeTaskJobProjectionRequest, PathBuf) {
        let state_dir = temp_task_job_state_dir(projection_kind);
        seed_task_job_projection_runs(&state_dir);
        (
            RuntimeTaskJobProjectionRequest {
                schema_version: RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION.to_string(),
                projection_kind: projection_kind.to_string(),
                state_dir: Some(state_dir.to_string_lossy().to_string()),
                agent_id: None,
                status: None,
                task_id: None,
                job_id: None,
            },
            state_dir,
        )
    }

    fn temp_task_job_state_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let state_dir = std::env::temp_dir().join(format!(
            "ioi_runtime_task_job_projection_{label}_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(state_dir.join("runs")).expect("runs dir");
        state_dir
    }

    fn write_run_record(state_dir: &Path, file_name: &str, run: Value) {
        let path = state_dir.join("runs").join(file_name);
        fs::write(
            path,
            serde_json::to_string_pretty(&run).expect("serialize run"),
        )
        .expect("write run record");
    }

    fn seed_task_job_projection_runs(state_dir: &Path) {
        write_run_record(
            state_dir,
            "run_task_job_projection_a.json",
            json!({
                "id": "run_task_job_projection_a",
                "agentId": "agent_task_job",
                "status": "running",
                "objective": "Project a task",
                "mode": "send",
                "createdAt": "2026-06-06T04:59:00.000Z",
                "updatedAt": "2026-06-06T04:59:30.000Z",
                "events": [{ "type": "delta" }],
                "trace": { "qualityLedger": {} },
                "receipts": [{ "kind": "runtime_task" }],
                "artifacts": [{ "name": "runtime-task.json" }]
            }),
        );
        write_run_record(
            state_dir,
            "run_task_job_projection_b.json",
            json!({
                "id": "run_task_job_projection_b",
                "agentId": "agent_task_job",
                "status": "completed",
                "objective": "Project a job",
                "mode": "plan",
                "createdAt": "2026-06-06T05:00:00.000Z",
                "updatedAt": "2026-06-06T05:01:00.000Z",
                "events": [{ "type": "completed" }],
                "trace": { "qualityLedger": { "taskFamily": "planning" } },
                "receipts": [{ "kind": "runtime_job" }],
                "artifacts": [{ "name": "runtime-job.json" }]
            }),
        );
        write_run_record(
            state_dir,
            "run_task_job_projection_c.json",
            json!({
                "id": "run_task_job_projection_c",
                "agentId": "agent_other",
                "status": "completed",
                "createdAt": "2026-06-06T05:02:00.000Z",
                "updatedAt": "2026-06-06T05:03:00.000Z",
                "events": []
            }),
        );
    }

    fn task_job_create_request() -> RuntimeTaskJobCreateStateUpdateRequest {
        RuntimeTaskJobCreateStateUpdateRequest {
            schema_version: RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            agent_id: Some("agent_task_job".to_string()),
            run: json!({
                "id": "run_task_job_create",
                "agentId": "agent_task_job",
                "status": "completed",
                "objective": "Create a public runtime task",
                "mode": "send",
                "createdAt": "2026-06-06T04:59:00.000Z",
                "updatedAt": "2026-06-06T04:59:00.000Z",
                "usage": {},
                "usage_telemetry": {},
                "events": [{ "type": "completed" }],
                "trace": {
                    "usage_telemetry": {},
                    "qualityLedger": {
                        "taskFamily": "local_daemon_agentgres",
                        "selectedStrategy": "local_daemon_agentgres_execution"
                    }
                },
                "receipts": [{ "kind": "runtime_task" }],
                "artifacts": [{ "name": "runtime-task.json" }]
            }),
        }
    }

    #[test]
    fn rust_policy_plans_runtime_task_create_state_update() {
        let record = RuntimeTaskJobCreateStateUpdateCore
            .plan(&task_job_create_request())
            .expect("task create");

        assert_eq!(
            record.schema_version,
            RUNTIME_TASK_JOB_CREATE_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "task.create");
        assert_eq!(record.run_id, "run_task_job_create");
        assert_eq!(record.agent_id, "agent_task_job");
        assert_eq!(record.task_id, "task_run_task_job_create");
        assert_eq!(record.job_id, "job_run_task_job_create");
        assert_eq!(record.runtime_task["taskId"], "task_run_task_job_create");
        assert_eq!(record.runtime_job["jobId"], "job_run_task_job_create");
        assert_eq!(
            record.runtime_job["checklistId"],
            "checklist_run_task_job_create"
        );
        assert_eq!(
            record.runtime_checklist["checklistId"],
            "checklist_run_task_job_create"
        );
        assert_eq!(record.run["runtimeTask"]["taskId"], record.task_id);
        assert_eq!(record.run["runtimeJob"]["jobId"], record.job_id);
        assert_eq!(
            record.run["runtimeChecklist"]["checklistId"],
            "checklist_run_task_job_create"
        );
    }

    #[test]
    fn rust_policy_shapes_runtime_task_job_create_command_response() {
        let response = plan_runtime_task_job_create_state_update_response(
            RuntimeTaskJobCreateStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: task_job_create_request(),
            },
        )
        .expect("task job create command response");

        assert_eq!(
            response["source"],
            "rust_runtime_task_job_create_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["operation_kind"], "task.create");
        assert_eq!(response["task_id"], "task_run_task_job_create");
        assert_eq!(
            response["runtime_task"]["taskId"],
            "task_run_task_job_create"
        );
        assert_eq!(
            response["run"]["runtimeTask"]["taskId"],
            response["task_id"]
        );
    }

    #[test]
    fn rust_policy_rejects_runtime_task_create_agent_mismatch() {
        let mut request = task_job_create_request();
        request.agent_id = Some("agent_other".to_string());

        assert!(matches!(
            RuntimeTaskJobCreateStateUpdateCore.plan(&request),
            Err(RuntimeTaskJobCreateStateUpdateError::AgentIdMismatch { .. })
        ));
    }

    #[test]
    fn rust_policy_plans_runtime_task_cancel_state_update() {
        let record = RuntimeTaskJobCancelStateUpdateCore
            .plan(&task_job_cancel_request("task"))
            .expect("task cancel");

        assert_eq!(
            record.schema_version,
            RUNTIME_TASK_JOB_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "task.cancel");
        assert_eq!(record.cancel_kind, "task");
        assert_eq!(record.task_id.as_deref(), Some("task_run_task_job_cancel"));
        assert_eq!(record.run["status"], "canceled");
        assert_eq!(record.runtime_task["taskId"], "task_run_task_job_cancel");
        assert_eq!(record.runtime_task["status"], "canceled");
        assert_eq!(record.runtime_job["jobId"], "job_run_task_job_cancel");
        assert_eq!(record.runtime_checklist["status"], "canceled");
    }

    #[test]
    fn rust_policy_plans_runtime_job_cancel_state_update() {
        let record = RuntimeTaskJobCancelStateUpdateCore
            .plan(&task_job_cancel_request("job"))
            .expect("job cancel");

        assert_eq!(record.operation_kind, "job.cancel");
        assert_eq!(record.cancel_kind, "job");
        assert_eq!(record.job_id.as_deref(), Some("job_run_task_job_cancel"));
        assert_eq!(record.run["status"], "canceled");
        assert_eq!(record.runtime_job["status"], "canceled");
    }

    #[test]
    fn rust_policy_shapes_runtime_task_job_cancel_command_response() {
        let response = plan_runtime_task_job_cancel_state_update_response(
            RuntimeTaskJobCancelStateUpdateBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request: task_job_cancel_request("task"),
            },
        )
        .expect("task job cancel command response");

        assert_eq!(
            response["source"],
            "rust_runtime_task_job_cancel_state_update_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["operation_kind"], "task.cancel");
        assert_eq!(response["task_id"], "task_run_task_job_cancel");
        assert_eq!(response["run"]["status"], "canceled");
    }

    #[test]
    fn rust_policy_projects_runtime_task_list() {
        let (mut request, _state_dir) = task_job_projection_request("task.list");
        request.agent_id = Some("agent_task_job".to_string());

        let record = RuntimeTaskJobProjectionCore
            .project(&request)
            .expect("task projection");

        assert_eq!(
            record.schema_version,
            RUNTIME_TASK_JOB_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.operation_kind, "task.list");
        assert_eq!(record.records.len(), 2);
        assert_eq!(
            record.records[0]["taskId"],
            "task_run_task_job_projection_a"
        );
        assert_eq!(record.records[0]["status"], "running");
        assert_eq!(record.records[1]["taskFamily"], "planning");
    }

    #[test]
    fn rust_policy_projects_runtime_job_get() {
        let (mut request, _state_dir) = task_job_projection_request("job.get");
        request.job_id = Some("job_run_task_job_projection_b".to_string());

        let record = RuntimeTaskJobProjectionCore
            .project(&request)
            .expect("job get projection");

        assert_eq!(record.operation_kind, "job.get");
        assert_eq!(record.record_count, 1);
        assert_eq!(
            record.runtime_job.as_ref().unwrap()["jobId"],
            "job_run_task_job_projection_b"
        );
        assert_eq!(record.runtime_job.as_ref().unwrap()["status"], "completed");
    }

    #[test]
    fn rust_policy_filters_runtime_task_job_projection_in_rust() {
        let (mut request, _state_dir) = task_job_projection_request("job.list");
        request.agent_id = Some("agent_task_job".to_string());
        request.status = Some("completed".to_string());

        let record = RuntimeTaskJobProjectionCore
            .project(&request)
            .expect("filtered job projection");

        assert_eq!(record.operation_kind, "job.list");
        assert_eq!(record.record_count, 1);
        assert_eq!(record.records[0]["jobId"], "job_run_task_job_projection_b");
    }

    #[test]
    fn rust_policy_replays_runtime_task_job_projection_from_state_dir() {
        let (request, state_dir) = task_job_projection_request("task.list");

        let record = RuntimeTaskJobProjectionCore
            .project(&request)
            .expect("state_dir projection");

        assert!(state_dir
            .join("runs/run_task_job_projection_a.json")
            .exists());
        assert_eq!(record.operation_kind, "task.list");
        assert_eq!(record.record_count, 3);
        assert_eq!(
            record.records[0]["taskId"],
            "task_run_task_job_projection_a"
        );
    }

    #[test]
    fn rust_policy_rejects_runtime_task_job_projection_without_state_dir() {
        let (mut request, _state_dir) = task_job_projection_request("task.list");
        request.state_dir = None;

        assert!(matches!(
            RuntimeTaskJobProjectionCore.project(&request),
            Err(RuntimeTaskJobProjectionError::MissingField("state_dir"))
        ));
    }

    #[test]
    fn rust_policy_rejects_runtime_task_job_projection_run_candidate_transport() {
        let state_dir = temp_task_job_state_dir("retired-runs-candidate");
        seed_task_job_projection_runs(&state_dir);
        let error = serde_json::from_value::<RuntimeTaskJobProjectionRequest>(json!({
            "schema_version": RUNTIME_TASK_JOB_PROJECTION_REQUEST_SCHEMA_VERSION,
            "projection_kind": "task.list",
            "state_dir": state_dir.to_string_lossy(),
            "runs": []
        }))
        .expect_err("retired runs candidate transport must be rejected");

        assert!(error.to_string().contains("unknown field `runs`"));
    }

    #[test]
    fn rust_policy_shapes_runtime_task_job_projection_command_response() {
        let (mut request, _state_dir) = task_job_projection_request("task.get");
        request.task_id = Some("task_run_task_job_projection_a".to_string());
        let response =
            project_runtime_task_job_projection_response(RuntimeTaskJobProjectionBridgeRequest {
                backend: Some("rust_policy".to_string()),
                request,
            })
            .expect("task job projection command response");

        assert_eq!(
            response["source"],
            "rust_runtime_task_job_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(response["operation_kind"], "task.get");
        assert_eq!(
            response["runtime_task"]["taskId"],
            "task_run_task_job_projection_a"
        );
        assert_eq!(response["record_count"], 1);
    }

    #[test]
    fn rust_policy_rejects_mismatched_runtime_task_public_id() {
        let mut request = task_job_cancel_request("task");
        request.task_id = Some("task_retired_wrong_run".to_string());

        assert!(matches!(
            RuntimeTaskJobCancelStateUpdateCore.plan(&request),
            Err(RuntimeTaskJobCancelStateUpdateError::PublicIdMismatch { .. })
        ));
    }

    #[test]
    fn rust_policy_rejects_mismatched_runtime_task_job_run_id() {
        let mut request = task_job_cancel_request("job");
        request.run_id = Some("run_task_job_cancel_alias".to_string());
        request.job_id = Some("job_run_task_job_cancel_alias".to_string());

        assert!(matches!(
            RuntimeTaskJobCancelStateUpdateCore.plan(&request),
            Err(RuntimeTaskJobCancelStateUpdateError::RunIdMismatch { .. })
        ));
    }
}
