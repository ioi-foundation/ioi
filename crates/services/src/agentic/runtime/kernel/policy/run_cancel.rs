use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
    RUN_CANCEL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION,
    RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION, RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum RunCancelStateUpdateError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunCancelAdmissionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelStateUpdateRequest {
    pub schema_version: String,
    #[serde(default)]
    pub run_id: Option<String>,
    pub run: Value,
    pub canceled_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelStateUpdateRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub updated_at: String,
    pub stop_condition: Value,
    pub runtime_task: Value,
    pub runtime_job: Value,
    pub runtime_checklist: Value,
    pub run: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelAdmissionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    pub run_id: String,
    #[serde(default)]
    pub run_status: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCancelAdmissionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct RunCancelStateUpdateCore;

impl RunCancelStateUpdateCore {
    pub fn plan(
        &self,
        request: &RunCancelStateUpdateRequest,
    ) -> Result<RunCancelStateUpdateRecord, RunCancelStateUpdateError> {
        request.validate()?;
        let mut run =
            object_value(&request.run).ok_or(RunCancelStateUpdateError::MissingField("run"))?;
        let run_id = optional_trimmed(request.run_id.as_deref())
            .or_else(|| optional_json_string(&Value::Object(run.clone()), "id"))
            .ok_or(RunCancelStateUpdateError::MissingField("run.id"))?;
        let agent_id = optional_json_string(&Value::Object(run.clone()), "agentId")
            .ok_or(RunCancelStateUpdateError::MissingField("agentId"))?;
        let mode = optional_json_string(&Value::Object(run.clone()), "mode")
            .unwrap_or_else(|| "send".to_string());
        let created_at = optional_json_string(&Value::Object(run.clone()), "createdAt")
            .unwrap_or_else(|| request.canceled_at.clone());
        let events = run
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut canceled_events = events
            .into_iter()
            .filter(|event| {
                !is_terminal_event_type(json_string_value(event, "type").as_deref())
                    && !is_job_terminal_event_type(json_string_value(event, "type").as_deref())
            })
            .collect::<Vec<_>>();
        let has_runtime_task_event = canceled_events
            .iter()
            .any(|event| json_string_value(event, "type").as_deref() == Some("runtime_task"));
        let has_runtime_checklist_event = canceled_events
            .iter()
            .any(|event| json_string_value(event, "type").as_deref() == Some("runtime_checklist"));
        let final_event_count = canceled_events.len()
            + if has_runtime_task_event { 0 } else { 1 }
            + if has_runtime_checklist_event { 0 } else { 1 }
            + 2;
        let runtime_task = runtime_task_record_for_canceled_run(
            &Value::Object(run.clone()),
            &run_id,
            &agent_id,
            &mode,
            &created_at,
            &request.canceled_at,
        );
        let runtime_checklist_receipt_id = format!("receipt_{run_id}_runtime_checklist");
        let mut runtime_job = runtime_job_record_for_canceled_run(
            &Value::Object(run.clone()),
            &runtime_task,
            &run_id,
            &created_at,
            &request.canceled_at,
            final_event_count,
        );
        let runtime_checklist = runtime_checklist_record_for_canceled_run(
            &Value::Object(run.clone()),
            &runtime_task,
            &runtime_job,
            &run_id,
            &created_at,
            &request.canceled_at,
        );
        runtime_job = attach_runtime_checklist_to_job(runtime_job, &runtime_checklist);

        for event in &mut canceled_events {
            match json_string_value(event, "type").as_deref() {
                Some("runtime_task") => {
                    let mut data = object_value(&runtime_task).unwrap_or_default();
                    data.insert(
                        "receiptId".to_string(),
                        Value::String(format!("receipt_{run_id}_runtime_task")),
                    );
                    data.insert(
                        "eventKind".to_string(),
                        Value::String("RuntimeTaskRecord".to_string()),
                    );
                    data.insert(
                        "workflowNodeId".to_string(),
                        Value::String("runtime.runtime-task".to_string()),
                    );
                    if let Some(object) = event.as_object_mut() {
                        object.insert("data".to_string(), Value::Object(data));
                    }
                }
                Some("runtime_checklist") => {
                    let mut data = object_value(&runtime_checklist).unwrap_or_default();
                    data.insert(
                        "receiptId".to_string(),
                        Value::String(runtime_checklist_receipt_id.clone()),
                    );
                    data.insert(
                        "eventKind".to_string(),
                        Value::String("RuntimeChecklistRecord".to_string()),
                    );
                    data.insert(
                        "workflowNodeId".to_string(),
                        Value::String("runtime.runtime-checklist".to_string()),
                    );
                    if let Some(object) = event.as_object_mut() {
                        object.insert("data".to_string(), Value::Object(data));
                    }
                }
                _ => {}
            }
        }
        if !has_runtime_task_event {
            let mut data = object_value(&runtime_task).unwrap_or_default();
            data.insert(
                "receiptId".to_string(),
                Value::String(format!("receipt_{run_id}_runtime_task")),
            );
            data.insert(
                "eventKind".to_string(),
                Value::String("RuntimeTaskRecord".to_string()),
            );
            data.insert(
                "workflowNodeId".to_string(),
                Value::String("runtime.runtime-task".to_string()),
            );
            canceled_events.push(make_run_event(
                &run_id,
                &agent_id,
                canceled_events.len(),
                "runtime_task",
                "Runtime task record written",
                Value::Object(data),
                &request.canceled_at,
            ));
        }
        if !has_runtime_checklist_event {
            let mut data = object_value(&runtime_checklist).unwrap_or_default();
            data.insert(
                "receiptId".to_string(),
                Value::String(runtime_checklist_receipt_id.clone()),
            );
            data.insert(
                "eventKind".to_string(),
                Value::String("RuntimeChecklistRecord".to_string()),
            );
            data.insert(
                "workflowNodeId".to_string(),
                Value::String("runtime.runtime-checklist".to_string()),
            );
            canceled_events.push(make_run_event(
                &run_id,
                &agent_id,
                canceled_events.len(),
                "runtime_checklist",
                "Runtime checklist recorded",
                Value::Object(data),
                &request.canceled_at,
            ));
        }
        let mut job_data = object_value(&runtime_job).unwrap_or_default();
        job_data.insert(
            "lifecycleStatus".to_string(),
            Value::String("canceled".to_string()),
        );
        job_data.insert(
            "receiptId".to_string(),
            Value::String(format!("receipt_{run_id}_runtime_job")),
        );
        job_data.insert(
            "eventKind".to_string(),
            Value::String("JobCanceled".to_string()),
        );
        job_data.insert(
            "workflowNodeId".to_string(),
            Value::String("runtime.runtime-job".to_string()),
        );
        canceled_events.push(make_run_event(
            &run_id,
            &agent_id,
            canceled_events.len(),
            "job_canceled",
            "Runtime job canceled",
            Value::Object(job_data),
            &request.canceled_at,
        ));
        canceled_events.push(make_run_event(
            &run_id,
            &agent_id,
            canceled_events.len(),
            "canceled",
            "Run canceled",
            json!({
                "reason": "operator_cancel",
                "priorStatus": optional_json_string(&Value::Object(run.clone()), "status").unwrap_or_default(),
            }),
            &request.canceled_at,
        ));

        let runtime_checklist_receipt = json!({
            "id": runtime_checklist_receipt_id,
            "kind": "runtime_checklist",
            "summary": runtime_checklist.get("summary").cloned().unwrap_or(Value::Null),
            "redaction": "redacted",
            "evidenceRefs": [
                runtime_checklist.get("checklistId").cloned().unwrap_or(Value::Null),
                runtime_task.get("taskId").cloned().unwrap_or(Value::Null),
                runtime_job.get("jobId").cloned().unwrap_or(Value::Null),
                "RuntimeChecklistNode",
                "runtime.checklists.durable_projection",
            ],
        });
        let mut receipts = run
            .get("receipts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|receipt| {
                if json_string_value(&receipt, "id")
                    == json_string_value(&runtime_checklist_receipt, "id")
                {
                    runtime_checklist_receipt.clone()
                } else {
                    receipt
                }
            })
            .collect::<Vec<_>>();
        if !receipts.iter().any(|receipt| {
            json_string_value(receipt, "id") == json_string_value(&runtime_checklist_receipt, "id")
        }) {
            receipts.push(runtime_checklist_receipt);
        }
        let stop_condition = json!({
            "reason": "marginal_improvement_too_low",
            "evidenceSufficient": true,
            "rationale": "Cancellation became the single terminal event and replay cursor continuity was preserved.",
        });
        let mut trace = run.get("trace").and_then(object_value).unwrap_or_default();
        trace.insert("events".to_string(), Value::Array(canceled_events.clone()));
        trace.insert("receipts".to_string(), Value::Array(receipts.clone()));
        trace.insert("runtimeTask".to_string(), runtime_task.clone());
        trace.insert("runtimeJob".to_string(), runtime_job.clone());
        trace.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        trace.insert("stopCondition".to_string(), stop_condition.clone());
        let mut quality_ledger = trace
            .get("qualityLedger")
            .and_then(object_value)
            .unwrap_or_default();
        let mut labels = quality_ledger
            .get("failureOntologyLabels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !labels
            .iter()
            .any(|label| label.as_str() == Some("operator_cancel"))
        {
            labels.push(Value::String("operator_cancel".to_string()));
        }
        quality_ledger.insert("failureOntologyLabels".to_string(), Value::Array(labels));
        trace.insert("qualityLedger".to_string(), Value::Object(quality_ledger));

        let mut artifacts = run
            .get("artifacts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(
                |artifact| match json_string_value(&artifact, "name").as_deref() {
                    Some("runtime-task.json") => {
                        artifact_with_content(artifact, runtime_task.clone())
                    }
                    Some("runtime-job.json") => {
                        artifact_with_content(artifact, runtime_job.clone())
                    }
                    Some("runtime-checklist.json") => {
                        artifact_with_content(artifact, runtime_checklist.clone())
                    }
                    _ => artifact,
                },
            )
            .collect::<Vec<_>>();
        if !artifacts.iter().any(|artifact| {
            json_string_value(artifact, "name").as_deref() == Some("runtime-checklist.json")
        }) {
            artifacts.push(runtime_artifact(
                &run_id,
                "runtime-checklist.json",
                "application/json",
                &format!("receipt_{run_id}_runtime_checklist"),
                runtime_checklist.clone(),
                "redacted",
            ));
        }

        run.insert("status".to_string(), Value::String("canceled".to_string()));
        run.insert(
            "updatedAt".to_string(),
            Value::String(request.canceled_at.clone()),
        );
        run.insert("events".to_string(), Value::Array(canceled_events));
        run.insert("trace".to_string(), Value::Object(trace));
        run.insert("receipts".to_string(), Value::Array(receipts));
        run.insert("artifacts".to_string(), Value::Array(artifacts));
        run.insert("runtimeTask".to_string(), runtime_task.clone());
        run.insert("runtimeJob".to_string(), runtime_job.clone());
        run.insert("runtimeChecklist".to_string(), runtime_checklist.clone());
        run.insert(
            "result".to_string(),
            Value::String("Run canceled with terminal event continuity preserved.".to_string()),
        );

        Ok(RunCancelStateUpdateRecord {
            schema_version: RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_run_cancel_state_update".to_string(),
            status: "planned".to_string(),
            operation_kind: "run.cancel".to_string(),
            run_id: Some(run_id),
            updated_at: request.canceled_at.clone(),
            stop_condition,
            runtime_task,
            runtime_job,
            runtime_checklist,
            run: Value::Object(run),
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RunCancelAdmissionRequiredCore;

impl RunCancelAdmissionRequiredCore {
    pub fn plan(
        &self,
        request: &RunCancelAdmissionRequiredRequest,
    ) -> Result<RunCancelAdmissionRequiredRecord, RunCancelAdmissionRequiredError> {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let run_id = optional_trimmed(Some(request.run_id.as_str())).unwrap();
        let run_status = optional_trimmed(request.run_status.as_deref());
        let source = optional_trimmed(request.source.as_deref());
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_run_cancel_js_facade_retired".to_string(),
                "rust_daemon_core_run_cancel_required".to_string(),
                "agentgres_run_cancel_state_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.run_cancel",
            "operation": operation,
            "operation_kind": operation_kind,
            "run_id": run_id,
            "run_status": run_status,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(RunCancelAdmissionRequiredRecord {
            schema_version: RUN_CANCEL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
            object: "ioi.runtime_run_cancel_admission_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_run_cancel_rust_core_required".to_string(),
            message:
                "Run cancellation requires direct Rust daemon-core state admission and persistence."
                    .to_string(),
            rust_core_boundary: "runtime.run_cancel".to_string(),
            operation,
            operation_kind,
            run_id,
            run_status,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl RunCancelStateUpdateRequest {
    pub fn validate(&self) -> Result<(), RunCancelStateUpdateError> {
        if self.schema_version != RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION {
            return Err(RunCancelStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if !self.run.is_object() {
            return Err(RunCancelStateUpdateError::MissingField("run"));
        }
        if optional_trimmed(Some(self.canceled_at.as_str())).is_none() {
            return Err(RunCancelStateUpdateError::MissingField("canceled_at"));
        }
        Ok(())
    }
}

impl RunCancelAdmissionRequiredRequest {
    pub fn validate(&self) -> Result<(), RunCancelAdmissionRequiredError> {
        if self.schema_version != RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(RunCancelAdmissionRequiredError::InvalidSchemaVersion {
                expected: RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(RunCancelAdmissionRequiredError::MissingField("operation"));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(RunCancelAdmissionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        if optional_trimmed(Some(self.run_id.as_str())).is_none() {
            return Err(RunCancelAdmissionRequiredError::MissingField("run_id"));
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

fn optional_json_string(value: &Value, key: &str) -> Option<String> {
    json_string_value(value, key)
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

fn is_terminal_event_type(value: Option<&str>) -> bool {
    matches!(value, Some("completed" | "canceled" | "failed" | "error"))
}

fn is_job_terminal_event_type(value: Option<&str>) -> bool {
    matches!(value, Some("job_completed" | "job_failed" | "job_canceled"))
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

fn compact_string_values(values: Vec<Option<String>>) -> Vec<Value> {
    values
        .into_iter()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .map(Value::String)
        .collect()
}

fn unique_string_values(values: Vec<String>) -> Vec<Value> {
    let mut unique = Vec::<String>::new();
    for value in values {
        let text = value.trim();
        if !text.is_empty() && !unique.iter().any(|candidate| candidate == text) {
            unique.push(text.to_string());
        }
    }
    unique.into_iter().map(Value::String).collect()
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

fn runtime_task_record_for_canceled_run(
    run: &Value,
    run_id: &str,
    agent_id: &str,
    mode: &str,
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
    json!({
        "schemaVersion": "ioi.agent-runtime.task-record.v1",
        "object": "ioi.runtime_task",
        "taskId": format!("task_{run_id}"),
        "runId": run_id,
        "agentId": agent_id,
        "threadId": thread_id_for_agent(agent_id),
        "turnId": turn_id_for_run(run_id),
        "status": "canceled",
        "mode": mode,
        "taskFamily": task_family,
        "selectedStrategy": selected_strategy,
        "summary": format!("Runtime task for {task_family} is canceled."),
        "promptHash": sha256_hex(optional_json_string(run, "objective").unwrap_or_default().as_str()),
        "promptIncluded": false,
        "objectivePreviewIncluded": false,
        "modelRouteDecisionId": string_or_null(model_route_decision_id.as_deref()),
        "activeSkillHookManifestId": string_or_null(active_skill_hook_manifest_id.as_deref()),
        "createdAt": created_at,
        "updatedAt": updated_at,
        "durable": true,
        "replayable": true,
        "cancelable": false,
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

fn runtime_job_record_for_canceled_run(
    run: &Value,
    runtime_task: &Value,
    run_id: &str,
    created_at: &str,
    updated_at: &str,
    event_count: usize,
) -> Value {
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let artifact_names = run
        .get("artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|artifact| json_string_value(&artifact, "name"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let receipt_kinds = run
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|receipt| json_string_value(&receipt, "kind"))
        .map(Value::String)
        .collect::<Vec<_>>();
    let queued_at = run
        .get("runtimeJob")
        .and_then(|job| json_string_value(job, "queuedAt"))
        .unwrap_or_else(|| created_at.to_string());
    let started_at = run
        .get("runtimeJob")
        .and_then(|job| json_string_value(job, "startedAt"))
        .unwrap_or_else(|| created_at.to_string());
    let progress = json!({
        "completedSteps": 1,
        "totalSteps": 1,
        "percent": 100,
    });
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
        task_id,
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
        "status": "canceled",
        "lifecycle": ["queued", "started", "canceled"],
        "summary": format!("Runtime job job_{run_id} is canceled."),
        "queueName": "local-agentgres",
        "runner": "local-daemon-agentgres",
        "jobType": "agent_run",
        "priority": "normal",
        "background": true,
        "durable": true,
        "replayable": true,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "queuedAt": queued_at,
        "startedAt": started_at,
        "completedAt": updated_at,
        "progress": progress,
        "eventCount": event_count,
        "terminalEventCount": 1,
        "artifactNames": artifact_names,
        "receiptKinds": receipt_kinds,
        "checklistId": Value::Null,
        "checklistStatus": Value::Null,
        "checklistItemCount": Value::Null,
        "checklistCompletedItemCount": Value::Null,
        "failure": Value::Null,
        "cancellation": json!({ "reason": "operator_cancel" }),
        "retryCount": 0,
        "cancelable": false,
        "cancelEndpoint": format!("/v1/jobs/job_{run_id}/cancel"),
        "endpoints": endpoints,
        "workflowNodeId": "runtime.runtime-job",
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    })
}

fn runtime_checklist_record_for_canceled_run(
    _run: &Value,
    runtime_task: &Value,
    runtime_job: &Value,
    run_id: &str,
    created_at: &str,
    updated_at: &str,
) -> Value {
    let checklist_id = format!("checklist_{run_id}");
    let task_id =
        json_string_value(runtime_task, "taskId").unwrap_or_else(|| format!("task_{run_id}"));
    let job_id = json_string_value(runtime_job, "jobId").unwrap_or_else(|| format!("job_{run_id}"));
    let items = vec![
        checklist_item(
            &checklist_id,
            "task_record",
            "Runtime task record durable",
            "passed",
            vec![
                task_id.clone(),
                "RuntimeTaskNode".to_string(),
                "runtime.tasks.durable_projection".to_string(),
            ],
        ),
        checklist_item(
            &checklist_id,
            "job_record",
            "Runtime job record durable",
            "passed",
            vec![
                job_id.clone(),
                "RuntimeJobNode".to_string(),
                "runtime.jobs.durable_projection".to_string(),
            ],
        ),
        checklist_item(
            &checklist_id,
            "job_queued",
            "Job queued event emitted",
            "passed",
            vec!["JobQueued".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "job_started",
            "Job started event emitted",
            "passed",
            vec!["JobStarted".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "job_terminal",
            "Job canceled event emitted",
            "canceled",
            vec!["JobCanceled".to_string()],
        ),
        checklist_item(
            &checklist_id,
            "artifacts",
            "Runtime task/job/checklist artifacts attached",
            "passed",
            vec![
                "runtime-task.json".to_string(),
                "runtime-job.json".to_string(),
                "runtime-checklist.json".to_string(),
            ],
        ),
    ];
    let redaction = json!({
        "profile": "runtime_checklist_safe",
        "promptIncluded": false,
        "secretValuesIncluded": false,
    });
    let evidence_refs = json!([
        "runtime_checklist",
        "runtime.checklists.durable_projection",
        "RuntimeChecklistNode",
        task_id,
        job_id,
        format!("run:{run_id}"),
    ]);
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
        "status": "canceled",
        "summary": format!("Runtime checklist for job_{run_id} is canceled."),
        "durable": true,
        "replayable": true,
        "readOnly": true,
        "itemCount": items.len(),
        "completedItemCount": items
            .iter()
            .filter(|item| json_string_value(item, "status").as_deref() == Some("passed"))
            .count(),
        "canceledItemCount": items
            .iter()
            .filter(|item| json_string_value(item, "status").as_deref() == Some("canceled"))
            .count(),
        "failedItemCount": 0,
        "blockedItemCount": 0,
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
        "redaction": redaction,
        "evidenceRefs": evidence_refs,
    })
}

fn checklist_item(
    checklist_id: &str,
    suffix: &str,
    label: &str,
    status: &str,
    evidence_refs: Vec<String>,
) -> Value {
    json!({
        "itemId": format!("{checklist_id}:{suffix}"),
        "label": label,
        "status": status,
        "evidenceRefs": unique_string_values(evidence_refs),
    })
}

fn attach_runtime_checklist_to_job(mut runtime_job: Value, runtime_checklist: &Value) -> Value {
    let artifact_names = runtime_job
        .get("artifactNames")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(std::iter::once("runtime-checklist.json".to_string()))
        .collect::<Vec<_>>();
    let receipt_kinds = runtime_job
        .get("receiptKinds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(std::iter::once("runtime_checklist".to_string()))
        .collect::<Vec<_>>();
    let evidence_refs = runtime_job
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(
            runtime_checklist
                .get("checklistId")
                .and_then(Value::as_str)
                .map(str::to_string),
        )
        .chain(std::iter::once("runtime_checklist".to_string()))
        .collect::<Vec<_>>();
    if let Some(job) = runtime_job.as_object_mut() {
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
        job.insert(
            "artifactNames".to_string(),
            Value::Array(unique_string_values(artifact_names)),
        );
        job.insert(
            "receiptKinds".to_string(),
            Value::Array(unique_string_values(receipt_kinds)),
        );
        job.insert(
            "evidenceRefs".to_string(),
            Value::Array(unique_string_values(evidence_refs)),
        );
    }
    runtime_job
}

fn make_run_event(
    run_id: &str,
    agent_id: &str,
    index: usize,
    event_type: &str,
    summary: &str,
    data: Value,
    created_at: &str,
) -> Value {
    json!({
        "id": format!("{run_id}:event:{:03}:{event_type}", index),
        "runId": run_id,
        "agentId": agent_id,
        "type": event_type,
        "cursor": format!("{run_id}:{index}"),
        "createdAt": created_at,
        "summary": summary,
        "data": data,
    })
}

fn artifact_with_content(mut artifact: Value, content: Value) -> Value {
    if let Some(object) = artifact.as_object_mut() {
        object.insert("content".to_string(), content);
    }
    artifact
}

fn runtime_artifact(
    run_id: &str,
    name: &str,
    media_type: &str,
    receipt_id: &str,
    content: Value,
    redaction: &str,
) -> Value {
    json!({
        "artifactId": format!("artifact_{run_id}_{name}"),
        "name": name,
        "mediaType": media_type,
        "receiptId": receipt_id,
        "content": content,
        "redaction": redaction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cancel_state_update_request() -> RunCancelStateUpdateRequest {
        RunCancelStateUpdateRequest {
            schema_version: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION.to_string(),
            run_id: Some("run_cancel_one".to_string()),
            canceled_at: "2026-06-06T04:45:00.000Z".to_string(),
            run: json!({
                "id": "run_cancel_one",
                "agentId": "agent_one",
                "status": "running",
                "objective": "Cancel this run",
                "mode": "send",
                "createdAt": "2026-06-04T00:00:00.000Z",
                "updatedAt": "2026-06-04T00:00:01.000Z",
                "runtimeJob": {
                    "queuedAt": "2026-06-04T00:00:00.000Z",
                    "startedAt": "2026-06-04T00:00:00.500Z"
                },
                "events": [
                    {
                        "id": "run_cancel_one:event:000:runtime_task",
                        "type": "runtime_task",
                        "data": { "status": "running", "receiptId": "old_task_receipt" }
                    },
                    {
                        "id": "run_cancel_one:event:001:delta",
                        "type": "delta",
                        "data": { "text": "partial" }
                    },
                    {
                        "id": "run_cancel_one:event:002:job_completed",
                        "type": "job_completed",
                        "data": { "status": "completed" }
                    },
                    {
                        "id": "run_cancel_one:event:003:completed",
                        "type": "completed",
                        "data": { "status": "completed" }
                    }
                ],
                "trace": {
                    "events": [],
                    "receipts": [],
                    "qualityLedger": {
                        "failureOntologyLabels": ["existing_label"]
                    }
                },
                "receipts": [{ "id": "receipt_existing", "kind": "existing" }],
                "artifacts": [
                    {
                        "name": "runtime-task.json",
                        "content": { "status": "running" }
                    }
                ]
            }),
        }
    }

    #[test]
    fn rust_policy_plans_run_cancel_state_update() {
        let record = RunCancelStateUpdateCore
            .plan(&run_cancel_state_update_request())
            .expect("run cancel state update");

        assert_eq!(
            record.schema_version,
            RUN_CANCEL_STATE_UPDATE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "planned");
        assert_eq!(record.operation_kind, "run.cancel");
        assert_eq!(record.run["status"], "canceled");
        assert_eq!(record.run["updatedAt"], "2026-06-06T04:45:00.000Z");
        assert_eq!(
            record.run["result"],
            "Run canceled with terminal event continuity preserved."
        );
        let event_types = record.run["events"]
            .as_array()
            .expect("events")
            .iter()
            .map(|event| event["type"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            event_types,
            vec![
                "runtime_task",
                "delta",
                "runtime_checklist",
                "job_canceled",
                "canceled",
            ]
        );
        assert_eq!(record.runtime_task["status"], "canceled");
        assert_eq!(record.runtime_job["eventCount"], 5);
        assert_eq!(record.runtime_checklist["status"], "canceled");
        assert_eq!(record.stop_condition["evidenceSufficient"], true);
        assert!(
            record.run["trace"]["qualityLedger"]["failureOntologyLabels"]
                .as_array()
                .expect("failure labels")
                .iter()
                .any(|label| label.as_str() == Some("operator_cancel"))
        );
        assert_eq!(
            record.run["receipts"]
                .as_array()
                .expect("receipts")
                .last()
                .and_then(|receipt| receipt.get("id"))
                .and_then(Value::as_str),
            Some("receipt_run_cancel_one_runtime_checklist")
        );
        assert_eq!(
            record.run["artifacts"]
                .as_array()
                .expect("artifacts")
                .iter()
                .find(|artifact| artifact["name"] == "runtime-checklist.json")
                .and_then(|artifact| artifact["content"]["status"].as_str()),
            Some("canceled")
        );
    }

    #[test]
    fn rust_policy_plans_run_cancel_admission_required() {
        let record = RunCancelAdmissionRequiredCore
            .plan(&RunCancelAdmissionRequiredRequest {
                schema_version: RUN_CANCEL_ADMISSION_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
                operation: "run_cancel".to_string(),
                operation_kind: "run.cancel".to_string(),
                run_id: "run_cancel_one".to_string(),
                run_status: Some("running".to_string()),
                source: Some("operator".to_string()),
                evidence_refs: vec![
                    "runtime_run_cancel_js_facade_retired".to_string(),
                    "rust_daemon_core_run_cancel_required".to_string(),
                    "agentgres_run_cancel_state_truth_required".to_string(),
                ],
            })
            .expect("run cancel admission required");

        assert_eq!(
            record.schema_version,
            RUN_CANCEL_ADMISSION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "runtime_run_cancel_rust_core_required");
        assert_eq!(record.rust_core_boundary, "runtime.run_cancel");
        assert_eq!(record.operation, "run_cancel");
        assert_eq!(record.operation_kind, "run.cancel");
        assert_eq!(record.details["run_id"], "run_cancel_one");
        assert_eq!(record.details["run_status"], "running");
        assert!(record.details.get("runId").is_none());
        assert!(record.details.get("runStatus").is_none());
    }

    #[test]
    fn rust_policy_rejects_invalid_run_cancel_state_update_schema() {
        let mut request = run_cancel_state_update_request();
        request.schema_version = "legacy.schema".to_string();

        let error = RunCancelStateUpdateCore
            .plan(&request)
            .expect_err("schema should fail");

        assert_eq!(
            error,
            RunCancelStateUpdateError::InvalidSchemaVersion {
                expected: RUN_CANCEL_STATE_UPDATE_REQUEST_SCHEMA_VERSION,
                actual: "legacy.schema".to_string(),
            }
        );
    }
}
