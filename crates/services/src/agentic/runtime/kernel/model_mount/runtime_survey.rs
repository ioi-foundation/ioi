use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    non_empty_string,
    read_projection::{plan_read_projection, ModelMountReadProjectionRequest},
    require_non_empty, sha256_hex, trimmed_string, ModelMountError,
    MODEL_MOUNT_RUNTIME_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SURVEY_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION,
};

const RUNTIME_SURVEY_BOUNDARY: &str = "model_mount.runtime_survey";
const RUNTIME_SURVEY_OPERATION_KIND: &str = "model_mount.runtime_survey.capture";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRuntimeSurveyRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRuntimeSurveyPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub receipt: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub survey_hash: String,
}

impl ModelMountRuntimeSurveyRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if self.operation_kind != RUNTIME_SURVEY_OPERATION_KIND {
            return Err(ModelMountError::UnsupportedRuntimeSurveyOperation);
        }
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if self
            .state_dir
            .as_ref()
            .and_then(|value| non_empty_string(value))
            .is_none()
        {
            return Err(ModelMountError::MissingField("state_dir"));
        }
        Ok(())
    }
}

pub(super) fn plan_runtime_survey(
    request: &ModelMountRuntimeSurveyRequest,
) -> Result<ModelMountRuntimeSurveyPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let checked_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let state_dir = request
        .state_dir
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .ok_or(ModelMountError::MissingField("state_dir"))?;

    let engines = runtime_projection(&state_dir, "runtime_engines", None)?;
    let runtime_preference = runtime_projection(&state_dir, "runtime_preference", None)?;
    let selected_engines = selected_runtime_engines(&engines);
    let selected_engine_ids = selected_engines
        .iter()
        .filter_map(|engine| {
            string_field(engine, "id").or_else(|| string_field(engine, "engine_id"))
        })
        .collect::<Vec<_>>();
    let hardware = rust_hardware_snapshot();
    let lm_studio = json!({
        "status": "not_checked",
        "source": "rust_daemon_core_runtime_survey",
        "js_cli_execution": false,
        "evidence_refs": [
            "lm_studio_public_runtime_survey_cli_retired",
            "rust_daemon_core_runtime_survey"
        ],
    });
    let evidence_refs = runtime_survey_evidence_refs();
    let engine_count = engines.as_array().map(Vec::len).unwrap_or(0);
    let survey_seed = json!({
        "operation_kind": operation_kind.clone(),
        "checked_at": checked_at.clone(),
        "engine_count": engine_count,
        "selected_engine_ids": selected_engine_ids.clone(),
        "runtime_preference": runtime_preference.clone(),
        "hardware": hardware.clone(),
        "lm_studio": lm_studio.clone(),
        "source": source.clone(),
    });
    let survey_hash = format!("sha256:{}", hash_json(&survey_seed)?);
    let receipt_id = format!(
        "receipt_runtime_survey_{}",
        &survey_hash["sha256:".len()..32]
    );
    let receipt_refs = vec![receipt_id.clone()];
    let details = json!({
        "checked_at": checked_at.clone(),
        "engine_count": engine_count,
        "selected_engines": selected_engines.clone(),
        "selected_engine_ids": selected_engine_ids.clone(),
        "runtime_preference": runtime_preference.clone(),
        "hardware": hardware.clone(),
        "lm_studio": lm_studio.clone(),
        "runtime_survey_hash": survey_hash.clone(),
        "rust_core_boundary": RUNTIME_SURVEY_BOUNDARY,
        "operation_kind": operation_kind.clone(),
        "rust_daemon_core_receipt_author": "model_mount.runtime_survey",
        "js_hardware_probe_executed": false,
        "js_runtime_engine_read_executed": false,
        "js_lm_studio_probe_executed": false,
        "agentgres_receipt_state_commit_required": true,
        "evidence_refs": evidence_refs.clone(),
    });
    let receipt = json!({
        "id": receipt_id.clone(),
        "kind": "runtime_survey",
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
        "createdAt": checked_at.clone(),
        "summary": "Rust daemon-core runtime survey capture",
        "redaction": "redacted",
        "receipt_refs": receipt_refs.clone(),
        "evidenceRefs": evidence_refs.clone(),
        "details": details.clone(),
    });
    let public_response = json_object_without_nulls(json!({
        "schemaVersion": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
        "object": "ioi.model_mount_runtime_survey",
        "status": "checked",
        "receiptId": receipt_id.clone(),
        "checkedAt": checked_at.clone(),
        "engineCount": engine_count,
        "engines": engines.clone(),
        "selectedEngines": details_value(&details, "selected_engines"),
        "selectedEngineIds": details_value(&details, "selected_engine_ids"),
        "runtimePreference": details_value(&details, "runtime_preference"),
        "hardware": public_hardware(&hardware),
        "lmStudio": public_lm_studio(&lm_studio),
        "rustCoreBoundary": RUNTIME_SURVEY_BOUNDARY,
        "operationKind": operation_kind.clone(),
        "surveyHash": survey_hash.clone(),
        "jsHardwareProbeExecuted": false,
        "jsRuntimeEngineReadExecuted": false,
        "jsLmStudioProbeExecuted": false,
        "evidenceRefs": evidence_refs.clone(),
    }));

    Ok(ModelMountRuntimeSurveyPlan {
        schema_version: MODEL_MOUNT_RUNTIME_SURVEY_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_runtime_survey_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: RUNTIME_SURVEY_BOUNDARY.to_string(),
        operation_kind,
        source,
        receipt,
        public_response,
        receipt_refs,
        evidence_refs,
        survey_hash,
    })
}

fn runtime_projection(
    state_dir: &str,
    projection_kind: &str,
    engine_id: Option<String>,
) -> Result<Value, ModelMountError> {
    let request = ModelMountReadProjectionRequest {
        projection_kind: projection_kind.to_string(),
        schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
        generated_at: None,
        receipt_id: None,
        engine_id,
        provider_id: None,
        download_id: None,
        base_url: None,
        state_dir: Some(state_dir.to_string()),
        state: json!({}),
    };
    plan_read_projection(&request)
        .map(|plan| plan.projection)
        .map_err(|error| ModelMountError::RuntimeSurveyProjectionFailed(error.message))
}

fn selected_runtime_engines(engines: &Value) -> Vec<Value> {
    engines
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|engine| bool_field(engine, "selected"))
        .collect()
}

fn rust_hardware_snapshot() -> Value {
    json_object_without_nulls(json!({
        "status": "checked",
        "source": "rust_daemon_core_runtime_survey",
        "cpu_count": std::thread::available_parallelism().ok().map(|value| value.get()),
        "total_memory_bytes": linux_total_memory_bytes(),
        "js_probe_execution": false,
        "evidence_refs": [
            "rust_daemon_core_runtime_survey",
            "model_mount_runtime_survey_js_facade_retired"
        ],
    }))
}

fn linux_total_memory_bytes() -> Option<u64> {
    let meminfo = fs::read_to_string(Path::new("/proc/meminfo")).ok()?;
    for line in meminfo.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let kib = rest
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())?;
        return kib.checked_mul(1024);
    }
    None
}

fn public_hardware(hardware: &Value) -> Value {
    json_object_without_nulls(json!({
        "status": string_field(hardware, "status"),
        "source": string_field(hardware, "source"),
        "cpuCount": hardware.get("cpu_count").cloned().unwrap_or(Value::Null),
        "totalMemoryBytes": hardware.get("total_memory_bytes").cloned().unwrap_or(Value::Null),
        "jsProbeExecution": hardware.get("js_probe_execution").cloned().unwrap_or(Value::Bool(false)),
        "evidenceRefs": hardware.get("evidence_refs").cloned().unwrap_or_else(|| json!([])),
    }))
}

fn public_lm_studio(lm_studio: &Value) -> Value {
    json_object_without_nulls(json!({
        "status": string_field(lm_studio, "status"),
        "source": string_field(lm_studio, "source"),
        "jsCliExecution": lm_studio.get("js_cli_execution").cloned().unwrap_or(Value::Bool(false)),
        "evidenceRefs": lm_studio.get("evidence_refs").cloned().unwrap_or_else(|| json!([])),
    }))
}

fn runtime_survey_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_runtime_survey_js_facade_retired".to_string(),
        "rust_daemon_core_runtime_survey".to_string(),
        "agentgres_runtime_survey_truth_required".to_string(),
        "rust_model_mount_core".to_string(),
    ]
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
}

fn details_value(details: &Value, field: &str) -> Value {
    details.get(field).cloned().unwrap_or(Value::Null)
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn bool_field(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn json_object_without_nulls(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    object.retain(|_, value| !value.is_null());
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn request(state_dir: String) -> ModelMountRuntimeSurveyRequest {
        ModelMountRuntimeSurveyRequest {
            schema_version: MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION.to_string(),
            operation_kind: RUNTIME_SURVEY_OPERATION_KIND.to_string(),
            source: Some("runtime-daemon.model_mounting.runtime_survey".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            state_dir: Some(state_dir),
            body: json!({}),
        }
    }

    fn write_runtime_engine_record(state_dir: &Path) {
        let record_dir = state_dir.join("runtime-engine-controls");
        fs::create_dir_all(&record_dir).expect("runtime-engine record dir");
        fs::write(
            record_dir.join("runtime-engine-control-test.json"),
            serde_json::to_string_pretty(&json!({
                "schema_version": "ioi.model_mount.runtime_engine_plan.v1",
                "object": "ioi.model_mount_runtime_engine_record",
                "id": "runtime-engine-control:test",
                "engine_id": "backend.llama-cpp",
                "rust_core_boundary": "model_mount.runtime_engine",
                "operation_kind": "model_mount.runtime_preference.write",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "generated_at": "2026-06-13T11:00:00.000Z",
                "control_hash": "sha256:runtime-engine-control",
                "public_response": {
                    "selected_engine_id": "backend.llama-cpp"
                },
                "receipt_refs": ["receipt://runtime-engine", "sha256:runtime-engine-control"],
                "evidence_refs": [
                    "public_runtime_engine_js_facade_retired",
                    "rust_daemon_core_runtime_engine",
                    "agentgres_runtime_engine_truth_required"
                ]
            }))
            .expect("runtime-engine record json"),
        )
        .expect("runtime-engine record");
    }

    #[test]
    fn rust_core_plans_runtime_survey_receipt_from_agentgres_runtime_engine_replay() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_engine_record(temp.path());

        let plan = plan_runtime_survey(&request(temp.path().to_string_lossy().to_string()))
            .expect("runtime survey plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_RUNTIME_SURVEY_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.rust_core_boundary, RUNTIME_SURVEY_BOUNDARY);
        assert_eq!(plan.operation_kind, RUNTIME_SURVEY_OPERATION_KIND);
        assert_eq!(plan.receipt["kind"], "runtime_survey");
        assert!(plan.receipt["id"]
            .as_str()
            .expect("receipt id")
            .starts_with("receipt_runtime_survey_"));
        assert_eq!(plan.receipt["details"]["engine_count"], 1);
        assert_eq!(
            plan.receipt["details"]["runtime_preference"]["selected_engine_id"],
            "backend.llama-cpp"
        );
        assert_eq!(
            plan.receipt["details"]["js_runtime_engine_read_executed"],
            false
        );
        assert_eq!(plan.public_response["engineCount"], 1);
        assert_eq!(
            plan.public_response["selectedEngineIds"][0],
            "backend.llama-cpp"
        );
        assert_eq!(plan.public_response["jsHardwareProbeExecuted"], false);
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_runtime_survey".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_runtime_survey_truth_required".to_string()));
    }

    #[test]
    fn rust_core_plans_model_mount_runtime_survey_direct_api() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_runtime_engine_record(temp.path());

        let response = plan_runtime_survey(&request(temp.path().to_string_lossy().to_string()))
            .expect("runtime survey direct api plan");

        assert_eq!(response.operation_kind, RUNTIME_SURVEY_OPERATION_KIND);
        assert_eq!(response.rust_core_boundary, RUNTIME_SURVEY_BOUNDARY);
        assert_eq!(response.receipt["kind"], "runtime_survey");
        assert!(response.survey_hash.starts_with("sha256:"));
        assert!(response
            .evidence_refs
            .contains(&"rust_daemon_core_runtime_survey".to_string()));
    }

    #[test]
    fn rust_core_rejects_runtime_survey_without_state_dir() {
        let mut invalid = request(String::new());
        invalid.state_dir = None;
        let error = plan_runtime_survey(&invalid).expect_err("missing state_dir rejected");
        assert_eq!(error, ModelMountError::MissingField("state_dir"));
    }
}
