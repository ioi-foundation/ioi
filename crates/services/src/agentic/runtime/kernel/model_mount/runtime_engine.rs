use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRuntimeEngineRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRuntimeEnginePlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub control_hash: String,
}

impl ModelMountRuntimeEngineRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !runtime_engine_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedRuntimeEngineOperation);
        }
        Ok(())
    }
}

pub(super) fn plan_runtime_engine(
    request: &ModelMountRuntimeEngineRequest,
) -> Result<ModelMountRuntimeEnginePlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let body = object_or_empty(&request.body);
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let engine_id = request
        .engine_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(body, "engine_id"))
        .ok_or(ModelMountError::MissingField("engine_id"))?;
    let body_hash = hash_json(&request.body)?;
    let control_seed = json!({
        "operation_kind": operation_kind,
        "engine_id": engine_id,
        "body_hash": body_hash,
        "source": source,
        "generated_at": generated_at,
    });
    let control_hash = format!("sha256:{}", hash_json(&control_seed)?);
    let record_id = format!(
        "runtime-engine-control:{}",
        &control_hash["sha256:".len()..24]
    );
    let receipt_refs = non_empty_vec(&request.receipt_refs);
    let evidence_refs = runtime_engine_evidence_refs();
    let public_response = public_response_for(&operation_kind, body, &engine_id);
    let mut record_receipt_refs = receipt_refs.clone();
    push_unique_ref(&mut record_receipt_refs, &control_hash);
    let record = json!({
        "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
        "object": "ioi.model_mount_runtime_engine_record",
        "id": record_id,
        "engine_id": engine_id,
        "rust_core_boundary": "model_mount.runtime_engine",
        "operation_kind": operation_kind,
        "status": "planned",
        "source": source,
        "generated_at": generated_at,
        "body_hash": format!("sha256:{body_hash}"),
        "control_hash": control_hash,
        "public_response": public_response,
        "receipt_refs": record_receipt_refs,
        "evidence_refs": evidence_refs,
    });
    Ok(ModelMountRuntimeEnginePlan {
        schema_version: MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_runtime_engine_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.runtime_engine".to_string(),
        operation_kind,
        source,
        record_dir: "runtime-engine-controls".to_string(),
        record_id,
        record,
        public_response,
        receipt_refs,
        evidence_refs,
        control_hash,
    })
}

fn public_response_for(operation_kind: &str, body: &Map<String, Value>, engine_id: &str) -> Value {
    let base = json!({
        "object": "ioi.model_mount_runtime_engine",
        "status": "planned",
        "engine_id": engine_id,
        "rust_core_boundary": "model_mount.runtime_engine",
        "js_preference_write": false,
        "js_profile_write": false,
        "js_projection_write": false,
    });
    let mut response = object_or_empty(&base).clone();
    response.insert(
        "operation_kind".to_string(),
        Value::String(operation_kind.to_string()),
    );
    match operation_kind {
        "model_mount.runtime_preference.write" => {
            response.insert(
                "selected_engine_id".to_string(),
                Value::String(engine_id.to_string()),
            );
        }
        "model_mount.runtime_engine_profile.write" => {
            response.insert("profile_recorded".to_string(), Value::Bool(true));
            if let Some(default_load_options) = body.get("default_load_options") {
                response.insert(
                    "default_load_options".to_string(),
                    default_load_options.clone(),
                );
            }
            if let Some(operator_label) = string_field(body, "operator_label") {
                response.insert("operator_label".to_string(), Value::String(operator_label));
            }
        }
        "model_mount.runtime_engine_profile.delete" => {
            response.insert("profile_deleted".to_string(), Value::Bool(true));
        }
        _ => {}
    }
    Value::Object(response)
}

fn runtime_engine_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.runtime_preference.write"
            | "model_mount.runtime_engine_profile.write"
            | "model_mount.runtime_engine_profile.delete"
    )
}

fn runtime_engine_evidence_refs() -> Vec<String> {
    vec![
        "public_runtime_engine_js_facade_retired".to_string(),
        "rust_daemon_core_runtime_engine".to_string(),
        "agentgres_runtime_engine_truth_required".to_string(),
    ]
}

fn object_or_empty(value: &Value) -> &Map<String, Value> {
    match value.as_object() {
        Some(object) => object,
        None => empty_map(),
    }
}

fn empty_map() -> &'static Map<String, Value> {
    use std::sync::OnceLock;
    static EMPTY: OnceLock<Map<String, Value>> = OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation_kind: &str) -> ModelMountRuntimeEngineRequest {
        ModelMountRuntimeEngineRequest {
            schema_version: MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            engine_id: Some("backend.llama-cpp".to_string()),
            source: Some("runtime-daemon.model_mounting.runtime_engine".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            body: json!({
                "engine_id": "backend.llama-cpp",
                "default_load_options": { "gpu_layers": 4 },
                "operator_label": "Llama.cpp",
            }),
            receipt_refs: vec!["receipt://runtime-engine".to_string()],
        }
    }

    #[test]
    fn rust_core_plans_runtime_engine_preference_record() {
        let plan = plan_runtime_engine(&request("model_mount.runtime_preference.write"))
            .expect("runtime-engine preference plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.rust_core_boundary, "model_mount.runtime_engine");
        assert_eq!(plan.operation_kind, "model_mount.runtime_preference.write");
        assert_eq!(plan.record_dir, "runtime-engine-controls");
        assert_eq!(plan.record["engine_id"], "backend.llama-cpp");
        assert_eq!(
            plan.public_response["selected_engine_id"],
            "backend.llama-cpp"
        );
        assert_eq!(plan.public_response["js_preference_write"], false);
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_runtime_engine".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_runtime_engine_truth_required".to_string()));
    }

    #[test]
    fn rust_core_plans_runtime_engine_profile_records() {
        let write = plan_runtime_engine(&request("model_mount.runtime_engine_profile.write"))
            .expect("runtime-engine profile write plan");
        assert_eq!(write.public_response["profile_recorded"], true);
        assert_eq!(
            write.public_response["default_load_options"]["gpu_layers"],
            4
        );

        let delete = plan_runtime_engine(&request("model_mount.runtime_engine_profile.delete"))
            .expect("runtime-engine profile delete plan");
        assert_eq!(delete.public_response["profile_deleted"], true);
    }

    #[test]
    fn rust_core_plans_model_mount_runtime_engine_direct_api() {
        let response = plan_runtime_engine(&request("model_mount.runtime_engine_profile.write"))
            .expect("runtime-engine direct api plan");

        assert_eq!(
            response.operation_kind,
            "model_mount.runtime_engine_profile.write"
        );
        assert_eq!(response.rust_core_boundary, "model_mount.runtime_engine");
        assert_eq!(response.record_dir, "runtime-engine-controls");
        assert_eq!(response.record["engine_id"], "backend.llama-cpp");
        assert!(response
            .evidence_refs
            .contains(&"rust_daemon_core_runtime_engine".to_string()));
    }
}
