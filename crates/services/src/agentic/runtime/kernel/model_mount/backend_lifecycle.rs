use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountBackendLifecycleRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_kind: Option<String>,
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
pub struct ModelMountBackendLifecyclePlan {
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

#[derive(Debug, Deserialize)]
pub struct ModelMountBackendLifecycleBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountBackendLifecycleRequest,
}

impl ModelMountBackendLifecycleRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !backend_lifecycle_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedBackendLifecycleOperation);
        }
        Ok(())
    }
}

pub fn plan_model_mount_backend_lifecycle_response(
    request: ModelMountBackendLifecycleBridgeRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_backend_lifecycle(&request.request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let public_response = plan.public_response.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let control_hash = plan.control_hash.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_model_mount_backend_lifecycle_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_backend_lifecycle".to_string()),
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub(super) fn plan_backend_lifecycle(
    request: &ModelMountBackendLifecycleRequest,
) -> Result<ModelMountBackendLifecyclePlan, ModelMountError> {
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
    let backend_id = request
        .backend_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(body, "backend_id"))
        .ok_or(ModelMountError::MissingField("backend_id"))?;
    let backend_kind = request
        .backend_kind
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(body, "backend_kind"));
    let body_hash = hash_json(&request.body)?;
    let control_seed = json!({
        "operation_kind": operation_kind,
        "backend_id": backend_id,
        "backend_kind": backend_kind,
        "body_hash": body_hash,
        "source": source,
        "generated_at": generated_at,
    });
    let control_hash = format!("sha256:{}", hash_json(&control_seed)?);
    let record_id = format!(
        "backend-lifecycle-control:{}",
        &control_hash["sha256:".len()..24]
    );
    let receipt_refs = non_empty_vec(&request.receipt_refs);
    let evidence_refs = backend_lifecycle_evidence_refs();
    let public_response = public_response_for(&operation_kind, body, &backend_id, &backend_kind);
    let mut record_receipt_refs = receipt_refs.clone();
    push_unique_ref(&mut record_receipt_refs, &control_hash);
    let record = json!({
        "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
        "object": "ioi.model_mount_backend_lifecycle_record",
        "id": record_id,
        "backend_id": backend_id,
        "backend_kind": backend_kind,
        "rust_core_boundary": "model_mount.backend_lifecycle",
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
    Ok(ModelMountBackendLifecyclePlan {
        schema_version: MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_backend_lifecycle_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.backend_lifecycle".to_string(),
        operation_kind,
        source,
        record_dir: "model-backend-lifecycle-controls".to_string(),
        record_id,
        record,
        public_response,
        receipt_refs,
        evidence_refs,
        control_hash,
    })
}

fn public_response_for(
    operation_kind: &str,
    body: &Map<String, Value>,
    backend_id: &str,
    backend_kind: &Option<String>,
) -> Value {
    let base = json!({
        "object": "ioi.model_mount_backend_lifecycle",
        "status": "planned",
        "backend_id": backend_id,
        "backend_kind": backend_kind,
        "rust_core_boundary": "model_mount.backend_lifecycle",
        "js_backend_registry_read": false,
        "js_process_control": false,
        "js_log_read": false,
        "js_log_write": false,
    });
    let mut response = object_or_empty(&base).clone();
    response.insert(
        "operation_kind".to_string(),
        Value::String(operation_kind.to_string()),
    );
    if let Some(base_url) = string_field(body, "base_url") {
        response.insert("base_url".to_string(), Value::String(base_url));
    }
    match operation_kind {
        "model_mount.backend.health" => {
            response.insert(
                "backend_status".to_string(),
                Value::String("health_planned".to_string()),
            );
        }
        "model_mount.backend.start" => {
            response.insert(
                "backend_status".to_string(),
                Value::String("start_planned".to_string()),
            );
            if let Some(load_options) = body.get("load_options") {
                response.insert("load_options".to_string(), load_options.clone());
            }
        }
        "model_mount.backend.stop" => {
            response.insert(
                "backend_status".to_string(),
                Value::String("stop_planned".to_string()),
            );
        }
        "model_mount.backend.logs_read" => {
            response.insert("logs".to_string(), Value::Array(Vec::new()));
            response.insert("count".to_string(), Value::Number(0.into()));
        }
        _ => {}
    }
    Value::Object(response)
}

fn backend_lifecycle_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.backend.health"
            | "model_mount.backend.start"
            | "model_mount.backend.stop"
            | "model_mount.backend.logs_read"
    )
}

fn backend_lifecycle_evidence_refs() -> Vec<String> {
    vec![
        "public_backend_lifecycle_js_facade_retired".to_string(),
        "rust_daemon_core_backend_lifecycle".to_string(),
        "agentgres_backend_lifecycle_truth_required".to_string(),
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

    fn request(operation_kind: &str) -> ModelMountBackendLifecycleRequest {
        ModelMountBackendLifecycleRequest {
            schema_version: MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            backend_id: Some("backend.llama_cpp".to_string()),
            backend_kind: Some("llama_cpp".to_string()),
            source: Some("runtime-daemon.model_mounting.backend_lifecycle".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            body: json!({
                "backend_id": "backend.llama_cpp",
                "backend_kind": "llama_cpp",
                "load_options": { "context_length": 4096 },
            }),
            receipt_refs: vec!["receipt://backend-lifecycle".to_string()],
        }
    }

    #[test]
    fn rust_core_plans_backend_lifecycle_start_record() {
        let plan = plan_backend_lifecycle(&request("model_mount.backend.start"))
            .expect("backend lifecycle start plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.rust_core_boundary, "model_mount.backend_lifecycle");
        assert_eq!(plan.operation_kind, "model_mount.backend.start");
        assert_eq!(plan.record_dir, "model-backend-lifecycle-controls");
        assert_eq!(plan.record["backend_id"], "backend.llama_cpp");
        assert_eq!(plan.public_response["backend_status"], "start_planned");
        assert_eq!(plan.public_response["js_process_control"], false);
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_backend_lifecycle".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_backend_lifecycle_truth_required".to_string()));
    }

    #[test]
    fn rust_core_plans_backend_lifecycle_health_stop_and_logs_records() {
        let health = plan_backend_lifecycle(&request("model_mount.backend.health"))
            .expect("backend lifecycle health plan");
        assert_eq!(health.public_response["backend_status"], "health_planned");

        let stop = plan_backend_lifecycle(&request("model_mount.backend.stop"))
            .expect("backend lifecycle stop plan");
        assert_eq!(stop.public_response["backend_status"], "stop_planned");

        let logs = plan_backend_lifecycle(&request("model_mount.backend.logs_read"))
            .expect("backend lifecycle logs plan");
        assert_eq!(logs.public_response["logs"], json!([]));
        assert_eq!(logs.public_response["count"], 0);
    }

    #[test]
    fn rust_core_shapes_model_mount_backend_lifecycle_command_response() {
        let response =
            plan_model_mount_backend_lifecycle_response(ModelMountBackendLifecycleBridgeRequest {
                backend: Some("rust_model_mount_backend_lifecycle".to_string()),
                request: request("model_mount.backend.start"),
            })
            .expect("backend lifecycle command response");

        assert_eq!(
            response["source"],
            "rust_model_mount_backend_lifecycle_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_backend_lifecycle");
        assert_eq!(response["operation_kind"], "model_mount.backend.start");
        assert_eq!(
            response["rust_core_boundary"],
            "model_mount.backend_lifecycle"
        );
        assert_eq!(response["record_dir"], "model-backend-lifecycle-controls");
    }
}
