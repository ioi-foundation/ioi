use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountServerControlRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_control_id: Option<String>,
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
pub struct ModelMountServerControlPlan {
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
pub struct ModelMountServerControlBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountServerControlRequest,
}

impl ModelMountServerControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !server_control_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedServerControlOperation);
        }
        Ok(())
    }
}

pub fn plan_model_mount_server_control_response(
    request: ModelMountServerControlBridgeRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_server_control(&request.request)?;
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
        "source": "rust_model_mount_server_control_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_server_control".to_string()),
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

pub(super) fn plan_server_control(
    request: &ModelMountServerControlRequest,
) -> Result<ModelMountServerControlPlan, ModelMountError> {
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
    let server_control_id = request
        .server_control_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(body, "server_control_id"))
        .unwrap_or_else(|| "server-control.default".to_string());
    let body_hash = hash_json(&request.body)?;
    let control_seed = json!({
        "operation_kind": operation_kind,
        "server_control_id": server_control_id,
        "body_hash": body_hash,
        "source": source,
        "generated_at": generated_at,
    });
    let control_hash = format!("sha256:{}", hash_json(&control_seed)?);
    let record_id = format!("server-control:{}", &control_hash["sha256:".len()..24]);
    let receipt_refs = non_empty_vec(&request.receipt_refs);
    let evidence_refs = server_control_evidence_refs();
    let public_response = public_response_for(&operation_kind, body, &server_control_id);
    let mut record_receipt_refs = receipt_refs.clone();
    push_unique_ref(&mut record_receipt_refs, &control_hash);
    let record = json!({
        "schema_version": MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION,
        "object": "ioi.model_mount_server_control_record",
        "id": record_id,
        "server_control_id": server_control_id,
        "rust_core_boundary": "model_mount.server_control",
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
    Ok(ModelMountServerControlPlan {
        schema_version: MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_server_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.server_control".to_string(),
        operation_kind,
        source,
        record_dir: "model-server-controls".to_string(),
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
    server_control_id: &str,
) -> Value {
    let base = json!({
        "object": "ioi.model_mount_server_control",
        "status": "planned",
        "server_control_id": server_control_id,
        "rust_core_boundary": "model_mount.server_control",
        "js_state_write": false,
        "js_log_write": false,
        "js_transport_execution": false,
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
        "model_mount.server_control.start" => {
            response.insert(
                "server_status".to_string(),
                Value::String("start_planned".to_string()),
            );
        }
        "model_mount.server_control.stop" => {
            response.insert(
                "server_status".to_string(),
                Value::String("stop_planned".to_string()),
            );
        }
        "model_mount.server_control.restart" => {
            response.insert(
                "server_status".to_string(),
                Value::String("restart_planned".to_string()),
            );
        }
        "model_mount.server_control.logs_read" | "model_mount.server_control.log_projection" => {
            response.insert("logs".to_string(), Value::Array(Vec::new()));
            response.insert("count".to_string(), Value::Number(0.into()));
        }
        "model_mount.server_control.events_read" => {
            response.insert("events".to_string(), Value::Array(Vec::new()));
            response.insert("count".to_string(), Value::Number(0.into()));
        }
        "model_mount.server_control.log_append" => {
            response.insert("log_appended".to_string(), Value::Bool(true));
        }
        "model_mount.server_control.write" => {
            response.insert("state_recorded".to_string(), Value::Bool(true));
        }
        "model_mount.server_control.record_operation" => {
            if let Some(operation) = string_field(body, "operation") {
                response.insert("operation".to_string(), Value::String(operation));
            }
            if let Some(status) = string_field(body, "status") {
                response.insert("operation_status".to_string(), Value::String(status));
            }
            response.insert("operation_recorded".to_string(), Value::Bool(true));
        }
        _ => {}
    }
    Value::Object(response)
}

fn server_control_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.server_control.start"
            | "model_mount.server_control.stop"
            | "model_mount.server_control.restart"
            | "model_mount.server_control.write"
            | "model_mount.server_control.record_operation"
            | "model_mount.server_control.logs_read"
            | "model_mount.server_control.events_read"
            | "model_mount.server_control.log_projection"
            | "model_mount.server_control.log_append"
    )
}

fn server_control_evidence_refs() -> Vec<String> {
    vec![
        "public_server_control_js_facade_retired".to_string(),
        "rust_daemon_core_server_control".to_string(),
        "agentgres_server_control_truth_required".to_string(),
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

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    sha256_hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation_kind: &str) -> ModelMountServerControlRequest {
        ModelMountServerControlRequest {
            schema_version: MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            server_control_id: Some("server-control.default".to_string()),
            source: Some("runtime-daemon.model_mounting.server_control".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            body: json!({
                "base_url": "http://daemon.test",
                "authorization": "Bearer retired",
                "operation": "server_stop",
                "status": "blocked"
            }),
            receipt_refs: vec!["receipt://server-control".to_string()],
        }
    }

    #[test]
    fn rust_core_plans_server_control_start_record() {
        let plan = plan_server_control(&request("model_mount.server_control.start"))
            .expect("server control plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.status, "planned");
        assert_eq!(plan.rust_core_boundary, "model_mount.server_control");
        assert_eq!(plan.operation_kind, "model_mount.server_control.start");
        assert_eq!(plan.record_dir, "model-server-controls");
        assert_eq!(plan.record["server_control_id"], "server-control.default");
        assert_eq!(
            plan.record["public_response"]["server_status"],
            "start_planned"
        );
        assert_eq!(plan.record["public_response"]["js_state_write"], false);
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_server_control".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_server_control_truth_required".to_string()));
    }

    #[test]
    fn rust_core_plans_server_control_read_and_log_records() {
        let logs = plan_server_control(&request("model_mount.server_control.logs_read"))
            .expect("logs read plan");
        assert_eq!(
            logs.public_response["logs"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(logs.public_response["count"], 0);

        let append = plan_server_control(&request("model_mount.server_control.log_append"))
            .expect("log append plan");
        assert_eq!(append.public_response["log_appended"], true);
        assert_eq!(append.record["public_response"]["js_log_write"], false);
    }

    #[test]
    fn rust_core_shapes_model_mount_server_control_command_response() {
        let response =
            plan_model_mount_server_control_response(ModelMountServerControlBridgeRequest {
                backend: Some("rust_model_mount_server_control".to_string()),
                request: request("model_mount.server_control.record_operation"),
            })
            .expect("server control command response");

        assert_eq!(
            response["source"],
            "rust_model_mount_server_control_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_server_control");
        assert_eq!(
            response["operation_kind"],
            "model_mount.server_control.record_operation"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.server_control");
        assert_eq!(
            response["record"]["public_response"]["operation_recorded"],
            true
        );
        assert!(response["control_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
    }
}
