use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

mod adapter_boundary;
mod aggregate;
mod authority;
mod receipt;
mod status;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionRequest {
    pub projection_kind: String,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionPlan {
    pub projection_kind: String,
    pub projection: Value,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMountReadProjectionError {
    pub code: &'static str,
    pub message: String,
}

impl ModelMountReadProjectionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(super) fn plan_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
    let projection = model_mount_read_projection(request)?;
    Ok(ModelMountReadProjectionPlan {
        projection_kind: request.projection_kind.clone(),
        projection,
        evidence_refs: vec![
            "rust_daemon_core_model_mount_projection".to_string(),
            "agentgres_model_mount_read_truth".to_string(),
            "model_mount_js_read_projection_authoring_retired".to_string(),
        ],
    })
}

pub(super) fn model_mount_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    match request.projection_kind.as_str() {
        "snapshot" => Ok(aggregate::snapshot(request)),
        "projection" => Ok(aggregate::projection(request)),
        "projection_summary" => Ok(receipt::projection_summary(request)),
        "receipt_replay" => receipt::receipt_replay(request),
        "model_route_decisions" => Ok(receipt::route_decisions(request)),
        "authority_snapshot" => Ok(authority::authority_snapshot(request)),
        "server_status" => Ok(status::server_status(request)),
        "artifacts" => Ok(Value::Array(Vec::new())),
        "product_artifacts" => Ok(Value::Array(Vec::new())),
        "providers" => Ok(Value::Array(Vec::new())),
        "endpoints" => Ok(Value::Array(Vec::new())),
        "instances" => Ok(Value::Array(Vec::new())),
        "routes" => Ok(Value::Array(Vec::new())),
        "model_capabilities" => Ok(Value::Array(Vec::new())),
        "downloads" => Ok(Value::Array(Vec::new())),
        "backends" => Ok(Value::Array(Vec::new())),
        "oauth_sessions" => Err(ModelMountReadProjectionError::new(
            "model_mount_oauth_read_projection_js_retired",
            "OAuth session read projection requires Rust daemon-core wallet/cTEE projection",
        )),
        "oauth_states" => Err(ModelMountReadProjectionError::new(
            "model_mount_oauth_read_projection_js_retired",
            "OAuth state read projection requires Rust daemon-core wallet/cTEE projection",
        )),
        "provider_health" => Ok(Value::Array(Vec::new())),
        "workflow_bindings" => Ok(adapter_boundary::workflow_bindings()),
        "adapter_boundaries" => Ok(adapter_boundary::adapter_boundaries(&request.state)),
        "runtime_engines" => Ok(Value::Array(Vec::new())),
        "runtime_engine_profiles" => Ok(Value::Array(Vec::new())),
        "runtime_preference" => Ok(Value::Null),
        "runtime_preference_for_endpoint" => Ok(Value::Null),
        "runtime_default_load_options" => Ok(Value::Null),
        "runtime_engine_detail" => model_mount_runtime_engine_detail(request),
        "runtime_model_catalog" => Ok(Value::Array(Vec::new())),
        "open_ai_model_list" => Ok(json!({
            "object": "list",
            "data": [],
        })),
        "latest_provider_health" => receipt::latest_provider_health(request),
        "latest_vault_health" => receipt::latest_vault_health(request),
        "latest_runtime_survey" => Ok(receipt::latest_runtime_survey(request)),
        "catalog_status" => Err(ModelMountReadProjectionError::new(
            "model_catalog_status_js_readback_retired",
            "Model catalog status readback requires Rust daemon-core catalog projection",
        )),
        other => Err(ModelMountReadProjectionError::new(
            "model_mount_read_projection_kind_unsupported",
            format!("unsupported model_mount read projection kind {other}"),
        )),
    }
}

fn model_mount_runtime_engine_detail(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("unknown_runtime_engine");
    Err(ModelMountReadProjectionError::new(
        "model_mount_runtime_engine_not_found",
        format!("runtime engine not found: {engine_id}"),
    ))
}

fn model_mount_projection_schema_version(request: &ModelMountReadProjectionRequest) -> String {
    request
        .schema_version
        .clone()
        .unwrap_or_else(|| MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string())
}

fn model_mount_projection_generated_at(request: &ModelMountReadProjectionRequest) -> String {
    request
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

fn array_field(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn object_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(_)) => value.cloned().unwrap_or(Value::Null),
        Some(Value::Null) | None => Value::Null,
        Some(other) => other.clone(),
    }
}

fn receipts_by_kind(receipts: &[Value], kind: &str) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| json_string_field(receipt, "kind").as_deref() == Some(kind))
        .cloned()
        .collect()
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_projection_is_planned_in_rust_model_mount_core() {
        let plan = plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: "projection_summary".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state: serde_json::json!({
                "receipts": [
                    {"id": "receipt_1", "kind": "model_route_selection", "details": {}}
                ]
            }),
        })
        .expect("read projection planned in Rust model_mount core");

        assert_eq!(plan.projection_kind, "projection_summary");
        assert_eq!(
            plan.projection["schemaVersion"],
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(
            plan.projection["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(plan.projection["watermark"], 1);
        assert_eq!(plan.projection["receiptCount"], 1);
        assert_eq!(
            plan.evidence_refs,
            vec![
                "rust_daemon_core_model_mount_projection",
                "agentgres_model_mount_read_truth",
                "model_mount_js_read_projection_authoring_retired",
            ],
        );
    }
}
